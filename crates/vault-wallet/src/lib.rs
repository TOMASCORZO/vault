//! Production-intent finalized compact-block scanning boundary for Vault.
//!
//! The wallet scans complete authenticated compact blocks locally, replays the
//! exact note-tree transition, and produces an opaque atomic store update. This
//! crate deliberately has no network fetcher, unauthenticated scan entry point,
//! volatile production store, or spendable unfinalized-note path. Its first
//! encrypted transactional ShardTree store is production-intent, not release
//! ready: concrete platform/hardware seed custody, trusted birthday/target
//! bootstrap operations, recovery policy beyond
//! the bounded account range, migrations, platform key storage, crash injection,
//! access-pattern benchmarks, and independent review remain H1 activation
//! gates.

mod checkpoint_distribution;
mod checkpoint_policy_store;
mod custody;
#[cfg(target_os = "macos")]
mod macos_keychain_guard;
mod recovery;
mod storage;
#[cfg(target_os = "windows")]
mod windows_tpm_guard;

pub use checkpoint_distribution::{
    AuthenticatedRecoveryTarget, CheckpointDistributionDraft, CheckpointDistributionError,
    CheckpointPolicyBootstrapDraft, CheckpointPolicyUpdateDraft, CheckpointPublisherSignature,
    CheckpointTrustPolicy, MAX_CHECKPOINT_POLICY_BOOTSTRAP_BYTES,
    MAX_CHECKPOINT_POLICY_UPDATE_BYTES, MAX_CHECKPOINT_PUBLISHERS, RecoveryTargetDistributionDraft,
    checkpoint_publisher_id, verify_birthday_checkpoint_distribution,
    verify_checkpoint_policy_bootstrap, verify_checkpoint_policy_update,
    verify_recovery_target_distribution,
};
pub use checkpoint_policy_store::{
    CheckpointPolicyAnchor, CheckpointPolicyRollbackGuard, CheckpointPolicyRollbackGuardError,
    CheckpointPolicyStore, CheckpointPolicyStoreError,
};
pub use custody::{
    WALLET_SEED_ENTROPY_BYTES, WALLET_SEED_RECOVERY_PACKAGE_BYTES, WalletSeedCustodian,
    WalletSeedCustodyError, WalletSeedImportError, WalletSeedMaterial,
};
#[cfg(target_os = "macos")]
pub use macos_keychain_guard::MacOsKeychainRollbackGuard;
pub use recovery::{
    FinalizedRecoverySource, MAX_RECOVERY_BLOCKS_PER_ADVANCE, WalletRecoveryAdvance,
    WalletRecoveryCoordinatorError, WalletRecoveryCoordinatorFailure, advance_seed_recovery,
};
pub use storage::{
    EncryptedWalletDb, WalletBackupSummary, WalletDatabaseConfig, WalletDbError, WalletSpendWitness,
};
#[cfg(target_os = "windows")]
pub use windows_tpm_guard::WindowsTpmRollbackGuard;

use core::fmt;
use std::collections::BTreeSet;

use subtle::ConstantTimeEq;
use vault_privacy::{
    ActionNullifier, DecryptedNote, EncryptedNote, KeyScope, MAX_SCAN_BATCH_OUTPUTS,
    MAX_SCAN_VIEWING_KEYS, NoteCommitmentTree, NoteTreeRoot, NoteTreeSnapshot, PrivacyError,
    VaultFullViewingKey, VaultIncomingViewingKey, VaultSpendingKey, scan_incoming_notes,
};
use vault_protocol::{
    AuthenticatedCompactBlock, ChainId, CompactBlockCommitment, CompactBlockError,
    FinalizedCompactBlockHeader, TransactionId,
};

const SCAN_ACCOUNTS_PER_CRYPTO_BATCH: usize = MAX_SCAN_VIEWING_KEYS / 2;
const MAX_SCAN_CRYPTO_BATCHES: usize = 8;
const RECOVERY_ACCOUNT_ID_DOMAIN: &str = "vault.wallet.recovery-account-id-v1.2026-08-23";
const SCAN_ACCOUNT_SET_DOMAIN: &str = "vault.wallet.scan-account-set-v1.2026-08-23";

/// Absolute account bound for one complete block scan.
///
/// Each account contributes external and internal incoming capabilities. The
/// scanner evaluates eight fixed primitive batches of sixteen capabilities;
/// it never raises or bypasses the privacy primitive's per-call bound.
pub const MAX_SCAN_ACCOUNTS: usize = SCAN_ACCOUNTS_PER_CRYPTO_BATCH * MAX_SCAN_CRYPTO_BATCHES;

/// Fail-closed local scanning error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletScanError {
    /// Trusted checkpoint metadata or tree state was invalid.
    InvalidCheckpoint,
    /// The compact block belongs to another network.
    WrongNetwork,
    /// Finalized heights were not strictly consecutive.
    HeightDiscontinuity,
    /// The compact block does not extend the exact stored finalized tip.
    ParentMismatch,
    /// Authenticated compact-block or note-tree validation failed.
    InvalidCompactBlock,
    /// Local authenticated note decryption rejected public input.
    NoteDecryptionFailure,
    /// The wallet-local account identifier is the reserved all-zero value.
    InvalidAccountId,
    /// More accounts were supplied than the bounded scanner supports.
    TooManyScanAccounts,
    /// Two supplied scan accounts use the same wallet-local identifier.
    DuplicateScanAccountId,
    /// Two supplied accounts expose the same incoming capability.
    DuplicateScanCapability,
    /// A detected note could not produce its canonical future nullifier.
    NullifierDerivationFailure,
    /// Two detected notes produced the same future spend nullifier.
    DuplicateOwnedNullifier,
    /// A depth-32 note position could not be represented canonically.
    PositionOverflow,
}

impl fmt::Display for WalletScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCheckpoint => "wallet scan checkpoint is invalid",
            Self::WrongNetwork => "compact block belongs to another network",
            Self::HeightDiscontinuity => "finalized compact-block height is discontinuous",
            Self::ParentMismatch => "compact block does not extend the finalized wallet tip",
            Self::InvalidCompactBlock => "authenticated compact block is invalid",
            Self::NoteDecryptionFailure => "local note trial decryption failed",
            Self::InvalidAccountId => "zero wallet account identifier is reserved",
            Self::TooManyScanAccounts => "wallet scan exceeds the account limit",
            Self::DuplicateScanAccountId => "wallet scan contains a duplicate account identifier",
            Self::DuplicateScanCapability => "wallet scan contains a duplicate incoming capability",
            Self::NullifierDerivationFailure => {
                "detected wallet note could not derive its spend nullifier"
            }
            Self::DuplicateOwnedNullifier => {
                "detected wallet notes contain a duplicate spend nullifier"
            }
            Self::PositionOverflow => "wallet note position overflow",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WalletScanError {}

impl From<CompactBlockError> for WalletScanError {
    fn from(_: CompactBlockError) -> Self {
        Self::InvalidCompactBlock
    }
}

/// Stable wallet-local account identifier.
///
/// It is never transmitted to a node and MUST be stored only inside the
/// encrypted wallet database. Callers should generate it randomly when an
/// account is created and retain it across rescans and migrations.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct WalletAccountId([u8; 32]);

impl fmt::Debug for WalletAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletAccountId(REDACTED)")
    }
}

impl WalletAccountId {
    /// Validates an opaque wallet-local account identifier.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, WalletScanError> {
        if bytes == [0; 32] {
            return Err(WalletScanError::InvalidAccountId);
        }
        Ok(Self(bytes))
    }

    /// Exact private-storage representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Full scan capability for one local account.
///
/// Both external recipient notes and internal change are always scanned. The
/// full viewing key is also retained for local nullifier derivation, allowing
/// durable storage to recognize a later spend without querying a server for
/// wallet-specific data. This capability cannot authorize spending.
pub struct WalletScanAccount<'a> {
    account_id: WalletAccountId,
    full_viewing_key: &'a VaultFullViewingKey,
    external: VaultIncomingViewingKey,
    internal: VaultIncomingViewingKey,
}

impl fmt::Debug for WalletScanAccount<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletScanAccount(REDACTED)")
    }
}

impl<'a> WalletScanAccount<'a> {
    /// Derives both incoming scopes from a validated full viewing key.
    #[must_use]
    pub fn new(account_id: WalletAccountId, full_viewing_key: &'a VaultFullViewingKey) -> Self {
        Self {
            account_id,
            full_viewing_key,
            external: full_viewing_key.incoming_viewing_key(KeyScope::External),
            internal: full_viewing_key.incoming_viewing_key(KeyScope::Internal),
        }
    }

    /// Stable encrypted-storage identifier for this account.
    #[must_use]
    pub const fn account_id(&self) -> WalletAccountId {
        self.account_id
    }

    fn incoming(&self, scope: KeyScope) -> &VaultIncomingViewingKey {
        match scope {
            KeyScope::External => &self.external,
            KeyScope::Internal => &self.internal,
        }
    }
}

/// Fail-closed deterministic seed-recovery planning error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletRecoveryError {
    /// Recovery must cover at least one account and remain within its global bound.
    InvalidAccountCount,
    /// Seed material or account-key derivation was rejected.
    AccountDerivationFailed,
    /// Birthday, account set, and target do not belong to the same network.
    WrongNetwork,
    /// The target is not strictly after the birthday or regresses the note tree.
    InvalidTarget,
    /// The trailing unused-account gap is zero or exceeds the covered range.
    InvalidGapLimit,
}

impl fmt::Display for WalletRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidAccountCount => "wallet recovery account count is invalid",
            Self::AccountDerivationFailed => "wallet recovery account derivation failed",
            Self::WrongNetwork => "wallet recovery inputs belong to different networks",
            Self::InvalidTarget => "wallet recovery target is invalid",
            Self::InvalidGapLimit => "wallet recovery account gap is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WalletRecoveryError {}

struct WalletRecoveryAccount {
    account_index: u32,
    account_id: WalletAccountId,
    full_viewing_key: VaultFullViewingKey,
}

impl fmt::Debug for WalletRecoveryAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletRecoveryAccount(REDACTED)")
    }
}

/// Ephemeral deterministic scan capabilities derived from a wallet seed.
///
/// Spending keys and the seed are never retained. Only full viewing keys live
/// in this value and are zeroized by their underlying types on drop. Account
/// indices are the contiguous range `0..account_count`; diversified address
/// indices do not need discovery because one account viewing key covers them.
pub struct WalletRecoveryAccounts {
    chain_id: ChainId,
    accounts: Vec<WalletRecoveryAccount>,
    commitment: [u8; 32],
}

impl fmt::Debug for WalletRecoveryAccounts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletRecoveryAccounts(REDACTED)")
    }
}

impl WalletRecoveryAccounts {
    /// Derives a contiguous, globally bounded account range from seed material.
    pub fn derive(
        seed: &WalletSeedMaterial,
        chain_id: ChainId,
        account_count: usize,
    ) -> Result<Self, WalletRecoveryError> {
        if account_count == 0 || account_count > MAX_SCAN_ACCOUNTS {
            return Err(WalletRecoveryError::InvalidAccountCount);
        }
        let mut accounts = Vec::with_capacity(account_count);
        for raw_index in 0..account_count {
            let account_index =
                u32::try_from(raw_index).map_err(|_| WalletRecoveryError::InvalidAccountCount)?;
            let spending_key = VaultSpendingKey::derive(
                seed.expose_for_derivation(),
                *chain_id.as_bytes(),
                account_index,
            )
            .map_err(|_: PrivacyError| WalletRecoveryError::AccountDerivationFailed)?;
            let full_viewing_key = spending_key.full_viewing_key();
            drop(spending_key);
            let account_id = recovery_account_id(chain_id, account_index, &full_viewing_key)?;
            accounts.push(WalletRecoveryAccount {
                account_index,
                account_id,
                full_viewing_key,
            });
        }
        let commitment = recovery_account_set_commitment(&accounts);
        Ok(Self {
            chain_id,
            accounts,
            commitment,
        })
    }

    /// Requests a single scoped seed use from an external custodian and retains
    /// only the derived viewing capabilities.
    pub fn derive_from_custodian<Custodian: WalletSeedCustodian>(
        custodian: &mut Custodian,
        chain_id: ChainId,
        account_count: usize,
    ) -> Result<Self, WalletSeedCustodyError<Custodian::Error>> {
        if account_count == 0 || account_count > MAX_SCAN_ACCOUNTS {
            return Err(WalletSeedCustodyError::Recovery(
                WalletRecoveryError::InvalidAccountCount,
            ));
        }
        custodian
            .use_seed(|seed| Self::derive(seed, chain_id, account_count))
            .map_err(WalletSeedCustodyError::Custodian)?
            .map_err(WalletSeedCustodyError::Recovery)
    }

    /// Network domain used for all derived accounts.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Number of contiguous account indices covered by this recovery pass.
    #[must_use]
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Stable private account identifier for one covered account index.
    #[must_use]
    pub fn account_id(&self, account_index: u32) -> Option<WalletAccountId> {
        self.accounts
            .get(usize::try_from(account_index).ok()?)
            .filter(|account| account.account_index == account_index)
            .map(|account| account.account_id)
    }

    /// Viewing capability for constructing addresses or recovery fixtures.
    #[must_use]
    pub fn full_viewing_key(&self, account_index: u32) -> Option<&VaultFullViewingKey> {
        self.accounts
            .get(usize::try_from(account_index).ok()?)
            .filter(|account| account.account_index == account_index)
            .map(|account| &account.full_viewing_key)
    }

    /// Builds the ordered external-and-internal scan account set.
    #[must_use]
    pub fn scan_accounts(&self) -> Vec<WalletScanAccount<'_>> {
        self.accounts
            .iter()
            .map(|account| WalletScanAccount::new(account.account_id, &account.full_viewing_key))
            .collect()
    }
}

fn recovery_account_id(
    chain_id: ChainId,
    account_index: u32,
    full_viewing_key: &VaultFullViewingKey,
) -> Result<WalletAccountId, WalletRecoveryError> {
    let viewing_key = full_viewing_key.export();
    for counter in 0..=u8::MAX {
        let mut hasher = blake3::Hasher::new_derive_key(RECOVERY_ACCOUNT_ID_DOMAIN);
        hasher.update(chain_id.as_bytes());
        hasher.update(&account_index.to_be_bytes());
        hasher.update(&[counter]);
        hasher.update(viewing_key.as_ref());
        if let Ok(account_id) = WalletAccountId::from_bytes(*hasher.finalize().as_bytes()) {
            return Ok(account_id);
        }
    }
    Err(WalletRecoveryError::AccountDerivationFailed)
}

fn recovery_account_set_commitment(accounts: &[WalletRecoveryAccount]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SCAN_ACCOUNT_SET_DOMAIN);
    hasher.update(
        &u64::try_from(accounts.len())
            .expect("bounded account count fits u64")
            .to_be_bytes(),
    );
    for account in accounts {
        hasher.update(&account.account_index.to_be_bytes());
        hasher.update(&account.account_id.to_bytes());
        hasher.update(account.full_viewing_key.export().as_ref());
    }
    *hasher.finalize().as_bytes()
}

fn scan_account_set_commitment(accounts: &[WalletScanAccount<'_>]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SCAN_ACCOUNT_SET_DOMAIN);
    hasher.update(
        &u64::try_from(accounts.len())
            .expect("bounded account count fits u64")
            .to_be_bytes(),
    );
    for (index, account) in accounts.iter().enumerate() {
        hasher.update(
            &u32::try_from(index)
                .expect("bounded account index fits u32")
                .to_be_bytes(),
        );
        hasher.update(&account.account_id.to_bytes());
        hasher.update(account.full_viewing_key.export().as_ref());
    }
    *hasher.finalize().as_bytes()
}

fn validate_scan_accounts(accounts: &[WalletScanAccount<'_>]) -> Result<(), WalletScanError> {
    if accounts.len() > MAX_SCAN_ACCOUNTS {
        return Err(WalletScanError::TooManyScanAccounts);
    }

    let mut account_ids = BTreeSet::new();
    for account in accounts {
        if !account_ids.insert(account.account_id) {
            return Err(WalletScanError::DuplicateScanAccountId);
        }
    }

    let capabilities = accounts
        .iter()
        .flat_map(|account| {
            [
                account.incoming(KeyScope::External).export(),
                account.incoming(KeyScope::Internal).export(),
            ]
        })
        .collect::<Vec<_>>();
    for (index, capability) in capabilities.iter().enumerate() {
        if capabilities[index + 1..]
            .iter()
            .any(|other| bool::from(capability.as_ref().ct_eq(other.as_ref())))
        {
            return Err(WalletScanError::DuplicateScanCapability);
        }
    }
    Ok(())
}

/// Exact finalized wallet scan position restored only from authenticated,
/// encrypted wallet storage or a separately verified recovery checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletScanTip {
    chain_id: ChainId,
    height: u64,
    block_hash: [u8; 32],
    tree: NoteCommitmentTree,
}

impl WalletScanTip {
    /// Restores an independently verified checkpoint and validates the complete
    /// minimal note-tree frontier before it can be used.
    pub fn from_verified_checkpoint(
        chain_id: ChainId,
        height: u64,
        block_hash: [u8; 32],
        tree_snapshot: &NoteTreeSnapshot,
    ) -> Result<Self, WalletScanError> {
        if chain_id.is_zero() || block_hash == [0; 32] {
            return Err(WalletScanError::InvalidCheckpoint);
        }
        let tree = NoteCommitmentTree::restore(tree_snapshot)
            .map_err(|_| WalletScanError::InvalidCheckpoint)?;
        Ok(Self {
            chain_id,
            height,
            block_hash,
            tree,
        })
    }

    /// Network domain of the checkpoint.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Last durably committed finalized height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Last durably committed finalized block identifier.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    /// Current depth-32 note-tree size.
    #[must_use]
    pub fn tree_size(&self) -> u64 {
        self.tree.size()
    }

    /// Current canonical note-tree root.
    #[must_use]
    pub fn tree_root(&self) -> NoteTreeRoot {
        self.tree.typed_root()
    }

    /// Minimal validated frontier for encrypted durable storage.
    #[must_use]
    pub fn tree_snapshot(&self) -> NoteTreeSnapshot {
        self.tree.snapshot()
    }
}

/// Finalized note-tree frontier immediately before recovery scanning begins.
///
/// Construction binds a canonical frontier to fields already imported through
/// the finalized-consensus header boundary. It does not independently prove
/// finality, and selecting a checkpoint after the first possible wallet output
/// can permanently omit funds from recovery.
#[derive(Clone, Eq, PartialEq)]
pub struct WalletBirthdayCheckpoint {
    tip: WalletScanTip,
}

impl fmt::Debug for WalletBirthdayCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletBirthdayCheckpoint(REDACTED)")
    }
}

impl WalletBirthdayCheckpoint {
    /// Binds a validated frontier to an independently finalized header.
    pub fn from_finalized_header(
        header: &FinalizedCompactBlockHeader,
        tree_snapshot: &NoteTreeSnapshot,
    ) -> Result<Self, WalletScanError> {
        if header.height() == u64::MAX {
            return Err(WalletScanError::InvalidCheckpoint);
        }
        let tip = WalletScanTip::from_verified_checkpoint(
            header.chain_id(),
            header.height(),
            header.block_hash(),
            tree_snapshot,
        )?;
        if tip.tree_size() != header.post_tree_size() || tip.tree_root() != header.post_tree_root()
        {
            return Err(WalletScanError::InvalidCheckpoint);
        }
        Ok(Self { tip })
    }

    /// Network whose finalized history must be scanned.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.tip.chain_id
    }

    /// Finalized height immediately before the first recovery scan.
    #[must_use]
    pub const fn checkpoint_height(&self) -> u64 {
        self.tip.height
    }

    /// First height that recovery must scan without gaps.
    #[must_use]
    pub const fn first_scan_height(&self) -> u64 {
        self.tip.height + 1
    }

    /// Finalized checkpoint block identifier.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.tip.block_hash
    }

    /// Canonical recovery frontier.
    #[must_use]
    pub fn tree_snapshot(&self) -> NoteTreeSnapshot {
        self.tip.tree_snapshot()
    }

    pub(crate) fn from_stored_tip(tip: WalletScanTip) -> Result<Self, WalletScanError> {
        if tip.height == 0 || tip.height == u64::MAX {
            return Err(WalletScanError::InvalidCheckpoint);
        }
        Ok(Self { tip })
    }

    pub(crate) fn into_tip(self) -> WalletScanTip {
        self.tip
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct WalletRecoveryTarget {
    pub(crate) height: u64,
    pub(crate) block_hash: [u8; 32],
    pub(crate) tree_size: u64,
    pub(crate) tree_root: NoteTreeRoot,
}

/// Immutable recovery contract binding birthday, target, seed accounts, and
/// the conservative trailing unused-account rule.
pub struct WalletRecoveryPlan {
    pub(crate) checkpoint: WalletBirthdayCheckpoint,
    pub(crate) target: WalletRecoveryTarget,
    pub(crate) account_ids: Vec<WalletAccountId>,
    pub(crate) account_set_commitment: [u8; 32],
    pub(crate) gap_limit: u8,
}

impl fmt::Debug for WalletRecoveryPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletRecoveryPlan(REDACTED)")
    }
}

impl WalletRecoveryPlan {
    /// Creates a recovery contract from independently finalized boundaries.
    ///
    /// Completion means every block through `target_header` was scanned with
    /// this exact account set and enough unused indices follow the highest
    /// used account. It does not prove that the chosen birthday predates every
    /// wallet output; that remains an external recovery invariant.
    pub fn new(
        checkpoint: WalletBirthdayCheckpoint,
        target_header: &FinalizedCompactBlockHeader,
        accounts: &WalletRecoveryAccounts,
        gap_limit: usize,
    ) -> Result<Self, WalletRecoveryError> {
        if checkpoint.chain_id() != target_header.chain_id()
            || checkpoint.chain_id() != accounts.chain_id()
        {
            return Err(WalletRecoveryError::WrongNetwork);
        }
        if target_header.height() <= checkpoint.checkpoint_height()
            || target_header.post_tree_size() < checkpoint.tip.tree_size()
        {
            return Err(WalletRecoveryError::InvalidTarget);
        }
        if gap_limit == 0
            || gap_limit > accounts.account_count()
            || gap_limit > usize::from(u8::MAX)
        {
            return Err(WalletRecoveryError::InvalidGapLimit);
        }
        Ok(Self {
            checkpoint,
            target: WalletRecoveryTarget {
                height: target_header.height(),
                block_hash: target_header.block_hash(),
                tree_size: target_header.post_tree_size(),
                tree_root: target_header.post_tree_root(),
            },
            account_ids: accounts
                .accounts
                .iter()
                .map(|account| account.account_id)
                .collect(),
            account_set_commitment: accounts.commitment,
            gap_limit: u8::try_from(gap_limit)
                .expect("validated recovery gap fits canonical encoding"),
        })
    }

    /// Creates a recovery contract from a target authenticated by checkpoint
    /// publishers and independently matched to consensus-finalized state.
    pub fn new_with_authenticated_target(
        checkpoint: WalletBirthdayCheckpoint,
        target: &AuthenticatedRecoveryTarget,
        accounts: &WalletRecoveryAccounts,
        gap_limit: usize,
    ) -> Result<Self, WalletRecoveryError> {
        Self::new(checkpoint, target.finalized_header(), accounts, gap_limit)
    }

    /// Finalized birthday immediately before scanning begins.
    #[must_use]
    pub const fn checkpoint(&self) -> &WalletBirthdayCheckpoint {
        &self.checkpoint
    }

    /// Independently finalized height that must be reached exactly.
    #[must_use]
    pub const fn target_height(&self) -> u64 {
        self.target.height
    }

    /// Number of contiguous seed accounts tested at every height.
    #[must_use]
    pub fn account_count(&self) -> usize {
        self.account_ids.len()
    }

    /// Required empty indices after the highest recovered account.
    #[must_use]
    pub const fn gap_limit(&self) -> u8 {
        self.gap_limit
    }
}

/// Authenticated durable recovery state. Numeric details are intentionally not
/// included in `Debug`; callers may access them by matching the value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum WalletRecoveryStatus {
    /// A genesis-created wallet did not enter seed recovery.
    NotRequired,
    /// Historical scanning has not yet reached the exact finalized target.
    InProgress {
        /// Original birthday height.
        birthday_height: u64,
        /// Last atomically committed scan height.
        scanned_height: u64,
        /// Exact independently finalized recovery target.
        target_height: u64,
        /// Contiguous seed account count scanned at every height.
        account_count: u8,
        /// Required trailing unused-account count.
        gap_limit: u8,
    },
    /// The target and conservative trailing account gap were both satisfied.
    Complete {
        /// Finalized target at which recovery closed.
        target_height: u64,
        /// Account indices covered by the completed pass.
        account_count: u8,
        /// Highest account index with an authenticated recovered note.
        highest_used_account: Option<u32>,
    },
    /// The target was reached but activity was too near the configured bound.
    /// Recovery must restart from the same birthday with a larger account set.
    RequiresLargerAccountRange {
        /// Finalized target reached by the failed-closed pass.
        target_height: u64,
        /// Account indices covered by the exhausted pass.
        account_count: u8,
        /// Highest account index with an authenticated recovered note.
        highest_used_account: u32,
        /// Required trailing unused-account count.
        gap_limit: u8,
    },
}

impl fmt::Debug for WalletRecoveryStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletRecoveryStatus(REDACTED)")
    }
}

/// One incoming note found while scanning every output in a finalized block.
pub struct ScannedNote {
    transaction_id: TransactionId,
    action_index: u8,
    position: u32,
    action_nullifier: ActionNullifier,
    output: EncryptedNote,
    account_id: WalletAccountId,
    key_scope: KeyScope,
    spend_nullifier: ActionNullifier,
    decrypted: DecryptedNote,
}

impl fmt::Debug for ScannedNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScannedNote(REDACTED)")
    }
}

impl ScannedNote {
    /// Transaction containing this output.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Canonical action index within the compact transaction.
    #[must_use]
    pub const fn action_index(&self) -> u8 {
        self.action_index
    }

    /// Global depth-32 note-tree leaf position.
    #[must_use]
    pub const fn position(&self) -> u32 {
        self.position
    }

    /// Public action nullifier used as the new note's unique `rho` domain.
    #[must_use]
    pub const fn action_nullifier(&self) -> ActionNullifier {
        self.action_nullifier
    }

    /// Exact encrypted output committed by consensus.
    #[must_use]
    pub const fn output(&self) -> &EncryptedNote {
        &self.output
    }

    /// Stable wallet-local account that owns this note.
    #[must_use]
    pub const fn account_id(&self) -> WalletAccountId {
        self.account_id
    }

    /// Incoming key scope that authenticated the note.
    #[must_use]
    pub const fn key_scope(&self) -> KeyScope {
        self.key_scope
    }

    /// Unique nullifier that will appear publicly if this note is spent.
    #[must_use]
    pub const fn spend_nullifier(&self) -> ActionNullifier {
        self.spend_nullifier
    }

    /// Authenticated private note and fixed memo.
    #[must_use]
    pub const fn decrypted(&self) -> &DecryptedNote {
        &self.decrypted
    }
}

/// Opaque all-or-nothing durable store update for one finalized block.
///
/// Fields are constructible only by [`scan_finalized_block`]. A store MUST
/// compare its current tip with the expected parent/pre-tree fields and commit
/// the new tip, every public nullifier, every commitment needed by its witness
/// engine, and all detected notes in one database transaction.
pub struct ScannedBlockUpdate {
    expected_parent_height: u64,
    expected_parent_hash: [u8; 32],
    expected_pre_tree_size: u64,
    expected_pre_tree_root: NoteTreeRoot,
    compact_commitment: CompactBlockCommitment,
    next_tip: WalletScanTip,
    scan_account_set_commitment: [u8; 32],
    nullifiers: Vec<ActionNullifier>,
    note_commitments: Vec<[u8; 32]>,
    detected_notes: Vec<ScannedNote>,
}

impl fmt::Debug for ScannedBlockUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScannedBlockUpdate")
            .field("height", &self.next_tip.height)
            .field("action_count", &self.nullifiers.len())
            .field("wallet_specific_state", &"REDACTED")
            .finish()
    }
}

impl ScannedBlockUpdate {
    /// Height the durable store must currently contain.
    #[must_use]
    pub const fn expected_parent_height(&self) -> u64 {
        self.expected_parent_height
    }

    /// Block hash the durable store must currently contain.
    #[must_use]
    pub const fn expected_parent_hash(&self) -> [u8; 32] {
        self.expected_parent_hash
    }

    /// Note-tree size the durable witness engine must currently contain.
    #[must_use]
    pub const fn expected_pre_tree_size(&self) -> u64 {
        self.expected_pre_tree_size
    }

    /// Note-tree root the durable witness engine must currently contain.
    #[must_use]
    pub const fn expected_pre_tree_root(&self) -> NoteTreeRoot {
        self.expected_pre_tree_root
    }

    /// Header-authenticated compact payload commitment.
    #[must_use]
    pub const fn compact_commitment(&self) -> CompactBlockCommitment {
        self.compact_commitment
    }

    /// Validated post-block tip to commit atomically.
    #[must_use]
    pub const fn next_tip(&self) -> &WalletScanTip {
        &self.next_tip
    }

    /// Commitment to the ordered account IDs and full viewing capabilities
    /// tested for every output in this block.
    #[must_use]
    pub const fn scan_account_set_commitment(&self) -> [u8; 32] {
        self.scan_account_set_commitment
    }

    /// Every public consumed nullifier in finalized block order. The store uses
    /// these to mark any locally owned note spent without remote queries.
    #[must_use]
    pub fn nullifiers(&self) -> &[ActionNullifier] {
        &self.nullifiers
    }

    /// Every appended output commitment in finalized block order.
    #[must_use]
    pub fn note_commitments(&self) -> &[[u8; 32]] {
        &self.note_commitments
    }

    /// Locally authenticated incoming notes.
    #[must_use]
    pub fn detected_notes(&self) -> &[ScannedNote] {
        &self.detected_notes
    }
}

/// Minimal success result safe to expose after an atomic store commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletScanSummary {
    height: u64,
    action_count: usize,
}

impl WalletScanSummary {
    /// Finalized height committed.
    #[must_use]
    pub const fn height(self) -> u64 {
        self.height
    }

    /// Full public action count scanned locally.
    #[must_use]
    pub const fn action_count(self) -> usize {
        self.action_count
    }
}

/// Durable finalized wallet storage boundary.
///
/// `commit_finalized_block` MUST be a single serializable transaction and MUST
/// fail if its current tip differs from any `expected_*` field. No permissive
/// or volatile implementation is provided by this crate.
pub trait FinalizedWalletStore {
    /// Opaque backend failure.
    type Error: std::error::Error;

    /// Loads and authenticates the exact durable finalized tip.
    fn load_tip(&self) -> Result<WalletScanTip, Self::Error>;

    /// Atomically commits the complete block delta or leaves all state
    /// unchanged. Uncertain commit outcomes must poison/close the store handle.
    fn commit_finalized_block(&mut self, update: ScannedBlockUpdate) -> Result<(), Self::Error>;
}

/// Combined scanner/store failure without discarding the backend error.
#[derive(Debug)]
pub enum ScanCommitError<E> {
    /// Authenticated compact-block scanning failed before storage mutation.
    Scan(WalletScanError),
    /// Loading or committing the durable store failed.
    Store(E),
}

impl<E: fmt::Display> fmt::Display for ScanCommitError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scan(error) => write!(formatter, "wallet scan failed: {error}"),
            Self::Store(_) => formatter.write_str("durable wallet store operation failed"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ScanCommitError<E> {}

/// Scans a complete authenticated finalized block locally and validates its
/// exact chain/tree transition. Every output is trial-decrypted in fixed-size
/// bounded batches regardless of whether earlier outputs matched.
pub fn scan_finalized_block(
    tip: &WalletScanTip,
    authenticated: &AuthenticatedCompactBlock,
    accounts: &[WalletScanAccount<'_>],
) -> Result<ScannedBlockUpdate, WalletScanError> {
    let block = authenticated.block();
    if block.chain_id() != tip.chain_id {
        return Err(WalletScanError::WrongNetwork);
    }
    if tip.height.checked_add(1) != Some(block.height()) {
        return Err(WalletScanError::HeightDiscontinuity);
    }
    if block.parent_hash() != tip.block_hash {
        return Err(WalletScanError::ParentMismatch);
    }
    if block.pre_tree_size() != tip.tree.size() || block.pre_tree_root() != tip.tree.typed_root() {
        return Err(WalletScanError::ParentMismatch);
    }
    validate_scan_accounts(accounts)?;
    let scan_account_set_commitment = scan_account_set_commitment(accounts);
    let post_tree = block.verify_tree_transition(&tip.tree)?;

    struct OutputMetadata<'a> {
        transaction_id: TransactionId,
        action_index: u8,
        position: u32,
        nullifier: ActionNullifier,
        output: &'a EncryptedNote,
    }

    let mut metadata = Vec::with_capacity(block.action_count());
    let mut nullifiers = Vec::with_capacity(block.action_count());
    let mut note_commitments = Vec::with_capacity(block.action_count());
    let mut ordinal = 0u64;
    for transaction in block.transactions() {
        for (action_index, action) in transaction.actions().iter().enumerate() {
            let position = block
                .pre_tree_size()
                .checked_add(ordinal)
                .and_then(|position| u32::try_from(position).ok())
                .ok_or(WalletScanError::PositionOverflow)?;
            metadata.push(OutputMetadata {
                transaction_id: transaction.transaction_id(),
                action_index: u8::try_from(action_index)
                    .map_err(|_| WalletScanError::PositionOverflow)?,
                position,
                nullifier: action.nullifier(),
                output: action.output(),
            });
            nullifiers.push(action.nullifier());
            note_commitments.push(action.output().note_commitment());
            ordinal = ordinal
                .checked_add(1)
                .ok_or(WalletScanError::PositionOverflow)?;
        }
    }

    let mut detected_notes = Vec::new();
    let mut owned_nullifiers = BTreeSet::new();
    for chunk in metadata.chunks(MAX_SCAN_BATCH_OUTPUTS) {
        let outputs = chunk
            .iter()
            .map(|item| (item.nullifier, item.output))
            .collect::<Vec<_>>();
        let mut chunk_notes = (0..chunk.len()).map(|_| None).collect::<Vec<_>>();
        for account_batch in accounts.chunks(SCAN_ACCOUNTS_PER_CRYPTO_BATCH) {
            let viewing_keys = account_batch
                .iter()
                .flat_map(|account| {
                    [
                        account.incoming(KeyScope::External),
                        account.incoming(KeyScope::Internal),
                    ]
                })
                .collect::<Vec<_>>();
            let results = scan_incoming_notes(&viewing_keys, &outputs)
                .map_err(|_| WalletScanError::NoteDecryptionFailure)?;
            for (output_index, (item, detected)) in chunk.iter().zip(results).enumerate() {
                let Some(detected) = detected else {
                    continue;
                };
                if chunk_notes[output_index].is_some() {
                    return Err(WalletScanError::NoteDecryptionFailure);
                }
                let viewing_key_index = detected.viewing_key_index();
                let account_index = viewing_key_index / 2;
                let key_scope = if viewing_key_index % 2 == 0 {
                    KeyScope::External
                } else {
                    KeyScope::Internal
                };
                let account = account_batch
                    .get(account_index)
                    .ok_or(WalletScanError::NoteDecryptionFailure)?;
                let decrypted = detected.into_decrypted();
                let spend_nullifier = account
                    .full_viewing_key
                    .note_nullifier(decrypted.note())
                    .map_err(|_| WalletScanError::NullifierDerivationFailure)?;
                if !owned_nullifiers.insert(spend_nullifier) {
                    return Err(WalletScanError::DuplicateOwnedNullifier);
                }
                chunk_notes[output_index] = Some(ScannedNote {
                    transaction_id: item.transaction_id,
                    action_index: item.action_index,
                    position: item.position,
                    action_nullifier: item.nullifier,
                    output: item.output.clone(),
                    account_id: account.account_id,
                    key_scope,
                    spend_nullifier,
                    decrypted,
                });
            }
        }
        detected_notes.extend(chunk_notes.into_iter().flatten());
    }

    Ok(ScannedBlockUpdate {
        expected_parent_height: tip.height,
        expected_parent_hash: tip.block_hash,
        expected_pre_tree_size: tip.tree.size(),
        expected_pre_tree_root: tip.tree.typed_root(),
        compact_commitment: block.commitment(),
        next_tip: WalletScanTip {
            chain_id: tip.chain_id,
            height: block.height(),
            block_hash: block.block_hash(),
            tree: post_tree,
        },
        scan_account_set_commitment,
        nullifiers,
        note_commitments,
        detected_notes,
    })
}

/// Loads the exact durable tip, scans one authenticated finalized block, and
/// commits its complete delta through the storage transaction boundary.
pub fn scan_and_commit<S: FinalizedWalletStore>(
    store: &mut S,
    authenticated: &AuthenticatedCompactBlock,
    accounts: &[WalletScanAccount<'_>],
) -> Result<WalletScanSummary, ScanCommitError<S::Error>> {
    let tip = store.load_tip().map_err(ScanCommitError::Store)?;
    let update =
        scan_finalized_block(&tip, authenticated, accounts).map_err(ScanCommitError::Scan)?;
    let summary = WalletScanSummary {
        height: update.next_tip.height,
        action_count: update.nullifiers.len(),
    };
    store
        .commit_finalized_block(update)
        .map_err(ScanCommitError::Store)?;
    Ok(summary)
}
