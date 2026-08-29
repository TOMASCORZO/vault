//! Rollback-resistant wallet state protocol for platform custody adapters.

use core::fmt;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    EncryptedWalletDb, FinalizedWalletStore, ScannedBlockUpdate, WalletCompactionSummary,
    WalletDbError, WalletScanTip,
};

const ROLLBACK_STATE_VERSION: u8 = 1;
const ROLLBACK_STATE_BYTES: usize = 90;

/// Independently random wallet-database root key held by a platform adapter.
///
/// This key is distinct from the wallet seed and authorizes only database and
/// backup decryption. It is zeroized on drop and intentionally not `Clone`.
pub struct WalletRootKey(Zeroizing<[u8; 32]>);

impl WalletRootKey {
    /// Generates a non-zero root key from the operating-system CSPRNG.
    pub fn generate() -> Result<Self, WalletRootKeyError> {
        let mut bytes = [0; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| WalletRootKeyError::EntropyUnavailable)?;
        Self::from_bytes(bytes)
    }

    /// Imports exactly 32 bytes loaded from a protected platform record.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, WalletRootKeyError> {
        if bytes == [0; 32] {
            return Err(WalletRootKeyError::InvalidKey);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Borrows the root key for the bounded database/backup operation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for WalletRootKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletRootKey(REDACTED)")
    }
}

/// Root-key generation or protected-record failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletRootKeyError {
    /// Operating-system entropy was unavailable.
    EntropyUnavailable,
    /// A protected record contained the forbidden all-zero key.
    InvalidKey,
}

impl fmt::Display for WalletRootKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EntropyUnavailable => "wallet root-key entropy is unavailable",
            Self::InvalidKey => "wallet root key is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WalletRootKeyError {}

/// Protected platform slot for exactly one database root key.
///
/// `create` must be no-clobber and durable. Implementations must restrict
/// access to the intended application/user and document synchronization,
/// backup, authentication prompts, lock-state, and crash-dump behavior.
pub trait WalletRootKeyStore {
    /// Platform adapter failure.
    type Error: std::error::Error;

    /// Stores a new key only when the protected slot is empty.
    fn create(&mut self, root_key: &WalletRootKey) -> Result<bool, Self::Error>;

    /// Loads the existing protected key into zeroizing process memory.
    fn load(&mut self) -> Result<Option<WalletRootKey>, Self::Error>;
}

/// Commitment to one exact encrypted database identity and finalized tip.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WalletRollbackAnchor {
    height: u64,
    commitment: [u8; 32],
}

impl WalletRollbackAnchor {
    pub(crate) fn new(height: u64, commitment: [u8; 32]) -> Result<Self, WalletDbError> {
        if commitment == [0; 32] {
            return Err(WalletDbError::CorruptState);
        }
        Ok(Self { height, commitment })
    }

    /// Exact finalized height bound by this anchor.
    #[must_use]
    pub const fn height(self) -> u64 {
        self.height
    }

    /// Domain-separated commitment to database identity, scope, and full tip.
    #[must_use]
    pub const fn commitment(self) -> [u8; 32] {
        self.commitment
    }
}

impl fmt::Debug for WalletRollbackAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletRollbackAnchor(REDACTED)")
    }
}

/// Canonical two-phase state stored by a rollback-resistant platform adapter.
///
/// The secure store must protect this complete value with atomic compare-and-
/// swap semantics. A pending anchor is deliberately not auto-cleared when the
/// database still matches the stable anchor: after a crash that state is
/// indistinguishable from an attacker rolling back a completed database write.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WalletRollbackState {
    generation: u64,
    stable: WalletRollbackAnchor,
    pending: Option<WalletRollbackAnchor>,
}

impl WalletRollbackState {
    fn initial(stable: WalletRollbackAnchor) -> Self {
        Self {
            generation: 1,
            stable,
            pending: None,
        }
    }

    fn prepare(
        self,
        pending: WalletRollbackAnchor,
    ) -> Result<Self, WalletRollbackError<core::convert::Infallible>> {
        if self.pending.is_some()
            || pending.height()
                != self
                    .stable
                    .height()
                    .checked_add(1)
                    .ok_or(WalletRollbackError::GenerationExhausted)?
            || pending == self.stable
        {
            return Err(WalletRollbackError::InvalidTransition);
        }
        Ok(Self {
            generation: self
                .generation
                .checked_add(1)
                .ok_or(WalletRollbackError::GenerationExhausted)?,
            stable: self.stable,
            pending: Some(pending),
        })
    }

    fn finalize(self) -> Result<Self, WalletRollbackError<core::convert::Infallible>> {
        let pending = self.pending.ok_or(WalletRollbackError::InvalidTransition)?;
        Ok(Self {
            generation: self
                .generation
                .checked_add(1)
                .ok_or(WalletRollbackError::GenerationExhausted)?,
            stable: pending,
            pending: None,
        })
    }

    fn cancel(self) -> Result<Self, WalletRollbackError<core::convert::Infallible>> {
        if self.pending.is_none() {
            return Err(WalletRollbackError::InvalidTransition);
        }
        Ok(Self {
            generation: self
                .generation
                .checked_add(1)
                .ok_or(WalletRollbackError::GenerationExhausted)?,
            stable: self.stable,
            pending: None,
        })
    }

    /// Monotonically increasing secure-store generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Last fully finalized database anchor.
    #[must_use]
    pub const fn stable(self) -> WalletRollbackAnchor {
        self.stable
    }

    /// Prepared successor whose database commit may have completed.
    #[must_use]
    pub const fn pending(self) -> Option<WalletRollbackAnchor> {
        self.pending
    }

    /// Fixed-size canonical encoding for a protected platform record.
    #[must_use]
    pub fn to_bytes(self) -> [u8; ROLLBACK_STATE_BYTES] {
        let mut output = [0; ROLLBACK_STATE_BYTES];
        output[0] = ROLLBACK_STATE_VERSION;
        output[1..9].copy_from_slice(&self.generation.to_be_bytes());
        output[9..17].copy_from_slice(&self.stable.height.to_be_bytes());
        output[17..49].copy_from_slice(&self.stable.commitment);
        if let Some(pending) = self.pending {
            output[49] = 1;
            output[50..58].copy_from_slice(&pending.height.to_be_bytes());
            output[58..90].copy_from_slice(&pending.commitment);
        }
        output
    }

    /// Parses and validates the exact protected platform record.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletRollbackStateError> {
        if bytes.len() != ROLLBACK_STATE_BYTES || bytes[0] != ROLLBACK_STATE_VERSION {
            return Err(WalletRollbackStateError);
        }
        let generation = u64::from_be_bytes(
            bytes[1..9]
                .try_into()
                .map_err(|_| WalletRollbackStateError)?,
        );
        let stable = WalletRollbackAnchor {
            height: u64::from_be_bytes(
                bytes[9..17]
                    .try_into()
                    .map_err(|_| WalletRollbackStateError)?,
            ),
            commitment: bytes[17..49]
                .try_into()
                .map_err(|_| WalletRollbackStateError)?,
        };
        let pending = match bytes[49] {
            0 if bytes[50..].iter().all(|byte| *byte == 0) => None,
            1 => Some(WalletRollbackAnchor {
                height: u64::from_be_bytes(
                    bytes[50..58]
                        .try_into()
                        .map_err(|_| WalletRollbackStateError)?,
                ),
                commitment: bytes[58..90]
                    .try_into()
                    .map_err(|_| WalletRollbackStateError)?,
            }),
            _ => return Err(WalletRollbackStateError),
        };
        let state = Self {
            generation,
            stable,
            pending,
        };
        if generation == 0
            || stable.commitment == [0; 32]
            || pending.is_some_and(|anchor| {
                anchor.commitment == [0; 32]
                    || anchor == stable
                    || stable.height.checked_add(1) != Some(anchor.height)
            })
        {
            return Err(WalletRollbackStateError);
        }
        Ok(state)
    }
}

impl fmt::Debug for WalletRollbackState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletRollbackState(REDACTED)")
    }
}

/// Invalid canonical rollback-state record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletRollbackStateError;

impl fmt::Display for WalletRollbackStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("wallet rollback state is invalid")
    }
}

impl std::error::Error for WalletRollbackStateError {}

/// Atomic, durable, rollback-resistant platform state for exactly one wallet.
///
/// Implementations must bind the instance to one protected keychain/secure-
/// element slot. `compare_and_swap` must replace the complete fixed-size state
/// only when the stored value exactly equals `expected`, survive power loss,
/// and reject host-controlled rollback. An ordinary file does not implement
/// this security contract.
pub trait WalletSecureRollbackStore {
    /// Platform adapter failure.
    type Error: std::error::Error;

    /// Loads the complete protected state, or `None` for an unused slot.
    fn load(&mut self) -> Result<Option<WalletRollbackState>, Self::Error>;

    /// Atomically compares and replaces the complete protected state.
    fn compare_and_swap(
        &mut self,
        expected: Option<&WalletRollbackState>,
        replacement: &WalletRollbackState,
    ) -> Result<bool, Self::Error>;
}

/// Failure from the database/secure-state two-phase protocol.
pub enum WalletRollbackError<E> {
    /// Encrypted wallet database operation failed.
    Database(WalletDbError),
    /// Platform secure-state adapter failed.
    SecureStore(E),
    /// The protected slot was already enrolled.
    AlreadyEnrolled,
    /// The protected slot has not been enrolled.
    NotEnrolled,
    /// Atomic compare-and-swap observed an unexpected value.
    ConcurrentModification,
    /// Database state does not match the protected stable or pending anchor.
    RollbackDetected,
    /// A crash left a prepared transition while the database still matches the
    /// old stable anchor; clearing it automatically could accept an attack.
    AmbiguousPendingTransition,
    /// Anchor height/generation arithmetic or state transition was invalid.
    InvalidTransition,
    /// Protected generation space was exhausted.
    GenerationExhausted,
    /// This wrapper is unusable after an uncertain outcome.
    Poisoned,
}

impl<E> fmt::Debug for WalletRollbackError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletRollbackError(REDACTED)")
    }
}

impl<E> fmt::Display for WalletRollbackError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Database(_) => "wallet database operation failed",
            Self::SecureStore(_) => "wallet secure rollback store failed",
            Self::AlreadyEnrolled => "wallet rollback slot is already enrolled",
            Self::NotEnrolled => "wallet rollback slot is not enrolled",
            Self::ConcurrentModification => "wallet rollback state changed concurrently",
            Self::RollbackDetected => "wallet database rollback was detected",
            Self::AmbiguousPendingTransition => "wallet rollback transition is ambiguous",
            Self::InvalidTransition => "wallet rollback transition is invalid",
            Self::GenerationExhausted => "wallet rollback generation is exhausted",
            Self::Poisoned => "wallet rollback-protected handle is poisoned",
        };
        formatter.write_str(message)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for WalletRollbackError<E> {}

/// Encrypted wallet coupled to a rollback-resistant two-phase state slot.
pub struct RollbackProtectedWalletDb<S> {
    database: EncryptedWalletDb,
    store: S,
    state: WalletRollbackState,
    poisoned: bool,
}

impl<S> fmt::Debug for RollbackProtectedWalletDb<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RollbackProtectedWalletDb(REDACTED)")
    }
}

impl<S: WalletSecureRollbackStore> RollbackProtectedWalletDb<S> {
    /// Enrolls a newly created or independently trusted database into an empty
    /// secure slot. Production enrollment must happen in the creation/recovery
    /// ceremony before the database can be exposed to rollback.
    pub fn enroll(
        database: EncryptedWalletDb,
        mut store: S,
    ) -> Result<Self, WalletRollbackError<S::Error>> {
        if store
            .load()
            .map_err(WalletRollbackError::SecureStore)?
            .is_some()
        {
            return Err(WalletRollbackError::AlreadyEnrolled);
        }
        let state = WalletRollbackState::initial(
            database
                .rollback_anchor()
                .map_err(WalletRollbackError::Database)?,
        );
        if !store
            .compare_and_swap(None, &state)
            .map_err(WalletRollbackError::SecureStore)?
        {
            return Err(WalletRollbackError::ConcurrentModification);
        }
        if store.load().map_err(WalletRollbackError::SecureStore)? != Some(state) {
            return Err(WalletRollbackError::ConcurrentModification);
        }
        Ok(Self {
            database,
            store,
            state,
            poisoned: false,
        })
    }

    /// Opens a database against an existing protected slot and resolves only
    /// the unambiguous `database == pending` crash case.
    pub fn open(
        database: EncryptedWalletDb,
        mut store: S,
    ) -> Result<Self, WalletRollbackError<S::Error>> {
        let mut state = store
            .load()
            .map_err(WalletRollbackError::SecureStore)?
            .ok_or(WalletRollbackError::NotEnrolled)?;
        let current = database
            .rollback_anchor()
            .map_err(WalletRollbackError::Database)?;
        match state.pending {
            None if current == state.stable => {}
            Some(pending) if current == pending => {
                let replacement = state.finalize().map_err(map_infallible_transition_error)?;
                if !store
                    .compare_and_swap(Some(&state), &replacement)
                    .map_err(WalletRollbackError::SecureStore)?
                {
                    return Err(WalletRollbackError::ConcurrentModification);
                }
                state = replacement;
            }
            Some(_) if current == state.stable => {
                return Err(WalletRollbackError::AmbiguousPendingTransition);
            }
            None | Some(_) => return Err(WalletRollbackError::RollbackDetected),
        }
        Ok(Self {
            database,
            store,
            state,
            poisoned: false,
        })
    }

    /// Read-only access to authenticated wallet operations.
    #[must_use]
    pub const fn database(&self) -> &EncryptedWalletDb {
        &self.database
    }

    /// Current finalized secure-state generation.
    #[must_use]
    pub const fn rollback_state(&self) -> WalletRollbackState {
        self.state
    }

    /// Compacts without changing the rollback anchor, then verifies it still
    /// equals the protected stable value.
    pub fn compact(&mut self) -> Result<WalletCompactionSummary, WalletRollbackError<S::Error>> {
        if self.poisoned {
            return Err(WalletRollbackError::Poisoned);
        }
        let summary = self
            .database
            .compact()
            .map_err(WalletRollbackError::Database)?;
        if self
            .database
            .rollback_anchor()
            .map_err(WalletRollbackError::Database)?
            != self.state.stable
        {
            self.poisoned = true;
            return Err(WalletRollbackError::RollbackDetected);
        }
        Ok(summary)
    }

    fn commit(&mut self, update: ScannedBlockUpdate) -> Result<(), WalletRollbackError<S::Error>> {
        if self.poisoned {
            return Err(WalletRollbackError::Poisoned);
        }
        let current_tip = self
            .database
            .load_tip()
            .map_err(WalletRollbackError::Database)?;
        let current = self
            .database
            .rollback_anchor()
            .map_err(WalletRollbackError::Database)?;
        if self.state.pending.is_some() || current != self.state.stable {
            self.poisoned = true;
            return Err(WalletRollbackError::RollbackDetected);
        }
        if update.expected_parent_height() != current_tip.height()
            || update.expected_parent_hash() != current_tip.block_hash()
            || update.expected_pre_tree_size() != current_tip.tree_size()
            || update.expected_pre_tree_root() != current_tip.tree_root()
        {
            return Err(WalletRollbackError::Database(WalletDbError::TipMismatch));
        }
        let pending_anchor = self
            .database
            .rollback_anchor_for_tip(update.next_tip())
            .map_err(WalletRollbackError::Database)?;
        let prepared = self
            .state
            .prepare(pending_anchor)
            .map_err(map_infallible_transition_error)?;
        if !self
            .store
            .compare_and_swap(Some(&self.state), &prepared)
            .map_err(WalletRollbackError::SecureStore)?
        {
            self.poisoned = true;
            return Err(WalletRollbackError::ConcurrentModification);
        }

        match self.database.commit_finalized_block(update) {
            Ok(()) => {
                let finalized = prepared
                    .finalize()
                    .map_err(map_infallible_transition_error)?;
                match self.store.compare_and_swap(Some(&prepared), &finalized) {
                    Ok(true) => {
                        self.state = finalized;
                        Ok(())
                    }
                    Ok(false) => {
                        self.poisoned = true;
                        Err(WalletRollbackError::ConcurrentModification)
                    }
                    Err(error) => {
                        self.poisoned = true;
                        Err(WalletRollbackError::SecureStore(error))
                    }
                }
            }
            Err(error) if error != WalletDbError::Poisoned => {
                let cancelled = prepared.cancel().map_err(map_infallible_transition_error)?;
                match self.store.compare_and_swap(Some(&prepared), &cancelled) {
                    Ok(true) => {
                        self.state = cancelled;
                        Err(WalletRollbackError::Database(error))
                    }
                    Ok(false) => {
                        self.poisoned = true;
                        Err(WalletRollbackError::ConcurrentModification)
                    }
                    Err(store_error) => {
                        self.poisoned = true;
                        Err(WalletRollbackError::SecureStore(store_error))
                    }
                }
            }
            Err(error) => {
                self.poisoned = true;
                Err(WalletRollbackError::Database(error))
            }
        }
    }
}

impl<S> FinalizedWalletStore for RollbackProtectedWalletDb<S>
where
    S: WalletSecureRollbackStore,
    S::Error: 'static,
{
    type Error = WalletRollbackError<S::Error>;

    fn load_tip(&self) -> Result<WalletScanTip, Self::Error> {
        if self.poisoned {
            return Err(WalletRollbackError::Poisoned);
        }
        self.database
            .load_tip()
            .map_err(WalletRollbackError::Database)
    }

    fn commit_finalized_block(&mut self, update: ScannedBlockUpdate) -> Result<(), Self::Error> {
        self.commit(update)
    }
}

fn map_infallible_transition_error<E>(
    error: WalletRollbackError<core::convert::Infallible>,
) -> WalletRollbackError<E> {
    match error {
        WalletRollbackError::InvalidTransition => WalletRollbackError::InvalidTransition,
        WalletRollbackError::GenerationExhausted => WalletRollbackError::GenerationExhausted,
        WalletRollbackError::Database(_)
        | WalletRollbackError::SecureStore(_)
        | WalletRollbackError::AlreadyEnrolled
        | WalletRollbackError::NotEnrolled
        | WalletRollbackError::ConcurrentModification
        | WalletRollbackError::RollbackDetected
        | WalletRollbackError::AmbiguousPendingTransition
        | WalletRollbackError::Poisoned => unreachable!("internal transition error is bounded"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_state_codec_is_exact_and_rejects_noncanonical_records() {
        let stable = WalletRollbackAnchor::new(7, [0x11; 32]).unwrap();
        let pending = WalletRollbackAnchor::new(8, [0x22; 32]).unwrap();
        let initial = WalletRollbackState::initial(stable);
        assert_eq!(
            WalletRollbackState::from_bytes(&initial.to_bytes()).unwrap(),
            initial
        );
        let prepared = initial.prepare(pending).unwrap();
        assert_eq!(
            WalletRollbackState::from_bytes(&prepared.to_bytes()).unwrap(),
            prepared
        );
        assert_eq!(prepared.finalize().unwrap().stable(), pending);

        for length in 0..ROLLBACK_STATE_BYTES {
            assert!(WalletRollbackState::from_bytes(&prepared.to_bytes()[..length]).is_err());
        }
        let mut unknown_version = initial.to_bytes();
        unknown_version[0] = 2;
        assert!(WalletRollbackState::from_bytes(&unknown_version).is_err());
        let mut noncanonical_absent = initial.to_bytes();
        noncanonical_absent[89] = 1;
        assert!(WalletRollbackState::from_bytes(&noncanonical_absent).is_err());
        let mut skipped_height = prepared.to_bytes();
        skipped_height[50..58].copy_from_slice(&9u64.to_be_bytes());
        assert!(WalletRollbackState::from_bytes(&skipped_height).is_err());
    }

    #[test]
    fn root_key_type_rejects_zero_and_redacts_diagnostics() {
        assert_eq!(
            WalletRootKey::from_bytes([0; 32]).unwrap_err(),
            WalletRootKeyError::InvalidKey
        );
        let key = WalletRootKey::from_bytes([0xA5; 32]).unwrap();
        assert_eq!(key.as_bytes(), &[0xA5; 32]);
        assert_eq!(format!("{key:?}"), "WalletRootKey(REDACTED)");
    }
}
