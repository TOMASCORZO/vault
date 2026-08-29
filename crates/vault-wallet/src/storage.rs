//! Encrypted transactional finalized-wallet persistence.
//!
//! SQLite provides the atomic commit boundary; every wallet-private payload is
//! independently authenticated with XChaCha20-Poly1305 and fresh randomness.
//! ShardTree maintains marked-note witnesses and finalized checkpoints inside
//! the same SQL transaction as notes and the scan tip. Table cardinality,
//! shard indices, checkpoint heights, file size, and I/O timing remain local
//! metadata leakage and are explicit H1 network/side-channel gates.

mod backup;

pub use backup::{WalletBackupSummary, WalletRestoreDrillSummary};

use core::fmt;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use blake3::Hasher;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use fs2::FileExt;
use incrementalmerkletree::{Address, Level, Marking, Position, Retention, frontier::Frontier};
use orchard::tree::MerkleHashOrchard;
use rand_core::{OsRng, RngCore};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use shardtree::{
    LocatedPrunableTree, Node, PrunableTree, RetentionFlags, ShardTree, Tree,
    store::{Checkpoint, ShardStore, TreeState},
};
use vault_privacy::{
    ActionNullifier, DECRYPTED_NOTE_BYTES, DecryptedNote, KeyScope, NOTE_TREE_DEPTH,
    NoteMembershipPath, NoteTreeRoot, NoteTreeSnapshot,
};
use vault_protocol::{ChainId, TransactionId};
use zeroize::Zeroizing;

use crate::{
    FinalizedWalletStore, ScannedBlockUpdate, WalletAccountId, WalletBirthdayCheckpoint,
    WalletRecoveryPlan, WalletRecoveryStatus, WalletRecoveryTarget, WalletRollbackAnchor,
    WalletScanTip,
};

const LEGACY_SCHEMA_VERSION: u32 = 1;
const SCHEMA_VERSION: u32 = 2;
const SHARD_HEIGHT: u8 = 16;
const MAX_CHECKPOINTS_LIMIT: usize = 4_096;
const MAX_DATABASE_CHECKPOINT_ROWS: usize = 8_192;
const MAX_ENCRYPTED_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_TREE_CODEC_NODES: usize = 262_143;
const KEY_CHECK_PLAINTEXT: &[u8] = b"vault-wallet-db-key-check-v1";
const MASTER_KEY_DOMAIN: &str = "vault.wallet-db-v1.master-key.2026-08-23";
const INDEX_KEY_DOMAIN: &str = "vault.wallet-db-v1.nullifier-index-key.2026-08-23";
const ROLLBACK_ANCHOR_DOMAIN: &str = "vault.wallet.rollback-anchor-v1.2026-08-27";
const NULLIFIER_TAG_DOMAIN: &[u8] = b"vault.wallet-db-v1.nullifier-tag.2026-08-23";
const RECORD_AAD_DOMAIN: &[u8] = b"vault.wallet-db-v1.record-aad.2026-08-23";
const NOTE_RECORD_BYTES: usize =
    1 + 32 + 1 + 4 + 32 + 1 + 32 + 32 + 32 + 1 + 8 + DECRYPTED_NOTE_BYTES;

type WalletShardTree<'a> = ShardTree<SqliteShardStore<'a>, NOTE_TREE_DEPTH, SHARD_HEIGHT>;

/// Fail-closed encrypted wallet database error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletDbError {
    /// The path is not an absolute canonical path under a protected directory.
    InvalidPath,
    /// The target database already exists.
    AlreadyExists,
    /// The requested database does not exist.
    Missing,
    /// Another process owns the wallet database lock.
    Locked,
    /// File type, ownership, link count, or permissions are unsafe.
    UnsafeFile,
    /// The platform cannot provide the required no-follow/permission controls.
    UnsupportedPlatform,
    /// Randomness for a database identity or AEAD nonce was unavailable.
    EntropyUnavailable,
    /// The database engine rejected an operation.
    DatabaseFailure,
    /// The root key is wrong or an encrypted record failed authentication.
    AuthenticationFailed,
    /// Schema, canonical encoding, or authenticated state is inconsistent.
    CorruptState,
    /// The database schema is not accepted by this operation.
    UnsupportedSchema,
    /// The legacy database cannot be upgraded without losing recovery state.
    UnsupportedMigration,
    /// The opened database belongs to another network or wallet identity.
    ScopeMismatch,
    /// The authenticated tip is older than the caller's secure monotonic floor.
    RollbackDetected,
    /// The database configuration violates production resource bounds.
    InvalidConfiguration,
    /// Ordinary creation cannot bypass the explicit birthday-recovery path.
    NonEmptyInitializationUnsupported,
    /// The store tip changed relative to the scanner's authenticated parent.
    TipMismatch,
    /// ShardTree insertion, checkpoint, root, or witness validation failed.
    WitnessStateFailure,
    /// The requested owned note does not exist.
    NoteNotFound,
    /// The requested note has already been spent in finalized state.
    NoteAlreadySpent,
    /// Seed recovery has not satisfied its finalized target and account gap.
    RecoveryIncomplete,
    /// A scan update was produced with a different seed account set.
    RecoveryAccountMismatch,
    /// The recovery scan did not arrive at the exact finalized target.
    RecoveryTargetMismatch,
    /// Used accounts reached too near the configured upper account bound.
    RecoveryAccountRangeExhausted,
    /// The handle is poisoned after an uncertain commit or rollback outcome.
    Poisoned,
    /// The backup container is malformed, non-canonical, or inconsistent.
    InvalidBackup,
    /// The backup snapshot exceeds the fixed v1 resource limit.
    BackupTooLarge,
}

impl fmt::Display for WalletDbError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPath => "wallet database path is not protected and canonical",
            Self::AlreadyExists => "wallet database already exists",
            Self::Missing => "wallet database does not exist",
            Self::Locked => "wallet database is locked by another process",
            Self::UnsafeFile => "wallet database file metadata is unsafe",
            Self::UnsupportedPlatform => "wallet database platform controls are unsupported",
            Self::EntropyUnavailable => "wallet database entropy source failed",
            Self::DatabaseFailure => "wallet database engine operation failed",
            Self::AuthenticationFailed => "wallet database authentication failed",
            Self::CorruptState => "wallet database state is corrupt",
            Self::UnsupportedSchema => "wallet database schema is unsupported",
            Self::UnsupportedMigration => "wallet database migration is unsupported",
            Self::ScopeMismatch => "wallet database scope does not match the caller",
            Self::RollbackDetected => "wallet database rollback was detected",
            Self::InvalidConfiguration => "wallet database configuration is invalid",
            Self::NonEmptyInitializationUnsupported => {
                "wallet database initialization requires the explicit recovery path"
            }
            Self::TipMismatch => "wallet database tip does not match the scanned parent",
            Self::WitnessStateFailure => "wallet witness state transition failed",
            Self::NoteNotFound => "wallet note was not found",
            Self::NoteAlreadySpent => "wallet note is already spent",
            Self::RecoveryIncomplete => "wallet seed recovery is incomplete",
            Self::RecoveryAccountMismatch => {
                "wallet scan account set does not match the recovery plan"
            }
            Self::RecoveryTargetMismatch => {
                "wallet recovery did not match its exact finalized target"
            }
            Self::RecoveryAccountRangeExhausted => {
                "wallet recovery requires a larger account range"
            }
            Self::Poisoned => "wallet database handle is poisoned",
            Self::InvalidBackup => "wallet backup is invalid",
            Self::BackupTooLarge => "wallet backup exceeds the v1 size limit",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WalletDbError {}

/// Immutable parameters committed when a wallet database is created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletDatabaseConfig {
    wallet_id: [u8; 32],
    maximum_note_value: u64,
    max_checkpoints: usize,
}

impl WalletDatabaseConfig {
    /// Validates a random wallet-instance ID and bounded witness policy.
    pub fn new(
        wallet_id: [u8; 32],
        maximum_note_value: u64,
        max_checkpoints: usize,
    ) -> Result<Self, WalletDbError> {
        if wallet_id == [0; 32]
            || maximum_note_value == 0
            || max_checkpoints == 0
            || max_checkpoints > MAX_CHECKPOINTS_LIMIT
        {
            return Err(WalletDbError::InvalidConfiguration);
        }
        Ok(Self {
            wallet_id,
            maximum_note_value,
            max_checkpoints,
        })
    }

    /// Opaque database scope used for backup/mix-up protection.
    #[must_use]
    pub const fn wallet_id(self) -> [u8; 32] {
        self.wallet_id
    }

    /// Maximum accepted private note value.
    #[must_use]
    pub const fn maximum_note_value(self) -> u64 {
        self.maximum_note_value
    }

    /// Number of ordinary finalized checkpoints retained by ShardTree.
    #[must_use]
    pub const fn max_checkpoints(self) -> usize {
        self.max_checkpoints
    }
}

/// Private note plus a current finalized Merkle witness.
pub struct WalletSpendWitness {
    account_id: WalletAccountId,
    key_scope: KeyScope,
    transaction_id: TransactionId,
    action_index: u8,
    action_nullifier: ActionNullifier,
    spend_nullifier: ActionNullifier,
    decrypted: DecryptedNote,
    membership_path: NoteMembershipPath,
    anchor: [u8; 32],
    checkpoint_height: u64,
}

impl fmt::Debug for WalletSpendWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletSpendWitness(REDACTED)")
    }
}

impl WalletSpendWitness {
    /// Owning wallet-local account.
    #[must_use]
    pub const fn account_id(&self) -> WalletAccountId {
        self.account_id
    }

    /// Recipient or change scope used by the note.
    #[must_use]
    pub const fn key_scope(&self) -> KeyScope {
        self.key_scope
    }

    /// Transaction that created the note.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Action index that created the note.
    #[must_use]
    pub const fn action_index(&self) -> u8 {
        self.action_index
    }

    /// Public action nullifier used as the note's `rho`.
    #[must_use]
    pub const fn action_nullifier(&self) -> ActionNullifier {
        self.action_nullifier
    }

    /// Future public nullifier for this spend.
    #[must_use]
    pub const fn spend_nullifier(&self) -> ActionNullifier {
        self.spend_nullifier
    }

    /// Authenticated note and private memo.
    #[must_use]
    pub const fn decrypted(&self) -> &DecryptedNote {
        &self.decrypted
    }

    /// Current depth-32 authentication path.
    #[must_use]
    pub const fn membership_path(&self) -> &NoteMembershipPath {
        &self.membership_path
    }

    /// Finalized anchor authenticated by the local chain tip.
    #[must_use]
    pub const fn anchor(&self) -> [u8; 32] {
        self.anchor
    }

    /// Finalized checkpoint at which the path and anchor are valid.
    #[must_use]
    pub const fn checkpoint_height(&self) -> u64 {
        self.checkpoint_height
    }
}

struct WalletDbCrypto {
    schema_version: u32,
    database_id: [u8; 32],
    chain_id: ChainId,
    wallet_id: [u8; 32],
    encryption_key: Zeroizing<[u8; 32]>,
    index_key: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum RecordKind {
    KeyCheck = 1,
    Tip = 2,
    Shard = 3,
    Cap = 4,
    Checkpoint = 5,
    Note = 6,
    RetainedCheckpoint = 7,
    Origin = 8,
    Recovery = 9,
}

impl WalletDbCrypto {
    fn derive(
        root_key: &[u8; 32],
        database_id: [u8; 32],
        chain_id: ChainId,
        wallet_id: [u8; 32],
        maximum_note_value: u64,
        max_checkpoints: usize,
    ) -> Self {
        Self::derive_for_schema(
            root_key,
            database_id,
            chain_id,
            wallet_id,
            maximum_note_value,
            max_checkpoints,
            SCHEMA_VERSION,
        )
    }

    fn derive_for_schema(
        root_key: &[u8; 32],
        database_id: [u8; 32],
        chain_id: ChainId,
        wallet_id: [u8; 32],
        maximum_note_value: u64,
        max_checkpoints: usize,
        schema_version: u32,
    ) -> Self {
        fn derive_subkey(
            domain: &str,
            root_key: &[u8; 32],
            database_id: &[u8; 32],
            chain_id: &ChainId,
            wallet_id: &[u8; 32],
            maximum_note_value: u64,
            max_checkpoints: usize,
        ) -> Zeroizing<[u8; 32]> {
            let mut hasher = Hasher::new_derive_key(domain);
            hasher.update(root_key);
            hasher.update(database_id);
            hasher.update(chain_id.as_bytes());
            hasher.update(wallet_id);
            hasher.update(&maximum_note_value.to_be_bytes());
            hasher.update(
                &u64::try_from(max_checkpoints)
                    .expect("bounded checkpoint count fits u64")
                    .to_be_bytes(),
            );
            Zeroizing::new(*hasher.finalize().as_bytes())
        }

        Self {
            schema_version,
            database_id,
            chain_id,
            wallet_id,
            encryption_key: derive_subkey(
                MASTER_KEY_DOMAIN,
                root_key,
                &database_id,
                &chain_id,
                &wallet_id,
                maximum_note_value,
                max_checkpoints,
            ),
            index_key: derive_subkey(
                INDEX_KEY_DOMAIN,
                root_key,
                &database_id,
                &chain_id,
                &wallet_id,
                maximum_note_value,
                max_checkpoints,
            ),
        }
    }

    fn aad(&self, kind: RecordKind, record_key: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            RECORD_AAD_DOMAIN.len() + 4 + 32 + 32 + 32 + 1 + 2 + record_key.len(),
        );
        aad.extend_from_slice(RECORD_AAD_DOMAIN);
        aad.extend_from_slice(&self.schema_version.to_be_bytes());
        aad.extend_from_slice(&self.database_id);
        aad.extend_from_slice(self.chain_id.as_bytes());
        aad.extend_from_slice(&self.wallet_id);
        aad.push(kind as u8);
        aad.extend_from_slice(
            &u16::try_from(record_key.len())
                .expect("wallet record keys are statically bounded")
                .to_be_bytes(),
        );
        aad.extend_from_slice(record_key);
        aad
    }

    fn seal(
        &self,
        kind: RecordKind,
        record_key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, WalletDbError> {
        if plaintext.len() > MAX_ENCRYPTED_PLAINTEXT_BYTES {
            return Err(WalletDbError::CorruptState);
        }
        let mut nonce = [0; 24];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| WalletDbError::EntropyUnavailable)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.encryption_key.as_ref()));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &self.aad(kind, record_key),
                },
            )
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        let mut encoded = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
        encoded.push(1);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        Ok(encoded)
    }

    fn open(
        &self,
        kind: RecordKind,
        record_key: &[u8],
        encoded: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, WalletDbError> {
        if encoded.len() < 1 + 24 + 16
            || encoded.len() > 1 + 24 + 16 + MAX_ENCRYPTED_PLAINTEXT_BYTES
            || encoded[0] != 1
        {
            return Err(WalletDbError::CorruptState);
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.encryption_key.as_ref()));
        cipher
            .decrypt(
                XNonce::from_slice(&encoded[1..25]),
                Payload {
                    msg: &encoded[25..],
                    aad: &self.aad(kind, record_key),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| WalletDbError::AuthenticationFailed)
    }

    fn nullifier_tag(&self, nullifier: ActionNullifier) -> [u8; 32] {
        let mut hasher = Hasher::new_keyed(&self.index_key);
        hasher.update(NULLIFIER_TAG_DOMAIN);
        hasher.update(&nullifier.to_bytes());
        *hasher.finalize().as_bytes()
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    nodes: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            nodes: 0,
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WalletDbError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WalletDbError::CorruptState)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(WalletDbError::CorruptState)?;
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self) -> Result<u8, WalletDbError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, WalletDbError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| WalletDbError::CorruptState)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, WalletDbError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| WalletDbError::CorruptState)?,
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WalletDbError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WalletDbError::CorruptState)
    }

    fn count_node(&mut self) -> Result<(), WalletDbError> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(WalletDbError::CorruptState)?;
        if self.nodes > MAX_TREE_CODEC_NODES {
            return Err(WalletDbError::CorruptState);
        }
        Ok(())
    }

    fn finish(self) -> Result<(), WalletDbError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WalletDbError::CorruptState)
        }
    }
}

fn parse_merkle_hash(bytes: [u8; 32]) -> Result<MerkleHashOrchard, WalletDbError> {
    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes))
        .ok_or(WalletDbError::CorruptState)
}

fn encode_tree_node(
    tree: &PrunableTree<MerkleHashOrchard>,
    output: &mut Vec<u8>,
) -> Result<(), WalletDbError> {
    if output.len() > MAX_ENCRYPTED_PLAINTEXT_BYTES {
        return Err(WalletDbError::CorruptState);
    }
    match &**tree {
        Node::Nil => output.push(0),
        Node::Leaf {
            value: (hash, flags),
        } => {
            output.push(1);
            output.extend_from_slice(&hash.to_bytes());
            output.push(flags.bits());
        }
        Node::Parent { ann, left, right } => {
            output.push(2);
            match ann {
                Some(hash) => {
                    output.push(1);
                    output.extend_from_slice(&hash.to_bytes());
                }
                None => output.push(0),
            }
            encode_tree_node(left, output)?;
            encode_tree_node(right, output)?;
        }
    }
    Ok(())
}

fn encode_tree(tree: &PrunableTree<MerkleHashOrchard>) -> Result<Vec<u8>, WalletDbError> {
    let mut output = Vec::new();
    encode_tree_node(tree, &mut output)?;
    if output.len() > MAX_ENCRYPTED_PLAINTEXT_BYTES {
        return Err(WalletDbError::CorruptState);
    }
    Ok(output)
}

fn decode_tree_node(
    decoder: &mut Decoder<'_>,
    remaining_depth: u8,
) -> Result<PrunableTree<MerkleHashOrchard>, WalletDbError> {
    decoder.count_node()?;
    match decoder.u8()? {
        0 => Ok(Tree::empty()),
        1 => {
            let hash = parse_merkle_hash(decoder.array()?)?;
            let flags =
                RetentionFlags::from_bits(decoder.u8()?).ok_or(WalletDbError::CorruptState)?;
            Ok(Tree::leaf((hash, flags)))
        }
        2 if remaining_depth > 0 => {
            let annotation = match decoder.u8()? {
                0 => None,
                1 => Some(Arc::new(parse_merkle_hash(decoder.array()?)?)),
                _ => return Err(WalletDbError::CorruptState),
            };
            let left = decode_tree_node(decoder, remaining_depth - 1)?;
            let right = decode_tree_node(decoder, remaining_depth - 1)?;
            if left.is_empty() && right.is_empty() {
                return Err(WalletDbError::CorruptState);
            }
            Ok(Tree::parent(annotation, left, right))
        }
        _ => Err(WalletDbError::CorruptState),
    }
}

fn decode_tree(
    bytes: &[u8],
    maximum_depth: u8,
) -> Result<PrunableTree<MerkleHashOrchard>, WalletDbError> {
    if bytes.is_empty() || bytes.len() > MAX_ENCRYPTED_PLAINTEXT_BYTES {
        return Err(WalletDbError::CorruptState);
    }
    let mut decoder = Decoder::new(bytes);
    let tree = decode_tree_node(&mut decoder, maximum_depth)?;
    decoder.finish()?;
    Ok(tree)
}

fn encode_checkpoint(checkpoint: &Checkpoint) -> Result<Vec<u8>, WalletDbError> {
    let mut output = Vec::with_capacity(1 + 8 + 4 + checkpoint.marks_removed().len() * 8);
    match checkpoint.tree_state() {
        TreeState::Empty => output.push(0),
        TreeState::AtPosition(position) => {
            output.push(1);
            output.extend_from_slice(&u64::from(position).to_be_bytes());
        }
    }
    output.extend_from_slice(
        &u32::try_from(checkpoint.marks_removed().len())
            .map_err(|_| WalletDbError::CorruptState)?
            .to_be_bytes(),
    );
    for position in checkpoint.marks_removed() {
        output.extend_from_slice(&u64::from(*position).to_be_bytes());
    }
    if output.len() > MAX_ENCRYPTED_PLAINTEXT_BYTES {
        return Err(WalletDbError::CorruptState);
    }
    Ok(output)
}

fn decode_checkpoint(bytes: &[u8]) -> Result<Checkpoint, WalletDbError> {
    let mut decoder = Decoder::new(bytes);
    let tree_state = match decoder.u8()? {
        0 => TreeState::Empty,
        1 => TreeState::AtPosition(Position::from(decoder.u64()?)),
        _ => return Err(WalletDbError::CorruptState),
    };
    let count = usize::try_from(decoder.u32()?).map_err(|_| WalletDbError::CorruptState)?;
    if count > MAX_ENCRYPTED_PLAINTEXT_BYTES / 8 {
        return Err(WalletDbError::CorruptState);
    }
    let mut marks_removed = BTreeSet::new();
    for _ in 0..count {
        if !marks_removed.insert(Position::from(decoder.u64()?)) {
            return Err(WalletDbError::CorruptState);
        }
    }
    decoder.finish()?;
    Ok(Checkpoint::from_parts(tree_state, marks_removed))
}

fn encode_tip(tip: &WalletScanTip) -> Result<Vec<u8>, WalletDbError> {
    let snapshot = tip.tree_snapshot();
    let mut output = Vec::with_capacity(1 + 32 + 8 + 32 + 8 + 1 + 32 + 1 + 32 * 32);
    output.push(1);
    output.extend_from_slice(tip.chain_id().as_bytes());
    output.extend_from_slice(&tip.height().to_be_bytes());
    output.extend_from_slice(&tip.block_hash());
    output.extend_from_slice(&snapshot.tree_size().to_be_bytes());
    match snapshot.leaf() {
        Some(leaf) => {
            output.push(1);
            output.extend_from_slice(&leaf);
        }
        None => output.push(0),
    }
    output.push(u8::try_from(snapshot.ommers().len()).map_err(|_| WalletDbError::CorruptState)?);
    for ommer in snapshot.ommers() {
        output.extend_from_slice(ommer);
    }
    Ok(output)
}

fn decode_tip(bytes: &[u8]) -> Result<WalletScanTip, WalletDbError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.u8()? != 1 {
        return Err(WalletDbError::CorruptState);
    }
    let chain_id = ChainId::new(decoder.array()?);
    let height = decoder.u64()?;
    let block_hash = decoder.array()?;
    let tree_size = decoder.u64()?;
    let leaf = match decoder.u8()? {
        0 => None,
        1 => Some(decoder.array()?),
        _ => return Err(WalletDbError::CorruptState),
    };
    let ommer_count = usize::from(decoder.u8()?);
    if ommer_count > usize::from(NOTE_TREE_DEPTH) {
        return Err(WalletDbError::CorruptState);
    }
    let mut ommers = Vec::with_capacity(ommer_count);
    for _ in 0..ommer_count {
        ommers.push(decoder.array()?);
    }
    decoder.finish()?;
    WalletScanTip::from_verified_checkpoint(
        chain_id,
        height,
        block_hash,
        &NoteTreeSnapshot::from_parts(tree_size, leaf, ommers),
    )
    .map_err(|_| WalletDbError::CorruptState)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WalletOriginKind {
    Genesis,
    Birthday,
}

struct WalletOrigin {
    kind: WalletOriginKind,
    tip: WalletScanTip,
}

impl fmt::Debug for WalletOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletOrigin(REDACTED)")
    }
}

fn encode_origin(origin: &WalletOrigin) -> Result<Vec<u8>, WalletDbError> {
    let encoded_tip = encode_tip(&origin.tip)?;
    let mut output = Vec::with_capacity(2 + encoded_tip.len());
    output.push(1);
    output.push(match origin.kind {
        WalletOriginKind::Genesis => 0,
        WalletOriginKind::Birthday => 1,
    });
    output.extend_from_slice(&encoded_tip);
    Ok(output)
}

fn decode_origin(bytes: &[u8]) -> Result<WalletOrigin, WalletDbError> {
    if bytes.len() < 3 || bytes[0] != 1 {
        return Err(WalletDbError::CorruptState);
    }
    let kind = match bytes[1] {
        0 => WalletOriginKind::Genesis,
        1 => WalletOriginKind::Birthday,
        _ => return Err(WalletDbError::CorruptState),
    };
    let tip = decode_tip(&bytes[2..])?;
    match kind {
        WalletOriginKind::Genesis if tip.height() == 0 && tip.tree_size() == 0 => {}
        WalletOriginKind::Birthday if tip.height() > 0 && tip.height() < u64::MAX => {}
        WalletOriginKind::Genesis | WalletOriginKind::Birthday => {
            return Err(WalletDbError::CorruptState);
        }
    }
    Ok(WalletOrigin { kind, tip })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WalletRecoveryPhase {
    InProgress,
    Complete,
    AccountRangeExhausted,
}

struct SeedRecoveryProgress {
    phase: WalletRecoveryPhase,
    state_height: u64,
    state_block_hash: [u8; 32],
    target: WalletRecoveryTarget,
    account_ids: Vec<WalletAccountId>,
    account_set_commitment: [u8; 32],
    gap_limit: u8,
    used_accounts: u64,
}

impl fmt::Debug for SeedRecoveryProgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SeedRecoveryProgress(REDACTED)")
    }
}

enum WalletRecoveryState {
    NotRequired,
    Seed(SeedRecoveryProgress),
}

impl fmt::Debug for WalletRecoveryState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletRecoveryState(REDACTED)")
    }
}

fn account_mask(account_count: usize) -> Result<u64, WalletDbError> {
    match account_count {
        1..=63 => Ok((1u64 << account_count) - 1),
        64 => Ok(u64::MAX),
        _ => Err(WalletDbError::CorruptState),
    }
}

fn highest_used_account(progress: &SeedRecoveryProgress) -> Option<u32> {
    (0..progress.account_ids.len())
        .rev()
        .find(|index| progress.used_accounts & (1u64 << index) != 0)
        .and_then(|index| u32::try_from(index).ok())
}

fn recovery_gap_satisfied(progress: &SeedRecoveryProgress) -> bool {
    let trailing_unused =
        highest_used_account(progress).map_or(progress.account_ids.len(), |index| {
            progress.account_ids.len().saturating_sub(
                usize::try_from(index).expect("bounded account index fits usize") + 1,
            )
        });
    trailing_unused >= usize::from(progress.gap_limit)
}

fn tip_matches_recovery_target(tip: &WalletScanTip, target: WalletRecoveryTarget) -> bool {
    tip.height() == target.height
        && tip.block_hash() == target.block_hash
        && tip.tree_size() == target.tree_size
        && tip.tree_root() == target.tree_root
}

fn encode_recovery_state(state: &WalletRecoveryState) -> Result<Vec<u8>, WalletDbError> {
    let WalletRecoveryState::Seed(progress) = state else {
        return Ok(vec![1, 0]);
    };
    let account_count =
        u8::try_from(progress.account_ids.len()).map_err(|_| WalletDbError::CorruptState)?;
    if account_count == 0
        || usize::from(account_count) > crate::MAX_SCAN_ACCOUNTS
        || progress.gap_limit == 0
        || progress.gap_limit > account_count
        || progress.account_set_commitment == [0; 32]
        || progress.used_accounts & !account_mask(progress.account_ids.len())? != 0
    {
        return Err(WalletDbError::CorruptState);
    }
    let mut unique = BTreeSet::new();
    if progress
        .account_ids
        .iter()
        .any(|account_id| !unique.insert(*account_id))
    {
        return Err(WalletDbError::CorruptState);
    }
    if progress.state_height == 0 || progress.state_block_hash == [0; 32] {
        return Err(WalletDbError::CorruptState);
    }
    let mut output = Vec::with_capacity(165 + progress.account_ids.len() * 32);
    output.extend_from_slice(&[
        1,
        1,
        match progress.phase {
            WalletRecoveryPhase::InProgress => 0,
            WalletRecoveryPhase::Complete => 1,
            WalletRecoveryPhase::AccountRangeExhausted => 2,
        },
    ]);
    output.extend_from_slice(&progress.state_height.to_be_bytes());
    output.extend_from_slice(&progress.state_block_hash);
    output.extend_from_slice(&progress.target.height.to_be_bytes());
    output.extend_from_slice(&progress.target.block_hash);
    output.extend_from_slice(&progress.target.tree_size.to_be_bytes());
    output.extend_from_slice(&progress.target.tree_root.to_bytes());
    output.push(progress.gap_limit);
    output.push(account_count);
    output.extend_from_slice(&progress.account_set_commitment);
    output.extend_from_slice(&progress.used_accounts.to_be_bytes());
    for account_id in &progress.account_ids {
        output.extend_from_slice(&account_id.to_bytes());
    }
    Ok(output)
}

fn decode_recovery_state(bytes: &[u8]) -> Result<WalletRecoveryState, WalletDbError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.u8()? != 1 {
        return Err(WalletDbError::CorruptState);
    }
    match decoder.u8()? {
        0 => {
            decoder.finish()?;
            Ok(WalletRecoveryState::NotRequired)
        }
        1 => {
            let phase = match decoder.u8()? {
                0 => WalletRecoveryPhase::InProgress,
                1 => WalletRecoveryPhase::Complete,
                2 => WalletRecoveryPhase::AccountRangeExhausted,
                _ => return Err(WalletDbError::CorruptState),
            };
            let state_height = decoder.u64()?;
            let state_block_hash = decoder.array()?;
            let target = WalletRecoveryTarget {
                height: decoder.u64()?,
                block_hash: decoder.array()?,
                tree_size: decoder.u64()?,
                tree_root: NoteTreeRoot::from_bytes(decoder.array()?)
                    .map_err(|_| WalletDbError::CorruptState)?,
            };
            let gap_limit = decoder.u8()?;
            let account_count = usize::from(decoder.u8()?);
            let account_set_commitment = decoder.array()?;
            let used_accounts = decoder.u64()?;
            if state_height == 0
                || state_block_hash == [0; 32]
                || target.height == 0
                || target.block_hash == [0; 32]
                || account_count == 0
                || account_count > crate::MAX_SCAN_ACCOUNTS
                || gap_limit == 0
                || usize::from(gap_limit) > account_count
                || account_set_commitment == [0; 32]
                || used_accounts & !account_mask(account_count)? != 0
            {
                return Err(WalletDbError::CorruptState);
            }
            let mut account_ids = Vec::with_capacity(account_count);
            let mut unique = BTreeSet::new();
            for _ in 0..account_count {
                let account_id = WalletAccountId::from_bytes(decoder.array()?)
                    .map_err(|_| WalletDbError::CorruptState)?;
                if !unique.insert(account_id) {
                    return Err(WalletDbError::CorruptState);
                }
                account_ids.push(account_id);
            }
            decoder.finish()?;
            Ok(WalletRecoveryState::Seed(SeedRecoveryProgress {
                phase,
                state_height,
                state_block_hash,
                target,
                account_ids,
                account_set_commitment,
                gap_limit,
                used_accounts,
            }))
        }
        _ => Err(WalletDbError::CorruptState),
    }
}

fn incremental_frontier(
    tip: &WalletScanTip,
) -> Result<Frontier<MerkleHashOrchard, NOTE_TREE_DEPTH>, WalletDbError> {
    let snapshot = tip.tree_snapshot();
    if snapshot.tree_size() == 0 {
        if snapshot.leaf().is_some() || !snapshot.ommers().is_empty() {
            return Err(WalletDbError::CorruptState);
        }
        return Ok(Frontier::empty());
    }
    let position = snapshot
        .tree_size()
        .checked_sub(1)
        .map(Position::from)
        .ok_or(WalletDbError::CorruptState)?;
    let leaf = parse_merkle_hash(snapshot.leaf().ok_or(WalletDbError::CorruptState)?)?;
    let ommers = snapshot
        .ommers()
        .iter()
        .copied()
        .map(parse_merkle_hash)
        .collect::<Result<Vec<_>, _>>()?;
    let frontier =
        Frontier::from_parts(position, leaf, ommers).map_err(|_| WalletDbError::CorruptState)?;
    if frontier.tree_size() != snapshot.tree_size() {
        return Err(WalletDbError::CorruptState);
    }
    Ok(frontier)
}

struct StoredNote {
    account_id: WalletAccountId,
    key_scope: KeyScope,
    position: u32,
    transaction_id: TransactionId,
    action_index: u8,
    action_nullifier: ActionNullifier,
    note_commitment: [u8; 32],
    spend_nullifier: ActionNullifier,
    spent_height: Option<u64>,
    decrypted: DecryptedNote,
}

impl StoredNote {
    fn from_scanned(note: &crate::ScannedNote, maximum_value: u64) -> Result<Self, WalletDbError> {
        let commitment = note
            .decrypted()
            .note()
            .commitment()
            .map_err(|_| WalletDbError::CorruptState)?;
        if commitment != note.output().note_commitment()
            || note
                .decrypted()
                .note()
                .action_nullifier()
                .map_err(|_| WalletDbError::CorruptState)?
                != note.action_nullifier()
        {
            return Err(WalletDbError::CorruptState);
        }
        Ok(Self {
            account_id: note.account_id(),
            key_scope: note.key_scope(),
            position: note.position(),
            transaction_id: note.transaction_id(),
            action_index: note.action_index(),
            action_nullifier: note.action_nullifier(),
            note_commitment: commitment,
            spend_nullifier: note.spend_nullifier(),
            spent_height: None,
            decrypted: DecryptedNote::decode_private(
                *note.decrypted().encode_private(),
                maximum_value,
            )
            .map_err(|_| WalletDbError::CorruptState)?,
        })
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, WalletDbError> {
        let mut output = Zeroizing::new(Vec::with_capacity(NOTE_RECORD_BYTES));
        output.push(1);
        output.extend_from_slice(&self.account_id.to_bytes());
        output.push(match self.key_scope {
            KeyScope::External => 0,
            KeyScope::Internal => 1,
        });
        output.extend_from_slice(&self.position.to_be_bytes());
        output.extend_from_slice(self.transaction_id.as_bytes());
        output.push(self.action_index);
        output.extend_from_slice(&self.action_nullifier.to_bytes());
        output.extend_from_slice(&self.note_commitment);
        output.extend_from_slice(&self.spend_nullifier.to_bytes());
        match self.spent_height {
            None => {
                output.push(0);
                output.extend_from_slice(&0u64.to_be_bytes());
            }
            Some(height) if height > 0 => {
                output.push(1);
                output.extend_from_slice(&height.to_be_bytes());
            }
            Some(_) => return Err(WalletDbError::CorruptState),
        }
        output.extend_from_slice(self.decrypted.encode_private().as_ref());
        if output.len() != NOTE_RECORD_BYTES {
            return Err(WalletDbError::CorruptState);
        }
        Ok(output)
    }

    fn decode(bytes: &[u8], maximum_value: u64) -> Result<Self, WalletDbError> {
        if bytes.len() != NOTE_RECORD_BYTES {
            return Err(WalletDbError::CorruptState);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.u8()? != 1 {
            return Err(WalletDbError::CorruptState);
        }
        let account_id = WalletAccountId::from_bytes(decoder.array()?)
            .map_err(|_| WalletDbError::CorruptState)?;
        let key_scope = match decoder.u8()? {
            0 => KeyScope::External,
            1 => KeyScope::Internal,
            _ => return Err(WalletDbError::CorruptState),
        };
        let position = decoder.u32()?;
        let transaction_id = TransactionId::new(decoder.array()?);
        if transaction_id.is_zero() {
            return Err(WalletDbError::CorruptState);
        }
        let action_index = decoder.u8()?;
        let action_nullifier = ActionNullifier::from_bytes(decoder.array()?)
            .map_err(|_| WalletDbError::CorruptState)?;
        let note_commitment = decoder.array()?;
        parse_merkle_hash(note_commitment)?;
        let spend_nullifier = ActionNullifier::from_bytes(decoder.array()?)
            .map_err(|_| WalletDbError::CorruptState)?;
        let spent_flag = decoder.u8()?;
        let spent_value = decoder.u64()?;
        let spent_height = match (spent_flag, spent_value) {
            (0, 0) => None,
            (1, height) if height > 0 => Some(height),
            _ => return Err(WalletDbError::CorruptState),
        };
        let decrypted = DecryptedNote::decode_private(decoder.array()?, maximum_value)
            .map_err(|_| WalletDbError::CorruptState)?;
        decoder.finish()?;
        if decrypted
            .note()
            .commitment()
            .map_err(|_| WalletDbError::CorruptState)?
            != note_commitment
            || decrypted
                .note()
                .action_nullifier()
                .map_err(|_| WalletDbError::CorruptState)?
                != action_nullifier
        {
            return Err(WalletDbError::CorruptState);
        }
        Ok(Self {
            account_id,
            key_scope,
            position,
            transaction_id,
            action_index,
            action_nullifier,
            note_commitment,
            spend_nullifier,
            spent_height,
            decrypted,
        })
    }
}

struct DatabaseMetadata {
    database_id: [u8; 32],
    chain_id: ChainId,
    wallet_id: [u8; 32],
    maximum_note_value: u64,
    max_checkpoints: usize,
    key_check: Vec<u8>,
}

fn map_database_error<T>(result: rusqlite::Result<T>) -> Result<T, WalletDbError> {
    result.map_err(|_| WalletDbError::DatabaseFailure)
}

#[cfg(unix)]
fn effective_user_id() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
fn protected_parent(path: &Path) -> Result<PathBuf, WalletDbError> {
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute() || path.file_name().is_none() {
        return Err(WalletDbError::InvalidPath);
    }
    let parent = path.parent().ok_or(WalletDbError::InvalidPath)?;
    let canonical = fs::canonicalize(parent).map_err(|_| WalletDbError::InvalidPath)?;
    if canonical != parent {
        return Err(WalletDbError::InvalidPath);
    }
    let metadata = fs::metadata(&canonical).map_err(|_| WalletDbError::InvalidPath)?;
    if !metadata.is_dir() || metadata.uid() != effective_user_id() || metadata.mode() & 0o022 != 0 {
        return Err(WalletDbError::UnsafeFile);
    }
    Ok(canonical)
}

#[cfg(unix)]
fn lock_path(path: &Path) -> Result<PathBuf, WalletDbError> {
    use std::ffi::OsString;

    let name = path.file_name().ok_or(WalletDbError::InvalidPath)?;
    let mut lock_name = OsString::from(name);
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

#[cfg(unix)]
fn open_lock(path: &Path) -> Result<File, WalletDbError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let path = lock_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| WalletDbError::UnsafeFile)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| WalletDbError::UnsafeFile)?;
    let metadata = file.metadata().map_err(|_| WalletDbError::UnsafeFile)?;
    if !metadata.is_file()
        || metadata.uid() != effective_user_id()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(WalletDbError::UnsafeFile);
    }
    file.try_lock_exclusive()
        .map_err(|_| WalletDbError::Locked)?;
    Ok(file)
}

#[cfg(unix)]
fn create_database_file(path: &Path) -> Result<(), WalletDbError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    match fs::symlink_metadata(path) {
        Ok(_) => return Err(WalletDbError::AlreadyExists),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(WalletDbError::UnsafeFile),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| match error.kind() {
            ErrorKind::AlreadyExists => WalletDbError::AlreadyExists,
            _ => WalletDbError::UnsafeFile,
        })?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| WalletDbError::UnsafeFile)?;
    file.sync_all().map_err(|_| WalletDbError::DatabaseFailure)
}

#[cfg(unix)]
fn verify_database_file(path: &Path) -> Result<(), WalletDbError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        ErrorKind::NotFound => WalletDbError::Missing,
        _ => WalletDbError::UnsafeFile,
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_user_id()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(WalletDbError::UnsafeFile);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), WalletDbError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| WalletDbError::DatabaseFailure)
}

#[cfg(not(unix))]
fn protected_parent(_: &Path) -> Result<PathBuf, WalletDbError> {
    Err(WalletDbError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn open_lock(_: &Path) -> Result<File, WalletDbError> {
    Err(WalletDbError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn create_database_file(_: &Path) -> Result<(), WalletDbError> {
    Err(WalletDbError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn verify_database_file(_: &Path) -> Result<(), WalletDbError> {
    Err(WalletDbError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn sync_parent(_: &Path) -> Result<(), WalletDbError> {
    Err(WalletDbError::UnsupportedPlatform)
}

fn open_sqlite(path: &Path) -> Result<Connection, WalletDbError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_EXRESCODE;
    map_database_error(Connection::open_with_flags(path, flags))
}

fn configure_connection(connection: &Connection) -> Result<(), WalletDbError> {
    use rusqlite::config::DbConfig;

    map_database_error(connection.busy_timeout(Duration::ZERO))?;
    map_database_error(connection.pragma_update(None, "foreign_keys", true))?;
    map_database_error(connection.pragma_update(None, "trusted_schema", false))?;
    map_database_error(connection.pragma_update(None, "temp_store", "MEMORY"))?;
    map_database_error(connection.pragma_update(None, "secure_delete", true))?;
    map_database_error(connection.pragma_update(None, "journal_mode", "DELETE"))?;
    map_database_error(connection.pragma_update(None, "synchronous", "EXTRA"))?;
    map_database_error(connection.pragma_update(None, "fullfsync", true))?;
    map_database_error(connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true))?;
    let journal_mode: String =
        map_database_error(connection.query_row("PRAGMA journal_mode", [], |row| row.get(0)))?;
    let synchronous: i64 =
        map_database_error(connection.query_row("PRAGMA synchronous", [], |row| row.get(0)))?;
    if !journal_mode.eq_ignore_ascii_case("delete") || synchronous != 3 {
        return Err(WalletDbError::DatabaseFailure);
    }
    Ok(())
}

fn create_schema(transaction: &Transaction<'_>) -> Result<(), WalletDbError> {
    map_database_error(transaction.execute_batch(
        "
        CREATE TABLE wallet_metadata (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            schema_version INTEGER NOT NULL CHECK (schema_version = 2),
            database_id BLOB NOT NULL CHECK (length(database_id) = 32),
            chain_id BLOB NOT NULL CHECK (length(chain_id) = 32),
            wallet_id BLOB NOT NULL CHECK (length(wallet_id) = 32),
            maximum_note_value INTEGER NOT NULL CHECK (maximum_note_value > 0),
            max_checkpoints INTEGER NOT NULL CHECK (max_checkpoints > 0 AND max_checkpoints <= 4096),
            key_check BLOB NOT NULL
        ) STRICT;
        CREATE TABLE wallet_tip (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            payload BLOB NOT NULL
        ) STRICT;
        CREATE TABLE wallet_origin (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            payload BLOB NOT NULL
        ) STRICT;
        CREATE TABLE wallet_recovery (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            payload BLOB NOT NULL
        ) STRICT;
        CREATE TABLE wallet_notes (
            nullifier_tag BLOB PRIMARY KEY CHECK (length(nullifier_tag) = 32),
            payload BLOB NOT NULL
        ) STRICT, WITHOUT ROWID;
        CREATE TABLE tree_shards (
            shard_index INTEGER PRIMARY KEY CHECK (shard_index >= 0),
            payload BLOB NOT NULL
        ) STRICT;
        CREATE TABLE tree_cap (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            payload BLOB NOT NULL
        ) STRICT;
        CREATE TABLE tree_checkpoints (
            checkpoint_id INTEGER PRIMARY KEY CHECK (checkpoint_id >= 0),
            payload BLOB NOT NULL
        ) STRICT;
        CREATE TABLE tree_retained_checkpoints (
            checkpoint_id INTEGER PRIMARY KEY CHECK (checkpoint_id >= 0),
            payload BLOB NOT NULL
        ) STRICT;
        PRAGMA user_version = 2;
        ",
    ))
}

fn load_metadata_for_schema(
    connection: &Connection,
    expected_schema_version: u32,
) -> Result<DatabaseMetadata, WalletDbError> {
    let row = map_database_error(connection.query_row(
        "SELECT schema_version, database_id, chain_id, wallet_id, maximum_note_value,
                max_checkpoints, key_check
         FROM wallet_metadata WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        },
    ))?;
    let database_id = row.1.try_into().map_err(|_| WalletDbError::CorruptState)?;
    let chain_bytes: [u8; 32] = row.2.try_into().map_err(|_| WalletDbError::CorruptState)?;
    let wallet_id = row.3.try_into().map_err(|_| WalletDbError::CorruptState)?;
    let maximum_note_value = u64::try_from(row.4).map_err(|_| WalletDbError::CorruptState)?;
    let max_checkpoints = usize::try_from(row.5).map_err(|_| WalletDbError::CorruptState)?;
    if row.0 != i64::from(expected_schema_version)
        || database_id == [0; 32]
        || chain_bytes == [0; 32]
        || wallet_id == [0; 32]
        || maximum_note_value == 0
        || max_checkpoints == 0
        || max_checkpoints > MAX_CHECKPOINTS_LIMIT
    {
        return Err(WalletDbError::CorruptState);
    }
    Ok(DatabaseMetadata {
        database_id,
        chain_id: ChainId::new(chain_bytes),
        wallet_id,
        maximum_note_value,
        max_checkpoints,
        key_check: row.6,
    })
}

fn record_key_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn migration_interrupt(stage: u8, fail_after_stage: Option<u8>) -> Result<(), WalletDbError> {
    if fail_after_stage == Some(stage) {
        Err(WalletDbError::DatabaseFailure)
    } else {
        Ok(())
    }
}

fn reseal_singleton_payload(
    transaction: &Transaction<'_>,
    legacy_crypto: &WalletDbCrypto,
    current_crypto: &WalletDbCrypto,
    select: &str,
    update: &str,
    kind: RecordKind,
    record_key: &[u8],
) -> Result<(), WalletDbError> {
    let payload: Vec<u8> = map_database_error(transaction.query_row(select, [], |row| row.get(0)))?;
    let plaintext = legacy_crypto.open(kind, record_key, &payload)?;
    let replacement = current_crypto.seal(kind, record_key, &plaintext)?;
    if map_database_error(transaction.execute(update, params![replacement]))? != 1 {
        return Err(WalletDbError::CorruptState);
    }
    Ok(())
}

fn reseal_integer_keyed_payloads(
    transaction: &Transaction<'_>,
    legacy_crypto: &WalletDbCrypto,
    current_crypto: &WalletDbCrypto,
    select_next: &str,
    update: &str,
    kind: RecordKind,
) -> Result<(), WalletDbError> {
    let mut previous = -1i64;
    loop {
        let row = map_database_error(
            transaction
                .query_row(select_next, params![previous], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .optional(),
        )?;
        let Some((raw_key, payload)) = row else {
            return Ok(());
        };
        if raw_key <= previous {
            return Err(WalletDbError::CorruptState);
        }
        let key = u64::try_from(raw_key).map_err(|_| WalletDbError::CorruptState)?;
        let record_key = record_key_u64(key);
        let plaintext = legacy_crypto.open(kind, &record_key, &payload)?;
        let replacement = current_crypto.seal(kind, &record_key, &plaintext)?;
        if map_database_error(transaction.execute(update, params![replacement, raw_key]))? != 1 {
            return Err(WalletDbError::CorruptState);
        }
        previous = raw_key;
    }
}

fn reseal_note_payloads(
    transaction: &Transaction<'_>,
    legacy_crypto: &WalletDbCrypto,
    current_crypto: &WalletDbCrypto,
) -> Result<(), WalletDbError> {
    let mut previous: Option<Vec<u8>> = None;
    loop {
        let row = match previous.as_deref() {
            None => map_database_error(
                transaction
                    .query_row(
                        "SELECT nullifier_tag, payload FROM wallet_notes
                         ORDER BY nullifier_tag ASC LIMIT 1",
                        [],
                        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                    )
                    .optional(),
            )?,
            Some(previous_tag) => map_database_error(
                transaction
                    .query_row(
                        "SELECT nullifier_tag, payload FROM wallet_notes
                         WHERE nullifier_tag > ?1 ORDER BY nullifier_tag ASC LIMIT 1",
                        params![previous_tag],
                        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                    )
                    .optional(),
            )?,
        };
        let Some((raw_tag, payload)) = row else {
            return Ok(());
        };
        let tag: [u8; 32] = raw_tag
            .as_slice()
            .try_into()
            .map_err(|_| WalletDbError::CorruptState)?;
        if previous
            .as_deref()
            .is_some_and(|prior| prior >= raw_tag.as_slice())
        {
            return Err(WalletDbError::CorruptState);
        }
        let plaintext = legacy_crypto.open(RecordKind::Note, &tag, &payload)?;
        let replacement = current_crypto.seal(RecordKind::Note, &tag, &plaintext)?;
        if map_database_error(transaction.execute(
            "UPDATE wallet_notes SET payload = ?1 WHERE nullifier_tag = ?2",
            params![replacement, &raw_tag],
        ))? != 1
        {
            return Err(WalletDbError::CorruptState);
        }
        previous = Some(raw_tag);
    }
}

fn migrate_schema_v1_to_v2(
    transaction: &Transaction<'_>,
    legacy_crypto: &WalletDbCrypto,
    current_crypto: &WalletDbCrypto,
    metadata: &DatabaseMetadata,
    fail_after_stage: Option<u8>,
) -> Result<(), WalletDbError> {
    reseal_singleton_payload(
        transaction,
        legacy_crypto,
        current_crypto,
        "SELECT payload FROM wallet_tip WHERE singleton = 1",
        "UPDATE wallet_tip SET payload = ?1 WHERE singleton = 1",
        RecordKind::Tip,
        b"tip",
    )?;
    migration_interrupt(1, fail_after_stage)?;
    reseal_singleton_payload(
        transaction,
        legacy_crypto,
        current_crypto,
        "SELECT payload FROM wallet_origin WHERE singleton = 1",
        "UPDATE wallet_origin SET payload = ?1 WHERE singleton = 1",
        RecordKind::Origin,
        b"origin",
    )?;
    migration_interrupt(2, fail_after_stage)?;
    reseal_note_payloads(transaction, legacy_crypto, current_crypto)?;
    migration_interrupt(3, fail_after_stage)?;
    reseal_integer_keyed_payloads(
        transaction,
        legacy_crypto,
        current_crypto,
        "SELECT shard_index, payload FROM tree_shards
         WHERE shard_index > ?1 ORDER BY shard_index ASC LIMIT 1",
        "UPDATE tree_shards SET payload = ?1 WHERE shard_index = ?2",
        RecordKind::Shard,
    )?;
    migration_interrupt(4, fail_after_stage)?;
    reseal_singleton_payload(
        transaction,
        legacy_crypto,
        current_crypto,
        "SELECT payload FROM tree_cap WHERE singleton = 1",
        "UPDATE tree_cap SET payload = ?1 WHERE singleton = 1",
        RecordKind::Cap,
        b"cap",
    )?;
    migration_interrupt(5, fail_after_stage)?;
    reseal_integer_keyed_payloads(
        transaction,
        legacy_crypto,
        current_crypto,
        "SELECT checkpoint_id, payload FROM tree_checkpoints
         WHERE checkpoint_id > ?1 ORDER BY checkpoint_id ASC LIMIT 1",
        "UPDATE tree_checkpoints SET payload = ?1 WHERE checkpoint_id = ?2",
        RecordKind::Checkpoint,
    )?;
    migration_interrupt(6, fail_after_stage)?;
    reseal_integer_keyed_payloads(
        transaction,
        legacy_crypto,
        current_crypto,
        "SELECT checkpoint_id, payload FROM tree_retained_checkpoints
         WHERE checkpoint_id > ?1 ORDER BY checkpoint_id ASC LIMIT 1",
        "UPDATE tree_retained_checkpoints SET payload = ?1 WHERE checkpoint_id = ?2",
        RecordKind::RetainedCheckpoint,
    )?;
    migration_interrupt(7, fail_after_stage)?;

    let key_check = legacy_crypto.open(RecordKind::KeyCheck, b"key-check", &metadata.key_check)?;
    if key_check.as_slice() != KEY_CHECK_PLAINTEXT {
        return Err(WalletDbError::AuthenticationFailed);
    }
    let replacement_key_check =
        current_crypto.seal(RecordKind::KeyCheck, b"key-check", KEY_CHECK_PLAINTEXT)?;
    map_database_error(transaction.execute_batch(
        "CREATE TABLE wallet_metadata_v2 (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            schema_version INTEGER NOT NULL CHECK (schema_version = 2),
            database_id BLOB NOT NULL CHECK (length(database_id) = 32),
            chain_id BLOB NOT NULL CHECK (length(chain_id) = 32),
            wallet_id BLOB NOT NULL CHECK (length(wallet_id) = 32),
            maximum_note_value INTEGER NOT NULL CHECK (maximum_note_value > 0),
            max_checkpoints INTEGER NOT NULL CHECK (max_checkpoints > 0 AND max_checkpoints <= 4096),
            key_check BLOB NOT NULL
        ) STRICT;",
    ))?;
    if map_database_error(transaction.execute(
        "INSERT INTO wallet_metadata_v2(
            singleton, schema_version, database_id, chain_id, wallet_id,
            maximum_note_value, max_checkpoints, key_check
         ) VALUES (1, 2, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            metadata.database_id.to_vec(),
            metadata.chain_id.as_bytes().to_vec(),
            metadata.wallet_id.to_vec(),
            i64::try_from(metadata.maximum_note_value).map_err(|_| WalletDbError::CorruptState)?,
            i64::try_from(metadata.max_checkpoints).map_err(|_| WalletDbError::CorruptState)?,
            replacement_key_check,
        ],
    ))? != 1
    {
        return Err(WalletDbError::CorruptState);
    }
    map_database_error(transaction.execute_batch(
        "DROP TABLE wallet_metadata;
         ALTER TABLE wallet_metadata_v2 RENAME TO wallet_metadata;",
    ))?;
    migration_interrupt(8, fail_after_stage)?;

    let recovery_payload = current_crypto.seal(
        RecordKind::Recovery,
        b"recovery",
        &encode_recovery_state(&WalletRecoveryState::NotRequired)?,
    )?;
    map_database_error(transaction.execute_batch(
        "CREATE TABLE wallet_recovery (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            payload BLOB NOT NULL
        ) STRICT;",
    ))?;
    if map_database_error(transaction.execute(
        "INSERT INTO wallet_recovery(singleton, payload) VALUES (1, ?1)",
        params![recovery_payload],
    ))? != 1
    {
        return Err(WalletDbError::CorruptState);
    }
    map_database_error(transaction.pragma_update(None, "user_version", SCHEMA_VERSION))?;
    migration_interrupt(9, fail_after_stage)
}

struct SqliteShardStore<'a> {
    connection: &'a Connection,
    crypto: &'a WalletDbCrypto,
}

impl<'a> SqliteShardStore<'a> {
    fn new(connection: &'a Connection, crypto: &'a WalletDbCrypto) -> Self {
        Self { connection, crypto }
    }

    fn load_checkpoint(&self, checkpoint_id: u64) -> Result<Option<Checkpoint>, WalletDbError> {
        let encrypted = map_database_error(
            self.connection
                .query_row(
                    "SELECT payload FROM tree_checkpoints WHERE checkpoint_id = ?1",
                    params![i64::try_from(checkpoint_id).map_err(|_| WalletDbError::CorruptState)?],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional(),
        )?;
        encrypted
            .map(|payload| {
                let plaintext = self.crypto.open(
                    RecordKind::Checkpoint,
                    &record_key_u64(checkpoint_id),
                    &payload,
                )?;
                decode_checkpoint(&plaintext)
            })
            .transpose()
    }
}

impl ShardStore for SqliteShardStore<'_> {
    type H = MerkleHashOrchard;
    type CheckpointId = u64;
    type Error = WalletDbError;

    fn get_shard(
        &self,
        shard_root: Address,
    ) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        if shard_root.level() != Level::from(SHARD_HEIGHT) {
            return Err(WalletDbError::WitnessStateFailure);
        }
        let shard_index = shard_root.index();
        let encrypted = map_database_error(
            self.connection
                .query_row(
                    "SELECT payload FROM tree_shards WHERE shard_index = ?1",
                    params![i64::try_from(shard_index).map_err(|_| WalletDbError::CorruptState)?],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional(),
        )?;
        encrypted
            .map(|payload| {
                let plaintext =
                    self.crypto
                        .open(RecordKind::Shard, &record_key_u64(shard_index), &payload)?;
                let tree = decode_tree(&plaintext, SHARD_HEIGHT)?;
                LocatedPrunableTree::from_parts(shard_root, tree)
                    .map_err(|_| WalletDbError::CorruptState)
            })
            .transpose()
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        let index = map_database_error(
            self.connection
                .query_row(
                    "SELECT shard_index FROM tree_shards ORDER BY shard_index DESC LIMIT 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .optional(),
        )?;
        index
            .map(|value| {
                let index = u64::try_from(value).map_err(|_| WalletDbError::CorruptState)?;
                self.get_shard(Address::from_parts(Level::from(SHARD_HEIGHT), index))?
                    .ok_or(WalletDbError::CorruptState)
            })
            .transpose()
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        if subtree.root_addr().level() != Level::from(SHARD_HEIGHT) {
            return Err(WalletDbError::WitnessStateFailure);
        }
        let shard_index = subtree.root_addr().index();
        let plaintext = encode_tree(subtree.root())?;
        let encrypted =
            self.crypto
                .seal(RecordKind::Shard, &record_key_u64(shard_index), &plaintext)?;
        map_database_error(self.connection.execute(
            "INSERT INTO tree_shards(shard_index, payload) VALUES (?1, ?2)
             ON CONFLICT(shard_index) DO UPDATE SET payload = excluded.payload",
            params![
                i64::try_from(shard_index).map_err(|_| WalletDbError::CorruptState)?,
                encrypted
            ],
        ))?;
        Ok(())
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        let mut statement = map_database_error(
            self.connection
                .prepare("SELECT shard_index FROM tree_shards ORDER BY shard_index ASC"),
        )?;
        let rows = map_database_error(statement.query_map([], |row| row.get::<_, i64>(0)))?;
        let mut roots = Vec::new();
        for row in rows {
            let index =
                u64::try_from(map_database_error(row)?).map_err(|_| WalletDbError::CorruptState)?;
            roots.push(Address::from_parts(Level::from(SHARD_HEIGHT), index));
        }
        Ok(roots)
    }

    fn truncate_shards(&mut self, shard_index: u64) -> Result<(), Self::Error> {
        map_database_error(self.connection.execute(
            "DELETE FROM tree_shards WHERE shard_index >= ?1",
            params![i64::try_from(shard_index).map_err(|_| WalletDbError::CorruptState)?],
        ))?;
        Ok(())
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        let encrypted = map_database_error(self.connection.query_row(
            "SELECT payload FROM tree_cap WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        ))?;
        let plaintext = self.crypto.open(RecordKind::Cap, b"cap", &encrypted)?;
        decode_tree(&plaintext, NOTE_TREE_DEPTH - SHARD_HEIGHT)
    }

    fn put_cap(&mut self, cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        let plaintext = encode_tree(&cap)?;
        let encrypted = self.crypto.seal(RecordKind::Cap, b"cap", &plaintext)?;
        map_database_error(self.connection.execute(
            "UPDATE tree_cap SET payload = ?1 WHERE singleton = 1",
            params![encrypted],
        ))?;
        Ok(())
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        let value = map_database_error(self.connection.query_row(
            "SELECT MIN(checkpoint_id) FROM tree_checkpoints",
            [],
            |row| row.get::<_, Option<i64>>(0),
        ))?;
        value
            .map(|value| u64::try_from(value).map_err(|_| WalletDbError::CorruptState))
            .transpose()
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        let value = map_database_error(self.connection.query_row(
            "SELECT MAX(checkpoint_id) FROM tree_checkpoints",
            [],
            |row| row.get::<_, Option<i64>>(0),
        ))?;
        value
            .map(|value| u64::try_from(value).map_err(|_| WalletDbError::CorruptState))
            .transpose()
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        let plaintext = encode_checkpoint(&checkpoint)?;
        let encrypted = self.crypto.seal(
            RecordKind::Checkpoint,
            &record_key_u64(checkpoint_id),
            &plaintext,
        )?;
        map_database_error(self.connection.execute(
            "INSERT INTO tree_checkpoints(checkpoint_id, payload) VALUES (?1, ?2)",
            params![
                i64::try_from(checkpoint_id).map_err(|_| WalletDbError::CorruptState)?,
                encrypted
            ],
        ))?;
        Ok(())
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        let count: i64 = map_database_error(self.connection.query_row(
            "SELECT COUNT(*) FROM tree_checkpoints",
            [],
            |row| row.get(0),
        ))?;
        usize::try_from(count).map_err(|_| WalletDbError::CorruptState)
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        let row = map_database_error(
            self.connection
                .query_row(
                    "SELECT checkpoint_id, payload FROM tree_checkpoints
                     ORDER BY checkpoint_id DESC LIMIT 1 OFFSET ?1",
                    params![
                        i64::try_from(checkpoint_depth).map_err(|_| WalletDbError::CorruptState)?
                    ],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional(),
        )?;
        row.map(|(raw_id, payload)| {
            let checkpoint_id = u64::try_from(raw_id).map_err(|_| WalletDbError::CorruptState)?;
            let plaintext = self.crypto.open(
                RecordKind::Checkpoint,
                &record_key_u64(checkpoint_id),
                &payload,
            )?;
            Ok((checkpoint_id, decode_checkpoint(&plaintext)?))
        })
        .transpose()
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        self.load_checkpoint(*checkpoint_id)
    }

    fn with_checkpoints<F>(&mut self, limit: usize, mut callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        let checkpoints = self.collect_checkpoints(limit)?;
        for (checkpoint_id, checkpoint) in &checkpoints {
            callback(checkpoint_id, checkpoint)?;
        }
        Ok(())
    }

    fn for_each_checkpoint<F>(&self, limit: usize, mut callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        let checkpoints = self.collect_checkpoints(limit)?;
        for (checkpoint_id, checkpoint) in &checkpoints {
            callback(checkpoint_id, checkpoint)?;
        }
        Ok(())
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        let Some(mut checkpoint) = self.load_checkpoint(*checkpoint_id)? else {
            return Ok(false);
        };
        update(&mut checkpoint)?;
        let plaintext = encode_checkpoint(&checkpoint)?;
        let encrypted = self.crypto.seal(
            RecordKind::Checkpoint,
            &record_key_u64(*checkpoint_id),
            &plaintext,
        )?;
        let changed = map_database_error(self.connection.execute(
            "UPDATE tree_checkpoints SET payload = ?1 WHERE checkpoint_id = ?2",
            params![
                encrypted,
                i64::try_from(*checkpoint_id).map_err(|_| WalletDbError::CorruptState)?
            ],
        ))?;
        if changed != 1 {
            return Err(WalletDbError::CorruptState);
        }
        Ok(true)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &Self::CheckpointId) -> Result<(), Self::Error> {
        map_database_error(self.connection.execute(
            "DELETE FROM tree_checkpoints WHERE checkpoint_id = ?1",
            params![i64::try_from(*checkpoint_id).map_err(|_| WalletDbError::CorruptState)?],
        ))?;
        Ok(())
    }

    fn add_retained_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        let payload = self.crypto.seal(
            RecordKind::RetainedCheckpoint,
            &record_key_u64(checkpoint_id),
            b"retained",
        )?;
        map_database_error(self.connection.execute(
            "INSERT OR IGNORE INTO tree_retained_checkpoints(checkpoint_id, payload)
             VALUES (?1, ?2)",
            params![
                i64::try_from(checkpoint_id).map_err(|_| WalletDbError::CorruptState)?,
                payload
            ],
        ))?;
        Ok(())
    }

    fn remove_retained_checkpoint(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        map_database_error(self.connection.execute(
            "DELETE FROM tree_retained_checkpoints WHERE checkpoint_id = ?1",
            params![i64::try_from(*checkpoint_id).map_err(|_| WalletDbError::CorruptState)?],
        ))?;
        Ok(())
    }

    fn retained_checkpoints(&self) -> Result<BTreeSet<Self::CheckpointId>, Self::Error> {
        let mut statement = map_database_error(self.connection.prepare(
            "SELECT checkpoint_id, payload FROM tree_retained_checkpoints
             ORDER BY checkpoint_id ASC",
        ))?;
        let rows = map_database_error(statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        }))?;
        let mut result = BTreeSet::new();
        for row in rows {
            let (raw_checkpoint, payload) = map_database_error(row)?;
            let checkpoint =
                u64::try_from(raw_checkpoint).map_err(|_| WalletDbError::CorruptState)?;
            let plaintext = self.crypto.open(
                RecordKind::RetainedCheckpoint,
                &record_key_u64(checkpoint),
                &payload,
            )?;
            if plaintext.as_slice() != b"retained" {
                return Err(WalletDbError::CorruptState);
            }
            if !result.insert(checkpoint) {
                return Err(WalletDbError::CorruptState);
            }
        }
        Ok(result)
    }

    fn truncate_checkpoints_retaining(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        map_database_error(self.connection.execute(
            "DELETE FROM tree_checkpoints WHERE checkpoint_id > ?1",
            params![i64::try_from(*checkpoint_id).map_err(|_| WalletDbError::CorruptState)?],
        ))?;
        if let Some(checkpoint) = self.load_checkpoint(*checkpoint_id)? {
            let replacement = Checkpoint::from_parts(checkpoint.tree_state(), BTreeSet::new());
            let plaintext = encode_checkpoint(&replacement)?;
            let encrypted = self.crypto.seal(
                RecordKind::Checkpoint,
                &record_key_u64(*checkpoint_id),
                &plaintext,
            )?;
            map_database_error(self.connection.execute(
                "UPDATE tree_checkpoints SET payload = ?1 WHERE checkpoint_id = ?2",
                params![
                    encrypted,
                    i64::try_from(*checkpoint_id).map_err(|_| WalletDbError::CorruptState)?
                ],
            ))?;
        }
        Ok(())
    }
}

impl SqliteShardStore<'_> {
    fn collect_checkpoints(&self, limit: usize) -> Result<Vec<(u64, Checkpoint)>, WalletDbError> {
        let mut statement = map_database_error(self.connection.prepare(
            "SELECT checkpoint_id, payload FROM tree_checkpoints
             ORDER BY checkpoint_id ASC LIMIT ?1",
        ))?;
        let rows = map_database_error(statement.query_map(
            params![i64::try_from(limit).map_err(|_| WalletDbError::CorruptState)?],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        ))?;
        let mut result = Vec::new();
        for row in rows {
            let (raw_id, payload) = map_database_error(row)?;
            let checkpoint_id = u64::try_from(raw_id).map_err(|_| WalletDbError::CorruptState)?;
            let plaintext = self.crypto.open(
                RecordKind::Checkpoint,
                &record_key_u64(checkpoint_id),
                &payload,
            )?;
            result.push((checkpoint_id, decode_checkpoint(&plaintext)?));
        }
        Ok(result)
    }
}

/// Redacted storage measurements from one validated database compaction.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WalletCompactionSummary {
    before_bytes: u64,
    after_bytes: u64,
    before_pages: u64,
    after_pages: u64,
    reclaimed_pages: u64,
}

impl fmt::Debug for WalletCompactionSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletCompactionSummary(REDACTED)")
    }
}

impl WalletCompactionSummary {
    /// Database file length before compaction.
    #[must_use]
    pub const fn before_bytes(self) -> u64 {
        self.before_bytes
    }

    /// Database file length after compaction and validation.
    #[must_use]
    pub const fn after_bytes(self) -> u64 {
        self.after_bytes
    }

    /// SQLite page count before compaction.
    #[must_use]
    pub const fn before_pages(self) -> u64 {
        self.before_pages
    }

    /// SQLite page count after compaction.
    #[must_use]
    pub const fn after_pages(self) -> u64 {
        self.after_pages
    }

    /// Free-list pages removed by the successful compaction.
    #[must_use]
    pub const fn reclaimed_pages(self) -> u64 {
        self.reclaimed_pages
    }
}

/// Encrypted, single-writer, transactional finalized wallet database.
///
/// The database file is not a generic SQLite privacy boundary: schema shape,
/// row counts, checkpoint heights, and shard indices remain observable. Every
/// wallet-specific value and note-to-nullifier index is nevertheless keyed and
/// authenticated. A handle is permanently poisoned after uncertain durability.
pub struct EncryptedWalletDb {
    path: PathBuf,
    connection: Connection,
    _lock: File,
    crypto: WalletDbCrypto,
    config: WalletDatabaseConfig,
    poisoned: bool,
}

impl fmt::Debug for EncryptedWalletDb {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedWalletDb(REDACTED)")
    }
}

impl EncryptedWalletDb {
    /// Creates a new database at the chain's empty genesis wallet tip.
    /// Existing targets are never opened or replaced by this operation.
    pub fn create(
        path: &Path,
        root_key: &[u8; 32],
        config: WalletDatabaseConfig,
        initial_tip: WalletScanTip,
    ) -> Result<Self, WalletDbError> {
        if initial_tip.height() != 0 || initial_tip.tree_size() != 0 {
            return Err(WalletDbError::NonEmptyInitializationUnsupported);
        }
        Self::create_with_origin(
            path,
            root_key,
            config,
            WalletOrigin {
                kind: WalletOriginKind::Genesis,
                tip: initial_tip,
            },
            WalletRecoveryState::NotRequired,
        )
    }

    /// Creates a new database from a complete, bounded seed-recovery plan.
    ///
    /// Recovery must scan every finalized block with the exact derived account
    /// set committed by the plan. Selecting a birthday after the account's
    /// first possible output can permanently omit funds.
    pub fn create_from_recovery_plan(
        path: &Path,
        root_key: &[u8; 32],
        config: WalletDatabaseConfig,
        plan: WalletRecoveryPlan,
    ) -> Result<Self, WalletDbError> {
        let WalletRecoveryPlan {
            checkpoint,
            target,
            account_ids,
            account_set_commitment,
            gap_limit,
        } = plan;
        let checkpoint_tip = checkpoint.into_tip();
        Self::create_with_origin(
            path,
            root_key,
            config,
            WalletOrigin {
                kind: WalletOriginKind::Birthday,
                tip: checkpoint_tip.clone(),
            },
            WalletRecoveryState::Seed(SeedRecoveryProgress {
                phase: WalletRecoveryPhase::InProgress,
                state_height: checkpoint_tip.height(),
                state_block_hash: checkpoint_tip.block_hash(),
                target,
                account_ids,
                account_set_commitment,
                gap_limit,
                used_accounts: 0,
            }),
        )
    }

    fn create_with_origin(
        path: &Path,
        root_key: &[u8; 32],
        config: WalletDatabaseConfig,
        origin: WalletOrigin,
        recovery: WalletRecoveryState,
    ) -> Result<Self, WalletDbError> {
        if config.maximum_note_value > i64::MAX as u64 {
            return Err(WalletDbError::InvalidConfiguration);
        }
        let initial_tip = &origin.tip;
        let frontier = incremental_frontier(initial_tip)?;
        let parent = protected_parent(path)?;
        let lock = open_lock(path)?;
        create_database_file(path)?;
        verify_database_file(path)?;

        let mut connection = open_sqlite(path)?;
        configure_connection(&connection)?;
        let mut database_id = [0; 32];
        OsRng
            .try_fill_bytes(&mut database_id)
            .map_err(|_| WalletDbError::EntropyUnavailable)?;
        if database_id == [0; 32] {
            return Err(WalletDbError::EntropyUnavailable);
        }
        let crypto = WalletDbCrypto::derive(
            root_key,
            database_id,
            initial_tip.chain_id(),
            config.wallet_id,
            config.maximum_note_value,
            config.max_checkpoints,
        );
        let key_check = crypto.seal(RecordKind::KeyCheck, b"key-check", KEY_CHECK_PLAINTEXT)?;
        let tip_payload = crypto.seal(RecordKind::Tip, b"tip", &encode_tip(initial_tip)?)?;
        let origin_payload =
            crypto.seal(RecordKind::Origin, b"origin", &encode_origin(&origin)?)?;
        let recovery_payload = crypto.seal(
            RecordKind::Recovery,
            b"recovery",
            &encode_recovery_state(&recovery)?,
        )?;
        let cap_payload = crypto.seal(RecordKind::Cap, b"cap", &encode_tree(&Tree::empty())?)?;

        let transaction = map_database_error(
            connection.transaction_with_behavior(TransactionBehavior::Exclusive),
        )?;
        let initialized = (|| {
            create_schema(&transaction)?;
            map_database_error(transaction.execute(
                "INSERT INTO wallet_metadata(
                    singleton, schema_version, database_id, chain_id, wallet_id,
                    maximum_note_value, max_checkpoints, key_check
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    i64::from(SCHEMA_VERSION),
                    database_id.to_vec(),
                    initial_tip.chain_id().as_bytes().to_vec(),
                    config.wallet_id.to_vec(),
                    i64::try_from(config.maximum_note_value)
                        .map_err(|_| WalletDbError::InvalidConfiguration)?,
                    i64::try_from(config.max_checkpoints)
                        .map_err(|_| WalletDbError::InvalidConfiguration)?,
                    key_check
                ],
            ))?;
            map_database_error(transaction.execute(
                "INSERT INTO wallet_tip(singleton, payload) VALUES (1, ?1)",
                params![tip_payload],
            ))?;
            map_database_error(transaction.execute(
                "INSERT INTO wallet_origin(singleton, payload) VALUES (1, ?1)",
                params![origin_payload],
            ))?;
            map_database_error(transaction.execute(
                "INSERT INTO wallet_recovery(singleton, payload) VALUES (1, ?1)",
                params![recovery_payload],
            ))?;
            map_database_error(transaction.execute(
                "INSERT INTO tree_cap(singleton, payload) VALUES (1, ?1)",
                params![cap_payload],
            ))?;
            let store = SqliteShardStore::new(&transaction, &crypto);
            let mut tree = WalletShardTree::new(store, config.max_checkpoints);
            tree.insert_frontier(
                frontier,
                Retention::Checkpoint {
                    id: initial_tip.height(),
                    marking: Marking::Reference,
                },
            )
            .map_err(|_| WalletDbError::WitnessStateFailure)?;
            let root = tree
                .root_at_checkpoint_id_caching(&initial_tip.height())
                .map_err(|_| WalletDbError::WitnessStateFailure)?
                .ok_or(WalletDbError::WitnessStateFailure)?;
            if root.to_bytes() != initial_tip.tree_root().to_bytes()
                || tree
                    .max_leaf_position(None)
                    .map_err(|_| WalletDbError::WitnessStateFailure)?
                    != initial_tip.tree_size().checked_sub(1).map(Position::from)
            {
                return Err(WalletDbError::WitnessStateFailure);
            }
            Ok(())
        })();
        match initialized {
            Ok(()) => map_database_error(transaction.commit())?,
            Err(error) => {
                if transaction.rollback().is_err() {
                    return Err(WalletDbError::Poisoned);
                }
                return Err(error);
            }
        }
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        sync_parent(&parent)?;

        let database = Self {
            path: path.to_path_buf(),
            connection,
            _lock: lock,
            crypto,
            config,
            poisoned: false,
        };
        database.validate_open_state()?;
        Ok(database)
    }

    /// Opens an existing database and authenticates its network, wallet scope,
    /// key check, tip, ShardTree root, and maximum leaf position.
    pub fn open(
        path: &Path,
        root_key: &[u8; 32],
        expected_chain_id: ChainId,
        expected_wallet_id: [u8; 32],
        minimum_finalized_height: u64,
    ) -> Result<Self, WalletDbError> {
        protected_parent(path)?;
        verify_database_file(path)?;
        let lock = open_lock(path)?;
        Self::open_locked(
            path,
            root_key,
            expected_chain_id,
            expected_wallet_id,
            minimum_finalized_height,
            lock,
        )
    }

    /// Migrates an authenticated schema-1 genesis wallet to schema 2.
    ///
    /// A complete authenticated legacy backup is published before the
    /// in-place transaction begins. Schema-1 birthday wallets cannot be
    /// upgraded because they predate durable account-set and completeness
    /// state; they must be recovered into a new destination instead.
    pub fn migrate_legacy_v1(
        path: &Path,
        migration_backup_path: &Path,
        root_key: &[u8; 32],
        expected_chain_id: ChainId,
        expected_wallet_id: [u8; 32],
        minimum_finalized_height: u64,
    ) -> Result<Self, WalletDbError> {
        if path == migration_backup_path {
            return Err(WalletDbError::InvalidPath);
        }
        protected_parent(path)?;
        verify_database_file(path)?;
        let lock = open_lock(path)?;
        let legacy = Self::open_legacy_locked(
            path,
            root_key,
            expected_chain_id,
            expected_wallet_id,
            minimum_finalized_height,
            lock,
        )?;
        if legacy.load_origin_record(&legacy.connection)?.kind != WalletOriginKind::Genesis {
            return Err(WalletDbError::UnsupportedMigration);
        }
        legacy.export_backup(migration_backup_path, root_key)?;
        legacy.migrate_legacy_in_place(path, root_key, None)
    }

    fn open_restored_with_legacy_migration(
        path: &Path,
        root_key: &[u8; 32],
        expected_chain_id: ChainId,
        expected_wallet_id: [u8; 32],
        minimum_finalized_height: u64,
    ) -> Result<Self, WalletDbError> {
        match Self::open(
            path,
            root_key,
            expected_chain_id,
            expected_wallet_id,
            minimum_finalized_height,
        ) {
            Ok(database) => Ok(database),
            Err(WalletDbError::UnsupportedSchema) => {
                let lock = open_lock(path)?;
                let legacy = Self::open_legacy_locked(
                    path,
                    root_key,
                    expected_chain_id,
                    expected_wallet_id,
                    minimum_finalized_height,
                    lock,
                )?;
                if legacy.load_origin_record(&legacy.connection)?.kind != WalletOriginKind::Genesis
                {
                    return Err(WalletDbError::UnsupportedMigration);
                }
                legacy.migrate_legacy_in_place(path, root_key, None)
            }
            Err(error) => Err(error),
        }
    }

    fn migrate_legacy_in_place(
        mut self,
        path: &Path,
        root_key: &[u8; 32],
        fail_after_stage: Option<u8>,
    ) -> Result<Self, WalletDbError> {
        if self.crypto.schema_version != LEGACY_SCHEMA_VERSION {
            return Err(WalletDbError::UnsupportedSchema);
        }
        let metadata = load_metadata_for_schema(&self.connection, LEGACY_SCHEMA_VERSION)?;
        let current_crypto = WalletDbCrypto::derive(
            root_key,
            metadata.database_id,
            metadata.chain_id,
            metadata.wallet_id,
            metadata.maximum_note_value,
            metadata.max_checkpoints,
        );
        let transaction = map_database_error(
            self.connection
                .transaction_with_behavior(TransactionBehavior::Exclusive),
        )?;
        let migrated = migrate_schema_v1_to_v2(
            &transaction,
            &self.crypto,
            &current_crypto,
            &metadata,
            fail_after_stage,
        );
        match migrated {
            Ok(()) => map_database_error(transaction.commit())?,
            Err(error) => {
                if transaction.rollback().is_err() {
                    return Err(WalletDbError::Poisoned);
                }
                return Err(error);
            }
        }
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        self.crypto = current_crypto;
        self.validate_open_state()?;
        Ok(self)
    }

    fn open_locked(
        path: &Path,
        root_key: &[u8; 32],
        expected_chain_id: ChainId,
        expected_wallet_id: [u8; 32],
        minimum_finalized_height: u64,
        lock: File,
    ) -> Result<Self, WalletDbError> {
        Self::open_locked_at_schema(
            path,
            root_key,
            expected_chain_id,
            expected_wallet_id,
            minimum_finalized_height,
            lock,
            SCHEMA_VERSION,
        )
    }

    fn open_legacy_locked(
        path: &Path,
        root_key: &[u8; 32],
        expected_chain_id: ChainId,
        expected_wallet_id: [u8; 32],
        minimum_finalized_height: u64,
        lock: File,
    ) -> Result<Self, WalletDbError> {
        Self::open_locked_at_schema(
            path,
            root_key,
            expected_chain_id,
            expected_wallet_id,
            minimum_finalized_height,
            lock,
            LEGACY_SCHEMA_VERSION,
        )
    }

    fn open_locked_at_schema(
        path: &Path,
        root_key: &[u8; 32],
        expected_chain_id: ChainId,
        expected_wallet_id: [u8; 32],
        minimum_finalized_height: u64,
        lock: File,
        schema_version: u32,
    ) -> Result<Self, WalletDbError> {
        let connection = open_sqlite(path)?;
        configure_connection(&connection)?;
        let quick_check: String =
            map_database_error(
                connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0)),
            )?;
        if quick_check != "ok" {
            return Err(WalletDbError::CorruptState);
        }
        let user_version: i64 =
            map_database_error(connection.query_row("PRAGMA user_version", [], |row| row.get(0)))?;
        if user_version != i64::from(schema_version) {
            return Err(WalletDbError::UnsupportedSchema);
        }
        let metadata = load_metadata_for_schema(&connection, schema_version)?;
        if metadata.chain_id != expected_chain_id || metadata.wallet_id != expected_wallet_id {
            return Err(WalletDbError::ScopeMismatch);
        }
        let crypto = WalletDbCrypto::derive_for_schema(
            root_key,
            metadata.database_id,
            metadata.chain_id,
            metadata.wallet_id,
            metadata.maximum_note_value,
            metadata.max_checkpoints,
            schema_version,
        );
        let key_check = crypto.open(RecordKind::KeyCheck, b"key-check", &metadata.key_check)?;
        if key_check.as_slice() != KEY_CHECK_PLAINTEXT {
            return Err(WalletDbError::AuthenticationFailed);
        }
        let database = Self {
            path: path.to_path_buf(),
            connection,
            _lock: lock,
            crypto,
            config: WalletDatabaseConfig {
                wallet_id: metadata.wallet_id,
                maximum_note_value: metadata.maximum_note_value,
                max_checkpoints: metadata.max_checkpoints,
            },
            poisoned: false,
        };
        database.validate_open_state()?;
        if database.load_tip_record(&database.connection)?.height() < minimum_finalized_height {
            return Err(WalletDbError::RollbackDetected);
        }
        Ok(database)
    }

    /// Immutable creation-time database policy.
    #[must_use]
    pub const fn config(&self) -> WalletDatabaseConfig {
        self.config
    }

    /// Commits the exact database identity, scope, and authenticated finalized
    /// tip for a rollback-resistant platform state slot.
    pub fn rollback_anchor(&self) -> Result<WalletRollbackAnchor, WalletDbError> {
        if self.poisoned {
            return Err(WalletDbError::Poisoned);
        }
        let tip = self.load_tip_record(&self.connection)?;
        self.rollback_anchor_for_tip(&tip)
    }

    pub(crate) fn rollback_anchor_for_tip(
        &self,
        tip: &WalletScanTip,
    ) -> Result<WalletRollbackAnchor, WalletDbError> {
        if tip.chain_id() != self.crypto.chain_id {
            return Err(WalletDbError::ScopeMismatch);
        }
        let mut hasher = Hasher::new_derive_key(ROLLBACK_ANCHOR_DOMAIN);
        hasher.update(&self.crypto.database_id);
        hasher.update(self.crypto.chain_id.as_bytes());
        hasher.update(&self.crypto.wallet_id);
        hasher.update(&tip.height().to_be_bytes());
        hasher.update(&tip.block_hash());
        hasher.update(&tip.tree_size().to_be_bytes());
        hasher.update(&tip.tree_root().to_bytes());
        WalletRollbackAnchor::new(tip.height(), *hasher.finalize().as_bytes())
    }

    /// Rewrites the database with SQLite `VACUUM`, then revalidates all private
    /// state before returning storage measurements.
    ///
    /// Compaction can require temporary disk space comparable to the database.
    /// Callers must create and drill a current backup first. Any failure is
    /// reported; if the post-failure database cannot be fully validated, the
    /// handle is permanently poisoned.
    pub fn compact(&mut self) -> Result<WalletCompactionSummary, WalletDbError> {
        if self.poisoned {
            return Err(WalletDbError::Poisoned);
        }
        self.validate_open_state()?;
        let before_bytes = fs::metadata(&self.path)
            .map_err(|_| WalletDbError::DatabaseFailure)?
            .len();
        let before_pages = u64::try_from(map_database_error(self.connection.query_row(
            "PRAGMA page_count",
            [],
            |row| row.get::<_, i64>(0),
        ))?)
        .map_err(|_| WalletDbError::DatabaseFailure)?;
        let before_free_pages = u64::try_from(map_database_error(self.connection.query_row(
            "PRAGMA freelist_count",
            [],
            |row| row.get::<_, i64>(0),
        ))?)
        .map_err(|_| WalletDbError::DatabaseFailure)?;

        if map_database_error(self.connection.execute_batch("VACUUM")).is_err() {
            if self.validate_open_state().is_err() {
                self.poisoned = true;
                return Err(WalletDbError::Poisoned);
            }
            return Err(WalletDbError::DatabaseFailure);
        }
        File::open(&self.path)
            .and_then(|file| file.sync_all())
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        self.validate_open_state()?;

        let after_bytes = fs::metadata(&self.path)
            .map_err(|_| WalletDbError::DatabaseFailure)?
            .len();
        let after_pages = u64::try_from(map_database_error(self.connection.query_row(
            "PRAGMA page_count",
            [],
            |row| row.get::<_, i64>(0),
        ))?)
        .map_err(|_| WalletDbError::DatabaseFailure)?;
        let after_free_pages = u64::try_from(map_database_error(self.connection.query_row(
            "PRAGMA freelist_count",
            [],
            |row| row.get::<_, i64>(0),
        ))?)
        .map_err(|_| WalletDbError::DatabaseFailure)?;
        if after_free_pages != 0 {
            self.poisoned = true;
            return Err(WalletDbError::Poisoned);
        }
        Ok(WalletCompactionSummary {
            before_bytes,
            after_bytes,
            before_pages,
            after_pages,
            reclaimed_pages: before_free_pages,
        })
    }

    /// Authenticated birthday frontier retained for deterministic seed rescans.
    pub fn birthday_checkpoint(&self) -> Result<Option<WalletBirthdayCheckpoint>, WalletDbError> {
        if self.poisoned {
            return Err(WalletDbError::Poisoned);
        }
        let origin = self.load_origin_record(&self.connection)?;
        match origin.kind {
            WalletOriginKind::Genesis => Ok(None),
            WalletOriginKind::Birthday => WalletBirthdayCheckpoint::from_stored_tip(origin.tip)
                .map(Some)
                .map_err(|_| WalletDbError::CorruptState),
        }
    }

    /// Loads the authenticated recovery phase without exposing seed material
    /// or viewing capabilities.
    pub fn recovery_status(&self) -> Result<WalletRecoveryStatus, WalletDbError> {
        if self.poisoned {
            return Err(WalletDbError::Poisoned);
        }
        let tip = self.load_tip_record(&self.connection)?;
        let origin = self.load_origin_record(&self.connection)?;
        match self.load_recovery_record(&self.connection)? {
            WalletRecoveryState::NotRequired => Ok(WalletRecoveryStatus::NotRequired),
            WalletRecoveryState::Seed(progress) => {
                let account_count = u8::try_from(progress.account_ids.len())
                    .map_err(|_| WalletDbError::CorruptState)?;
                Ok(match progress.phase {
                    WalletRecoveryPhase::InProgress => WalletRecoveryStatus::InProgress {
                        birthday_height: origin.tip.height(),
                        scanned_height: tip.height(),
                        target_height: progress.target.height,
                        account_count,
                        gap_limit: progress.gap_limit,
                    },
                    WalletRecoveryPhase::Complete => WalletRecoveryStatus::Complete {
                        target_height: progress.target.height,
                        account_count,
                        highest_used_account: highest_used_account(&progress),
                    },
                    WalletRecoveryPhase::AccountRangeExhausted => {
                        WalletRecoveryStatus::RequiresLargerAccountRange {
                            target_height: progress.target.height,
                            account_count,
                            highest_used_account: highest_used_account(&progress)
                                .ok_or(WalletDbError::CorruptState)?,
                            gap_limit: progress.gap_limit,
                        }
                    }
                })
            }
        }
    }

    pub(crate) fn recovery_account_set_matches(
        &self,
        commitment: [u8; 32],
    ) -> Result<bool, WalletDbError> {
        if self.poisoned {
            return Err(WalletDbError::Poisoned);
        }
        Ok(matches!(
            self.load_recovery_record(&self.connection)?,
            WalletRecoveryState::Seed(SeedRecoveryProgress {
                account_set_commitment,
                ..
            }) if account_set_commitment == commitment
        ))
    }

    /// Builds a current finalized witness for one known owned nullifier.
    pub fn witness_for_spend(
        &self,
        spend_nullifier: ActionNullifier,
    ) -> Result<WalletSpendWitness, WalletDbError> {
        if self.poisoned {
            return Err(WalletDbError::Poisoned);
        }
        if !matches!(
            self.load_recovery_record(&self.connection)?,
            WalletRecoveryState::NotRequired
                | WalletRecoveryState::Seed(SeedRecoveryProgress {
                    phase: WalletRecoveryPhase::Complete,
                    ..
                })
        ) {
            return Err(WalletDbError::RecoveryIncomplete);
        }
        let tip = self.load_tip_record(&self.connection)?;
        let note = self
            .load_note(&self.connection, spend_nullifier)?
            .ok_or(WalletDbError::NoteNotFound)?;
        if note.spent_height.is_some() {
            return Err(WalletDbError::NoteAlreadySpent);
        }
        let store = SqliteShardStore::new(&self.connection, &self.crypto);
        let tree = WalletShardTree::new(store, self.config.max_checkpoints);
        let path = tree
            .witness_at_checkpoint_id(Position::from(u64::from(note.position)), &tip.height())
            .map_err(|_| WalletDbError::WitnessStateFailure)?
            .ok_or(WalletDbError::WitnessStateFailure)?;
        if path.position() != Position::from(u64::from(note.position)) {
            return Err(WalletDbError::CorruptState);
        }
        let authentication_nodes = path
            .path_elems()
            .iter()
            .map(MerkleHashOrchard::to_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| WalletDbError::CorruptState)?;
        let membership_path = NoteMembershipPath::from_parts(note.position, authentication_nodes)
            .map_err(|_| WalletDbError::CorruptState)?;
        if !membership_path.verify(note.note_commitment, tip.tree_root().to_bytes()) {
            return Err(WalletDbError::CorruptState);
        }
        Ok(WalletSpendWitness {
            account_id: note.account_id,
            key_scope: note.key_scope,
            transaction_id: note.transaction_id,
            action_index: note.action_index,
            action_nullifier: note.action_nullifier,
            spend_nullifier: note.spend_nullifier,
            decrypted: note.decrypted,
            membership_path,
            anchor: tip.tree_root().to_bytes(),
            checkpoint_height: tip.height(),
        })
    }

    fn load_tip_record(&self, connection: &Connection) -> Result<WalletScanTip, WalletDbError> {
        let payload = map_database_error(connection.query_row(
            "SELECT payload FROM wallet_tip WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        ))?;
        let plaintext = self.crypto.open(RecordKind::Tip, b"tip", &payload)?;
        let tip = decode_tip(&plaintext)?;
        if tip.chain_id() != self.crypto.chain_id {
            return Err(WalletDbError::CorruptState);
        }
        Ok(tip)
    }

    fn load_origin_record(&self, connection: &Connection) -> Result<WalletOrigin, WalletDbError> {
        let payload = map_database_error(connection.query_row(
            "SELECT payload FROM wallet_origin WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        ))?;
        let plaintext = self.crypto.open(RecordKind::Origin, b"origin", &payload)?;
        let origin = decode_origin(&plaintext)?;
        if origin.tip.chain_id() != self.crypto.chain_id {
            return Err(WalletDbError::CorruptState);
        }
        Ok(origin)
    }

    fn load_recovery_record(
        &self,
        connection: &Connection,
    ) -> Result<WalletRecoveryState, WalletDbError> {
        let payload = map_database_error(connection.query_row(
            "SELECT payload FROM wallet_recovery WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        ))?;
        let plaintext = self
            .crypto
            .open(RecordKind::Recovery, b"recovery", &payload)?;
        decode_recovery_state(&plaintext)
    }

    fn load_note(
        &self,
        connection: &Connection,
        spend_nullifier: ActionNullifier,
    ) -> Result<Option<StoredNote>, WalletDbError> {
        let tag = self.crypto.nullifier_tag(spend_nullifier);
        let payload = map_database_error(
            connection
                .query_row(
                    "SELECT payload FROM wallet_notes WHERE nullifier_tag = ?1",
                    params![tag.to_vec()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional(),
        )?;
        payload
            .map(|payload| {
                let plaintext = self.crypto.open(RecordKind::Note, &tag, &payload)?;
                let note = StoredNote::decode(&plaintext, self.config.maximum_note_value)?;
                if note.spend_nullifier != spend_nullifier {
                    return Err(WalletDbError::CorruptState);
                }
                Ok(note)
            })
            .transpose()
    }

    fn write_note(
        &self,
        connection: &Connection,
        note: &StoredNote,
        insert: bool,
    ) -> Result<(), WalletDbError> {
        let tag = self.crypto.nullifier_tag(note.spend_nullifier);
        let plaintext = note.encode()?;
        let payload = self.crypto.seal(RecordKind::Note, &tag, &plaintext)?;
        let changed = if insert {
            map_database_error(connection.execute(
                "INSERT INTO wallet_notes(nullifier_tag, payload) VALUES (?1, ?2)",
                params![tag.to_vec(), payload],
            ))?
        } else {
            map_database_error(connection.execute(
                "UPDATE wallet_notes SET payload = ?1 WHERE nullifier_tag = ?2",
                params![payload, tag.to_vec()],
            ))?
        };
        if changed != 1 {
            return Err(WalletDbError::CorruptState);
        }
        Ok(())
    }

    fn validate_open_state(&self) -> Result<(), WalletDbError> {
        let tip = self.load_tip_record(&self.connection)?;
        let origin = self.load_origin_record(&self.connection)?;
        if origin.tip.height() > tip.height()
            || origin.tip.tree_size() > tip.tree_size()
            || (origin.tip.height() == tip.height() && origin.tip != tip)
        {
            return Err(WalletDbError::CorruptState);
        }
        match self.crypto.schema_version {
            LEGACY_SCHEMA_VERSION => {
                let recovery_tables: i64 = map_database_error(self.connection.query_row(
                    "SELECT count(*) FROM sqlite_schema
                     WHERE type = 'table' AND name = 'wallet_recovery'",
                    [],
                    |row| row.get(0),
                ))?;
                if recovery_tables != 0 {
                    return Err(WalletDbError::CorruptState);
                }
            }
            SCHEMA_VERSION => {
                let recovery = self.load_recovery_record(&self.connection)?;
                match (origin.kind, &recovery) {
                    (WalletOriginKind::Genesis, WalletRecoveryState::NotRequired) => {}
                    (WalletOriginKind::Birthday, WalletRecoveryState::Seed(progress)) => {
                        if progress.state_height != tip.height()
                            || progress.state_block_hash != tip.block_hash()
                            || progress.target.height <= origin.tip.height()
                            || progress.target.tree_size < origin.tip.tree_size()
                        {
                            return Err(WalletDbError::CorruptState);
                        }
                        match progress.phase {
                            WalletRecoveryPhase::InProgress
                                if tip.height() < progress.target.height => {}
                            WalletRecoveryPhase::Complete
                                if tip.height() >= progress.target.height =>
                            {
                                if !recovery_gap_satisfied(progress)
                                    || (tip.height() == progress.target.height
                                        && !tip_matches_recovery_target(&tip, progress.target))
                                {
                                    return Err(WalletDbError::CorruptState);
                                }
                            }
                            WalletRecoveryPhase::AccountRangeExhausted
                                if tip_matches_recovery_target(&tip, progress.target) =>
                            {
                                if recovery_gap_satisfied(progress)
                                    || highest_used_account(progress).is_none()
                                {
                                    return Err(WalletDbError::CorruptState);
                                }
                            }
                            WalletRecoveryPhase::InProgress
                            | WalletRecoveryPhase::Complete
                            | WalletRecoveryPhase::AccountRangeExhausted => {
                                return Err(WalletDbError::CorruptState);
                            }
                        }
                    }
                    (WalletOriginKind::Genesis, WalletRecoveryState::Seed(_))
                    | (WalletOriginKind::Birthday, WalletRecoveryState::NotRequired) => {
                        return Err(WalletDbError::CorruptState);
                    }
                }
            }
            _ => return Err(WalletDbError::UnsupportedSchema),
        }
        let store = SqliteShardStore::new(&self.connection, &self.crypto);
        let tree = WalletShardTree::new(store, self.config.max_checkpoints);
        let maximum_position = tree
            .max_leaf_position(None)
            .map_err(|_| WalletDbError::WitnessStateFailure)?;
        let expected_position = tip.tree_size().checked_sub(1).map(Position::from);
        if maximum_position != expected_position {
            return Err(WalletDbError::CorruptState);
        }
        let root = tree
            .root_at_checkpoint_depth(None)
            .map_err(|_| WalletDbError::WitnessStateFailure)?
            .ok_or(WalletDbError::CorruptState)?;
        if root.to_bytes() != tip.tree_root().to_bytes() {
            return Err(WalletDbError::CorruptState);
        }
        let latest = tree
            .store()
            .max_checkpoint_id()?
            .ok_or(WalletDbError::CorruptState)?;
        if latest != tip.height() {
            return Err(WalletDbError::CorruptState);
        }
        self.validate_note_index(&tree, &tip)?;
        Ok(())
    }

    fn validate_note_index(
        &self,
        tree: &WalletShardTree<'_>,
        tip: &WalletScanTip,
    ) -> Result<(), WalletDbError> {
        let checkpoint_count = tree.store().checkpoint_count()?;
        if checkpoint_count > MAX_DATABASE_CHECKPOINT_ROWS {
            return Err(WalletDbError::CorruptState);
        }
        if tree.store().retained_checkpoints()?.len() > MAX_CHECKPOINTS_LIMIT {
            return Err(WalletDbError::CorruptState);
        }
        let mut marks_removed = BTreeSet::new();
        tree.store()
            .for_each_checkpoint(checkpoint_count, |_, checkpoint| {
                marks_removed.extend(checkpoint.marks_removed().iter().copied());
                Ok(())
            })?;
        let mut effective_marked = tree
            .marked_positions()
            .map_err(|_| WalletDbError::WitnessStateFailure)?;
        for position in marks_removed {
            effective_marked.remove(&position);
        }

        let mut statement = map_database_error(
            self.connection
                .prepare("SELECT nullifier_tag, payload FROM wallet_notes"),
        )?;
        let rows = map_database_error(statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        }))?;
        let mut unspent_positions = BTreeSet::new();
        for row in rows {
            let (raw_tag, payload) = map_database_error(row)?;
            let tag: [u8; 32] = raw_tag
                .try_into()
                .map_err(|_| WalletDbError::CorruptState)?;
            let plaintext = self.crypto.open(RecordKind::Note, &tag, &payload)?;
            let note = StoredNote::decode(&plaintext, self.config.maximum_note_value)?;
            if self.crypto.nullifier_tag(note.spend_nullifier) != tag
                || u64::from(note.position) >= tip.tree_size()
                || note
                    .spent_height
                    .is_some_and(|height| height > tip.height())
            {
                return Err(WalletDbError::CorruptState);
            }
            if note.spent_height.is_none() {
                let position = Position::from(u64::from(note.position));
                if !unspent_positions.insert(position)
                    || tree
                        .get_marked_leaf(position)
                        .map_err(|_| WalletDbError::WitnessStateFailure)?
                        .is_none_or(|hash| hash.to_bytes() != note.note_commitment)
                {
                    return Err(WalletDbError::CorruptState);
                }
            }
        }
        if unspent_positions != effective_marked {
            return Err(WalletDbError::CorruptState);
        }
        Ok(())
    }

    fn apply_finalized_block(
        &self,
        transaction: &Transaction<'_>,
        update: &ScannedBlockUpdate,
    ) -> Result<(), WalletDbError> {
        let current = self.load_tip_record(transaction)?;
        if current.height() != update.expected_parent_height()
            || current.block_hash() != update.expected_parent_hash()
            || current.tree_size() != update.expected_pre_tree_size()
            || current.tree_root() != update.expected_pre_tree_root()
        {
            return Err(WalletDbError::TipMismatch);
        }

        let mut recovery = self.load_recovery_record(transaction)?;
        if let WalletRecoveryState::Seed(progress) = &mut recovery {
            if progress.state_height != current.height()
                || progress.state_block_hash != current.block_hash()
            {
                return Err(WalletDbError::CorruptState);
            }
            match progress.phase {
                WalletRecoveryPhase::InProgress => {
                    if update.scan_account_set_commitment() != progress.account_set_commitment {
                        return Err(WalletDbError::RecoveryAccountMismatch);
                    }
                    if update.next_tip().height() > progress.target.height {
                        return Err(WalletDbError::RecoveryTargetMismatch);
                    }
                    for note in update.detected_notes() {
                        let index = progress
                            .account_ids
                            .iter()
                            .position(|account_id| *account_id == note.account_id())
                            .ok_or(WalletDbError::RecoveryAccountMismatch)?;
                        progress.used_accounts |= 1u64
                            .checked_shl(
                                u32::try_from(index).map_err(|_| WalletDbError::CorruptState)?,
                            )
                            .ok_or(WalletDbError::CorruptState)?;
                    }
                    if update.next_tip().height() == progress.target.height {
                        if !tip_matches_recovery_target(update.next_tip(), progress.target) {
                            return Err(WalletDbError::RecoveryTargetMismatch);
                        }
                        progress.phase = if recovery_gap_satisfied(progress) {
                            WalletRecoveryPhase::Complete
                        } else {
                            WalletRecoveryPhase::AccountRangeExhausted
                        };
                    }
                }
                WalletRecoveryPhase::Complete => {}
                WalletRecoveryPhase::AccountRangeExhausted => {
                    return Err(WalletDbError::RecoveryAccountRangeExhausted);
                }
            }
        }

        let mut marked_positions = BTreeSet::new();
        for note in update.detected_notes() {
            let position = u64::from(note.position());
            let offset = position
                .checked_sub(update.expected_pre_tree_size())
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(WalletDbError::CorruptState)?;
            if update.note_commitments().get(offset) != Some(&note.output().note_commitment())
                || !marked_positions.insert(position)
            {
                return Err(WalletDbError::CorruptState);
            }
        }

        let store = SqliteShardStore::new(transaction, &self.crypto);
        let mut tree = WalletShardTree::new(store, self.config.max_checkpoints);
        let last_index = update.note_commitments().len().checked_sub(1);
        let mut values = Vec::with_capacity(update.note_commitments().len());
        for (index, commitment) in update.note_commitments().iter().enumerate() {
            let position = update
                .expected_pre_tree_size()
                .checked_add(u64::try_from(index).map_err(|_| WalletDbError::CorruptState)?)
                .ok_or(WalletDbError::CorruptState)?;
            let hash = parse_merkle_hash(*commitment)?;
            let marking = marked_positions.contains(&position);
            let retention = if Some(index) == last_index {
                Retention::Checkpoint {
                    id: update.next_tip().height(),
                    marking: if marking {
                        Marking::Marked
                    } else {
                        Marking::None
                    },
                }
            } else if marking {
                Retention::Marked
            } else {
                Retention::Ephemeral
            };
            values.push((hash, retention));
        }
        if values.is_empty() {
            if !tree
                .checkpoint(update.next_tip().height())
                .map_err(|_| WalletDbError::WitnessStateFailure)?
            {
                return Err(WalletDbError::WitnessStateFailure);
            }
        } else {
            let inserted = tree
                .batch_insert(
                    Position::from(update.expected_pre_tree_size()),
                    values.into_iter(),
                )
                .map_err(|_| WalletDbError::WitnessStateFailure)?
                .ok_or(WalletDbError::WitnessStateFailure)?;
            if u64::from(inserted.0).checked_add(1) != Some(update.next_tip().tree_size()) {
                return Err(WalletDbError::WitnessStateFailure);
            }
        }
        let root = tree
            .root_at_checkpoint_id_caching(&update.next_tip().height())
            .map_err(|_| WalletDbError::WitnessStateFailure)?
            .ok_or(WalletDbError::WitnessStateFailure)?;
        if root.to_bytes() != update.next_tip().tree_root().to_bytes() {
            return Err(WalletDbError::WitnessStateFailure);
        }

        for scanned in update.detected_notes() {
            let note = StoredNote::from_scanned(scanned, self.config.maximum_note_value)?;
            self.write_note(transaction, &note, true)?;
        }
        for nullifier in update.nullifiers() {
            if let Some(mut note) = self.load_note(transaction, *nullifier)? {
                if note.spent_height.is_some() {
                    return Err(WalletDbError::CorruptState);
                }
                note.spent_height = Some(update.next_tip().height());
                self.write_note(transaction, &note, false)?;
                if !tree
                    .remove_mark(
                        Position::from(u64::from(note.position)),
                        Some(&update.next_tip().height()),
                    )
                    .map_err(|_| WalletDbError::WitnessStateFailure)?
                {
                    return Err(WalletDbError::WitnessStateFailure);
                }
            }
        }

        let tip_payload =
            self.crypto
                .seal(RecordKind::Tip, b"tip", &encode_tip(update.next_tip())?)?;
        let changed = map_database_error(transaction.execute(
            "UPDATE wallet_tip SET payload = ?1 WHERE singleton = 1",
            params![tip_payload],
        ))?;
        if changed != 1 {
            return Err(WalletDbError::CorruptState);
        }
        if let WalletRecoveryState::Seed(progress) = &mut recovery {
            progress.state_height = update.next_tip().height();
            progress.state_block_hash = update.next_tip().block_hash();
        }
        let recovery_payload = self.crypto.seal(
            RecordKind::Recovery,
            b"recovery",
            &encode_recovery_state(&recovery)?,
        )?;
        let changed = map_database_error(transaction.execute(
            "UPDATE wallet_recovery SET payload = ?1 WHERE singleton = 1",
            params![recovery_payload],
        ))?;
        if changed != 1 {
            return Err(WalletDbError::CorruptState);
        }
        Ok(())
    }
}

impl FinalizedWalletStore for EncryptedWalletDb {
    type Error = WalletDbError;

    fn load_tip(&self) -> Result<WalletScanTip, Self::Error> {
        if self.poisoned {
            return Err(WalletDbError::Poisoned);
        }
        self.load_tip_record(&self.connection)
    }

    fn commit_finalized_block(&mut self, update: ScannedBlockUpdate) -> Result<(), Self::Error> {
        if self.poisoned {
            return Err(WalletDbError::Poisoned);
        }
        let transaction = map_database_error(Transaction::new_unchecked(
            &self.connection,
            TransactionBehavior::Immediate,
        ))?;
        let result = self.apply_finalized_block(&transaction, &update);
        match result {
            Ok(()) => match transaction.commit() {
                Ok(()) => Ok(()),
                Err(_) => {
                    self.poisoned = true;
                    Err(WalletDbError::Poisoned)
                }
            },
            Err(error) => {
                if transaction.rollback().is_err() {
                    self.poisoned = true;
                    Err(WalletDbError::Poisoned)
                } else {
                    Err(error)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use vault_privacy::{MEMO_BYTES, NoteCommitmentTree, PreparedNoteOutput, VaultSpendingKey};
    use vault_protocol::{
        CompactBlock, CompactBlockAction, CompactBlockTransaction, FinalizedCompactBlockHeader,
        TransactionId,
    };

    use crate::{WalletScanAccount, scan_finalized_block};

    const TEST_CHAIN: [u8; 32] = [0x31; 32];
    const TEST_WALLET: [u8; 32] = [0x32; 32];
    const TEST_ROOT_KEY: [u8; 32] = [0x33; 32];

    fn test_tip() -> WalletScanTip {
        WalletScanTip::from_verified_checkpoint(
            ChainId::new(TEST_CHAIN),
            0,
            [0x34; 32],
            &NoteTreeSnapshot::from_parts(0, None, vec![]),
        )
        .unwrap()
    }

    fn test_config() -> WalletDatabaseConfig {
        WalletDatabaseConfig::new(TEST_WALLET, 21_000_000 * 1_000_000_000, 100).unwrap()
    }

    fn test_path(directory: &Path, name: &str) -> PathBuf {
        fs::canonicalize(directory).unwrap().join(name)
    }

    fn convert_current_fixture_to_legacy(path: &Path) {
        let mut connection = open_sqlite(path).unwrap();
        configure_connection(&connection).unwrap();
        let metadata = load_metadata_for_schema(&connection, SCHEMA_VERSION).unwrap();
        let current_crypto = WalletDbCrypto::derive(
            &TEST_ROOT_KEY,
            metadata.database_id,
            metadata.chain_id,
            metadata.wallet_id,
            metadata.maximum_note_value,
            metadata.max_checkpoints,
        );
        let legacy_crypto = WalletDbCrypto::derive_for_schema(
            &TEST_ROOT_KEY,
            metadata.database_id,
            metadata.chain_id,
            metadata.wallet_id,
            metadata.maximum_note_value,
            metadata.max_checkpoints,
            LEGACY_SCHEMA_VERSION,
        );
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .unwrap();
        reseal_singleton_payload(
            &transaction,
            &current_crypto,
            &legacy_crypto,
            "SELECT payload FROM wallet_tip WHERE singleton = 1",
            "UPDATE wallet_tip SET payload = ?1 WHERE singleton = 1",
            RecordKind::Tip,
            b"tip",
        )
        .unwrap();
        reseal_singleton_payload(
            &transaction,
            &current_crypto,
            &legacy_crypto,
            "SELECT payload FROM wallet_origin WHERE singleton = 1",
            "UPDATE wallet_origin SET payload = ?1 WHERE singleton = 1",
            RecordKind::Origin,
            b"origin",
        )
        .unwrap();
        reseal_note_payloads(&transaction, &current_crypto, &legacy_crypto).unwrap();
        reseal_integer_keyed_payloads(
            &transaction,
            &current_crypto,
            &legacy_crypto,
            "SELECT shard_index, payload FROM tree_shards
             WHERE shard_index > ?1 ORDER BY shard_index ASC LIMIT 1",
            "UPDATE tree_shards SET payload = ?1 WHERE shard_index = ?2",
            RecordKind::Shard,
        )
        .unwrap();
        reseal_singleton_payload(
            &transaction,
            &current_crypto,
            &legacy_crypto,
            "SELECT payload FROM tree_cap WHERE singleton = 1",
            "UPDATE tree_cap SET payload = ?1 WHERE singleton = 1",
            RecordKind::Cap,
            b"cap",
        )
        .unwrap();
        reseal_integer_keyed_payloads(
            &transaction,
            &current_crypto,
            &legacy_crypto,
            "SELECT checkpoint_id, payload FROM tree_checkpoints
             WHERE checkpoint_id > ?1 ORDER BY checkpoint_id ASC LIMIT 1",
            "UPDATE tree_checkpoints SET payload = ?1 WHERE checkpoint_id = ?2",
            RecordKind::Checkpoint,
        )
        .unwrap();
        reseal_integer_keyed_payloads(
            &transaction,
            &current_crypto,
            &legacy_crypto,
            "SELECT checkpoint_id, payload FROM tree_retained_checkpoints
             WHERE checkpoint_id > ?1 ORDER BY checkpoint_id ASC LIMIT 1",
            "UPDATE tree_retained_checkpoints SET payload = ?1 WHERE checkpoint_id = ?2",
            RecordKind::RetainedCheckpoint,
        )
        .unwrap();
        let key_check = current_crypto
            .open(RecordKind::KeyCheck, b"key-check", &metadata.key_check)
            .unwrap();
        assert_eq!(key_check.as_slice(), KEY_CHECK_PLAINTEXT);
        let legacy_key_check = legacy_crypto
            .seal(RecordKind::KeyCheck, b"key-check", KEY_CHECK_PLAINTEXT)
            .unwrap();
        transaction
            .execute_batch(
                "CREATE TABLE wallet_metadata_v1 (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                    database_id BLOB NOT NULL CHECK (length(database_id) = 32),
                    chain_id BLOB NOT NULL CHECK (length(chain_id) = 32),
                    wallet_id BLOB NOT NULL CHECK (length(wallet_id) = 32),
                    maximum_note_value INTEGER NOT NULL CHECK (maximum_note_value > 0),
                    max_checkpoints INTEGER NOT NULL CHECK (max_checkpoints > 0 AND max_checkpoints <= 4096),
                    key_check BLOB NOT NULL
                ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            transaction
                .execute(
                    "INSERT INTO wallet_metadata_v1(
                        singleton, schema_version, database_id, chain_id, wallet_id,
                        maximum_note_value, max_checkpoints, key_check
                     ) VALUES (1, 1, ?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        metadata.database_id.to_vec(),
                        metadata.chain_id.as_bytes().to_vec(),
                        metadata.wallet_id.to_vec(),
                        i64::try_from(metadata.maximum_note_value).unwrap(),
                        i64::try_from(metadata.max_checkpoints).unwrap(),
                        legacy_key_check,
                    ],
                )
                .unwrap(),
            1
        );
        transaction
            .execute_batch(
                "DROP TABLE wallet_recovery;
                 DROP TABLE wallet_metadata;
                 ALTER TABLE wallet_metadata_v1 RENAME TO wallet_metadata;
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    fn commit_test_note(database: &mut EncryptedWalletDb) -> ActionNullifier {
        let tip = database.load_tip().unwrap();
        let owner = VaultSpendingKey::derive(&[0x35; 32], TEST_CHAIN, 0)
            .unwrap()
            .full_viewing_key();
        let action_nullifier = ActionNullifier::from_bytes([0x36; 32]).unwrap();
        let mut rng = ChaCha20Rng::from_seed([0x37; 32]);
        let prepared = PreparedNoteOutput::create(
            &owner,
            KeyScope::External,
            owner.address_at(0, KeyScope::External),
            123_456,
            test_config().maximum_note_value(),
            action_nullifier,
            [0x38; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let second_nullifier = ActionNullifier::from_bytes([0x3C; 32]).unwrap();
        let second = PreparedNoteOutput::create(
            &owner,
            KeyScope::Internal,
            owner.address_at(1, KeyScope::Internal),
            654_321,
            test_config().maximum_note_value(),
            second_nullifier,
            [0x3D; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let mut post_tree = NoteCommitmentTree::restore(&tip.tree_snapshot()).unwrap();
        post_tree
            .append(prepared.encrypted_note().note_commitment())
            .unwrap();
        post_tree
            .append(second.encrypted_note().note_commitment())
            .unwrap();
        let transaction = CompactBlockTransaction::new(
            TransactionId::new([0x39; 32]),
            vec![
                CompactBlockAction::new(action_nullifier, prepared.encrypted_note().clone()),
                CompactBlockAction::new(second_nullifier, second.encrypted_note().clone()),
            ],
        )
        .unwrap();
        let block = CompactBlock::new(
            tip.chain_id(),
            1,
            [0x3A; 32],
            tip.block_hash(),
            tip.tree_size(),
            tip.tree_root(),
            post_tree.size(),
            post_tree.typed_root(),
            vec![transaction],
        )
        .unwrap();
        let header = FinalizedCompactBlockHeader::from_verified_consensus(
            block.chain_id(),
            block.height(),
            block.block_hash(),
            block.parent_hash(),
            block.pre_tree_size(),
            block.pre_tree_root(),
            block.post_tree_size(),
            block.post_tree_root(),
            block.commitment(),
        )
        .unwrap();
        let authenticated = block.authenticate(header).unwrap();
        let account =
            WalletScanAccount::new(WalletAccountId::from_bytes([0x3B; 32]).unwrap(), &owner);
        let update = scan_finalized_block(&tip, &authenticated, &[account]).unwrap();
        let spend_nullifier = update.detected_notes()[0].spend_nullifier();
        database.commit_finalized_block(update).unwrap();
        spend_nullifier
    }

    fn acceptance_bytes(context: &str, ordinal: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(&ordinal.to_be_bytes());
        *hasher.finalize().as_bytes()
    }

    fn acceptance_nullifier(ordinal: u64) -> ActionNullifier {
        for counter in 0..=u8::MAX {
            let mut hasher = blake3::Hasher::new_derive_key("vault.h1-a2.migration.nullifier.v1");
            hasher.update(&ordinal.to_be_bytes());
            hasher.update(&[counter]);
            if let Ok(nullifier) = ActionNullifier::from_bytes(*hasher.finalize().as_bytes()) {
                return nullifier;
            }
        }
        panic!("bounded migration fixture nullifier sampling exhausted")
    }

    fn commit_acceptance_history_block(
        database: &mut EncryptedWalletDb,
        owner: &vault_privacy::VaultFullViewingKey,
        height: u64,
        actions_per_block: usize,
    ) {
        let tip = database.load_tip().unwrap();
        assert_eq!(tip.height().checked_add(1), Some(height));
        let mut rng = ChaCha20Rng::from_seed(acceptance_bytes(
            "vault.h1-a2.migration.block-rng.v1",
            height,
        ));
        let mut actions = Vec::with_capacity(actions_per_block);
        for action_index in 0..actions_per_block {
            let ordinal = height
                .checked_mul(16)
                .and_then(|value| value.checked_add(action_index as u64))
                .unwrap();
            let nullifier = acceptance_nullifier(ordinal);
            let output = PreparedNoteOutput::create(
                owner,
                KeyScope::External,
                owner.address_at(u32::try_from(ordinal).unwrap(), KeyScope::External),
                ordinal.checked_add(1).unwrap(),
                test_config().maximum_note_value(),
                nullifier,
                [u8::try_from(action_index).unwrap(); MEMO_BYTES],
                &mut rng,
            )
            .unwrap();
            actions.push(CompactBlockAction::new(
                nullifier,
                output.encrypted_note().clone(),
            ));
        }
        actions.sort_by_key(CompactBlockAction::nullifier);
        let mut post_tree = NoteCommitmentTree::restore(&tip.tree_snapshot()).unwrap();
        for action in &actions {
            post_tree.append(action.output().note_commitment()).unwrap();
        }
        let transaction = CompactBlockTransaction::new(
            TransactionId::new(acceptance_bytes(
                "vault.h1-a2.migration.transaction.v1",
                height,
            )),
            actions,
        )
        .unwrap();
        let block = CompactBlock::new(
            tip.chain_id(),
            height,
            acceptance_bytes("vault.h1-a2.migration.block.v1", height),
            tip.block_hash(),
            tip.tree_size(),
            tip.tree_root(),
            post_tree.size(),
            post_tree.typed_root(),
            vec![transaction],
        )
        .unwrap();
        let header = FinalizedCompactBlockHeader::from_verified_consensus(
            block.chain_id(),
            block.height(),
            block.block_hash(),
            block.parent_hash(),
            block.pre_tree_size(),
            block.pre_tree_root(),
            block.post_tree_size(),
            block.post_tree_root(),
            block.commitment(),
        )
        .unwrap();
        let authenticated = block.authenticate(header).unwrap();
        let account =
            WalletScanAccount::new(WalletAccountId::from_bytes([0x45; 32]).unwrap(), owner);
        let update = scan_finalized_block(&tip, &authenticated, &[account]).unwrap();
        assert_eq!(update.detected_notes().len(), actions_per_block);
        database.commit_finalized_block(update).unwrap();
    }

    fn hash(byte: u8) -> MerkleHashOrchard {
        parse_merkle_hash([byte; 32]).unwrap()
    }

    #[test]
    fn tree_codec_is_canonical_bounded_and_rejects_every_truncated_prefix() {
        let tree = Tree::parent(
            Some(Arc::new(hash(1))),
            Tree::leaf((hash(2), RetentionFlags::MARKED)),
            Tree::parent(
                None,
                Tree::leaf((hash(3), RetentionFlags::CHECKPOINT)),
                Tree::empty(),
            ),
        );
        let encoded = encode_tree(&tree).unwrap();
        assert_eq!(decode_tree(&encoded, 2).unwrap(), tree);
        for length in 0..encoded.len() {
            assert!(decode_tree(&encoded[..length], 2).is_err());
        }

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_tree(&trailing, 2).unwrap_err(),
            WalletDbError::CorruptState
        );
        assert_eq!(
            decode_tree(&encoded, 1).unwrap_err(),
            WalletDbError::CorruptState
        );
        assert_eq!(
            decode_tree(&[2, 0, 0, 0], 1).unwrap_err(),
            WalletDbError::CorruptState
        );
    }

    #[test]
    fn checkpoint_codec_rejects_truncation_trailing_bytes_and_duplicate_marks() {
        let checkpoint = Checkpoint::from_parts(
            TreeState::AtPosition(Position::from(100)),
            BTreeSet::from([Position::from(3), Position::from(99)]),
        );
        let encoded = encode_checkpoint(&checkpoint).unwrap();
        let decoded = decode_checkpoint(&encoded).unwrap();
        assert_eq!(decoded.tree_state(), checkpoint.tree_state());
        assert_eq!(decoded.marks_removed(), checkpoint.marks_removed());
        for length in 0..encoded.len() {
            assert!(decode_checkpoint(&encoded[..length]).is_err());
        }

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_checkpoint(&trailing).unwrap_err(),
            WalletDbError::CorruptState
        );
        let mut duplicate = Vec::new();
        duplicate.push(0);
        duplicate.extend_from_slice(&2u32.to_be_bytes());
        duplicate.extend_from_slice(&7u64.to_be_bytes());
        duplicate.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(
            decode_checkpoint(&duplicate).unwrap_err(),
            WalletDbError::CorruptState
        );
    }

    #[test]
    fn recovery_origin_codec_rejects_truncation_trailing_bytes_and_kind_mismatch() {
        let genesis_tip = WalletScanTip::from_verified_checkpoint(
            ChainId::new([0x31; 32]),
            0,
            [0x41; 32],
            &NoteTreeSnapshot::from_parts(0, None, vec![]),
        )
        .unwrap();
        let origin = WalletOrigin {
            kind: WalletOriginKind::Genesis,
            tip: genesis_tip,
        };
        let encoded = encode_origin(&origin).unwrap();
        let decoded = decode_origin(&encoded).unwrap();
        assert_eq!(decoded.kind, WalletOriginKind::Genesis);
        assert_eq!(decoded.tip, origin.tip);
        for length in 0..encoded.len() {
            assert!(decode_origin(&encoded[..length]).is_err());
        }

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_origin(&trailing).unwrap_err(),
            WalletDbError::CorruptState
        );
        let mut unknown_kind = encoded.clone();
        unknown_kind[1] = 2;
        assert_eq!(
            decode_origin(&unknown_kind).unwrap_err(),
            WalletDbError::CorruptState
        );
        let mut false_birthday = encoded;
        false_birthday[1] = 1;
        assert_eq!(
            decode_origin(&false_birthday).unwrap_err(),
            WalletDbError::CorruptState
        );
    }

    #[test]
    fn seed_recovery_codec_is_canonical_bounded_and_rejects_tampering() {
        let state = WalletRecoveryState::Seed(SeedRecoveryProgress {
            phase: WalletRecoveryPhase::InProgress,
            state_height: 25,
            state_block_hash: [0x41; 32],
            target: WalletRecoveryTarget {
                height: 50,
                block_hash: [0x51; 32],
                tree_size: 0,
                tree_root: vault_privacy::NoteCommitmentTree::new().typed_root(),
            },
            account_ids: vec![
                WalletAccountId::from_bytes([0x61; 32]).unwrap(),
                WalletAccountId::from_bytes([0x62; 32]).unwrap(),
                WalletAccountId::from_bytes([0x63; 32]).unwrap(),
            ],
            account_set_commitment: [0x71; 32],
            gap_limit: 2,
            used_accounts: 1,
        });
        let encoded = encode_recovery_state(&state).unwrap();
        let WalletRecoveryState::Seed(decoded) = decode_recovery_state(&encoded).unwrap() else {
            panic!("seed recovery expected");
        };
        assert_eq!(decoded.phase, WalletRecoveryPhase::InProgress);
        assert_eq!(decoded.state_height, 25);
        assert_eq!(decoded.target.height, 50);
        assert_eq!(decoded.account_ids.len(), 3);
        assert_eq!(decoded.used_accounts, 1);
        for length in 0..encoded.len() {
            assert!(decode_recovery_state(&encoded[..length]).is_err());
        }

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_recovery_state(&trailing).unwrap_err(),
            WalletDbError::CorruptState
        );
        let mut unknown_phase = encoded.clone();
        unknown_phase[2] = 3;
        assert_eq!(
            decode_recovery_state(&unknown_phase).unwrap_err(),
            WalletDbError::CorruptState
        );
        let mut out_of_range_mask = encoded.clone();
        out_of_range_mask[157] = 0x80;
        assert_eq!(
            decode_recovery_state(&out_of_range_mask).unwrap_err(),
            WalletDbError::CorruptState
        );
        let mut duplicate_account = encoded;
        duplicate_account[197..229].copy_from_slice(&[0x61; 32]);
        assert_eq!(
            decode_recovery_state(&duplicate_account).unwrap_err(),
            WalletDbError::CorruptState
        );

        assert!(matches!(
            decode_recovery_state(&[1, 0]).unwrap(),
            WalletRecoveryState::NotRequired
        ));
        assert_eq!(
            decode_recovery_state(&[1, 0, 0]).unwrap_err(),
            WalletDbError::CorruptState
        );
    }

    #[test]
    fn legacy_migration_requires_backup_and_restore_upgrades_the_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = test_path(directory.path(), "wallet.sqlite3");
        let backup_path = test_path(directory.path(), "wallet-v1.backup");
        let occupied_backup_path = test_path(directory.path(), "occupied.backup");
        let restored_path = test_path(directory.path(), "wallet-restored.sqlite3");
        let database =
            EncryptedWalletDb::create(&path, &TEST_ROOT_KEY, test_config(), test_tip()).unwrap();
        drop(database);
        convert_current_fixture_to_legacy(&path);

        assert_eq!(
            EncryptedWalletDb::open(
                &path,
                &TEST_ROOT_KEY,
                ChainId::new(TEST_CHAIN),
                TEST_WALLET,
                0,
            )
            .unwrap_err(),
            WalletDbError::UnsupportedSchema
        );
        fs::write(&occupied_backup_path, b"do not replace").unwrap();
        assert_eq!(
            EncryptedWalletDb::migrate_legacy_v1(
                &path,
                &occupied_backup_path,
                &TEST_ROOT_KEY,
                ChainId::new(TEST_CHAIN),
                TEST_WALLET,
                0,
            )
            .unwrap_err(),
            WalletDbError::AlreadyExists
        );
        assert_eq!(fs::read(&occupied_backup_path).unwrap(), b"do not replace");
        assert_eq!(
            EncryptedWalletDb::open(
                &path,
                &TEST_ROOT_KEY,
                ChainId::new(TEST_CHAIN),
                TEST_WALLET,
                0,
            )
            .unwrap_err(),
            WalletDbError::UnsupportedSchema
        );
        let migrated = EncryptedWalletDb::migrate_legacy_v1(
            &path,
            &backup_path,
            &TEST_ROOT_KEY,
            ChainId::new(TEST_CHAIN),
            TEST_WALLET,
            0,
        )
        .unwrap();
        assert!(backup_path.exists());
        assert_eq!(migrated.load_tip().unwrap(), test_tip());
        assert_eq!(
            migrated.recovery_status().unwrap(),
            WalletRecoveryStatus::NotRequired
        );
        drop(migrated);
        assert_eq!(
            Connection::open(&path)
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        let redundant_backup_path = test_path(directory.path(), "redundant.backup");
        assert_eq!(
            EncryptedWalletDb::migrate_legacy_v1(
                &path,
                &redundant_backup_path,
                &TEST_ROOT_KEY,
                ChainId::new(TEST_CHAIN),
                TEST_WALLET,
                0,
            )
            .unwrap_err(),
            WalletDbError::UnsupportedSchema
        );
        assert!(!redundant_backup_path.exists());

        let restored = EncryptedWalletDb::restore_backup(
            &backup_path,
            &restored_path,
            &TEST_ROOT_KEY,
            ChainId::new(TEST_CHAIN),
            TEST_WALLET,
            0,
        )
        .unwrap();
        assert_eq!(restored.load_tip().unwrap(), test_tip());
        assert_eq!(
            restored.recovery_status().unwrap(),
            WalletRecoveryStatus::NotRequired
        );
        drop(restored);
        assert_eq!(
            Connection::open(&restored_path)
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn every_legacy_migration_stage_rolls_back_atomically() {
        let directory = tempfile::tempdir().unwrap();
        for stage in 1..=9 {
            let path = test_path(directory.path(), &format!("wallet-stage-{stage}.sqlite3"));
            let database =
                EncryptedWalletDb::create(&path, &TEST_ROOT_KEY, test_config(), test_tip())
                    .unwrap();
            drop(database);
            convert_current_fixture_to_legacy(&path);

            let lock = open_lock(&path).unwrap();
            let legacy = EncryptedWalletDb::open_legacy_locked(
                &path,
                &TEST_ROOT_KEY,
                ChainId::new(TEST_CHAIN),
                TEST_WALLET,
                0,
                lock,
            )
            .unwrap();
            assert_eq!(
                legacy
                    .migrate_legacy_in_place(&path, &TEST_ROOT_KEY, Some(stage))
                    .unwrap_err(),
                WalletDbError::DatabaseFailure
            );

            let lock = open_lock(&path).unwrap();
            let reopened = EncryptedWalletDb::open_legacy_locked(
                &path,
                &TEST_ROOT_KEY,
                ChainId::new(TEST_CHAIN),
                TEST_WALLET,
                0,
                lock,
            )
            .unwrap();
            assert_eq!(reopened.load_tip().unwrap(), test_tip());
            drop(reopened);
            let connection = Connection::open(&path).unwrap();
            assert_eq!(
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT count(*) FROM sqlite_schema
                         WHERE type = 'table' AND name = 'wallet_recovery'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn legacy_migration_reseals_nonempty_notes_shards_and_checkpoints() {
        let directory = tempfile::tempdir().unwrap();
        let path = test_path(directory.path(), "wallet-nonempty.sqlite3");
        let backup_path = test_path(directory.path(), "wallet-nonempty-v1.backup");
        let restored_path = test_path(directory.path(), "wallet-nonempty-restored.sqlite3");
        let mut database =
            EncryptedWalletDb::create(&path, &TEST_ROOT_KEY, test_config(), test_tip()).unwrap();
        let spend_nullifier = commit_test_note(&mut database);
        let expected_tip = database.load_tip().unwrap();
        assert_eq!(expected_tip.height(), 1);
        drop(database);
        let connection = Connection::open(&path).unwrap();
        assert!(
            connection
                .query_row("SELECT count(*) FROM wallet_notes", [], |row| row
                    .get::<_, i64>(0))
                .unwrap()
                > 0
        );
        assert!(
            connection
                .query_row("SELECT count(*) FROM tree_shards", [], |row| row
                    .get::<_, i64>(0))
                .unwrap()
                > 0
        );
        drop(connection);
        convert_current_fixture_to_legacy(&path);

        let migrated = EncryptedWalletDb::migrate_legacy_v1(
            &path,
            &backup_path,
            &TEST_ROOT_KEY,
            ChainId::new(TEST_CHAIN),
            TEST_WALLET,
            1,
        )
        .unwrap();
        assert_eq!(migrated.load_tip().unwrap(), expected_tip);
        assert_eq!(
            migrated
                .witness_for_spend(spend_nullifier)
                .unwrap()
                .decrypted()
                .note()
                .value(),
            123_456
        );
        drop(migrated);

        let restored = EncryptedWalletDb::restore_backup(
            &backup_path,
            &restored_path,
            &TEST_ROOT_KEY,
            ChainId::new(TEST_CHAIN),
            TEST_WALLET,
            1,
        )
        .unwrap();
        assert_eq!(restored.load_tip().unwrap(), expected_tip);
        assert_eq!(
            restored
                .witness_for_spend(spend_nullifier)
                .unwrap()
                .decrypted()
                .note()
                .value(),
            123_456
        );
    }

    #[test]
    #[ignore = "opt-in external H1-A2 migration acceptance campaign"]
    fn h1_a2_external_legacy_migration_campaign() {
        let directory = std::env::var_os("VAULT_H1_A2_MIGRATION_DIR")
            .map(PathBuf::from)
            .and_then(|path| fs::canonicalize(path).ok())
            .expect("VAULT_H1_A2_MIGRATION_DIR must be an existing canonical directory");
        let blocks = std::env::var("VAULT_H1_A2_MIGRATION_BLOCKS")
            .unwrap_or_else(|_| "10000".to_owned())
            .parse::<u64>()
            .expect("migration block count is an integer");
        let actions_per_block = std::env::var("VAULT_H1_A2_MIGRATION_ACTIONS")
            .unwrap_or_else(|_| "2".to_owned())
            .parse::<usize>()
            .expect("migration action count is an integer");
        let max_checkpoints = std::env::var("VAULT_H1_A2_MIGRATION_CHECKPOINTS")
            .unwrap_or_else(|_| "100".to_owned())
            .parse::<usize>()
            .expect("migration checkpoint count is an integer");
        assert!((1..=1_000_000).contains(&blocks));
        assert!([2, 4, 8, 16].contains(&actions_per_block));
        assert!((1..=MAX_CHECKPOINTS_LIMIT).contains(&max_checkpoints));

        let path = directory.join("wallet-migration.sqlite3");
        let backup_path = directory.join("wallet-migration-v1.vwb");
        let restored_path = directory.join("wallet-migration-restored.sqlite3");
        assert!(!path.exists() && !backup_path.exists() && !restored_path.exists());
        let config = WalletDatabaseConfig::new(
            TEST_WALLET,
            test_config().maximum_note_value(),
            max_checkpoints,
        )
        .unwrap();
        let mut database =
            EncryptedWalletDb::create(&path, &TEST_ROOT_KEY, config, test_tip()).unwrap();
        let owner = VaultSpendingKey::derive(&[0x44; 32], TEST_CHAIN, 0)
            .unwrap()
            .full_viewing_key();
        let history_started = std::time::Instant::now();
        let progress_interval = (blocks / 100).max(1);
        for height in 1..=blocks {
            commit_acceptance_history_block(&mut database, &owner, height, actions_per_block);
            if height % progress_interval == 0 || height == blocks {
                println!(
                    "migration_fixture_progress height={height} elapsed_seconds={:.3} database_bytes={}",
                    history_started.elapsed().as_secs_f64(),
                    fs::metadata(&path).unwrap().len()
                );
            }
        }
        let expected_tip = database.load_tip().unwrap();
        drop(database);
        convert_current_fixture_to_legacy(&path);
        let legacy_bytes = fs::metadata(&path).unwrap().len();

        let migration_started = std::time::Instant::now();
        let migrated = EncryptedWalletDb::migrate_legacy_v1(
            &path,
            &backup_path,
            &TEST_ROOT_KEY,
            ChainId::new(TEST_CHAIN),
            TEST_WALLET,
            blocks,
        )
        .unwrap();
        assert_eq!(migrated.load_tip().unwrap(), expected_tip);
        let migration_seconds = migration_started.elapsed().as_secs_f64();
        drop(migrated);

        let restore_started = std::time::Instant::now();
        let restored = EncryptedWalletDb::restore_backup(
            &backup_path,
            &restored_path,
            &TEST_ROOT_KEY,
            ChainId::new(TEST_CHAIN),
            TEST_WALLET,
            blocks,
        )
        .unwrap();
        assert_eq!(restored.load_tip().unwrap(), expected_tip);
        drop(restored);
        let note_rows = Connection::open(&path)
            .unwrap()
            .query_row("SELECT count(*) FROM wallet_notes", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(
            note_rows,
            i64::try_from(blocks).unwrap() * i64::try_from(actions_per_block).unwrap()
        );
        println!(
            "migration_complete blocks={blocks} actions_per_block={actions_per_block} note_rows={note_rows} legacy_bytes={legacy_bytes} migrated_bytes={} backup_bytes={} restored_bytes={} migration_seconds={migration_seconds:.3} restore_seconds={:.3}",
            fs::metadata(&path).unwrap().len(),
            fs::metadata(&backup_path).unwrap().len(),
            fs::metadata(&restored_path).unwrap().len(),
            restore_started.elapsed().as_secs_f64()
        );
    }
}
