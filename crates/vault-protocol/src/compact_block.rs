//! Canonical compact-block boundary for private wallet scanning.
//!
//! Compact blocks contain every transfer-v2 nullifier and encrypted output in
//! finalized block order. They are not trusted merely because they decode: a
//! wallet must authenticate their non-circular commitment against a finalized
//! consensus header and independently replay the note-tree transition.

use core::fmt;
use std::collections::BTreeSet;

use blake3::Hasher;
use vault_privacy::{
    ActionNullifier, EncryptedNote, NOTE_CIPHERTEXT_BYTES, NOTE_TREE_DEPTH, NoteCommitmentTree,
    NoteTreeRoot, OUTGOING_CIPHERTEXT_BYTES,
};

use crate::{ALLOWED_TRANSFER_V2_ACTION_COUNTS, ChainId, TransactionId, TransferV2};

const COMPACT_BLOCK_COMMITMENT_DOMAIN: &str =
    "vault.protocol.compact-block-v1.commitment.2026-08-23";

/// Canonical compact-block discriminator.
pub const COMPACT_BLOCK_MAGIC: [u8; 4] = *b"VCB1";
/// Canonical compact-block codec version.
pub const COMPACT_BLOCK_VERSION: u16 = 1;
/// Absolute decoder bound on transactions in one compact block.
pub const MAX_COMPACT_BLOCK_TRANSACTIONS: usize = 8_192;
/// Absolute decoder bound on transfer-v2 actions in one compact block.
pub const MAX_COMPACT_BLOCK_ACTIONS: usize = 16_384;

const ENCRYPTED_NOTE_BYTES: usize = 3 * 32 + NOTE_CIPHERTEXT_BYTES + OUTGOING_CIPHERTEXT_BYTES;
/// Exact encoded bytes for one nullifier/output compact action.
pub const COMPACT_BLOCK_ACTION_BYTES: usize = 32 + ENCRYPTED_NOTE_BYTES;
const COMPACT_TRANSACTION_HEADER_BYTES: usize = 32 + 1;
/// Exact bytes preceding the first compact transaction.
pub const COMPACT_BLOCK_HEADER_BYTES: usize = 4 + 2 + 32 + 8 + 32 + 32 + 8 + 32 + 8 + 32 + 4 + 4;
/// Absolute pre-allocation bound for a canonical compact block.
pub const MAX_COMPACT_BLOCK_BYTES: usize = COMPACT_BLOCK_HEADER_BYTES
    + COMPACT_TRANSACTION_HEADER_BYTES * MAX_COMPACT_BLOCK_TRANSACTIONS
    + COMPACT_BLOCK_ACTION_BYTES * MAX_COMPACT_BLOCK_ACTIONS;

/// Fail-closed compact-block error. Detailed parser offsets are deliberately
/// excluded from wallet-facing diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactBlockError {
    /// Input exceeded an absolute transaction, action, or byte bound.
    ResourceLimitExceeded,
    /// Framing, lengths, reserved values, or canonical encodings were invalid.
    InvalidEncoding,
    /// The codec version is not supported.
    UnsupportedVersion,
    /// Chain, height, block hash, or parent hash used a reserved value.
    InvalidBlockIdentity,
    /// Transaction ordering/count or action ordering/count was invalid.
    InvalidTransaction,
    /// A transaction identifier appeared more than once in the block.
    DuplicateTransaction,
    /// A public nullifier appeared more than once in the block.
    DuplicateNullifier,
    /// An output note commitment appeared more than once in the block.
    DuplicateNoteCommitment,
    /// Declared pre/post tree sizes or roots are inconsistent.
    InvalidTreeTransition,
    /// The compact block did not match authenticated finalized-header data.
    HeaderMismatch,
}

impl fmt::Display for CompactBlockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ResourceLimitExceeded => "compact block exceeds resource limits",
            Self::InvalidEncoding => "compact block encoding is invalid",
            Self::UnsupportedVersion => "compact block version is unsupported",
            Self::InvalidBlockIdentity => "compact block identity is invalid",
            Self::InvalidTransaction => "compact block transaction is invalid",
            Self::DuplicateTransaction => "compact block repeats a transaction",
            Self::DuplicateNullifier => "compact block repeats a nullifier",
            Self::DuplicateNoteCommitment => "compact block repeats a note commitment",
            Self::InvalidTreeTransition => "compact block tree transition is invalid",
            Self::HeaderMismatch => "compact block does not match the finalized header",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CompactBlockError {}

/// One canonical nullifier/output pair retained for wallet scanning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlockAction {
    nullifier: ActionNullifier,
    output: EncryptedNote,
}

impl CompactBlockAction {
    /// Creates a compact action from already validated transfer-v2 fields.
    #[must_use]
    pub const fn new(nullifier: ActionNullifier, output: EncryptedNote) -> Self {
        Self { nullifier, output }
    }

    /// Public consumed-note marker and note-encryption domain input.
    #[must_use]
    pub const fn nullifier(&self) -> ActionNullifier {
        self.nullifier
    }

    /// Full fixed-size encrypted output; compact scanning never asks a server
    /// for wallet-specific ciphertext fragments.
    #[must_use]
    pub const fn output(&self) -> &EncryptedNote {
        &self.output
    }

    fn visit_canonical(&self, write: &mut impl FnMut(&[u8])) {
        write(&self.nullifier.to_bytes());
        write(&self.output.note_commitment());
        write(&self.output.value_commitment());
        write(&self.output.ephemeral_key());
        write(self.output.note_ciphertext());
        write(self.output.outgoing_ciphertext());
    }
}

/// One accepted transfer-v2 transaction stripped of proofs, signatures, gas,
/// and other fields unnecessary for note discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlockTransaction {
    transaction_id: TransactionId,
    actions: Vec<CompactBlockAction>,
}

impl CompactBlockTransaction {
    /// Constructs a canonical compact transaction. Actions retain the exact
    /// nullifier order of the accepted transfer-v2 effects.
    pub fn new(
        transaction_id: TransactionId,
        actions: Vec<CompactBlockAction>,
    ) -> Result<Self, CompactBlockError> {
        if transaction_id.is_zero() || !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&actions.len()) {
            return Err(CompactBlockError::InvalidTransaction);
        }
        for pair in actions.windows(2) {
            if pair[0].nullifier >= pair[1].nullifier {
                return Err(CompactBlockError::InvalidTransaction);
            }
        }
        let mut commitments = BTreeSet::new();
        for action in &actions {
            if !commitments.insert(action.output.note_commitment()) {
                return Err(CompactBlockError::DuplicateNoteCommitment);
            }
        }
        Ok(Self {
            transaction_id,
            actions,
        })
    }

    /// Content-derived identifier of the complete accepted transaction.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Canonically ordered actions, including padded dummy actions.
    #[must_use]
    pub fn actions(&self) -> &[CompactBlockAction] {
        &self.actions
    }

    fn visit_canonical(&self, write: &mut impl FnMut(&[u8])) {
        write(self.transaction_id.as_bytes());
        write(
            &[u8::try_from(self.actions.len()).expect("action count is bounded at construction")],
        );
        for action in &self.actions {
            action.visit_canonical(write);
        }
    }
}

/// Non-circular digest committed by the finalized consensus header.
///
/// The digest covers all compact-block fields except `block_hash`. The header
/// separately authenticates its own hash and this digest, avoiding a circular
/// definition in which the block hash would commit to a digest containing
/// itself.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompactBlockCommitment([u8; 32]);

impl fmt::Debug for CompactBlockCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CompactBlockCommitment")
            .field(&format_args!("{:02x?}…", &self.0[..4]))
            .finish()
    }
}

impl CompactBlockCommitment {
    /// Restores a non-zero commitment read from authenticated header state.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CompactBlockError> {
        if bytes == [0; 32] {
            return Err(CompactBlockError::InvalidBlockIdentity);
        }
        Ok(Self(bytes))
    }

    /// Canonical header bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Fields supplied by an independently authenticated finalized consensus
/// header. Constructing this value is an assertion by the future light-client
/// or full-node adapter; it is not proof of finality by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedCompactBlockHeader {
    chain_id: ChainId,
    height: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    pre_tree_size: u64,
    pre_tree_root: NoteTreeRoot,
    post_tree_size: u64,
    post_tree_root: NoteTreeRoot,
    compact_commitment: CompactBlockCommitment,
}

impl FinalizedCompactBlockHeader {
    /// Imports fields only after the caller has verified consensus finality and
    /// the activated header commitment rules.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_consensus(
        chain_id: ChainId,
        height: u64,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        pre_tree_size: u64,
        pre_tree_root: NoteTreeRoot,
        post_tree_size: u64,
        post_tree_root: NoteTreeRoot,
        compact_commitment: CompactBlockCommitment,
    ) -> Result<Self, CompactBlockError> {
        if chain_id.is_zero()
            || height == 0
            || block_hash == [0; 32]
            || parent_hash == [0; 32]
            || block_hash == parent_hash
            || pre_tree_size > post_tree_size
            || post_tree_size > (1u64 << NOTE_TREE_DEPTH)
        {
            return Err(CompactBlockError::InvalidBlockIdentity);
        }
        Ok(Self {
            chain_id,
            height,
            block_hash,
            parent_hash,
            pre_tree_size,
            pre_tree_root,
            post_tree_size,
            post_tree_root,
            compact_commitment,
        })
    }

    /// Finalized network domain.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Finalized consensus height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Finalized consensus block identifier.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    /// Note-tree size after the finalized block.
    #[must_use]
    pub const fn post_tree_size(&self) -> u64 {
        self.post_tree_size
    }

    /// Note-tree root after the finalized block.
    #[must_use]
    pub const fn post_tree_root(&self) -> NoteTreeRoot {
        self.post_tree_root
    }
}

/// Canonical full compact block. Decoding validates structure but does not
/// authenticate finality; call [`CompactBlock::authenticate`] before scanning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlock {
    chain_id: ChainId,
    height: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    pre_tree_size: u64,
    pre_tree_root: NoteTreeRoot,
    post_tree_size: u64,
    post_tree_root: NoteTreeRoot,
    transactions: Vec<CompactBlockTransaction>,
    action_count: usize,
}

impl CompactBlock {
    /// Constructs and fully validates one compact block.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        height: u64,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        pre_tree_size: u64,
        pre_tree_root: NoteTreeRoot,
        post_tree_size: u64,
        post_tree_root: NoteTreeRoot,
        transactions: Vec<CompactBlockTransaction>,
    ) -> Result<Self, CompactBlockError> {
        if chain_id.is_zero()
            || height == 0
            || block_hash == [0; 32]
            || parent_hash == [0; 32]
            || block_hash == parent_hash
        {
            return Err(CompactBlockError::InvalidBlockIdentity);
        }
        if transactions.len() > MAX_COMPACT_BLOCK_TRANSACTIONS {
            return Err(CompactBlockError::ResourceLimitExceeded);
        }
        let action_count = transactions.iter().try_fold(0usize, |total, transaction| {
            total
                .checked_add(transaction.actions.len())
                .ok_or(CompactBlockError::ResourceLimitExceeded)
        })?;
        if action_count > MAX_COMPACT_BLOCK_ACTIONS {
            return Err(CompactBlockError::ResourceLimitExceeded);
        }
        let expected_post_size = pre_tree_size
            .checked_add(
                u64::try_from(action_count)
                    .map_err(|_| CompactBlockError::ResourceLimitExceeded)?,
            )
            .ok_or(CompactBlockError::InvalidTreeTransition)?;
        if post_tree_size != expected_post_size || post_tree_size > (1u64 << NOTE_TREE_DEPTH) {
            return Err(CompactBlockError::InvalidTreeTransition);
        }

        let mut transaction_ids = BTreeSet::new();
        let mut nullifiers = BTreeSet::new();
        let mut commitments = BTreeSet::new();
        for transaction in &transactions {
            if !transaction_ids.insert(transaction.transaction_id) {
                return Err(CompactBlockError::DuplicateTransaction);
            }
            for action in &transaction.actions {
                if !nullifiers.insert(action.nullifier) {
                    return Err(CompactBlockError::DuplicateNullifier);
                }
                if !commitments.insert(action.output.note_commitment()) {
                    return Err(CompactBlockError::DuplicateNoteCommitment);
                }
            }
        }

        let encoded_length = COMPACT_BLOCK_HEADER_BYTES
            .checked_add(COMPACT_TRANSACTION_HEADER_BYTES * transactions.len())
            .and_then(|length| {
                length.checked_add(COMPACT_BLOCK_ACTION_BYTES.checked_mul(action_count)?)
            })
            .ok_or(CompactBlockError::ResourceLimitExceeded)?;
        if encoded_length > MAX_COMPACT_BLOCK_BYTES {
            return Err(CompactBlockError::ResourceLimitExceeded);
        }

        Ok(Self {
            chain_id,
            height,
            block_hash,
            parent_hash,
            pre_tree_size,
            pre_tree_root,
            post_tree_size,
            post_tree_root,
            transactions,
            action_count,
        })
    }

    /// Builds compact data only from transfers already accepted by consensus.
    /// This helper does not verify proofs or signatures itself.
    pub fn from_accepted_transfers(
        chain_id: ChainId,
        height: u64,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        pre_tree: &NoteCommitmentTree,
        transfers: &[TransferV2],
    ) -> Result<Self, CompactBlockError> {
        let mut post_tree = pre_tree.clone();
        let transactions = transfers
            .iter()
            .map(|transfer| {
                if transfer.effects().chain_id() != chain_id {
                    return Err(CompactBlockError::InvalidTransaction);
                }
                let actions = transfer
                    .effects()
                    .actions()
                    .iter()
                    .map(|action| {
                        post_tree
                            .append(action.output().note_commitment())
                            .map_err(|_| CompactBlockError::InvalidTreeTransition)?;
                        Ok(CompactBlockAction::new(
                            action.nullifier(),
                            action.output().clone(),
                        ))
                    })
                    .collect::<Result<Vec<_>, CompactBlockError>>()?;
                CompactBlockTransaction::new(transfer.transaction_id(), actions)
            })
            .collect::<Result<Vec<_>, CompactBlockError>>()?;
        Self::new(
            chain_id,
            height,
            block_hash,
            parent_hash,
            pre_tree.size(),
            pre_tree.typed_root(),
            post_tree.size(),
            post_tree.typed_root(),
            transactions,
        )
    }

    /// Exact canonical wire/storage encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.visit_canonical(true, &mut |part| bytes.extend_from_slice(part));
        debug_assert_eq!(bytes.len(), self.encoded_len());
        bytes
    }

    /// Parses exact canonical bytes with all bounds checked before allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, CompactBlockError> {
        if bytes.len() < COMPACT_BLOCK_HEADER_BYTES || bytes.len() > MAX_COMPACT_BLOCK_BYTES {
            return Err(CompactBlockError::ResourceLimitExceeded);
        }
        let mut reader = Reader::new(bytes);
        if reader.take_array::<4>()? != COMPACT_BLOCK_MAGIC {
            return Err(CompactBlockError::InvalidEncoding);
        }
        if u16::from_le_bytes(reader.take_array()?) != COMPACT_BLOCK_VERSION {
            return Err(CompactBlockError::UnsupportedVersion);
        }
        let chain_id = ChainId::new(reader.take_array()?);
        let height = u64::from_le_bytes(reader.take_array()?);
        let block_hash = reader.take_array()?;
        let parent_hash = reader.take_array()?;
        let pre_tree_size = u64::from_le_bytes(reader.take_array()?);
        let pre_tree_root = NoteTreeRoot::from_bytes(reader.take_array()?)
            .map_err(|_| CompactBlockError::InvalidEncoding)?;
        let post_tree_size = u64::from_le_bytes(reader.take_array()?);
        let post_tree_root = NoteTreeRoot::from_bytes(reader.take_array()?)
            .map_err(|_| CompactBlockError::InvalidEncoding)?;
        let transaction_count = usize::try_from(u32::from_le_bytes(reader.take_array()?))
            .map_err(|_| CompactBlockError::ResourceLimitExceeded)?;
        let declared_action_count = usize::try_from(u32::from_le_bytes(reader.take_array()?))
            .map_err(|_| CompactBlockError::ResourceLimitExceeded)?;
        if transaction_count > MAX_COMPACT_BLOCK_TRANSACTIONS
            || declared_action_count > MAX_COMPACT_BLOCK_ACTIONS
        {
            return Err(CompactBlockError::ResourceLimitExceeded);
        }
        let expected_length = COMPACT_BLOCK_HEADER_BYTES
            .checked_add(COMPACT_TRANSACTION_HEADER_BYTES * transaction_count)
            .and_then(|length| {
                length.checked_add(COMPACT_BLOCK_ACTION_BYTES.checked_mul(declared_action_count)?)
            })
            .ok_or(CompactBlockError::ResourceLimitExceeded)?;
        if bytes.len() != expected_length {
            return Err(CompactBlockError::InvalidEncoding);
        }

        let mut transactions = Vec::with_capacity(transaction_count);
        let mut decoded_action_count = 0usize;
        for _ in 0..transaction_count {
            let transaction_id = TransactionId::new(reader.take_array()?);
            let action_count = usize::from(reader.take_byte()?);
            if !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&action_count) {
                return Err(CompactBlockError::InvalidTransaction);
            }
            decoded_action_count = decoded_action_count
                .checked_add(action_count)
                .ok_or(CompactBlockError::ResourceLimitExceeded)?;
            if decoded_action_count > declared_action_count {
                return Err(CompactBlockError::InvalidEncoding);
            }
            let mut actions = Vec::with_capacity(action_count);
            for _ in 0..action_count {
                let nullifier = ActionNullifier::from_bytes(reader.take_array()?)
                    .map_err(|_| CompactBlockError::InvalidEncoding)?;
                let output = EncryptedNote::from_parts(
                    reader.take_array()?,
                    reader.take_array()?,
                    reader.take_array()?,
                    reader.take_array()?,
                    reader.take_array()?,
                )
                .map_err(|_| CompactBlockError::InvalidEncoding)?;
                actions.push(CompactBlockAction::new(nullifier, output));
            }
            transactions.push(CompactBlockTransaction::new(transaction_id, actions)?);
        }
        if decoded_action_count != declared_action_count || !reader.is_finished() {
            return Err(CompactBlockError::InvalidEncoding);
        }
        Self::new(
            chain_id,
            height,
            block_hash,
            parent_hash,
            pre_tree_size,
            pre_tree_root,
            post_tree_size,
            post_tree_root,
            transactions,
        )
    }

    /// Non-circular commitment that a finalized header must authenticate.
    #[must_use]
    pub fn commitment(&self) -> CompactBlockCommitment {
        let mut hasher = Hasher::new_derive_key(COMPACT_BLOCK_COMMITMENT_DOMAIN);
        self.visit_canonical(false, &mut |part| {
            hasher.update(part);
        });
        CompactBlockCommitment(*hasher.finalize().as_bytes())
    }

    /// Consumes this decoded block only after every finalized-header field and
    /// the non-circular compact commitment match.
    pub fn authenticate(
        self,
        header: FinalizedCompactBlockHeader,
    ) -> Result<AuthenticatedCompactBlock, CompactBlockError> {
        if self.chain_id != header.chain_id
            || self.height != header.height
            || self.block_hash != header.block_hash
            || self.parent_hash != header.parent_hash
            || self.pre_tree_size != header.pre_tree_size
            || self.pre_tree_root != header.pre_tree_root
            || self.post_tree_size != header.post_tree_size
            || self.post_tree_root != header.post_tree_root
            || self.commitment() != header.compact_commitment
        {
            return Err(CompactBlockError::HeaderMismatch);
        }
        Ok(AuthenticatedCompactBlock(self))
    }

    /// Independently replays every output commitment from the expected
    /// pre-state and returns the exact validated post-state.
    pub fn verify_tree_transition(
        &self,
        pre_tree: &NoteCommitmentTree,
    ) -> Result<NoteCommitmentTree, CompactBlockError> {
        if pre_tree.size() != self.pre_tree_size || pre_tree.typed_root() != self.pre_tree_root {
            return Err(CompactBlockError::InvalidTreeTransition);
        }
        let mut post_tree = pre_tree.clone();
        for transaction in &self.transactions {
            for action in &transaction.actions {
                post_tree
                    .append(action.output.note_commitment())
                    .map_err(|_| CompactBlockError::InvalidTreeTransition)?;
            }
        }
        if post_tree.size() != self.post_tree_size || post_tree.typed_root() != self.post_tree_root
        {
            return Err(CompactBlockError::InvalidTreeTransition);
        }
        Ok(post_tree)
    }

    /// Network domain.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Finalized block height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Finalized consensus block identifier.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    /// Exact finalized parent block identifier.
    #[must_use]
    pub const fn parent_hash(&self) -> [u8; 32] {
        self.parent_hash
    }

    /// Note-tree size immediately before this block.
    #[must_use]
    pub const fn pre_tree_size(&self) -> u64 {
        self.pre_tree_size
    }

    /// Note-tree root immediately before this block.
    #[must_use]
    pub const fn pre_tree_root(&self) -> NoteTreeRoot {
        self.pre_tree_root
    }

    /// Note-tree size after every action in block order.
    #[must_use]
    pub const fn post_tree_size(&self) -> u64 {
        self.post_tree_size
    }

    /// Note-tree root after every action in block order.
    #[must_use]
    pub const fn post_tree_root(&self) -> NoteTreeRoot {
        self.post_tree_root
    }

    /// Canonical block-order compact transactions.
    #[must_use]
    pub fn transactions(&self) -> &[CompactBlockTransaction] {
        &self.transactions
    }

    /// Total number of public actions scanned without wallet-specific queries.
    #[must_use]
    pub const fn action_count(&self) -> usize {
        self.action_count
    }

    /// Exact encoded length without allocating an encoded copy.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        COMPACT_BLOCK_HEADER_BYTES
            + COMPACT_TRANSACTION_HEADER_BYTES * self.transactions.len()
            + COMPACT_BLOCK_ACTION_BYTES * self.action_count
    }

    fn visit_canonical(&self, include_block_hash: bool, write: &mut impl FnMut(&[u8])) {
        write(&COMPACT_BLOCK_MAGIC);
        write(&COMPACT_BLOCK_VERSION.to_le_bytes());
        write(self.chain_id.as_bytes());
        write(&self.height.to_le_bytes());
        if include_block_hash {
            write(&self.block_hash);
        }
        write(&self.parent_hash);
        write(&self.pre_tree_size.to_le_bytes());
        write(&self.pre_tree_root.to_bytes());
        write(&self.post_tree_size.to_le_bytes());
        write(&self.post_tree_root.to_bytes());
        write(
            &u32::try_from(self.transactions.len())
                .expect("transaction count is bounded at construction")
                .to_le_bytes(),
        );
        write(
            &u32::try_from(self.action_count)
                .expect("action count is bounded at construction")
                .to_le_bytes(),
        );
        for transaction in &self.transactions {
            transaction.visit_canonical(write);
        }
    }
}

/// Compact block proven equal to caller-supplied finalized-header fields.
pub struct AuthenticatedCompactBlock(CompactBlock);

impl fmt::Debug for AuthenticatedCompactBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedCompactBlock")
            .field("height", &self.0.height)
            .field("action_count", &self.0.action_count)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedCompactBlock {
    /// Authenticated canonical compact block.
    #[must_use]
    pub const fn block(&self) -> &CompactBlock {
        &self.0
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CompactBlockError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(CompactBlockError::InvalidEncoding)?;
        let slice = self
            .bytes
            .get(self.cursor..end)
            .ok_or(CompactBlockError::InvalidEncoding)?;
        self.cursor = end;
        slice
            .try_into()
            .map_err(|_| CompactBlockError::InvalidEncoding)
    }

    fn take_byte(&mut self) -> Result<u8, CompactBlockError> {
        Ok(self.take_array::<1>()?[0])
    }

    const fn is_finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}
