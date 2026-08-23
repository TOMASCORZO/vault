//! Consensus-facing H1 protocol types for Vault.
//!
//! This crate validates transaction structure, domain separation, replay
//! protection, resource limits, canonical transfer-v2 privacy fields, and
//! proof-verifier integration. Cryptographic note construction is supplied by
//! `vault-privacy`; the complete transfer circuit remains a separate audited
//! component. No permissive or mock verifier is compiled into this crate.

mod compact_block;
mod error;
mod ids;
mod state;
mod state_v2;
mod transfer;
mod transfer_v2;

pub use compact_block::{
    AuthenticatedCompactBlock, COMPACT_BLOCK_ACTION_BYTES, COMPACT_BLOCK_HEADER_BYTES,
    COMPACT_BLOCK_MAGIC, COMPACT_BLOCK_VERSION, CompactBlock, CompactBlockAction,
    CompactBlockCommitment, CompactBlockError, CompactBlockTransaction,
    FinalizedCompactBlockHeader, MAX_COMPACT_BLOCK_ACTIONS, MAX_COMPACT_BLOCK_BYTES,
    MAX_COMPACT_BLOCK_TRANSACTIONS,
};
pub use error::{ProofVerificationError, ProtocolError};
pub use ids::{
    BalanceCommitment, BurnCommitment, ChainId, CircuitId, EphemeralKey, NoteCommitment, Nullifier,
    PublicInputDigest, StateRoot, TransactionId,
};
pub use state::{ApplyReceipt, ShieldedState, ShieldedStateConfig, TransferProofVerifier};
pub use state_v2::{
    ApplyReceiptV2, ShieldedStateV2, ShieldedStateV2Config, TransferV2ProofVerifier,
};
pub use transfer::{
    EncryptedBurn, GasParameters, ShieldedOutput, ShieldedTransfer, TRANSFER_V1_PROTOCOL_VERSION,
};
pub use transfer_v2::{
    ALLOWED_TRANSFER_V2_ACTION_COUNTS, EncryptedBurnV2, PreparedTransferV2Authorization,
    TRANSFER_V2_ACTION_BYTES, TRANSFER_V2_BURN_CIPHERTEXT_BYTES, TRANSFER_V2_EFFECT_HEADER_BYTES,
    TRANSFER_V2_MAGIC, TRANSFER_V2_MAX_EFFECT_BYTES, TRANSFER_V2_MAX_ENCODED_BYTES,
    TRANSFER_V2_PROTOCOL_VERSION, TransferV2, TransferV2Action, TransferV2Effects,
    TransferV2SignerPolicy,
};

/// Maximum number of consumed notes in a transfer-v1 transaction.
pub const MAX_NULLIFIERS: usize = 16;
/// Maximum number of created notes in a transfer-v1 transaction.
pub const MAX_OUTPUTS: usize = 16;
/// Maximum encrypted payload size for one output note.
pub const MAX_NOTE_CIPHERTEXT_BYTES: usize = 4 * 1024;
/// Maximum encrypted burn payload size.
pub const MAX_BURN_CIPHERTEXT_BYTES: usize = 256;
/// Hard pre-verification proof-size limit used for denial-of-service protection.
pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
