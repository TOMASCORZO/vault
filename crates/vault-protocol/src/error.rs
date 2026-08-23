use std::fmt;

use vault_privacy::{ActionNullifier, NoteTreeRoot};

use crate::{ChainId, CircuitId, NoteCommitment, Nullifier, StateRoot};

/// Deliberately opaque proof failure returned by a cryptographic backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofVerificationError;

impl fmt::Display for ProofVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "proof verification failed")
    }
}

impl std::error::Error for ProofVerificationError {}

/// Consensus validation errors for transfer-v1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// State configuration contains a reserved or impossible value.
    InvalidConfiguration(&'static str),
    /// Transaction version is not accepted by this state machine.
    UnsupportedVersion { expected: u16, actual: u16 },
    /// Transaction belongs to a different network.
    WrongChainId { expected: ChainId, actual: ChainId },
    /// Transaction targets a proof program that is not activated.
    WrongCircuitId {
        expected: CircuitId,
        actual: CircuitId,
    },
    /// State anchor is outside the accepted recent-root window.
    UnknownAnchor(StateRoot),
    /// At least one input note is required.
    MissingNullifiers,
    /// Input count exceeds the consensus limit.
    TooManyNullifiers { count: usize, maximum: usize },
    /// The all-zero nullifier encoding is reserved.
    ZeroNullifier,
    /// A nullifier appears more than once in the transaction.
    DuplicateNullifier(Nullifier),
    /// A note has already been consumed by an earlier transaction.
    NullifierAlreadySpent(Nullifier),
    /// At least one output note is required.
    MissingOutputs,
    /// Output count exceeds the consensus limit.
    TooManyOutputs { count: usize, maximum: usize },
    /// The all-zero note commitment encoding is reserved.
    ZeroNoteCommitment,
    /// Two outputs in one transaction use the same commitment.
    DuplicateNoteCommitment(NoteCommitment),
    /// A commitment already exists in shielded state.
    NoteCommitmentAlreadyExists(NoteCommitment),
    /// The all-zero ephemeral-key encoding is reserved.
    ZeroEphemeralKey,
    /// An output omitted its encrypted note payload.
    EmptyNoteCiphertext,
    /// An encrypted note exceeds the pre-verification limit.
    NoteCiphertextTooLarge { size: usize, maximum: usize },
    /// The all-zero balance commitment encoding is reserved.
    ZeroBalanceCommitment,
    /// The all-zero burn commitment encoding is reserved.
    ZeroBurnCommitment,
    /// The burn aggregate payload is missing.
    EmptyBurnCiphertext,
    /// The encrypted burn exceeds the consensus limit.
    BurnCiphertextTooLarge { size: usize, maximum: usize },
    /// Transfer proof is missing.
    EmptyProof,
    /// Transfer proof exceeds the denial-of-service limit.
    ProofTooLarge { size: usize, maximum: usize },
    /// Transfer-v1 has a fixed gas schedule.
    IncorrectGasUnits { expected: u64, actual: u64 },
    /// Offered fee per gas is below the current consensus minimum.
    FeePerGasTooLow { minimum: u64, actual: u64 },
    /// Gas multiplication exceeded the amount representation.
    FeeOverflow,
    /// The activated cryptographic verifier rejected the proof.
    InvalidProof,
    /// A new state root used the reserved all-zero encoding.
    ZeroStateRoot,
    /// Transfer-v2 network-codec discriminator is not exact.
    InvalidTransferV2Magic,
    /// A transfer-v2 byte string is truncated, oversized, or non-canonical.
    InvalidTransferV2Encoding(&'static str),
    /// Transaction bytes exceed the allocation-independent decoder bound.
    TransactionTooLarge { size: usize, maximum: usize },
    /// The action count is not one of the activated padding buckets.
    InvalidActionCount { count: usize },
    /// Actions are not strictly sorted by their canonical nullifier bytes.
    NonCanonicalActionOrder,
    /// Two paired actions expose the same nullifier.
    DuplicateActionNullifier,
    /// The note-tree anchor is not a canonical Pallas field element.
    InvalidNoteTreeRoot,
    /// A canonical note-tree anchor is outside the accepted recent-root window.
    UnknownNoteTreeRoot(NoteTreeRoot),
    /// An action nullifier is zero or non-canonical.
    InvalidActionNullifier,
    /// A RedPallas randomized spend key is malformed or the identity.
    InvalidRandomizedSpendKey,
    /// Two actions reuse the same randomized spend-validating key.
    DuplicateRandomizedSpendKey,
    /// A Pallas value commitment is not canonically encoded.
    InvalidValueCommitment,
    /// An encrypted note contains a malformed commitment or ephemeral key.
    InvalidEncryptedNote,
    /// Two outputs reuse the same ephemeral note-encryption key.
    DuplicateOutputEphemeralKey,
    /// Two outputs contain the same value commitment.
    DuplicateOutputValueCommitment,
    /// Spend signature is malformed, mismatched, or invalid for the effects.
    InvalidSpendAuthorization,
    /// Number of spend signatures differs from the padded action count.
    AuthorizationCountMismatch { expected: usize, actual: usize },
    /// Number of independently verified output packets differs from the
    /// padded action count.
    OutputAuthorizationCountMismatch { expected: usize, actual: usize },
    /// At least one verified output token belongs to another network, action,
    /// ciphertext, or signer.
    InvalidOutputAuthorization,
    /// Requested action index does not exist in the fixed signing session.
    InvalidAuthorizationIndex { index: usize, action_count: usize },
    /// Burn-encryption construction identifier is reserved zero.
    ZeroBurnSchemeId,
    /// Burn threshold public-key identifier is reserved zero.
    ZeroBurnKeyId,
    /// Burn commitment is the identity or ciphertext is the reserved zero value.
    InvalidBurnCiphertext,
    /// Transaction targets a burn-encryption construction not activated here.
    WrongBurnSchemeId,
    /// Transaction targets a threshold burn key not activated for its epoch.
    WrongBurnKeyId,
    /// Transaction targets a burn-key epoch not accepted at the current height.
    WrongBurnEpoch { expected: u64, actual: u64 },
    /// Gas fields contain zero or another structurally impossible value.
    InvalidGasParameters,
    /// A signer policy refuses a fee bid above its approved ceiling.
    FeePerGasTooHigh { maximum: u64, actual: u64 },
    /// A signer policy refuses the resulting total gas debit.
    GasFeeTooHigh { maximum: u128, actual: u128 },
    /// Transfer-v2 deterministic gas arithmetic overflowed.
    GasScheduleOverflow,
    /// The note commitment tree cannot append the complete action bundle.
    NoteTreeCapacityExceeded,
    /// A transfer-v2 action nullifier was already accepted globally.
    ActionNullifierAlreadySpent(ActionNullifier),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(reason) => {
                write!(formatter, "invalid configuration: {reason}")
            }
            Self::UnsupportedVersion { expected, actual } => {
                write!(
                    formatter,
                    "unsupported version {actual}; expected {expected}"
                )
            }
            Self::WrongChainId { .. } => write!(formatter, "transaction belongs to another chain"),
            Self::WrongCircuitId { .. } => write!(formatter, "proof circuit is not activated"),
            Self::UnknownAnchor(_) => write!(formatter, "state anchor is not recent"),
            Self::MissingNullifiers => write!(formatter, "transaction has no nullifiers"),
            Self::TooManyNullifiers { count, maximum } => {
                write!(formatter, "{count} nullifiers exceed limit {maximum}")
            }
            Self::ZeroNullifier => write!(formatter, "zero nullifier is reserved"),
            Self::DuplicateNullifier(_) => write!(formatter, "transaction repeats a nullifier"),
            Self::NullifierAlreadySpent(_) => write!(formatter, "nullifier is already spent"),
            Self::MissingOutputs => write!(formatter, "transaction has no outputs"),
            Self::TooManyOutputs { count, maximum } => {
                write!(formatter, "{count} outputs exceed limit {maximum}")
            }
            Self::ZeroNoteCommitment => write!(formatter, "zero note commitment is reserved"),
            Self::DuplicateNoteCommitment(_) => {
                write!(formatter, "transaction repeats an output commitment")
            }
            Self::NoteCommitmentAlreadyExists(_) => {
                write!(formatter, "output commitment already exists")
            }
            Self::ZeroEphemeralKey => write!(formatter, "zero ephemeral key is reserved"),
            Self::EmptyNoteCiphertext => write!(formatter, "encrypted note is empty"),
            Self::NoteCiphertextTooLarge { size, maximum } => {
                write!(formatter, "encrypted note size {size} exceeds {maximum}")
            }
            Self::ZeroBalanceCommitment => write!(formatter, "zero balance commitment is reserved"),
            Self::ZeroBurnCommitment => write!(formatter, "zero burn commitment is reserved"),
            Self::EmptyBurnCiphertext => write!(formatter, "encrypted burn is empty"),
            Self::BurnCiphertextTooLarge { size, maximum } => {
                write!(formatter, "encrypted burn size {size} exceeds {maximum}")
            }
            Self::EmptyProof => write!(formatter, "proof is empty"),
            Self::ProofTooLarge { size, maximum } => {
                write!(formatter, "proof size {size} exceeds {maximum}")
            }
            Self::IncorrectGasUnits { expected, actual } => {
                write!(
                    formatter,
                    "gas units {actual} do not equal required {expected}"
                )
            }
            Self::FeePerGasTooLow { minimum, actual } => {
                write!(formatter, "fee per gas {actual} is below minimum {minimum}")
            }
            Self::FeeOverflow => write!(formatter, "gas fee overflow"),
            Self::InvalidProof => write!(formatter, "invalid transfer proof"),
            Self::ZeroStateRoot => write!(formatter, "zero state root is reserved"),
            Self::InvalidTransferV2Magic => write!(formatter, "invalid transfer-v2 magic"),
            Self::InvalidTransferV2Encoding(reason) => {
                write!(formatter, "invalid transfer-v2 encoding: {reason}")
            }
            Self::TransactionTooLarge { size, maximum } => {
                write!(formatter, "transaction size {size} exceeds {maximum}")
            }
            Self::InvalidActionCount { count } => {
                write!(
                    formatter,
                    "action count {count} is not an allowed padding bucket"
                )
            }
            Self::NonCanonicalActionOrder => {
                write!(formatter, "actions are not canonically ordered")
            }
            Self::DuplicateActionNullifier => {
                write!(formatter, "two actions expose the same nullifier")
            }
            Self::InvalidNoteTreeRoot => write!(formatter, "invalid note-tree root"),
            Self::UnknownNoteTreeRoot(_) => write!(formatter, "note-tree root is not recent"),
            Self::InvalidActionNullifier => write!(formatter, "invalid action nullifier"),
            Self::InvalidRandomizedSpendKey => {
                write!(formatter, "invalid randomized spend key")
            }
            Self::DuplicateRandomizedSpendKey => {
                write!(formatter, "two actions reuse a randomized spend key")
            }
            Self::InvalidValueCommitment => write!(formatter, "invalid value commitment"),
            Self::InvalidEncryptedNote => write!(formatter, "invalid encrypted note"),
            Self::DuplicateOutputEphemeralKey => {
                write!(formatter, "two outputs reuse an ephemeral key")
            }
            Self::DuplicateOutputValueCommitment => {
                write!(formatter, "two outputs repeat a value commitment")
            }
            Self::InvalidSpendAuthorization => write!(formatter, "invalid spend authorization"),
            Self::AuthorizationCountMismatch { expected, actual } => write!(
                formatter,
                "authorization count {actual} does not equal action count {expected}"
            ),
            Self::OutputAuthorizationCountMismatch { expected, actual } => write!(
                formatter,
                "verified output count {actual} does not equal action count {expected}"
            ),
            Self::InvalidOutputAuthorization => {
                write!(
                    formatter,
                    "invalid independently verified output authorization"
                )
            }
            Self::InvalidAuthorizationIndex {
                index,
                action_count,
            } => write!(
                formatter,
                "authorization index {index} is outside action count {action_count}"
            ),
            Self::ZeroBurnSchemeId => write!(formatter, "zero burn scheme id is reserved"),
            Self::ZeroBurnKeyId => write!(formatter, "zero burn key id is reserved"),
            Self::InvalidBurnCiphertext => write!(formatter, "invalid encrypted burn payload"),
            Self::WrongBurnSchemeId => write!(formatter, "burn scheme is not activated"),
            Self::WrongBurnKeyId => write!(formatter, "burn key is not activated"),
            Self::WrongBurnEpoch { expected, actual } => {
                write!(
                    formatter,
                    "burn epoch {actual} does not equal active epoch {expected}"
                )
            }
            Self::InvalidGasParameters => write!(formatter, "invalid gas parameters"),
            Self::FeePerGasTooHigh { maximum, actual } => {
                write!(
                    formatter,
                    "fee per gas {actual} exceeds signer limit {maximum}"
                )
            }
            Self::GasFeeTooHigh { maximum, actual } => {
                write!(formatter, "gas fee {actual} exceeds signer limit {maximum}")
            }
            Self::GasScheduleOverflow => write!(formatter, "gas schedule overflow"),
            Self::NoteTreeCapacityExceeded => write!(formatter, "note tree capacity exceeded"),
            Self::ActionNullifierAlreadySpent(_) => {
                write!(formatter, "action nullifier is already spent")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}
