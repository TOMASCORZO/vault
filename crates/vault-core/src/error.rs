use std::fmt;

use crate::{AccountId, Amount, NoteId};

/// Errors returned by the transparent reference ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerError {
    /// An amount exceeded the range supported by the model.
    ArithmeticOverflow,
    /// A subtraction would have produced a negative amount.
    ArithmeticUnderflow,
    /// Initial issuance exceeded the immutable supply cap.
    SupplyAboveCap {
        /// Requested initial issuance.
        initial_supply: Amount,
        /// Configured maximum supply.
        max_supply: Amount,
    },
    /// A zero-value transfer was requested.
    ZeroTransfer,
    /// A request contained no input notes.
    MissingInputs,
    /// The same note appeared more than once in one request.
    DuplicateInput(NoteId),
    /// The note identifier has never existed.
    UnknownNote(NoteId),
    /// The note has already been consumed.
    NoteAlreadySpent(NoteId),
    /// A sender attempted to consume another account's note.
    WrongOwner {
        /// Note being consumed.
        note: NoteId,
        /// Owner asserted by the request.
        expected: AccountId,
        /// Owner stored in the reference ledger.
        actual: AccountId,
    },
    /// Inputs did not cover the payment, burn, and gas.
    InsufficientFunds {
        /// Sum of input notes.
        available: Amount,
        /// Payment plus burn and gas.
        required: Amount,
    },
    /// Internal conservation-of-supply checks failed.
    InvariantViolation,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArithmeticOverflow => write!(formatter, "amount arithmetic overflow"),
            Self::ArithmeticUnderflow => write!(formatter, "amount arithmetic underflow"),
            Self::SupplyAboveCap {
                initial_supply,
                max_supply,
            } => write!(
                formatter,
                "initial supply {initial_supply} exceeds cap {max_supply}"
            ),
            Self::ZeroTransfer => write!(formatter, "transfer amount must be greater than zero"),
            Self::MissingInputs => write!(formatter, "transfer requires at least one input note"),
            Self::DuplicateInput(note) => write!(formatter, "duplicate input note {}", note.0),
            Self::UnknownNote(note) => write!(formatter, "unknown note {}", note.0),
            Self::NoteAlreadySpent(note) => write!(formatter, "note {} is already spent", note.0),
            Self::WrongOwner {
                note,
                expected,
                actual,
            } => write!(
                formatter,
                "note {} belongs to account {}, not account {}",
                note.0, actual.0, expected.0
            ),
            Self::InsufficientFunds {
                available,
                required,
            } => write!(
                formatter,
                "insufficient inputs: {available} available, {required} required"
            ),
            Self::InvariantViolation => write!(formatter, "supply invariant violated"),
        }
    }
}

impl std::error::Error for LedgerError {}
