//! Transparent economic reference model for Vault.
//!
//! This crate deliberately models amounts and owners in clear text. It exists
//! to validate accounting invariants before equivalent rules are encoded in a
//! zero-knowledge circuit. It is not a cryptographic or production ledger.

mod amount;
mod error;
mod ledger;

pub use amount::{ATOMIC_UNITS_PER_VLT, Amount, BURN_BASIS_POINTS, burn_for};
pub use error::LedgerError;
pub use ledger::{
    AccountId, GenesisConfig, Ledger, Note, NoteId, TransferReceipt, TransferRequest,
};
