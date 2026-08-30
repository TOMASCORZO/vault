//! Shared, deterministic statement for Vault's experimental RISC Zero backend.
//!
//! The legacy `AccountingV1` statement proves private accounting only. The
//! versioned `TransferV2` statement additionally reconstructs the production
//! Ironwood/Orchard and burn-encryption relations required by C1. Neither
//! statement is activated for consensus by this crate.

use blake3::Hasher;
use serde::{Deserialize, Serialize};

pub mod transfer_v2;

use transfer_v2::{TransferV2ReferenceClaim, TransferV2ReferenceJournal};

const PUBLIC_INPUT_DOMAIN: &str = "vault.protocol.transfer-v1.public-inputs.2026-08-21";
const BALANCE_DOMAIN: &str = "vault.zk.risc0.accounting-v1.balance.2026-08-21";
const BURN_DOMAIN: &str = "vault.zk.risc0.accounting-v1.burn.2026-08-21";

/// Transfer-v1 protocol version accepted by the research guest.
pub const TRANSFER_V1_PROTOCOL_VERSION: u16 = 1;
/// Maximum private inputs mirrored from the consensus envelope.
pub const MAX_INPUTS: usize = 16;
/// Maximum private outputs mirrored from the consensus envelope.
pub const MAX_OUTPUTS: usize = 16;

/// One proof-bound public output envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicOutput {
    /// Public note commitment.
    pub note_commitment: [u8; 32],
    /// Ephemeral note-encryption key.
    pub ephemeral_key: [u8; 32],
    /// Authenticated encrypted note payload.
    pub ciphertext: Vec<u8>,
}

/// One proof-bound public burn envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicBurn {
    /// Hiding commitment constrained by the accounting guest.
    pub commitment: [u8; 32],
    /// Placeholder for the future threshold-encrypted burn amount.
    pub ciphertext: Vec<u8>,
}

/// Every public transfer field, in the exact transfer-v1 transcript order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferPublicFields {
    /// Protocol version.
    pub version: u16,
    /// Network domain.
    pub chain_id: [u8; 32],
    /// Activated circuit or guest image identifier.
    pub circuit_id: [u8; 32],
    /// Recent authenticated state root.
    pub anchor: [u8; 32],
    /// Consumed-note nullifiers.
    pub nullifiers: Vec<[u8; 32]>,
    /// Created encrypted notes.
    pub outputs: Vec<PublicOutput>,
    /// Research commitment to the complete private accounting witness.
    pub balance_commitment: [u8; 32],
    /// Hidden burn envelope.
    pub burn: PublicBurn,
    /// Deterministic gas units.
    pub gas_units: u64,
    /// Atomic VLT paid for each gas unit.
    pub fee_per_gas: u64,
}

impl TransferPublicFields {
    /// Recomputes the consensus public-input digest inside the proven program.
    #[must_use]
    pub fn public_inputs_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(PUBLIC_INPUT_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.chain_id);
        hasher.update(&self.circuit_id);
        hasher.update(&self.anchor);
        update_count(&mut hasher, self.nullifiers.len());
        for nullifier in &self.nullifiers {
            hasher.update(nullifier);
        }
        update_count(&mut hasher, self.outputs.len());
        for output in &self.outputs {
            hasher.update(&output.note_commitment);
            hasher.update(&output.ephemeral_key);
            update_bytes(&mut hasher, &output.ciphertext);
        }
        hasher.update(&self.balance_commitment);
        hasher.update(&self.burn.commitment);
        update_bytes(&mut hasher, &self.burn.ciphertext);
        hasher.update(&self.gas_units.to_le_bytes());
        hasher.update(&self.fee_per_gas.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Private accounting witness. Recipient/change classification is temporary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountingWitness {
    /// Private values of consumed VLT notes.
    pub input_values: Vec<u128>,
    /// Values sent to external recipients and therefore subject to burn.
    pub recipient_output_values: Vec<u128>,
    /// Values returned internally to the spender.
    pub change_output_values: Vec<u128>,
    /// Independent 256-bit hiding material for the accounting commitment.
    pub balance_blinding: [u8; 32],
    /// Independent 256-bit hiding material for the burn commitment.
    pub burn_blinding: [u8; 32],
}

/// Private and public data consumed by the zkVM guest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountingClaim {
    /// Full public transfer envelope.
    pub public: TransferPublicFields,
    /// Secret amounts and blindings.
    pub witness: AccountingWitness,
}

/// Minimal public result committed to the RISC Zero journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountingJournal {
    /// Digest recomputed from the full public envelope inside the guest.
    pub public_inputs_digest: [u8; 32],
    /// Number of consumed private notes.
    pub input_count: u16,
    /// Number of created private notes.
    pub output_count: u16,
    /// Public gas fee proven to be funded by the private inputs.
    pub gas_fee: u128,
}

/// Versioned guest input. New statements must be explicit variants so an old
/// host cannot be silently reinterpreted under a changed circuit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReferenceClaim {
    /// Legacy accounting-only transfer-v1 research statement.
    AccountingV1(Box<AccountingClaim>),
    /// First bounded transfer-v2 reference-statement increment.
    TransferV2(Box<TransferV2ReferenceClaim>),
}

/// Versioned authenticated guest journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReferenceJournal {
    /// Result of the legacy accounting-only transfer-v1 statement.
    AccountingV1(AccountingJournal),
    /// Result of the first transfer-v2 reference-statement increment.
    TransferV2(TransferV2ReferenceJournal),
}

impl ReferenceClaim {
    /// Validates exactly the selected statement and preserves its version in
    /// the authenticated journal.
    pub fn validate(&self) -> Result<ReferenceJournal, ReferenceError> {
        match self {
            Self::AccountingV1(claim) => claim
                .validate()
                .map(ReferenceJournal::AccountingV1)
                .map_err(ReferenceError::AccountingV1),
            Self::TransferV2(claim) => claim
                .validate()
                .map(ReferenceJournal::TransferV2)
                .map_err(ReferenceError::TransferV2),
        }
    }
}

/// Versioned guest rejection without erasing which statement failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceError {
    /// Legacy accounting-v1 validation failed.
    AccountingV1(AccountingError),
    /// Transfer-v2 reference validation failed.
    TransferV2(transfer_v2::TransferV2ReferenceError),
}

/// Deterministic rejection reasons shared by native tests and the zkVM guest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingError {
    /// The public protocol version is not transfer-v1.
    UnsupportedVersion,
    /// Input count is outside transfer-v1 limits.
    InvalidInputCount,
    /// Output count is outside transfer-v1 limits.
    InvalidOutputCount,
    /// Public and private note counts disagree.
    CountMismatch,
    /// A checked addition or multiplication overflowed `u128`.
    ArithmeticOverflow,
    /// Private inputs do not fund outputs, burn, and gas exactly.
    ConservationFailure,
    /// The public balance commitment does not open to this witness.
    BalanceCommitmentMismatch,
    /// The public burn commitment does not open to the exact mandatory burn.
    BurnCommitmentMismatch,
}

impl AccountingClaim {
    /// Executes all accounting constraints and returns the public journal.
    pub fn validate(&self) -> Result<AccountingJournal, AccountingError> {
        if self.public.version != TRANSFER_V1_PROTOCOL_VERSION {
            return Err(AccountingError::UnsupportedVersion);
        }

        let input_count = self.witness.input_values.len();
        if !(1..=MAX_INPUTS).contains(&input_count) {
            return Err(AccountingError::InvalidInputCount);
        }

        let output_count = self
            .witness
            .recipient_output_values
            .len()
            .checked_add(self.witness.change_output_values.len())
            .ok_or(AccountingError::ArithmeticOverflow)?;
        if !(1..=MAX_OUTPUTS).contains(&output_count) {
            return Err(AccountingError::InvalidOutputCount);
        }
        if input_count != self.public.nullifiers.len() || output_count != self.public.outputs.len()
        {
            return Err(AccountingError::CountMismatch);
        }

        let input_sum = checked_sum(&self.witness.input_values)?;
        let recipient_sum = checked_sum(&self.witness.recipient_output_values)?;
        let change_sum = checked_sum(&self.witness.change_output_values)?;
        let burn = burn_for(recipient_sum);
        let gas_fee = u128::from(self.public.gas_units)
            .checked_mul(u128::from(self.public.fee_per_gas))
            .ok_or(AccountingError::ArithmeticOverflow)?;

        let required = recipient_sum
            .checked_add(change_sum)
            .and_then(|value| value.checked_add(burn))
            .and_then(|value| value.checked_add(gas_fee))
            .ok_or(AccountingError::ArithmeticOverflow)?;
        if input_sum != required {
            return Err(AccountingError::ConservationFailure);
        }

        if balance_commitment(&self.public, &self.witness, burn, gas_fee)
            != self.public.balance_commitment
        {
            return Err(AccountingError::BalanceCommitmentMismatch);
        }
        if burn_commitment(burn, &self.witness.burn_blinding) != self.public.burn.commitment {
            return Err(AccountingError::BurnCommitmentMismatch);
        }

        Ok(AccountingJournal {
            public_inputs_digest: self.public.public_inputs_digest(),
            input_count: u16::try_from(input_count)
                .map_err(|_| AccountingError::InvalidInputCount)?,
            output_count: u16::try_from(output_count)
                .map_err(|_| AccountingError::InvalidOutputCount)?,
            gas_fee,
        })
    }
}

/// Exact 0.5% burn, rounded upward to the smallest atomic unit.
#[must_use]
pub const fn burn_for(taxable_amount: u128) -> u128 {
    let quotient = taxable_amount / 200;
    let remainder = taxable_amount % 200;
    quotient + if remainder == 0 { 0 } else { 1 }
}

/// Research-only BLAKE3 commitment to all accounting values and one blinding.
///
/// This is not the final algebraic value commitment and is not homomorphic.
#[must_use]
pub fn balance_commitment(
    public: &TransferPublicFields,
    witness: &AccountingWitness,
    burn: u128,
    gas_fee: u128,
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(BALANCE_DOMAIN);
    update_u128_values(&mut hasher, &witness.input_values);
    update_u128_values(&mut hasher, &witness.recipient_output_values);
    update_u128_values(&mut hasher, &witness.change_output_values);
    hasher.update(&burn.to_le_bytes());
    hasher.update(&gas_fee.to_le_bytes());
    hasher.update(&public.gas_units.to_le_bytes());
    hasher.update(&public.fee_per_gas.to_le_bytes());
    hasher.update(&witness.balance_blinding);
    *hasher.finalize().as_bytes()
}

/// Research-only hiding commitment to the exact mandatory burn.
#[must_use]
pub fn burn_commitment(burn: u128, blinding: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(BURN_DOMAIN);
    hasher.update(&burn.to_le_bytes());
    hasher.update(blinding);
    *hasher.finalize().as_bytes()
}

fn checked_sum(values: &[u128]) -> Result<u128, AccountingError> {
    values.iter().try_fold(0_u128, |sum, value| {
        sum.checked_add(*value)
            .ok_or(AccountingError::ArithmeticOverflow)
    })
}

fn update_count(hasher: &mut Hasher, count: usize) {
    hasher.update(&(count as u64).to_le_bytes());
}

fn update_bytes(hasher: &mut Hasher, bytes: &[u8]) {
    update_count(hasher, bytes.len());
    hasher.update(bytes);
}

fn update_u128_values(hasher: &mut Hasher, values: &[u128]) {
    update_count(hasher, values.len());
    for value in values {
        hasher.update(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_claim() -> AccountingClaim {
        let witness = AccountingWitness {
            input_values: vec![10_065],
            recipient_output_values: vec![10_000],
            change_output_values: vec![5],
            balance_blinding: [7; 32],
            burn_blinding: [9; 32],
        };
        let mut public = TransferPublicFields {
            version: TRANSFER_V1_PROTOCOL_VERSION,
            chain_id: [1; 32],
            circuit_id: [2; 32],
            anchor: [3; 32],
            nullifiers: vec![[4; 32]],
            outputs: vec![
                PublicOutput {
                    note_commitment: [5; 32],
                    ephemeral_key: [6; 32],
                    ciphertext: vec![7],
                },
                PublicOutput {
                    note_commitment: [8; 32],
                    ephemeral_key: [9; 32],
                    ciphertext: vec![10],
                },
            ],
            balance_commitment: [0; 32],
            burn: PublicBurn {
                commitment: [0; 32],
                ciphertext: vec![11],
            },
            gas_units: 10,
            fee_per_gas: 1,
        };
        let burn = burn_for(10_000);
        let gas_fee = 10;
        public.balance_commitment = balance_commitment(&public, &witness, burn, gas_fee);
        public.burn.commitment = burn_commitment(burn, &witness.burn_blinding);
        AccountingClaim { public, witness }
    }

    #[test]
    fn validates_exact_conservation_burn_and_gas() {
        let journal = valid_claim().validate().expect("valid accounting claim");
        assert_eq!(journal.input_count, 1);
        assert_eq!(journal.output_count, 2);
        assert_eq!(journal.gas_fee, 10);
    }

    #[test]
    fn burn_rounds_up_at_atomic_boundaries() {
        assert_eq!(burn_for(0), 0);
        assert_eq!(burn_for(1), 1);
        assert_eq!(burn_for(199), 1);
        assert_eq!(burn_for(200), 1);
        assert_eq!(burn_for(201), 2);
    }

    #[test]
    fn rejects_value_creation() {
        let mut claim = valid_claim();
        claim.witness.input_values[0] -= 1;
        assert_eq!(claim.validate(), Err(AccountingError::ConservationFailure));
    }

    #[test]
    fn rejects_wrong_burn_opening() {
        let mut claim = valid_claim();
        claim.public.burn.commitment[0] ^= 1;
        assert_eq!(
            claim.validate(),
            Err(AccountingError::BurnCommitmentMismatch)
        );
    }

    #[test]
    fn public_digest_binds_ciphertexts() {
        let mut claim = valid_claim();
        let digest = claim.public.public_inputs_digest();
        claim.public.outputs[0].ciphertext[0] ^= 1;
        assert_ne!(claim.public.public_inputs_digest(), digest);
    }
}
