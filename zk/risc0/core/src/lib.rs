//! Shared transfer-v2 statement for Vault's isolated RISC Zero oracle.
//!
//! This crate validates the production-intent transfer invariants but exposes
//! no consensus verifier or state-transition adapter.

use serde::{Deserialize, Serialize};
use vault_burn::{
    BURN_ENCRYPTION_SCHEME_ID, BurnCiphertext, EpochBurnPublicKey, MAX_BURN_PARTICIPANTS,
};
use vault_privacy::{
    NOTE_TREE_DEPTH, OUTPUT_AUTHORIZATION_PACKET_BYTES, PRIVATE_NOTE_BYTES,
    reference::{verifies_reference_burn_commitment, verify_reference_action},
};
use vault_protocol::{TRANSFER_V2_MAX_EFFECT_BYTES, TransferV2Effects};
use zeroize::Zeroize;

/// Exact reference statement schema accepted by the guest.
pub const REFERENCE_STATEMENT_VERSION: u16 = 1;
/// Native-VLT monetary-policy maximum used by every private note witness.
pub const MAXIMUM_NATIVE_VALUE: u64 = 21_000_000 * 1_000_000_000;

/// One private action witness paired with the action at the same public index.
#[derive(Serialize, Deserialize)]
pub struct ReferenceActionWitness {
    /// Canonical 96-byte full viewing capability controlling the input note.
    pub full_viewing_key: Vec<u8>,
    /// Canonical fixed private Ironwood V3 input note.
    pub input_note: Vec<u8>,
    /// Zero-based input position in the note tree.
    pub membership_position: u32,
    /// Exactly 32 canonical sibling nodes, from leaf to root.
    pub membership_auth_path: Vec<[u8; 32]>,
    /// Non-zero Pallas scalar `alpha` randomizing the public spend key.
    pub authorization_randomizer: [u8; 32],
    /// Non-zero Orchard net-value commitment trapdoor.
    pub net_value_trapdoor: [u8; 32],
    /// Exact fixed output-authorization packet reconstructed in the guest.
    pub output_authorization_packet: Vec<u8>,
}

impl Drop for ReferenceActionWitness {
    fn drop(&mut self) {
        self.full_viewing_key.zeroize();
        self.input_note.zeroize();
        self.membership_position.zeroize();
        self.membership_auth_path.zeroize();
        self.authorization_randomizer.zeroize();
        self.net_value_trapdoor.zeroize();
        self.output_authorization_packet.zeroize();
    }
}

/// Complete public DKG-result descriptor selected by the transfer effects.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochKeyClaim {
    /// Burn-key epoch.
    pub epoch: u64,
    /// Shamir threshold.
    pub threshold: u16,
    /// Strictly sorted non-zero participant evaluation points.
    pub participants: Vec<u16>,
    /// Feldman coefficient commitments in polynomial-degree order.
    pub coefficient_commitments: Vec<[u8; 32]>,
}

/// Private openings shared by conservation, the burn commitment, and ElGamal.
#[derive(Serialize, Deserialize)]
pub struct BurnOpeningWitness {
    /// Circuit-compatible non-zero burn value-commitment trapdoor.
    pub commitment_trapdoor: [u8; 32],
    /// Circuit-compatible non-zero threshold-ElGamal randomness.
    pub encryption_randomness: [u8; 32],
}

impl Drop for BurnOpeningWitness {
    fn drop(&mut self) {
        self.commitment_trapdoor.zeroize();
        self.encryption_randomness.zeroize();
    }
}

/// Exact public effects and private witnesses consumed by the zkVM guest.
#[derive(Serialize, Deserialize)]
pub struct TransferV2ReferenceClaim {
    /// Must equal [`REFERENCE_STATEMENT_VERSION`].
    pub statement_version: u16,
    /// Canonical `TransferV2Effects` bytes.
    pub effects: Vec<u8>,
    /// Private action witnesses in exact canonical public action order.
    pub actions: Vec<ReferenceActionWitness>,
    /// Complete epoch DKG-result descriptor.
    pub epoch_key: EpochKeyClaim,
    /// Exact hidden-burn openings.
    pub burn: BurnOpeningWitness,
}

/// Minimal public result authenticated by the RISC Zero receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferV2ReferenceJournal {
    /// Digest recomputed from canonical effects inside the guest.
    pub public_inputs_digest: [u8; 32],
    /// Public padded action count.
    pub action_count: u16,
    /// Public gas debit proven funded by the private inputs.
    pub gas_fee: u128,
}

/// Deterministic native and guest rejection classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceError {
    /// Claim schema version is unknown.
    UnsupportedStatementVersion,
    /// Public effects exceed the protocol bound or are not canonical v2 bytes.
    InvalidEffects,
    /// Private action witness count or a fixed witness field has another size.
    InvalidWitnessShape,
    /// A per-action private relation failed.
    InvalidAction,
    /// Checked `u128` accounting overflowed.
    ArithmeticOverflow,
    /// Private inputs do not exactly fund outputs, burn, and gas.
    ConservationFailure,
    /// The supplied DKG result does not match the public scheme/key/epoch.
    EpochKeyMismatch,
    /// The public burn commitment does not open to the mandatory burn.
    BurnCommitmentMismatch,
    /// The public burn ciphertext does not encrypt that burn under the epoch key.
    BurnCiphertextMismatch,
}

impl TransferV2ReferenceClaim {
    /// Validates the complete transfer-v2 reference statement.
    pub fn validate(&self) -> Result<TransferV2ReferenceJournal, ReferenceError> {
        if self.statement_version != REFERENCE_STATEMENT_VERSION {
            return Err(ReferenceError::UnsupportedStatementVersion);
        }
        if self.effects.len() > TRANSFER_V2_MAX_EFFECT_BYTES {
            return Err(ReferenceError::InvalidEffects);
        }
        let effects = TransferV2Effects::decode_canonical(&self.effects)
            .map_err(|_| ReferenceError::InvalidEffects)?;
        if self.actions.len() != effects.actions().len() {
            return Err(ReferenceError::InvalidWitnessShape);
        }

        let mut input_sum = 0_u128;
        let mut output_sum = 0_u128;
        let mut taxable_sum = 0_u128;
        for (public_action, witness) in effects.actions().iter().zip(&self.actions) {
            let full_viewing_key: [u8; 96] = witness
                .full_viewing_key
                .as_slice()
                .try_into()
                .map_err(|_| ReferenceError::InvalidWitnessShape)?;
            let input_note: [u8; PRIVATE_NOTE_BYTES] = witness
                .input_note
                .as_slice()
                .try_into()
                .map_err(|_| ReferenceError::InvalidWitnessShape)?;
            let membership_auth_path: [[u8; 32]; NOTE_TREE_DEPTH as usize] = witness
                .membership_auth_path
                .as_slice()
                .try_into()
                .map_err(|_| ReferenceError::InvalidWitnessShape)?;
            if witness.output_authorization_packet.len() != OUTPUT_AUTHORIZATION_PACKET_BYTES {
                return Err(ReferenceError::InvalidWitnessShape);
            }
            let values = verify_reference_action(
                *effects.chain_id().as_bytes(),
                effects.anchor().to_bytes(),
                public_action.nullifier(),
                public_action.randomized_verification_key(),
                public_action.net_value_commitment(),
                public_action.output(),
                full_viewing_key,
                input_note,
                witness.membership_position,
                membership_auth_path,
                witness.authorization_randomizer,
                witness.net_value_trapdoor,
                &witness.output_authorization_packet,
                MAXIMUM_NATIVE_VALUE,
            )
            .map_err(|_| ReferenceError::InvalidAction)?;
            input_sum = input_sum
                .checked_add(u128::from(values.input_value()))
                .ok_or(ReferenceError::ArithmeticOverflow)?;
            output_sum = output_sum
                .checked_add(u128::from(values.output_value()))
                .ok_or(ReferenceError::ArithmeticOverflow)?;
            taxable_sum = taxable_sum
                .checked_add(u128::from(values.taxable_output()))
                .ok_or(ReferenceError::ArithmeticOverflow)?;
        }

        let burn = burn_for(taxable_sum);
        let gas_fee = effects
            .gas()
            .total_fee()
            .map_err(|_| ReferenceError::ArithmeticOverflow)?;
        let required = output_sum
            .checked_add(burn)
            .and_then(|value| value.checked_add(gas_fee))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        if input_sum != required {
            return Err(ReferenceError::ConservationFailure);
        }
        let burn = u64::try_from(burn).map_err(|_| ReferenceError::ArithmeticOverflow)?;
        if burn > MAXIMUM_NATIVE_VALUE {
            return Err(ReferenceError::ArithmeticOverflow);
        }

        if self.epoch_key.participants.len() > MAX_BURN_PARTICIPANTS {
            return Err(ReferenceError::InvalidWitnessShape);
        }
        let epoch_key = EpochBurnPublicKey::from_parts(
            self.epoch_key.epoch,
            self.epoch_key.threshold,
            self.epoch_key.participants.clone(),
            self.epoch_key.coefficient_commitments.clone(),
        )
        .map_err(|_| ReferenceError::EpochKeyMismatch)?;
        let public_burn = effects.burn();
        if public_burn.scheme_id() != BURN_ENCRYPTION_SCHEME_ID
            || public_burn.key_id() != epoch_key.key_id()
            || public_burn.epoch() != epoch_key.epoch()
        {
            return Err(ReferenceError::EpochKeyMismatch);
        }
        if !verifies_reference_burn_commitment(
            burn,
            self.burn.commitment_trapdoor,
            public_burn.commitment(),
        ) {
            return Err(ReferenceError::BurnCommitmentMismatch);
        }
        let ciphertext = BurnCiphertext::from_bytes(*public_burn.ciphertext())
            .map_err(|_| ReferenceError::BurnCiphertextMismatch)?;
        if !ciphertext.verifies_reference_opening(
            burn,
            MAXIMUM_NATIVE_VALUE,
            self.burn.encryption_randomness,
            &epoch_key,
        ) {
            return Err(ReferenceError::BurnCiphertextMismatch);
        }

        Ok(TransferV2ReferenceJournal {
            public_inputs_digest: *effects.public_inputs_digest().as_bytes(),
            action_count: u16::try_from(effects.actions().len())
                .map_err(|_| ReferenceError::InvalidWitnessShape)?,
            gas_fee,
        })
    }
}

/// Exact ceiling 0.5% burn over the external transfer value.
#[must_use]
pub const fn burn_for(taxable_amount: u128) -> u128 {
    let quotient = taxable_amount / 200;
    let remainder = taxable_amount % 200;
    quotient + if remainder == 0 { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burn_rounds_at_every_boundary_class() {
        assert_eq!(burn_for(0), 0);
        assert_eq!(burn_for(1), 1);
        assert_eq!(burn_for(199), 1);
        assert_eq!(burn_for(200), 1);
        assert_eq!(burn_for(201), 2);
        assert_eq!(burn_for(399), 2);
        assert_eq!(burn_for(400), 2);
    }
}
