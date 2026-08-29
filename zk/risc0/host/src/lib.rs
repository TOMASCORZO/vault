//! Fail-closed host for Vault's isolated transfer-v2 RISC Zero oracle.
//!
//! The receipt is real cryptographic evidence, but this crate intentionally
//! implements no consensus proof-verifier trait and cannot mutate Vault state.

mod fixture;

use std::time::Instant;

pub use fixture::{ReferenceFixture, reference_fixture};
use risc0_zkvm::{Digest, ExecutorEnv, Receipt, default_prover};
use thiserror::Error;
use vault_protocol::{MAX_PROOF_BYTES, TransferV2Effects};
use vault_zk_transfer_core::{
    ReferenceError, TransferV2ReferenceClaim, TransferV2ReferenceJournal,
};
use vault_zk_transfer_methods::{VAULT_ZK_TRANSFER_GUEST_ELF, VAULT_ZK_TRANSFER_GUEST_ID};

/// Reviewed guest image ID for the transfer-v2 reference statement.
///
/// CI fails if rebuilding the pinned guest produces another image.
pub const REVIEWED_REFERENCE_V2_IMAGE_ID: [u8; 32] = [
    0xbb, 0x59, 0x16, 0x20, 0xa5, 0x30, 0xed, 0x74, 0x6d, 0xf4, 0x2f, 0xa9, 0x54, 0x45, 0xf1, 0x88,
    0xc8, 0x06, 0xb6, 0x05, 0xdb, 0x8b, 0xf5, 0x05, 0x14, 0xd9, 0x1b, 0x33, 0xef, 0xab, 0x52, 0x56,
];

/// Proof-generation measurements captured by the local reference host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvingMetrics {
    /// Wall-clock proving time.
    pub elapsed_ms: u128,
    /// Canonical bincode receipt size.
    pub proof_bytes: usize,
    /// Number of zkVM proof segments.
    pub segments: usize,
    /// Total zkVM cycles, including paging and reserved cycles.
    pub total_cycles: u64,
    /// Cycles spent running guest code.
    pub user_cycles: u64,
}

/// A serialized proof plus its verified journal and measurements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofArtifact {
    /// Canonical bincode-encoded RISC Zero receipt.
    pub proof: Vec<u8>,
    /// Journal authenticated by the receipt.
    pub journal: TransferV2ReferenceJournal,
    /// Local proving measurements.
    pub metrics: ProvingMetrics,
}

/// Detailed local failures; no variant is a consensus error surface.
#[derive(Debug, Error)]
pub enum ZkBackendError {
    /// The native statement rejected before invoking the prover.
    #[error("native transfer-v2 reference claim rejected: {0:?}")]
    InvalidClaim(ReferenceError),
    /// The process requested RISC Zero's fake-receipt development mode.
    #[error("RISC0_DEV_MODE is set but Vault requires cryptographic receipts")]
    DevelopmentModeRequested,
    /// The zkVM execution environment could not encode the claim.
    #[error("failed to build zkVM environment: {0}")]
    Environment(String),
    /// The prover rejected or failed to execute the guest.
    #[error("zkVM proving failed: {0}")]
    Proving(String),
    /// The receipt could not be canonically serialized.
    #[error("failed to serialize receipt: {0}")]
    ReceiptEncoding(String),
    /// Proof bytes exceed the common protocol maximum.
    #[error("receipt exceeds the Vault proof bound")]
    ReceiptTooLarge,
    /// Proof bytes were not one canonical receipt encoding.
    #[error("failed to decode canonical receipt: {0}")]
    ReceiptDecoding(String),
    /// Cryptographic receipt verification failed.
    #[error("receipt verification failed: {0}")]
    ReceiptVerification(String),
    /// The authenticated journal used another schema.
    #[error("failed to decode authenticated journal: {0}")]
    JournalDecoding(String),
    /// The receipt proved public effects other than those requested.
    #[error("receipt journal does not match the requested transfer-v2 effects")]
    JournalMismatch,
}

/// Exact RISC Zero image identifier separately pinned from effects `circuit_id`.
#[must_use]
pub fn reference_image_id() -> [u8; 32] {
    let digest = Digest::from(VAULT_ZK_TRANSFER_GUEST_ID);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_bytes());
    bytes
}

/// Generates and immediately verifies one real transfer-v2 reference receipt.
pub fn prove(claim: &TransferV2ReferenceClaim) -> Result<ProofArtifact, ZkBackendError> {
    reject_development_mode()?;
    let expected_journal = claim.validate().map_err(ZkBackendError::InvalidClaim)?;
    let env = ExecutorEnv::builder()
        .write(claim)
        .map_err(|error| ZkBackendError::Environment(error.to_string()))?
        .build()
        .map_err(|error| ZkBackendError::Environment(error.to_string()))?;

    let started = Instant::now();
    let prove_info = default_prover()
        .prove(env, VAULT_ZK_TRANSFER_GUEST_ELF)
        .map_err(|error| ZkBackendError::Proving(error.to_string()))?;
    let elapsed_ms = started.elapsed().as_millis();
    prove_info
        .receipt
        .verify(VAULT_ZK_TRANSFER_GUEST_ID)
        .map_err(|error| ZkBackendError::ReceiptVerification(error.to_string()))?;
    let journal: TransferV2ReferenceJournal = prove_info
        .receipt
        .journal
        .decode()
        .map_err(|error| ZkBackendError::JournalDecoding(error.to_string()))?;
    if journal != expected_journal {
        return Err(ZkBackendError::JournalMismatch);
    }

    let proof = bincode::serialize(&prove_info.receipt)
        .map_err(|error| ZkBackendError::ReceiptEncoding(error.to_string()))?;
    if proof.len() > MAX_PROOF_BYTES {
        return Err(ZkBackendError::ReceiptTooLarge);
    }
    let metrics = ProvingMetrics {
        elapsed_ms,
        proof_bytes: proof.len(),
        segments: prove_info.stats.segments,
        total_cycles: prove_info.stats.total_cycles,
        user_cycles: prove_info.stats.user_cycles,
    };
    Ok(ProofArtifact {
        proof,
        journal,
        metrics,
    })
}

/// Verifies one canonical receipt against exact public transfer-v2 effects.
pub fn verify(
    expected_effects: &TransferV2Effects,
    proof: &[u8],
) -> Result<TransferV2ReferenceJournal, ZkBackendError> {
    reject_development_mode()?;
    if proof.len() > MAX_PROOF_BYTES {
        return Err(ZkBackendError::ReceiptTooLarge);
    }
    let receipt: Receipt = bincode::deserialize(proof)
        .map_err(|error| ZkBackendError::ReceiptDecoding(error.to_string()))?;
    let canonical = bincode::serialize(&receipt)
        .map_err(|error| ZkBackendError::ReceiptEncoding(error.to_string()))?;
    if canonical != proof {
        return Err(ZkBackendError::ReceiptDecoding(
            "alternate receipt encoding".to_owned(),
        ));
    }
    receipt
        .verify(VAULT_ZK_TRANSFER_GUEST_ID)
        .map_err(|error| ZkBackendError::ReceiptVerification(error.to_string()))?;
    let journal: TransferV2ReferenceJournal = receipt
        .journal
        .decode()
        .map_err(|error| ZkBackendError::JournalDecoding(error.to_string()))?;
    let expected_action_count = u16::try_from(expected_effects.actions().len())
        .map_err(|_| ZkBackendError::JournalMismatch)?;
    let expected_gas = expected_effects
        .gas()
        .total_fee()
        .map_err(|_| ZkBackendError::JournalMismatch)?;
    if journal.public_inputs_digest != *expected_effects.public_inputs_digest().as_bytes()
        || journal.action_count != expected_action_count
        || journal.gas_fee != expected_gas
    {
        return Err(ZkBackendError::JournalMismatch);
    }
    Ok(journal)
}

fn reject_development_mode() -> Result<(), ZkBackendError> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        Err(ZkBackendError::DevelopmentModeRequested)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_privacy::{
        ActionNullifier, CanonicalValueCommitment, EncryptedNote, NoteTreeRoot, OutputKind,
        VaultSpendingKey,
    };
    use vault_protocol::{EncryptedBurnV2, GasParameters, TransferV2Action};
    use vault_zk_transfer_core::{REFERENCE_STATEMENT_VERSION, ReferenceError};

    fn replace_effects(
        fixture: &mut ReferenceFixture,
        anchor: NoteTreeRoot,
        burn: EncryptedBurnV2,
        gas: GasParameters,
        actions: Vec<TransferV2Action>,
    ) {
        let effects = TransferV2Effects::new(
            fixture.effects.chain_id(),
            fixture.effects.circuit_id(),
            anchor,
            burn,
            gas,
            actions,
        )
        .expect("mutated effects remain canonical");
        fixture.claim.effects = effects.encode_canonical();
        fixture.effects = effects;
    }

    fn replace_actions(fixture: &mut ReferenceFixture, actions: Vec<TransferV2Action>) {
        replace_effects(
            fixture,
            fixture.effects.anchor(),
            fixture.effects.burn().clone(),
            fixture.effects.gas(),
            actions,
        );
    }

    fn replace_anchor(fixture: &mut ReferenceFixture, anchor: NoteTreeRoot) {
        let burn = fixture.effects.burn().clone();
        let gas = fixture.effects.gas();
        let actions = fixture.effects.actions().to_vec();
        replace_effects(fixture, anchor, burn, gas, actions);
    }

    fn replace_burn(fixture: &mut ReferenceFixture, burn: EncryptedBurnV2) {
        let anchor = fixture.effects.anchor();
        let gas = fixture.effects.gas();
        let actions = fixture.effects.actions().to_vec();
        replace_effects(fixture, anchor, burn, gas, actions);
    }

    fn replace_gas(fixture: &mut ReferenceFixture, gas: GasParameters) {
        let anchor = fixture.effects.anchor();
        let burn = fixture.effects.burn().clone();
        let actions = fixture.effects.actions().to_vec();
        replace_effects(fixture, anchor, burn, gas, actions);
    }

    fn actions_with_outputs(
        fixture: &ReferenceFixture,
        outputs: [EncryptedNote; 2],
    ) -> Vec<TransferV2Action> {
        fixture
            .effects
            .actions()
            .iter()
            .zip(outputs)
            .map(|(action, output)| {
                TransferV2Action::new(
                    action.nullifier(),
                    action.randomized_verification_key(),
                    action.net_value_commitment(),
                    output,
                )
            })
            .collect()
    }

    #[test]
    fn native_reference_validates_complete_transfer_v2_bundle() {
        let fixture = reference_fixture();
        let journal = fixture.claim.validate().expect("valid reference claim");
        assert_eq!(journal.action_count, 2);
        assert_eq!(journal.gas_fee, 25);
        assert_eq!(
            journal.public_inputs_digest,
            *fixture.effects.public_inputs_digest().as_bytes()
        );
    }

    #[test]
    fn statement_shape_and_private_action_mutations_fail_closed() {
        let mut fixture = reference_fixture();
        fixture.claim.statement_version = REFERENCE_STATEMENT_VERSION + 1;
        assert_eq!(
            fixture.claim.validate(),
            Err(ReferenceError::UnsupportedStatementVersion)
        );

        let mut fixture = reference_fixture();
        fixture.claim.actions.pop();
        assert_eq!(
            fixture.claim.validate(),
            Err(ReferenceError::InvalidWitnessShape)
        );

        let mut fixture = reference_fixture();
        fixture.claim.actions[0].membership_auth_path[0][0] ^= 1;
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        fixture.claim.actions[0].authorization_randomizer[0] ^= 1;
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        fixture.claim.actions[0].net_value_trapdoor[0] ^= 1;
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        let last = fixture.claim.actions[0].output_authorization_packet.len() - 1;
        fixture.claim.actions[0].output_authorization_packet[last] ^= 1;
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));
    }

    #[test]
    fn anchor_nullifier_randomized_key_and_net_commitment_mutations_fail_closed() {
        let mut fixture = reference_fixture();
        let mut anchor_bytes = fixture.effects.anchor().to_bytes();
        let alternate_anchor = (1_u8..=u8::MAX)
            .find_map(|delta| {
                anchor_bytes[0] ^= delta;
                let candidate = NoteTreeRoot::from_bytes(anchor_bytes).ok();
                anchor_bytes[0] ^= delta;
                candidate.filter(|value| *value != fixture.effects.anchor())
            })
            .expect("a nearby canonical alternate anchor exists");
        replace_anchor(&mut fixture, alternate_anchor);
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        let original = fixture.effects.actions().to_vec();
        let alternate_nullifier = (1_u8..=63)
            .filter_map(|byte| ActionNullifier::from_bytes([byte; 32]).ok())
            .find(|candidate| {
                *candidate < original[1].nullifier() && *candidate != original[0].nullifier()
            })
            .expect("canonical lower alternate nullifier exists");
        let actions = vec![
            TransferV2Action::new(
                alternate_nullifier,
                original[0].randomized_verification_key(),
                original[0].net_value_commitment(),
                original[0].output().clone(),
            ),
            original[1].clone(),
        ];
        replace_actions(&mut fixture, actions);
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        let original = fixture.effects.actions().to_vec();
        let actions = vec![
            TransferV2Action::new(
                original[0].nullifier(),
                original[1].randomized_verification_key(),
                original[0].net_value_commitment(),
                original[0].output().clone(),
            ),
            TransferV2Action::new(
                original[1].nullifier(),
                original[0].randomized_verification_key(),
                original[1].net_value_commitment(),
                original[1].output().clone(),
            ),
        ];
        replace_actions(&mut fixture, actions);
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        let original = fixture.effects.actions().to_vec();
        let actions = vec![
            TransferV2Action::new(
                original[0].nullifier(),
                original[0].randomized_verification_key(),
                original[1].net_value_commitment(),
                original[0].output().clone(),
            ),
            TransferV2Action::new(
                original[1].nullifier(),
                original[1].randomized_verification_key(),
                original[0].net_value_commitment(),
                original[1].output().clone(),
            ),
        ];
        replace_actions(&mut fixture, actions);
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));
    }

    #[test]
    fn output_opening_rho_and_ciphertext_mutations_fail_closed() {
        let mut fixture = reference_fixture();
        let original = fixture.effects.actions().to_vec();
        let first = original[0].output();
        let second = original[1].output();
        let outputs = [
            EncryptedNote::from_parts(
                second.note_commitment(),
                first.value_commitment(),
                first.ephemeral_key(),
                *first.note_ciphertext(),
                *first.outgoing_ciphertext(),
            )
            .expect("swapped note commitment remains canonical"),
            EncryptedNote::from_parts(
                first.note_commitment(),
                second.value_commitment(),
                second.ephemeral_key(),
                *second.note_ciphertext(),
                *second.outgoing_ciphertext(),
            )
            .expect("swapped note commitment remains canonical"),
        ];
        let actions = actions_with_outputs(&fixture, outputs);
        replace_actions(&mut fixture, actions);
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        let original = fixture.effects.actions().to_vec();
        let first = original[0].output();
        let second = original[1].output();
        let outputs = [
            EncryptedNote::from_parts(
                first.note_commitment(),
                second.value_commitment(),
                first.ephemeral_key(),
                *first.note_ciphertext(),
                *first.outgoing_ciphertext(),
            )
            .expect("swapped value commitment remains canonical"),
            EncryptedNote::from_parts(
                second.note_commitment(),
                first.value_commitment(),
                second.ephemeral_key(),
                *second.note_ciphertext(),
                *second.outgoing_ciphertext(),
            )
            .expect("swapped value commitment remains canonical"),
        ];
        let actions = actions_with_outputs(&fixture, outputs);
        replace_actions(&mut fixture, actions);
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        let other_nullifier = fixture.effects.actions()[1].nullifier().to_bytes();
        fixture.claim.actions[0].output_authorization_packet[91..123]
            .copy_from_slice(&other_nullifier);
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        let original = fixture.effects.actions().to_vec();
        let first = original[0].output();
        let second = original[1].output();
        let outputs = [
            EncryptedNote::from_parts(
                first.note_commitment(),
                first.value_commitment(),
                second.ephemeral_key(),
                *second.note_ciphertext(),
                *second.outgoing_ciphertext(),
            )
            .expect("swapped ciphertext tuple remains canonical"),
            EncryptedNote::from_parts(
                second.note_commitment(),
                second.value_commitment(),
                first.ephemeral_key(),
                *first.note_ciphertext(),
                *first.outgoing_ciphertext(),
            )
            .expect("swapped ciphertext tuple remains canonical"),
        ];
        let actions = actions_with_outputs(&fixture, outputs);
        replace_actions(&mut fixture, actions);
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));
    }

    #[test]
    fn owner_classification_burn_and_epoch_mutations_fail_closed() {
        let mut fixture = reference_fixture();
        let other = VaultSpendingKey::derive(&[0x5a; 32], [0x31; 32], 0)
            .expect("valid alternate owner")
            .full_viewing_key()
            .export();
        fixture.claim.actions[0].full_viewing_key = other.to_vec();
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        let external = fixture
            .claim
            .actions
            .iter_mut()
            .find(|action| {
                action.output_authorization_packet[39] == OutputKind::ExternalPayment as u8
            })
            .expect("fixture contains one external payment");
        external.output_authorization_packet[39] = OutputKind::InternalChange as u8;
        assert_eq!(fixture.claim.validate(), Err(ReferenceError::InvalidAction));

        let mut fixture = reference_fixture();
        fixture.claim.burn.commitment_trapdoor[0] ^= 1;
        assert_eq!(
            fixture.claim.validate(),
            Err(ReferenceError::BurnCommitmentMismatch)
        );

        let mut fixture = reference_fixture();
        fixture.claim.burn.encryption_randomness[0] ^= 1;
        assert_eq!(
            fixture.claim.validate(),
            Err(ReferenceError::BurnCiphertextMismatch)
        );

        let mut fixture = reference_fixture();
        fixture.claim.epoch_key.epoch += 1;
        assert_eq!(
            fixture.claim.validate(),
            Err(ReferenceError::EpochKeyMismatch)
        );
    }

    #[test]
    fn gas_conservation_and_public_burn_mutations_fail_closed() {
        let mut fixture = reference_fixture();
        let gas = fixture.effects.gas();
        replace_gas(
            &mut fixture,
            GasParameters {
                units: gas.units + 1,
                fee_per_gas: gas.fee_per_gas,
            },
        );
        assert_eq!(
            fixture.claim.validate(),
            Err(ReferenceError::ConservationFailure)
        );

        let mut fixture = reference_fixture();
        let alternate_commitment = CanonicalValueCommitment::from_bytes(
            fixture.effects.actions()[0].output().value_commitment(),
        )
        .expect("output value commitment is canonical");
        let public_burn = fixture.effects.burn();
        let burn = EncryptedBurnV2::new(
            public_burn.scheme_id(),
            public_burn.key_id(),
            public_burn.epoch(),
            alternate_commitment,
            *public_burn.ciphertext(),
        )
        .expect("alternate burn commitment is canonical");
        replace_burn(&mut fixture, burn);
        assert_eq!(
            fixture.claim.validate(),
            Err(ReferenceError::BurnCommitmentMismatch)
        );

        let mut fixture = reference_fixture();
        let public_burn = fixture.effects.burn();
        let mut ciphertext = *public_burn.ciphertext();
        let (c1, c2) = ciphertext.split_at_mut(32);
        c1.swap_with_slice(c2);
        let burn = EncryptedBurnV2::new(
            public_burn.scheme_id(),
            public_burn.key_id(),
            public_burn.epoch(),
            public_burn.commitment(),
            ciphertext,
        )
        .expect("swapped ciphertext points remain canonical");
        replace_burn(&mut fixture, burn);
        assert_eq!(
            fixture.claim.validate(),
            Err(ReferenceError::BurnCiphertextMismatch)
        );
    }

    #[test]
    fn guest_image_id_changes_require_explicit_review() {
        assert_eq!(reference_image_id(), REVIEWED_REFERENCE_V2_IMAGE_ID);
    }

    #[test]
    fn malformed_receipts_fail_closed_without_a_consensus_adapter() {
        let fixture = reference_fixture();
        assert!(verify(&fixture.effects, b"not a receipt").is_err());
    }
}
