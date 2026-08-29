use std::fmt;

use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_privacy::{
    ActionNullifier, KeyScope, NoteCommitmentTree, PreparedNetValueCommitment,
    RandomizedSpendValidatingKey, VaultSpendingKey,
};
use vault_protocol::{
    ChainId, CircuitId, EncryptedBurnV2, GasParameters, TransferV2Action, TransferV2Effects,
};
use vault_signer::{
    DELEGATED_PROVING_AUTHORIZATION_BYTES, DELEGATED_PROVING_POLICY_BYTES,
    DELEGATED_PROVING_REQUEST_MAX_BYTES, DELEGATED_PROVING_RESPONSE_MAX_BYTES,
    DELEGATED_PROVING_WITNESS_MAX_BYTES, DelegatedProverChannelBinding,
    DelegatedProverRevocationFacts, DelegatedProverRevocationId, DelegatedProvingAuthorization,
    DelegatedProvingAuthorizationFacts, DelegatedProvingAuthorizationId,
    DelegatedProvingDisclosure, DelegatedProvingError, DelegatedProvingJobId,
    DelegatedProvingPolicy, DelegatedProvingRequest, DelegatedProvingResponse,
    DelegatedTransferProofVerifier, DelegatedWitnessPackage, SignerConfirmationError,
    TrustedDelegatedProverRevocation, TrustedDelegatedProvingAuthorization,
};

const NETWORK: [u8; 32] = [0x31; 32];
const CIRCUIT: [u8; 32] = [0x42; 32];
const SUITE: [u8; 32] = [0x43; 32];
const PROVER_KEY: [u8; 32] = [0x44; 32];
const BURN_SCHEME: [u8; 32] = [0x53; 32];
const BURN_KEY: [u8; 32] = [0x54; 32];
const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;

fn make_effects(network: [u8; 32], circuit: [u8; 32], action_count: usize) -> TransferV2Effects {
    let spending_key = VaultSpendingKey::derive(&[0xA5; 32], network, 0).unwrap();
    let full_viewing_key = spending_key.full_viewing_key();
    let recipient = full_viewing_key.address_at(7, KeyScope::External);
    let mut rng = ChaCha20Rng::from_seed([0x66; 32]);
    let mut actions = Vec::with_capacity(action_count);
    for index in 0..u8::try_from(action_count).unwrap() {
        let mut nullifier_bytes = [0; 32];
        nullifier_bytes[..8].copy_from_slice(&(u64::from(index) + 1).to_le_bytes());
        let nullifier = ActionNullifier::from_bytes(nullifier_bytes).unwrap();
        let authorization = spending_key.prepare_spend_authorization(&mut rng).unwrap();
        let output = vault_privacy::PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            recipient,
            1_000 + u64::from(index),
            MAXIMUM_VALUE,
            nullifier,
            [index; 512],
            &mut rng,
        )
        .unwrap();
        let net_value_commitment = PreparedNetValueCommitment::create(
            1_100 + u64::from(index),
            1_000 + u64::from(index),
            &mut rng,
        )
        .unwrap()
        .commitment();
        actions.push(TransferV2Action::new(
            nullifier,
            RandomizedSpendValidatingKey::from_bytes(authorization.randomized_verification_key())
                .unwrap(),
            net_value_commitment,
            output.encrypted_note().clone(),
        ));
    }
    actions.sort_by_key(TransferV2Action::nullifier);
    let burn = EncryptedBurnV2::new(
        BURN_SCHEME,
        BURN_KEY,
        7,
        actions[0].net_value_commitment(),
        [0x64; 64],
    )
    .unwrap();
    TransferV2Effects::new(
        ChainId::new(network),
        CircuitId::new(circuit),
        NoteCommitmentTree::new().typed_root(),
        burn,
        GasParameters {
            units: 100 + 10 * u64::try_from(action_count).unwrap(),
            fee_per_gas: 2,
        },
        actions,
    )
    .unwrap()
}

fn policy() -> DelegatedProvingPolicy {
    DelegatedProvingPolicy::new(NETWORK, CIRCUIT, SUITE, 2, PROVER_KEY, 4_096, 64).unwrap()
}

fn authorization_fixture() -> (
    DelegatedProvingPolicy,
    TransferV2Effects,
    DelegatedWitnessPackage,
    DelegatedProvingAuthorization,
) {
    let policy = policy();
    let effects = make_effects(NETWORK, CIRCUIT, 2);
    let witness = DelegatedWitnessPackage::new(vec![0x55; 512]).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
    let authorization = DelegatedProvingAuthorization::new(
        &policy,
        DelegatedProvingJobId::generate(&mut rng).unwrap(),
        7,
        DelegatedProverChannelBinding::from_bytes([0x78; 32]).unwrap(),
        &effects,
        &witness,
    )
    .unwrap();
    (policy, effects, witness, authorization)
}

fn request_fixture() -> (
    DelegatedProvingPolicy,
    TransferV2Effects,
    DelegatedProvingAuthorization,
    Vec<u8>,
) {
    let policy = policy();
    let effects = make_effects(NETWORK, CIRCUIT, 2);
    let mut witness_bytes = vec![0x55; 512];
    witness_bytes[..4].copy_from_slice(b"VDPW");
    witness_bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
    witness_bytes[6] = 1;
    witness_bytes[7] = 2;
    witness_bytes[8..40].copy_from_slice(&NETWORK);
    witness_bytes[40..72].copy_from_slice(&CIRCUIT);
    witness_bytes[72..104].copy_from_slice(effects.public_inputs_digest().as_bytes());
    let witness = DelegatedWitnessPackage::new(witness_bytes.clone()).unwrap();
    let authorization = DelegatedProvingAuthorization::new(
        &policy,
        DelegatedProvingJobId::from_bytes([0x77; 32]).unwrap(),
        7,
        DelegatedProverChannelBinding::from_bytes([0x78; 32]).unwrap(),
        &effects,
        &witness,
    )
    .unwrap();
    (policy, effects, authorization, witness_bytes)
}

#[test]
fn policy_codec_binds_exact_suite_endpoint_bucket_and_resource_limits() {
    let policy = policy();
    let encoded = policy.encode();
    assert_eq!(encoded.len(), DELEGATED_PROVING_POLICY_BYTES);
    assert_eq!(DelegatedProvingPolicy::decode(&encoded).unwrap(), policy);
    assert_eq!(policy.network_id(), NETWORK);
    assert_eq!(policy.circuit_id(), CIRCUIT);
    assert_eq!(policy.proof_suite_id(), SUITE);
    assert_eq!(policy.prover_transport_key(), PROVER_KEY);
    assert_eq!(policy.action_count(), 2);
    assert_eq!(policy.maximum_witness_bytes(), 4_096);
    assert_eq!(policy.expected_proof_bytes(), 64);
    assert!(format!("{policy:?}").contains("REDACTED"));

    for offset in [0, 4, 6, 7, 144] {
        let mut malformed = encoded;
        malformed[offset] ^= 1;
        assert!(
            DelegatedProvingPolicy::decode(&malformed).is_err(),
            "malformed policy at offset {offset} was accepted"
        );
    }
    for range in [8..40, 40..72, 72..104, 104..136] {
        let mut malformed = encoded;
        malformed[range].fill(0);
        assert!(DelegatedProvingPolicy::decode(&malformed).is_err());
    }
    let mut changed_network = encoded;
    changed_network[8] ^= 1;
    let changed_network = DelegatedProvingPolicy::decode(&changed_network).unwrap();
    assert_ne!(changed_network.policy_id(), policy.policy_id());
    assert_ne!(
        changed_network.prover_fingerprint(),
        policy.prover_fingerprint()
    );

    for invalid in [
        DelegatedProvingPolicy::new(NETWORK, CIRCUIT, SUITE, 3, PROVER_KEY, 4_096, 64),
        DelegatedProvingPolicy::new(NETWORK, CIRCUIT, SUITE, 2, PROVER_KEY, 0, 64),
        DelegatedProvingPolicy::new(
            NETWORK,
            CIRCUIT,
            SUITE,
            2,
            PROVER_KEY,
            DELEGATED_PROVING_WITNESS_MAX_BYTES + 1,
            64,
        ),
        DelegatedProvingPolicy::new(NETWORK, CIRCUIT, SUITE, 2, [0; 32], 4_096, 64),
    ] {
        assert!(matches!(invalid, Err(DelegatedProvingError::InvalidPolicy)));
    }
}

#[test]
fn authorization_codec_binds_effects_channel_counter_and_exact_witness() {
    let (policy, effects, witness, authorization) = authorization_fixture();
    let encoded = authorization.encode();
    assert_eq!(encoded.len(), DELEGATED_PROVING_AUTHORIZATION_BYTES);
    assert_eq!(
        DelegatedProvingAuthorization::decode(&encoded, &policy, &effects).unwrap(),
        authorization
    );
    assert!(authorization.matches_witness_package(&witness));
    assert_eq!(authorization.action_count(), 2);
    assert_eq!(authorization.authorization_counter(), 7);
    assert_eq!(authorization.witness_bytes(), 512);
    assert_eq!(authorization.proof_bytes(), 64);
    assert!(format!("{authorization:?}").contains("REDACTED"));

    let other_witness = DelegatedWitnessPackage::new(vec![0x56; 512]).unwrap();
    assert!(!authorization.matches_witness_package(&other_witness));
    let wrong_effects = make_effects([0x32; 32], CIRCUIT, 2);
    assert!(DelegatedProvingAuthorization::decode(&encoded, &policy, &wrong_effects).is_err());

    for (offset, length) in [
        (0, 1),
        (4, 1),
        (6, 1),
        (7, 1),
        (8, 8),
        (16, 32),
        (48, 32),
        (80, 32),
        (112, 32),
        (144, 32),
        (176, 4),
        (180, 4),
    ] {
        let mut malformed = encoded;
        malformed[offset..offset + length].fill(0);
        assert!(
            DelegatedProvingAuthorization::decode(&malformed, &policy, &effects).is_err(),
            "malformed authorization at offset {offset} was accepted"
        );
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(DelegatedProvingAuthorization::decode(&trailing, &policy, &effects).is_err());
}

#[test]
fn request_codec_is_self_contained_bounded_and_exactly_bound() {
    let (policy, effects, authorization, witness_bytes) = request_fixture();
    let request = DelegatedProvingRequest::new(
        policy.clone(),
        authorization.clone(),
        effects.clone(),
        DelegatedWitnessPackage::new(witness_bytes.clone()).unwrap(),
    )
    .unwrap();
    let encoded = request.encode();
    assert!(encoded.len() <= DELEGATED_PROVING_REQUEST_MAX_BYTES);
    let decoded = DelegatedProvingRequest::decode(&encoded).unwrap();
    assert_eq!(decoded.policy(), &policy);
    assert_eq!(decoded.authorization(), &authorization);
    assert_eq!(decoded.effects(), &effects);
    assert!(format!("{decoded:?}").contains("REDACTED"));
    let (_, _, _, decoded_witness) = decoded.into_parts();
    assert_eq!(decoded_witness.as_slice(), witness_bytes);

    for offset in [0, 4, 6, 7, 8, 12, 16, 164, 348] {
        let mut malformed = encoded.to_vec();
        malformed[offset] ^= 1;
        assert!(
            DelegatedProvingRequest::decode(&malformed).is_err(),
            "malformed request at offset {offset} was accepted"
        );
    }
    for length in [0, 15, 347, encoded.len() - 1] {
        assert!(DelegatedProvingRequest::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(DelegatedProvingRequest::decode(&trailing).is_err());
    assert!(
        DelegatedProvingRequest::decode(&vec![0; DELEGATED_PROVING_REQUEST_MAX_BYTES + 1]).is_err()
    );

    let unbound = DelegatedWitnessPackage::new(vec![0x55; 512]).unwrap();
    assert!(matches!(
        DelegatedProvingRequest::new(policy, authorization, effects, unbound),
        Err(DelegatedProvingError::InvalidRequest)
    ));
}

#[derive(Default)]
struct AuthorizationConfirmation {
    seen: Option<DelegatedProvingAuthorizationFacts>,
    wrong: bool,
}

impl TrustedDelegatedProvingAuthorization for AuthorizationConfirmation {
    fn confirm_delegated_proving(
        &mut self,
        facts: &DelegatedProvingAuthorizationFacts,
    ) -> Result<DelegatedProvingAuthorizationId, SignerConfirmationError> {
        self.seen = Some(facts.clone());
        if self.wrong {
            Ok(DelegatedProvingAuthorizationId::from_bytes([0xFF; 32]))
        } else {
            Ok(facts.authorization_id())
        }
    }
}

#[test]
fn trusted_confirmation_exposes_the_irreversible_privacy_consequence() {
    let (policy, _, _, authorization) = authorization_fixture();
    let mut confirmation = AuthorizationConfirmation::default();
    let approved = authorization.confirm(&policy, &mut confirmation).unwrap();
    assert!(approved.matches(&policy, &authorization));
    let facts = confirmation.seen.unwrap();
    assert_eq!(facts.policy_id(), policy.policy_id());
    assert_eq!(facts.prover_id(), policy.prover_id());
    assert_eq!(facts.prover_fingerprint(), policy.prover_fingerprint());
    assert_eq!(facts.action_count(), 2);
    assert_eq!(facts.byte_lengths(), (512, 64));
    assert_eq!(facts.job().0, 7);
    let disclosure = facts.disclosure();
    assert_eq!(
        disclosure,
        DelegatedProvingDisclosure::CompleteTransferWitnessWithFullViewingKeyV1
    );
    assert!(disclosure.reveals_complete_transaction_witness());
    assert!(disclosure.reveals_full_viewing_capability());
    assert!(!disclosure.reveals_spending_authority());
    assert!(!disclosure.remotely_erasable());
    assert!(format!("{facts:?}").contains("REDACTED"));

    let mut wrong = AuthorizationConfirmation {
        seen: None,
        wrong: true,
    };
    assert!(matches!(
        authorization.confirm(&policy, &mut wrong),
        Err(DelegatedProvingError::ConfirmationFailed)
    ));
}

#[derive(Debug)]
struct TestVerifierError;

impl fmt::Display for TestVerifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("test verifier rejected proof")
    }
}

impl std::error::Error for TestVerifierError {}

struct TestVerifier {
    accept: bool,
    calls: usize,
}

impl DelegatedTransferProofVerifier for TestVerifier {
    type Error = TestVerifierError;

    fn verify_delegated_transfer(
        &mut self,
        proof_suite_id: [u8; 32],
        effects: &TransferV2Effects,
        proof: &[u8],
    ) -> Result<(), Self::Error> {
        self.calls += 1;
        if self.accept
            && proof_suite_id == SUITE
            && effects.public_inputs_digest().as_bytes() != &[0; 32]
            && proof == [0xA5; 64]
        {
            Ok(())
        } else {
            Err(TestVerifierError)
        }
    }
}

#[test]
fn response_codec_binds_job_context_before_local_verification() {
    let (policy, effects, authorization, _) = request_fixture();
    let response =
        DelegatedProvingResponse::new(&policy, &authorization, &effects, vec![0xA5; 64]).unwrap();
    let encoded = response.encode();
    assert!(encoded.len() <= DELEGATED_PROVING_RESPONSE_MAX_BYTES);
    assert_eq!(response.proof_bytes(), 64);
    assert!(format!("{response:?}").contains("REDACTED"));

    let decoded =
        DelegatedProvingResponse::decode(&encoded, &policy, &authorization, &effects).unwrap();
    assert_eq!(decoded.encode(), encoded);
    let mut verifier = TestVerifier {
        accept: true,
        calls: 0,
    };
    let verified = decoded
        .verify(&policy, &authorization, &effects, &mut verifier)
        .unwrap();
    assert_eq!(verifier.calls, 1);
    assert_eq!(verified.into_proof(), vec![0xA5; 64]);

    for offset in [0, 4, 6, 7, 8, 40, 72, 104, 136] {
        let mut malformed = encoded.clone();
        malformed[offset] ^= 1;
        assert!(
            DelegatedProvingResponse::decode(&malformed, &policy, &authorization, &effects)
                .is_err(),
            "malformed response at offset {offset} was accepted"
        );
    }
    for length in [0, 139, encoded.len() - 1] {
        assert!(
            DelegatedProvingResponse::decode(
                &encoded[..length],
                &policy,
                &authorization,
                &effects,
            )
            .is_err()
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(
        DelegatedProvingResponse::decode(&trailing, &policy, &authorization, &effects).is_err()
    );
    assert!(
        DelegatedProvingResponse::decode(
            &vec![0; DELEGATED_PROVING_RESPONSE_MAX_BYTES + 1],
            &policy,
            &authorization,
            &effects,
        )
        .is_err()
    );

    let mut mutated_proof = encoded;
    mutated_proof[140] ^= 1;
    let decoded =
        DelegatedProvingResponse::decode(&mutated_proof, &policy, &authorization, &effects)
            .unwrap();
    let mut verifier = TestVerifier {
        accept: true,
        calls: 0,
    };
    assert!(matches!(
        decoded.verify(&policy, &authorization, &effects, &mut verifier),
        Err(DelegatedProvingError::ProofRejected)
    ));
    assert_eq!(verifier.calls, 1);
}

#[test]
fn result_gate_requires_exact_effects_length_suite_and_local_verification() {
    let (policy, effects, _, authorization) = authorization_fixture();
    let mut verifier = TestVerifier {
        accept: true,
        calls: 0,
    };
    let verified = authorization
        .verify_result(&policy, &effects, vec![0xA5; 64], &mut verifier)
        .unwrap();
    assert_eq!(verifier.calls, 1);
    assert_eq!(
        verified.authorization_id(),
        authorization.authorization_id()
    );
    assert_eq!(verified.effects_digest(), effects.public_inputs_digest());
    assert!(format!("{verified:?}").contains("REDACTED"));
    assert_eq!(verified.into_proof(), vec![0xA5; 64]);

    assert!(matches!(
        authorization.verify_result(&policy, &effects, vec![0xA5; 63], &mut verifier),
        Err(DelegatedProvingError::ProofRejected)
    ));
    assert_eq!(verifier.calls, 1, "wrong length reached the verifier");

    verifier.accept = false;
    assert!(matches!(
        authorization.verify_result(&policy, &effects, vec![0xA5; 64], &mut verifier),
        Err(DelegatedProvingError::ProofRejected)
    ));
    assert_eq!(verifier.calls, 2);

    let wrong_effects = make_effects(NETWORK, [0x45; 32], 2);
    assert!(matches!(
        authorization.verify_result(&policy, &wrong_effects, vec![0xA5; 64], &mut verifier),
        Err(DelegatedProvingError::ProofRejected)
    ));
    assert_eq!(verifier.calls, 2, "wrong effects reached the verifier");
}

#[derive(Default)]
struct RevocationConfirmation {
    seen: Option<DelegatedProverRevocationFacts>,
    wrong: bool,
}

impl TrustedDelegatedProverRevocation for RevocationConfirmation {
    fn confirm_delegated_prover_revocation(
        &mut self,
        facts: &DelegatedProverRevocationFacts,
    ) -> Result<DelegatedProverRevocationId, SignerConfirmationError> {
        self.seen = Some(facts.clone());
        if self.wrong {
            Ok(DelegatedProverRevocationId::from_bytes([0xFE; 32]))
        } else {
            Ok(facts.revocation_id())
        }
    }
}

#[test]
fn permanent_revocation_binds_policy_generation_and_active_job() {
    let (policy, _, _, authorization) = authorization_fixture();
    let mut confirmation = RevocationConfirmation::default();
    let approved = policy
        .confirm_revocation(9, Some(&authorization), &mut confirmation)
        .unwrap();
    assert!(approved.matches(&policy, 9, Some(&authorization)));
    assert!(!approved.matches(&policy, 10, Some(&authorization)));
    let facts = confirmation.seen.unwrap();
    assert_eq!(facts.state_generation(), 9);
    assert_eq!(
        facts.active_authorization(),
        Some(authorization.authorization_id())
    );
    assert_eq!(facts.prover_fingerprint(), policy.prover_fingerprint());
    assert_eq!(facts.disclosure(), policy.disclosure());
    assert!(!facts.disclosure().remotely_erasable());
    assert!(format!("{facts:?}").contains("REDACTED"));

    let mut wrong = RevocationConfirmation {
        seen: None,
        wrong: true,
    };
    assert!(matches!(
        policy.confirm_revocation(9, Some(&authorization), &mut wrong),
        Err(DelegatedProvingError::ConfirmationFailed)
    ));
    assert!(matches!(
        policy.confirm_revocation(0, None, &mut wrong),
        Err(DelegatedProvingError::InvalidRevocation)
    ));
}
