mod common;

use std::collections::BTreeSet;

use proptest::prelude::*;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use tempfile::tempdir;
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NoteCommitmentTree, OutputAuthorizationPacket,
    OutputKind, PreparedNetValueCommitment, PreparedSpendAuthorization,
    RandomizedSpendValidatingKey, SpendAuthorizationDigest, VaultAddress, VaultFullViewingKey,
    VaultSpendingKey,
};
use vault_protocol::{
    ChainId, CircuitId, EncryptedBurnV2, GasParameters, ProtocolError, TransferV2,
    TransferV2Action, TransferV2Effects, TransferV2SignerPolicy,
};
use vault_signer::{
    ApprovedOutputIntent, BoundTransferV2SigningSession, CrashConsistentReplayStore,
    DurableReplayGuard, MAX_SIGNER_MESSAGE_BYTES, MULTISIG_COMMITMENT_SET_MAX_BYTES,
    MultisigAttemptId, MultisigCommitmentSet, MultisigNonceCommitment, MultisigParticipant,
    MultisigParticipantId, MultisigPolicy, PairedPeerId, SIGNER_AUTHORIZATION_REQUEST_MAX_BYTES,
    SessionChallenge, SessionError, SignerAuthorizationRequest, SignerConfirmationError,
    SignerTransport, SignerTransportMessageKind, TransferConfirmationFacts,
    TrustedTransferIntentSource,
};

const NETWORK: [u8; 32] = [0x31; 32];
const CIRCUIT: [u8; 32] = [0x42; 32];
const BURN_SCHEME: [u8; 32] = [0x53; 32];
const BURN_KEY: [u8; 32] = [0x54; 32];
const CHANNEL: [u8; 32] = [0x77; 32];
const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;
const BASE_GAS: u64 = 100;
const ACTION_GAS: u64 = 10;
const FEE_PER_GAS: u64 = 2;

struct Fixture {
    spending_key: VaultSpendingKey,
    full_viewing_key: VaultFullViewingKey,
    effects: TransferV2Effects,
    policy: TransferV2SignerPolicy,
    prepared: Vec<PreparedSpendAuthorization>,
    packets: Vec<OutputAuthorizationPacket>,
    intents: Vec<TestIntent>,
    rng: ChaCha20Rng,
}

#[derive(Clone)]
struct TestIntent {
    sender_scope: KeyScope,
    kind: OutputKind,
    recipient: VaultAddress,
    value: u64,
    memo: [u8; MEMO_BYTES],
}

struct TestConfirmation {
    intents: Vec<TestIntent>,
    seen: Vec<TransferConfirmationFacts>,
    reject: bool,
}

impl TestConfirmation {
    fn new(intents: &[TestIntent]) -> Self {
        Self {
            intents: intents.to_vec(),
            seen: Vec::new(),
            reject: false,
        }
    }
}

impl TrustedTransferIntentSource for TestConfirmation {
    fn confirm_transfer(
        &mut self,
        facts: &TransferConfirmationFacts,
    ) -> Result<Vec<ApprovedOutputIntent>, SignerConfirmationError> {
        self.seen.push(*facts);
        if self.reject {
            return Err(SignerConfirmationError::Rejected);
        }
        self.intents
            .iter()
            .map(|intent| {
                ApprovedOutputIntent::new(
                    intent.sender_scope,
                    intent.kind,
                    intent.recipient,
                    intent.value,
                    intent.memo,
                )
            })
            .collect()
    }
}

fn fixture(action_count: usize) -> Fixture {
    let spending_key = VaultSpendingKey::derive(&[0xa5; 32], NETWORK, 0).unwrap();
    let full_viewing_key = spending_key.full_viewing_key();
    let recipient = full_viewing_key.address_at(7, KeyScope::External);
    let mut rng = ChaCha20Rng::from_seed([0x66; 32]);
    let mut actions_and_private = Vec::new();
    for index in 0..u8::try_from(action_count).unwrap() {
        let mut nullifier_bytes = [0; 32];
        nullifier_bytes[..8].copy_from_slice(&(u64::from(index) + 1).to_le_bytes());
        let nullifier = ActionNullifier::from_bytes(nullifier_bytes).unwrap();
        let prepared = spending_key.prepare_spend_authorization(&mut rng).unwrap();
        let memo = [index; MEMO_BYTES];
        let output = vault_privacy::PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            recipient,
            1_000 + u64::from(index),
            MAXIMUM_VALUE,
            nullifier,
            memo,
            &mut rng,
        )
        .unwrap();
        let packet = output
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        let intent = TestIntent {
            sender_scope: KeyScope::External,
            kind: OutputKind::ExternalPayment,
            recipient,
            value: 1_000 + u64::from(index),
            memo,
        };
        let net_value_commitment = PreparedNetValueCommitment::create(
            1_100 + u64::from(index),
            1_000 + u64::from(index),
            &mut rng,
        )
        .unwrap()
        .commitment();
        let randomized_key =
            RandomizedSpendValidatingKey::from_bytes(prepared.randomized_verification_key())
                .unwrap();
        actions_and_private.push((
            TransferV2Action::new(
                nullifier,
                randomized_key,
                net_value_commitment,
                output.encrypted_note().clone(),
            ),
            prepared,
            packet,
            intent,
        ));
    }
    actions_and_private.sort_by_key(|(action, _, _, _)| action.nullifier());
    let burn = EncryptedBurnV2::new(
        BURN_SCHEME,
        BURN_KEY,
        7,
        actions_and_private[0].0.net_value_commitment(),
        [0x64; 64],
    )
    .unwrap();
    let gas_units = BASE_GAS + ACTION_GAS * u64::try_from(action_count).unwrap();
    let effects = TransferV2Effects::new(
        ChainId::new(NETWORK),
        CircuitId::new(CIRCUIT),
        NoteCommitmentTree::new().typed_root(),
        burn,
        GasParameters {
            units: gas_units,
            fee_per_gas: FEE_PER_GAS,
        },
        actions_and_private
            .iter()
            .map(|(action, _, _, _)| action.clone())
            .collect(),
    )
    .unwrap();
    let policy = TransferV2SignerPolicy::new(
        ChainId::new(NETWORK),
        CircuitId::new(CIRCUIT),
        BURN_SCHEME,
        BURN_KEY,
        7,
        action_count,
        gas_units,
        FEE_PER_GAS,
        u128::from(gas_units) * u128::from(FEE_PER_GAS),
    )
    .unwrap();
    let mut prepared = Vec::with_capacity(action_count);
    let mut packets = Vec::with_capacity(action_count);
    let mut intents = Vec::with_capacity(action_count);
    for (_, authorization, packet, intent) in actions_and_private {
        prepared.push(authorization);
        packets.push(packet);
        intents.push(intent);
    }
    Fixture {
        spending_key,
        full_viewing_key,
        effects,
        policy,
        prepared,
        packets,
        intents,
        rng,
    }
}

#[derive(Default)]
struct TestReplayGuard {
    highest_counter: u64,
    used: BTreeSet<[u8; 32]>,
}

impl DurableReplayGuard for TestReplayGuard {
    fn consume(&mut self, challenge: &SessionChallenge) -> Result<(), SessionError> {
        let session_id = *challenge.session_id();
        if challenge.counter() <= self.highest_counter || !self.used.insert(session_id) {
            return Err(SessionError::ReplayDetected);
        }
        self.highest_counter = challenge.counter();
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_with_confirmation<G: DurableReplayGuard>(
    expected_channel_binding: [u8; 32],
    challenge: &SessionChallenge,
    guard: &mut G,
    policy: &TransferV2SignerPolicy,
    request: SignerAuthorizationRequest,
    full_viewing_key: &VaultFullViewingKey,
    intents: &[TestIntent],
) -> Result<BoundTransferV2SigningSession, SessionError> {
    let mut confirmation = TestConfirmation::new(intents);
    BoundTransferV2SigningSession::prepare_confirmed_request(
        expected_channel_binding,
        challenge,
        guard,
        policy,
        request,
        full_viewing_key,
        &mut confirmation,
        MAXIMUM_VALUE,
    )
}

fn paired_transport() -> (SignerTransport, SignerTransport) {
    common::paired_transport([0x90; 32], NETWORK)
}

#[test]
fn encrypted_challenge_request_and_response_complete_end_to_end() {
    let mut fixture = fixture(2);
    let (mut coordinator_transport, mut signer_transport) = paired_transport();
    let channel_binding = signer_transport.channel_binding();
    let mut challenge_rng = ChaCha20Rng::from_seed([0x8e; 32]);
    let replay_directory = tempdir().unwrap();
    let mut replay_guard =
        CrashConsistentReplayStore::create(replay_directory.path().join("signer.vsrg")).unwrap();
    let issued_challenge = replay_guard
        .issue_challenge(NETWORK, channel_binding, &mut challenge_rng)
        .unwrap();

    let encrypted_challenge = signer_transport
        .write_message(
            SignerTransportMessageKind::Challenge,
            issued_challenge.encode().as_ref(),
        )
        .unwrap();
    let challenge_message = coordinator_transport
        .read_message(&encrypted_challenge)
        .unwrap();
    let echoed_challenge = SessionChallenge::decode(&challenge_message.payload).unwrap();
    let request = SignerAuthorizationRequest::new(
        &echoed_challenge,
        &fixture.policy,
        fixture.effects.clone(),
        fixture.packets,
    )
    .unwrap();
    let expected_transcript = request.transcript_id();
    let encrypted_request = coordinator_transport
        .write_message(
            SignerTransportMessageKind::AuthorizationRequest,
            request.encode().as_ref(),
        )
        .unwrap();
    let request_message = signer_transport.read_message(&encrypted_request).unwrap();
    let request = SignerAuthorizationRequest::decode(&request_message.payload).unwrap();
    let mut session = prepare_with_confirmation(
        channel_binding,
        &issued_challenge,
        &mut replay_guard,
        &fixture.policy,
        request,
        &fixture.full_viewing_key,
        &fixture.intents,
    )
    .unwrap();
    assert_eq!(session.transcript_id(), expected_transcript);
    for (index, prepared) in fixture.prepared.iter().enumerate() {
        session
            .sign_action(index, &fixture.spending_key, prepared, &mut fixture.rng)
            .unwrap();
    }
    let response = session.finish().unwrap();
    let encrypted_response = signer_transport
        .write_message(
            SignerTransportMessageKind::AuthorizationResponse,
            &response.encode(),
        )
        .unwrap();
    let response_message = coordinator_transport
        .read_message(&encrypted_response)
        .unwrap();
    let response = vault_signer::BoundTransferV2Authorizations::decode(
        &response_message.payload,
        expected_transcript,
        &fixture.effects,
    )
    .unwrap();
    let public_inputs = response.public_inputs_digest();
    let transfer = TransferV2::new(
        fixture.effects,
        public_inputs.as_bytes().to_vec(),
        response.into_authorizations(),
    )
    .unwrap();
    assert_eq!(transfer.verify_authorizations(), Ok(()));
}

#[test]
fn canonical_request_reconstructs_and_signs_once() {
    let mut fixture = fixture(2);
    let mut challenge_rng = ChaCha20Rng::from_seed([0x88; 32]);
    let challenge = SessionChallenge::generate(NETWORK, CHANNEL, 1, &mut challenge_rng).unwrap();
    let request = SignerAuthorizationRequest::new(
        &challenge,
        &fixture.policy,
        fixture.effects.clone(),
        fixture.packets,
    )
    .unwrap();
    let encoded = request.encode();
    assert!(encoded.len() <= SIGNER_AUTHORIZATION_REQUEST_MAX_BYTES);
    assert!(encoded.len() <= MAX_SIGNER_MESSAGE_BYTES);
    let decoded = SignerAuthorizationRequest::decode(&encoded).unwrap();
    assert_eq!(decoded.effects(), &fixture.effects);

    let mut guard = TestReplayGuard::default();
    let mut session = prepare_with_confirmation(
        CHANNEL,
        &challenge,
        &mut guard,
        &fixture.policy,
        decoded,
        &fixture.full_viewing_key,
        &fixture.intents,
    )
    .unwrap();
    let transcript = session.transcript_id();
    session
        .sign_action(
            0,
            &fixture.spending_key,
            &fixture.prepared[0],
            &mut fixture.rng,
        )
        .unwrap();
    assert_eq!(
        session.sign_action(
            0,
            &fixture.spending_key,
            &fixture.prepared[0],
            &mut fixture.rng,
        ),
        Err(SessionError::ActionAlreadySigned { index: 0 })
    );
    session
        .sign_action(
            1,
            &fixture.spending_key,
            &fixture.prepared[1],
            &mut fixture.rng,
        )
        .unwrap();
    let response = session.finish().unwrap();
    assert_eq!(response.transcript_id(), transcript);
    let encoded_response = response.encode();
    let response = vault_signer::BoundTransferV2Authorizations::decode(
        &encoded_response,
        transcript,
        &fixture.effects,
    )
    .unwrap();
    let public_inputs = response.public_inputs_digest();
    let transfer = TransferV2::new(
        fixture.effects,
        public_inputs.as_bytes().to_vec(),
        response.into_authorizations(),
    )
    .unwrap();
    assert_eq!(transfer.verify_authorizations(), Ok(()));
}

#[test]
fn final_multisig_authorization_path_accepts_only_the_agreed_standard_signature() {
    let mut fixture = fixture(2);
    let mut challenge_rng = ChaCha20Rng::from_seed([0x8A; 32]);
    let challenge = SessionChallenge::generate(NETWORK, CHANNEL, 1, &mut challenge_rng).unwrap();
    let request = SignerAuthorizationRequest::new(
        &challenge,
        &fixture.policy,
        fixture.effects.clone(),
        fixture.packets,
    )
    .unwrap();
    let mut guard = TestReplayGuard::default();
    let mut session = prepare_with_confirmation(
        CHANNEL,
        &challenge,
        &mut guard,
        &fixture.policy,
        request,
        &fixture.full_viewing_key,
        &fixture.intents,
    )
    .unwrap();

    let participant_key = |id: u16, seed: u8| {
        let key = VaultSpendingKey::derive(&[seed; 32], NETWORK, u32::from(id)).unwrap();
        MultisigParticipant::new(
            MultisigParticipantId::new(id).unwrap(),
            PairedPeerId::from_bytes([seed; 32]).unwrap(),
            key.full_viewing_key().spend_validating_key(),
        )
        .unwrap()
    };
    let multisig_policy = MultisigPolicy::new(
        NETWORK,
        2,
        &fixture.full_viewing_key,
        vec![participant_key(1, 0xA1), participant_key(2, 0xA2)],
    )
    .unwrap();
    let wrong_network_policy = MultisigPolicy::new(
        [0x32; 32],
        2,
        &fixture.full_viewing_key,
        vec![participant_key(1, 0xA1), participant_key(2, 0xA2)],
    )
    .unwrap();
    let authorization_digest = SpendAuthorizationDigest::derive(
        NETWORK,
        *fixture.effects.public_inputs_digest().as_bytes(),
    )
    .unwrap();

    for action_index in 0..2 {
        let attempt = MultisigAttemptId::generate(&mut fixture.rng).unwrap();
        let commitment = |id: u16, seed: u8| {
            let hiding = VaultSpendingKey::derive(
                &[seed; 32],
                NETWORK,
                u32::try_from(action_index * 4 + usize::from(id)).unwrap(),
            )
            .unwrap()
            .full_viewing_key()
            .spend_validating_key();
            let binding = VaultSpendingKey::derive(
                &[seed.wrapping_add(1); 32],
                NETWORK,
                u32::try_from(action_index * 4 + usize::from(id) + 16).unwrap(),
            )
            .unwrap()
            .full_viewing_key()
            .spend_validating_key();
            MultisigNonceCommitment::new(MultisigParticipantId::new(id).unwrap(), hiding, binding)
                .unwrap()
        };
        let commitments = MultisigCommitmentSet::new(
            &multisig_policy,
            attempt,
            vec![commitment(1, 0xB1), commitment(2, 0xC1)],
        )
        .unwrap();
        let wrong_network_commitments = MultisigCommitmentSet::new(
            &wrong_network_policy,
            attempt,
            vec![commitment(1, 0xB1), commitment(2, 0xC1)],
        )
        .unwrap();
        assert_eq!(
            session.multisig_agreement(
                action_index,
                &wrong_network_policy,
                &wrong_network_commitments,
                &fixture.prepared[action_index],
            ),
            Err(SessionError::InvalidMultisigAgreement)
        );
        assert!(commitments.encode().len() <= MULTISIG_COMMITMENT_SET_MAX_BYTES);
        let agreement = session
            .multisig_agreement(
                action_index,
                &multisig_policy,
                &commitments,
                &fixture.prepared[action_index],
            )
            .unwrap();

        // This creates the same standard RedPallas output that a reviewed
        // FROST aggregator must produce. It deliberately does not simulate
        // threshold shares or claim to test the disabled FROST implementation.
        let final_authorization = fixture
            .spending_key
            .sign_spend_authorization(
                &fixture.prepared[action_index],
                authorization_digest,
                &mut fixture.rng,
            )
            .unwrap();
        let wrong_action_index = 1 - action_index;
        let wrong_action_authorization = fixture
            .spending_key
            .sign_spend_authorization(
                &fixture.prepared[wrong_action_index],
                authorization_digest,
                &mut fixture.rng,
            )
            .unwrap();
        assert_eq!(
            session.attach_multisig_authorization(&agreement, wrong_action_authorization),
            Err(SessionError::Protocol(
                ProtocolError::InvalidSpendAuthorization
            ))
        );
        session
            .attach_multisig_authorization(&agreement, final_authorization)
            .unwrap();
    }

    let response = session.finish().unwrap();
    let transfer = TransferV2::new(
        fixture.effects,
        response.public_inputs_digest().as_bytes().to_vec(),
        response.into_authorizations(),
    )
    .unwrap();
    assert_eq!(transfer.verify_authorizations(), Ok(()));
}

#[test]
fn trusted_confirmation_binds_public_facts_and_rejection_consumes_nothing() {
    let fixture = fixture(2);
    let mut challenge_rng = ChaCha20Rng::from_seed([0x87; 32]);
    let challenge = SessionChallenge::generate(NETWORK, CHANNEL, 1, &mut challenge_rng).unwrap();
    let request = SignerAuthorizationRequest::new(
        &challenge,
        &fixture.policy,
        fixture.effects.clone(),
        fixture.packets,
    )
    .unwrap();
    let expected_transcript = request.transcript_id();
    let mut confirmation = TestConfirmation::new(&fixture.intents);
    confirmation.reject = true;
    let mut guard = TestReplayGuard::default();

    assert_eq!(
        BoundTransferV2SigningSession::prepare_confirmed_request(
            CHANNEL,
            &challenge,
            &mut guard,
            &fixture.policy,
            request,
            &fixture.full_viewing_key,
            &mut confirmation,
            MAXIMUM_VALUE,
        )
        .unwrap_err(),
        SessionError::ConfirmationFailed
    );
    assert_eq!(guard.highest_counter, 0);
    assert!(guard.used.is_empty());
    assert_eq!(confirmation.seen.len(), 1);
    let facts = confirmation.seen[0];
    assert_eq!(facts.network_id(), NETWORK);
    assert_eq!(facts.circuit_id(), CIRCUIT);
    assert_eq!(facts.burn_scheme_id(), BURN_SCHEME);
    assert_eq!(facts.burn_key_id(), BURN_KEY);
    assert_eq!(facts.burn_epoch(), 7);
    assert_eq!(facts.action_count(), 2);
    assert_eq!(facts.gas_units(), BASE_GAS + 2 * ACTION_GAS);
    assert_eq!(facts.fee_per_gas(), FEE_PER_GAS);
    assert_eq!(
        facts.total_gas_fee(),
        u128::from(BASE_GAS + 2 * ACTION_GAS) * u128::from(FEE_PER_GAS)
    );
    assert_eq!(
        facts.public_inputs_digest(),
        fixture.effects.public_inputs_digest()
    );
    assert_eq!(facts.transcript_id(), expected_transcript);
    assert!(format!("{facts:?}").contains("REDACTED"));
}

#[test]
fn response_codec_rejects_transcript_signature_and_length_mutations() {
    let mut fixture = fixture(2);
    let mut challenge_rng = ChaCha20Rng::from_seed([0x8d; 32]);
    let challenge = SessionChallenge::generate(NETWORK, CHANNEL, 1, &mut challenge_rng).unwrap();
    let request = SignerAuthorizationRequest::new(
        &challenge,
        &fixture.policy,
        fixture.effects.clone(),
        fixture.packets,
    )
    .unwrap();
    let mut session = prepare_with_confirmation(
        CHANNEL,
        &challenge,
        &mut TestReplayGuard::default(),
        &fixture.policy,
        request,
        &fixture.full_viewing_key,
        &fixture.intents,
    )
    .unwrap();
    for (index, prepared) in fixture.prepared.iter().enumerate() {
        session
            .sign_action(index, &fixture.spending_key, prepared, &mut fixture.rng)
            .unwrap();
    }
    let transcript = session.transcript_id();
    let response = session.finish().unwrap().encode();

    let mut wrong_transcript = response.clone();
    wrong_transcript[6] ^= 1;
    assert_eq!(
        vault_signer::BoundTransferV2Authorizations::decode(
            &wrong_transcript,
            transcript,
            &fixture.effects,
        )
        .unwrap_err(),
        SessionError::InvalidResponse
    );
    let mut wrong_signature = response.clone();
    *wrong_signature.last_mut().unwrap() ^= 1;
    assert_eq!(
        vault_signer::BoundTransferV2Authorizations::decode(
            &wrong_signature,
            transcript,
            &fixture.effects,
        )
        .unwrap_err(),
        SessionError::InvalidResponse
    );
    assert!(
        vault_signer::BoundTransferV2Authorizations::decode(
            &response[..response.len() - 1],
            transcript,
            &fixture.effects,
        )
        .is_err()
    );
    let mut trailing = response;
    trailing.push(0);
    assert!(
        vault_signer::BoundTransferV2Authorizations::decode(
            &trailing,
            transcript,
            &fixture.effects,
        )
        .is_err()
    );
}

#[test]
fn challenge_and_durable_guard_reject_replay() {
    let fixture = fixture(2);
    let mut challenge_rng = ChaCha20Rng::from_seed([0x89; 32]);
    let challenge = SessionChallenge::generate(NETWORK, CHANNEL, 9, &mut challenge_rng).unwrap();
    let request = SignerAuthorizationRequest::new(
        &challenge,
        &fixture.policy,
        fixture.effects.clone(),
        fixture.packets,
    )
    .unwrap();
    let encoded = request.encode();
    let mut guard = TestReplayGuard::default();
    prepare_with_confirmation(
        CHANNEL,
        &challenge,
        &mut guard,
        &fixture.policy,
        SignerAuthorizationRequest::decode(&encoded).unwrap(),
        &fixture.full_viewing_key,
        &fixture.intents,
    )
    .unwrap();
    assert_eq!(
        prepare_with_confirmation(
            CHANNEL,
            &challenge,
            &mut guard,
            &fixture.policy,
            SignerAuthorizationRequest::decode(&encoded).unwrap(),
            &fixture.full_viewing_key,
            &fixture.intents,
        )
        .unwrap_err(),
        SessionError::ReplayDetected
    );
}

#[test]
fn request_mutations_and_cross_channel_use_fail_closed() {
    let fixture = fixture(2);
    let effects_len = fixture.effects.encode_canonical().len();
    let mut challenge_rng = ChaCha20Rng::from_seed([0x8a; 32]);
    let challenge = SessionChallenge::generate(NETWORK, CHANNEL, 1, &mut challenge_rng).unwrap();
    let request = SignerAuthorizationRequest::new(
        &challenge,
        &fixture.policy,
        fixture.effects.clone(),
        fixture.packets,
    )
    .unwrap();
    let encoded = request.encode();

    for malformed in [encoded[..encoded.len() - 1].to_vec(), {
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        trailing
    }] {
        assert!(SignerAuthorizationRequest::decode(&malformed).is_err());
    }

    let mut policy_mutation = encoded.to_vec();
    policy_mutation[6 + 110] ^= 1;
    let decoded = SignerAuthorizationRequest::decode(&policy_mutation).unwrap();
    assert_eq!(
        prepare_with_confirmation(
            CHANNEL,
            &challenge,
            &mut TestReplayGuard::default(),
            &fixture.policy,
            decoded,
            &fixture.full_viewing_key,
            &fixture.intents,
        )
        .unwrap_err(),
        SessionError::PolicyMismatch
    );

    let packet_start = 6 + 110 + 32 + 4 + effects_len + 1;
    let mut packet_mutation = encoded.to_vec();
    packet_mutation[packet_start + 123] ^= 1;
    let decoded = SignerAuthorizationRequest::decode(&packet_mutation).unwrap();
    assert_eq!(
        prepare_with_confirmation(
            CHANNEL,
            &challenge,
            &mut TestReplayGuard::default(),
            &fixture.policy,
            decoded,
            &fixture.full_viewing_key,
            &fixture.intents,
        )
        .unwrap_err(),
        SessionError::InvalidOutputAuthorization
    );

    let decoded = SignerAuthorizationRequest::decode(&encoded).unwrap();
    let mut confirmation = TestConfirmation::new(&fixture.intents);
    assert_eq!(
        BoundTransferV2SigningSession::prepare_confirmed_request(
            [0x78; 32],
            &challenge,
            &mut TestReplayGuard::default(),
            &fixture.policy,
            decoded,
            &fixture.full_viewing_key,
            &mut confirmation,
            MAXIMUM_VALUE,
        )
        .unwrap_err(),
        SessionError::ChannelBindingMismatch
    );
    assert!(confirmation.seen.is_empty());
}

#[test]
fn all_action_buckets_fit_one_bounded_encrypted_request() {
    let mut challenge_rng = ChaCha20Rng::from_seed([0x8b; 32]);
    for (counter, action_count) in [(1, 2), (2, 4), (3, 8), (4, 16)] {
        let fixture = fixture(action_count);
        let challenge =
            SessionChallenge::generate(NETWORK, CHANNEL, counter, &mut challenge_rng).unwrap();
        let request = SignerAuthorizationRequest::new(
            &challenge,
            &fixture.policy,
            fixture.effects,
            fixture.packets,
        )
        .unwrap();
        let encoded = request.encode();
        assert!(encoded.len() <= MAX_SIGNER_MESSAGE_BYTES);
        assert_eq!(
            SignerAuthorizationRequest::decode(&encoded)
                .unwrap()
                .effects()
                .actions()
                .len(),
            action_count
        );
    }
}

#[test]
fn incomplete_session_and_wrong_prepared_key_do_not_release_response() {
    let mut fixture = fixture(2);
    let mut challenge_rng = ChaCha20Rng::from_seed([0x8c; 32]);
    let challenge = SessionChallenge::generate(NETWORK, CHANNEL, 1, &mut challenge_rng).unwrap();
    let request = SignerAuthorizationRequest::new(
        &challenge,
        &fixture.policy,
        fixture.effects.clone(),
        fixture.packets,
    )
    .unwrap();
    let mut session = prepare_with_confirmation(
        CHANNEL,
        &challenge,
        &mut TestReplayGuard::default(),
        &fixture.policy,
        request,
        &fixture.full_viewing_key,
        &fixture.intents,
    )
    .unwrap();
    assert_eq!(
        session
            .sign_action(
                0,
                &fixture.spending_key,
                &fixture.prepared[1],
                &mut fixture.rng,
            )
            .unwrap_err(),
        SessionError::Protocol(ProtocolError::InvalidOutputAuthorization)
    );
    session
        .sign_action(
            0,
            &fixture.spending_key,
            &fixture.prepared[0],
            &mut fixture.rng,
        )
        .unwrap();
    assert_eq!(
        session.finish().unwrap_err(),
        SessionError::IncompleteSession
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn request_decoder_never_panics_and_accepts_only_canonical_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..40_000)
    ) {
        if let Ok(request) = SignerAuthorizationRequest::decode(&bytes) {
            let canonical = request.encode();
            prop_assert_eq!(&canonical[..], bytes.as_slice());
        }
    }
}
