#[cfg(unix)]
mod common;

use std::collections::BTreeSet;

use proptest::prelude::*;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
#[cfg(unix)]
use tempfile::tempdir;
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NoteCommitmentTree, OutputAuthorizationIntent,
    OutputAuthorizationPacket, OutputKind, PreparedNetValueCommitment, PreparedSpendAuthorization,
    RandomizedSpendValidatingKey, VaultFullViewingKey, VaultSpendingKey,
};
use vault_protocol::{
    ChainId, CircuitId, EncryptedBurnV2, GasParameters, ProtocolError, TransferV2,
    TransferV2Action, TransferV2Effects, TransferV2SignerPolicy,
};
use vault_signer::{
    BoundTransferV2SigningSession, DurableReplayGuard, MAX_SIGNER_MESSAGE_BYTES,
    SIGNER_AUTHORIZATION_REQUEST_MAX_BYTES, SessionChallenge, SessionError,
    SignerAuthorizationRequest,
};

#[cfg(unix)]
use vault_signer::{CrashConsistentReplayStore, SignerTransport, SignerTransportMessageKind};

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
    intents: Vec<OutputAuthorizationIntent>,
    rng: ChaCha20Rng,
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
        let intent = OutputAuthorizationIntent::new(
            NETWORK,
            KeyScope::External,
            OutputKind::ExternalPayment,
            recipient,
            1_000 + u64::from(index),
            nullifier,
            memo,
        )
        .unwrap();
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

#[cfg(unix)]
fn paired_transport() -> (SignerTransport, SignerTransport) {
    common::paired_transport([0x90; 32], NETWORK)
}

#[test]
#[cfg(unix)]
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
    let mut session = BoundTransferV2SigningSession::prepare_request(
        channel_binding,
        &issued_challenge,
        &mut replay_guard,
        &fixture.policy,
        request,
        &fixture.full_viewing_key,
        &fixture.intents,
        MAXIMUM_VALUE,
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
    let mut session = BoundTransferV2SigningSession::prepare_request(
        CHANNEL,
        &challenge,
        &mut guard,
        &fixture.policy,
        decoded,
        &fixture.full_viewing_key,
        &fixture.intents,
        MAXIMUM_VALUE,
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
    let mut session = BoundTransferV2SigningSession::prepare_request(
        CHANNEL,
        &challenge,
        &mut TestReplayGuard::default(),
        &fixture.policy,
        request,
        &fixture.full_viewing_key,
        &fixture.intents,
        MAXIMUM_VALUE,
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
    BoundTransferV2SigningSession::prepare_request(
        CHANNEL,
        &challenge,
        &mut guard,
        &fixture.policy,
        SignerAuthorizationRequest::decode(&encoded).unwrap(),
        &fixture.full_viewing_key,
        &fixture.intents,
        MAXIMUM_VALUE,
    )
    .unwrap();
    assert_eq!(
        BoundTransferV2SigningSession::prepare_request(
            CHANNEL,
            &challenge,
            &mut guard,
            &fixture.policy,
            SignerAuthorizationRequest::decode(&encoded).unwrap(),
            &fixture.full_viewing_key,
            &fixture.intents,
            MAXIMUM_VALUE,
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
        BoundTransferV2SigningSession::prepare_request(
            CHANNEL,
            &challenge,
            &mut TestReplayGuard::default(),
            &fixture.policy,
            decoded,
            &fixture.full_viewing_key,
            &fixture.intents,
            MAXIMUM_VALUE,
        )
        .unwrap_err(),
        SessionError::PolicyMismatch
    );

    let packet_start = 6 + 110 + 32 + 4 + effects_len + 1;
    let mut packet_mutation = encoded.to_vec();
    packet_mutation[packet_start + 123] ^= 1;
    let decoded = SignerAuthorizationRequest::decode(&packet_mutation).unwrap();
    assert_eq!(
        BoundTransferV2SigningSession::prepare_request(
            CHANNEL,
            &challenge,
            &mut TestReplayGuard::default(),
            &fixture.policy,
            decoded,
            &fixture.full_viewing_key,
            &fixture.intents,
            MAXIMUM_VALUE,
        )
        .unwrap_err(),
        SessionError::InvalidOutputAuthorization
    );

    let decoded = SignerAuthorizationRequest::decode(&encoded).unwrap();
    assert_eq!(
        BoundTransferV2SigningSession::prepare_request(
            [0x78; 32],
            &challenge,
            &mut TestReplayGuard::default(),
            &fixture.policy,
            decoded,
            &fixture.full_viewing_key,
            &fixture.intents,
            MAXIMUM_VALUE,
        )
        .unwrap_err(),
        SessionError::ChannelBindingMismatch
    );
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
    let mut session = BoundTransferV2SigningSession::prepare_request(
        CHANNEL,
        &challenge,
        &mut TestReplayGuard::default(),
        &fixture.policy,
        request,
        &fixture.full_viewing_key,
        &fixture.intents,
        MAXIMUM_VALUE,
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
