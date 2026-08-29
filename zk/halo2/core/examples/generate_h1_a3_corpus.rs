#[path = "../tests/support/mod.rs"]
mod support;

use std::{env, fs, path::PathBuf};

use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_privacy::{
    KeyScope, OUTPUT_AUTHORIZATION_PACKET_BYTES, OutputAuthorizationPacket, OutputKind,
    PreparedSpendAuthorization, VaultAddress, VaultFullViewingKey, VaultSpendingKey,
};
use vault_protocol::{TransferV2Effects, TransferV2SignerPolicy};
use vault_signer::{
    ApprovedOutputIntent, BoundTransferV2Authorizations, BoundTransferV2SigningSession,
    DelegatedProverChannelBinding, DelegatedProvingAuthorization, DelegatedProvingJobId,
    DelegatedProvingPolicy, DelegatedProvingRequest, DelegatedProvingResponse,
    DelegatedWitnessPackage, DurableReplayGuard, MultisigAttemptId, MultisigCommitmentSet,
    MultisigNonceCommitment, MultisigParticipant, MultisigParticipantId, MultisigPolicy,
    PairedPeerId, SessionChallenge, SessionError, SignerAuthorizationRequest,
    SignerConfirmationError, SignerHandshake, SignerTransportKeyPair, SignerTransportMessageKind,
    TransferConfirmationFacts, TrustedTransferIntentSource,
};
use vault_zk_halo2_core::{delegated_witness::DelegatedTransferWitness, suite::VaultTransferSuite};

use support::{VectorBundle, delegated_conformance_fixture};

const NETWORK: [u8; 32] = [0x31; 32];
const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;
const WITNESS_HEADER_BYTES: usize = 208;
const ACTION_WITNESS_BYTES: usize = 2_662;
const PRIVATE_NOTE_BYTES: usize = 115;
const MEMBERSHIP_PATH_BYTES: usize = 1_028;
const PRIVATE_SCALAR_BYTES: usize = 32;
const PACKET_OFFSET: usize = PRIVATE_NOTE_BYTES + MEMBERSHIP_PATH_BYTES + 2 * PRIVATE_SCALAR_BYTES;
const ALPHA_OFFSET: usize = PRIVATE_NOTE_BYTES + MEMBERSHIP_PATH_BYTES;

struct Corpus {
    output: PathBuf,
    rows: Vec<(String, String, String, usize, String)>,
}

impl Corpus {
    fn new(output: PathBuf) -> Self {
        fs::create_dir_all(&output).unwrap();
        Self {
            output,
            rows: Vec::new(),
        }
    }

    fn add(&mut self, name: impl Into<String>, format: &str, expectation: &str, bytes: &[u8]) {
        let name = name.into();
        let path = self.output.join(&name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        self.rows.push((
            name,
            format.to_owned(),
            expectation.to_owned(),
            bytes.len(),
            blake3::hash(bytes).to_hex().to_string(),
        ));
    }

    fn add_codec_pair(&mut self, name: &str, format: &str, bytes: &[u8]) {
        self.add(name, format, "accept", bytes);
        let mut malformed = bytes.to_vec();
        malformed[0] ^= 1;
        self.add(format!("{name}.bad-magic"), format, "reject", &malformed);
    }

    fn finish(mut self) {
        self.rows.sort_by(|left, right| left.0.cmp(&right.0));
        let mut manifest = String::from("path\tformat\texpectation\tbytes\tblake3\n");
        for (path, format, expectation, bytes, digest) in self.rows {
            manifest.push_str(&format!(
                "{path}\t{format}\t{expectation}\t{bytes}\t{digest}\n"
            ));
        }
        fs::write(self.output.join("MANIFEST.tsv"), manifest).unwrap();
    }
}

#[derive(Clone)]
struct Intent {
    scope: KeyScope,
    kind: OutputKind,
    recipient: VaultAddress,
    value: u64,
    memo: [u8; 512],
}

struct Confirmation(Vec<Intent>);

impl TrustedTransferIntentSource for Confirmation {
    fn confirm_transfer(
        &mut self,
        _facts: &TransferConfirmationFacts,
    ) -> Result<Vec<ApprovedOutputIntent>, SignerConfirmationError> {
        self.0
            .iter()
            .map(|intent| {
                ApprovedOutputIntent::new(
                    intent.scope,
                    intent.kind,
                    intent.recipient,
                    intent.value,
                    intent.memo,
                )
                .map_err(|_| SignerConfirmationError::InvalidIntent)
            })
            .collect()
    }
}

#[derive(Default)]
struct ReplayGuard(bool);

impl DurableReplayGuard for ReplayGuard {
    fn consume(&mut self, _challenge: &SessionChallenge) -> Result<(), SessionError> {
        if self.0 {
            Err(SessionError::ReplayDetected)
        } else {
            self.0 = true;
            Ok(())
        }
    }
}

struct ActionMaterial {
    alpha: [u8; 32],
    packet: Vec<u8>,
    intent: Intent,
}

fn action_material(witness: &[u8], action_count: usize) -> Vec<ActionMaterial> {
    (0..action_count)
        .map(|index| {
            let start = WITNESS_HEADER_BYTES + index * ACTION_WITNESS_BYTES;
            let alpha = witness[start + ALPHA_OFFSET..start + ALPHA_OFFSET + 32]
                .try_into()
                .unwrap();
            let packet = witness
                [start + PACKET_OFFSET..start + PACKET_OFFSET + OUTPUT_AUTHORIZATION_PACKET_BYTES]
                .to_vec();
            let scope = match packet[38] {
                0 => KeyScope::External,
                1 => KeyScope::Internal,
                _ => unreachable!("validated packet scope"),
            };
            let kind = match packet[39] {
                0 => OutputKind::ExternalPayment,
                1 => OutputKind::InternalChange,
                2 => OutputKind::Dummy,
                _ => unreachable!("validated packet kind"),
            };
            let recipient = VaultAddress::from_bytes(packet[40..83].try_into().unwrap()).unwrap();
            let value = u64::from_le_bytes(packet[83..91].try_into().unwrap());
            let memo = packet[155..667].try_into().unwrap();
            ActionMaterial {
                alpha,
                packet,
                intent: Intent {
                    scope,
                    kind,
                    recipient,
                    value,
                    memo,
                },
            }
        })
        .collect()
}

fn point(seed: u8, account: u32) -> [u8; 32] {
    VaultSpendingKey::derive(&[seed; 32], NETWORK, account)
        .unwrap()
        .full_viewing_key()
        .spend_validating_key()
}

fn participant(id: u16, seed: u8) -> MultisigParticipant {
    MultisigParticipant::new(
        MultisigParticipantId::new(id).unwrap(),
        PairedPeerId::from_bytes([seed; 32]).unwrap(),
        point(seed, u32::from(id)),
    )
    .unwrap()
}

fn committed_proof(action_count: usize) -> Vec<u8> {
    let bytes: &[u8] = match action_count {
        2 => include_bytes!("../vectors/transfer-v2/transfer-v2-2.bin"),
        4 => include_bytes!("../vectors/transfer-v2/transfer-v2-4.bin"),
        8 => include_bytes!("../vectors/transfer-v2/transfer-v2-8.bin"),
        16 => include_bytes!("../vectors/transfer-v2/transfer-v2-16.bin"),
        _ => unreachable!("canonical bucket"),
    };
    VectorBundle::decode(bytes).unwrap().proof
}

fn signer_policy(effects: &TransferV2Effects) -> TransferV2SignerPolicy {
    let gas = effects.gas();
    TransferV2SignerPolicy::new(
        effects.chain_id(),
        effects.circuit_id(),
        effects.burn().scheme_id(),
        effects.burn().key_id(),
        effects.burn().epoch(),
        effects.actions().len(),
        gas.units,
        gas.fee_per_gas,
        gas.total_fee().unwrap(),
    )
    .unwrap()
}

fn add_bucket<const N: usize>(corpus: &mut Corpus) {
    let fixture = delegated_conformance_fixture::<N>();
    let effects = fixture.effects;
    let witness = fixture.delegated_witness.unwrap();
    let base = format!("bucket-{N}");
    let decoded = DelegatedTransferWitness::<N>::decode(&witness).unwrap();
    assert_eq!(decoded.encode().as_slice(), witness);
    decoded.prepare(&effects).unwrap();
    corpus.add(
        format!("{base}/effects.vlt2"),
        "VLT2-effects",
        "accept",
        &effects.encode_canonical(),
    );
    corpus.add_codec_pair(&format!("{base}/witness.vdpw"), "VDPW-v1", &witness);

    let material = action_material(&witness, N);
    for (index, action) in material.iter().enumerate() {
        OutputAuthorizationPacket::decode(&action.packet).unwrap();
        corpus.add_codec_pair(
            &format!("{base}/output-{index}-{:?}.vaop", action.intent.kind).to_lowercase(),
            "VAOP-v1",
            &action.packet,
        );
    }

    let full_viewing_key =
        VaultFullViewingKey::from_bytes(witness[112..208].try_into().unwrap()).unwrap();
    let spending_key = VaultSpendingKey::derive(&[0xA5; 32], NETWORK, 0).unwrap();
    assert_eq!(
        full_viewing_key.export().as_ref(),
        spending_key.full_viewing_key().export().as_ref()
    );
    let prepared = material
        .iter()
        .zip(effects.actions())
        .map(|(private, public)| {
            PreparedSpendAuthorization::from_proving_witness(
                full_viewing_key.spend_validating_key(),
                public.randomized_verification_key().to_bytes(),
                private.alpha,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let bucket = u8::try_from(N).unwrap();
    let coordinator_key = SignerTransportKeyPair::from_private([0x20 + bucket; 32]).unwrap();
    let signer_key = SignerTransportKeyPair::from_private([0x40 + bucket; 32]).unwrap();
    let mut coordinator_handshake = SignerHandshake::deterministic_vector_initiator(
        &coordinator_key,
        signer_key.public_key(),
        NETWORK,
        &[0x60 + bucket; 32],
    )
    .unwrap();
    let mut signer_handshake = SignerHandshake::deterministic_vector_responder(
        &signer_key,
        coordinator_key.public_key(),
        NETWORK,
        &[0x70 + bucket; 32],
    )
    .unwrap();
    let first_flight = coordinator_handshake.write_message().unwrap();
    signer_handshake.read_message(&first_flight).unwrap();
    let second_flight = signer_handshake.write_message().unwrap();
    coordinator_handshake.read_message(&second_flight).unwrap();
    corpus.add(
        format!("{base}/transport-handshake-1.noise"),
        "Noise-KK-flight-1",
        "accept",
        &first_flight,
    );
    corpus.add(
        format!("{base}/transport-handshake-2.noise"),
        "Noise-KK-flight-2",
        "accept",
        &second_flight,
    );
    let mut coordinator_transport = coordinator_handshake.into_transport().unwrap();
    let mut signer_transport = signer_handshake.into_transport().unwrap();
    assert_eq!(
        coordinator_transport.channel_binding(),
        signer_transport.channel_binding()
    );

    let mut challenge_rng = ChaCha20Rng::from_seed([0x80 + bucket; 32]);
    let channel = signer_transport.channel_binding();
    let challenge =
        SessionChallenge::generate(NETWORK, channel, N as u64, &mut challenge_rng).unwrap();
    let challenge_bytes = challenge.encode();
    corpus.add_codec_pair(
        &format!("{base}/challenge.vsch"),
        "VSCH-v1",
        &challenge_bytes,
    );
    let challenge_ciphertext = signer_transport
        .write_message(SignerTransportMessageKind::Challenge, &challenge_bytes)
        .unwrap();
    let decrypted = coordinator_transport
        .read_message(&challenge_ciphertext)
        .unwrap();
    assert_eq!(decrypted.kind, SignerTransportMessageKind::Challenge);
    assert_eq!(decrypted.payload, challenge_bytes.as_slice());
    corpus.add(
        format!("{base}/transport-challenge.ciphertext"),
        "Noise-KK-VST1",
        "decrypt-accept",
        &challenge_ciphertext,
    );
    let policy = signer_policy(&effects);
    let packets = material
        .iter()
        .map(|action| OutputAuthorizationPacket::decode(&action.packet).unwrap())
        .collect();
    let request =
        SignerAuthorizationRequest::new(&challenge, &policy, effects.clone(), packets).unwrap();
    let request_bytes = request.encode();
    corpus.add_codec_pair(
        &format!("{base}/sign-request.vsrq"),
        "VSRQ-v1",
        &request_bytes,
    );
    let request_ciphertext = coordinator_transport
        .write_message(
            SignerTransportMessageKind::AuthorizationRequest,
            &request_bytes,
        )
        .unwrap();
    let decrypted = signer_transport.read_message(&request_ciphertext).unwrap();
    assert_eq!(
        decrypted.kind,
        SignerTransportMessageKind::AuthorizationRequest
    );
    assert_eq!(decrypted.payload, request_bytes.as_slice());
    corpus.add(
        format!("{base}/transport-sign-request.ciphertext"),
        "Noise-KK-VST1",
        "decrypt-accept",
        &request_ciphertext,
    );
    let mut malformed_ciphertext = request_ciphertext;
    let last = malformed_ciphertext.len() - 1;
    malformed_ciphertext[last] ^= 1;
    corpus.add(
        format!("{base}/transport-sign-request.ciphertext.bad-tag"),
        "Noise-KK-VST1",
        "reject",
        &malformed_ciphertext,
    );
    let request = SignerAuthorizationRequest::decode(&request_bytes).unwrap();
    let mut confirmation = Confirmation(material.iter().map(|item| item.intent.clone()).collect());
    let mut session = BoundTransferV2SigningSession::prepare_confirmed_request(
        channel,
        &challenge,
        &mut ReplayGuard::default(),
        &policy,
        request,
        &full_viewing_key,
        &mut confirmation,
        MAXIMUM_VALUE,
    )
    .unwrap();
    let transcript = session.transcript_id();

    let multisig_policy = MultisigPolicy::new(
        NETWORK,
        2,
        &full_viewing_key,
        vec![
            participant(1, 0x61),
            participant(2, 0x62),
            participant(3, 0x63),
        ],
    )
    .unwrap();
    let commitments = MultisigCommitmentSet::new(
        &multisig_policy,
        MultisigAttemptId::from_bytes([0x40 + u8::try_from(N).unwrap(); 32]).unwrap(),
        vec![
            MultisigNonceCommitment::new(
                MultisigParticipantId::new(1).unwrap(),
                point(0x81, 1),
                point(0x82, 1),
            )
            .unwrap(),
            MultisigNonceCommitment::new(
                MultisigParticipantId::new(3).unwrap(),
                point(0x83, 3),
                point(0x84, 3),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let agreement = session
        .multisig_agreement(0, &multisig_policy, &commitments, &prepared[0])
        .unwrap();
    let multisig_policy_bytes = multisig_policy.encode();
    let commitment_bytes = commitments.encode();
    let agreement_bytes = agreement.encode();
    MultisigPolicy::decode(&multisig_policy_bytes).unwrap();
    MultisigCommitmentSet::decode(&commitment_bytes, &multisig_policy).unwrap();
    vault_signer::MultisigSigningAgreement::decode(
        &agreement_bytes,
        &multisig_policy,
        &commitments,
        &prepared[0],
    )
    .unwrap();
    corpus.add_codec_pair(
        &format!("{base}/multisig-policy.vmsp"),
        "VMSP-v1",
        &multisig_policy_bytes,
    );
    corpus.add_codec_pair(
        &format!("{base}/multisig-commitments.vmsc"),
        "VMSC-v1",
        &commitment_bytes,
    );
    corpus.add_codec_pair(
        &format!("{base}/multisig-agreement.vmsa"),
        "VMSA-v1",
        &agreement_bytes,
    );

    let mut signing_rng = ChaCha20Rng::from_seed([0x90 + u8::try_from(N).unwrap(); 32]);
    for (index, prepared) in prepared.iter().enumerate() {
        session
            .sign_action(index, &spending_key, prepared, &mut signing_rng)
            .unwrap();
    }
    let response = session.finish().unwrap();
    let response_bytes = response.encode();
    assert_eq!(
        BoundTransferV2Authorizations::decode(&response_bytes, transcript, &effects).unwrap(),
        response
    );
    corpus.add_codec_pair(
        &format!("{base}/sign-response.vsrp"),
        "VSRP-v1",
        &response_bytes,
    );
    let response_ciphertext = signer_transport
        .write_message(
            SignerTransportMessageKind::AuthorizationResponse,
            &response_bytes,
        )
        .unwrap();
    let decrypted = coordinator_transport
        .read_message(&response_ciphertext)
        .unwrap();
    assert_eq!(
        decrypted.kind,
        SignerTransportMessageKind::AuthorizationResponse
    );
    assert_eq!(decrypted.payload, response_bytes);
    corpus.add(
        format!("{base}/transport-sign-response.ciphertext"),
        "Noise-KK-VST1",
        "decrypt-accept",
        &response_ciphertext,
    );

    let suite = VaultTransferSuite::for_action_count(N).unwrap();
    let delegated_policy = DelegatedProvingPolicy::new(
        NETWORK,
        effects.circuit_id().into_bytes(),
        suite.circuit_id().into_bytes(),
        N,
        [0xD0 + u8::try_from(N).unwrap(); 32],
        witness.len(),
        suite.proof_bytes(),
    )
    .unwrap();
    let witness_package = DelegatedWitnessPackage::new(witness.clone()).unwrap();
    let authorization = DelegatedProvingAuthorization::new(
        &delegated_policy,
        DelegatedProvingJobId::from_bytes([u8::try_from(N).unwrap(); 32]).unwrap(),
        N as u64,
        DelegatedProverChannelBinding::from_bytes([0xC0 + u8::try_from(N).unwrap(); 32]).unwrap(),
        &effects,
        &witness_package,
    )
    .unwrap();
    let delegated_policy_bytes = delegated_policy.encode();
    let authorization_bytes = authorization.encode();
    let delegated_request = DelegatedProvingRequest::new(
        delegated_policy.clone(),
        authorization.clone(),
        effects.clone(),
        witness_package,
    )
    .unwrap();
    let delegated_request_bytes = delegated_request.encode();
    DelegatedProvingRequest::decode(&delegated_request_bytes).unwrap();
    corpus.add_codec_pair(
        &format!("{base}/delegated-policy.vdpp"),
        "VDPP-v1",
        &delegated_policy_bytes,
    );
    corpus.add_codec_pair(
        &format!("{base}/delegated-authorization.vdpa"),
        "VDPA-v1",
        &authorization_bytes,
    );
    corpus.add_codec_pair(
        &format!("{base}/delegated-request.vdpr"),
        "VDPR-v1",
        &delegated_request_bytes,
    );
    let proof = committed_proof(N);
    let delegated_response =
        DelegatedProvingResponse::new(&delegated_policy, &authorization, &effects, proof).unwrap();
    let delegated_response_bytes = delegated_response.encode();
    DelegatedProvingResponse::decode(
        &delegated_response_bytes,
        &delegated_policy,
        &authorization,
        &effects,
    )
    .unwrap();
    corpus.add(
        format!("{base}/delegated-response-context-negative.vdps"),
        "VDPS-v1",
        "codec-accept-local-proof-reject-different-effects",
        &delegated_response_bytes,
    );
    let mut malformed = delegated_response_bytes;
    malformed[0] ^= 1;
    corpus.add(
        format!("{base}/delegated-response-context-negative.vdps.bad-magic"),
        "VDPS-v1",
        "reject",
        &malformed,
    );
}

fn main() {
    let mut arguments = env::args_os().skip(1);
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .to_path_buf();
    let output = arguments.next().map_or_else(
        || workspace.join("docs/specs/test-vectors/h1-a3-v1"),
        PathBuf::from,
    );
    assert!(
        arguments.next().is_none(),
        "usage: generate_h1_a3_corpus [OUTPUT_DIRECTORY]"
    );
    let mut corpus = Corpus::new(output);
    add_bucket::<2>(&mut corpus);
    add_bucket::<4>(&mut corpus);
    add_bucket::<8>(&mut corpus);
    add_bucket::<16>(&mut corpus);
    corpus.finish();
}
