use pasta_curves::{
    group::{Group, GroupEncoding},
    pallas,
};
use proptest::prelude::*;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_burn::{
    BURN_CIPHERTEXT_BYTES, BURN_ENCRYPTION_SCHEME_ID, EpochBurnPublicKey, PreparedBurnCiphertext,
};
use vault_privacy::{
    ActionNullifier, EncryptedNote, KeyScope, MEMO_BYTES, NoteCommitmentTree,
    OutputAuthorizationIntent, OutputKind, PreparedNetValueCommitment, PreparedSpendAuthorization,
    RandomizedSpendValidatingKey, VaultSpendingKey, VerifiedOutputAuthorization,
};
use vault_protocol::{
    ChainId, CircuitId, EncryptedBurnV2, GasParameters, ProofVerificationError, ProtocolError,
    ShieldedStateV2, ShieldedStateV2Config, TRANSFER_V2_ACTION_BYTES,
    TRANSFER_V2_EFFECT_HEADER_BYTES, TRANSFER_V2_MAGIC, TRANSFER_V2_MAX_ENCODED_BYTES,
    TRANSFER_V2_PROTOCOL_VERSION, TransferV2, TransferV2Action, TransferV2Effects,
    TransferV2ProofVerifier, TransferV2SignerPolicy,
};

const NETWORK: [u8; 32] = [0x31; 32];
const CIRCUIT: [u8; 32] = [0x42; 32];
const BURN_SCHEME: [u8; 32] = [0x53; 32];
const BURN_KEY: [u8; 32] = [0x54; 32];
const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;
const BASE_GAS: u64 = 100;
const ACTION_GAS: u64 = 10;
const FEE_PER_GAS: u64 = 2;

#[derive(Debug)]
struct DigestVerifier;

impl TransferV2ProofVerifier for DigestVerifier {
    fn verify(
        &self,
        effects: &TransferV2Effects,
        proof: &[u8],
    ) -> Result<(), ProofVerificationError> {
        if proof == effects.public_inputs_digest().as_bytes() {
            Ok(())
        } else {
            Err(ProofVerificationError)
        }
    }
}

fn config() -> ShieldedStateV2Config {
    ShieldedStateV2Config {
        chain_id: ChainId::new(NETWORK),
        transfer_circuit_id: CircuitId::new(CIRCUIT),
        burn_scheme_id: BURN_SCHEME,
        burn_key_id: BURN_KEY,
        burn_epoch: 7,
        base_gas_units: BASE_GAS,
        gas_units_per_action: ACTION_GAS,
        minimum_fee_per_gas: FEE_PER_GAS,
        recent_anchor_limit: 4,
    }
}

struct SigningFixture {
    spending_key: VaultSpendingKey,
    effects: TransferV2Effects,
    prepared_authorizations: Vec<PreparedSpendAuthorization>,
    output_authorizations: Vec<VerifiedOutputAuthorization>,
    policy: TransferV2SignerPolicy,
    rng: ChaCha20Rng,
}

fn signing_fixture(anchor: vault_privacy::NoteTreeRoot, nonce: u8) -> SigningFixture {
    signing_fixture_with_count(anchor, nonce, 2)
}

fn signing_fixture_with_count(
    anchor: vault_privacy::NoteTreeRoot,
    nonce: u8,
    action_count: usize,
) -> SigningFixture {
    let spending_key = VaultSpendingKey::derive(&[0xA5; 32], NETWORK, 0).unwrap();
    let full_viewing_key = spending_key.full_viewing_key();
    let recipient = full_viewing_key.address_at(u32::from(nonce), KeyScope::External);
    let mut rng = ChaCha20Rng::from_seed([nonce; 32]);
    let mut actions_and_prepared = Vec::new();

    for index in 0..u8::try_from(action_count).unwrap() {
        let nullifier_bytes = [nonce.checked_add(index).unwrap(); 32];
        let nullifier = ActionNullifier::from_bytes(nullifier_bytes).unwrap();
        let prepared_authorization = spending_key.prepare_spend_authorization(&mut rng).unwrap();
        let memo = [index; MEMO_BYTES];
        let prepared_output = vault_privacy::PreparedNoteOutput::create(
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
        let output = prepared_output.encrypted_note().clone();
        let output_intent = OutputAuthorizationIntent::new(
            NETWORK,
            KeyScope::External,
            OutputKind::ExternalPayment,
            recipient,
            1_000 + u64::from(index),
            nullifier,
            memo,
        )
        .unwrap();
        let output_authorization = prepared_output
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap()
            .verify(&full_viewing_key, &output_intent, &output, MAXIMUM_VALUE)
            .unwrap();
        let net_value_commitment = PreparedNetValueCommitment::create(
            1_100 + u64::from(index),
            1_000 + u64::from(index),
            &mut rng,
        )
        .unwrap()
        .commitment();
        let randomized_verification_key = RandomizedSpendValidatingKey::from_bytes(
            prepared_authorization.randomized_verification_key(),
        )
        .unwrap();
        actions_and_prepared.push((
            TransferV2Action::new(
                nullifier,
                randomized_verification_key,
                net_value_commitment,
                output,
            ),
            prepared_authorization,
            output_authorization,
        ));
    }
    actions_and_prepared.sort_by_key(|(action, _, _)| action.nullifier());

    let burn_commitment = actions_and_prepared[0].0.net_value_commitment();
    let burn = EncryptedBurnV2::new(BURN_SCHEME, BURN_KEY, 7, burn_commitment, [0x64; 64]).unwrap();
    let effects = TransferV2Effects::new(
        ChainId::new(NETWORK),
        CircuitId::new(CIRCUIT),
        anchor,
        burn,
        GasParameters {
            units: BASE_GAS + ACTION_GAS * u64::try_from(action_count).unwrap(),
            fee_per_gas: FEE_PER_GAS,
        },
        actions_and_prepared
            .iter()
            .map(|(action, _, _)| action.clone())
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
        BASE_GAS + ACTION_GAS * u64::try_from(action_count).unwrap(),
        FEE_PER_GAS,
        u128::from(BASE_GAS + ACTION_GAS * u64::try_from(action_count).unwrap())
            * u128::from(FEE_PER_GAS),
    )
    .unwrap();
    let mut prepared_authorizations = Vec::with_capacity(actions_and_prepared.len());
    let mut output_authorizations = Vec::with_capacity(actions_and_prepared.len());
    for (_, prepared, output_authorization) in actions_and_prepared {
        prepared_authorizations.push(prepared);
        output_authorizations.push(output_authorization);
    }
    SigningFixture {
        spending_key,
        effects,
        prepared_authorizations,
        output_authorizations,
        policy,
        rng,
    }
}

fn signed_transfer(anchor: vault_privacy::NoteTreeRoot, nonce: u8) -> TransferV2 {
    let SigningFixture {
        spending_key,
        effects,
        prepared_authorizations,
        output_authorizations,
        policy,
        mut rng,
    } = signing_fixture(anchor, nonce);
    let signing_session = policy.prepare(&effects, output_authorizations).unwrap();
    let public_inputs = signing_session.public_inputs_digest();
    let authorizations = prepared_authorizations
        .iter()
        .enumerate()
        .map(|(index, prepared)| {
            signing_session
                .sign_action(index, &spending_key, prepared, &mut rng)
                .unwrap()
        })
        .collect();

    TransferV2::new(effects, public_inputs.as_bytes().to_vec(), authorizations).unwrap()
}

fn genesis_transfer(nonce: u8) -> TransferV2 {
    signed_transfer(NoteCommitmentTree::new().typed_root(), nonce)
}

fn rebuild_effects(
    original: &TransferV2Effects,
    chain_id: ChainId,
    circuit_id: CircuitId,
    burn: EncryptedBurnV2,
    gas: GasParameters,
) -> TransferV2Effects {
    TransferV2Effects::new(
        chain_id,
        circuit_id,
        original.anchor(),
        burn,
        gas,
        original.actions().to_vec(),
    )
    .unwrap()
}

#[test]
fn canonical_codec_round_trip_is_byte_exact() {
    let transfer = genesis_transfer(1);
    let encoded = transfer.encode();
    let decoded = TransferV2::decode(&encoded).unwrap();

    assert_eq!(&encoded[..4], &TRANSFER_V2_MAGIC);
    assert_eq!(
        u16::from_le_bytes(encoded[4..6].try_into().unwrap()),
        TRANSFER_V2_PROTOCOL_VERSION
    );
    assert_eq!(decoded, transfer);
    assert_eq!(decoded.encode(), encoded);
    assert_eq!(decoded.encoded_len(), encoded.len());
    assert_eq!(encoded.len(), 2_155);
    assert!(encoded.len() <= TRANSFER_V2_MAX_ENCODED_BYTES);
    assert_eq!(TRANSFER_V2_ACTION_BYTES, 852);
}

#[test]
fn every_truncated_prefix_and_trailing_byte_is_rejected() {
    let encoded = genesis_transfer(3).encode();
    for end in 0..encoded.len() {
        assert!(
            TransferV2::decode(&encoded[..end]).is_err(),
            "accepted truncated length {end}"
        );
    }

    let mut trailing = encoded;
    trailing.push(0);
    assert!(TransferV2::decode(&trailing).is_err());
}

#[test]
fn decoder_rejects_noncanonical_fields_and_invalid_authorization() {
    let transfer = genesis_transfer(5);
    let mut invalid_nullifier = transfer.encode();
    // Fixed effects header ends immediately before the first action.
    invalid_nullifier[TRANSFER_V2_EFFECT_HEADER_BYTES..TRANSFER_V2_EFFECT_HEADER_BYTES + 32]
        .fill(0xff);
    assert_eq!(
        TransferV2::decode(&invalid_nullifier).unwrap_err(),
        ProtocolError::InvalidActionNullifier
    );

    let mut tampered_ciphertext = transfer.encode();
    let first_note_ciphertext = TRANSFER_V2_EFFECT_HEADER_BYTES + 6 * 32;
    tampered_ciphertext[first_note_ciphertext + 100] ^= 1;
    assert_eq!(
        TransferV2::decode(&tampered_ciphertext).unwrap_err(),
        ProtocolError::InvalidSpendAuthorization
    );

    let mut tampered_signature = transfer.encode();
    let final_byte = tampered_signature.last_mut().unwrap();
    *final_byte ^= 1;
    assert_eq!(
        TransferV2::decode(&tampered_signature).unwrap_err(),
        ProtocolError::InvalidSpendAuthorization
    );
}

#[test]
fn constructors_enforce_padding_order_and_signature_count() {
    let transfer = genesis_transfer(7);
    let effects = transfer.effects();
    let one_action = vec![effects.actions()[0].clone()];
    assert_eq!(
        TransferV2Effects::new(
            effects.chain_id(),
            effects.circuit_id(),
            effects.anchor(),
            effects.burn().clone(),
            effects.gas(),
            one_action,
        )
        .unwrap_err(),
        ProtocolError::InvalidActionCount { count: 1 }
    );

    let reversed = effects.actions().iter().cloned().rev().collect();
    assert_eq!(
        TransferV2Effects::new(
            effects.chain_id(),
            effects.circuit_id(),
            effects.anchor(),
            effects.burn().clone(),
            effects.gas(),
            reversed,
        )
        .unwrap_err(),
        ProtocolError::NonCanonicalActionOrder
    );

    assert_eq!(
        TransferV2::new(effects.clone(), vec![1], vec![]).unwrap_err(),
        ProtocolError::AuthorizationCountMismatch {
            expected: 2,
            actual: 0,
        }
    );

    let first = &effects.actions()[0];
    let second = &effects.actions()[1];
    let reused_randomized_key = TransferV2Action::new(
        second.nullifier(),
        first.randomized_verification_key(),
        second.net_value_commitment(),
        second.output().clone(),
    );
    assert_eq!(
        TransferV2Effects::new(
            effects.chain_id(),
            effects.circuit_id(),
            effects.anchor(),
            effects.burn().clone(),
            effects.gas(),
            vec![first.clone(), reused_randomized_key],
        )
        .unwrap_err(),
        ProtocolError::DuplicateRandomizedSpendKey
    );

    let reused_ephemeral_key = EncryptedNote::from_parts(
        second.output().note_commitment(),
        second.output().value_commitment(),
        first.output().ephemeral_key(),
        *second.output().note_ciphertext(),
        *second.output().outgoing_ciphertext(),
    )
    .unwrap();
    let reused_ephemeral_key = TransferV2Action::new(
        second.nullifier(),
        second.randomized_verification_key(),
        second.net_value_commitment(),
        reused_ephemeral_key,
    );
    assert_eq!(
        TransferV2Effects::new(
            effects.chain_id(),
            effects.circuit_id(),
            effects.anchor(),
            effects.burn().clone(),
            effects.gas(),
            vec![first.clone(), reused_ephemeral_key],
        )
        .unwrap_err(),
        ProtocolError::DuplicateOutputEphemeralKey
    );
}

#[test]
fn signer_policy_rejects_domain_burn_shape_and_gas_mutations() {
    let anchor = NoteCommitmentTree::new().typed_root();

    let fixture = signing_fixture(anchor, 31);
    let mutated = rebuild_effects(
        &fixture.effects,
        ChainId::new([0x99; 32]),
        fixture.effects.circuit_id(),
        fixture.effects.burn().clone(),
        fixture.effects.gas(),
    );
    assert_eq!(
        fixture
            .policy
            .prepare(&mutated, fixture.output_authorizations)
            .unwrap_err(),
        ProtocolError::WrongChainId {
            expected: ChainId::new(NETWORK),
            actual: ChainId::new([0x99; 32]),
        }
    );

    let fixture = signing_fixture(anchor, 33);
    let mutated = rebuild_effects(
        &fixture.effects,
        fixture.effects.chain_id(),
        CircuitId::new([0x98; 32]),
        fixture.effects.burn().clone(),
        fixture.effects.gas(),
    );
    assert_eq!(
        fixture
            .policy
            .prepare(&mutated, fixture.output_authorizations)
            .unwrap_err(),
        ProtocolError::WrongCircuitId {
            expected: CircuitId::new(CIRCUIT),
            actual: CircuitId::new([0x98; 32]),
        }
    );

    for (nonce, scheme, key, epoch, expected) in [
        (
            35,
            [0x97; 32],
            BURN_KEY,
            7,
            ProtocolError::WrongBurnSchemeId,
        ),
        (
            37,
            BURN_SCHEME,
            [0x96; 32],
            7,
            ProtocolError::WrongBurnKeyId,
        ),
        (
            39,
            BURN_SCHEME,
            BURN_KEY,
            8,
            ProtocolError::WrongBurnEpoch {
                expected: 7,
                actual: 8,
            },
        ),
    ] {
        let fixture = signing_fixture(anchor, nonce);
        let original_burn = fixture.effects.burn();
        let burn = EncryptedBurnV2::new(
            scheme,
            key,
            epoch,
            original_burn.commitment(),
            *original_burn.ciphertext(),
        )
        .unwrap();
        let mutated = rebuild_effects(
            &fixture.effects,
            fixture.effects.chain_id(),
            fixture.effects.circuit_id(),
            burn,
            fixture.effects.gas(),
        );
        assert_eq!(
            fixture
                .policy
                .prepare(&mutated, fixture.output_authorizations)
                .unwrap_err(),
            expected
        );
    }

    let fixture = signing_fixture(anchor, 41);
    let wrong_shape_policy = TransferV2SignerPolicy::new(
        ChainId::new(NETWORK),
        CircuitId::new(CIRCUIT),
        BURN_SCHEME,
        BURN_KEY,
        7,
        4,
        BASE_GAS + ACTION_GAS * 2,
        FEE_PER_GAS,
        240,
    )
    .unwrap();
    assert_eq!(
        wrong_shape_policy
            .prepare(&fixture.effects, fixture.output_authorizations)
            .unwrap_err(),
        ProtocolError::InvalidActionCount { count: 2 }
    );

    let fixture = signing_fixture(anchor, 43);
    let mutated = rebuild_effects(
        &fixture.effects,
        fixture.effects.chain_id(),
        fixture.effects.circuit_id(),
        fixture.effects.burn().clone(),
        GasParameters {
            units: BASE_GAS + ACTION_GAS * 2 + 1,
            fee_per_gas: FEE_PER_GAS,
        },
    );
    assert_eq!(
        fixture
            .policy
            .prepare(&mutated, fixture.output_authorizations)
            .unwrap_err(),
        ProtocolError::IncorrectGasUnits {
            expected: 120,
            actual: 121,
        }
    );

    let fixture = signing_fixture(anchor, 45);
    let mutated = rebuild_effects(
        &fixture.effects,
        fixture.effects.chain_id(),
        fixture.effects.circuit_id(),
        fixture.effects.burn().clone(),
        GasParameters {
            units: BASE_GAS + ACTION_GAS * 2,
            fee_per_gas: FEE_PER_GAS + 1,
        },
    );
    assert_eq!(
        fixture
            .policy
            .prepare(&mutated, fixture.output_authorizations)
            .unwrap_err(),
        ProtocolError::FeePerGasTooHigh {
            maximum: 2,
            actual: 3,
        }
    );

    let fixture = signing_fixture(anchor, 47);
    let total_fee_policy = TransferV2SignerPolicy::new(
        ChainId::new(NETWORK),
        CircuitId::new(CIRCUIT),
        BURN_SCHEME,
        BURN_KEY,
        7,
        2,
        BASE_GAS + ACTION_GAS * 2,
        FEE_PER_GAS + 1,
        240,
    )
    .unwrap();
    let mutated = rebuild_effects(
        &fixture.effects,
        fixture.effects.chain_id(),
        fixture.effects.circuit_id(),
        fixture.effects.burn().clone(),
        GasParameters {
            units: BASE_GAS + ACTION_GAS * 2,
            fee_per_gas: FEE_PER_GAS + 1,
        },
    );
    assert_eq!(
        total_fee_policy
            .prepare(&mutated, fixture.output_authorizations)
            .unwrap_err(),
        ProtocolError::GasFeeTooHigh {
            maximum: 240,
            actual: 360,
        }
    );
}

#[test]
fn every_padding_bucket_uses_the_policy_bound_signing_session() {
    let anchor = NoteCommitmentTree::new().typed_root();
    for (nonce, action_count) in [(1, 2), (5, 4), (9, 8), (17, 16)] {
        let SigningFixture {
            spending_key,
            effects,
            prepared_authorizations,
            output_authorizations,
            policy,
            mut rng,
        } = signing_fixture_with_count(anchor, nonce, action_count);
        let session = policy.prepare(&effects, output_authorizations).unwrap();
        let authorizations = prepared_authorizations
            .iter()
            .enumerate()
            .map(|(index, prepared)| {
                session
                    .sign_action(index, &spending_key, prepared, &mut rng)
                    .unwrap()
            })
            .collect();
        let transfer = TransferV2::new(
            effects,
            session.public_inputs_digest().as_bytes().to_vec(),
            authorizations,
        )
        .unwrap();
        assert_eq!(transfer.effects().actions().len(), action_count);
        assert_eq!(transfer.verify_authorizations(), Ok(()));
    }
}

#[test]
fn signing_session_rejects_missing_swapped_and_wrong_signer_authorizations() {
    let anchor = NoteCommitmentTree::new().typed_root();

    let mut fixture = signing_fixture(anchor, 49);
    fixture.output_authorizations.pop();
    assert_eq!(
        fixture
            .policy
            .prepare(&fixture.effects, fixture.output_authorizations)
            .unwrap_err(),
        ProtocolError::OutputAuthorizationCountMismatch {
            expected: 2,
            actual: 1,
        }
    );

    let mut fixture = signing_fixture(anchor, 51);
    fixture.output_authorizations.swap(0, 1);
    assert_eq!(
        fixture
            .policy
            .prepare(&fixture.effects, fixture.output_authorizations)
            .unwrap_err(),
        ProtocolError::InvalidOutputAuthorization
    );

    let mut fixture = signing_fixture(anchor, 53);
    let session = fixture
        .policy
        .prepare(&fixture.effects, fixture.output_authorizations)
        .unwrap();
    assert_eq!(
        session
            .sign_action(
                2,
                &fixture.spending_key,
                &fixture.prepared_authorizations[0],
                &mut fixture.rng,
            )
            .unwrap_err(),
        ProtocolError::InvalidAuthorizationIndex {
            index: 2,
            action_count: 2,
        }
    );
    assert_eq!(
        session
            .sign_action(
                0,
                &fixture.spending_key,
                &fixture.prepared_authorizations[1],
                &mut fixture.rng,
            )
            .unwrap_err(),
        ProtocolError::InvalidOutputAuthorization
    );

    let wrong_spending_key = VaultSpendingKey::derive(&[0x5A; 32], NETWORK, 0).unwrap();
    assert_eq!(
        session
            .sign_action(
                0,
                &wrong_spending_key,
                &fixture.prepared_authorizations[0],
                &mut fixture.rng,
            )
            .unwrap_err(),
        ProtocolError::InvalidOutputAuthorization
    );
}

#[test]
fn signatures_bind_chain_and_every_effect_but_not_proof_encoding() {
    let transfer = genesis_transfer(9);
    let effects = transfer.effects();
    let wrong_chain_effects = TransferV2Effects::new(
        ChainId::new([0x99; 32]),
        effects.circuit_id(),
        effects.anchor(),
        effects.burn().clone(),
        effects.gas(),
        effects.actions().to_vec(),
    )
    .unwrap();
    assert_eq!(
        TransferV2::new(
            wrong_chain_effects,
            transfer.proof().to_vec(),
            transfer.authorizations().to_vec(),
        )
        .unwrap_err(),
        ProtocolError::InvalidSpendAuthorization
    );

    let original_txid = transfer.transaction_id();
    let changed_proof = transfer.with_proof(vec![0xEE; 48]).unwrap();
    assert_eq!(
        changed_proof.verify_authorizations(),
        Ok(()),
        "proof generation may finish after effect authorization"
    );
    assert_ne!(changed_proof.transaction_id(), original_txid);
}

#[test]
fn state_applies_proven_bundle_and_derives_note_tree_atomically() {
    let transfer = genesis_transfer(11);
    let mut expected_tree = NoteCommitmentTree::new();
    for action in transfer.effects().actions() {
        expected_tree
            .append(action.output().note_commitment())
            .unwrap();
    }

    let mut state = ShieldedStateV2::new(config(), DigestVerifier).unwrap();
    let receipt = state.apply_transfer(&transfer).unwrap();
    assert_eq!(receipt.action_count, 2);
    assert_eq!(receipt.first_output_position, 0);
    assert_eq!(receipt.new_note_tree_root, expected_tree.typed_root());
    assert_eq!(receipt.gas_fee, 240);
    assert_eq!(state.note_tree_size(), 2);
    assert_eq!(state.spent_nullifier_count(), 2);
    assert_eq!(state.current_root(), expected_tree.typed_root());

    assert!(matches!(
        state.apply_transfer(&transfer),
        Err(ProtocolError::ActionNullifierAlreadySpent(_))
    ));
}

#[test]
fn invalid_proof_and_wrong_epoch_leave_state_unchanged() {
    let transfer = genesis_transfer(13);
    let invalid_proof = transfer.clone().with_proof(vec![0xFF; 32]).unwrap();
    let mut state = ShieldedStateV2::new(config(), DigestVerifier).unwrap();
    let genesis = state.current_root();

    assert_eq!(
        state.apply_transfer(&invalid_proof),
        Err(ProtocolError::InvalidProof)
    );
    assert_eq!(state.current_root(), genesis);
    assert_eq!(state.note_tree_size(), 0);
    assert_eq!(state.spent_nullifier_count(), 0);

    let mut wrong_epoch = config();
    wrong_epoch.burn_epoch = 8;
    let mut state = ShieldedStateV2::new(wrong_epoch, DigestVerifier).unwrap();
    assert_eq!(
        state.apply_transfer(&transfer),
        Err(ProtocolError::WrongBurnEpoch {
            expected: 8,
            actual: 7,
        })
    );
    assert_eq!(state.current_root(), genesis);
}

#[test]
fn anchor_window_rejects_evicted_roots() {
    let mut strict_config = config();
    strict_config.recent_anchor_limit = 1;
    let mut state = ShieldedStateV2::new(strict_config, DigestVerifier).unwrap();
    let genesis = state.current_root();
    state.apply_transfer(&signed_transfer(genesis, 17)).unwrap();
    state.finalize_block_anchor();
    assert!(!state.accepts_anchor(genesis));

    let stale = signed_transfer(genesis, 19);
    assert_eq!(
        state.apply_transfer(&stale),
        Err(ProtocolError::UnknownNoteTreeRoot(genesis))
    );
}

#[test]
fn decoder_rejects_allocation_above_absolute_bound() {
    let oversized = vec![0; TRANSFER_V2_MAX_ENCODED_BYTES + 1];
    assert_eq!(
        TransferV2::decode(&oversized),
        Err(ProtocolError::TransactionTooLarge {
            size: TRANSFER_V2_MAX_ENCODED_BYTES + 1,
            maximum: TRANSFER_V2_MAX_ENCODED_BYTES,
        })
    );
}

#[test]
fn typed_threshold_burn_payload_binds_the_exact_epoch_key() {
    let commitments = [pallas::Scalar::from(7), pallas::Scalar::from(11)]
        .map(|coefficient| (pallas::Point::generator() * coefficient).to_bytes());
    let epoch_key =
        EpochBurnPublicKey::from_parts(12, 2, vec![1, 2, 3], commitments.to_vec()).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
    let encrypted =
        PreparedBurnCiphertext::encrypt(50, MAXIMUM_VALUE, &epoch_key, &mut rng).unwrap();
    let commitment = genesis_transfer(23).effects().burn().commitment();
    let payload =
        EncryptedBurnV2::from_threshold_ciphertext(&epoch_key, commitment, encrypted.ciphertext())
            .unwrap();

    assert_eq!(payload.scheme_id(), BURN_ENCRYPTION_SCHEME_ID);
    assert_eq!(payload.key_id(), epoch_key.key_id());
    assert_eq!(payload.epoch(), 12);
    assert_eq!(payload.ciphertext(), &encrypted.ciphertext().to_bytes());
    assert_eq!(
        EncryptedBurnV2::new(
            BURN_ENCRYPTION_SCHEME_ID,
            epoch_key.key_id(),
            epoch_key.epoch(),
            commitment,
            [0xff; BURN_CIPHERTEXT_BYTES],
        ),
        Err(ProtocolError::InvalidBurnCiphertext)
    );
}

#[test]
fn transfer_v2_reference_vector() {
    let transfer = genesis_transfer(15);
    assert_eq!(
        transfer.public_inputs_digest().to_string(),
        "5b46bbd5050150a9dceac4fdfb57922b60be3ab51879896fedab21a297a77237"
    );
    assert_eq!(
        transfer.transaction_id().to_string(),
        "a63b1f146782592d887951d0b21b815352ab84e078291f9867ce3482cdf10059"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn decoder_never_panics_and_accepts_only_canonical_bytes(
        tail in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        let mut bytes = Vec::with_capacity(6 + tail.len());
        bytes.extend_from_slice(&TRANSFER_V2_MAGIC);
        bytes.extend_from_slice(&TRANSFER_V2_PROTOCOL_VERSION.to_le_bytes());
        bytes.extend_from_slice(&tail);
        if let Ok(transfer) = TransferV2::decode(&bytes) {
            prop_assert_eq!(transfer.encode(), bytes);
        }
    }

    #[test]
    fn effects_decoder_never_panics_and_accepts_only_canonical_bytes(
        tail in prop::collection::vec(any::<u8>(), 0..16_384)
    ) {
        let mut bytes = Vec::with_capacity(6 + tail.len());
        bytes.extend_from_slice(&TRANSFER_V2_MAGIC);
        bytes.extend_from_slice(&TRANSFER_V2_PROTOCOL_VERSION.to_le_bytes());
        bytes.extend_from_slice(&tail);
        if let Ok(effects) = TransferV2Effects::decode_canonical(&bytes) {
            prop_assert_eq!(effects.encode_canonical(), bytes);
        }
    }
}
