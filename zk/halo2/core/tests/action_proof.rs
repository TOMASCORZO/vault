use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use incrementalmerkletree::{Hashable, Level};
use orchard::{
    note::ExtractedNoteCommitment,
    tree::{MerkleHashOrchard, MerklePath},
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NoteMembershipPath, NoteTreeRoot,
    PreparedNetValueCommitment, PreparedNoteOutput, PrivateNote, RandomizedSpendValidatingKey,
    VaultSpendingKey, circuit::PreparedActionCircuit,
};
use vault_protocol::{
    ChainId, CircuitId, EncryptedBurnV2, GasParameters, TransferV2Action, TransferV2Effects,
    TransferV2ProofVerifier,
};
use vault_zk_halo2_core::{
    ACTION_VERIFYING_KEY_ID, AccountingProofError, AccountingProofVerifier, ActionProof,
    ActionProvingKey, ActionVerifyingKey, CompositeTransferProof, CompositeTransferVerifier,
    TWO_ACTION_PROOF_BYTES, composite_circuit_id, prove, verify,
};

const NETWORK: [u8; 32] = [0x31; 32];
const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;
const ACCOUNTING_SUITE: [u8; 32] = [0xc3; 32];
const ACCOUNTING_PROOF: [u8; 32] = [0xd4; 32];

#[derive(Debug)]
struct TestAccountingVerifier {
    active: Arc<AtomicBool>,
}

impl AccountingProofVerifier for TestAccountingVerifier {
    fn suite_id(&self) -> [u8; 32] {
        ACCOUNTING_SUITE
    }

    fn verify(
        &self,
        _effects: &TransferV2Effects,
        proof: &[u8],
    ) -> Result<(), AccountingProofError> {
        if self.active.load(Ordering::SeqCst) && proof == ACCOUNTING_PROOF {
            Ok(())
        } else {
            Err(AccountingProofError)
        }
    }
}

fn nullifier(byte: u8) -> ActionNullifier {
    ActionNullifier::from_bytes([byte; 32]).unwrap()
}

fn two_leaf_paths(commitments: [[u8; 32]; 2]) -> (NoteTreeRoot, [NoteMembershipPath; 2]) {
    let commitments = commitments.map(|bytes| {
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&bytes))
            .unwrap()
    });
    let leaves = commitments.map(|cmx| MerkleHashOrchard::from_cmx(&cmx));

    let auth_paths = [0_u32, 1_u32].map(|position| {
        let mut nodes = [MerkleHashOrchard::empty_leaf(); 32];
        nodes[0] = leaves[1 - position as usize];
        for level in 1_u8..32 {
            nodes[usize::from(level)] = MerkleHashOrchard::empty_root(Level::from(level));
        }
        let orchard_path = MerklePath::from_parts(position, nodes);
        let root = orchard_path.root(commitments[position as usize]);
        let path =
            NoteMembershipPath::from_parts(position, nodes.map(|node| node.to_bytes())).unwrap();
        (root, path)
    });

    assert_eq!(auth_paths[0].0, auth_paths[1].0);
    (
        NoteTreeRoot::from_bytes(auth_paths[0].0.to_bytes()).unwrap(),
        [auth_paths[0].1.clone(), auth_paths[1].1.clone()],
    )
}

fn fixture() -> (TransferV2Effects, Vec<PreparedActionCircuit>) {
    let spending_key = VaultSpendingKey::derive(&[0xa5; 32], NETWORK, 0).unwrap();
    let full_viewing_key = spending_key.full_viewing_key();
    let input_address = full_viewing_key.address_at(0, KeyScope::External);
    let recipient = VaultSpendingKey::derive(&[0xb6; 32], NETWORK, 0)
        .unwrap()
        .full_viewing_key()
        .address_at(0, KeyScope::External);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);

    let inputs = [
        PrivateNote::create(input_address, 10_100, MAXIMUM_VALUE, nullifier(2), &mut rng).unwrap(),
        PrivateNote::create(input_address, 5_100, MAXIMUM_VALUE, nullifier(3), &mut rng).unwrap(),
    ];
    let commitments = [
        inputs[0].commitment().unwrap(),
        inputs[1].commitment().unwrap(),
    ];
    let (anchor, paths) = two_leaf_paths(commitments);

    let mut prepared = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        let action_nullifier = full_viewing_key.note_nullifier(input).unwrap();
        let output_value = input.value() - 100;
        let output = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            recipient,
            output_value,
            MAXIMUM_VALUE,
            action_nullifier,
            [index as u8; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let authorization = spending_key.prepare_spend_authorization(&mut rng).unwrap();
        let net_value =
            PreparedNetValueCommitment::create(input.value(), output_value, &mut rng).unwrap();
        let action = TransferV2Action::new(
            action_nullifier,
            RandomizedSpendValidatingKey::from_bytes(authorization.randomized_verification_key())
                .unwrap(),
            net_value.commitment(),
            output.encrypted_note().clone(),
        );
        let circuit = PreparedActionCircuit::new(
            &full_viewing_key,
            input,
            &paths[index],
            &output,
            &authorization,
            &net_value,
            anchor,
        )
        .unwrap();
        prepared.push((action, circuit));
    }
    prepared.sort_by_key(|(action, _)| action.nullifier());

    let burn = EncryptedBurnV2::new(
        [0x52; 32],
        [0x53; 32],
        1,
        prepared[0].0.net_value_commitment(),
        [0x54; 64],
    )
    .unwrap();
    let effects = TransferV2Effects::new(
        ChainId::new(NETWORK),
        CircuitId::new(ACTION_VERIFYING_KEY_ID),
        anchor,
        burn,
        GasParameters {
            units: 120,
            fee_per_gas: 1,
        },
        prepared.iter().map(|(action, _)| action.clone()).collect(),
    )
    .unwrap();
    let circuits = prepared.into_iter().map(|(_, circuit)| circuit).collect();
    (effects, circuits)
}

#[test]
fn real_two_action_proof_is_canonical_and_fail_closed() {
    let (effects, circuits) = fixture();
    let keygen_started = Instant::now();
    let proving_key = ActionProvingKey::build();
    let proving_key_ms = keygen_started.elapsed().as_millis();
    let verifier_keygen_started = Instant::now();
    let verifying_key = ActionVerifyingKey::build();
    let verifying_key_ms = verifier_keygen_started.elapsed().as_millis();
    let proving_started = Instant::now();
    let proof = prove(
        &proving_key,
        &effects,
        circuits,
        ChaCha20Rng::from_seed([0x72; 32]),
    )
    .unwrap();
    let proving_ms = proving_started.elapsed().as_millis();

    assert_eq!(proof.as_bytes().len(), TWO_ACTION_PROOF_BYTES);
    let verification_started = Instant::now();
    verify(&verifying_key, &effects, &proof).unwrap();
    let verification_ms = verification_started.elapsed().as_millis();
    eprintln!(
        "halo2 metrics: pk={proving_key_ms}ms vk={verifying_key_ms}ms prove={proving_ms}ms verify={verification_ms}ms proof={}B",
        proof.as_bytes().len()
    );

    let wrong_anchor = NoteTreeRoot::from_bytes(orchard::Anchor::empty_tree().to_bytes()).unwrap();
    let tampered_effects = TransferV2Effects::new(
        effects.chain_id(),
        effects.circuit_id(),
        wrong_anchor,
        effects.burn().clone(),
        effects.gas(),
        effects.actions().to_vec(),
    )
    .unwrap();
    assert!(verify(&verifying_key, &tampered_effects, &proof).is_err());

    let mut tampered_bytes = proof.as_bytes().to_vec();
    tampered_bytes[TWO_ACTION_PROOF_BYTES / 2] ^= 1;
    let tampered_proof = ActionProof::from_bytes(tampered_bytes, 2).unwrap();
    assert!(verify(&verifying_key, &effects, &tampered_proof).is_err());

    assert!(ActionProof::from_bytes(vec![0; TWO_ACTION_PROOF_BYTES - 1], 2).is_err());

    // The only consensus adapter requires both proof layers and a circuit ID
    // derived from both verifying suites. This test-only accounting verifier
    // stands in solely to exercise that fail-closed composition boundary.
    let composite_effects = TransferV2Effects::new(
        effects.chain_id(),
        composite_circuit_id(ACCOUNTING_SUITE),
        effects.anchor(),
        effects.burn().clone(),
        effects.gas(),
        effects.actions().to_vec(),
    )
    .unwrap();
    let composite = CompositeTransferProof::new(
        2,
        ACCOUNTING_SUITE,
        proof.clone(),
        ACCOUNTING_PROOF.to_vec(),
    )
    .unwrap();
    let accounting_active = Arc::new(AtomicBool::new(true));
    let composite_verifier = CompositeTransferVerifier::new(TestAccountingVerifier {
        active: Arc::clone(&accounting_active),
    });
    let composite_bytes = composite.encode();
    composite_verifier
        .verify(&composite_effects, &composite_bytes)
        .unwrap();

    let rejected_accounting =
        CompositeTransferProof::new(2, ACCOUNTING_SUITE, proof.clone(), vec![0; 32]).unwrap();
    assert!(
        composite_verifier
            .verify(&composite_effects, &rejected_accounting.encode())
            .is_err()
    );

    accounting_active.store(false, Ordering::SeqCst);
    assert!(
        composite_verifier
            .verify(&composite_effects, &composite_bytes)
            .is_err()
    );
}
