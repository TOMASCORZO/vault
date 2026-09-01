//! Opt-in C1 proving, C4 vector verification, and C6 receipt compression.

use std::{fs::OpenOptions, io::Write, path::PathBuf, time::Instant};

use incrementalmerkletree::{Hashable, Level};
use orchard::{
    note::ExtractedNoteCommitment,
    tree::{MerkleHashOrchard, MerklePath},
};
use pasta_curves::{
    group::{Group, GroupEncoding},
    pallas,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use risc0_zkvm::{InnerReceipt, ProverOpts, Receipt, default_prover};
use vault_burn::{EpochBurnPublicKey, PreparedBurnCiphertext};
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NOTE_TREE_DEPTH, NoteMembershipPath, NoteTreeRoot,
    OutputKind, PreparedBurnCommitment, PreparedNetValueCommitment, PreparedNoteOutput,
    PrivateNote, RandomizedSpendValidatingKey, VaultSpendingKey,
};
use vault_protocol::{
    ChainId, CircuitId, EncryptedBurnV2, GasParameters, MAX_PROOF_BYTES, PublicInputDigest,
    TransferV2Action, TransferV2Effects,
};
use vault_zk_accounting_core::transfer_v2::{
    MAXIMUM_VLT_ATOMIC, TransferV2ActionWitness, TransferV2BurnWitness, TransferV2ReferenceClaim,
};
use vault_zk_risc0::{
    REVIEWED_REFERENCE_GUEST_ID, ZkBackendError, prove_transfer_v2, verify_transfer_v2,
};

const NETWORK: [u8; 32] = [0x31; 32];
const C4_RECEIPT_BYTES: usize = 311_977_650;
const C4_PUBLIC_INPUTS: &str = "ad626fcc1292ab423bdfc773c568662c02aecd83f9b29481ea040a236b909454";

fn nullifier(byte: u8) -> ActionNullifier {
    ActionNullifier::from_bytes([byte; 32]).unwrap()
}

fn two_leaf_paths(commitments: [[u8; 32]; 2]) -> (NoteTreeRoot, [NoteMembershipPath; 2]) {
    let commitments = commitments.map(|bytes| {
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&bytes))
            .unwrap()
    });
    let leaves = commitments.map(|cmx| MerkleHashOrchard::from_cmx(&cmx));
    let paths = [0_u32, 1_u32].map(|position| {
        let mut nodes = [MerkleHashOrchard::empty_leaf(); NOTE_TREE_DEPTH as usize];
        nodes[0] = leaves[1 - position as usize];
        for level in 1_u8..NOTE_TREE_DEPTH {
            nodes[usize::from(level)] = MerkleHashOrchard::empty_root(Level::from(level));
        }
        let path = MerklePath::from_parts(position, nodes);
        let root = path.root(commitments[position as usize]);
        (
            root,
            NoteMembershipPath::from_parts(position, nodes.map(|node| node.to_bytes())).unwrap(),
        )
    });
    assert_eq!(paths[0].0, paths[1].0);
    (
        NoteTreeRoot::from_bytes(paths[0].0.to_bytes()).unwrap(),
        [paths[0].1.clone(), paths[1].1.clone()],
    )
}

fn deterministic_claim() -> TransferV2ReferenceClaim {
    let spending_key = VaultSpendingKey::derive(&[0xA5; 32], NETWORK, 0).unwrap();
    let full_viewing_key = spending_key.full_viewing_key();
    let input_address = full_viewing_key.address_at(0, KeyScope::Internal);
    let external_address = VaultSpendingKey::derive(&[0xB6; 32], NETWORK, 0)
        .unwrap()
        .full_viewing_key()
        .address_at(0, KeyScope::External);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let inputs = [
        PrivateNote::create(
            input_address,
            5_051,
            MAXIMUM_VLT_ATOMIC,
            nullifier(2),
            &mut rng,
        )
        .unwrap(),
        PrivateNote::create(
            input_address,
            1_000,
            MAXIMUM_VLT_ATOMIC,
            nullifier(3),
            &mut rng,
        )
        .unwrap(),
    ];
    let (anchor, paths) = two_leaf_paths([
        inputs[0].commitment().unwrap(),
        inputs[1].commitment().unwrap(),
    ]);

    let recipients = [external_address, input_address];
    let output_values = [5_000, 1_000];
    let kinds = [OutputKind::ExternalPayment, OutputKind::InternalChange];
    let mut prepared = Vec::new();
    for index in 0..2 {
        let action_nullifier = full_viewing_key.note_nullifier(&inputs[index]).unwrap();
        let output = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            recipients[index],
            output_values[index],
            MAXIMUM_VLT_ATOMIC,
            action_nullifier,
            [index as u8; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let authorization = spending_key.prepare_spend_authorization(&mut rng).unwrap();
        let net = PreparedNetValueCommitment::create(
            inputs[index].value(),
            output_values[index],
            &mut rng,
        )
        .unwrap();
        let packet = output.authorization_packet(NETWORK, kinds[index]).unwrap();
        let witness = TransferV2ActionWitness {
            full_viewing_key: full_viewing_key.export().to_vec(),
            input_note: inputs[index].encode_private().to_vec(),
            membership_position: paths[index].position(),
            membership_auth_path: paths[index].auth_path().to_vec(),
            output_authorization_packet: packet.encode().to_vec(),
            authorization_randomizer: *authorization.randomizer(),
            net_value_commitment_trapdoor: *net.trapdoor(),
        };
        let public = TransferV2Action::new(
            action_nullifier,
            RandomizedSpendValidatingKey::from_bytes(authorization.randomized_verification_key())
                .unwrap(),
            net.commitment(),
            output.encrypted_note().clone(),
        );
        prepared.push((action_nullifier, witness, public));
    }
    prepared.sort_by_key(|(action_nullifier, _, _)| *action_nullifier);
    let (actions, public_actions): (Vec<_>, Vec<_>) = prepared
        .into_iter()
        .map(|(_, witness, public)| (witness, public))
        .unzip();

    let coefficients = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
    let commitments = coefficients
        .map(|value| (pallas::Point::generator() * value).to_bytes())
        .to_vec();
    let epoch_key =
        EpochBurnPublicKey::from_parts(9, 2, vec![1, 2, 3], commitments.clone()).unwrap();
    let burn_commitment = PreparedBurnCommitment::create(25, MAXIMUM_VLT_ATOMIC, &mut rng).unwrap();
    let burn_ciphertext =
        PreparedBurnCiphertext::encrypt(25, MAXIMUM_VLT_ATOMIC, &epoch_key, &mut rng).unwrap();
    let effects = TransferV2Effects::new(
        ChainId::new(NETWORK),
        CircuitId::new([0x44; 32]),
        anchor,
        EncryptedBurnV2::from_threshold_ciphertext(
            &epoch_key,
            burn_commitment.commitment(),
            burn_ciphertext.ciphertext(),
        )
        .unwrap(),
        GasParameters {
            units: 2,
            fee_per_gas: 13,
        },
        public_actions,
    )
    .unwrap();

    TransferV2ReferenceClaim {
        canonical_effects: effects.encode_canonical(),
        actions,
        burn: TransferV2BurnWitness {
            epoch: epoch_key.epoch(),
            threshold: epoch_key.threshold(),
            participants: epoch_key.participants().to_vec(),
            coefficient_commitments: commitments,
            commitment_trapdoor: *burn_commitment.trapdoor(),
            encryption_randomness: *burn_ciphertext.randomness(),
        },
    }
}

#[test]
#[ignore = "expensive real zkVM receipt; run explicitly for C1 evidence"]
fn proves_and_verifies_real_transfer_v2_receipt() -> Result<(), Box<dyn std::error::Error>> {
    assert!(std::env::var_os("RISC0_DEV_MODE").is_none());
    let claim = deterministic_claim();
    let native_journal = claim.validate().unwrap();
    let effects = TransferV2Effects::decode_canonical(&claim.canonical_effects)?;
    assert_eq!(
        native_journal.public_inputs_digest,
        *effects.public_inputs_digest().as_bytes()
    );

    let artifact = prove_transfer_v2(&claim)?;
    let verified = verify_transfer_v2(effects.public_inputs_digest(), &artifact.proof)?;
    assert_eq!(verified, native_journal);
    assert_eq!(artifact.journal, native_journal);

    let mut wrong_digest = effects.public_inputs_digest().into_bytes();
    wrong_digest[0] ^= 1;
    assert!(matches!(
        verify_transfer_v2(PublicInputDigest::new(wrong_digest), &artifact.proof),
        Err(ZkBackendError::PublicInputMismatch)
    ));

    if let Some(path) = std::env::var_os("VAULT_C1_RECEIPT_PATH") {
        std::fs::write(path, &artifact.proof)?;
    }

    println!("guest_id={}", encode_hex(&REVIEWED_REFERENCE_GUEST_ID));
    println!("public_inputs={}", effects.public_inputs_digest());
    println!("action_count={}", artifact.journal.action_count);
    println!("gas_fee={}", artifact.journal.gas_fee);
    println!("proof_bytes={}", artifact.metrics.proof_bytes);
    println!("elapsed_ms={}", artifact.metrics.elapsed_ms);
    println!("segments={}", artifact.metrics.segments);
    println!("total_cycles={}", artifact.metrics.total_cycles);
    println!("user_cycles={}", artifact.metrics.user_cycles);
    Ok(())
}

#[test]
#[ignore = "verify the explicitly supplied published C4 receipt vector"]
fn published_risc0_vector_verifies_offline_and_rejects_mutations()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(std::env::var_os("RISC0_DEV_MODE").is_none());
    let path = std::env::var_os("VAULT_C4_RECEIPT_VERIFY_PATH").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VAULT_C4_RECEIPT_VERIFY_PATH must name the published receipt",
        )
    })?;
    let mut proof = std::fs::read(path)?;
    assert_eq!(proof.len(), C4_RECEIPT_BYTES);
    let claim = deterministic_claim();
    let native_journal = claim.validate().unwrap();
    let effects = TransferV2Effects::decode_canonical(&claim.canonical_effects)?;
    assert_eq!(effects.public_inputs_digest().to_string(), C4_PUBLIC_INPUTS);
    assert_eq!(native_journal.action_count, 2);
    assert_eq!(native_journal.gas_fee, 26);

    let verified = verify_transfer_v2(effects.public_inputs_digest(), &proof)?;
    assert_eq!(verified, native_journal);

    let mut wrong_digest = effects.public_inputs_digest().into_bytes();
    wrong_digest[0] ^= 1;
    assert!(matches!(
        verify_transfer_v2(PublicInputDigest::new(wrong_digest), &proof),
        Err(ZkBackendError::PublicInputMismatch)
    ));

    let mutation_index = proof.len() / 2;
    proof[mutation_index] ^= 0x01;
    assert!(verify_transfer_v2(effects.public_inputs_digest(), &proof).is_err());
    proof[mutation_index] ^= 0x01;
    assert!(verify_transfer_v2(effects.public_inputs_digest(), &proof[..proof.len() - 1]).is_err());

    println!("guest_id={}", encode_hex(&REVIEWED_REFERENCE_GUEST_ID));
    println!("public_inputs={}", effects.public_inputs_digest());
    println!("proof_bytes={}", proof.len());
    Ok(())
}

#[test]
#[ignore = "expensive C6 Composite-to-Succinct compression; run only on declared CUDA hardware"]
fn compresses_published_composite_to_succinct_and_rejects_mutations()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(std::env::var_os("RISC0_DEV_MODE").is_none());
    let input_path = PathBuf::from(
        std::env::var_os("VAULT_C6_COMPOSITE_RECEIPT_PATH")
            .ok_or("VAULT_C6_COMPOSITE_RECEIPT_PATH must name the published C4 receipt")?,
    );
    let output_path = PathBuf::from(
        std::env::var_os("VAULT_C6_SUCCINCT_RECEIPT_PATH")
            .ok_or("VAULT_C6_SUCCINCT_RECEIPT_PATH must name a new output file")?,
    );
    assert!(input_path.is_absolute());
    assert!(output_path.is_absolute());
    assert!(
        !output_path.exists(),
        "refusing to overwrite output receipt"
    );

    let composite_bytes = std::fs::read(&input_path)?;
    assert_eq!(composite_bytes.len(), C4_RECEIPT_BYTES);
    let composite: Receipt = bincode::deserialize(&composite_bytes)?;
    assert!(matches!(&composite.inner, InnerReceipt::Composite(_)));
    composite.verify(REVIEWED_REFERENCE_GUEST_ID)?;

    let claim = deterministic_claim();
    let native_journal = claim.validate().unwrap();
    let effects = TransferV2Effects::decode_canonical(&claim.canonical_effects)?;
    let verified_composite = verify_transfer_v2(effects.public_inputs_digest(), &composite_bytes)?;
    assert_eq!(verified_composite, native_journal);

    let compression_started = Instant::now();
    let succinct = default_prover().compress(&ProverOpts::succinct(), &composite)?;
    let compression_elapsed_ms = compression_started.elapsed().as_millis();
    assert!(matches!(&succinct.inner, InnerReceipt::Succinct(_)));
    succinct.verify(REVIEWED_REFERENCE_GUEST_ID)?;
    assert_eq!(succinct.journal.bytes, composite.journal.bytes);

    let succinct_bytes = bincode::serialize(&succinct)?;
    let verified_succinct = verify_transfer_v2(effects.public_inputs_digest(), &succinct_bytes)?;
    assert_eq!(verified_succinct, native_journal);

    let mut wrong_digest = effects.public_inputs_digest().into_bytes();
    wrong_digest[0] ^= 1;
    assert!(matches!(
        verify_transfer_v2(PublicInputDigest::new(wrong_digest), &succinct_bytes),
        Err(ZkBackendError::PublicInputMismatch)
    ));
    let mut mutated = succinct_bytes.clone();
    let mutation_index = mutated.len() / 2;
    mutated[mutation_index] ^= 1;
    assert!(verify_transfer_v2(effects.public_inputs_digest(), &mutated).is_err());
    assert!(
        verify_transfer_v2(
            effects.public_inputs_digest(),
            &succinct_bytes[..succinct_bytes.len() - 1],
        )
        .is_err()
    );

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)?;
    output.write_all(&succinct_bytes)?;
    output.sync_all()?;
    drop(output);

    let reopened = std::fs::read(&output_path)?;
    assert_eq!(reopened, succinct_bytes);
    assert_eq!(
        verify_transfer_v2(effects.public_inputs_digest(), &reopened)?,
        native_journal
    );

    println!("guest_id={}", encode_hex(&REVIEWED_REFERENCE_GUEST_ID));
    println!("public_inputs={}", effects.public_inputs_digest());
    println!("input_receipt_kind=composite");
    println!("input_receipt_bytes={}", composite_bytes.len());
    println!("output_receipt_kind=succinct");
    println!("output_receipt_bytes={}", succinct_bytes.len());
    println!("compression_elapsed_ms={compression_elapsed_ms}");
    println!(
        "protocol_size_compatible={}",
        succinct_bytes.len() <= MAX_PROOF_BYTES
    );
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
