mod support;

use support::{
    VectorBundle, VerifierMaterial, conformance_fixture, effects_from_bytes, encode_instances,
    mutated_effects,
};
use vault_zk_halo2_core::suite::VaultTransferSuite;

fn verify_vector<const N: usize>(bytes: &[u8]) {
    let bundle = VectorBundle::decode(bytes).expect("canonical committed H1-C3 vector");
    let suite = VaultTransferSuite::for_action_count(N).unwrap();
    assert_eq!(bundle.action_count, u8::try_from(N).unwrap());
    assert_eq!(bundle.k, suite.k());
    assert_eq!(bundle.suite_id, suite.circuit_id().into_bytes());
    assert_eq!(bundle.proof_seed, [0x80 + u8::try_from(N).unwrap(); 32]);
    assert_eq!(bundle.proof.len(), suite.proof_bytes());
    assert_eq!(bundle.expected, [1, 0, 0]);
    assert_eq!(bundle.encode(), bytes);

    let fixture = conformance_fixture::<N>();
    assert_eq!(bundle.witness, fixture.witness);
    assert_eq!(bundle.effects, fixture.effects.encode_canonical());
    assert_eq!(bundle.instances, encode_instances(&fixture));
    assert_eq!(
        bundle.mutated_effects,
        mutated_effects(&fixture.effects).encode_canonical()
    );

    let effects = effects_from_bytes(&bundle.effects);
    let field_mutation = effects_from_bytes(&bundle.mutated_effects);
    let verifier = VerifierMaterial::<N>::build();
    assert!(verifier.verify(&effects, &fixture.epoch_key, &bundle.proof));
    assert!(!verifier.verify(&field_mutation, &fixture.epoch_key, &bundle.proof));

    let mut proof_mutation = bundle.proof.clone();
    proof_mutation[bundle.proof_mutation_offset] ^= bundle.proof_mutation_xor;
    assert!(!verifier.verify(&effects, &fixture.epoch_key, &proof_mutation));
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "real H1-C3 vector verification runs in the release-mode Halo2 gate"
)]
fn selected_transfer_vectors_accept_and_mutations_fail_closed() {
    verify_vector::<2>(include_bytes!("../vectors/transfer-v2/transfer-v2-2.bin"));
    verify_vector::<4>(include_bytes!("../vectors/transfer-v2/transfer-v2-4.bin"));
    verify_vector::<8>(include_bytes!("../vectors/transfer-v2/transfer-v2-8.bin"));
    verify_vector::<16>(include_bytes!("../vectors/transfer-v2/transfer-v2-16.bin"));
}

#[test]
fn vector_codec_rejects_truncation_trailing_bytes_and_section_mutation() {
    let vector = include_bytes!("../vectors/transfer-v2/transfer-v2-2.bin");
    for length in [0, 1, 4, 6, 7, vector.len() / 2, vector.len() - 1] {
        assert!(VectorBundle::decode(&vector[..length]).is_err());
    }
    let mut trailing = vector.to_vec();
    trailing.push(0);
    assert!(VectorBundle::decode(&trailing).is_err());

    let mut mutated = vector.to_vec();
    let last = mutated.len() - 1;
    mutated[last] ^= 1;
    assert!(VectorBundle::decode(&mutated).is_err());
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "real parameter and VK reconstruction runs in the release-mode Halo2 gate"
)]
fn parameter_loading_rebuilds_only_the_exact_selected_verifying_key() {
    let generated = VerifierMaterial::<2>::build();
    let parameter_bytes = generated.parameter_bytes();
    let fixture = conformance_fixture::<2>();
    let vector =
        VectorBundle::decode(include_bytes!("../vectors/transfer-v2/transfer-v2-2.bin")).unwrap();
    let effects = effects_from_bytes(&vector.effects);

    let rebuilt = VerifierMaterial::<2>::build_from_parameter_bytes(&parameter_bytes).unwrap();
    assert!(rebuilt.verify(&effects, &fixture.epoch_key, &vector.proof));

    let mut corrupted = parameter_bytes.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(VerifierMaterial::<2>::build_from_parameter_bytes(&corrupted).is_err());

    let mut extended = parameter_bytes.clone();
    extended.push(0);
    assert!(VerifierMaterial::<2>::build_from_parameter_bytes(&extended).is_err());
    assert!(VerifierMaterial::<16>::build_from_parameter_bytes(&parameter_bytes).is_err());
}
