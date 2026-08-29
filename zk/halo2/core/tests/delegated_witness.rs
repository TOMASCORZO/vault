mod support;

use vault_zk_halo2_core::delegated_witness::{
    DELEGATED_TRANSFER_WITNESS_MAX_BYTES, DelegatedTransferWitness,
};

use support::{delegated_conformance_fixture, mutated_effects};

fn assert_round_trip_and_reconstruction<const N: usize>() {
    let fixture = delegated_conformance_fixture::<N>();
    let witness = fixture.delegated_witness.as_deref().unwrap();
    assert!(witness.len() <= DELEGATED_TRANSFER_WITNESS_MAX_BYTES);

    let decoded = DelegatedTransferWitness::<N>::decode(witness).unwrap();
    assert_eq!(decoded.encode().as_slice(), witness);
    assert_eq!(decoded.encoded_len(), witness.len());

    let reconstructed = decoded.prepare(&fixture.effects).unwrap();
    assert_eq!(
        reconstructed.public_inputs(),
        fixture.prepared.public_inputs()
    );
}

#[test]
fn every_transfer_bucket_round_trips_and_reconstructs_exactly() {
    assert_round_trip_and_reconstruction::<2>();
    assert_round_trip_and_reconstruction::<4>();
    assert_round_trip_and_reconstruction::<8>();
    assert_round_trip_and_reconstruction::<16>();
}

macro_rules! assert_committed_witness {
    ($count:literal) => {{
        let fixture = delegated_conformance_fixture::<$count>();
        let committed = include_bytes!(concat!(
            "../../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
            stringify!($count),
            "/witness.vdpw"
        ));
        assert_eq!(fixture.delegated_witness.as_deref().unwrap(), committed);
    }};
}

#[test]
fn committed_witness_corpus_is_byte_exact() {
    assert_committed_witness!(2);
    assert_committed_witness!(4);
    assert_committed_witness!(8);
    assert_committed_witness!(16);
}

#[test]
fn parser_rejects_headers_counts_truncation_trailing_and_nested_packets() {
    let fixture = delegated_conformance_fixture::<2>();
    let original = fixture.delegated_witness.as_deref().unwrap();

    for offset in [0, 4, 6, 7] {
        let mut mutation = original.to_vec();
        mutation[offset] ^= 1;
        assert!(DelegatedTransferWitness::<2>::decode(&mutation).is_err());
    }
    for length in [0, 1, 207, original.len() - 1] {
        assert!(DelegatedTransferWitness::<2>::decode(&original[..length]).is_err());
    }
    let mut trailing = original.to_vec();
    trailing.push(0);
    assert!(DelegatedTransferWitness::<2>::decode(&trailing).is_err());

    // Header (208) + note (115) + path (1,028) + two private scalars (64).
    let output_packet_magic = 208 + 115 + 1_028 + 64;
    let mut nested = original.to_vec();
    nested[output_packet_magic] ^= 1;
    assert!(DelegatedTransferWitness::<2>::decode(&nested).is_err());

    // The epoch participant count follows all fixed action witnesses.
    let participant_count = 208 + 2 * 2_662 + 8 + 2;
    let mut invalid_epoch = original.to_vec();
    invalid_epoch[participant_count..participant_count + 2].copy_from_slice(&0_u16.to_le_bytes());
    assert!(DelegatedTransferWitness::<2>::decode(&invalid_epoch).is_err());
}

#[test]
fn reconstruction_rejects_wrong_effects_and_private_openings() {
    let fixture = delegated_conformance_fixture::<2>();
    let witness = fixture.delegated_witness.as_deref().unwrap();
    let decoded = DelegatedTransferWitness::<2>::decode(witness).unwrap();
    assert!(decoded.prepare(&mutated_effects(&fixture.effects)).is_err());

    let mut wrong_burn_opening = witness.to_vec();
    let last = wrong_burn_opening.len() - 1;
    wrong_burn_opening[last] ^= 1;
    let decoded = DelegatedTransferWitness::<2>::decode(&wrong_burn_opening).unwrap();
    assert!(decoded.prepare(&fixture.effects).is_err());
}

#[test]
fn bounded_mutation_smoke_never_panics() {
    let fixture = delegated_conformance_fixture::<2>();
    let original = fixture.delegated_witness.as_deref().unwrap();
    for iteration in 0..512_usize {
        let mut mutation = original.to_vec();
        let offset = iteration.wrapping_mul(2_654_435_761) % mutation.len();
        mutation[offset] ^= 1_u8 << (iteration % 8);
        let result = std::panic::catch_unwind(|| DelegatedTransferWitness::<2>::decode(&mutation));
        assert!(result.is_ok());
    }

    let oversized = vec![0_u8; DELEGATED_TRANSFER_WITNESS_MAX_BYTES + 1];
    assert!(DelegatedTransferWitness::<2>::decode(&oversized).is_err());
}
