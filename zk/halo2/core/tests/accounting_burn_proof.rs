use std::time::Instant;

use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::{Circuit, SingleVerifier, create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{
    group::{Group, GroupEncoding},
    pallas,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_burn::{EpochBurnPublicKey, PreparedBurnCiphertext};
use vault_privacy::PreparedBurnCommitment;
use vault_zk_halo2_core::{
    accounting::{AccountingActionWitness, PreparedAccountingArithmetic},
    burn_binding::{ACCOUNTING_BURN_K, PreparedAccountingBurn},
};

const MAXIMUM_AMOUNT: u64 = 21_000_000 * 1_000_000_000;

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "real proof evidence runs in the release-mode Halo2 CI gate"
)]
fn real_accounting_burn_proof_round_trip_is_fail_closed() {
    let arithmetic = PreparedAccountingArithmetic::new(
        [
            AccountingActionWitness::enabled(5_051, 5_000, true),
            AccountingActionWitness::dummy(),
        ],
        2,
        13,
    )
    .unwrap();
    let coefficients = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
    let commitments = coefficients.map(|value| (pallas::Point::generator() * value).to_bytes());
    let epoch_key =
        EpochBurnPublicKey::from_parts(9, 2, vec![1, 2, 3], commitments.to_vec()).unwrap();
    let mut commitment_rng = ChaCha20Rng::from_seed([0xC1; 32]);
    let commitment =
        PreparedBurnCommitment::create(25, MAXIMUM_AMOUNT, &mut commitment_rng).unwrap();
    let mut encryption_rng = ChaCha20Rng::from_seed([0xC2; 32]);
    let ciphertext =
        PreparedBurnCiphertext::encrypt(25, MAXIMUM_AMOUNT, &epoch_key, &mut encryption_rng)
            .unwrap();
    let prepared =
        PreparedAccountingBurn::new(arithmetic, &commitment, &ciphertext, &epoch_key).unwrap();
    let circuit = prepared.circuit();
    let empty_circuit = circuit.without_witnesses();
    let public = prepared.public_inputs();
    let public_columns = public.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let proof_instances = [&public_columns[..]];

    let started = Instant::now();
    let params: Params<EqAffine> = Params::new(ACCOUNTING_BURN_K);
    let vk = keygen_vk(&params, &empty_circuit).expect("accounting/burn verifying key");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("accounting/burn proving key");
    let keygen_elapsed = started.elapsed();

    let proving_started = Instant::now();
    let mut transcript = Blake2bWrite::<Vec<u8>, EqAffine, Challenge255<EqAffine>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &proof_instances,
        ChaCha20Rng::from_seed([0xC3; 32]),
        &mut transcript,
    )
    .expect("accounting/burn proof generation");
    let proof = transcript.finalize();
    let proving_elapsed = proving_started.elapsed();

    let verification_started = Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(&proof);
    verify_proof(
        &params,
        pk.get_vk(),
        strategy,
        &proof_instances,
        &mut transcript,
    )
    .expect("accounting/burn proof verification");
    let verification_elapsed = verification_started.elapsed();

    let mut tampered_proof = proof.clone();
    let middle = tampered_proof.len() / 2;
    tampered_proof[middle] ^= 1;
    let strategy = SingleVerifier::new(&params);
    let mut transcript =
        Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(&tampered_proof);
    assert!(
        verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &proof_instances,
            &mut transcript,
        )
        .is_err()
    );

    let mut wrong_public = public;
    wrong_public[0][6] += Fp::one();
    let wrong_columns = wrong_public.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let wrong_instances = [&wrong_columns[..]];
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(&proof);
    assert!(
        verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &wrong_instances,
            &mut transcript,
        )
        .is_err()
    );

    eprintln!(
        "accounting-burn keygen={keygen_elapsed:?} prove={proving_elapsed:?} verify={verification_elapsed:?} proof_bytes={}",
        proof.len()
    );
}
