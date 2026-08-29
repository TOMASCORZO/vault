//! Explicit H1-A1 benchmark harness for the selected transfer-v2 Halo2 suites.
//!
//! This executable is intentionally excluded from normal gates and transfer
//! processing. It measures one bucket per process so an external timing tool
//! can capture a meaningful process peak-RSS value.

#[path = "../tests/support/mod.rs"]
mod support;

use std::{env, process, time::Instant};

use support::{
    ProverMaterial, VectorBundle, VerifierMaterial, conformance_fixture, effects_from_bytes,
};
use vault_zk_halo2_core::suite::VaultTransferSuite;

#[derive(Clone, Copy)]
struct Config {
    bucket: usize,
    samples: usize,
    batch_size: usize,
    prove: bool,
}

impl Config {
    fn parse() -> Result<Self, &'static str> {
        let mut config = Self {
            bucket: 2,
            samples: 5,
            batch_size: 8,
            prove: false,
        };
        let mut args = env::args().skip(1);
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--bucket" => {
                    config.bucket = args
                        .next()
                        .ok_or("--bucket requires a value")?
                        .parse()
                        .map_err(|_| "invalid --bucket")?;
                }
                "--samples" => {
                    config.samples = args
                        .next()
                        .ok_or("--samples requires a value")?
                        .parse()
                        .map_err(|_| "invalid --samples")?;
                }
                "--batch-size" => {
                    config.batch_size = args
                        .next()
                        .ok_or("--batch-size requires a value")?
                        .parse()
                        .map_err(|_| "invalid --batch-size")?;
                }
                "--prove" => config.prove = true,
                _ => return Err("unknown argument"),
            }
        }
        if ![2, 4, 8, 16].contains(&config.bucket)
            || config.samples == 0
            || config.samples > 64
            || config.batch_size == 0
            || config.batch_size > 256
        {
            return Err("bucket, sample, or batch-size outside the benchmark bounds");
        }
        Ok(config)
    }
}

fn print_timings(label: &str, mut nanoseconds: Vec<u128>) {
    nanoseconds.sort_unstable();
    let minimum = nanoseconds[0] as f64 / 1_000_000.0;
    let median = nanoseconds[nanoseconds.len() / 2] as f64 / 1_000_000.0;
    let maximum = nanoseconds[nanoseconds.len() - 1] as f64 / 1_000_000.0;
    println!(
        "metric={label} samples={} min_ms={minimum:.3} median_ms={median:.3} max_ms={maximum:.3}",
        nanoseconds.len()
    );
}

fn run<const N: usize>(config: Config, vector_bytes: &[u8]) {
    let suite = VaultTransferSuite::for_action_count(N).unwrap();
    let bundle = VectorBundle::decode(vector_bytes).expect("committed H1-C3 vector");
    let fixture = conformance_fixture::<N>();
    let effects = effects_from_bytes(&bundle.effects);
    assert_eq!(config.bucket, N);
    assert_eq!(bundle.suite_id, suite.circuit_id().into_bytes());
    assert_eq!(bundle.proof.len(), suite.proof_bytes());

    println!(
        "h1_a1_halo2 bucket={N} k={} suite={} proof_bytes={} samples={} batch_size={} prove={}",
        suite.k(),
        suite.circuit_id(),
        bundle.proof.len(),
        config.samples,
        config.batch_size,
        config.prove
    );
    println!(
        "startup_strategy=deterministic_in_memory_pk_vk_reconstruction persistent_pk_vk=disabled canonical_identity=parameter_and_pinned_vk_fingerprints batch_workload=repeated_committed_vector"
    );

    let started = Instant::now();
    let generated = VerifierMaterial::<N>::build();
    println!(
        "metric=generated_parameter_vk_startup samples=1 elapsed_ms={:.3}",
        started.elapsed().as_secs_f64() * 1_000.0
    );
    let parameter_bytes = generated.parameter_bytes();
    println!("parameter_bytes={}", parameter_bytes.len());
    drop(generated);

    let started = Instant::now();
    let verifier = VerifierMaterial::<N>::build_from_parameter_bytes(&parameter_bytes)
        .expect("canonical serialized parameters rebuild the selected VK");
    println!(
        "metric=parameter_load_vk_rebuild_startup samples=1 elapsed_ms={:.3}",
        started.elapsed().as_secs_f64() * 1_000.0
    );
    assert!(verifier.verify(&effects, &fixture.epoch_key, &bundle.proof));

    let mut standalone = Vec::with_capacity(config.samples);
    for _ in 0..config.samples {
        let started = Instant::now();
        assert!(verifier.verify(&effects, &fixture.epoch_key, &bundle.proof));
        standalone.push(started.elapsed().as_nanos());
    }
    print_timings("standalone_verify", standalone);

    let mut batch = Vec::with_capacity(config.samples);
    for _ in 0..config.samples {
        let started = Instant::now();
        assert!(verifier.verify_batch(
            &effects,
            &fixture.epoch_key,
            &bundle.proof,
            config.batch_size
        ));
        batch.push(started.elapsed().as_nanos());
    }
    print_timings("batch_verify", batch);

    let mut malformed = bundle.proof.clone();
    malformed[bundle.proof_mutation_offset] ^= bundle.proof_mutation_xor;
    assert!(!verifier.verify(&effects, &fixture.epoch_key, &malformed));
    assert!(!verifier.verify_batch(&effects, &fixture.epoch_key, &malformed, config.batch_size));

    if config.prove {
        let started = Instant::now();
        let prover = ProverMaterial::<N>::build();
        println!(
            "metric=reusable_prover_material_build samples=1 elapsed_ms={:.3}",
            started.elapsed().as_secs_f64() * 1_000.0
        );
        let mut proving = Vec::with_capacity(config.samples);
        for sample in 0..config.samples {
            let seed_byte = 0xd0_u8
                .checked_add(u8::try_from(sample).unwrap())
                .expect("sample count is bounded");
            let started = Instant::now();
            let proof = prover.prove(&fixture, [seed_byte; 32]);
            proving.push(started.elapsed().as_nanos());
            assert_eq!(proof.len(), suite.proof_bytes());
            assert!(verifier.verify(&effects, &fixture.epoch_key, &proof));
        }
        print_timings("prove_plus_immediate_self_verify", proving);
    }
}

fn main() {
    let config = Config::parse().unwrap_or_else(|error| {
        eprintln!(
            "{error}; usage: h1_a1_benchmark [--bucket 2|4|8|16] [--samples 1..64] [--batch-size 1..256] [--prove]"
        );
        process::exit(2);
    });
    match config.bucket {
        2 => run::<2>(
            config,
            include_bytes!("../vectors/transfer-v2/transfer-v2-2.bin"),
        ),
        4 => run::<4>(
            config,
            include_bytes!("../vectors/transfer-v2/transfer-v2-4.bin"),
        ),
        8 => run::<8>(
            config,
            include_bytes!("../vectors/transfer-v2/transfer-v2-8.bin"),
        ),
        16 => run::<16>(
            config,
            include_bytes!("../vectors/transfer-v2/transfer-v2-16.bin"),
        ),
        _ => unreachable!(),
    }
}
