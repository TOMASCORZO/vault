//! H1-A1 target-validator workload across all selected transfer buckets.
//!
//! This executable is opt-in acceptance tooling. It dispatches committed
//! 2/4/8/16-Action proofs through their exact pinned verifier material in one
//! deterministic block workload; it is not called by transfer processing.

#[path = "../tests/support/mod.rs"]
mod support;

use std::{env, process, time::Instant};

use support::{VectorBundle, VerifierMaterial, conformance_fixture, effects_from_bytes};
use vault_burn::EpochBurnPublicKey;
use vault_protocol::TransferV2Effects;
use vault_zk_halo2_core::suite::VaultTransferSuite;

const COMMON_SEQUENCE: &[usize] = &[2, 2, 2, 2, 4, 4, 8, 16];
const BALANCED_SEQUENCE: &[usize] = &[2, 4, 8, 16];
const MAX_HEAVY_SEQUENCE: &[usize] = &[16, 16, 16, 8, 4, 2];

struct Config {
    profile: &'static str,
    samples: usize,
    block_size: usize,
}

impl Config {
    fn parse() -> Result<Self, &'static str> {
        let mut profile = "common";
        let mut samples = 5;
        let mut block_size = 32;
        let mut args = env::args().skip(1);
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--profile" => {
                    profile = match args.next().as_deref() {
                        Some("common") => "common",
                        Some("balanced") => "balanced",
                        Some("max-heavy") => "max-heavy",
                        _ => return Err("invalid --profile"),
                    };
                }
                "--samples" => {
                    samples = args
                        .next()
                        .ok_or("--samples requires a value")?
                        .parse()
                        .map_err(|_| "invalid --samples")?;
                }
                "--block-size" => {
                    block_size = args
                        .next()
                        .ok_or("--block-size requires a value")?
                        .parse()
                        .map_err(|_| "invalid --block-size")?;
                }
                _ => return Err("unknown argument"),
            }
        }
        let minimum_block_size = match profile {
            "common" => COMMON_SEQUENCE.len(),
            "balanced" => BALANCED_SEQUENCE.len(),
            "max-heavy" => MAX_HEAVY_SEQUENCE.len(),
            _ => unreachable!("profile validated during parsing"),
        };
        if samples == 0 || samples > 64 || block_size < minimum_block_size || block_size > 256 {
            return Err("sample or block-size outside the benchmark bounds");
        }
        Ok(Self {
            profile,
            samples,
            block_size,
        })
    }

    fn sequence(&self) -> &'static [usize] {
        match self.profile {
            "common" => COMMON_SEQUENCE,
            "balanced" => BALANCED_SEQUENCE,
            "max-heavy" => MAX_HEAVY_SEQUENCE,
            _ => unreachable!("profile validated during parsing"),
        }
    }
}

struct Case<const N: usize> {
    verifier: VerifierMaterial<N>,
    effects: TransferV2Effects,
    epoch_key: EpochBurnPublicKey,
    proof: Vec<u8>,
}

impl<const N: usize> Case<N> {
    fn build(vector_bytes: &[u8]) -> Self {
        let suite = VaultTransferSuite::for_action_count(N).unwrap();
        let bundle = VectorBundle::decode(vector_bytes).expect("committed H1-C3 vector");
        let fixture = conformance_fixture::<N>();
        let effects = effects_from_bytes(&bundle.effects);
        assert_eq!(bundle.suite_id, suite.circuit_id().into_bytes());
        assert_eq!(bundle.proof.len(), suite.proof_bytes());
        let verifier = VerifierMaterial::<N>::build();
        assert!(verifier.verify(&effects, &fixture.epoch_key, &bundle.proof));
        let mut malformed = bundle.proof.clone();
        malformed[bundle.proof_mutation_offset] ^= bundle.proof_mutation_xor;
        assert!(!verifier.verify(&effects, &fixture.epoch_key, &malformed));
        Self {
            verifier,
            effects,
            epoch_key: fixture.epoch_key,
            proof: bundle.proof,
        }
    }

    fn verify(&self) -> bool {
        self.verifier
            .verify(&self.effects, &self.epoch_key, &self.proof)
    }
}

struct Workload {
    two: Case<2>,
    four: Case<4>,
    eight: Case<8>,
    sixteen: Case<16>,
}

impl Workload {
    fn build() -> Self {
        Self {
            two: Case::build(include_bytes!("../vectors/transfer-v2/transfer-v2-2.bin")),
            four: Case::build(include_bytes!("../vectors/transfer-v2/transfer-v2-4.bin")),
            eight: Case::build(include_bytes!("../vectors/transfer-v2/transfer-v2-8.bin")),
            sixteen: Case::build(include_bytes!("../vectors/transfer-v2/transfer-v2-16.bin")),
        }
    }

    fn verify(&self, bucket: usize) -> bool {
        match bucket {
            2 => self.two.verify(),
            4 => self.four.verify(),
            8 => self.eight.verify(),
            16 => self.sixteen.verify(),
            _ => false,
        }
    }
}

fn print_timings(mut nanoseconds: Vec<u128>) {
    nanoseconds.sort_unstable();
    let minimum = nanoseconds[0] as f64 / 1_000_000.0;
    let median = nanoseconds[nanoseconds.len() / 2] as f64 / 1_000_000.0;
    let maximum = nanoseconds[nanoseconds.len() - 1] as f64 / 1_000_000.0;
    println!(
        "metric=heterogeneous_block_verify samples={} min_ms={minimum:.3} median_ms={median:.3} max_ms={maximum:.3}",
        nanoseconds.len()
    );
}

fn main() {
    let config = Config::parse().unwrap_or_else(|error| {
        eprintln!(
            "{error}; usage: h1_a1_heterogeneous_validator [--profile common|balanced|max-heavy] [--samples 1..64] [--block-size 1..256]"
        );
        process::exit(2);
    });
    println!(
        "h1_a1_heterogeneous_validator profile={} samples={} block_size={} sequence={:?} deterministic_wrap=true",
        config.profile,
        config.samples,
        config.block_size,
        config.sequence()
    );
    println!(
        "workload_kind=sequential_suite_dispatch source=committed_h1_c3_vectors measured_mainnet_distribution=false"
    );
    let started = Instant::now();
    let workload = Workload::build();
    println!(
        "metric=all_suite_verifier_startup samples=1 elapsed_ms={:.3}",
        started.elapsed().as_secs_f64() * 1_000.0
    );

    let mut counts = [0usize; 4];
    let mut timings = Vec::with_capacity(config.samples);
    for _ in 0..config.samples {
        let started = Instant::now();
        for index in 0..config.block_size {
            let bucket = config.sequence()[index % config.sequence().len()];
            assert!(workload.verify(bucket));
            counts[match bucket {
                2 => 0,
                4 => 1,
                8 => 2,
                16 => 3,
                _ => unreachable!(),
            }] += 1;
        }
        timings.push(started.elapsed().as_nanos());
    }
    println!(
        "verified_counts bucket_2={} bucket_4={} bucket_8={} bucket_16={}",
        counts[0], counts[1], counts[2], counts[3]
    );
    print_timings(timings);
}
