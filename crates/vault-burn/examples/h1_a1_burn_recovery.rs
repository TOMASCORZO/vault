//! Explicit H1-A1 resource harness for bounded aggregate-burn recovery.
//!
//! The benchmark requires the non-default `reference-oracle` feature and is
//! never part of transfer construction, verification, or normal test gates.

#[cfg(feature = "reference-oracle")]
use std::{
    env,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    mem,
    path::PathBuf,
    process,
    time::{Duration, Instant},
};

#[cfg(feature = "reference-oracle")]
use vault_burn::{BoundedBurnRecovery, MAX_EPOCH_BURN_ATOMIC};

#[cfg(feature = "reference-oracle")]
#[derive(Clone)]
struct Config {
    maximum: u64,
    amount: u64,
    samples: usize,
    cache: Option<PathBuf>,
}

#[cfg(feature = "reference-oracle")]
impl Config {
    fn parse() -> Result<Self, &'static str> {
        let mut maximum = None;
        let mut amount = None;
        let mut samples = 3_usize;
        let mut cache = None;
        let mut arguments = env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--maximum" => {
                    maximum = Some(
                        arguments
                            .next()
                            .ok_or("--maximum requires a value")?
                            .parse()
                            .map_err(|_| "invalid --maximum")?,
                    );
                }
                "--amount" => {
                    amount = Some(
                        arguments
                            .next()
                            .ok_or("--amount requires a value")?
                            .parse()
                            .map_err(|_| "invalid --amount")?,
                    );
                }
                "--samples" => {
                    samples = arguments
                        .next()
                        .ok_or("--samples requires a value")?
                        .parse()
                        .map_err(|_| "invalid --samples")?;
                }
                "--cache" => {
                    cache = Some(PathBuf::from(
                        arguments.next().ok_or("--cache requires a path")?,
                    ));
                }
                _ => return Err("unknown argument"),
            }
        }
        let maximum = maximum.ok_or("--maximum is required")?;
        let amount = amount.unwrap_or(maximum);
        if maximum > MAX_EPOCH_BURN_ATOMIC || amount > maximum || samples == 0 || samples > 64 {
            return Err("benchmark value outside the H1-A1 bounds");
        }
        Ok(Self {
            maximum,
            amount,
            samples,
            cache,
        })
    }
}

#[cfg(feature = "reference-oracle")]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(feature = "reference-oracle")]
fn build_recovery(config: &Config) -> (BoundedBurnRecovery, Duration) {
    let Some(cache_path) = &config.cache else {
        let started = Instant::now();
        let recovery = BoundedBurnRecovery::new(config.maximum).unwrap_or_else(|error| {
            eprintln!("recovery table construction failed: {error}");
            process::exit(1);
        });
        return (recovery, started.elapsed());
    };

    let cache_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(cache_path)
        .unwrap_or_else(|error| {
            eprintln!("refusing to create recovery cache: {error}");
            process::exit(1);
        });
    let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, cache_file);
    let started = Instant::now();
    let (built, digest) =
        BoundedBurnRecovery::build_with_canonical_cache(config.maximum, &mut writer)
            .unwrap_or_else(|error| {
                eprintln!("recovery cache construction failed: {error}");
                process::exit(1);
            });
    writer.flush().unwrap_or_else(|error| {
        eprintln!("recovery cache flush failed: {error}");
        process::exit(1);
    });
    let cache_file = writer.into_inner().unwrap_or_else(|error| {
        eprintln!("recovery cache finalization failed: {}", error.error());
        process::exit(1);
    });
    cache_file.sync_all().unwrap_or_else(|error| {
        eprintln!("recovery cache sync failed: {error}");
        process::exit(1);
    });
    let build = started.elapsed();
    let cache_bytes = cache_file.metadata().unwrap().len();
    assert_eq!(cache_bytes, built.canonical_cache_len().unwrap());
    println!(
        "metric=cache_build path={} cache_bytes={} digest={} elapsed_ms={:.3}",
        cache_path.display(),
        cache_bytes,
        hex(&digest),
        build.as_secs_f64() * 1_000.0
    );
    drop(cache_file);
    drop(built);

    let started = Instant::now();
    let cache_file = File::open(cache_path).unwrap_or_else(|error| {
        eprintln!("recovery cache reopen failed: {error}");
        process::exit(1);
    });
    let reader = BufReader::with_capacity(4 * 1024 * 1024, cache_file);
    let recovery = BoundedBurnRecovery::from_canonical_cache(config.maximum, digest, reader)
        .unwrap_or_else(|error| {
            eprintln!("recovery cache validation failed: {error}");
            process::exit(1);
        });
    println!(
        "metric=cache_restart path={} cache_bytes={} digest={} elapsed_ms={:.3}",
        cache_path.display(),
        cache_bytes,
        hex(&digest),
        started.elapsed().as_secs_f64() * 1_000.0
    );
    (recovery, build)
}

#[cfg(feature = "reference-oracle")]
fn main() {
    let config = Config::parse().unwrap_or_else(|error| {
        eprintln!(
            "{error}; usage: h1_a1_burn_recovery --maximum N [--amount N] [--samples 1..64] [--cache NEW_PATH]"
        );
        process::exit(2);
    });

    let (recovery, build) = build_recovery(&config);
    let entry_payload_bytes = mem::size_of::<([u8; 32], u64)>();
    let payload_lower_bound = u128::from(recovery.step_size())
        * u128::try_from(entry_payload_bytes).expect("entry payload size fits u128");
    println!(
        "h1_a1_burn_recovery maximum={} amount={} step_size={} samples={} entry_payload_bytes={} payload_lower_bound_bytes={} build_ms={:.3}",
        config.maximum,
        config.amount,
        recovery.step_size(),
        config.samples,
        entry_payload_bytes,
        payload_lower_bound,
        build.as_secs_f64() * 1_000.0
    );

    let mut recoveries = Vec::with_capacity(config.samples);
    for _ in 0..config.samples {
        let started = Instant::now();
        let recovered = recovery
            .recover_known_amount_for_benchmark(config.amount)
            .expect("known in-range benchmark amount must recover");
        assert_eq!(recovered, config.amount);
        recoveries.push(started.elapsed().as_nanos());
    }
    recoveries.sort_unstable();
    println!(
        "metric=recover samples={} min_ms={:.3} median_ms={:.3} max_ms={:.3}",
        recoveries.len(),
        recoveries[0] as f64 / 1_000_000.0,
        recoveries[recoveries.len() / 2] as f64 / 1_000_000.0,
        recoveries[recoveries.len() - 1] as f64 / 1_000_000.0,
    );
}

#[cfg(not(feature = "reference-oracle"))]
fn main() {
    eprintln!("h1_a1_burn_recovery requires --features reference-oracle");
    std::process::exit(2);
}
