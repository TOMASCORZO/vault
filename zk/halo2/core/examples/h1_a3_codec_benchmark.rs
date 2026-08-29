use std::{env, hint::black_box, time::Instant};

use vault_signer::{DelegatedProvingRequest, SignerAuthorizationRequest};
use vault_zk_halo2_core::delegated_witness::DelegatedTransferWitness;

fn benchmark<const N: usize>(
    iterations: usize,
    witness: &[u8],
    delegated_request: &[u8],
    signer_request: &[u8],
) {
    let start = Instant::now();
    for _ in 0..iterations {
        let decoded = DelegatedTransferWitness::<N>::decode(black_box(witness)).unwrap();
        black_box(decoded.encode());
        let decoded = DelegatedProvingRequest::decode(black_box(delegated_request)).unwrap();
        black_box(decoded.encode());
        let decoded = SignerAuthorizationRequest::decode(black_box(signer_request)).unwrap();
        black_box(decoded.encode());
    }
    let elapsed = start.elapsed();
    println!(
        "bucket={N} iterations={iterations} witness_bytes={} delegated_request_bytes={} signer_request_bytes={} total_ms={:.3} us_per_iteration={:.3}",
        witness.len(),
        delegated_request.len(),
        signer_request.len(),
        elapsed.as_secs_f64() * 1_000.0,
        elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64,
    );
}

macro_rules! bucket {
    ($count:literal, $iterations:expr) => {
        benchmark::<$count>(
            $iterations,
            include_bytes!(concat!(
                "../../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
                stringify!($count),
                "/witness.vdpw"
            )),
            include_bytes!(concat!(
                "../../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
                stringify!($count),
                "/delegated-request.vdpr"
            )),
            include_bytes!(concat!(
                "../../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
                stringify!($count),
                "/sign-request.vsrq"
            )),
        );
    };
}

fn main() {
    let mut arguments = env::args().skip(1);
    let iterations = arguments
        .next()
        .map_or(Ok(100), |value| value.parse::<usize>())
        .expect("iterations must be an integer");
    assert!(
        (1..=10_000).contains(&iterations) && arguments.next().is_none(),
        "usage: h1_a3_codec_benchmark [iterations: 1..10000]"
    );
    bucket!(2, iterations);
    bucket!(4, iterations);
    bucket!(8, iterations);
    bucket!(16, iterations);
}
