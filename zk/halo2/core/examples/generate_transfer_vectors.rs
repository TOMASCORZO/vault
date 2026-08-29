#[path = "../tests/support/mod.rs"]
mod support;

use std::{env, fs, path::PathBuf};

use support::{VectorBundle, conformance_fixture, create_real_proof};

fn generate<const N: usize>(output: &std::path::Path) {
    let fixture = conformance_fixture::<N>();
    let seed = [0x80_u8.checked_add(u8::try_from(N).unwrap()).unwrap(); 32];
    let proof = create_real_proof(&fixture, seed);
    let bundle = VectorBundle::new(&fixture, seed, proof);
    let encoded = bundle.encode();
    let path = output.join(format!("transfer-v2-{N}.bin"));
    fs::write(&path, &encoded).unwrap();
    println!(
        "bucket={N} suite={} proof={} vector={} path={}",
        vault_zk_halo2_core::suite::VaultTransferSuite::for_action_count(N)
            .unwrap()
            .circuit_id(),
        bundle.proof.len(),
        encoded.len(),
        path.display()
    );
}

fn main() {
    let mut arguments = env::args_os().skip(1);
    let output = arguments.next().map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors/transfer-v2"),
        PathBuf::from,
    );
    assert!(
        arguments.next().is_none(),
        "usage: generate_transfer_vectors [OUTPUT_DIRECTORY]"
    );
    fs::create_dir_all(&output).unwrap();
    generate::<2>(&output);
    generate::<4>(&output);
    generate::<8>(&output);
    generate::<16>(&output);
}
