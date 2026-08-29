#[path = "../tests/support/mod.rs"]
mod support;

use std::{fs, path::Path};

use support::{VectorBundle, vector_section_digest};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/transfer-v2");
    for action_count in [2, 4, 8, 16] {
        let path = directory.join(format!("transfer-v2-{action_count}.bin"));
        let bytes = fs::read(&path).unwrap();
        let bundle = VectorBundle::decode(&bytes).unwrap();
        println!(
            "bucket={} k={} suite={} proof_bytes={} proof_digest={} witness_digest={} effects_digest={} instances_digest={} vector_bytes={}",
            bundle.action_count,
            bundle.k,
            hex(&bundle.suite_id),
            bundle.proof.len(),
            hex(&vector_section_digest(b"proof", &bundle.proof)),
            hex(&vector_section_digest(b"witness", &bundle.witness)),
            hex(&vector_section_digest(b"effects", &bundle.effects)),
            hex(&vector_section_digest(b"instances", &bundle.instances)),
            bytes.len(),
        );
    }
}
