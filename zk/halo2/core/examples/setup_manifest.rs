//! Reproduces the selected Halo2 parameter and candidate verifying-key digests.
//!
//! This is setup tooling, not an activation mechanism. Candidate transfer VKs
//! remain ineligible for consensus until their exact digests are frozen by the
//! H1 conformance-vector and review gates.

use std::fmt::Write as _;

use blake3::Hasher;
use halo2_proofs::{pasta::EqAffine, plonk::keygen_vk, poly::commitment::Params};
use vault_zk_halo2_core::suite::VaultTransferSuite;
use vault_zk_halo2_core::transfer_circuit::{
    VAULT_TRANSFER_K_2_TO_8, VAULT_TRANSFER_K_16, VaultTransferCircuit, vault_transfer_k,
};

const ACTION_K: u32 = 11;
const PARAMETER_DIGEST_CONTEXT: &str = "vault.zk.halo2.parameters.v1";
const VERIFYING_KEY_DIGEST_CONTEXT: &str = "vault.zk.halo2.verifying-key.v1";

fn digest(context: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(context);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parameter_record(k: u32) -> Params<EqAffine> {
    let params = Params::new(k);
    let mut bytes = Vec::new();
    params
        .write(&mut bytes)
        .expect("serializing generated Halo2 parameters into memory cannot fail");
    println!(
        "parameters k={k} bytes={} blake3={}",
        bytes.len(),
        hex(&digest(PARAMETER_DIGEST_CONTEXT, &bytes))
    );
    params
}

fn verifying_key_record<const N: usize>(params: &Params<EqAffine>) {
    let suite = VaultTransferSuite::for_action_count(N)
        .expect("the manifest contains only canonical transfer-v2 buckets");
    assert_eq!(
        Some(params.k()),
        vault_transfer_k(N),
        "manifest parameter does not match the selected bucket degree"
    );
    let circuit = VaultTransferCircuit::<N>::empty()
        .expect("the manifest contains only canonical transfer-v2 buckets");
    let vk = keygen_vk(params, &circuit).expect("candidate Vault transfer verifying key");
    let pinned = format!("{:?}", vk.pinned());
    let verifying_key_digest = digest(VERIFYING_KEY_DIGEST_CONTEXT, pinned.as_bytes());
    let mut parameter_bytes = Vec::new();
    params.write(&mut parameter_bytes).unwrap();
    assert_eq!(
        digest(PARAMETER_DIGEST_CONTEXT, &parameter_bytes),
        suite.parameter_digest()
    );
    assert_eq!(verifying_key_digest, suite.verifying_key_digest());
    println!(
        "transfer-v2 bucket={N} k={} pinned-bytes={} blake3={} suite={} proof-bytes={}",
        params.k(),
        pinned.len(),
        hex(&verifying_key_digest),
        suite.circuit_id(),
        suite.proof_bytes(),
    );
}

fn main() {
    let mut contexts = String::new();
    writeln!(
        contexts,
        "parameter-digest-context={PARAMETER_DIGEST_CONTEXT}"
    )
    .expect("writing to a string cannot fail");
    writeln!(
        contexts,
        "verifying-key-digest-context={VERIFYING_KEY_DIGEST_CONTEXT}"
    )
    .expect("writing to a string cannot fail");
    print!("{contexts}");

    let _action_params = parameter_record(ACTION_K);
    let standard_transfer_params = parameter_record(VAULT_TRANSFER_K_2_TO_8);
    let maximum_transfer_params = parameter_record(VAULT_TRANSFER_K_16);
    verifying_key_record::<2>(&standard_transfer_params);
    verifying_key_record::<4>(&standard_transfer_params);
    verifying_key_record::<8>(&standard_transfer_params);
    verifying_key_record::<16>(&maximum_transfer_params);
}
