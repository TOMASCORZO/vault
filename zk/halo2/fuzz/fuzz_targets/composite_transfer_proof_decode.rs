#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_zk_halo2_core::{ActionProof, CompositeTransferProof, TWO_ACTION_PROOF_BYTES};

const ACCOUNTING_SUITE: [u8; 32] = [0xa1; 32];
const OTHER_ACCOUNTING_SUITE: [u8; 32] = [0xa2; 32];

fn assert_decode_contract(bytes: &[u8], action_count: usize) {
    if let Ok(decoded) = CompositeTransferProof::decode(bytes, action_count, ACCOUNTING_SUITE) {
        assert_eq!(decoded.encode(), bytes);
        assert!(
            CompositeTransferProof::decode(bytes, action_count, OTHER_ACCOUNTING_SUITE).is_err()
        );
    }
}

fn structured_envelope(data: &[u8]) -> Vec<u8> {
    let action_proof = ActionProof::from_bytes(vec![0x72; TWO_ACTION_PROOF_BYTES], 2)
        .expect("the canonical two-Action proof length is fixed");
    let accounting_len = data.len().min(4_096).saturating_add(1);
    let mut accounting_proof = vec![0xb2; accounting_len];
    for (destination, source) in accounting_proof.iter_mut().zip(data) {
        *destination = *source;
    }
    CompositeTransferProof::new(2, ACCOUNTING_SUITE, action_proof, accounting_proof)
        .expect("the structured fuzz envelope stays inside protocol bounds")
        .encode()
}

fuzz_target!(|data: &[u8]| {
    for action_count in [2, 4, 8, 16] {
        assert_decode_contract(data, action_count);
        let _ = ActionProof::from_bytes(data.to_vec(), action_count);
    }

    // Always expose the fuzzer to a structurally valid deep path, even before
    // it discovers the complete magic, suite IDs, and canonical lengths in raw
    // input. Input triples select deterministic byte mutations across it.
    let mut structured = structured_envelope(data);
    for mutation in data.chunks_exact(3).take(64) {
        let offset = usize::from(u16::from_le_bytes([mutation[0], mutation[1]])) % structured.len();
        structured[offset] ^= mutation[2].max(1);
    }
    assert_decode_contract(&structured, 2);
});
