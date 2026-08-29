//! Exact, non-activating identities for the selected monolithic transfer suites.

use vault_protocol::CircuitId;

use crate::{
    ACTION_VERIFYING_KEY_ID,
    transfer_circuit::{VAULT_TRANSFER_K_2_TO_8, VAULT_TRANSFER_K_16},
};

const SUITE_ID_DOMAIN: &str = "vault.zk.halo2.transfer-v2.monolithic-suite.v1";
const TRANSFER_PROTOCOL_VERSION: u16 = 2;
const TRANSCRIPT_ID: &[u8] = b"halo2_proofs-0.3.5/Blake2b/Challenge255/EqAffine";
const INSTANCE_SCHEMA_ID: &[u8] = b"vault-transfer-v2-public-inputs-v1";

const PARAMETERS_K14: [u8; 32] = [
    0xa9, 0x41, 0x5b, 0x7c, 0x41, 0xb8, 0xe8, 0xab, 0x0a, 0x9b, 0x92, 0x19, 0xb4, 0x23, 0xd4, 0xef,
    0x09, 0x84, 0xda, 0x31, 0x30, 0xf4, 0x8b, 0x30, 0x72, 0x50, 0xcb, 0x9c, 0x94, 0xcf, 0xa2, 0x09,
];
const PARAMETERS_K15: [u8; 32] = [
    0x25, 0x0b, 0x53, 0x59, 0x7c, 0xb3, 0x42, 0xb5, 0x50, 0x93, 0x43, 0xb5, 0x03, 0x02, 0xd1, 0x7e,
    0x61, 0x35, 0x07, 0xba, 0xa8, 0xe3, 0x9c, 0x81, 0x8f, 0xa4, 0xaf, 0x25, 0x8c, 0xd8, 0x5a, 0x34,
];
const VERIFYING_KEY_2: [u8; 32] = [
    0x01, 0x82, 0x7a, 0xf9, 0x61, 0x0e, 0xfb, 0x6a, 0x76, 0x29, 0x24, 0x77, 0x29, 0x2d, 0xec, 0xa7,
    0x5f, 0x7a, 0x5d, 0x24, 0x80, 0xf1, 0x3f, 0x50, 0x2f, 0xb6, 0xec, 0x3f, 0x67, 0x7b, 0x2d, 0xf9,
];
const VERIFYING_KEY_4: [u8; 32] = [
    0x19, 0xda, 0x82, 0xd8, 0x08, 0x7f, 0x4e, 0x3f, 0xa2, 0xbc, 0xb9, 0x0d, 0x1e, 0xb1, 0x8b, 0xd5,
    0x03, 0xfb, 0xe9, 0x48, 0xa7, 0xa9, 0x12, 0x8e, 0xa2, 0x79, 0x23, 0x54, 0x02, 0x01, 0xf4, 0x3e,
];
const VERIFYING_KEY_8: [u8; 32] = [
    0xb8, 0xd1, 0xb7, 0xd0, 0x0b, 0x23, 0x7e, 0x1c, 0xa4, 0x64, 0x9f, 0x3f, 0xba, 0x4a, 0x63, 0xfd,
    0x2f, 0xe8, 0x00, 0x23, 0x08, 0xd8, 0x33, 0xf9, 0x58, 0x30, 0x97, 0x47, 0xaf, 0xf2, 0x45, 0x6e,
];
const VERIFYING_KEY_16: [u8; 32] = [
    0x23, 0xd1, 0x95, 0x3c, 0x70, 0xe9, 0x03, 0x19, 0x4e, 0x65, 0xa1, 0x9f, 0x6f, 0xd8, 0x0f, 0x5b,
    0xed, 0xdb, 0x54, 0x77, 0x07, 0x6e, 0x84, 0xdc, 0x04, 0xe2, 0x63, 0x51, 0x0e, 0xc2, 0x14, 0x0c,
];

/// Reproducible metadata for one canonical transfer-v2 Action bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultTransferSuite {
    action_count: u8,
    k: u32,
    proof_bytes: usize,
    parameter_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
}

impl VaultTransferSuite {
    /// Selects exactly one of transfer-v2's four padded Action buckets.
    #[must_use]
    pub const fn for_action_count(action_count: usize) -> Option<Self> {
        match action_count {
            2 => Some(Self::new(
                2,
                VAULT_TRANSFER_K_2_TO_8,
                9_600,
                PARAMETERS_K14,
                VERIFYING_KEY_2,
            )),
            4 => Some(Self::new(
                4,
                VAULT_TRANSFER_K_2_TO_8,
                9_600,
                PARAMETERS_K14,
                VERIFYING_KEY_4,
            )),
            8 => Some(Self::new(
                8,
                VAULT_TRANSFER_K_2_TO_8,
                9_600,
                PARAMETERS_K14,
                VERIFYING_KEY_8,
            )),
            16 => Some(Self::new(
                16,
                VAULT_TRANSFER_K_16,
                9_664,
                PARAMETERS_K15,
                VERIFYING_KEY_16,
            )),
            _ => None,
        }
    }

    const fn new(
        action_count: u8,
        k: u32,
        proof_bytes: usize,
        parameter_digest: [u8; 32],
        verifying_key_digest: [u8; 32],
    ) -> Self {
        Self {
            action_count,
            k,
            proof_bytes,
            parameter_digest,
            verifying_key_digest,
        }
    }

    /// Padded Action count whose circuit shape this suite identifies.
    #[must_use]
    pub const fn action_count(self) -> u8 {
        self.action_count
    }

    /// Halo2 evaluation-domain degree selected for this bucket.
    #[must_use]
    pub const fn k(self) -> u32 {
        self.k
    }

    /// Exact raw Blake2b transcript length accepted for this circuit shape.
    #[must_use]
    pub const fn proof_bytes(self) -> usize {
        self.proof_bytes
    }

    /// H1-C2 fingerprint of the canonical transparent parameters.
    #[must_use]
    pub const fn parameter_digest(self) -> [u8; 32] {
        self.parameter_digest
    }

    /// H1-C2 fingerprint of the exact pinned verifying-key representation.
    #[must_use]
    pub const fn verifying_key_digest(self) -> [u8; 32] {
        self.verifying_key_digest
    }

    /// Candidate circuit ID bound into H1-C3 effects and conformance vectors.
    ///
    /// Returning an ID here does not activate it. Consensus must still use a
    /// later reviewed allow-list and an exact verifier adapter.
    #[must_use]
    pub fn circuit_id(self) -> CircuitId {
        let mut hasher = blake3::Hasher::new_derive_key(SUITE_ID_DOMAIN);
        hasher.update(&TRANSFER_PROTOCOL_VERSION.to_le_bytes());
        hasher.update(&[self.action_count]);
        hasher.update(&self.k.to_le_bytes());
        hasher.update(&ACTION_VERIFYING_KEY_ID);
        hasher.update(&self.parameter_digest);
        hasher.update(&self.verifying_key_digest);
        hasher.update(&(TRANSCRIPT_ID.len() as u16).to_le_bytes());
        hasher.update(TRANSCRIPT_ID);
        hasher.update(&(INSTANCE_SCHEMA_ID.len() as u16).to_le_bytes());
        hasher.update(INSTANCE_SCHEMA_ID);
        CircuitId::new(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_canonical_buckets_receive_distinct_nonzero_suite_ids() {
        let suites =
            [2, 4, 8, 16].map(|count| VaultTransferSuite::for_action_count(count).unwrap());
        for (index, suite) in suites.iter().enumerate() {
            assert!(!suite.circuit_id().is_zero());
            assert_eq!(usize::from(suite.action_count()), [2, 4, 8, 16][index]);
        }
        for first in 0..suites.len() {
            for second in first + 1..suites.len() {
                assert_ne!(suites[first].circuit_id(), suites[second].circuit_id());
            }
        }
        for unsupported in [0, 1, 3, 15, 17, usize::MAX] {
            assert!(VaultTransferSuite::for_action_count(unsupported).is_none());
        }
    }
}
