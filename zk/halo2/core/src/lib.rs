//! Pinned production-intent Halo2 Action proof layer for Vault transfer-v2.
//!
//! This crate proves the Ironwood action statement: ownership, note opening,
//! Merkle membership, nullifier derivation, randomized spend key, paired output
//! opening, dummy enable rules, and the net value commitment. Its consensus
//! adapter can only be constructed with the mandatory accounting, burn, and
//! ciphertext verifier; the core Action proof alone cannot authorize state
//! mutation.

use orchard::{
    Proof,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use vault_privacy::{PrivacyError, circuit::PreparedActionCircuit};
use vault_protocol::{
    CircuitId, MAX_PROOF_BYTES, ProofVerificationError, TransferV2Effects, TransferV2ProofVerifier,
};

pub mod accounting;
pub mod burn_binding;
pub mod delegated_witness;
pub mod suite;
pub mod transfer_circuit;

const COMPOSITE_CIRCUIT_ID_DOMAIN: &str =
    "vault.zk.halo2.transfer-v2.composite-circuit-id.2026-08-22";
const COMPOSITE_MAGIC: [u8; 4] = *b"VZK2";
const COMPOSITE_VERSION: u16 = 1;
const COMPOSITE_HEADER_BYTES: usize = 4 + 2 + 32 + 32 + 1 + 4 + 4;

/// SHA-256 of Orchard 0.15.5's canonical pinned `PostNu6_3` verifying-key
/// description (`src/circuit_data/circuit_description_post_nu6_3`).
///
/// This identifies the exact circuit shape and fixed columns; it is not a
/// human-selected version label.
pub const ACTION_VERIFYING_KEY_ID: [u8; 32] = [
    0x8d, 0x32, 0x5e, 0xe6, 0x75, 0x3c, 0x8e, 0xff, 0xb7, 0xd5, 0x18, 0x4b, 0xdd, 0x72, 0x92, 0x55,
    0xd2, 0x69, 0x7d, 0xd1, 0x73, 0x0c, 0x02, 0x78, 0x08, 0x4c, 0xd9, 0x11, 0x92, 0x02, 0x0e, 0x90,
];

/// Canonical Halo2 proof bytes for two actions.
pub const TWO_ACTION_PROOF_BYTES: usize = 7_264;

/// Errors kept detailed for prover tooling and mapped to one opaque consensus
/// rejection by the future composite verifier.
#[derive(Debug, Error)]
pub enum ActionProofError {
    /// No circuits were supplied or the count differs from the public actions.
    #[error("private circuit count does not match public action count")]
    ActionCountMismatch,
    /// The action count is outside transfer-v2's padded buckets.
    #[error("unsupported transfer-v2 action count")]
    UnsupportedActionCount,
    /// A public action cannot be converted to the pinned circuit instance.
    #[error("invalid public action instance: {0}")]
    InvalidInstance(PrivacyError),
    /// Proof length is not canonical for this action count.
    #[error("non-canonical Halo2 proof length: expected {expected}, got {actual}")]
    NonCanonicalProofLength {
        /// Required byte length.
        expected: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// Halo2 rejected proving or verification.
    #[error("Halo2 action proof failed")]
    Halo2,
    /// The composite proof envelope is malformed or uses another suite.
    #[error("invalid composite transfer proof")]
    InvalidCompositeProof,
}

/// Opaque rejection from the mandatory accounting and burn proof layer.
#[derive(Clone, Copy, Debug, Error)]
#[error("accounting and burn proof verification failed")]
pub struct AccountingProofError;

/// Required second proof layer for Vault-specific private accounting.
///
/// A conforming implementation must verify exact conservation, public gas,
/// proof-derived recipient/change classification, the ceiling 0.5% burn,
/// output value bindings, and equality between the committed and encrypted
/// burn plaintext. This crate intentionally ships no permissive implementation.
pub trait AccountingProofVerifier: Send + Sync {
    /// Digest of the exact accounting circuit and burn-encryption parameters.
    fn suite_id(&self) -> [u8; 32];

    /// Verifies all Vault-specific statements against the complete effects.
    fn verify(&self, effects: &TransferV2Effects, proof: &[u8])
    -> Result<(), AccountingProofError>;
}

/// Reusable proving key for the exact hardened circuit.
#[derive(Debug)]
pub struct ActionProvingKey {
    proving: ProvingKey,
    verifying: VerifyingKey,
}

impl ActionProvingKey {
    /// Deterministically derives the proving key from the pinned circuit.
    #[must_use]
    pub fn build() -> Self {
        Self {
            proving: ProvingKey::build(OrchardCircuitVersion::PostNu6_3),
            verifying: VerifyingKey::build(OrchardCircuitVersion::PostNu6_3),
        }
    }
}

/// Reusable verifying key for the exact hardened circuit.
#[derive(Debug)]
pub struct ActionVerifyingKey(VerifyingKey);

impl ActionVerifyingKey {
    /// Deterministically derives the verifying key from the pinned circuit.
    #[must_use]
    pub fn build() -> Self {
        Self(VerifyingKey::build(OrchardCircuitVersion::PostNu6_3))
    }
}

/// Canonically-sized aggregated proof over every padded action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionProof(Vec<u8>);

impl ActionProof {
    /// Parses a proof only after checking its exact action-count-dependent size.
    pub fn from_bytes(bytes: Vec<u8>, action_count: usize) -> Result<Self, ActionProofError> {
        validate_action_count(action_count)?;
        let expected = Proof::expected_proof_size(action_count);
        if bytes.len() != expected {
            return Err(ActionProofError::NonCanonicalProofLength {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Exact Halo2 transcript bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the typed proof for a future composite proof envelope.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Canonical two-layer proof payload carried by transfer-v2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeTransferProof {
    action_count: u8,
    accounting_suite_id: [u8; 32],
    action_proof: ActionProof,
    accounting_proof: Vec<u8>,
}

impl CompositeTransferProof {
    /// Creates the only proof envelope eligible for the composite verifier.
    pub fn new(
        action_count: usize,
        accounting_suite_id: [u8; 32],
        action_proof: ActionProof,
        accounting_proof: Vec<u8>,
    ) -> Result<Self, ActionProofError> {
        validate_action_count(action_count)?;
        if accounting_suite_id == [0; 32] || accounting_proof.is_empty() {
            return Err(ActionProofError::InvalidCompositeProof);
        }
        let action_count =
            u8::try_from(action_count).map_err(|_| ActionProofError::InvalidCompositeProof)?;
        let proof = Self {
            action_count,
            accounting_suite_id,
            action_proof,
            accounting_proof,
        };
        if proof.encoded_len() > MAX_PROOF_BYTES {
            return Err(ActionProofError::InvalidCompositeProof);
        }
        Ok(proof)
    }

    /// Parses one exact, non-extensible encoding and rejects trailing bytes.
    pub fn decode(
        bytes: &[u8],
        expected_action_count: usize,
        expected_accounting_suite_id: [u8; 32],
    ) -> Result<Self, ActionProofError> {
        validate_action_count(expected_action_count)?;
        if bytes.len() < COMPOSITE_HEADER_BYTES || bytes.len() > MAX_PROOF_BYTES {
            return Err(ActionProofError::InvalidCompositeProof);
        }
        let mut offset = 0;
        if take::<4>(bytes, &mut offset)? != COMPOSITE_MAGIC
            || u16::from_le_bytes(take(bytes, &mut offset)?) != COMPOSITE_VERSION
        {
            return Err(ActionProofError::InvalidCompositeProof);
        }
        if take::<32>(bytes, &mut offset)? != ACTION_VERIFYING_KEY_ID {
            return Err(ActionProofError::InvalidCompositeProof);
        }
        let accounting_suite_id = take::<32>(bytes, &mut offset)?;
        if accounting_suite_id != expected_accounting_suite_id || accounting_suite_id == [0; 32] {
            return Err(ActionProofError::InvalidCompositeProof);
        }
        let action_count = usize::from(take::<1>(bytes, &mut offset)?[0]);
        if action_count != expected_action_count {
            return Err(ActionProofError::InvalidCompositeProof);
        }
        let action_len = usize::try_from(u32::from_le_bytes(take(bytes, &mut offset)?))
            .map_err(|_| ActionProofError::InvalidCompositeProof)?;
        let accounting_len = usize::try_from(u32::from_le_bytes(take(bytes, &mut offset)?))
            .map_err(|_| ActionProofError::InvalidCompositeProof)?;
        if accounting_len == 0
            || action_len != Proof::expected_proof_size(action_count)
            || offset
                .checked_add(action_len)
                .and_then(|value| value.checked_add(accounting_len))
                != Some(bytes.len())
        {
            return Err(ActionProofError::InvalidCompositeProof);
        }
        let action_end = offset + action_len;
        let action_proof =
            ActionProof::from_bytes(bytes[offset..action_end].to_vec(), action_count)?;
        let accounting_proof = bytes[action_end..].to_vec();
        Self::new(
            action_count,
            accounting_suite_id,
            action_proof,
            accounting_proof,
        )
    }

    /// Canonical network payload placed in `TransferV2::proof`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&COMPOSITE_MAGIC);
        bytes.extend_from_slice(&COMPOSITE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&ACTION_VERIFYING_KEY_ID);
        bytes.extend_from_slice(&self.accounting_suite_id);
        bytes.push(self.action_count);
        bytes.extend_from_slice(
            &u32::try_from(self.action_proof.0.len())
                .expect("canonical action proof length fits u32")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.accounting_proof.len())
                .expect("composite proof is bounded below u32::MAX")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.action_proof.0);
        bytes.extend_from_slice(&self.accounting_proof);
        bytes
    }

    fn encoded_len(&self) -> usize {
        COMPOSITE_HEADER_BYTES + self.action_proof.0.len() + self.accounting_proof.len()
    }
}

/// Derives the consensus circuit ID from both independently pinned proof suites.
#[must_use]
pub fn composite_circuit_id(accounting_suite_id: [u8; 32]) -> CircuitId {
    let mut hasher = blake3::Hasher::new_derive_key(COMPOSITE_CIRCUIT_ID_DOMAIN);
    hasher.update(&COMPOSITE_VERSION.to_le_bytes());
    hasher.update(&ACTION_VERIFYING_KEY_ID);
    hasher.update(&accounting_suite_id);
    CircuitId::new(*hasher.finalize().as_bytes())
}

/// Consensus adapter that can only be constructed with both proof verifiers.
#[derive(Debug)]
pub struct CompositeTransferVerifier<A> {
    action: ActionVerifyingKey,
    accounting: A,
}

impl<A: AccountingProofVerifier> CompositeTransferVerifier<A> {
    /// Builds an adapter for one exact accounting suite.
    #[must_use]
    pub fn new(accounting: A) -> Self {
        Self {
            action: ActionVerifyingKey::build(),
            accounting,
        }
    }

    /// Circuit ID that consensus configuration must activate for this verifier.
    #[must_use]
    pub fn circuit_id(&self) -> CircuitId {
        composite_circuit_id(self.accounting.suite_id())
    }
}

impl<A: AccountingProofVerifier> TransferV2ProofVerifier for CompositeTransferVerifier<A> {
    fn verify(
        &self,
        effects: &TransferV2Effects,
        proof: &[u8],
    ) -> Result<(), ProofVerificationError> {
        if effects.circuit_id() != self.circuit_id() {
            return Err(ProofVerificationError);
        }
        let composite = CompositeTransferProof::decode(
            proof,
            effects.actions().len(),
            self.accounting.suite_id(),
        )
        .map_err(|_| ProofVerificationError)?;
        verify(&self.action, effects, &composite.action_proof)
            .map_err(|_| ProofVerificationError)?;
        self.accounting
            .verify(effects, &composite.accounting_proof)
            .map_err(|_| ProofVerificationError)
    }
}

/// Creates one aggregated proof after checking private/public action counts.
pub fn prove<R: RngCore + CryptoRng>(
    proving_key: &ActionProvingKey,
    effects: &TransferV2Effects,
    witnesses: Vec<PreparedActionCircuit>,
    rng: R,
) -> Result<ActionProof, ActionProofError> {
    validate_action_count(effects.actions().len())?;
    if witnesses.len() != effects.actions().len() {
        return Err(ActionProofError::ActionCountMismatch);
    }

    let (circuits, instances): (Vec<_>, Vec<_>) = witnesses
        .into_iter()
        .map(|prepared| {
            let (circuit, instance, _) = prepared.into_parts();
            (circuit, instance)
        })
        .unzip();
    let expected_instances = instances_for_effects(effects)?;

    // Both representations are derived independently. Verification below is
    // authoritative and makes a mismatched witness fail before returning bytes.
    let proof = Proof::create(&proving_key.proving, &circuits, &expected_instances, rng)
        .map_err(|_| ActionProofError::Halo2)?;
    let typed = ActionProof::from_bytes(proof.as_ref().to_vec(), effects.actions().len())?;

    let witness_proof = Proof::new(typed.0.clone());
    witness_proof
        .verify(&proving_key.verifying, &instances)
        .map_err(|_| ActionProofError::Halo2)?;
    witness_proof
        .verify(&proving_key.verifying, &expected_instances)
        .map_err(|_| ActionProofError::Halo2)?;

    Ok(typed)
}

/// Verifies the core action layer against independently parsed transfer fields.
///
/// Successful return is not sufficient to accept a Vault transfer. The future
/// composite verifier must additionally verify conservation, gas, exact burn,
/// output/ciphertext bindings, and the burn encryption statement.
pub fn verify(
    verifying_key: &ActionVerifyingKey,
    effects: &TransferV2Effects,
    proof: &ActionProof,
) -> Result<(), ActionProofError> {
    validate_action_count(effects.actions().len())?;
    let expected = Proof::expected_proof_size(effects.actions().len());
    if proof.0.len() != expected {
        return Err(ActionProofError::NonCanonicalProofLength {
            expected,
            actual: proof.0.len(),
        });
    }
    let instances = instances_for_effects(effects)?;
    Proof::new(proof.0.clone())
        .verify(&verifying_key.0, &instances)
        .map_err(|_| ActionProofError::Halo2)
}

fn instances_for_effects(
    effects: &TransferV2Effects,
) -> Result<Vec<orchard::circuit::Instance>, ActionProofError> {
    effects
        .actions()
        .iter()
        .map(|action| {
            vault_privacy::circuit::instance_from_parts(
                effects.anchor(),
                action.net_value_commitment(),
                action.nullifier(),
                action.randomized_verification_key(),
                action.output().note_commitment(),
            )
            .map_err(ActionProofError::InvalidInstance)
        })
        .collect()
}

fn validate_action_count(action_count: usize) -> Result<(), ActionProofError> {
    if vault_protocol::ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&action_count) {
        Ok(())
    } else {
        Err(ActionProofError::UnsupportedActionCount)
    }
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], ActionProofError> {
    let end = offset
        .checked_add(N)
        .ok_or(ActionProofError::InvalidCompositeProof)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(ActionProofError::InvalidCompositeProof)?
        .try_into()
        .map_err(|_| ActionProofError::InvalidCompositeProof)?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNTING_SUITE: [u8; 32] = [0xa1; 32];

    fn encoded_composite() -> Vec<u8> {
        CompositeTransferProof::new(
            2,
            ACCOUNTING_SUITE,
            ActionProof::from_bytes(vec![0x72; TWO_ACTION_PROOF_BYTES], 2).unwrap(),
            vec![0xb2; 96],
        )
        .unwrap()
        .encode()
    }

    #[test]
    fn composite_codec_is_exact_and_suite_bound() {
        let encoded = encoded_composite();
        let decoded = CompositeTransferProof::decode(&encoded, 2, ACCOUNTING_SUITE).unwrap();
        assert_eq!(decoded.encode(), encoded);
        assert_ne!(composite_circuit_id(ACCOUNTING_SUITE).into_bytes(), [0; 32]);
        assert_ne!(
            composite_circuit_id(ACCOUNTING_SUITE),
            composite_circuit_id([0xa2; 32])
        );

        for end in 0..encoded.len() {
            assert!(CompositeTransferProof::decode(&encoded[..end], 2, ACCOUNTING_SUITE).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(CompositeTransferProof::decode(&trailing, 2, ACCOUNTING_SUITE).is_err());
        assert!(CompositeTransferProof::decode(&encoded, 4, ACCOUNTING_SUITE).is_err());
        assert!(CompositeTransferProof::decode(&encoded, 2, [0xa2; 32]).is_err());
    }

    #[test]
    fn composite_codec_rejects_mutated_headers_and_empty_accounting() {
        let encoded = encoded_composite();
        for offset in [0, 4, 6, 38, 70, 71, 75] {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 1;
            assert!(CompositeTransferProof::decode(&mutated, 2, ACCOUNTING_SUITE).is_err());
        }
        let action = ActionProof::from_bytes(vec![0; TWO_ACTION_PROOF_BYTES], 2).unwrap();
        assert!(CompositeTransferProof::new(2, ACCOUNTING_SUITE, action, Vec::new()).is_err());
    }

    #[test]
    fn composite_codec_structured_malformed_corpus_never_panics_or_extends() {
        let encoded = encoded_composite();

        for offset in 0..COMPOSITE_HEADER_BYTES {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 1_u8 << (offset % 8);
            assert!(CompositeTransferProof::decode(&mutated, 2, ACCOUNTING_SUITE).is_err());
        }

        for appended in [1, 2, 31, 256, 4_096] {
            let mut extended = encoded.clone();
            extended.resize(encoded.len() + appended, 0xa5);
            assert!(CompositeTransferProof::decode(&extended, 2, ACCOUNTING_SUITE).is_err());
        }

        for replacement in [0_u32, 1, u32::MAX] {
            for field in [71_usize, 75] {
                let mut mutated = encoded.clone();
                mutated[field..field + 4].copy_from_slice(&replacement.to_le_bytes());
                assert!(CompositeTransferProof::decode(&mutated, 2, ACCOUNTING_SUITE).is_err());
            }
        }

        let oversized = vec![0; MAX_PROOF_BYTES + 1];
        assert!(CompositeTransferProof::decode(&oversized, 2, ACCOUNTING_SUITE).is_err());

        let mut state = 0x6a09_e667_f3bc_c909_u64;
        for _ in 0..2_048 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = usize::try_from(state % 16_385).unwrap();
            let mut bytes = vec![0_u8; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            if let Some(first) = bytes.first_mut() {
                *first = COMPOSITE_MAGIC[0] ^ 1;
            }
            assert!(CompositeTransferProof::decode(&bytes, 2, ACCOUNTING_SUITE).is_err());
        }
    }
}
