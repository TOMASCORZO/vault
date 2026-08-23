//! Fail-closed RISC Zero adapter for Vault's experimental accounting proof.
//!
//! The receipt is a real zkVM proof, but the guest statement remains a research
//! subset of transfer-v1. Do not activate this circuit with real funds.

use std::time::Instant;

use risc0_zkvm::{Digest, ExecutorEnv, Receipt, default_prover};
use thiserror::Error;
use vault_protocol::{
    CircuitId, ProofVerificationError, PublicInputDigest, ShieldedTransfer, TransferProofVerifier,
};
use vault_zk_accounting_core::{
    AccountingClaim, AccountingJournal, PublicBurn, PublicOutput, TransferPublicFields,
};
use vault_zk_accounting_methods::{VAULT_ZK_ACCOUNTING_GUEST_ELF, VAULT_ZK_ACCOUNTING_GUEST_ID};

/// Reviewed guest image ID for the post-remediation accounting-v1 build.
///
/// CI deliberately fails if the compiled guest no longer produces these bytes.
pub const REVIEWED_ACCOUNTING_V1_CIRCUIT_ID: [u8; 32] = [
    203, 198, 46, 206, 178, 141, 54, 213, 107, 153, 116, 228, 70, 98, 91, 222, 230, 165, 188,
    144, 219, 168, 115, 190, 60, 241, 106, 73, 194, 142, 20, 217,
];

/// Proof-generation measurements captured on the local machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvingMetrics {
    /// Wall-clock proving time.
    pub elapsed_ms: u128,
    /// Serialized receipt size accepted by the Vault envelope.
    pub proof_bytes: usize,
    /// Number of zkVM proof segments.
    pub segments: usize,
    /// Total zkVM cycles, including paging and reserved cycles.
    pub total_cycles: u64,
    /// Cycles spent running guest code.
    pub user_cycles: u64,
}

/// A serialized proof plus its verified public journal and measurements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofArtifact {
    /// Bincode-encoded RISC Zero receipt.
    pub proof: Vec<u8>,
    /// Journal authenticated by the receipt.
    pub journal: AccountingJournal,
    /// Local proving measurements.
    pub metrics: ProvingMetrics,
}

/// Detailed errors for prover tooling; consensus maps every one to one opaque error.
#[derive(Debug, Error)]
pub enum ZkBackendError {
    /// The process requested RISC Zero's fake-receipt development mode.
    #[error("RISC0_DEV_MODE is set but Vault requires cryptographic receipts")]
    DevelopmentModeRequested,
    /// The zkVM execution environment could not encode the claim.
    #[error("failed to build zkVM environment: {0}")]
    Environment(String),
    /// The prover rejected or failed to execute the guest.
    #[error("zkVM proving failed: {0}")]
    Proving(String),
    /// The receipt could not be encoded for the transaction envelope.
    #[error("failed to serialize receipt: {0}")]
    ReceiptEncoding(String),
    /// Proof bytes were not a canonical receipt encoding.
    #[error("failed to decode receipt: {0}")]
    ReceiptDecoding(String),
    /// Cryptographic receipt verification failed.
    #[error("receipt verification failed: {0}")]
    ReceiptVerification(String),
    /// The authenticated journal used an unexpected schema.
    #[error("failed to decode authenticated journal: {0}")]
    JournalDecoding(String),
    /// The receipt proved a public statement other than the requested transfer.
    #[error("receipt public-input digest does not match the transfer")]
    PublicInputMismatch,
}

/// Returns the canonical transfer circuit identifier derived from the guest image ID.
#[must_use]
pub fn activated_circuit_id() -> CircuitId {
    let digest = Digest::from(VAULT_ZK_ACCOUNTING_GUEST_ID);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_bytes());
    CircuitId::new(bytes)
}

/// Converts the consensus envelope into the exact transcript recomputed by the guest.
#[must_use]
pub fn public_fields(transfer: &ShieldedTransfer) -> TransferPublicFields {
    TransferPublicFields {
        version: transfer.version(),
        chain_id: transfer.chain_id().into_bytes(),
        circuit_id: transfer.circuit_id().into_bytes(),
        anchor: transfer.anchor().into_bytes(),
        nullifiers: transfer
            .nullifiers()
            .iter()
            .map(|value| value.into_bytes())
            .collect(),
        outputs: transfer
            .outputs()
            .iter()
            .map(|output| PublicOutput {
                note_commitment: output.commitment().into_bytes(),
                ephemeral_key: output.ephemeral_key().into_bytes(),
                ciphertext: output.ciphertext().to_vec(),
            })
            .collect(),
        balance_commitment: transfer.balance_commitment().into_bytes(),
        burn: PublicBurn {
            commitment: transfer.burn().commitment().into_bytes(),
            ciphertext: transfer.burn().ciphertext().to_vec(),
        },
        gas_units: transfer.gas().units,
        fee_per_gas: transfer.gas().fee_per_gas,
    }
}

/// Generates and immediately verifies one real accounting receipt.
pub fn prove(claim: &AccountingClaim) -> Result<ProofArtifact, ZkBackendError> {
    reject_development_mode()?;
    let env = ExecutorEnv::builder()
        .write(claim)
        .map_err(|error| ZkBackendError::Environment(error.to_string()))?
        .build()
        .map_err(|error| ZkBackendError::Environment(error.to_string()))?;

    let started = Instant::now();
    let prove_info = default_prover()
        .prove(env, VAULT_ZK_ACCOUNTING_GUEST_ELF)
        .map_err(|error| ZkBackendError::Proving(error.to_string()))?;
    let elapsed_ms = started.elapsed().as_millis();
    prove_info
        .receipt
        .verify(VAULT_ZK_ACCOUNTING_GUEST_ID)
        .map_err(|error| ZkBackendError::ReceiptVerification(error.to_string()))?;

    let journal: AccountingJournal = prove_info
        .receipt
        .journal
        .decode()
        .map_err(|error| ZkBackendError::JournalDecoding(error.to_string()))?;
    let expected_digest = claim.public.public_inputs_digest();
    if journal.public_inputs_digest != expected_digest {
        return Err(ZkBackendError::PublicInputMismatch);
    }

    let proof = bincode::serialize(&prove_info.receipt)
        .map_err(|error| ZkBackendError::ReceiptEncoding(error.to_string()))?;
    let metrics = ProvingMetrics {
        elapsed_ms,
        proof_bytes: proof.len(),
        segments: prove_info.stats.segments,
        total_cycles: prove_info.stats.total_cycles,
        user_cycles: prove_info.stats.user_cycles,
    };

    Ok(ProofArtifact {
        proof,
        journal,
        metrics,
    })
}

/// Decodes and verifies one receipt against an exact transfer public-input digest.
pub fn verify(
    expected_public_inputs: PublicInputDigest,
    proof: &[u8],
) -> Result<AccountingJournal, ZkBackendError> {
    reject_development_mode()?;
    let receipt: Receipt = bincode::deserialize(proof)
        .map_err(|error| ZkBackendError::ReceiptDecoding(error.to_string()))?;
    receipt
        .verify(VAULT_ZK_ACCOUNTING_GUEST_ID)
        .map_err(|error| ZkBackendError::ReceiptVerification(error.to_string()))?;
    let journal: AccountingJournal = receipt
        .journal
        .decode()
        .map_err(|error| ZkBackendError::JournalDecoding(error.to_string()))?;
    if journal.public_inputs_digest != *expected_public_inputs.as_bytes() {
        return Err(ZkBackendError::PublicInputMismatch);
    }
    Ok(journal)
}

fn reject_development_mode() -> Result<(), ZkBackendError> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        Err(ZkBackendError::DevelopmentModeRequested)
    } else {
        Ok(())
    }
}

/// Consensus adapter with no development-mode acceptance path.
#[derive(Clone, Copy, Debug, Default)]
pub struct Risc0AccountingVerifier;

impl TransferProofVerifier for Risc0AccountingVerifier {
    fn verify(
        &self,
        circuit_id: CircuitId,
        public_inputs: PublicInputDigest,
        proof: &[u8],
    ) -> Result<(), ProofVerificationError> {
        if circuit_id != activated_circuit_id() {
            return Err(ProofVerificationError);
        }
        verify(public_inputs, proof)
            .map(|_| ())
            .map_err(|_| ProofVerificationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_protocol::{
        BalanceCommitment, BurnCommitment, ChainId, EncryptedBurn, EphemeralKey, GasParameters,
        NoteCommitment, Nullifier, ShieldedOutput, StateRoot, TRANSFER_V1_PROTOCOL_VERSION,
    };

    fn example_transfer() -> ShieldedTransfer {
        ShieldedTransfer::new(
            TRANSFER_V1_PROTOCOL_VERSION,
            ChainId::new([1; 32]),
            activated_circuit_id(),
            StateRoot::new([2; 32]),
            vec![Nullifier::new([3; 32])],
            vec![ShieldedOutput::new(
                NoteCommitment::new([4; 32]),
                EphemeralKey::new([5; 32]),
                vec![6],
            )],
            BalanceCommitment::new([7; 32]),
            EncryptedBurn::new(BurnCommitment::new([8; 32]), vec![9]),
            GasParameters {
                units: 10,
                fee_per_gas: 2,
            },
            vec![10],
        )
    }

    #[test]
    fn guest_transcript_matches_consensus_transcript() {
        let transfer = example_transfer();
        assert_eq!(
            public_fields(&transfer).public_inputs_digest(),
            *transfer.public_inputs_digest().as_bytes()
        );
    }

    #[test]
    fn guest_image_id_changes_require_explicit_review() {
        assert_eq!(
            activated_circuit_id().into_bytes(),
            REVIEWED_ACCOUNTING_V1_CIRCUIT_ID
        );
    }

    #[test]
    fn adapter_rejects_malformed_receipt() {
        let transfer = example_transfer();
        let verifier = Risc0AccountingVerifier;
        assert_eq!(
            verifier.verify(
                activated_circuit_id(),
                transfer.public_inputs_digest(),
                b"not a receipt"
            ),
            Err(ProofVerificationError)
        );
    }
}
