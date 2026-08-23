use std::collections::{BTreeSet, VecDeque};

use crate::{
    ChainId, CircuitId, MAX_BURN_CIPHERTEXT_BYTES, MAX_NOTE_CIPHERTEXT_BYTES, MAX_NULLIFIERS,
    MAX_OUTPUTS, MAX_PROOF_BYTES, NoteCommitment, Nullifier, ProofVerificationError, ProtocolError,
    PublicInputDigest, ShieldedTransfer, StateRoot, TransactionId,
};

/// Cryptographic backend accepted by the shielded state machine.
///
/// Implementations must verify the exact activated circuit against the supplied
/// public-input digest. A production verifier must fail closed and must never
/// expose a development mode capable of accepting fake receipts.
pub trait TransferProofVerifier: Send + Sync {
    /// Verifies one transfer proof.
    fn verify(
        &self,
        circuit_id: CircuitId,
        public_inputs: PublicInputDigest,
        proof: &[u8],
    ) -> Result<(), ProofVerificationError>;
}

/// Consensus parameters required by transfer-v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShieldedStateConfig {
    /// Network domain accepted by this state machine.
    pub chain_id: ChainId,
    /// Only proof program accepted until a delayed upgrade activates another.
    pub transfer_circuit_id: CircuitId,
    /// Exact deterministic gas cost of transfer-v1.
    pub transfer_gas_units: u64,
    /// Consensus minimum fee bid.
    pub minimum_fee_per_gas: u64,
    /// Number of recent state roots accepted for membership proofs.
    pub recent_anchor_limit: usize,
}

/// Result committed after a shielded transfer is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyReceipt {
    /// Content-derived transaction identifier.
    pub transaction_id: TransactionId,
    /// Public statement verified by the proof backend.
    pub public_inputs: PublicInputDigest,
    /// Number of notes consumed.
    pub consumed_notes: usize,
    /// Number of notes created.
    pub created_notes: usize,
    /// Gas transferred to the block fee pool, in atomic VLT units.
    pub gas_fee: u128,
}

/// Replay-protected shielded state surrounding an injected proof verifier.
#[derive(Debug)]
pub struct ShieldedState<V> {
    config: ShieldedStateConfig,
    verifier: V,
    recent_anchors: VecDeque<StateRoot>,
    spent_nullifiers: BTreeSet<Nullifier>,
    note_commitments: BTreeSet<NoteCommitment>,
}

impl<V: TransferProofVerifier> ShieldedState<V> {
    /// Creates shielded state anchored at genesis.
    pub fn new(
        config: ShieldedStateConfig,
        verifier: V,
        genesis_root: StateRoot,
    ) -> Result<Self, ProtocolError> {
        if config.chain_id.is_zero() {
            return Err(ProtocolError::InvalidConfiguration("chain id is zero"));
        }
        if config.transfer_circuit_id.is_zero() {
            return Err(ProtocolError::InvalidConfiguration("circuit id is zero"));
        }
        if config.transfer_gas_units == 0 {
            return Err(ProtocolError::InvalidConfiguration("transfer gas is zero"));
        }
        if config.minimum_fee_per_gas == 0 {
            return Err(ProtocolError::InvalidConfiguration("minimum fee is zero"));
        }
        if config.recent_anchor_limit == 0 {
            return Err(ProtocolError::InvalidConfiguration(
                "anchor window is empty",
            ));
        }
        if genesis_root.is_zero() {
            return Err(ProtocolError::ZeroStateRoot);
        }

        Ok(Self {
            config,
            verifier,
            recent_anchors: VecDeque::from([genesis_root]),
            spent_nullifiers: BTreeSet::new(),
            note_commitments: BTreeSet::new(),
        })
    }

    /// Records a post-block root and evicts anchors outside the consensus window.
    pub fn record_anchor(&mut self, root: StateRoot) -> Result<(), ProtocolError> {
        if root.is_zero() {
            return Err(ProtocolError::ZeroStateRoot);
        }
        if self.recent_anchors.contains(&root) {
            return Ok(());
        }
        self.recent_anchors.push_back(root);
        while self.recent_anchors.len() > self.config.recent_anchor_limit {
            self.recent_anchors.pop_front();
        }
        Ok(())
    }

    /// Number of globally spent nullifiers.
    #[must_use]
    pub fn spent_nullifier_count(&self) -> usize {
        self.spent_nullifiers.len()
    }

    /// Number of globally registered note commitments.
    #[must_use]
    pub fn note_commitment_count(&self) -> usize {
        self.note_commitments.len()
    }

    /// Whether an anchor is currently accepted for membership proofs.
    #[must_use]
    pub fn accepts_anchor(&self, anchor: StateRoot) -> bool {
        self.recent_anchors.contains(&anchor)
    }

    /// Validates, verifies, and atomically records a transfer.
    pub fn apply_transfer(
        &mut self,
        transfer: &ShieldedTransfer,
    ) -> Result<ApplyReceipt, ProtocolError> {
        self.validate_structure(transfer)?;

        let public_inputs = transfer.public_inputs_digest();
        let gas_fee = transfer.gas().total_fee()?;
        self.verifier
            .verify(transfer.circuit_id(), public_inputs, transfer.proof())
            .map_err(|_| ProtocolError::InvalidProof)?;

        // No fallible operation follows the first mutation.
        self.spent_nullifiers
            .extend(transfer.nullifiers().iter().copied());
        self.note_commitments
            .extend(transfer.outputs().iter().map(|output| output.commitment()));

        Ok(ApplyReceipt {
            transaction_id: transfer.transaction_id(),
            public_inputs,
            consumed_notes: transfer.nullifiers().len(),
            created_notes: transfer.outputs().len(),
            gas_fee,
        })
    }

    fn validate_structure(&self, transfer: &ShieldedTransfer) -> Result<(), ProtocolError> {
        if transfer.version() != crate::TRANSFER_V1_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                expected: crate::TRANSFER_V1_PROTOCOL_VERSION,
                actual: transfer.version(),
            });
        }
        if transfer.chain_id() != self.config.chain_id {
            return Err(ProtocolError::WrongChainId {
                expected: self.config.chain_id,
                actual: transfer.chain_id(),
            });
        }
        if transfer.circuit_id() != self.config.transfer_circuit_id {
            return Err(ProtocolError::WrongCircuitId {
                expected: self.config.transfer_circuit_id,
                actual: transfer.circuit_id(),
            });
        }
        if !self.recent_anchors.contains(&transfer.anchor()) {
            return Err(ProtocolError::UnknownAnchor(transfer.anchor()));
        }

        self.validate_nullifiers(transfer)?;
        self.validate_outputs(transfer)?;

        if transfer.balance_commitment().is_zero() {
            return Err(ProtocolError::ZeroBalanceCommitment);
        }
        if transfer.burn().commitment().is_zero() {
            return Err(ProtocolError::ZeroBurnCommitment);
        }
        let burn_size = transfer.burn().ciphertext().len();
        if burn_size == 0 {
            return Err(ProtocolError::EmptyBurnCiphertext);
        }
        if burn_size > MAX_BURN_CIPHERTEXT_BYTES {
            return Err(ProtocolError::BurnCiphertextTooLarge {
                size: burn_size,
                maximum: MAX_BURN_CIPHERTEXT_BYTES,
            });
        }

        let proof_size = transfer.proof().len();
        if proof_size == 0 {
            return Err(ProtocolError::EmptyProof);
        }
        if proof_size > MAX_PROOF_BYTES {
            return Err(ProtocolError::ProofTooLarge {
                size: proof_size,
                maximum: MAX_PROOF_BYTES,
            });
        }

        let gas = transfer.gas();
        if gas.units != self.config.transfer_gas_units {
            return Err(ProtocolError::IncorrectGasUnits {
                expected: self.config.transfer_gas_units,
                actual: gas.units,
            });
        }
        if gas.fee_per_gas < self.config.minimum_fee_per_gas {
            return Err(ProtocolError::FeePerGasTooLow {
                minimum: self.config.minimum_fee_per_gas,
                actual: gas.fee_per_gas,
            });
        }
        gas.total_fee()?;

        Ok(())
    }

    fn validate_nullifiers(&self, transfer: &ShieldedTransfer) -> Result<(), ProtocolError> {
        let nullifiers = transfer.nullifiers();
        if nullifiers.is_empty() {
            return Err(ProtocolError::MissingNullifiers);
        }
        if nullifiers.len() > MAX_NULLIFIERS {
            return Err(ProtocolError::TooManyNullifiers {
                count: nullifiers.len(),
                maximum: MAX_NULLIFIERS,
            });
        }

        let mut unique = BTreeSet::new();
        for nullifier in nullifiers {
            if nullifier.is_zero() {
                return Err(ProtocolError::ZeroNullifier);
            }
            if !unique.insert(*nullifier) {
                return Err(ProtocolError::DuplicateNullifier(*nullifier));
            }
            if self.spent_nullifiers.contains(nullifier) {
                return Err(ProtocolError::NullifierAlreadySpent(*nullifier));
            }
        }
        Ok(())
    }

    fn validate_outputs(&self, transfer: &ShieldedTransfer) -> Result<(), ProtocolError> {
        let outputs = transfer.outputs();
        if outputs.is_empty() {
            return Err(ProtocolError::MissingOutputs);
        }
        if outputs.len() > MAX_OUTPUTS {
            return Err(ProtocolError::TooManyOutputs {
                count: outputs.len(),
                maximum: MAX_OUTPUTS,
            });
        }

        let mut unique = BTreeSet::new();
        for output in outputs {
            let commitment = output.commitment();
            if commitment.is_zero() {
                return Err(ProtocolError::ZeroNoteCommitment);
            }
            if !unique.insert(commitment) {
                return Err(ProtocolError::DuplicateNoteCommitment(commitment));
            }
            if self.note_commitments.contains(&commitment) {
                return Err(ProtocolError::NoteCommitmentAlreadyExists(commitment));
            }
            if output.ephemeral_key().is_zero() {
                return Err(ProtocolError::ZeroEphemeralKey);
            }
            let ciphertext_size = output.ciphertext().len();
            if ciphertext_size == 0 {
                return Err(ProtocolError::EmptyNoteCiphertext);
            }
            if ciphertext_size > MAX_NOTE_CIPHERTEXT_BYTES {
                return Err(ProtocolError::NoteCiphertextTooLarge {
                    size: ciphertext_size,
                    maximum: MAX_NOTE_CIPHERTEXT_BYTES,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BalanceCommitment, BurnCommitment, EncryptedBurn, GasParameters, ShieldedOutput,
        TRANSFER_V1_PROTOCOL_VERSION,
    };

    #[derive(Debug)]
    struct DigestVerifier;

    impl TransferProofVerifier for DigestVerifier {
        fn verify(
            &self,
            _circuit_id: CircuitId,
            public_inputs: PublicInputDigest,
            proof: &[u8],
        ) -> Result<(), ProofVerificationError> {
            if proof == public_inputs.as_bytes() {
                Ok(())
            } else {
                Err(ProofVerificationError)
            }
        }
    }

    fn chain_id() -> ChainId {
        ChainId::new([1; 32])
    }

    fn circuit_id() -> CircuitId {
        CircuitId::new([2; 32])
    }

    fn root(value: u8) -> StateRoot {
        StateRoot::new([value; 32])
    }

    fn config() -> ShieldedStateConfig {
        ShieldedStateConfig {
            chain_id: chain_id(),
            transfer_circuit_id: circuit_id(),
            transfer_gas_units: 10,
            minimum_fee_per_gas: 2,
            recent_anchor_limit: 2,
        }
    }

    fn transfer_with(chain: ChainId, nullifier: u8, commitment: u8) -> ShieldedTransfer {
        let transfer = ShieldedTransfer::new(
            TRANSFER_V1_PROTOCOL_VERSION,
            chain,
            circuit_id(),
            root(3),
            vec![Nullifier::new([nullifier; 32])],
            vec![ShieldedOutput::new(
                NoteCommitment::new([commitment; 32]),
                crate::EphemeralKey::new([5; 32]),
                vec![6, 7, 8],
            )],
            BalanceCommitment::new([9; 32]),
            EncryptedBurn::new(BurnCommitment::new([10; 32]), vec![11, 12]),
            GasParameters {
                units: 10,
                fee_per_gas: 2,
            },
            vec![1],
        );
        let digest = transfer.public_inputs_digest();
        transfer.with_proof(digest.as_bytes().to_vec())
    }

    fn state() -> ShieldedState<DigestVerifier> {
        ShieldedState::new(config(), DigestVerifier, root(3)).expect("valid test state")
    }

    #[test]
    fn accepts_valid_transfer_and_records_replay_protection() {
        let mut state = state();
        let transfer = transfer_with(chain_id(), 4, 7);
        let receipt = state
            .apply_transfer(&transfer)
            .expect("digest verifier accepts bound proof");

        assert_eq!(receipt.gas_fee, 20);
        assert_eq!(receipt.consumed_notes, 1);
        assert_eq!(receipt.created_notes, 1);
        assert_eq!(state.spent_nullifier_count(), 1);
        assert_eq!(state.note_commitment_count(), 1);

        let replay = state.apply_transfer(&transfer);
        assert!(matches!(
            replay,
            Err(ProtocolError::NullifierAlreadySpent(_))
        ));
    }

    #[test]
    fn invalid_proof_does_not_mutate_state() {
        let mut state = state();
        let transfer = transfer_with(chain_id(), 4, 7).with_proof(vec![99]);
        let result = state.apply_transfer(&transfer);

        assert_eq!(result, Err(ProtocolError::InvalidProof));
        assert_eq!(state.spent_nullifier_count(), 0);
        assert_eq!(state.note_commitment_count(), 0);
    }

    #[test]
    fn rejects_cross_chain_replay_before_proof_verification() {
        let mut state = state();
        let transfer = transfer_with(ChainId::new([99; 32]), 4, 7);
        let result = state.apply_transfer(&transfer);
        assert!(matches!(result, Err(ProtocolError::WrongChainId { .. })));
    }

    #[test]
    fn rejects_duplicate_nullifier_in_one_transaction() {
        let mut state = state();
        let original = transfer_with(chain_id(), 4, 7);
        let transfer = ShieldedTransfer::new(
            original.version(),
            original.chain_id(),
            original.circuit_id(),
            original.anchor(),
            vec![Nullifier::new([4; 32]), Nullifier::new([4; 32])],
            original.outputs().to_vec(),
            original.balance_commitment(),
            original.burn().clone(),
            original.gas(),
            original.proof().to_vec(),
        );
        let result = state.apply_transfer(&transfer);
        assert!(matches!(result, Err(ProtocolError::DuplicateNullifier(_))));
    }

    #[test]
    fn anchor_window_evicts_old_roots() {
        let mut state = state();
        state.record_anchor(root(4)).expect("valid root");
        state.record_anchor(root(5)).expect("valid root");

        assert!(!state.accepts_anchor(root(3)));
        assert!(state.accepts_anchor(root(4)));
        assert!(state.accepts_anchor(root(5)));
    }

    #[test]
    fn public_input_digest_binds_ciphertext() {
        let first = transfer_with(chain_id(), 4, 7);
        let original_output = &first.outputs()[0];
        let changed = ShieldedTransfer::new(
            first.version(),
            first.chain_id(),
            first.circuit_id(),
            first.anchor(),
            first.nullifiers().to_vec(),
            vec![ShieldedOutput::new(
                original_output.commitment(),
                original_output.ephemeral_key(),
                vec![6, 7, 9],
            )],
            first.balance_commitment(),
            first.burn().clone(),
            first.gas(),
            first.proof().to_vec(),
        );

        assert_ne!(first.public_inputs_digest(), changed.public_inputs_digest());
    }

    #[test]
    fn transaction_id_binds_exact_proof_bytes() {
        let first = transfer_with(chain_id(), 4, 7);
        let second = first.clone().with_proof(vec![42; 32]);
        assert_eq!(first.public_inputs_digest(), second.public_inputs_digest());
        assert_ne!(first.transaction_id(), second.transaction_id());
    }

    #[test]
    fn transfer_v1_reference_vector() {
        let transfer = transfer_with(chain_id(), 4, 7);
        assert_eq!(
            transfer.public_inputs_digest().to_string(),
            "16ff379d455ae3c066ebeaee36017619ec5546dff5626cf546ea96ba44778933"
        );
        assert_eq!(
            transfer.transaction_id().to_string(),
            "472f91a359fe1e8cbee06b68f84b9d2e1e59e8324b3f90a8e8d29b363d213641"
        );
    }
}
