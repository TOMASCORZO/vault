//! Atomic transfer-v2 shielded state transition.

use std::collections::{BTreeSet, VecDeque};

use vault_privacy::{ActionNullifier, NOTE_TREE_DEPTH, NoteCommitmentTree, NoteTreeRoot};

use crate::{
    ChainId, CircuitId, ProofVerificationError, ProtocolError, PublicInputDigest, TransactionId,
    TransferV2, TransferV2Effects,
};

/// Specialized proof backend for the exact canonical transfer-v2 effects.
///
/// Unlike the legacy v1 adapter, this interface supplies every public field so
/// a Halo2-style verifier can construct its native instance columns. An
/// implementation MUST bind all fields, the action count, and the activated
/// circuit suite; checking only [`TransferV2Effects::public_inputs_digest`] is
/// insufficient unless the proof itself constrains the same digest computation.
pub trait TransferV2ProofVerifier: Send + Sync {
    /// Verifies a proof against the complete canonical public statement.
    fn verify(
        &self,
        effects: &TransferV2Effects,
        proof: &[u8],
    ) -> Result<(), ProofVerificationError>;
}

/// Consensus parameters required by transfer-v2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShieldedStateV2Config {
    /// Network domain accepted by this state machine.
    pub chain_id: ChainId,
    /// Only transfer-v2 proof program accepted until governed activation.
    pub transfer_circuit_id: CircuitId,
    /// Exact burn-encryption construction and parameter digest.
    pub burn_scheme_id: [u8; 32],
    /// Digest of the active threshold public key and participant policy.
    pub burn_key_id: [u8; 32],
    /// Epoch whose threshold public key accepts new burn ciphertexts.
    pub burn_epoch: u64,
    /// Fixed verification and state-transition charge.
    pub base_gas_units: u64,
    /// Additional deterministic charge for every real or padded action.
    pub gas_units_per_action: u64,
    /// Consensus minimum fee bid.
    pub minimum_fee_per_gas: u64,
    /// Number of finalized-block note-tree roots accepted for membership proofs.
    pub recent_anchor_limit: usize,
}

impl ShieldedStateV2Config {
    fn validate(self) -> Result<(), ProtocolError> {
        if self.chain_id.is_zero() {
            return Err(ProtocolError::InvalidConfiguration("chain id is zero"));
        }
        if self.transfer_circuit_id.is_zero() {
            return Err(ProtocolError::InvalidConfiguration("circuit id is zero"));
        }
        if self.burn_scheme_id == [0; 32] {
            return Err(ProtocolError::InvalidConfiguration(
                "burn scheme id is zero",
            ));
        }
        if self.burn_key_id == [0; 32] {
            return Err(ProtocolError::InvalidConfiguration("burn key id is zero"));
        }
        if self.base_gas_units == 0 || self.gas_units_per_action == 0 {
            return Err(ProtocolError::InvalidConfiguration(
                "transfer-v2 gas schedule contains zero",
            ));
        }
        if self.minimum_fee_per_gas == 0 {
            return Err(ProtocolError::InvalidConfiguration("minimum fee is zero"));
        }
        if self.recent_anchor_limit == 0 {
            return Err(ProtocolError::InvalidConfiguration(
                "anchor window is empty",
            ));
        }
        Ok(())
    }

    /// Exact gas units for an activated padded action bucket.
    pub fn required_gas(self, action_count: usize) -> Result<u64, ProtocolError> {
        let action_count =
            u64::try_from(action_count).map_err(|_| ProtocolError::GasScheduleOverflow)?;
        self.gas_units_per_action
            .checked_mul(action_count)
            .and_then(|actions| self.base_gas_units.checked_add(actions))
            .ok_or(ProtocolError::GasScheduleOverflow)
    }
}

/// Consensus receipt after an atomic transfer-v2 state update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyReceiptV2 {
    /// Content-derived identifier over the full canonical transaction.
    pub transaction_id: TransactionId,
    /// Exact public statement accepted by the proof backend.
    pub public_inputs: PublicInputDigest,
    /// Number of real and padded paired actions.
    pub action_count: usize,
    /// First leaf position appended by this bundle.
    pub first_output_position: u64,
    /// Deterministically derived post-transfer note-tree root.
    pub new_note_tree_root: NoteTreeRoot,
    /// Public gas fee transferred to the block fee pool.
    pub gas_fee: u128,
}

/// Replay-protected transfer-v2 state with an internally derived note tree.
///
/// This in-memory H1 component begins from the canonical empty tree. Durable,
/// authenticated database restoration remains an H2 requirement and must not
/// trust an unauthenticated frontier or nullifier index.
#[derive(Debug)]
pub struct ShieldedStateV2<V> {
    config: ShieldedStateV2Config,
    verifier: V,
    note_tree: NoteCommitmentTree,
    recent_anchors: VecDeque<NoteTreeRoot>,
    spent_nullifiers: BTreeSet<ActionNullifier>,
    note_commitments: BTreeSet<[u8; 32]>,
}

impl<V: TransferV2ProofVerifier> ShieldedStateV2<V> {
    /// Creates genesis state at the canonical empty Orchard root.
    pub fn new(config: ShieldedStateV2Config, verifier: V) -> Result<Self, ProtocolError> {
        config.validate()?;
        let note_tree = NoteCommitmentTree::new();
        let root = note_tree.typed_root();
        Ok(Self {
            config,
            verifier,
            note_tree,
            recent_anchors: VecDeque::from([root]),
            spent_nullifiers: BTreeSet::new(),
            note_commitments: BTreeSet::new(),
        })
    }

    /// Current canonical note-tree root.
    #[must_use]
    pub fn current_root(&self) -> NoteTreeRoot {
        self.note_tree.typed_root()
    }

    /// Number of note commitments appended, including padded outputs.
    #[must_use]
    pub fn note_tree_size(&self) -> u64 {
        self.note_tree.size()
    }

    /// Number of globally consumed real and dummy nullifiers.
    #[must_use]
    pub fn spent_nullifier_count(&self) -> usize {
        self.spent_nullifiers.len()
    }

    /// Whether a root is inside the configured membership window.
    #[must_use]
    pub fn accepts_anchor(&self, root: NoteTreeRoot) -> bool {
        self.recent_anchors.contains(&root)
    }

    /// Records the current tree root once after a block is finalized.
    ///
    /// Transaction application deliberately does not advance the anchor window:
    /// every transfer in one block may prove against the same recent pre-block
    /// root. The consensus/block executor must call this exactly at its block
    /// finalization boundary.
    pub fn finalize_block_anchor(&mut self) -> NoteTreeRoot {
        let root = self.current_root();
        self.record_anchor(root);
        root
    }

    /// Validates, verifies, and atomically applies a transfer-v2 bundle.
    pub fn apply_transfer(
        &mut self,
        transfer: &TransferV2,
    ) -> Result<ApplyReceiptV2, ProtocolError> {
        self.validate_structure(transfer)?;

        // Build the complete successor before the expensive proof check. This
        // validates capacity and guarantees no fallible operation after the
        // first state mutation.
        let mut next_tree = self.note_tree.clone();
        for action in transfer.effects().actions() {
            next_tree
                .append(action.output().note_commitment())
                .map_err(|_| ProtocolError::NoteTreeCapacityExceeded)?;
        }
        let new_root = next_tree.typed_root();

        let public_inputs = transfer.public_inputs_digest();
        self.verifier
            .verify(transfer.effects(), transfer.proof())
            .map_err(|_| ProtocolError::InvalidProof)?;

        let first_output_position = self.note_tree.size();
        let action_count = transfer.effects().actions().len();
        let gas_fee = transfer.effects().gas().total_fee()?;

        self.spent_nullifiers.extend(
            transfer
                .effects()
                .actions()
                .iter()
                .map(|action| action.nullifier()),
        );
        self.note_commitments.extend(
            transfer
                .effects()
                .actions()
                .iter()
                .map(|action| action.output().note_commitment()),
        );
        self.note_tree = next_tree;

        Ok(ApplyReceiptV2 {
            transaction_id: transfer.transaction_id(),
            public_inputs,
            action_count,
            first_output_position,
            new_note_tree_root: new_root,
            gas_fee,
        })
    }

    fn validate_structure(&self, transfer: &TransferV2) -> Result<(), ProtocolError> {
        let effects = transfer.effects();
        if effects.chain_id() != self.config.chain_id {
            return Err(ProtocolError::WrongChainId {
                expected: self.config.chain_id,
                actual: effects.chain_id(),
            });
        }
        if effects.circuit_id() != self.config.transfer_circuit_id {
            return Err(ProtocolError::WrongCircuitId {
                expected: self.config.transfer_circuit_id,
                actual: effects.circuit_id(),
            });
        }
        if !self.recent_anchors.contains(&effects.anchor()) {
            return Err(ProtocolError::UnknownNoteTreeRoot(effects.anchor()));
        }
        if effects.burn().scheme_id() != self.config.burn_scheme_id {
            return Err(ProtocolError::WrongBurnSchemeId);
        }
        if effects.burn().key_id() != self.config.burn_key_id {
            return Err(ProtocolError::WrongBurnKeyId);
        }
        if effects.burn().epoch() != self.config.burn_epoch {
            return Err(ProtocolError::WrongBurnEpoch {
                expected: self.config.burn_epoch,
                actual: effects.burn().epoch(),
            });
        }

        let expected_gas = self.config.required_gas(effects.actions().len())?;
        let gas = effects.gas();
        if gas.units != expected_gas {
            return Err(ProtocolError::IncorrectGasUnits {
                expected: expected_gas,
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
        transfer.verify_authorizations()?;

        let capacity = 1u64 << NOTE_TREE_DEPTH;
        let action_count = u64::try_from(effects.actions().len())
            .map_err(|_| ProtocolError::NoteTreeCapacityExceeded)?;
        if self
            .note_tree
            .size()
            .checked_add(action_count)
            .is_none_or(|size| size > capacity)
        {
            return Err(ProtocolError::NoteTreeCapacityExceeded);
        }

        let mut new_commitments = BTreeSet::new();
        for action in effects.actions() {
            if self.spent_nullifiers.contains(&action.nullifier()) {
                return Err(ProtocolError::ActionNullifierAlreadySpent(
                    action.nullifier(),
                ));
            }
            let commitment = action.output().note_commitment();
            if !new_commitments.insert(commitment) {
                return Err(ProtocolError::DuplicateNoteCommitment(
                    crate::NoteCommitment::new(commitment),
                ));
            }
            if self.note_commitments.contains(&commitment) {
                return Err(ProtocolError::NoteCommitmentAlreadyExists(
                    crate::NoteCommitment::new(commitment),
                ));
            }
        }
        Ok(())
    }

    fn record_anchor(&mut self, root: NoteTreeRoot) {
        if self.recent_anchors.back() == Some(&root) {
            return;
        }
        self.recent_anchors.push_back(root);
        while self.recent_anchors.len() > self.config.recent_anchor_limit {
            self.recent_anchors.pop_front();
        }
    }
}
