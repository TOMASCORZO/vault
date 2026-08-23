use blake3::Hasher;

use crate::{
    BalanceCommitment, BurnCommitment, ChainId, CircuitId, EphemeralKey, NoteCommitment, Nullifier,
    ProtocolError, PublicInputDigest, StateRoot, TransactionId,
};

const PUBLIC_INPUT_DOMAIN: &str = "vault.protocol.transfer-v1.public-inputs.2026-08-21";
const TRANSACTION_ID_DOMAIN: &str = "vault.protocol.transfer-v1.transaction-id.2026-08-21";

/// Consensus version implemented by this transaction envelope.
pub const TRANSFER_V1_PROTOCOL_VERSION: u16 = 1;

/// Public gas parameters for a shielded transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GasParameters {
    /// Deterministic gas units charged by transfer-v1.
    pub units: u64,
    /// Atomic VLT units offered for each gas unit.
    pub fee_per_gas: u64,
}

impl GasParameters {
    /// Computes the complete public gas fee in atomic VLT units.
    pub fn total_fee(self) -> Result<u128, ProtocolError> {
        u128::from(self.units)
            .checked_mul(u128::from(self.fee_per_gas))
            .ok_or(ProtocolError::FeeOverflow)
    }
}

/// Hiding commitment and threshold-encrypted representation of one burn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBurn {
    commitment: BurnCommitment,
    ciphertext: Vec<u8>,
}

impl EncryptedBurn {
    /// Creates an encrypted burn payload.
    #[must_use]
    pub fn new(commitment: BurnCommitment, ciphertext: Vec<u8>) -> Self {
        Self {
            commitment,
            ciphertext,
        }
    }

    /// Hiding commitment constrained by the transfer proof.
    #[must_use]
    pub const fn commitment(&self) -> BurnCommitment {
        self.commitment
    }

    /// Ciphertext intended for delayed aggregate opening.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Public representation of one encrypted output note.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldedOutput {
    commitment: NoteCommitment,
    ephemeral_key: EphemeralKey,
    ciphertext: Vec<u8>,
}

impl ShieldedOutput {
    /// Creates a shielded output envelope.
    #[must_use]
    pub fn new(
        commitment: NoteCommitment,
        ephemeral_key: EphemeralKey,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            commitment,
            ephemeral_key,
            ciphertext,
        }
    }

    /// Hiding note commitment appended to shielded state.
    #[must_use]
    pub const fn commitment(&self) -> NoteCommitment {
        self.commitment
    }

    /// Ephemeral note-encryption key.
    #[must_use]
    pub const fn ephemeral_key(&self) -> EphemeralKey {
        self.ephemeral_key
    }

    /// Authenticated encrypted note bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Consensus-facing envelope for a private VLT transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldedTransfer {
    version: u16,
    chain_id: ChainId,
    circuit_id: CircuitId,
    anchor: StateRoot,
    nullifiers: Vec<Nullifier>,
    outputs: Vec<ShieldedOutput>,
    balance_commitment: BalanceCommitment,
    burn: EncryptedBurn,
    gas: GasParameters,
    proof: Vec<u8>,
}

impl ShieldedTransfer {
    /// Creates a transfer envelope. Consensus validation happens in `ShieldedState`.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        version: u16,
        chain_id: ChainId,
        circuit_id: CircuitId,
        anchor: StateRoot,
        nullifiers: Vec<Nullifier>,
        outputs: Vec<ShieldedOutput>,
        balance_commitment: BalanceCommitment,
        burn: EncryptedBurn,
        gas: GasParameters,
        proof: Vec<u8>,
    ) -> Self {
        Self {
            version,
            chain_id,
            circuit_id,
            anchor,
            nullifiers,
            outputs,
            balance_commitment,
            burn,
            gas,
            proof,
        }
    }

    /// Replaces proof bytes without changing the public statement.
    #[must_use]
    pub fn with_proof(mut self, proof: Vec<u8>) -> Self {
        self.proof = proof;
        self
    }

    /// Protocol version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Network domain.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Activated transfer circuit.
    #[must_use]
    pub const fn circuit_id(&self) -> CircuitId {
        self.circuit_id
    }

    /// Recent shielded-state root used by membership proofs.
    #[must_use]
    pub const fn anchor(&self) -> StateRoot {
        self.anchor
    }

    /// Consumed-note nullifiers.
    #[must_use]
    pub fn nullifiers(&self) -> &[Nullifier] {
        &self.nullifiers
    }

    /// Created encrypted notes.
    #[must_use]
    pub fn outputs(&self) -> &[ShieldedOutput] {
        &self.outputs
    }

    /// Commitment that binds value conservation and authorization.
    #[must_use]
    pub const fn balance_commitment(&self) -> BalanceCommitment {
        self.balance_commitment
    }

    /// Hidden burn payload.
    #[must_use]
    pub const fn burn(&self) -> &EncryptedBurn {
        &self.burn
    }

    /// Public gas schedule and bid.
    #[must_use]
    pub const fn gas(&self) -> GasParameters {
        self.gas
    }

    /// Opaque proof bytes for the activated verifier.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Deterministically hashes every proof-bound public field and encrypted payload.
    #[must_use]
    pub fn public_inputs_digest(&self) -> PublicInputDigest {
        let mut hasher = Hasher::new_derive_key(PUBLIC_INPUT_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(self.chain_id.as_bytes());
        hasher.update(self.circuit_id.as_bytes());
        hasher.update(self.anchor.as_bytes());
        update_count(&mut hasher, self.nullifiers.len());
        for nullifier in &self.nullifiers {
            hasher.update(nullifier.as_bytes());
        }
        update_count(&mut hasher, self.outputs.len());
        for output in &self.outputs {
            hasher.update(output.commitment.as_bytes());
            hasher.update(output.ephemeral_key.as_bytes());
            update_bytes(&mut hasher, &output.ciphertext);
        }
        hasher.update(self.balance_commitment.as_bytes());
        hasher.update(self.burn.commitment.as_bytes());
        update_bytes(&mut hasher, &self.burn.ciphertext);
        hasher.update(&self.gas.units.to_le_bytes());
        hasher.update(&self.gas.fee_per_gas.to_le_bytes());
        PublicInputDigest::new(*hasher.finalize().as_bytes())
    }

    /// Computes the transaction identifier, including the exact proof bytes.
    #[must_use]
    pub fn transaction_id(&self) -> TransactionId {
        let mut hasher = Hasher::new_derive_key(TRANSACTION_ID_DOMAIN);
        hasher.update(self.public_inputs_digest().as_bytes());
        update_bytes(&mut hasher, &self.proof);
        TransactionId::new(*hasher.finalize().as_bytes())
    }
}

fn update_count(hasher: &mut Hasher, count: usize) {
    hasher.update(&(count as u64).to_le_bytes());
}

fn update_bytes(hasher: &mut Hasher, bytes: &[u8]) {
    update_count(hasher, bytes.len());
    hasher.update(bytes);
}
