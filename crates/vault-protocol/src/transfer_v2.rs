//! Canonical, proof-bound transfer-v2 transaction codec.

use std::collections::BTreeSet;

use blake3::Hasher;
use rand_core::{CryptoRng, RngCore};
use vault_burn::{BURN_ENCRYPTION_SCHEME_ID, BurnCiphertext, EpochBurnPublicKey};
use vault_privacy::{
    ActionNullifier, CanonicalValueCommitment, EncryptedNote, NOTE_CIPHERTEXT_BYTES, NoteTreeRoot,
    OUTGOING_CIPHERTEXT_BYTES, PreparedSpendAuthorization, RandomizedSpendValidatingKey,
    SpendAuthorization, SpendAuthorizationDigest, VaultSpendingKey, VerifiedOutputAuthorization,
};

use crate::{
    ChainId, CircuitId, GasParameters, MAX_PROOF_BYTES, ProtocolError, PublicInputDigest,
    TransactionId,
};

const PUBLIC_INPUT_DOMAIN: &str = "vault.protocol.transfer-v2.public-inputs.2026-08-22";
const TRANSACTION_ID_DOMAIN: &str = "vault.protocol.transfer-v2.transaction-id.2026-08-22";
const SIGNER_POLICY_DOMAIN: &str = "vault.protocol.transfer-v2.signer-policy.v1";

/// Canonical network-codec discriminator.
pub const TRANSFER_V2_MAGIC: [u8; 4] = *b"VLT2";
/// Consensus version implemented by this codec.
pub const TRANSFER_V2_PROTOCOL_VERSION: u16 = 2;
/// Fixed ciphertext size reserved for the activated epoch burn-encryption scheme.
pub const TRANSFER_V2_BURN_CIPHERTEXT_BYTES: usize = 64;
/// Allowed padded action buckets. The selected bucket remains public metadata.
pub const ALLOWED_TRANSFER_V2_ACTION_COUNTS: [usize; 4] = [2, 4, 8, 16];
/// Exact encoded bytes for one action, excluding its 64-byte authorization.
pub const TRANSFER_V2_ACTION_BYTES: usize =
    6 * 32 + NOTE_CIPHERTEXT_BYTES + OUTGOING_CIPHERTEXT_BYTES;

const FIXED_EFFECT_BYTES: usize =
    4 + 2 + 5 * 32 + 8 + 32 + TRANSFER_V2_BURN_CIPHERTEXT_BYTES + 8 + 8 + 1;
/// Bytes before the first action in the canonical effects encoding.
pub const TRANSFER_V2_EFFECT_HEADER_BYTES: usize = FIXED_EFFECT_BYTES;
/// Maximum exact effects bytes before proof length and authorizations.
pub const TRANSFER_V2_MAX_EFFECT_BYTES: usize = FIXED_EFFECT_BYTES + TRANSFER_V2_ACTION_BYTES * 16;
const AUTHORIZATION_BYTES: usize = 64;
/// Absolute decoder bound before any allocation.
pub const TRANSFER_V2_MAX_ENCODED_BYTES: usize = FIXED_EFFECT_BYTES
    + TRANSFER_V2_ACTION_BYTES * 16
    + 4
    + MAX_PROOF_BYTES
    + AUTHORIZATION_BYTES * 16;

/// Fixed-shape encrypted representation of the hidden mandatory burn.
///
/// `scheme_id` pins the exact threshold-encryption construction and parameters;
/// `epoch` selects its validator key. The activated proof circuit must constrain
/// the commitment and ciphertext to the same burn amount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBurnV2 {
    scheme_id: [u8; 32],
    key_id: [u8; 32],
    epoch: u64,
    commitment: CanonicalValueCommitment,
    ciphertext: [u8; TRANSFER_V2_BURN_CIPHERTEXT_BYTES],
}

impl EncryptedBurnV2 {
    /// Constructs a fixed-size burn payload for a non-zero scheme identifier.
    pub fn new(
        scheme_id: [u8; 32],
        key_id: [u8; 32],
        epoch: u64,
        commitment: CanonicalValueCommitment,
        ciphertext: [u8; TRANSFER_V2_BURN_CIPHERTEXT_BYTES],
    ) -> Result<Self, ProtocolError> {
        if scheme_id == [0; 32] {
            return Err(ProtocolError::ZeroBurnSchemeId);
        }
        if key_id == [0; 32] {
            return Err(ProtocolError::ZeroBurnKeyId);
        }
        if commitment.is_identity()
            || ciphertext == [0; TRANSFER_V2_BURN_CIPHERTEXT_BYTES]
            || (scheme_id == BURN_ENCRYPTION_SCHEME_ID
                && BurnCiphertext::from_bytes(ciphertext).is_err())
        {
            return Err(ProtocolError::InvalidBurnCiphertext);
        }
        Ok(Self {
            scheme_id,
            key_id,
            epoch,
            commitment,
            ciphertext,
        })
    }

    /// Constructs the pinned Pallas threshold-ElGamal payload from typed,
    /// canonically validated key and ciphertext data.
    pub fn from_threshold_ciphertext(
        epoch_key: &EpochBurnPublicKey,
        commitment: CanonicalValueCommitment,
        ciphertext: BurnCiphertext,
    ) -> Result<Self, ProtocolError> {
        Self::new(
            BURN_ENCRYPTION_SCHEME_ID,
            epoch_key.key_id(),
            epoch_key.epoch(),
            commitment,
            ciphertext.to_bytes(),
        )
    }

    /// Activated threshold-encryption scheme and parameter digest.
    #[must_use]
    pub const fn scheme_id(&self) -> [u8; 32] {
        self.scheme_id
    }

    /// Digest of the exact epoch threshold public key and participant policy.
    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    /// Validator-key epoch used by this ciphertext.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Hiding commitment to the burn amount.
    #[must_use]
    pub const fn commitment(&self) -> CanonicalValueCommitment {
        self.commitment
    }

    /// Exact scheme-specific ciphertext bytes.
    #[must_use]
    pub const fn ciphertext(&self) -> &[u8; TRANSFER_V2_BURN_CIPHERTEXT_BYTES] {
        &self.ciphertext
    }
}

/// One paired spend/output action in a padded transfer-v2 bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferV2Action {
    nullifier: ActionNullifier,
    randomized_verification_key: RandomizedSpendValidatingKey,
    net_value_commitment: CanonicalValueCommitment,
    output: EncryptedNote,
}

impl TransferV2Action {
    /// Creates a canonical action from already validated privacy types.
    #[must_use]
    pub const fn new(
        nullifier: ActionNullifier,
        randomized_verification_key: RandomizedSpendValidatingKey,
        net_value_commitment: CanonicalValueCommitment,
        output: EncryptedNote,
    ) -> Self {
        Self {
            nullifier,
            randomized_verification_key,
            net_value_commitment,
            output,
        }
    }

    /// Unique public marker of the consumed real or dummy note.
    #[must_use]
    pub const fn nullifier(&self) -> ActionNullifier {
        self.nullifier
    }

    /// Per-spend randomized RedPallas validating key.
    #[must_use]
    pub const fn randomized_verification_key(&self) -> RandomizedSpendValidatingKey {
        self.randomized_verification_key
    }

    /// Commitment to input value minus paired output value.
    #[must_use]
    pub const fn net_value_commitment(&self) -> CanonicalValueCommitment {
        self.net_value_commitment
    }

    /// Fixed-size authenticated output note.
    #[must_use]
    pub const fn output(&self) -> &EncryptedNote {
        &self.output
    }
}

/// Public effects proven by the activated transfer-v2 circuit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferV2Effects {
    chain_id: ChainId,
    circuit_id: CircuitId,
    anchor: NoteTreeRoot,
    burn: EncryptedBurnV2,
    gas: GasParameters,
    actions: Vec<TransferV2Action>,
}

impl TransferV2Effects {
    /// Builds a canonical public statement. Actions must be strictly sorted by
    /// nullifier and padded to an allowed bucket.
    pub fn new(
        chain_id: ChainId,
        circuit_id: CircuitId,
        anchor: NoteTreeRoot,
        burn: EncryptedBurnV2,
        gas: GasParameters,
        actions: Vec<TransferV2Action>,
    ) -> Result<Self, ProtocolError> {
        if chain_id.is_zero() {
            return Err(ProtocolError::InvalidConfiguration("chain id is zero"));
        }
        if circuit_id.is_zero() {
            return Err(ProtocolError::InvalidConfiguration("circuit id is zero"));
        }
        if gas.units == 0 || gas.fee_per_gas == 0 {
            return Err(ProtocolError::InvalidGasParameters);
        }
        gas.total_fee()?;
        if !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&actions.len()) {
            return Err(ProtocolError::InvalidActionCount {
                count: actions.len(),
            });
        }
        for pair in actions.windows(2) {
            let first = pair[0].nullifier();
            let second = pair[1].nullifier();
            if first == second {
                return Err(ProtocolError::DuplicateActionNullifier);
            }
            if first > second {
                return Err(ProtocolError::NonCanonicalActionOrder);
            }
        }
        let mut randomized_keys = BTreeSet::new();
        let mut note_commitments = BTreeSet::new();
        let mut output_value_commitments = BTreeSet::new();
        let mut ephemeral_keys = BTreeSet::new();
        for action in &actions {
            if !randomized_keys.insert(action.randomized_verification_key()) {
                return Err(ProtocolError::DuplicateRandomizedSpendKey);
            }
            if !note_commitments.insert(action.output().note_commitment()) {
                return Err(ProtocolError::DuplicateNoteCommitment(
                    crate::NoteCommitment::new(action.output().note_commitment()),
                ));
            }
            if !output_value_commitments.insert(action.output().value_commitment()) {
                return Err(ProtocolError::DuplicateOutputValueCommitment);
            }
            if !ephemeral_keys.insert(action.output().ephemeral_key()) {
                return Err(ProtocolError::DuplicateOutputEphemeralKey);
            }
        }

        Ok(Self {
            chain_id,
            circuit_id,
            anchor,
            burn,
            gas,
            actions,
        })
    }

    /// Network domain.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Exact activated proof program.
    #[must_use]
    pub const fn circuit_id(&self) -> CircuitId {
        self.circuit_id
    }

    /// Recent note-tree root used by all real input membership proofs.
    #[must_use]
    pub const fn anchor(&self) -> NoteTreeRoot {
        self.anchor
    }

    /// Proof-bound hidden burn payload.
    #[must_use]
    pub const fn burn(&self) -> &EncryptedBurnV2 {
        &self.burn
    }

    /// Public deterministic resource charge and fee bid.
    #[must_use]
    pub const fn gas(&self) -> GasParameters {
        self.gas
    }

    /// Canonically sorted paired actions, including padding.
    #[must_use]
    pub fn actions(&self) -> &[TransferV2Action] {
        &self.actions
    }

    /// Hash of the unique effects encoding consumed by the proof verifier.
    #[must_use]
    pub fn public_inputs_digest(&self) -> PublicInputDigest {
        let mut hasher = Hasher::new_derive_key(PUBLIC_INPUT_DOMAIN);
        hasher.update(&self.encode());
        PublicInputDigest::new(*hasher.finalize().as_bytes())
    }

    /// Canonical public effects bytes used by proofs, signatures, and private
    /// signer requests.
    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        self.encode()
    }

    /// Parses exact effects without accepting a proof or spend signatures.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > TRANSFER_V2_MAX_EFFECT_BYTES {
            return Err(ProtocolError::TransactionTooLarge {
                size: bytes.len(),
                maximum: TRANSFER_V2_MAX_EFFECT_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.take_array::<4>()? != TRANSFER_V2_MAGIC {
            return Err(ProtocolError::InvalidTransferV2Magic);
        }
        let version = u16::from_le_bytes(reader.take_array()?);
        if version != TRANSFER_V2_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                expected: TRANSFER_V2_PROTOCOL_VERSION,
                actual: version,
            });
        }
        let chain_id = ChainId::new(reader.take_array()?);
        let circuit_id = CircuitId::new(reader.take_array()?);
        let anchor = NoteTreeRoot::from_bytes(reader.take_array()?)
            .map_err(|_| ProtocolError::InvalidNoteTreeRoot)?;
        let burn_scheme_id = reader.take_array()?;
        let burn_key_id = reader.take_array()?;
        let burn_epoch = u64::from_le_bytes(reader.take_array()?);
        let burn_commitment = CanonicalValueCommitment::from_bytes(reader.take_array()?)
            .map_err(|_| ProtocolError::InvalidValueCommitment)?;
        let burn_ciphertext = reader.take_array()?;
        let gas = GasParameters {
            units: u64::from_le_bytes(reader.take_array()?),
            fee_per_gas: u64::from_le_bytes(reader.take_array()?),
        };
        let action_count = usize::from(reader.take_byte()?);
        if !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&action_count) {
            return Err(ProtocolError::InvalidActionCount {
                count: action_count,
            });
        }
        let expected_length = FIXED_EFFECT_BYTES
            .checked_add(TRANSFER_V2_ACTION_BYTES * action_count)
            .ok_or(ProtocolError::InvalidTransferV2Encoding(
                "effects length overflow",
            ))?;
        if bytes.len() != expected_length {
            return Err(ProtocolError::InvalidTransferV2Encoding(
                "effects length mismatch",
            ));
        }
        let mut actions = Vec::with_capacity(action_count);
        for _ in 0..action_count {
            let nullifier = ActionNullifier::from_bytes(reader.take_array()?)
                .map_err(|_| ProtocolError::InvalidActionNullifier)?;
            let randomized_verification_key =
                RandomizedSpendValidatingKey::from_bytes(reader.take_array()?)
                    .map_err(|_| ProtocolError::InvalidRandomizedSpendKey)?;
            let net_value_commitment = CanonicalValueCommitment::from_bytes(reader.take_array()?)
                .map_err(|_| ProtocolError::InvalidValueCommitment)?;
            let output = EncryptedNote::from_parts(
                reader.take_array()?,
                reader.take_array()?,
                reader.take_array()?,
                reader.take_array()?,
                reader.take_array()?,
            )
            .map_err(|_| ProtocolError::InvalidEncryptedNote)?;
            actions.push(TransferV2Action::new(
                nullifier,
                randomized_verification_key,
                net_value_commitment,
                output,
            ));
        }
        reader.finish()?;
        let burn = EncryptedBurnV2::new(
            burn_scheme_id,
            burn_key_id,
            burn_epoch,
            burn_commitment,
            burn_ciphertext,
        )?;
        Self::new(chain_id, circuit_id, anchor, burn, gas, actions)
    }

    fn authorization_digest(&self) -> SpendAuthorizationDigest {
        SpendAuthorizationDigest::derive(
            *self.chain_id.as_bytes(),
            *self.public_inputs_digest().as_bytes(),
        )
        .expect("TransferV2Effects rejects the zero chain ID")
    }

    fn encoded_len(&self) -> usize {
        FIXED_EFFECT_BYTES + TRANSFER_V2_ACTION_BYTES * self.actions.len()
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&TRANSFER_V2_MAGIC);
        bytes.extend_from_slice(&TRANSFER_V2_PROTOCOL_VERSION.to_le_bytes());
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(self.circuit_id.as_bytes());
        bytes.extend_from_slice(&self.anchor.to_bytes());
        bytes.extend_from_slice(&self.burn.scheme_id);
        bytes.extend_from_slice(&self.burn.key_id);
        bytes.extend_from_slice(&self.burn.epoch.to_le_bytes());
        bytes.extend_from_slice(&self.burn.commitment.to_bytes());
        bytes.extend_from_slice(&self.burn.ciphertext);
        bytes.extend_from_slice(&self.gas.units.to_le_bytes());
        bytes.extend_from_slice(&self.gas.fee_per_gas.to_le_bytes());
        bytes.push(
            u8::try_from(self.actions.len()).expect("transfer-v2 action count is at most 16"),
        );
        for action in &self.actions {
            bytes.extend_from_slice(&action.nullifier.to_bytes());
            bytes.extend_from_slice(&action.randomized_verification_key.to_bytes());
            bytes.extend_from_slice(&action.net_value_commitment.to_bytes());
            let output = &action.output;
            bytes.extend_from_slice(&output.note_commitment());
            bytes.extend_from_slice(&output.value_commitment());
            bytes.extend_from_slice(&output.ephemeral_key());
            bytes.extend_from_slice(output.note_ciphertext());
            bytes.extend_from_slice(output.outgoing_ciphertext());
        }
        debug_assert_eq!(bytes.len(), self.encoded_len());
        bytes
    }
}

/// Exact domains, burn descriptor, padded shape, and gas ceilings approved by
/// a signer before it considers any transfer-v2 effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferV2SignerPolicy {
    chain_id: ChainId,
    circuit_id: CircuitId,
    burn_scheme_id: [u8; 32],
    burn_key_id: [u8; 32],
    burn_epoch: u64,
    action_count: usize,
    gas_units: u64,
    maximum_fee_per_gas: u64,
    maximum_gas_fee: u128,
}

impl TransferV2SignerPolicy {
    /// Creates a fail-closed signing policy for one exact activated suite.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        circuit_id: CircuitId,
        burn_scheme_id: [u8; 32],
        burn_key_id: [u8; 32],
        burn_epoch: u64,
        action_count: usize,
        gas_units: u64,
        maximum_fee_per_gas: u64,
        maximum_gas_fee: u128,
    ) -> Result<Self, ProtocolError> {
        if chain_id.is_zero()
            || circuit_id.is_zero()
            || burn_scheme_id == [0; 32]
            || burn_key_id == [0; 32]
            || !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&action_count)
            || gas_units == 0
            || maximum_fee_per_gas == 0
            || maximum_gas_fee == 0
        {
            return Err(ProtocolError::InvalidConfiguration(
                "invalid transfer-v2 signer policy",
            ));
        }
        Ok(Self {
            chain_id,
            circuit_id,
            burn_scheme_id,
            burn_key_id,
            burn_epoch,
            action_count,
            gas_units,
            maximum_fee_per_gas,
            maximum_gas_fee,
        })
    }

    /// Validates complete effects and one independently reconstructed output
    /// token per action before exposing a signable digest.
    pub fn prepare(
        &self,
        effects: &TransferV2Effects,
        output_authorizations: Vec<VerifiedOutputAuthorization>,
    ) -> Result<PreparedTransferV2Authorization, ProtocolError> {
        if effects.chain_id != self.chain_id {
            return Err(ProtocolError::WrongChainId {
                expected: self.chain_id,
                actual: effects.chain_id,
            });
        }
        if effects.circuit_id != self.circuit_id {
            return Err(ProtocolError::WrongCircuitId {
                expected: self.circuit_id,
                actual: effects.circuit_id,
            });
        }
        if effects.burn.scheme_id != self.burn_scheme_id {
            return Err(ProtocolError::WrongBurnSchemeId);
        }
        if effects.burn.key_id != self.burn_key_id {
            return Err(ProtocolError::WrongBurnKeyId);
        }
        if effects.burn.epoch != self.burn_epoch {
            return Err(ProtocolError::WrongBurnEpoch {
                expected: self.burn_epoch,
                actual: effects.burn.epoch,
            });
        }
        if effects.actions.len() != self.action_count {
            return Err(ProtocolError::InvalidActionCount {
                count: effects.actions.len(),
            });
        }
        if effects.gas.units != self.gas_units {
            return Err(ProtocolError::IncorrectGasUnits {
                expected: self.gas_units,
                actual: effects.gas.units,
            });
        }
        if effects.gas.fee_per_gas > self.maximum_fee_per_gas {
            return Err(ProtocolError::FeePerGasTooHigh {
                maximum: self.maximum_fee_per_gas,
                actual: effects.gas.fee_per_gas,
            });
        }
        let gas_fee = effects.gas.total_fee()?;
        if gas_fee > self.maximum_gas_fee {
            return Err(ProtocolError::GasFeeTooHigh {
                maximum: self.maximum_gas_fee,
                actual: gas_fee,
            });
        }
        if output_authorizations.len() != effects.actions.len() {
            return Err(ProtocolError::OutputAuthorizationCountMismatch {
                expected: effects.actions.len(),
                actual: output_authorizations.len(),
            });
        }
        for (action, authorization) in effects.actions.iter().zip(&output_authorizations) {
            if authorization.network_id() != *effects.chain_id.as_bytes()
                || !authorization.matches_action(action.nullifier, &action.output)
            {
                return Err(ProtocolError::InvalidOutputAuthorization);
            }
        }

        Ok(PreparedTransferV2Authorization {
            public_inputs: effects.public_inputs_digest(),
            authorization_digest: effects.authorization_digest(),
            randomized_keys: effects
                .actions
                .iter()
                .map(|action| action.randomized_verification_key)
                .collect(),
            output_authorizations,
        })
    }

    /// Canonical digest of every signer-approved domain and resource ceiling.
    #[must_use]
    pub fn signer_policy_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(SIGNER_POLICY_DOMAIN);
        hasher.update(self.chain_id.as_bytes());
        hasher.update(self.circuit_id.as_bytes());
        hasher.update(&self.burn_scheme_id);
        hasher.update(&self.burn_key_id);
        hasher.update(&self.burn_epoch.to_le_bytes());
        hasher.update(
            &u8::try_from(self.action_count)
                .expect("validated action buckets fit in u8")
                .to_le_bytes(),
        );
        hasher.update(&self.gas_units.to_le_bytes());
        hasher.update(&self.maximum_fee_per_gas.to_le_bytes());
        hasher.update(&self.maximum_gas_fee.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Opaque, policy-checked transfer-v2 signing session.
///
/// It owns every verified output token so a coordinator cannot substitute an
/// output between packet validation and RedPallas signing.
pub struct PreparedTransferV2Authorization {
    public_inputs: PublicInputDigest,
    authorization_digest: SpendAuthorizationDigest,
    randomized_keys: Vec<RandomizedSpendValidatingKey>,
    output_authorizations: Vec<VerifiedOutputAuthorization>,
}

impl core::fmt::Debug for PreparedTransferV2Authorization {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedTransferV2Authorization")
            .field("action_count", &self.randomized_keys.len())
            .field("private_output_authorizations", &"REDACTED")
            .finish()
    }
}

impl PreparedTransferV2Authorization {
    /// Exact public-input digest this session has approved.
    #[must_use]
    pub const fn public_inputs_digest(&self) -> PublicInputDigest {
        self.public_inputs
    }

    /// Signs one exact action only when its prepared randomized key and output
    /// token were both validated under the same spending account.
    pub fn sign_action<R: RngCore + CryptoRng>(
        &self,
        action_index: usize,
        spending_key: &VaultSpendingKey,
        prepared: &PreparedSpendAuthorization,
        rng: &mut R,
    ) -> Result<SpendAuthorization, ProtocolError> {
        let expected_key = self.randomized_keys.get(action_index).ok_or(
            ProtocolError::InvalidAuthorizationIndex {
                index: action_index,
                action_count: self.randomized_keys.len(),
            },
        )?;
        let output_authorization = self.output_authorizations.get(action_index).ok_or(
            ProtocolError::InvalidAuthorizationIndex {
                index: action_index,
                action_count: self.output_authorizations.len(),
            },
        )?;
        if prepared.randomized_verification_key() != expected_key.to_bytes()
            || !output_authorization.verified_for(&spending_key.full_viewing_key())
        {
            return Err(ProtocolError::InvalidOutputAuthorization);
        }
        spending_key
            .sign_spend_authorization(prepared, self.authorization_digest, rng)
            .map_err(|_| ProtocolError::InvalidSpendAuthorization)
    }
}

/// Fully authorized transfer-v2 transaction with canonical binary encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferV2 {
    effects: TransferV2Effects,
    proof: Vec<u8>,
    authorizations: Vec<SpendAuthorization>,
}

impl TransferV2 {
    /// Attaches a bounded proof and one valid authorization per padded action.
    pub fn new(
        effects: TransferV2Effects,
        proof: Vec<u8>,
        authorizations: Vec<SpendAuthorization>,
    ) -> Result<Self, ProtocolError> {
        validate_proof_size(&proof)?;
        if authorizations.len() != effects.actions.len() {
            return Err(ProtocolError::AuthorizationCountMismatch {
                expected: effects.actions.len(),
                actual: authorizations.len(),
            });
        }
        let transfer = Self {
            effects,
            proof,
            authorizations,
        };
        transfer.verify_authorizations()?;
        Ok(transfer)
    }

    /// Parses an exact canonical transaction and rejects trailing bytes,
    /// malformed cryptographic encodings, invalid signatures, and oversized
    /// allocations before proof verification.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > TRANSFER_V2_MAX_ENCODED_BYTES {
            return Err(ProtocolError::TransactionTooLarge {
                size: bytes.len(),
                maximum: TRANSFER_V2_MAX_ENCODED_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.take_array::<4>()? != TRANSFER_V2_MAGIC {
            return Err(ProtocolError::InvalidTransferV2Magic);
        }
        let version = u16::from_le_bytes(reader.take_array()?);
        if version != TRANSFER_V2_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                expected: TRANSFER_V2_PROTOCOL_VERSION,
                actual: version,
            });
        }

        let chain_id = ChainId::new(reader.take_array()?);
        let circuit_id = CircuitId::new(reader.take_array()?);
        let anchor = NoteTreeRoot::from_bytes(reader.take_array()?)
            .map_err(|_| ProtocolError::InvalidNoteTreeRoot)?;
        let burn_scheme_id = reader.take_array()?;
        let burn_key_id = reader.take_array()?;
        let burn_epoch = u64::from_le_bytes(reader.take_array()?);
        let burn_commitment = CanonicalValueCommitment::from_bytes(reader.take_array()?)
            .map_err(|_| ProtocolError::InvalidValueCommitment)?;
        let burn_ciphertext = reader.take_array()?;
        let gas = GasParameters {
            units: u64::from_le_bytes(reader.take_array()?),
            fee_per_gas: u64::from_le_bytes(reader.take_array()?),
        };
        let action_count = usize::from(reader.take_byte()?);
        if !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&action_count) {
            return Err(ProtocolError::InvalidActionCount {
                count: action_count,
            });
        }

        let mut actions = Vec::with_capacity(action_count);
        for _ in 0..action_count {
            let nullifier = ActionNullifier::from_bytes(reader.take_array()?)
                .map_err(|_| ProtocolError::InvalidActionNullifier)?;
            let randomized_verification_key =
                RandomizedSpendValidatingKey::from_bytes(reader.take_array()?)
                    .map_err(|_| ProtocolError::InvalidRandomizedSpendKey)?;
            let net_value_commitment = CanonicalValueCommitment::from_bytes(reader.take_array()?)
                .map_err(|_| ProtocolError::InvalidValueCommitment)?;
            let note_commitment = reader.take_array()?;
            let output_value_commitment = reader.take_array()?;
            let ephemeral_key = reader.take_array()?;
            let note_ciphertext = reader.take_array()?;
            let outgoing_ciphertext = reader.take_array()?;
            let output = EncryptedNote::from_parts(
                note_commitment,
                output_value_commitment,
                ephemeral_key,
                note_ciphertext,
                outgoing_ciphertext,
            )
            .map_err(|_| ProtocolError::InvalidEncryptedNote)?;
            actions.push(TransferV2Action::new(
                nullifier,
                randomized_verification_key,
                net_value_commitment,
                output,
            ));
        }

        let proof_len = usize::try_from(u32::from_le_bytes(reader.take_array()?))
            .map_err(|_| ProtocolError::InvalidTransferV2Encoding("proof length"))?;
        if proof_len == 0 {
            return Err(ProtocolError::EmptyProof);
        }
        if proof_len > MAX_PROOF_BYTES {
            return Err(ProtocolError::ProofTooLarge {
                size: proof_len,
                maximum: MAX_PROOF_BYTES,
            });
        }
        let authorization_bytes = action_count.checked_mul(AUTHORIZATION_BYTES).ok_or(
            ProtocolError::InvalidTransferV2Encoding("authorization length overflow"),
        )?;
        let expected_remaining = proof_len.checked_add(authorization_bytes).ok_or(
            ProtocolError::InvalidTransferV2Encoding("remaining length overflow"),
        )?;
        if reader.remaining() != expected_remaining {
            return Err(ProtocolError::InvalidTransferV2Encoding(
                "encoded length mismatch",
            ));
        }
        let proof = reader.take(proof_len)?.to_vec();
        let mut authorizations = Vec::with_capacity(action_count);
        for action in &actions {
            let signature = reader.take_array()?;
            authorizations.push(
                SpendAuthorization::from_parts(
                    action.randomized_verification_key().to_bytes(),
                    signature,
                )
                .map_err(|_| ProtocolError::InvalidSpendAuthorization)?,
            );
        }
        reader.finish()?;

        let burn = EncryptedBurnV2::new(
            burn_scheme_id,
            burn_key_id,
            burn_epoch,
            burn_commitment,
            burn_ciphertext,
        )?;
        let effects = TransferV2Effects::new(chain_id, circuit_id, anchor, burn, gas, actions)?;
        Self::new(effects, proof, authorizations)
    }

    /// Canonical byte representation used on disk, on the wire, and for txid.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.effects.encode();
        bytes.extend_from_slice(
            &u32::try_from(self.proof.len())
                .expect("proof size is bounded below u32::MAX")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.proof);
        for authorization in &self.authorizations {
            bytes.extend_from_slice(&authorization.signature());
        }
        debug_assert_eq!(bytes.len(), self.encoded_len());
        bytes
    }

    /// Number of bytes in the canonical encoding.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.effects.encoded_len()
            + 4
            + self.proof.len()
            + AUTHORIZATION_BYTES * self.authorizations.len()
    }

    /// Public proof-bound effects.
    #[must_use]
    pub const fn effects(&self) -> &TransferV2Effects {
        &self.effects
    }

    /// Opaque proof for the exact activated circuit ID.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// One RedPallas authorization for every real or dummy action.
    #[must_use]
    pub fn authorizations(&self) -> &[SpendAuthorization] {
        &self.authorizations
    }

    /// Public-input digest supplied to the fail-closed proof verifier.
    #[must_use]
    pub fn public_inputs_digest(&self) -> PublicInputDigest {
        self.effects.public_inputs_digest()
    }

    /// Content identifier over the complete canonical bytes, including proof
    /// and spend authorizations.
    #[must_use]
    pub fn transaction_id(&self) -> TransactionId {
        let mut hasher = Hasher::new_derive_key(TRANSACTION_ID_DOMAIN);
        hasher.update(&self.encode());
        TransactionId::new(*hasher.finalize().as_bytes())
    }

    /// Rechecks every action signature against the exact effects digest.
    pub fn verify_authorizations(&self) -> Result<(), ProtocolError> {
        let digest = self.effects.authorization_digest();
        for (action, authorization) in self.effects.actions.iter().zip(&self.authorizations) {
            if authorization.validating_key() != action.randomized_verification_key()
                || !authorization.verify(digest)
            {
                return Err(ProtocolError::InvalidSpendAuthorization);
            }
        }
        Ok(())
    }

    /// Replaces only the proof bytes. Signatures remain valid because they bind
    /// transaction effects, while txid commits to the selected proof encoding.
    pub fn with_proof(mut self, proof: Vec<u8>) -> Result<Self, ProtocolError> {
        validate_proof_size(&proof)?;
        self.proof = proof;
        Ok(self)
    }
}

fn validate_proof_size(proof: &[u8]) -> Result<(), ProtocolError> {
    if proof.is_empty() {
        return Err(ProtocolError::EmptyProof);
    }
    if proof.len() > MAX_PROOF_BYTES {
        return Err(ProtocolError::ProofTooLarge {
            size: proof.len(),
            maximum: MAX_PROOF_BYTES,
        });
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ProtocolError::InvalidTransferV2Encoding("offset overflow"))?;
        let value =
            self.bytes
                .get(self.offset..end)
                .ok_or(ProtocolError::InvalidTransferV2Encoding(
                    "truncated transaction",
                ))?;
        self.offset = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProtocolError::InvalidTransferV2Encoding("invalid fixed field"))
    }

    fn take_byte(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(ProtocolError::InvalidTransferV2Encoding(
                "trailing transaction bytes",
            ))
        }
    }
}
