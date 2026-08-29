//! Canonical private witness package for delegated transfer proving.
//!
//! This codec does not create a transport or authorize a spend. It makes the
//! complete disclosure required by the selected monolithic circuit explicit,
//! bounded, reproducible, and independently reconstructible before proving.

use thiserror::Error;
use vault_burn::{
    BurnCiphertext, BurnEncryptionError, EpochBurnPublicKey, MAX_BURN_PARTICIPANTS,
    PreparedBurnCiphertext,
};
use vault_privacy::{
    NoteMembershipPath, OUTPUT_AUTHORIZATION_PACKET_BYTES, OutputAuthorizationError,
    OutputAuthorizationPacket, OutputKind, PRIVATE_NOTE_BYTES, PreparedBurnCommitment,
    PreparedNetValueCommitment, PreparedSpendAuthorization, PrivacyError, PrivateNote,
    VaultFullViewingKey, circuit::PreparedActionCircuit,
};
use vault_protocol::{ALLOWED_TRANSFER_V2_ACTION_COUNTS, TransferV2Effects};
use zeroize::Zeroizing;

use crate::{
    accounting::{
        AccountingActionWitness, AccountingArithmeticError, PreparedAccountingArithmetic,
    },
    burn_binding::{BurnBindingError, PreparedAccountingBurn},
    transfer_circuit::{PreparedVaultTransfer, VaultTransferPreparationError},
};

const WITNESS_MAGIC: [u8; 4] = *b"VDPW";
const WITNESS_VERSION: u16 = 1;
const DISCLOSURE_PROFILE: u8 = 1;
const WITNESS_HEADER_BYTES: usize = 4 + 2 + 1 + 1 + 32 + 32 + 32 + 8 + 96;
const MEMBERSHIP_PATH_BYTES: usize = 4 + 32 * 32;
const ACTION_WITNESS_BYTES: usize =
    PRIVATE_NOTE_BYTES + MEMBERSHIP_PATH_BYTES + 32 + 32 + OUTPUT_AUTHORIZATION_PACKET_BYTES;
const EPOCH_FIXED_BYTES: usize = 8 + 2 + 2 + 2;
const BURN_OPENING_BYTES: usize = 32 + 32;

/// Maximum exact v1 witness bytes at 16 Actions and 512 DKG participants.
pub const DELEGATED_TRANSFER_WITNESS_MAX_BYTES: usize = WITNESS_HEADER_BYTES
    + ACTION_WITNESS_BYTES * 16
    + EPOCH_FIXED_BYTES
    + MAX_BURN_PARTICIPANTS * 2
    + MAX_BURN_PARTICIPANTS * 32
    + BURN_OPENING_BYTES;

/// Private inputs for one sorted transfer Action.
pub struct DelegatedActionWitness {
    input_note: PrivateNote,
    membership_path: NoteMembershipPath,
    authorization_randomizer: Zeroizing<[u8; 32]>,
    net_value_trapdoor: Zeroizing<[u8; 32]>,
    output_packet: OutputAuthorizationPacket,
}

impl core::fmt::Debug for DelegatedActionWitness {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DelegatedActionWitness(REDACTED)")
    }
}

impl DelegatedActionWitness {
    /// Collects already-canonical private Action inputs for one witness package.
    #[must_use]
    pub fn new(
        input_note: PrivateNote,
        membership_path: NoteMembershipPath,
        authorization_randomizer: [u8; 32],
        net_value_trapdoor: [u8; 32],
        output_packet: OutputAuthorizationPacket,
    ) -> Self {
        Self {
            input_note,
            membership_path,
            authorization_randomizer: Zeroizing::new(authorization_randomizer),
            net_value_trapdoor: Zeroizing::new(net_value_trapdoor),
            output_packet,
        }
    }
}

/// Complete versioned witness disclosed to one delegated prover job.
pub struct DelegatedTransferWitness<const N: usize> {
    network_id: [u8; 32],
    circuit_id: [u8; 32],
    effects_digest: [u8; 32],
    maximum_value: u64,
    full_viewing_key: VaultFullViewingKey,
    actions: [DelegatedActionWitness; N],
    epoch_key: EpochBurnPublicKey,
    burn_commitment_trapdoor: Zeroizing<[u8; 32]>,
    burn_encryption_randomness: Zeroizing<[u8; 32]>,
}

impl<const N: usize> core::fmt::Debug for DelegatedTransferWitness<N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DelegatedTransferWitness")
            .field("action_count", &N)
            .field("encoded_bytes", &self.encoded_len())
            .field("private_witness", &"REDACTED")
            .finish()
    }
}

impl<const N: usize> DelegatedTransferWitness<N> {
    /// Binds a complete typed witness to exact canonical public effects.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        effects: &TransferV2Effects,
        maximum_value: u64,
        full_viewing_key: VaultFullViewingKey,
        actions: [DelegatedActionWitness; N],
        epoch_key: EpochBurnPublicKey,
        burn_commitment_trapdoor: [u8; 32],
        burn_encryption_randomness: [u8; 32],
    ) -> Result<Self, DelegatedWitnessError> {
        if !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&N)
            || effects.actions().len() != N
            || effects.chain_id().is_zero()
            || effects.circuit_id().is_zero()
            || maximum_value == 0
            || effects.burn().epoch() != epoch_key.epoch()
            || effects.burn().key_id() != epoch_key.key_id()
        {
            return Err(DelegatedWitnessError::PublicEffectsMismatch);
        }
        Ok(Self {
            network_id: effects.chain_id().into_bytes(),
            circuit_id: effects.circuit_id().into_bytes(),
            effects_digest: effects.public_inputs_digest().into_bytes(),
            maximum_value,
            full_viewing_key,
            actions,
            epoch_key,
            burn_commitment_trapdoor: Zeroizing::new(burn_commitment_trapdoor),
            burn_encryption_randomness: Zeroizing::new(burn_encryption_randomness),
        })
    }

    /// Parses every private field with strict pre-allocation bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, DelegatedWitnessError> {
        if bytes.len() > DELEGATED_TRANSFER_WITNESS_MAX_BYTES {
            return Err(DelegatedWitnessError::InvalidEncoding);
        }
        let mut reader = Reader::new(bytes);
        if reader.take::<4>()? != WITNESS_MAGIC
            || u16::from_le_bytes(reader.take()?) != WITNESS_VERSION
            || reader.take::<1>()?[0] != DISCLOSURE_PROFILE
            || usize::from(reader.take::<1>()?[0]) != N
            || !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&N)
        {
            return Err(DelegatedWitnessError::InvalidEncoding);
        }
        let network_id = reader.take()?;
        let circuit_id = reader.take()?;
        let effects_digest = reader.take()?;
        let maximum_value = u64::from_le_bytes(reader.take()?);
        if network_id == [0; 32]
            || circuit_id == [0; 32]
            || effects_digest == [0; 32]
            || maximum_value == 0
        {
            return Err(DelegatedWitnessError::InvalidEncoding);
        }
        let full_viewing_key = VaultFullViewingKey::from_bytes(reader.take()?)?;
        let mut actions = Vec::with_capacity(N);
        for _ in 0..N {
            let input_note = PrivateNote::decode_private(reader.take()?, maximum_value)?;
            let position = u32::from_le_bytes(reader.take()?);
            let mut auth_path = [[0_u8; 32]; 32];
            for node in &mut auth_path {
                *node = reader.take()?;
            }
            let membership_path = NoteMembershipPath::from_parts(position, auth_path)?;
            let authorization_randomizer = reader.take()?;
            let net_value_trapdoor = reader.take()?;
            let output_packet = OutputAuthorizationPacket::decode(
                reader.take_slice(OUTPUT_AUTHORIZATION_PACKET_BYTES)?,
            )?;
            actions.push(DelegatedActionWitness::new(
                input_note,
                membership_path,
                authorization_randomizer,
                net_value_trapdoor,
                output_packet,
            ));
        }
        let actions = actions
            .try_into()
            .map_err(|_| DelegatedWitnessError::InvalidEncoding)?;
        let epoch = u64::from_le_bytes(reader.take()?);
        let threshold = u16::from_le_bytes(reader.take()?);
        let participant_count = usize::from(u16::from_le_bytes(reader.take()?));
        if participant_count == 0 || participant_count > MAX_BURN_PARTICIPANTS {
            return Err(DelegatedWitnessError::InvalidEncoding);
        }
        let mut participants = Vec::with_capacity(participant_count);
        for _ in 0..participant_count {
            participants.push(u16::from_le_bytes(reader.take()?));
        }
        let commitment_count = usize::from(u16::from_le_bytes(reader.take()?));
        if commitment_count != usize::from(threshold) || commitment_count > MAX_BURN_PARTICIPANTS {
            return Err(DelegatedWitnessError::InvalidEncoding);
        }
        let mut commitments = Vec::with_capacity(commitment_count);
        for _ in 0..commitment_count {
            commitments.push(reader.take()?);
        }
        let epoch_key =
            EpochBurnPublicKey::from_parts(epoch, threshold, participants, commitments)?;
        let burn_commitment_trapdoor = reader.take()?;
        let burn_encryption_randomness = reader.take()?;
        if !reader.is_empty() {
            return Err(DelegatedWitnessError::InvalidEncoding);
        }
        let witness = Self {
            network_id,
            circuit_id,
            effects_digest,
            maximum_value,
            full_viewing_key,
            actions,
            epoch_key,
            burn_commitment_trapdoor: Zeroizing::new(burn_commitment_trapdoor),
            burn_encryption_randomness: Zeroizing::new(burn_encryption_randomness),
        };
        let canonical = witness.encode();
        if canonical.as_slice() != bytes {
            return Err(DelegatedWitnessError::InvalidEncoding);
        }
        Ok(witness)
    }

    /// Canonical, non-extensible private witness bytes.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(self.encoded_len()));
        bytes.extend_from_slice(&WITNESS_MAGIC);
        bytes.extend_from_slice(&WITNESS_VERSION.to_le_bytes());
        bytes.push(DISCLOSURE_PROFILE);
        bytes.push(u8::try_from(N).expect("canonical Action count fits u8"));
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.circuit_id);
        bytes.extend_from_slice(&self.effects_digest);
        bytes.extend_from_slice(&self.maximum_value.to_le_bytes());
        bytes.extend_from_slice(self.full_viewing_key.export().as_ref());
        for action in &self.actions {
            bytes.extend_from_slice(action.input_note.encode_private().as_ref());
            bytes.extend_from_slice(&action.membership_path.position().to_le_bytes());
            for node in action.membership_path.auth_path() {
                bytes.extend_from_slice(node);
            }
            bytes.extend_from_slice(action.authorization_randomizer.as_ref());
            bytes.extend_from_slice(action.net_value_trapdoor.as_ref());
            bytes.extend_from_slice(action.output_packet.encode().as_ref());
        }
        bytes.extend_from_slice(&self.epoch_key.epoch().to_le_bytes());
        bytes.extend_from_slice(&self.epoch_key.threshold().to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(self.epoch_key.participants().len())
                .expect("epoch participant bound fits u16")
                .to_le_bytes(),
        );
        for participant in self.epoch_key.participants() {
            bytes.extend_from_slice(&participant.to_le_bytes());
        }
        bytes.extend_from_slice(
            &u16::try_from(self.epoch_key.coefficient_commitments().len())
                .expect("epoch commitment bound fits u16")
                .to_le_bytes(),
        );
        for commitment in self.epoch_key.coefficient_commitments() {
            bytes.extend_from_slice(commitment);
        }
        bytes.extend_from_slice(self.burn_commitment_trapdoor.as_ref());
        bytes.extend_from_slice(self.burn_encryption_randomness.as_ref());
        debug_assert_eq!(bytes.len(), self.encoded_len());
        bytes
    }

    /// Exact package length before transport encryption.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        WITNESS_HEADER_BYTES
            + ACTION_WITNESS_BYTES * N
            + EPOCH_FIXED_BYTES
            + self.epoch_key.participants().len() * 2
            + self.epoch_key.coefficient_commitments().len() * 32
            + BURN_OPENING_BYTES
    }

    /// Reconstructs every selected circuit input against independent effects.
    pub fn prepare(
        self,
        effects: &TransferV2Effects,
    ) -> Result<PreparedVaultTransfer<N>, DelegatedWitnessError> {
        if effects.chain_id().as_bytes() != &self.network_id
            || effects.circuit_id().as_bytes() != &self.circuit_id
            || effects.public_inputs_digest().as_bytes() != &self.effects_digest
            || effects.actions().len() != N
            || effects.burn().epoch() != self.epoch_key.epoch()
            || effects.burn().key_id() != self.epoch_key.key_id()
        {
            return Err(DelegatedWitnessError::PublicEffectsMismatch);
        }
        let group_key = self.full_viewing_key.spend_validating_key();
        let mut circuits = Vec::with_capacity(N);
        let mut accounting = Vec::with_capacity(N);
        for (private, public) in self.actions.into_iter().zip(effects.actions()) {
            let input_value = private.input_note.value();
            let (output, kind) = private.output_packet.into_proving_witness(
                &self.full_viewing_key,
                self.network_id,
                public.nullifier(),
                public.output(),
                self.maximum_value,
            )?;
            let output_value = output.note().value();
            let authorization = PreparedSpendAuthorization::from_proving_witness(
                group_key,
                public.randomized_verification_key().to_bytes(),
                *private.authorization_randomizer,
            )?;
            let net_value = PreparedNetValueCommitment::from_proving_witness(
                input_value,
                output_value,
                *private.net_value_trapdoor,
                public.net_value_commitment(),
            )?;
            circuits.push(PreparedActionCircuit::new(
                &self.full_viewing_key,
                &private.input_note,
                &private.membership_path,
                &output,
                &authorization,
                &net_value,
                effects.anchor(),
            )?);
            accounting.push(match kind {
                OutputKind::ExternalPayment => {
                    AccountingActionWitness::enabled(input_value, output_value, true)
                }
                OutputKind::InternalChange => {
                    AccountingActionWitness::enabled(input_value, output_value, false)
                }
                OutputKind::Dummy if input_value == 0 && output_value == 0 => {
                    AccountingActionWitness::dummy()
                }
                OutputKind::Dummy => return Err(DelegatedWitnessError::InvalidDummyAction),
            });
        }
        let accounting = accounting
            .try_into()
            .map_err(|_| DelegatedWitnessError::InvalidEncoding)?;
        let arithmetic = PreparedAccountingArithmetic::new(
            accounting,
            effects.gas().units,
            effects.gas().fee_per_gas,
        )?;
        let burn_amount = arithmetic.burn();
        let burn_commitment = PreparedBurnCommitment::from_proving_witness(
            burn_amount,
            self.maximum_value,
            *self.burn_commitment_trapdoor,
            effects.burn().commitment(),
        )?;
        let burn_ciphertext = PreparedBurnCiphertext::from_proving_witness(
            burn_amount,
            self.maximum_value,
            &self.epoch_key,
            *self.burn_encryption_randomness,
            BurnCiphertext::from_bytes(*effects.burn().ciphertext())?,
        )?;
        let accounting = PreparedAccountingBurn::new(
            arithmetic,
            &burn_commitment,
            &burn_ciphertext,
            &self.epoch_key,
        )?;
        PreparedVaultTransfer::new(circuits, accounting, effects, &self.epoch_key)
            .map_err(Into::into)
    }
}

/// Fail-closed delegated witness parsing or reconstruction failure.
#[derive(Debug, Error)]
pub enum DelegatedWitnessError {
    /// Length, header, count, reserved field or trailing bytes are invalid.
    #[error("invalid delegated witness encoding")]
    InvalidEncoding,
    /// Public domains, digest, bucket or DKG identity do not match.
    #[error("delegated witness differs from canonical public effects")]
    PublicEffectsMismatch,
    /// A dummy output is paired with a non-zero private input or output.
    #[error("delegated witness contains an invalid dummy action")]
    InvalidDummyAction,
    /// A private note, path, key, scalar or commitment is invalid.
    #[error(transparent)]
    Privacy(#[from] PrivacyError),
    /// A private output packet is malformed or does not reconstruct.
    #[error(transparent)]
    Output(#[from] OutputAuthorizationError),
    /// The public DKG or burn randomness/ciphertext is invalid.
    #[error(transparent)]
    Burn(#[from] BurnEncryptionError),
    /// Private accounting is malformed or does not conserve value.
    #[error(transparent)]
    Accounting(#[from] AccountingArithmeticError),
    /// Burn commitment/ciphertext linkage failed.
    #[error(transparent)]
    BurnBinding(#[from] BurnBindingError),
    /// The reconstructed monolithic witness differs from public instances.
    #[error(transparent)]
    Preparation(#[from] VaultTransferPreparationError),
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], DelegatedWitnessError> {
        self.take_slice(N)?
            .try_into()
            .map_err(|_| DelegatedWitnessError::InvalidEncoding)
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], DelegatedWitnessError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DelegatedWitnessError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DelegatedWitnessError::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
