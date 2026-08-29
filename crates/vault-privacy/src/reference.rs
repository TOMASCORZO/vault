//! Feature-gated native checks used only by the isolated RISC Zero oracle.
//!
//! The production Halo2 path constrains these relations in-circuit. This
//! module deliberately has no verifier or state-transition adapter.

use ff::{Field, PrimeField};
use orchard::{
    keys::SpendValidatingKey,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use pasta_curves::pallas;

use crate::{
    ActionNullifier, CanonicalValueCommitment, EncryptedNote, NoteMembershipPath, OutputKind,
    PRIVATE_NOTE_BYTES, PrivateNote, RandomizedSpendValidatingKey, VaultFullViewingKey,
    signing::OutputAuthorizationPacket,
};

/// Private values recovered only after every per-action reference check passes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceActionValues {
    input_value: u64,
    output_value: u64,
    taxable_output: u64,
    is_dummy: bool,
}

impl ReferenceActionValues {
    /// Value of the paired consumed note.
    #[must_use]
    pub const fn input_value(self) -> u64 {
        self.input_value
    }

    /// Value of the paired created note.
    #[must_use]
    pub const fn output_value(self) -> u64 {
        self.output_value
    }

    /// Output value included in the mandatory burn base.
    #[must_use]
    pub const fn taxable_output(self) -> u64 {
        self.taxable_output
    }

    /// Whether both linked note values are zero.
    #[must_use]
    pub const fn is_dummy(self) -> bool {
        self.is_dummy
    }
}

/// Deterministic failures for one private reference action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceActionError {
    /// The full viewing capability, note, path, or packet is malformed.
    InvalidEncoding,
    /// The private input recipient is not controlled by the supplied account.
    WrongInputOwner,
    /// A non-zero input is not a member of the public anchor.
    InvalidMembership,
    /// The public nullifier is not derived from this note and account.
    NullifierMismatch,
    /// The public randomized spend key does not use this account and randomizer.
    RandomizedKeyMismatch,
    /// The public net-value commitment does not open to the linked note values.
    NetValueCommitmentMismatch,
    /// Output note/value openings or encryption do not reconstruct exactly.
    OutputConstructionMismatch,
    /// External/change/dummy classification is inconsistent with linked notes.
    InvalidClassification,
}

/// Validates every private relation shared by the reference and Action paths.
#[allow(clippy::too_many_arguments)]
pub fn verify_reference_action(
    network_id: [u8; 32],
    anchor: [u8; 32],
    expected_nullifier: ActionNullifier,
    expected_randomized_key: RandomizedSpendValidatingKey,
    expected_net_value_commitment: CanonicalValueCommitment,
    expected_output: &EncryptedNote,
    full_viewing_key_bytes: [u8; 96],
    input_note_bytes: [u8; PRIVATE_NOTE_BYTES],
    membership_position: u32,
    membership_auth_path: [[u8; 32]; 32],
    authorization_randomizer: [u8; 32],
    net_value_trapdoor: [u8; 32],
    output_packet_bytes: &[u8],
    maximum_value: u64,
) -> Result<ReferenceActionValues, ReferenceActionError> {
    let full_viewing_key = VaultFullViewingKey::from_bytes(full_viewing_key_bytes)
        .map_err(|_| ReferenceActionError::InvalidEncoding)?;
    let input_note = PrivateNote::decode_private(input_note_bytes, maximum_value)
        .map_err(|_| ReferenceActionError::InvalidEncoding)?;
    let membership_path = NoteMembershipPath::from_parts(membership_position, membership_auth_path)
        .map_err(|_| ReferenceActionError::InvalidEncoding)?;

    let orchard_fvk = full_viewing_key.orchard();
    if orchard_fvk
        .scope_for_address(&input_note.recipient().orchard())
        .is_none()
    {
        return Err(ReferenceActionError::WrongInputOwner);
    }

    let input_commitment = input_note
        .commitment()
        .map_err(|_| ReferenceActionError::InvalidEncoding)?;
    if input_note.value() != 0 && !membership_path.verify(input_commitment, anchor) {
        return Err(ReferenceActionError::InvalidMembership);
    }

    if full_viewing_key
        .note_nullifier(&input_note)
        .map_err(|_| ReferenceActionError::InvalidEncoding)?
        != expected_nullifier
    {
        return Err(ReferenceActionError::NullifierMismatch);
    }

    let Some(randomizer) =
        Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(authorization_randomizer))
            .filter(|value| !bool::from(value.is_zero()))
    else {
        return Err(ReferenceActionError::InvalidEncoding);
    };
    let spend_validating_key = SpendValidatingKey::from(orchard_fvk);
    let randomized = spend_validating_key.randomize(&randomizer);
    let randomized_bytes: [u8; 32] = (&randomized).into();
    if randomized_bytes != expected_randomized_key.to_bytes() {
        return Err(ReferenceActionError::RandomizedKeyMismatch);
    }

    let output_packet = OutputAuthorizationPacket::decode(output_packet_bytes)
        .map_err(|_| ReferenceActionError::InvalidEncoding)?;
    let output = output_packet
        .verify_reference_witness(
            &full_viewing_key,
            network_id,
            expected_nullifier,
            expected_output,
            maximum_value,
        )
        .map_err(|_| ReferenceActionError::OutputConstructionMismatch)?;

    let Some(net_trapdoor) =
        Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(net_value_trapdoor))
            .filter(|_| net_value_trapdoor != [0; 32])
    else {
        return Err(ReferenceActionError::InvalidEncoding);
    };
    let expected_net = ValueCommitment::derive(
        NoteValue::from_raw(input_note.value()) - NoteValue::from_raw(output.value()),
        net_trapdoor,
    );
    if expected_net.to_bytes() != expected_net_value_commitment.to_bytes() {
        return Err(ReferenceActionError::NetValueCommitmentMismatch);
    }

    let (taxable_output, is_dummy) = match output.kind() {
        OutputKind::ExternalPayment => (output.value(), false),
        OutputKind::InternalChange => {
            if output.value() == 0 || output.recipient() != input_note.recipient() {
                return Err(ReferenceActionError::InvalidClassification);
            }
            (0, false)
        }
        OutputKind::Dummy => {
            if input_note.value() != 0
                || output.value() != 0
                || output.recipient() != input_note.recipient()
            {
                return Err(ReferenceActionError::InvalidClassification);
            }
            (0, true)
        }
    };

    Ok(ReferenceActionValues {
        input_value: input_note.value(),
        output_value: output.value(),
        taxable_output,
        is_dummy,
    })
}

/// Checks the circuit-compatible Pallas burn commitment opening.
#[must_use]
pub fn verifies_reference_burn_commitment(
    amount: u64,
    trapdoor_bytes: [u8; 32],
    expected: CanonicalValueCommitment,
) -> bool {
    if trapdoor_bytes == [0; 32]
        || Option::<pallas::Base>::from(pallas::Base::from_repr(trapdoor_bytes)).is_none()
    {
        return false;
    }
    let Some(trapdoor) =
        Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(trapdoor_bytes))
    else {
        return false;
    };
    ValueCommitment::derive(NoteValue::from_raw(amount) - NoteValue::ZERO, trapdoor).to_bytes()
        == expected.to_bytes()
}
