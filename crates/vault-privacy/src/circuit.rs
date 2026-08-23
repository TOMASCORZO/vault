//! Typed bridge into the pinned Ironwood Action circuit.
//!
//! Enabling this module deliberately enables Orchard's heavy `circuit`
//! dependency graph. Wallet scanning and consensus parsing do not need it.

use ff::{Field, PrimeField};
use orchard::{
    Anchor,
    builder::SpendInfo,
    bundle::BundleVersion,
    circuit::{Circuit, Instance, OrchardCircuitVersion},
    note::{ExtractedNoteCommitment, Nullifier},
    primitives::redpallas::{self, SpendAuth},
    tree::{MerkleHashOrchard, MerklePath},
    value::{ValueCommitTrapdoor, ValueCommitment},
};
use pasta_curves::pallas;

use crate::{
    ActionNullifier, CanonicalValueCommitment, EncryptedNote, NoteMembershipPath, NoteTreeRoot,
    PreparedNetValueCommitment, PreparedNoteOutput, PreparedSpendAuthorization, PrivacyError,
    PrivateNote, RandomizedSpendValidatingKey, VaultFullViewingKey,
};

/// Exact hardened circuit used by Ironwood V3 actions.
pub const ACTION_CIRCUIT_VERSION: OrchardCircuitVersion = OrchardCircuitVersion::PostNu6_3;

/// A fully cross-checked private action circuit and its public instance.
///
/// Construction checks ownership, the Merkle path, output `rho`, randomized
/// authorization key, and net-value commitment before the expensive prover is
/// invoked. The circuit independently constrains those relationships.
#[derive(Debug)]
pub struct PreparedActionCircuit {
    circuit: Circuit,
    instance: Instance,
    encrypted_output: EncryptedNote,
}

impl PreparedActionCircuit {
    /// Builds one real or zero-valued dummy Ironwood action witness.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        full_viewing_key: &VaultFullViewingKey,
        input_note: &PrivateNote,
        membership_path: &NoteMembershipPath,
        output: &PreparedNoteOutput,
        authorization: &PreparedSpendAuthorization,
        net_value: &PreparedNetValueCommitment,
        anchor: NoteTreeRoot,
    ) -> Result<Self, PrivacyError> {
        let input_commitment = input_note.commitment()?;
        if input_note.value() != 0 && !membership_path.verify(input_commitment, anchor.to_bytes()) {
            return Err(PrivacyError::InvalidCircuitWitness);
        }

        let orchard_fvk = full_viewing_key.orchard();
        let orchard_input = input_note.orchard()?;
        let orchard_path = merkle_path(membership_path)?;
        let spend = SpendInfo::new(orchard_fvk.clone(), orchard_input, orchard_path)
            .ok_or(PrivacyError::InvalidCircuitWitness)?;
        let orchard_output = output.note().orchard()?;

        let alpha = parse_scalar(&authorization.randomizer())?;
        let rcv = parse_trapdoor(&net_value.trapdoor())?;
        let circuit =
            Circuit::from_action_context(spend, orchard_output, alpha, rcv, ACTION_CIRCUIT_VERSION)
                .ok_or(PrivacyError::InvalidCircuitWitness)?;

        let input_nullifier = input_note.orchard()?.nullifier(&orchard_fvk);
        let expected_nullifier = output.note().action_nullifier()?.orchard();
        if input_nullifier != expected_nullifier {
            return Err(PrivacyError::InvalidCircuitWitness);
        }

        let instance = instance_from_parts(
            anchor,
            net_value.commitment(),
            output.note().action_nullifier()?,
            RandomizedSpendValidatingKey::from_bytes(authorization.randomized_verification_key())?,
            output.encrypted_note().note_commitment(),
        )?;

        Ok(Self {
            circuit,
            instance,
            encrypted_output: output.encrypted_note().clone(),
        })
    }

    /// Consumes the checked wrapper for aggregated or monolithic proving.
    ///
    /// The exact encrypted output is retained so a higher-level prover can
    /// reject any divergence between the locally constructed output and the
    /// canonical transaction effects before proving.
    #[must_use]
    pub fn into_parts(self) -> (Circuit, Instance, EncryptedNote) {
        (self.circuit, self.instance, self.encrypted_output)
    }
}

/// Reconstructs the exact public Halo2 instance from transfer action fields.
pub fn instance_from_parts(
    anchor: NoteTreeRoot,
    net_value_commitment: CanonicalValueCommitment,
    nullifier: ActionNullifier,
    randomized_verification_key: RandomizedSpendValidatingKey,
    output_note_commitment: [u8; 32],
) -> Result<Instance, PrivacyError> {
    let anchor = Option::<Anchor>::from(Anchor::from_bytes(anchor.to_bytes()))
        .ok_or(PrivacyError::InvalidCircuitInstance)?;
    let value_commitment = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(
        &net_value_commitment.to_bytes(),
    ))
    .ok_or(PrivacyError::InvalidCircuitInstance)?;
    let nullifier = Option::<Nullifier>::from(Nullifier::from_bytes(&nullifier.to_bytes()))
        .ok_or(PrivacyError::InvalidCircuitInstance)?;
    let randomized_key =
        redpallas::VerificationKey::<SpendAuth>::try_from(randomized_verification_key.to_bytes())
            .map_err(|_| PrivacyError::InvalidCircuitInstance)?;
    let note_commitment = Option::<ExtractedNoteCommitment>::from(
        ExtractedNoteCommitment::from_bytes(&output_note_commitment),
    )
    .ok_or(PrivacyError::InvalidCircuitInstance)?;

    Instance::from_parts(
        anchor,
        value_commitment,
        nullifier,
        randomized_key,
        note_commitment,
        BundleVersion::ironwood_v3().default_flags(),
    )
    .ok_or(PrivacyError::InvalidCircuitInstance)
}

fn merkle_path(path: &NoteMembershipPath) -> Result<MerklePath, PrivacyError> {
    let auth_path = path
        .auth_path()
        .map(|node| {
            Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&node))
                .ok_or(PrivacyError::InvalidCircuitWitness)
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| PrivacyError::InvalidCircuitWitness)?;
    Ok(MerklePath::from_parts(path.position(), auth_path))
}

fn parse_scalar(bytes: &[u8; 32]) -> Result<pallas::Scalar, PrivacyError> {
    Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(*bytes))
        .filter(|scalar| !bool::from(scalar.is_zero()))
        .ok_or(PrivacyError::InvalidCircuitWitness)
}

fn parse_trapdoor(bytes: &[u8; 32]) -> Result<ValueCommitTrapdoor, PrivacyError> {
    Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(*bytes))
        .ok_or(PrivacyError::InvalidCircuitWitness)
}
