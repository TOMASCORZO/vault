//! Monolithic Vault transfer circuit composition.
//!
//! This module reuses the exact private cells constrained by the hardened
//! Ironwood/Orchard Action statement. The accounting layer cannot supply a
//! second, unrelated copy of any input or output value. A zero-tax output is
//! additionally constrained to the exact expanded receiver of its paired
//! consumed note, while the classification bit remains private.
//!
//! The shape remains non-activatable: both-backend vectors, benchmarks, and
//! independent review are still mandatory.

use ff::PrimeField;
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{AssignedCell, Layouter, Value, floor_planner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use orchard::circuit::{
    ActionCells, Circuit as OrchardActionCircuit, Config as OrchardActionConfig, Instance,
};
use pasta_curves::{group::GroupEncoding, pallas};
use thiserror::Error;
use vault_burn::{
    BURN_ENCRYPTION_SCHEME_ID, BurnCiphertext, BurnEncryptionError, EpochBurnPublicKey,
};
use vault_privacy::{PrivacyError, circuit::PreparedActionCircuit};
use vault_protocol::{ALLOWED_TRANSFER_V2_ACTION_COUNTS, TransferV2Effects};

use crate::{
    accounting::{AccountingArithmeticCircuit, AccountingArithmeticConfig},
    burn_binding::{
        BURN_BINDING_INSTANCE_OFFSET, BURN_BINDING_INSTANCE_VALUES, BurnBindingConfig,
        PreparedAccountingBurn,
    },
};

const ORCHARD_ACTION_INSTANCE_ROWS: usize = 10;
const TRANSFER_EFFECTS_DIGEST_LIMBS: usize = 2;
/// Domain used to derive [`MONOLITHIC_TRANSFER_SUITE_ID`] from the pinned
/// verifying-key descriptions in ascending bucket order.
pub const MONOLITHIC_TRANSFER_SUITE_ID_DOMAIN: &str =
    "vault.zk.halo2.monolithic-transfer-suite.2026-08-30";

/// First accounting-instance row occupied by the canonical 256-bit effects
/// digest, encoded as two little-endian 128-bit limbs.
pub const TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET: usize =
    BURN_BINDING_INSTANCE_OFFSET + BURN_BINDING_INSTANCE_VALUES;

/// Degree parameter for the monolithic Action/accounting/burn/effects shape.
///
/// `k = 15` is the smallest reviewed parameter that key-generates every
/// consensus action bucket through the maximum 16-action shape.
pub const VAULT_TRANSFER_K: u32 = 15;

/// Reviewed digest of the pinned verifying keys for the 2/4/8/16-action
/// monolithic transfer circuits, in ascending bucket order.
pub const MONOLITHIC_TRANSFER_SUITE_ID: [u8; 32] = [
    0x99, 0x15, 0x23, 0x42, 0x6f, 0x81, 0xb2, 0x35, 0x0b, 0x1b, 0x08, 0xa7, 0xe2, 0xde, 0x9f, 0x60,
    0xe3, 0x34, 0xf3, 0x44, 0xe4, 0x0c, 0x23, 0x90, 0x4c, 0x6d, 0xd8, 0xdb, 0x59, 0x37, 0xc8, 0x3a,
];

/// Canonical proof length for each circuit in the frozen monolithic suite.
pub const MONOLITHIC_TRANSFER_PROOF_BYTES: usize = 9_664;

/// Native failures while preparing the fixed-shape monolithic witness.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VaultTransferPreparationError {
    /// The const-generic action bucket is not allowed by transfer-v2.
    #[error("unsupported Vault transfer action count")]
    UnsupportedActionCount,
    /// The supplied Action witness count differs from the fixed circuit shape.
    #[error("Vault transfer Action witness count mismatch")]
    ActionCountMismatch,
    /// Public effects or the activated epoch key cannot form this statement.
    #[error(transparent)]
    InvalidPublicInputs(#[from] VaultTransferPublicInputError),
    /// Prepared private witnesses disagree with independently parsed effects.
    #[error("Vault transfer witnesses disagree with canonical public effects")]
    WitnessPublicInputMismatch,
    /// A locally constructed encrypted output differs from the exact effect
    /// bytes that the spending keys are being asked to authorize.
    #[error("Vault transfer encrypted output differs from canonical public effects")]
    EncryptedOutputMismatch,
}

/// Fail-closed errors while reconstructing the monolithic public statement.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VaultTransferPublicInputError {
    /// The fixed circuit bucket differs from the canonical action count.
    #[error("Vault transfer public action count mismatch")]
    ActionCountMismatch,
    /// The effects select another burn-encryption construction.
    #[error("Vault transfer burn scheme is not activated")]
    BurnSchemeMismatch,
    /// The effects do not commit to the supplied canonical DKG descriptor.
    #[error("Vault transfer burn key ID does not match the activated epoch key")]
    BurnKeyMismatch,
    /// The transaction and supplied DKG descriptor select different epochs.
    #[error("Vault transfer burn epoch does not match the activated epoch key")]
    BurnEpochMismatch,
    /// An Action field cannot form the canonical hardened circuit instance.
    #[error("Vault transfer contains an invalid Action instance: {0}")]
    InvalidActionInstance(PrivacyError),
    /// The pinned burn ciphertext is not canonical.
    #[error("Vault transfer contains an invalid burn ciphertext: {0}")]
    InvalidBurnCiphertext(BurnEncryptionError),
    /// A burn commitment, ciphertext component, or epoch key is not a
    /// non-identity canonical Pallas point.
    #[error("Vault transfer contains an invalid burn public point")]
    InvalidBurnPoint,
}

/// Canonical monolithic instance columns reconstructed by validators from the
/// complete typed effects and the activated epoch-key registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultTransferPublicInputs<const N: usize> {
    action_column: Vec<pallas::Base>,
    accounting_burn_column: Vec<pallas::Base>,
}

impl<const N: usize> VaultTransferPublicInputs<N> {
    /// Reconstructs every currently constrained public value without trusting
    /// prover-supplied instance data.
    pub fn from_effects(
        effects: &TransferV2Effects,
        epoch_key: &EpochBurnPublicKey,
    ) -> Result<Self, VaultTransferPublicInputError> {
        if !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&N) || effects.actions().len() != N {
            return Err(VaultTransferPublicInputError::ActionCountMismatch);
        }
        let burn = effects.burn();
        if burn.scheme_id() != BURN_ENCRYPTION_SCHEME_ID {
            return Err(VaultTransferPublicInputError::BurnSchemeMismatch);
        }
        if burn.key_id() != epoch_key.key_id() {
            return Err(VaultTransferPublicInputError::BurnKeyMismatch);
        }
        if burn.epoch() != epoch_key.epoch() {
            return Err(VaultTransferPublicInputError::BurnEpochMismatch);
        }

        let mut action_column = Vec::with_capacity(N * ORCHARD_ACTION_INSTANCE_ROWS);
        for action in effects.actions() {
            let instance = vault_privacy::circuit::instance_from_parts(
                effects.anchor(),
                action.net_value_commitment(),
                action.nullifier(),
                action.randomized_verification_key(),
                action.output().note_commitment(),
            )
            .map_err(VaultTransferPublicInputError::InvalidActionInstance)?;
            action_column.extend_from_slice(&instance.to_halo2_instance()[0]);
        }

        let ciphertext = BurnCiphertext::from_bytes(*burn.ciphertext())
            .map_err(VaultTransferPublicInputError::InvalidBurnCiphertext)?
            .to_bytes();
        let mut accounting_burn_column = vec![
            pallas::Base::from(effects.gas().units),
            pallas::Base::from(effects.gas().fee_per_gas),
        ];
        append_point_coordinates(&mut accounting_burn_column, burn.commitment().to_bytes())?;
        append_point_coordinates(
            &mut accounting_burn_column,
            ciphertext[..32]
                .try_into()
                .expect("fixed ciphertext component"),
        )?;
        append_point_coordinates(
            &mut accounting_burn_column,
            ciphertext[32..]
                .try_into()
                .expect("fixed ciphertext component"),
        )?;
        append_point_coordinates(&mut accounting_burn_column, epoch_key.encryption_key())?;
        accounting_burn_column.extend_from_slice(&effects_digest_limbs(effects));

        Ok(Self {
            action_column,
            accounting_burn_column,
        })
    }

    fn matches_prepared(
        &self,
        instances: &[Instance; N],
        accounting: &PreparedAccountingBurn<N>,
    ) -> bool {
        let mut action_column = Vec::with_capacity(N * ORCHARD_ACTION_INSTANCE_ROWS);
        for instance in instances {
            action_column.extend_from_slice(&instance.to_halo2_instance()[0]);
        }
        let accounting_burn_column = accounting
            .public_inputs()
            .pop()
            .expect("accounting/burn has one instance column");
        self.action_column == action_column
            && self
                .accounting_burn_column
                .get(..TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET)
                == Some(accounting_burn_column.as_slice())
    }

    /// Returns the two instance columns expected by `VaultTransferCircuit`.
    #[must_use]
    pub fn to_columns(&self) -> Vec<Vec<pallas::Base>> {
        vec![
            self.action_column.clone(),
            self.accounting_burn_column.clone(),
        ]
    }

    fn effects_digest(&self) -> [pallas::Base; TRANSFER_EFFECTS_DIGEST_LIMBS] {
        self.accounting_burn_column[TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET..]
            .try_into()
            .expect("canonical public inputs contain exactly two effects-digest limbs")
    }
}

fn effects_digest_limbs(effects: &TransferV2Effects) -> [pallas::Base; 2] {
    let digest = effects.public_inputs_digest().into_bytes();
    std::array::from_fn(|index| {
        let mut representation = <pallas::Base as PrimeField>::Repr::default();
        let start = index * 16;
        representation.as_mut()[..16].copy_from_slice(&digest[start..start + 16]);
        Option::<pallas::Base>::from(pallas::Base::from_repr(representation))
            .expect("a 128-bit limb is always canonical in the Pallas base field")
    })
}

fn append_point_coordinates(
    output: &mut Vec<pallas::Base>,
    bytes: [u8; 32],
) -> Result<(), VaultTransferPublicInputError> {
    let point = Option::<pallas::Affine>::from(pallas::Affine::from_bytes(&bytes))
        .ok_or(VaultTransferPublicInputError::InvalidBurnPoint)?;
    let coordinates = point.coordinates();
    if !bool::from(coordinates.is_some()) {
        return Err(VaultTransferPublicInputError::InvalidBurnPoint);
    }
    let coordinates = coordinates.unwrap();
    output.push(*coordinates.x());
    output.push(*coordinates.y());
    Ok(())
}

/// Cross-checked inputs for one monolithic transfer circuit.
pub struct PreparedVaultTransfer<const N: usize> {
    actions: [OrchardActionCircuit; N],
    accounting: PreparedAccountingBurn<N>,
    public_inputs: VaultTransferPublicInputs<N>,
}

impl<const N: usize> core::fmt::Debug for PreparedVaultTransfer<N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedVaultTransfer")
            .field("action_count", &N)
            .field("private_witness", &"REDACTED")
            .finish()
    }
}

impl<const N: usize> PreparedVaultTransfer<N> {
    /// Joins prepared Action witnesses with the accounting/burn witness.
    ///
    /// Equality of private values and change classification is enforced by the
    /// circuit itself; no host-only equality is trusted for proof validity.
    /// Exact encrypted-output equality is additionally checked as a
    /// construction-safety invariant before proving.
    pub fn new(
        actions: Vec<PreparedActionCircuit>,
        accounting: PreparedAccountingBurn<N>,
        effects: &TransferV2Effects,
        epoch_key: &EpochBurnPublicKey,
    ) -> Result<Self, VaultTransferPreparationError> {
        if !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&N) {
            return Err(VaultTransferPreparationError::UnsupportedActionCount);
        }
        if actions.len() != N {
            return Err(VaultTransferPreparationError::ActionCountMismatch);
        }

        let mut circuits = Vec::with_capacity(N);
        let mut instances = Vec::with_capacity(N);
        let mut encrypted_outputs = Vec::with_capacity(N);
        for action in actions {
            let (circuit, instance, encrypted_output) = action.into_parts();
            circuits.push(circuit);
            instances.push(instance);
            encrypted_outputs.push(encrypted_output);
        }
        let actions = circuits
            .try_into()
            .map_err(|_| VaultTransferPreparationError::ActionCountMismatch)?;
        let instances = instances
            .try_into()
            .map_err(|_| VaultTransferPreparationError::ActionCountMismatch)?;
        let public_inputs = VaultTransferPublicInputs::from_effects(effects, epoch_key)?;
        if encrypted_outputs
            .iter()
            .zip(effects.actions())
            .any(|(prepared, public)| prepared != public.output())
        {
            return Err(VaultTransferPreparationError::EncryptedOutputMismatch);
        }
        if !public_inputs.matches_prepared(&instances, &accounting) {
            return Err(VaultTransferPreparationError::WitnessPublicInputMismatch);
        }

        Ok(Self {
            actions,
            accounting,
            public_inputs,
        })
    }

    /// Builds the witness-bearing monolithic circuit.
    #[must_use]
    pub fn circuit(&self) -> VaultTransferCircuit<N> {
        VaultTransferCircuit {
            actions: Some(self.actions.clone()),
            accounting: Some(self.accounting.clone()),
            effects_digest: Some(self.public_inputs.effects_digest()),
        }
    }

    /// Canonical Action instances followed by accounting, burn, epoch-key, and
    /// complete-effects-digest instances. All public values are independently
    /// reconstructible by a verifier.
    #[must_use]
    pub fn public_inputs(&self) -> Vec<Vec<pallas::Base>> {
        self.public_inputs.to_columns()
    }
}

/// Fixed-shape monolithic transfer circuit for one padded Action bucket.
#[derive(Clone)]
pub struct VaultTransferCircuit<const N: usize> {
    actions: Option<[OrchardActionCircuit; N]>,
    accounting: Option<PreparedAccountingBurn<N>>,
    effects_digest: Option<[pallas::Base; TRANSFER_EFFECTS_DIGEST_LIMBS]>,
}

impl<const N: usize> core::fmt::Debug for VaultTransferCircuit<N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VaultTransferCircuit")
            .field("action_count", &N)
            .field("private_witness", &"REDACTED")
            .finish()
    }
}

/// Configuration of the composed Action, accounting, burn, and private-change
/// constraints.
#[derive(Clone, Debug)]
pub struct VaultTransferConfig {
    orchard: OrchardActionConfig,
    accounting: AccountingArithmeticConfig,
    burn: BurnBindingConfig,
    link: ActionAccountingLinkConfig,
    effects: PublicEffectsBindingConfig,
}

impl<const N: usize> Circuit<pallas::Base> for VaultTransferCircuit<N> {
    type Config = VaultTransferConfig;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self {
            actions: self
                .actions
                .as_ref()
                .map(|actions| actions.clone().map(|action| action.without_witnesses())),
            accounting: None,
            effects_digest: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let orchard = OrchardActionConfig::configure_for_composition(meta);
        let accounting = AccountingArithmeticCircuit::<N>::configure(meta);
        let ecc_advices = std::array::from_fn(|_| meta.advice_column());
        let burn = BurnBindingConfig::configure(meta, ecc_advices, accounting.instance);
        let link = ActionAccountingLinkConfig::configure(meta);
        let effects = PublicEffectsBindingConfig::configure(meta, accounting.instance);
        VaultTransferConfig {
            orchard,
            accounting,
            burn,
            link,
            effects,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        config
            .orchard
            .load_for_composition(&mut layouter.namespace(|| "Action Sinsemilla table"))?;
        config
            .burn
            .load(layouter.namespace(|| "burn-binding lookup"))?;

        let actions = self.actions.as_ref().ok_or(Error::Synthesis)?;
        let mut action_cells = Vec::with_capacity(N);
        for (index, action) in actions.iter().enumerate() {
            let cells = action.synthesize_for_composition(
                &config.orchard,
                &mut layouter.namespace(|| format!("Action {index}")),
                index * ORCHARD_ACTION_INSTANCE_ROWS,
            )?;
            action_cells.push(cells);
        }

        let arithmetic = AccountingArithmeticCircuit {
            witness: self
                .accounting
                .as_ref()
                .map(|prepared| prepared.arithmetic().clone()),
        };
        let summary = arithmetic.synthesize_with_summary(
            config.accounting,
            &mut layouter.namespace(|| "accounting arithmetic"),
        )?;

        config.link.assign(
            layouter.namespace(|| "Action/accounting shared-cell links"),
            &action_cells,
            &summary.action_inputs,
            &summary.action_outputs,
            &summary.taxable_flags,
        )?;

        config.burn.assign(
            layouter.namespace(|| "same-cell burn binding"),
            &summary.burn,
            self.accounting
                .as_ref()
                .map(PreparedAccountingBurn::binding),
            BURN_BINDING_INSTANCE_OFFSET,
        )?;
        config.effects.assign(
            layouter.namespace(|| "complete effects digest"),
            self.effects_digest,
        )
    }
}

#[derive(Clone, Debug)]
struct PublicEffectsBindingConfig {
    advice: Column<Advice>,
    instance: Column<halo2_proofs::plonk::Instance>,
}

impl PublicEffectsBindingConfig {
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        instance: Column<halo2_proofs::plonk::Instance>,
    ) -> Self {
        let advice = meta.advice_column();
        meta.enable_equality(advice);
        Self { advice, instance }
    }

    fn assign(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        digest: Option<[pallas::Base; TRANSFER_EFFECTS_DIGEST_LIMBS]>,
    ) -> Result<(), Error> {
        let cells = layouter.assign_region(
            || "bind canonical transfer effects digest",
            |mut region| {
                let mut cells = Vec::with_capacity(TRANSFER_EFFECTS_DIGEST_LIMBS);
                for row in 0..TRANSFER_EFFECTS_DIGEST_LIMBS {
                    cells.push(region.assign_advice(
                        || "prepared canonical effects digest limb",
                        self.advice,
                        row,
                        || digest.map_or(Value::unknown(), |values| Value::known(values[row])),
                    )?);
                }
                Ok(cells)
            },
        )?;
        for (row, cell) in cells.iter().enumerate() {
            layouter.constrain_instance(
                cell.cell(),
                self.instance,
                TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET + row,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ActionAccountingLinkConfig {
    advice: [Column<Advice>; 3],
    q_change: Selector,
}

impl ActionAccountingLinkConfig {
    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let advice = std::array::from_fn(|_| meta.advice_column());
        for column in advice {
            meta.enable_equality(column);
        }
        let q_change = meta.selector();
        meta.create_gate(
            "zero-tax output must be exact paired-address change",
            |meta| {
                let q = meta.query_selector(q_change);
                let taxable = meta.query_advice(advice[0], Rotation::cur());
                let old_coordinate = meta.query_advice(advice[1], Rotation::cur());
                let new_coordinate = meta.query_advice(advice[2], Rotation::cur());
                let one = halo2_proofs::plonk::Expression::Constant(pallas::Base::from(1));
                vec![q * (one - taxable) * (old_coordinate - new_coordinate)]
            },
        );
        Self { advice, q_change }
    }

    fn assign(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        actions: &[ActionCells],
        accounting_inputs: &[AssignedCell<pallas::Base, pallas::Base>],
        accounting_outputs: &[AssignedCell<pallas::Base, pallas::Base>],
        taxable_flags: &[AssignedCell<pallas::Base, pallas::Base>],
    ) -> Result<(), Error> {
        if actions.len() != accounting_inputs.len()
            || actions.len() != accounting_outputs.len()
            || actions.len() != taxable_flags.len()
        {
            return Err(Error::Synthesis);
        }

        layouter.assign_region(
            || "link values and private change classification",
            |mut region| {
                for (index, action) in actions.iter().enumerate() {
                    region.constrain_equal(
                        action.old_value().cell(),
                        accounting_inputs[index].cell(),
                    )?;
                    region.constrain_equal(
                        action.new_value().cell(),
                        accounting_outputs[index].cell(),
                    )?;

                    let old_coordinates = action.old_address_coordinates();
                    let new_coordinates = action.new_address_coordinates();
                    for coordinate in 0..old_coordinates.len() {
                        let row = index * old_coordinates.len() + coordinate;
                        self.q_change.enable(&mut region, row)?;
                        taxable_flags[index].copy_advice(
                            || "private taxable flag",
                            &mut region,
                            self.advice[0],
                            row,
                        )?;
                        old_coordinates[coordinate].copy_advice(
                            || "consumed-note receiver coordinate",
                            &mut region,
                            self.advice[1],
                            row,
                        )?;
                        new_coordinates[coordinate].copy_advice(
                            || "created-note receiver coordinate",
                            &mut region,
                            self.advice[2],
                            row,
                        )?;
                    }
                }
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use halo2_proofs::{
        pasta::{EqAffine, Fp},
        plonk::{Circuit, SingleVerifier, create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use incrementalmerkletree::{Hashable, Level};
    use orchard::{
        note::ExtractedNoteCommitment,
        tree::{MerkleHashOrchard, MerklePath},
    };
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use vault_burn::{EpochBurnPublicKey, PreparedBurnCiphertext};
    use vault_privacy::{
        ActionNullifier, EncryptedNote, KeyScope, MEMO_BYTES, NoteMembershipPath, NoteTreeRoot,
        PreparedBurnCommitment, PreparedNetValueCommitment, PreparedNoteOutput, PrivateNote,
        RandomizedSpendValidatingKey, VaultSpendingKey,
    };
    use vault_protocol::{
        ChainId, CircuitId, EncryptedBurnV2, GasParameters, TransferV2Action, TransferV2Effects,
    };
    use vault_zk_accounting_core::transfer_v2::{
        TransferV2ActionWitness, TransferV2BurnWitness, TransferV2ReferenceClaim,
    };

    use super::*;
    use crate::{
        accounting::{AccountingActionWitness, PreparedAccountingArithmetic},
        burn_binding::PreparedAccountingBurn,
    };

    const NETWORK: [u8; 32] = [0x31; 32];
    const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;
    const GAS_UNITS: u64 = 2;
    const FEE_PER_GAS: u64 = 13;

    #[derive(Clone, Copy)]
    enum FixtureMode {
        Valid,
        ShiftedAccountingValues,
        ExternalOutputClaimedAsChange,
        MismatchedNoteCiphertextEffects,
    }

    fn nullifier(byte: u8) -> ActionNullifier {
        ActionNullifier::from_bytes([byte; 32]).unwrap()
    }

    fn membership_paths(commitment_bytes: &[[u8; 32]]) -> (NoteTreeRoot, Vec<NoteMembershipPath>) {
        assert!(!commitment_bytes.is_empty());
        let commitments = commitment_bytes
            .iter()
            .map(|bytes| {
                Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(bytes))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut levels = Vec::with_capacity(33);
        levels.push(
            commitments
                .iter()
                .map(MerkleHashOrchard::from_cmx)
                .collect::<Vec<_>>(),
        );
        for level in 0_u8..32 {
            let current = &levels[usize::from(level)];
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            for pair in current.chunks(2) {
                let left = pair[0];
                let right = pair
                    .get(1)
                    .copied()
                    .unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(level)));
                next.push(MerkleHashOrchard::combine(
                    Level::from(level),
                    &left,
                    &right,
                ));
            }
            levels.push(next);
        }

        let paths = commitments
            .iter()
            .enumerate()
            .map(|(position, commitment)| {
                let nodes = std::array::from_fn(|level| {
                    let sibling = (position >> level) ^ 1;
                    levels[level]
                        .get(sibling)
                        .copied()
                        .unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(level as u8)))
                });
                let path = MerklePath::from_parts(position as u32, nodes);
                let root = path.root(*commitment);
                (root, path)
            })
            .collect::<Vec<_>>();
        let root = paths[0].0;
        assert!(paths.iter().all(|(candidate, _)| *candidate == root));
        let paths = paths
            .into_iter()
            .map(|(_, path)| {
                NoteMembershipPath::from_parts(
                    path.position(),
                    path.auth_path().map(|node| node.to_bytes()),
                )
                .unwrap()
            })
            .collect();
        (NoteTreeRoot::from_bytes(root.to_bytes()).unwrap(), paths)
    }

    fn two_leaf_paths(commitments: [[u8; 32]; 2]) -> (NoteTreeRoot, [NoteMembershipPath; 2]) {
        let (root, paths) = membership_paths(&commitments);
        (root, paths.try_into().unwrap())
    }

    #[derive(Debug)]
    struct Fixture {
        prepared: PreparedVaultTransfer<2>,
        effects: TransferV2Effects,
        epoch_key: EpochBurnPublicKey,
        reference: TransferV2ReferenceClaim,
    }

    fn fixture(mode: FixtureMode) -> Fixture {
        fixture_result(mode).unwrap()
    }

    fn fixture_result(mode: FixtureMode) -> Result<Fixture, VaultTransferPreparationError> {
        let spending_key = VaultSpendingKey::derive(&[0xA5; 32], NETWORK, 0).unwrap();
        let full_viewing_key = spending_key.full_viewing_key();
        let input_address = full_viewing_key.address_at(0, KeyScope::Internal);
        let external_recipient = VaultSpendingKey::derive(&[0xB6; 32], NETWORK, 0)
            .unwrap()
            .full_viewing_key()
            .address_at(0, KeyScope::External);
        let mut rng = ChaCha20Rng::from_seed([0x71; 32]);

        let input_values = match mode {
            FixtureMode::ExternalOutputClaimedAsChange => [5_026, 1_000],
            FixtureMode::Valid
            | FixtureMode::ShiftedAccountingValues
            | FixtureMode::MismatchedNoteCiphertextEffects => [5_051, 1_000],
        };
        let inputs = [
            PrivateNote::create(
                input_address,
                input_values[0],
                MAXIMUM_VALUE,
                nullifier(2),
                &mut rng,
            )
            .unwrap(),
            PrivateNote::create(
                input_address,
                input_values[1],
                MAXIMUM_VALUE,
                nullifier(3),
                &mut rng,
            )
            .unwrap(),
        ];
        let commitments = [
            inputs[0].commitment().unwrap(),
            inputs[1].commitment().unwrap(),
        ];
        let (anchor, paths) = two_leaf_paths(commitments);

        let recipients = [external_recipient, input_address];
        let output_values = [5_000, 1_000];
        let taxable = match mode {
            FixtureMode::ExternalOutputClaimedAsChange => [false, false],
            FixtureMode::Valid
            | FixtureMode::ShiftedAccountingValues
            | FixtureMode::MismatchedNoteCiphertextEffects => [true, false],
        };
        let accounting_inputs = match mode {
            FixtureMode::ShiftedAccountingValues => [4_051, 2_000],
            FixtureMode::Valid
            | FixtureMode::ExternalOutputClaimedAsChange
            | FixtureMode::MismatchedNoteCiphertextEffects => input_values,
        };

        let mut prepared = Vec::with_capacity(2);
        for index in 0..2 {
            let action_nullifier = full_viewing_key.note_nullifier(&inputs[index]).unwrap();
            let output = PreparedNoteOutput::create(
                &full_viewing_key,
                KeyScope::External,
                recipients[index],
                output_values[index],
                MAXIMUM_VALUE,
                action_nullifier,
                [index as u8; MEMO_BYTES],
                &mut rng,
            )
            .unwrap();
            let authorization = spending_key.prepare_spend_authorization(&mut rng).unwrap();
            let net_value = PreparedNetValueCommitment::create(
                inputs[index].value(),
                output_values[index],
                &mut rng,
            )
            .unwrap();
            let circuit = PreparedActionCircuit::new(
                &full_viewing_key,
                &inputs[index],
                &paths[index],
                &output,
                &authorization,
                &net_value,
                anchor,
            )
            .unwrap();
            let public_action = TransferV2Action::new(
                action_nullifier,
                RandomizedSpendValidatingKey::from_bytes(
                    authorization.randomized_verification_key(),
                )
                .unwrap(),
                net_value.commitment(),
                output.encrypted_note().clone(),
            );
            let kind = if output_values[index] == 0 {
                vault_privacy::OutputKind::Dummy
            } else if recipients[index] == input_address {
                vault_privacy::OutputKind::InternalChange
            } else {
                vault_privacy::OutputKind::ExternalPayment
            };
            let output_packet = output.authorization_packet(NETWORK, kind).unwrap();
            let reference = TransferV2ActionWitness {
                full_viewing_key: full_viewing_key.export().to_vec(),
                input_note: inputs[index].encode_private().to_vec(),
                membership_position: paths[index].position(),
                membership_auth_path: paths[index].auth_path().to_vec(),
                output_authorization_packet: output_packet.encode().to_vec(),
                authorization_randomizer: *authorization.randomizer(),
                net_value_commitment_trapdoor: *net_value.trapdoor(),
            };
            prepared.push((
                action_nullifier,
                circuit,
                public_action,
                AccountingActionWitness::enabled(
                    accounting_inputs[index],
                    output_values[index],
                    taxable[index],
                ),
                reference,
            ));
        }
        prepared.sort_by_key(|(action_nullifier, _, _, _, _)| *action_nullifier);

        let mut circuits = Vec::with_capacity(2);
        let mut public_actions = Vec::with_capacity(2);
        let mut reference_actions = Vec::with_capacity(2);
        let mut accounting_actions = [AccountingActionWitness::dummy(); 2];
        for (index, (_, circuit, public_action, accounting, reference)) in
            prepared.into_iter().enumerate()
        {
            circuits.push(circuit);
            public_actions.push(public_action);
            accounting_actions[index] = accounting;
            reference_actions.push(reference);
        }
        let arithmetic =
            PreparedAccountingArithmetic::new(accounting_actions, GAS_UNITS, FEE_PER_GAS).unwrap();

        let coefficients = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
        let commitments = coefficients.map(|value| {
            use pasta_curves::group::{Group, GroupEncoding};
            (pallas::Point::generator() * value).to_bytes()
        });
        let epoch_key =
            EpochBurnPublicKey::from_parts(9, 2, vec![1, 2, 3], commitments.to_vec()).unwrap();
        let burn = arithmetic.burn();
        let commitment = PreparedBurnCommitment::create(burn, MAXIMUM_VALUE, &mut rng).unwrap();
        let ciphertext =
            PreparedBurnCiphertext::encrypt(burn, MAXIMUM_VALUE, &epoch_key, &mut rng).unwrap();
        let accounting =
            PreparedAccountingBurn::new(arithmetic, &commitment, &ciphertext, &epoch_key).unwrap();
        let burn_payload = EncryptedBurnV2::from_threshold_ciphertext(
            &epoch_key,
            commitment.commitment(),
            ciphertext.ciphertext(),
        )
        .unwrap();
        if matches!(mode, FixtureMode::MismatchedNoteCiphertextEffects) {
            let action = &public_actions[0];
            let output = action.output();
            let mut changed_ciphertext = *output.note_ciphertext();
            changed_ciphertext[137] ^= 1;
            let changed_output = EncryptedNote::from_parts(
                output.note_commitment(),
                output.value_commitment(),
                output.ephemeral_key(),
                changed_ciphertext,
                *output.outgoing_ciphertext(),
            )
            .unwrap();
            public_actions[0] = TransferV2Action::new(
                action.nullifier(),
                action.randomized_verification_key(),
                action.net_value_commitment(),
                changed_output,
            );
        }
        let effects = TransferV2Effects::new(
            ChainId::new(NETWORK),
            CircuitId::new([0xC4; 32]),
            anchor,
            burn_payload,
            GasParameters {
                units: GAS_UNITS,
                fee_per_gas: FEE_PER_GAS,
            },
            public_actions,
        )
        .unwrap();
        let reference = TransferV2ReferenceClaim {
            canonical_effects: effects.encode_canonical(),
            actions: reference_actions,
            burn: TransferV2BurnWitness {
                epoch: epoch_key.epoch(),
                threshold: epoch_key.threshold(),
                participants: epoch_key.participants().to_vec(),
                coefficient_commitments: commitments.to_vec(),
                commitment_trapdoor: *commitment.trapdoor(),
                encryption_randomness: *ciphertext.randomness(),
            },
        };

        // Shifted private values deliberately preserve the exact public
        // transcript. Only the in-circuit equality between the hardened Action
        // value cells and the accounting cells may reject that substitution.
        let prepared = PreparedVaultTransfer::new(circuits, accounting, &effects, &epoch_key)?;

        Ok(Fixture {
            prepared,
            effects,
            epoch_key,
            reference,
        })
    }

    fn valid_bucket<const N: usize>() -> PreparedVaultTransfer<N> {
        assert!(ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&N));
        let spending_key = VaultSpendingKey::derive(&[0xD1; 32], NETWORK, 1).unwrap();
        let full_viewing_key = spending_key.full_viewing_key();
        let input_address = full_viewing_key.address_at(0, KeyScope::Internal);
        let external_recipient = VaultSpendingKey::derive(&[0xD2; 32], NETWORK, 1)
            .unwrap()
            .full_viewing_key()
            .address_at(0, KeyScope::External);
        let mut rng = ChaCha20Rng::from_seed([0xD3; 32]);

        let inputs = (0..N)
            .map(|index| {
                PrivateNote::create(
                    input_address,
                    if index == 0 { 5_051 } else { 1_000 },
                    MAXIMUM_VALUE,
                    nullifier(u8::try_from(index + 32).unwrap()),
                    &mut rng,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let commitments = inputs
            .iter()
            .map(|input| input.commitment().unwrap())
            .collect::<Vec<_>>();
        let (anchor, paths) = membership_paths(&commitments);

        let mut prepared = Vec::with_capacity(N);
        for index in 0..N {
            let action_nullifier = full_viewing_key.note_nullifier(&inputs[index]).unwrap();
            let recipient = if index == 0 {
                external_recipient
            } else {
                input_address
            };
            let output_value = if index == 0 { 5_000 } else { 1_000 };
            let output = PreparedNoteOutput::create(
                &full_viewing_key,
                KeyScope::External,
                recipient,
                output_value,
                MAXIMUM_VALUE,
                action_nullifier,
                [u8::try_from(index).unwrap(); MEMO_BYTES],
                &mut rng,
            )
            .unwrap();
            let authorization = spending_key.prepare_spend_authorization(&mut rng).unwrap();
            let net_value =
                PreparedNetValueCommitment::create(inputs[index].value(), output_value, &mut rng)
                    .unwrap();
            let circuit = PreparedActionCircuit::new(
                &full_viewing_key,
                &inputs[index],
                &paths[index],
                &output,
                &authorization,
                &net_value,
                anchor,
            )
            .unwrap();
            let public_action = TransferV2Action::new(
                action_nullifier,
                RandomizedSpendValidatingKey::from_bytes(
                    authorization.randomized_verification_key(),
                )
                .unwrap(),
                net_value.commitment(),
                output.encrypted_note().clone(),
            );
            prepared.push((
                action_nullifier,
                circuit,
                public_action,
                AccountingActionWitness::enabled(inputs[index].value(), output_value, index == 0),
            ));
        }
        prepared.sort_by_key(|(action_nullifier, _, _, _)| *action_nullifier);
        let mut circuits = Vec::with_capacity(N);
        let mut public_actions = Vec::with_capacity(N);
        let mut accounting_actions = Vec::with_capacity(N);
        for (_, circuit, public_action, accounting) in prepared {
            circuits.push(circuit);
            public_actions.push(public_action);
            accounting_actions.push(accounting);
        }
        let arithmetic = PreparedAccountingArithmetic::new(
            accounting_actions.try_into().unwrap(),
            GAS_UNITS,
            FEE_PER_GAS,
        )
        .unwrap();

        let coefficients = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
        let commitments = coefficients.map(|value| {
            use pasta_curves::group::{Group, GroupEncoding};
            (pallas::Point::generator() * value).to_bytes()
        });
        let epoch_key =
            EpochBurnPublicKey::from_parts(9, 2, vec![1, 2, 3], commitments.to_vec()).unwrap();
        let commitment =
            PreparedBurnCommitment::create(arithmetic.burn(), MAXIMUM_VALUE, &mut rng).unwrap();
        let ciphertext =
            PreparedBurnCiphertext::encrypt(arithmetic.burn(), MAXIMUM_VALUE, &epoch_key, &mut rng)
                .unwrap();
        let accounting =
            PreparedAccountingBurn::new(arithmetic, &commitment, &ciphertext, &epoch_key).unwrap();
        let effects = TransferV2Effects::new(
            ChainId::new(NETWORK),
            CircuitId::new([0xC4; 32]),
            anchor,
            EncryptedBurnV2::from_threshold_ciphertext(
                &epoch_key,
                commitment.commitment(),
                ciphertext.ciphertext(),
            )
            .unwrap(),
            GasParameters {
                units: GAS_UNITS,
                fee_per_gas: FEE_PER_GAS,
            },
            public_actions,
        )
        .unwrap();
        PreparedVaultTransfer::new(circuits, accounting, &effects, &epoch_key).unwrap()
    }

    fn effects_with_burn(effects: &TransferV2Effects, burn: EncryptedBurnV2) -> TransferV2Effects {
        TransferV2Effects::new(
            effects.chain_id(),
            effects.circuit_id(),
            effects.anchor(),
            burn,
            effects.gas(),
            effects.actions().to_vec(),
        )
        .unwrap()
    }

    fn effects_with_actions(
        effects: &TransferV2Effects,
        actions: Vec<TransferV2Action>,
    ) -> TransferV2Effects {
        TransferV2Effects::new(
            effects.chain_id(),
            effects.circuit_id(),
            effects.anchor(),
            effects.burn().clone(),
            effects.gas(),
            actions,
        )
        .unwrap()
    }

    #[test]
    fn public_inputs_bind_the_activated_burn_descriptor() {
        let Fixture {
            prepared,
            effects,
            epoch_key,
            ..
        } = fixture(FixtureMode::Valid);
        let canonical = VaultTransferPublicInputs::<2>::from_effects(&effects, &epoch_key).unwrap();
        assert_eq!(canonical.to_columns(), prepared.public_inputs());

        let burn = effects.burn();
        let wrong_scheme = EncryptedBurnV2::new(
            [0xA1; 32],
            burn.key_id(),
            burn.epoch(),
            burn.commitment(),
            *burn.ciphertext(),
        )
        .unwrap();
        assert_eq!(
            VaultTransferPublicInputs::<2>::from_effects(
                &effects_with_burn(&effects, wrong_scheme),
                &epoch_key,
            ),
            Err(VaultTransferPublicInputError::BurnSchemeMismatch)
        );

        let wrong_key = EncryptedBurnV2::new(
            burn.scheme_id(),
            [0xA2; 32],
            burn.epoch(),
            burn.commitment(),
            *burn.ciphertext(),
        )
        .unwrap();
        assert_eq!(
            VaultTransferPublicInputs::<2>::from_effects(
                &effects_with_burn(&effects, wrong_key),
                &epoch_key,
            ),
            Err(VaultTransferPublicInputError::BurnKeyMismatch)
        );

        let wrong_epoch = EncryptedBurnV2::new(
            burn.scheme_id(),
            burn.key_id(),
            burn.epoch() + 1,
            burn.commitment(),
            *burn.ciphertext(),
        )
        .unwrap();
        assert_eq!(
            VaultTransferPublicInputs::<2>::from_effects(
                &effects_with_burn(&effects, wrong_epoch),
                &epoch_key,
            ),
            Err(VaultTransferPublicInputError::BurnEpochMismatch)
        );

        let alternative_coefficients = [pallas::Scalar::from(13), pallas::Scalar::from(17)];
        let alternative_commitments = alternative_coefficients.map(|value| {
            use pasta_curves::group::{Group, GroupEncoding};
            (pallas::Point::generator() * value).to_bytes()
        });
        let alternative_key = EpochBurnPublicKey::from_parts(
            epoch_key.epoch(),
            2,
            vec![1, 2, 3],
            alternative_commitments.to_vec(),
        )
        .unwrap();
        assert_eq!(
            VaultTransferPublicInputs::<2>::from_effects(&effects, &alternative_key),
            Err(VaultTransferPublicInputError::BurnKeyMismatch)
        );
    }

    #[test]
    fn typed_replacement_ciphertext_cannot_reuse_the_prepared_proof_witness() {
        let Fixture {
            prepared,
            effects,
            epoch_key,
            ..
        } = fixture(FixtureMode::Valid);
        let mut rng = ChaCha20Rng::from_seed([0xD1; 32]);
        let replacement = PreparedBurnCiphertext::encrypt(
            prepared.accounting.arithmetic().burn(),
            MAXIMUM_VALUE,
            &epoch_key,
            &mut rng,
        )
        .unwrap();
        let replacement_burn = EncryptedBurnV2::from_threshold_ciphertext(
            &epoch_key,
            effects.burn().commitment(),
            replacement.ciphertext(),
        )
        .unwrap();
        let replacement_effects = effects_with_burn(&effects, replacement_burn);
        let replacement_inputs =
            VaultTransferPublicInputs::<2>::from_effects(&replacement_effects, &epoch_key).unwrap();
        assert_ne!(replacement_inputs.to_columns(), prepared.public_inputs());

        let prover = halo2_proofs::dev::MockProver::run(
            VAULT_TRANSFER_K,
            &prepared.circuit(),
            replacement_inputs.to_columns(),
        )
        .unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn complete_effects_digest_is_an_actual_circuit_instance() {
        let Fixture {
            prepared,
            effects,
            epoch_key,
            ..
        } = fixture(FixtureMode::Valid);
        let original_inputs = VaultTransferPublicInputs::<2>::from_effects(&effects, &epoch_key)
            .unwrap()
            .to_columns();
        let mut reconstructed_digest = [0_u8; 32];
        for (index, limb) in original_inputs[1][TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET..]
            .iter()
            .enumerate()
        {
            let representation = limb.to_repr();
            assert_eq!(&representation.as_ref()[16..], &[0_u8; 16]);
            reconstructed_digest[index * 16..(index + 1) * 16]
                .copy_from_slice(&representation.as_ref()[..16]);
        }
        assert_eq!(
            reconstructed_digest,
            effects.public_inputs_digest().into_bytes()
        );

        let original_action = &effects.actions()[0];
        let original_output = original_action.output();
        let mut changed_note_ciphertext = *original_output.note_ciphertext();
        changed_note_ciphertext[137] ^= 1;
        let changed_output = EncryptedNote::from_parts(
            original_output.note_commitment(),
            original_output.value_commitment(),
            original_output.ephemeral_key(),
            changed_note_ciphertext,
            *original_output.outgoing_ciphertext(),
        )
        .unwrap();
        let changed_action = TransferV2Action::new(
            original_action.nullifier(),
            original_action.randomized_verification_key(),
            original_action.net_value_commitment(),
            changed_output,
        );
        let mut changed_actions = effects.actions().to_vec();
        changed_actions[0] = changed_action;
        let changed_effects = effects_with_actions(&effects, changed_actions);
        let changed_inputs =
            VaultTransferPublicInputs::<2>::from_effects(&changed_effects, &epoch_key)
                .unwrap()
                .to_columns();

        assert_eq!(
            &original_inputs[1][..TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET],
            &changed_inputs[1][..TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET]
        );
        assert_ne!(
            &original_inputs[1][TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET..],
            &changed_inputs[1][TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET..]
        );
        let prover = halo2_proofs::dev::MockProver::run(
            VAULT_TRANSFER_K,
            &prepared.circuit(),
            changed_inputs,
        )
        .unwrap();
        assert!(prover.verify().is_err());

        let changed_domain = TransferV2Effects::new(
            ChainId::new([0x32; 32]),
            effects.circuit_id(),
            effects.anchor(),
            effects.burn().clone(),
            effects.gas(),
            effects.actions().to_vec(),
        )
        .unwrap();
        let changed_domain_inputs =
            VaultTransferPublicInputs::<2>::from_effects(&changed_domain, &epoch_key)
                .unwrap()
                .to_columns();
        assert_ne!(
            &original_inputs[1][TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET..],
            &changed_domain_inputs[1][TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET..]
        );
    }

    #[test]
    fn prover_preparation_rejects_an_effect_ciphertext_it_did_not_construct() {
        assert_eq!(
            fixture_result(FixtureMode::MismatchedNoteCiphertextEffects).unwrap_err(),
            VaultTransferPreparationError::EncryptedOutputMismatch
        );
    }

    #[test]
    fn monolithic_transfer_links_action_values_and_private_change() {
        let fixture = fixture(FixtureMode::Valid);
        let prepared = fixture.prepared;
        halo2_proofs::dev::MockProver::run(
            VAULT_TRANSFER_K,
            &prepared.circuit(),
            prepared.public_inputs(),
        )
        .unwrap()
        .assert_satisfied();
    }

    #[test]
    fn transparent_reference_and_halo2_accept_the_same_exact_witness() {
        let fixture = fixture(FixtureMode::Valid);
        let reference_journal = fixture.reference.validate().unwrap();
        assert_eq!(
            reference_journal.public_inputs_digest,
            *fixture.effects.public_inputs_digest().as_bytes()
        );
        assert_eq!(reference_journal.action_count, 2);
        assert_eq!(
            reference_journal.gas_fee,
            u128::from(GAS_UNITS * FEE_PER_GAS)
        );

        halo2_proofs::dev::MockProver::run(
            VAULT_TRANSFER_K,
            &fixture.prepared.circuit(),
            fixture.prepared.public_inputs(),
        )
        .unwrap()
        .assert_satisfied();
    }

    #[test]
    fn transparent_reference_and_halo2_both_reject_burn_evasion_vector() {
        let fixture = fixture(FixtureMode::ExternalOutputClaimedAsChange);
        assert_eq!(
            fixture.reference.validate(),
            Err(vault_zk_accounting_core::transfer_v2::TransferV2ReferenceError::ConservationFailure)
        );

        let prover = halo2_proofs::dev::MockProver::run(
            VAULT_TRANSFER_K,
            &fixture.prepared.circuit(),
            fixture.prepared.public_inputs(),
        )
        .unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn rejects_accounting_values_that_only_conserve_in_the_second_statement() {
        let fixture = fixture(FixtureMode::ShiftedAccountingValues);
        let prepared = fixture.prepared;
        let prover = halo2_proofs::dev::MockProver::run(
            VAULT_TRANSFER_K,
            &prepared.circuit(),
            prepared.public_inputs(),
        )
        .unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn rejects_external_output_claimed_as_zero_tax_change() {
        let fixture = fixture(FixtureMode::ExternalOutputClaimedAsChange);
        let prepared = fixture.prepared;
        let prover = halo2_proofs::dev::MockProver::run(
            VAULT_TRANSFER_K,
            &prepared.circuit(),
            prepared.public_inputs(),
        )
        .unwrap();
        assert!(prover.verify().is_err());
    }

    fn encode_vector_instances<const N: usize>(public: &[Vec<Fp>]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"VHV1");
        encoded.extend_from_slice(&1_u16.to_le_bytes());
        encoded.extend_from_slice(&u16::try_from(N).unwrap().to_le_bytes());
        encoded.extend_from_slice(&u16::try_from(public.len()).unwrap().to_le_bytes());
        for column in public {
            encoded.extend_from_slice(&u32::try_from(column.len()).unwrap().to_le_bytes());
            for value in column {
                encoded.extend_from_slice(value.to_repr().as_ref());
            }
        }
        encoded
    }

    fn publish_vector_if_requested<const N: usize>(public: &[Vec<Fp>], proof: &[u8]) {
        let Some(directory) = std::env::var_os("VAULT_HALO2_VECTOR_DIR") else {
            return;
        };
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).expect("create Halo2 vector directory");
        let stem = format!("halo2-transfer-v1-{N}");
        std::fs::write(
            directory.join(format!("{stem}.instances.bin")),
            encode_vector_instances::<N>(public),
        )
        .expect("write Halo2 public-instance vector");
        std::fs::write(directory.join(format!("{stem}.proof.bin")), proof)
            .expect("write Halo2 proof vector");
    }

    fn decode_vector_instances<const N: usize>(
        encoded: &[u8],
    ) -> Result<Vec<Vec<Fp>>, &'static str> {
        fn take<const M: usize>(
            encoded: &[u8],
            offset: &mut usize,
        ) -> Result<[u8; M], &'static str> {
            let end = offset
                .checked_add(M)
                .ok_or("instance-vector offset overflow")?;
            let bytes = encoded
                .get(*offset..end)
                .ok_or("truncated instance vector")?;
            *offset = end;
            bytes
                .try_into()
                .map_err(|_| "invalid instance-vector slice")
        }

        let mut offset = 0;
        if take::<4>(encoded, &mut offset)? != *b"VHV1"
            || u16::from_le_bytes(take(encoded, &mut offset)?) != 1
            || usize::from(u16::from_le_bytes(take(encoded, &mut offset)?)) != N
        {
            return Err("wrong instance-vector header");
        }
        let column_count = usize::from(u16::from_le_bytes(take(encoded, &mut offset)?));
        if column_count != 2 {
            return Err("wrong instance-vector column count");
        }

        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let rows = usize::try_from(u32::from_le_bytes(take(encoded, &mut offset)?))
                .map_err(|_| "instance-vector row count does not fit usize")?;
            let mut column = Vec::with_capacity(rows);
            for _ in 0..rows {
                let mut representation = <Fp as PrimeField>::Repr::default();
                representation
                    .as_mut()
                    .copy_from_slice(&take::<32>(encoded, &mut offset)?);
                column.push(
                    Option::<Fp>::from(Fp::from_repr(representation))
                        .ok_or("non-canonical instance field")?,
                );
            }
            columns.push(column);
        }
        if offset != encoded.len()
            || columns[0].len() != N * ORCHARD_ACTION_INSTANCE_ROWS
            || columns[1].len()
                != TRANSFER_EFFECTS_DIGEST_INSTANCE_OFFSET + TRANSFER_EFFECTS_DIGEST_LIMBS
        {
            return Err("wrong instance-vector shape or trailing bytes");
        }
        Ok(columns)
    }

    fn verify_published_vector<const N: usize>(encoded: &[u8], proof: &[u8]) {
        assert_eq!(proof.len(), MONOLITHIC_TRANSFER_PROOF_BYTES);
        let public = decode_vector_instances::<N>(encoded).expect("canonical public instances");
        let empty_circuit = valid_bucket::<N>().circuit().without_witnesses();
        let params: Params<EqAffine> = Params::new(VAULT_TRANSFER_K);
        let vk = keygen_vk(&params, &empty_circuit).expect("published vector verifying key");

        let verify = |candidate_public: &[Vec<Fp>], candidate_proof: &[u8]| {
            let columns = candidate_public
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let instances = [&columns[..]];
            let strategy = SingleVerifier::new(&params);
            let mut transcript =
                Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(candidate_proof);
            verify_proof(&params, &vk, strategy, &instances, &mut transcript)
        };

        verify(&public, proof).expect("published positive proof");
        let mut tampered_proof = proof.to_vec();
        let middle = tampered_proof.len() / 2;
        tampered_proof[middle] ^= 1;
        assert!(verify(&public, &tampered_proof).is_err());

        for column in 0..public.len() {
            for row in 0..public[column].len() {
                let mut mutated = public.clone();
                mutated[column][row] += Fp::one();
                assert!(
                    verify(&mutated, proof).is_err(),
                    "published proof accepted public mutation at column {column}, row {row}"
                );
            }
        }
    }

    fn prove_real_bucket<const N: usize>() -> (String, Vec<Vec<Fp>>, Vec<u8>) {
        let prepared = valid_bucket::<N>();
        let circuit = prepared.circuit();
        let empty_circuit = circuit.without_witnesses();
        let public = prepared.public_inputs();
        let public_columns = public.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let proof_instances = [&public_columns[..]];

        let keygen_started = Instant::now();
        let params: Params<EqAffine> = Params::new(VAULT_TRANSFER_K);
        let vk = keygen_vk(&params, &empty_circuit).expect("bucket verifying key");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("bucket proving key");
        let keygen_elapsed = keygen_started.elapsed();

        let proving_started = Instant::now();
        let mut transcript =
            Blake2bWrite::<Vec<u8>, EqAffine, Challenge255<EqAffine>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[circuit],
            &proof_instances,
            ChaCha20Rng::from_seed([u8::try_from(N).unwrap(); 32]),
            &mut transcript,
        )
        .expect("bucket proof generation");
        let proof = transcript.finalize();
        let proving_elapsed = proving_started.elapsed();

        let verification_started = Instant::now();
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(&proof);
        verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &proof_instances,
            &mut transcript,
        )
        .expect("bucket proof verification");
        let verification_elapsed = verification_started.elapsed();

        eprintln!(
            "Vault bucket={N} keygen={keygen_elapsed:?} prove={proving_elapsed:?} verify={verification_elapsed:?} proof_bytes={}",
            proof.len()
        );
        publish_vector_if_requested::<N>(&public, &proof);
        (format!("{:?}", pk.get_vk().pinned()), public, proof)
    }

    fn benchmark_real_bucket<const N: usize>(repetitions: usize) {
        for repetition in 1..=repetitions {
            let prepared = valid_bucket::<N>();
            let circuit = prepared.circuit();
            let empty_circuit = circuit.without_witnesses();
            let public = prepared.public_inputs();
            let public_columns = public.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let proof_instances = [&public_columns[..]];

            let keygen_started = Instant::now();
            let params: Params<EqAffine> = Params::new(VAULT_TRANSFER_K);
            let vk = keygen_vk(&params, &empty_circuit).expect("benchmark verifying key");
            let pk = keygen_pk(&params, vk, &empty_circuit).expect("benchmark proving key");
            let keygen_ms = keygen_started.elapsed().as_millis();

            let proving_started = Instant::now();
            let mut transcript =
                Blake2bWrite::<Vec<u8>, EqAffine, Challenge255<EqAffine>>::init(vec![]);
            create_proof(
                &params,
                &pk,
                &[circuit],
                &proof_instances,
                ChaCha20Rng::from_seed([u8::try_from(N).unwrap(); 32]),
                &mut transcript,
            )
            .expect("benchmark proof generation");
            let proof = transcript.finalize();
            let proving_ms = proving_started.elapsed().as_millis();

            let verification_started = Instant::now();
            let strategy = SingleVerifier::new(&params);
            let mut transcript =
                Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(&proof);
            verify_proof(
                &params,
                pk.get_vk(),
                strategy,
                &proof_instances,
                &mut transcript,
            )
            .expect("benchmark proof verification");
            let verification_us = verification_started.elapsed().as_micros();

            eprintln!(
                "VAULT_C6_METRIC backend=halo2 bucket={N} repetition={repetition} keygen_ms={keygen_ms} prove_ms={proving_ms} verify_us={verification_us} proof_bytes={}",
                proof.len()
            );
        }
    }

    #[test]
    #[ignore = "C6 benchmark runs only through scripts/benchmark-zk-c6-halo2-macos.sh"]
    fn c6_halo2_bucket_benchmark() {
        let bucket = std::env::var("VAULT_C6_BUCKET")
            .expect("VAULT_C6_BUCKET must select 2, 4, 8, or 16")
            .parse::<usize>()
            .expect("VAULT_C6_BUCKET must be an integer");
        let repetitions = std::env::var("VAULT_C6_REPETITIONS")
            .unwrap_or_else(|_| "3".to_owned())
            .parse::<usize>()
            .expect("VAULT_C6_REPETITIONS must be an integer");
        assert!((1..=20).contains(&repetitions));

        match bucket {
            2 => benchmark_real_bucket::<2>(repetitions),
            4 => benchmark_real_bucket::<4>(repetitions),
            8 => benchmark_real_bucket::<8>(repetitions),
            16 => benchmark_real_bucket::<16>(repetitions),
            _ => panic!("VAULT_C6_BUCKET must select 2, 4, 8, or 16"),
        }
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "real all-bucket proof evidence runs in the release-mode Halo2 CI gate"
    )]
    fn real_monolithic_proof_covers_every_consensus_bucket() {
        let mut hasher = blake3::Hasher::new_derive_key(MONOLITHIC_TRANSFER_SUITE_ID_DOMAIN);
        for (bucket, (pinned, _, _)) in [
            (2_u16, prove_real_bucket::<2>()),
            (4_u16, prove_real_bucket::<4>()),
            (8_u16, prove_real_bucket::<8>()),
            (16_u16, prove_real_bucket::<16>()),
        ] {
            hasher.update(&bucket.to_le_bytes());
            hasher.update(&(pinned.len() as u64).to_le_bytes());
            hasher.update(pinned.as_bytes());
        }
        let suite_id = hasher.finalize();
        assert_eq!(suite_id.as_bytes(), &MONOLITHIC_TRANSFER_SUITE_ID);
        eprintln!("Vault monolithic suite_id={}", suite_id.to_hex());
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "published real-proof vectors are verified by the release-mode offline gate"
    )]
    fn published_halo2_vectors_verify_offline_and_reject_mutations() {
        verify_published_vector::<2>(
            include_bytes!("../tests/vectors/halo2-transfer-v1-2.instances.bin"),
            include_bytes!("../tests/vectors/halo2-transfer-v1-2.proof.bin"),
        );
        verify_published_vector::<4>(
            include_bytes!("../tests/vectors/halo2-transfer-v1-4.instances.bin"),
            include_bytes!("../tests/vectors/halo2-transfer-v1-4.proof.bin"),
        );
        verify_published_vector::<8>(
            include_bytes!("../tests/vectors/halo2-transfer-v1-8.instances.bin"),
            include_bytes!("../tests/vectors/halo2-transfer-v1-8.proof.bin"),
        );
        verify_published_vector::<16>(
            include_bytes!("../tests/vectors/halo2-transfer-v1-16.instances.bin"),
            include_bytes!("../tests/vectors/halo2-transfer-v1-16.proof.bin"),
        );
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "real proof evidence runs in the release-mode Halo2 CI gate"
    )]
    fn real_monolithic_transfer_proof_round_trip_is_fail_closed() {
        let fixture = fixture(FixtureMode::Valid);
        let prepared = fixture.prepared;
        let circuit = prepared.circuit();
        let empty_circuit = circuit.without_witnesses();
        let public = prepared.public_inputs();
        let public_columns = public.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let proof_instances = [&public_columns[..]];

        let keygen_started = Instant::now();
        let params: Params<EqAffine> = Params::new(VAULT_TRANSFER_K);
        let vk = keygen_vk(&params, &empty_circuit).expect("Vault transfer verifying key");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("Vault transfer proving key");
        let keygen_elapsed = keygen_started.elapsed();

        let proving_started = Instant::now();
        let mut transcript =
            Blake2bWrite::<Vec<u8>, EqAffine, Challenge255<EqAffine>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[circuit],
            &proof_instances,
            ChaCha20Rng::from_seed([0xC7; 32]),
            &mut transcript,
        )
        .expect("Vault transfer proof generation");
        let proof = transcript.finalize();
        let proving_elapsed = proving_started.elapsed();

        let verification_started = Instant::now();
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(&proof);
        verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &proof_instances,
            &mut transcript,
        )
        .expect("Vault transfer proof verification");
        let verification_elapsed = verification_started.elapsed();

        let mut tampered_proof = proof.clone();
        let middle = tampered_proof.len() / 2;
        tampered_proof[middle] ^= 1;
        let strategy = SingleVerifier::new(&params);
        let mut transcript =
            Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(&tampered_proof);
        assert!(
            verify_proof(
                &params,
                pk.get_vk(),
                strategy,
                &proof_instances,
                &mut transcript,
            )
            .is_err()
        );

        let public_instance_cells = public.iter().map(Vec::len).sum::<usize>();
        for column in 0..public.len() {
            for row in 0..public[column].len() {
                let mut wrong_public = public.clone();
                wrong_public[column][row] += Fp::one();
                let wrong_columns = wrong_public.iter().map(Vec::as_slice).collect::<Vec<_>>();
                let wrong_instances = [&wrong_columns[..]];
                let strategy = SingleVerifier::new(&params);
                let mut transcript =
                    Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(&proof);
                assert!(
                    verify_proof(
                        &params,
                        pk.get_vk(),
                        strategy,
                        &wrong_instances,
                        &mut transcript,
                    )
                    .is_err(),
                    "proof accepted mutated public instance at column {column}, row {row}"
                );
            }
        }

        eprintln!(
            "Vault transfer keygen={keygen_elapsed:?} prove={proving_elapsed:?} verify={verification_elapsed:?} proof_bytes={} mutated_public_cells={public_instance_cells}",
            proof.len(),
        );
    }
}
