//! Halo2 gadget for equality of the exact burn arithmetic, commitment, and
//! threshold-ElGamal plaintext.
//!
//! The gadget accepts the parent's already range-constrained private burn cell.
//! It proves the Orchard value-commitment opening and both Pallas ciphertext
//! equations under an instance-bound epoch public key. It is a reusable part of
//! the final accounting circuit, not a standalone consensus verifier.

use ff::{Field, PrimeField};
use halo2_gadgets::{
    ecc::{
        FixedPoints, NonIdentityPoint, Point, ScalarVar,
        chip::{
            BaseFieldElem, CircuitVersion, EccChip, EccConfig, FixedPoint, FullScalar, H,
            ShortScalar,
        },
    },
    utilities::lookup_range_check::{LookupRangeCheck, PallasLookupRangeCheckConfig},
};
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, TableColumn},
};
use pasta_curves::{
    arithmetic::CurveExt,
    group::{Curve, Group, GroupEncoding},
    pallas,
};
use thiserror::Error;
use vault_burn::{EpochBurnPublicKey, PreparedBurnCiphertext, burn_message_generator_bytes};
use vault_privacy::PreparedBurnCommitment;
use zeroize::Zeroizing;

use crate::accounting::{
    AccountingArithmeticCircuit, AccountingArithmeticConfig, PreparedAccountingArithmetic,
};

const VALUE_COMMITMENT_PERSONALIZATION: &str = "z.cash:Orchard-cv";
const VALUE_COMMITMENT_VALUE_INPUT: &[u8] = b"v";
const VALUE_COMMITMENT_RANDOMNESS_INPUT: &[u8] = b"r";
const ECC_LOOKUP_BITS: usize = 10;

/// First instance row used by the binding when composed after public gas.
pub const BURN_BINDING_INSTANCE_OFFSET: usize = 2;
/// Two affine coordinates for each of commitment, C1, C2, and epoch key.
pub const BURN_BINDING_INSTANCE_VALUES: usize = 8;
/// Conservative degree parameter for the standalone gadget harness.
pub const BURN_BINDING_TEST_K: u32 = 14;
/// Degree parameter for the currently integrated arithmetic and burn-binding
/// circuit across all padded action buckets.
pub const ACCOUNTING_BURN_K: u32 = 14;

/// Failure to build a circuit witness from independently typed native data.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BurnBindingError {
    /// The commitment, ciphertext, and arithmetic do not carry one exact burn.
    #[error("burn binding amounts differ")]
    AmountMismatch,
    /// A secret scalar is not representable by the pinned circuit encoding.
    #[error("burn binding scalar is not circuit-compatible")]
    InvalidCircuitScalar,
    /// A public point is malformed, the identity, or inconsistent with secrets.
    #[error("burn binding point equation failed")]
    InvalidPointEquation,
}

/// Cross-checked secret and public data consumed by [`BurnBindingConfig`].
#[derive(Clone)]
pub struct PreparedBurnBinding {
    commitment_randomness: Zeroizing<[u8; 32]>,
    encryption_randomness: Zeroizing<[u8; 32]>,
    commitment: pallas::Affine,
    c1: pallas::Affine,
    c2: pallas::Affine,
    epoch_public_key: pallas::Affine,
}

impl std::fmt::Debug for PreparedBurnBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedBurnBinding")
            .field("commitment_randomness", &"REDACTED")
            .field("encryption_randomness", &"REDACTED")
            .field("public_points", &4)
            .finish()
    }
}

impl PreparedBurnBinding {
    /// Verifies the native equations before retaining a circuit witness.
    pub fn new(
        expected_burn: u64,
        commitment: &PreparedBurnCommitment,
        ciphertext: &PreparedBurnCiphertext,
        epoch_key: &EpochBurnPublicKey,
    ) -> Result<Self, BurnBindingError> {
        if commitment.amount() != expected_burn || ciphertext.amount() != expected_burn {
            return Err(BurnBindingError::AmountMismatch);
        }

        let commitment_randomness = commitment.trapdoor();
        let encryption_randomness = ciphertext.randomness();
        let commitment_scalar = circuit_scalar(&commitment_randomness)?;
        let encryption_scalar = circuit_scalar(&encryption_randomness)?;
        let commitment_point = parse_nonidentity(commitment.commitment().to_bytes())?;
        let ciphertext_bytes = ciphertext.ciphertext().to_bytes();
        let c1 = parse_nonidentity(
            ciphertext_bytes[..32]
                .try_into()
                .expect("fixed ciphertext component"),
        )?;
        let c2 = parse_nonidentity(
            ciphertext_bytes[32..]
                .try_into()
                .expect("fixed ciphertext component"),
        )?;
        let epoch_public_key = parse_nonidentity(epoch_key.encryption_key())?;

        let value_generator = value_commitment_generator(VALUE_COMMITMENT_VALUE_INPUT);
        let randomness_generator = value_commitment_generator(VALUE_COMMITMENT_RANDOMNESS_INPUT);
        let message_generator = parse_nonidentity(burn_message_generator_bytes())?;
        let burn_scalar = pallas::Scalar::from(expected_burn);
        if value_generator * burn_scalar + randomness_generator * commitment_scalar
            != pallas::Point::from(commitment_point)
            || pallas::Point::generator() * encryption_scalar != pallas::Point::from(c1)
            || message_generator * burn_scalar
                + pallas::Point::from(epoch_public_key) * encryption_scalar
                != pallas::Point::from(c2)
        {
            return Err(BurnBindingError::InvalidPointEquation);
        }

        Ok(Self {
            commitment_randomness,
            encryption_randomness,
            commitment: commitment_point,
            c1,
            c2,
            epoch_public_key,
        })
    }

    /// Instance values reconstructed by the verifier from typed effects and
    /// its activated epoch-key descriptor.
    #[must_use]
    pub fn public_inputs(&self) -> [pallas::Base; BURN_BINDING_INSTANCE_VALUES] {
        let points = [self.commitment, self.c1, self.c2, self.epoch_public_key];
        let mut values = [pallas::Base::ZERO; BURN_BINDING_INSTANCE_VALUES];
        for (index, point) in points.iter().enumerate() {
            let coordinates = point
                .coordinates()
                .expect("prepared burn binding excludes identity points");
            values[index * 2] = *coordinates.x();
            values[index * 2 + 1] = *coordinates.y();
        }
        values
    }
}

/// One witness whose exact arithmetic burn is also the committed and encrypted
/// burn. Recipient/change classification and note-value linkage remain outside
/// this type, so it deliberately has no consensus verifier implementation.
#[derive(Clone, Debug)]
pub struct PreparedAccountingBurn<const N: usize> {
    arithmetic: PreparedAccountingArithmetic<N>,
    binding: PreparedBurnBinding,
}

impl<const N: usize> PreparedAccountingBurn<N> {
    /// Joins independently checked arithmetic and cryptographic inputs and
    /// rejects any amount disagreement before Halo2 synthesis.
    pub fn new(
        arithmetic: PreparedAccountingArithmetic<N>,
        commitment: &PreparedBurnCommitment,
        ciphertext: &PreparedBurnCiphertext,
        epoch_key: &EpochBurnPublicKey,
    ) -> Result<Self, BurnBindingError> {
        let binding =
            PreparedBurnBinding::new(arithmetic.burn(), commitment, ciphertext, epoch_key)?;
        Ok(Self {
            arithmetic,
            binding,
        })
    }

    /// Builds the single circuit shape in which the arithmetic and ECC gadget
    /// share one constrained burn cell.
    #[must_use]
    pub fn circuit(&self) -> AccountingBurnCircuit<N> {
        AccountingBurnCircuit {
            witness: Some(self.clone()),
        }
    }

    /// Public gas followed by commitment, C1, C2, and epoch-key coordinates.
    #[must_use]
    pub fn public_inputs(&self) -> Vec<Vec<pallas::Base>> {
        let mut row = self
            .arithmetic
            .public_inputs()
            .pop()
            .expect("accounting arithmetic has one instance column");
        row.extend_from_slice(&self.binding.public_inputs());
        vec![row]
    }

    pub(crate) const fn arithmetic(&self) -> &PreparedAccountingArithmetic<N> {
        &self.arithmetic
    }

    pub(crate) const fn binding(&self) -> &PreparedBurnBinding {
        &self.binding
    }
}

/// Integrated private arithmetic plus burn commitment/ciphertext circuit.
#[derive(Clone, Debug)]
pub struct AccountingBurnCircuit<const N: usize> {
    witness: Option<PreparedAccountingBurn<N>>,
}

/// Configuration for [`AccountingBurnCircuit`].
#[derive(Clone, Debug)]
pub struct AccountingBurnConfig {
    arithmetic: AccountingArithmeticConfig,
    binding: BurnBindingConfig,
}

impl<const N: usize> Circuit<pallas::Base> for AccountingBurnCircuit<N> {
    type Config = AccountingBurnConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { witness: None }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let arithmetic = AccountingArithmeticCircuit::<N>::configure(meta);
        let ecc_advices = std::array::from_fn(|_| meta.advice_column());
        let binding = BurnBindingConfig::configure(meta, ecc_advices, arithmetic.instance);
        AccountingBurnConfig {
            arithmetic,
            binding,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        config
            .binding
            .load(layouter.namespace(|| "burn-binding lookup"))?;
        let arithmetic = AccountingArithmeticCircuit {
            witness: self
                .witness
                .as_ref()
                .map(|prepared| prepared.arithmetic.clone()),
        };
        let summary = arithmetic.synthesize_with_summary(
            config.arithmetic,
            &mut layouter.namespace(|| "accounting arithmetic"),
        )?;
        config.binding.assign(
            layouter.namespace(|| "same-cell burn binding"),
            &summary.burn,
            self.witness.as_ref().map(|prepared| &prepared.binding),
            BURN_BINDING_INSTANCE_OFFSET,
        )
    }
}

/// Configured Pallas ECC equations. The parent owns the arithmetic cells and
/// the shared instance column.
#[derive(Clone, Debug)]
pub struct BurnBindingConfig {
    ecc: EccConfig<NoFixedBases>,
    lookup_table: TableColumn,
    instance: Column<Instance>,
}

impl BurnBindingConfig {
    /// Adds the exact ECC constraints to a parent circuit.
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 10],
        instance: Column<Instance>,
    ) -> Self {
        let lagrange_coefficients = std::array::from_fn(|_| meta.fixed_column());
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let lookup_table = meta.lookup_table_column();
        let range_check = PallasLookupRangeCheckConfig::configure(meta, advices[9], lookup_table);
        let ecc =
            EccChip::<NoFixedBases>::configure(meta, advices, lagrange_coefficients, range_check);
        meta.enable_equality(instance);
        Self {
            ecc,
            lookup_table,
            instance,
        }
    }

    /// Loads the 10-bit range table required by variable-base scalar
    /// multiplication. The parent calls this exactly once per circuit.
    pub fn load(&self, mut layouter: impl Layouter<pallas::Base>) -> Result<(), Error> {
        layouter.assign_table(
            || "burn-binding 10-bit range table",
            |mut table| {
                for value in 0..(1 << ECC_LOOKUP_BITS) {
                    table.assign_cell(
                        || "range value",
                        self.lookup_table,
                        value,
                        || Value::known(pallas::Base::from(value as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }

    /// Constrains the parent's private burn cell to the public commitment and
    /// ciphertext. Public rows start at `instance_offset`.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        burn: &AssignedCell<pallas::Base, pallas::Base>,
        witness: Option<&PreparedBurnBinding>,
        instance_offset: usize,
    ) -> Result<(), Error> {
        let chip =
            EccChip::<NoFixedBases>::construct(self.ecc.clone(), CircuitVersion::AnchoredBase);
        let commitment_randomness = assign_scalar(
            layouter.namespace(|| "burn commitment randomness"),
            self.ecc.advices[0],
            witness.map(|value| *value.commitment_randomness),
        )?;
        let encryption_randomness = assign_scalar(
            layouter.namespace(|| "burn encryption randomness"),
            self.ecc.advices[0],
            witness.map(|value| *value.encryption_randomness),
        )?;
        let commitment_randomness = ScalarVar::from_base(
            chip.clone(),
            layouter.namespace(|| "commitment randomness as scalar"),
            &commitment_randomness,
        )?;

        let value_generator = constant_nonidentity(
            chip.clone(),
            layouter.namespace(|| "ValueCommitV"),
            value_commitment_generator(VALUE_COMMITMENT_VALUE_INPUT).to_affine(),
        )?;
        let randomness_generator = constant_nonidentity(
            chip.clone(),
            layouter.namespace(|| "ValueCommitR"),
            value_commitment_generator(VALUE_COMMITMENT_RANDOMNESS_INPUT).to_affine(),
        )?;
        let pallas_generator = constant_nonidentity(
            chip.clone(),
            layouter.namespace(|| "Pallas G"),
            pallas::Point::generator().to_affine(),
        )?;
        let message_generator = constant_nonidentity(
            chip.clone(),
            layouter.namespace(|| "burn H"),
            parse_nonidentity(burn_message_generator_bytes()).map_err(|_| Error::Synthesis)?,
        )?;

        let public_commitment = public_nonidentity(
            chip.clone(),
            layouter.namespace(|| "public burn commitment"),
            witness.map(|value| value.commitment),
        )?;
        let public_c1 = public_nonidentity(
            chip.clone(),
            layouter.namespace(|| "public burn C1"),
            witness.map(|value| value.c1),
        )?;
        let public_c2 = public_nonidentity(
            chip.clone(),
            layouter.namespace(|| "public burn C2"),
            witness.map(|value| value.c2),
        )?;
        let public_key = public_nonidentity(
            chip.clone(),
            layouter.namespace(|| "public epoch key"),
            witness.map(|value| value.epoch_public_key),
        )?;

        constrain_public_point(
            &mut layouter,
            &public_commitment,
            self.instance,
            instance_offset,
        )?;
        constrain_public_point(
            &mut layouter,
            &public_c1,
            self.instance,
            instance_offset + 2,
        )?;
        constrain_public_point(
            &mut layouter,
            &public_c2,
            self.instance,
            instance_offset + 4,
        )?;
        constrain_public_point(
            &mut layouter,
            &public_key,
            self.instance,
            instance_offset + 6,
        )?;

        let burn_for_commitment = ScalarVar::from_base(
            chip.clone(),
            layouter.namespace(|| "burn scalar for commitment"),
            burn,
        )?;
        let (value_term, _) = value_generator.mul(
            layouter.namespace(|| "[burn]ValueCommitV"),
            burn_for_commitment,
        )?;
        let (commitment_blind, _) = randomness_generator.mul(
            layouter.namespace(|| "[rcv]ValueCommitR"),
            commitment_randomness,
        )?;
        let computed_commitment = value_term.add(
            layouter.namespace(|| "burn value commitment"),
            &commitment_blind,
        )?;
        computed_commitment.constrain_equal(
            layouter.namespace(|| "bind burn commitment"),
            &public_commitment,
        )?;

        let randomness_for_c1 = ScalarVar::from_base(
            chip.clone(),
            layouter.namespace(|| "encryption scalar for C1"),
            &encryption_randomness,
        )?;
        let (computed_c1, _) =
            pallas_generator.mul(layouter.namespace(|| "C1 = [r]G"), randomness_for_c1)?;
        computed_c1.constrain_equal(layouter.namespace(|| "bind C1"), &public_c1)?;

        let burn_for_ciphertext = ScalarVar::from_base(
            chip.clone(),
            layouter.namespace(|| "burn scalar for ciphertext"),
            burn,
        )?;
        let (message, _) =
            message_generator.mul(layouter.namespace(|| "[burn]H"), burn_for_ciphertext)?;
        let randomness_for_mask = ScalarVar::from_base(
            chip,
            layouter.namespace(|| "encryption scalar for mask"),
            &encryption_randomness,
        )?;
        let (encryption_mask, _) =
            public_key.mul(layouter.namespace(|| "[r]PK_epoch"), randomness_for_mask)?;
        let computed_c2 = message.add(layouter.namespace(|| "C2 equation"), &encryption_mask)?;
        computed_c2.constrain_equal(layouter.namespace(|| "bind C2"), &public_c2)
    }
}

type BurnEccChip = EccChip<NoFixedBases>;
type BurnNonIdentityPoint = NonIdentityPoint<pallas::Affine, BurnEccChip>;

fn assign_scalar(
    mut layouter: impl Layouter<pallas::Base>,
    column: Column<Advice>,
    bytes: Option<[u8; 32]>,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    layouter.assign_region(
        || "circuit-compatible scalar",
        |mut region| {
            region.assign_advice(
                || "scalar",
                column,
                0,
                || {
                    bytes.map_or_else(Value::unknown, |bytes| {
                        Value::known(
                            Option::<pallas::Base>::from(pallas::Base::from_repr(bytes))
                                .expect("prepared scalar is canonical"),
                        )
                    })
                },
            )
        },
    )
}

fn constant_nonidentity(
    chip: BurnEccChip,
    mut layouter: impl Layouter<pallas::Base>,
    value: pallas::Affine,
) -> Result<BurnNonIdentityPoint, Error> {
    let witnessed = NonIdentityPoint::new(
        chip.clone(),
        layouter.namespace(|| "witness constant point"),
        Value::known(value),
    )?;
    let constant =
        Point::new_from_constant(chip, layouter.namespace(|| "load constant point"), value)?;
    witnessed.constrain_equal(layouter.namespace(|| "fix point constant"), &constant)?;
    Ok(witnessed)
}

fn public_nonidentity(
    chip: BurnEccChip,
    layouter: impl Layouter<pallas::Base>,
    value: Option<pallas::Affine>,
) -> Result<BurnNonIdentityPoint, Error> {
    NonIdentityPoint::new(
        chip,
        layouter,
        value.map_or_else(Value::unknown, Value::known),
    )
}

fn constrain_public_point(
    layouter: &mut impl Layouter<pallas::Base>,
    point: &BurnNonIdentityPoint,
    instance: Column<Instance>,
    offset: usize,
) -> Result<(), Error> {
    layouter.constrain_instance(point.inner().x().cell(), instance, offset)?;
    layouter.constrain_instance(point.inner().y().cell(), instance, offset + 1)
}

fn value_commitment_generator(input: &[u8]) -> pallas::Point {
    pallas::Point::hash_to_curve(VALUE_COMMITMENT_PERSONALIZATION)(input)
}

fn circuit_scalar(bytes: &[u8; 32]) -> Result<pallas::Scalar, BurnBindingError> {
    Option::<pallas::Base>::from(pallas::Base::from_repr(*bytes))
        .ok_or(BurnBindingError::InvalidCircuitScalar)?;
    Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(*bytes))
        .ok_or(BurnBindingError::InvalidCircuitScalar)
}

fn parse_nonidentity(bytes: [u8; 32]) -> Result<pallas::Affine, BurnBindingError> {
    Option::<pallas::Point>::from(pallas::Point::from_bytes(&bytes))
        .filter(|point| !bool::from(point.is_identity()))
        .map(|point| point.to_affine())
        .ok_or(BurnBindingError::InvalidPointEquation)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NoFixedBases;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoFullScalar {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoShortScalar {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoBaseScalar {}

impl FixedPoints<pallas::Affine> for NoFixedBases {
    type FullScalar = NoFullScalar;
    type ShortScalar = NoShortScalar;
    type Base = NoBaseScalar;
}

macro_rules! impl_uninhabited_fixed_point {
    ($type:ty, $kind:ty) => {
        impl FixedPoint<pallas::Affine> for $type {
            type FixedScalarKind = $kind;

            fn generator(&self) -> pallas::Affine {
                match *self {}
            }

            fn u(&self) -> Vec<[[u8; 32]; H]> {
                match *self {}
            }

            fn z(&self) -> Vec<u64> {
                match *self {}
            }
        }
    };
}

impl_uninhabited_fixed_point!(NoFullScalar, FullScalar);
impl_uninhabited_fixed_point!(NoShortScalar, ShortScalar);
impl_uninhabited_fixed_point!(NoBaseScalar, BaseFieldElem);

#[cfg(test)]
mod tests {
    use ff::Field;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    use super::*;

    const MAXIMUM_AMOUNT: u64 = 21_000_000 * 1_000_000_000;

    #[derive(Clone, Debug)]
    struct Harness {
        burn: Option<u64>,
        binding: Option<PreparedBurnBinding>,
    }

    #[derive(Clone, Debug)]
    struct HarnessConfig {
        burn: Column<Advice>,
        binding: BurnBindingConfig,
    }

    impl Circuit<pallas::Base> for Harness {
        type Config = HarnessConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                burn: None,
                binding: None,
            }
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            let instance = meta.instance_column();
            let burn = meta.advice_column();
            meta.enable_equality(burn);
            let advices = std::array::from_fn(|_| meta.advice_column());
            let binding = BurnBindingConfig::configure(meta, advices, instance);
            HarnessConfig { burn, binding }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            config.binding.load(layouter.namespace(|| "lookup table"))?;
            let burn = layouter.assign_region(
                || "parent burn cell",
                |mut region| {
                    region.assign_advice(
                        || "burn",
                        config.burn,
                        0,
                        || {
                            self.burn.map_or_else(Value::unknown, |burn| {
                                Value::known(pallas::Base::from(burn))
                            })
                        },
                    )
                },
            )?;
            config.binding.assign(
                layouter.namespace(|| "burn binding"),
                &burn,
                self.binding.as_ref(),
                0,
            )
        }
    }

    fn fixture() -> (Harness, Vec<Vec<pallas::Base>>) {
        let coefficients = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
        let commitments = coefficients.map(|value| (pallas::Point::generator() * value).to_bytes());
        let epoch_key =
            EpochBurnPublicKey::from_parts(9, 2, vec![1, 2, 3], commitments.to_vec()).unwrap();
        let mut commitment_rng = ChaCha20Rng::from_seed([0xB8; 32]);
        let commitment =
            PreparedBurnCommitment::create(25, MAXIMUM_AMOUNT, &mut commitment_rng).unwrap();
        let mut encryption_rng = ChaCha20Rng::from_seed([0xB9; 32]);
        let ciphertext =
            PreparedBurnCiphertext::encrypt(25, MAXIMUM_AMOUNT, &epoch_key, &mut encryption_rng)
                .unwrap();
        let binding = PreparedBurnBinding::new(25, &commitment, &ciphertext, &epoch_key).unwrap();
        let public = vec![binding.public_inputs().to_vec()];
        (
            Harness {
                burn: Some(25),
                binding: Some(binding),
            },
            public,
        )
    }

    #[test]
    fn exact_burn_opens_commitment_and_both_ciphertext_equations() {
        let (harness, public) = fixture();
        MockProver::run(BURN_BINDING_TEST_K, &harness, public)
            .unwrap()
            .assert_satisfied();
    }

    #[test]
    fn integrated_circuit_uses_the_arithmetic_burn_cell() {
        let arithmetic = PreparedAccountingArithmetic::new(
            [
                crate::accounting::AccountingActionWitness::enabled(5_051, 5_000, true),
                crate::accounting::AccountingActionWitness::dummy(),
            ],
            2,
            13,
        )
        .unwrap();
        assert_eq!(arithmetic.burn(), 25);

        let coefficients = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
        let commitments = coefficients.map(|value| (pallas::Point::generator() * value).to_bytes());
        let epoch_key =
            EpochBurnPublicKey::from_parts(9, 2, vec![1, 2, 3], commitments.to_vec()).unwrap();
        let mut commitment_rng = ChaCha20Rng::from_seed([0xBB; 32]);
        let commitment =
            PreparedBurnCommitment::create(25, MAXIMUM_AMOUNT, &mut commitment_rng).unwrap();
        let mut encryption_rng = ChaCha20Rng::from_seed([0xBC; 32]);
        let ciphertext =
            PreparedBurnCiphertext::encrypt(25, MAXIMUM_AMOUNT, &epoch_key, &mut encryption_rng)
                .unwrap();
        let prepared =
            PreparedAccountingBurn::new(arithmetic, &commitment, &ciphertext, &epoch_key).unwrap();
        let public = prepared.public_inputs();
        MockProver::run(ACCOUNTING_BURN_K, &prepared.circuit(), public.clone())
            .unwrap()
            .assert_satisfied();

        let mut wrong_ciphertext = public;
        wrong_ciphertext[0][BURN_BINDING_INSTANCE_OFFSET + 4] += pallas::Base::ONE;
        let prover =
            MockProver::run(ACCOUNTING_BURN_K, &prepared.circuit(), wrong_ciphertext).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn wrong_burn_or_public_ciphertext_fails() {
        let (mut harness, public) = fixture();
        harness.burn = Some(24);
        let prover = MockProver::run(BURN_BINDING_TEST_K, &harness, public.clone()).unwrap();
        assert!(prover.verify().is_err());

        let (harness, mut public) = fixture();
        public[0][4] += pallas::Base::ONE;
        let prover = MockProver::run(BURN_BINDING_TEST_K, &harness, public).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn preparation_rejects_amount_mismatch() {
        let coefficients = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
        let commitments = coefficients.map(|value| (pallas::Point::generator() * value).to_bytes());
        let epoch_key =
            EpochBurnPublicKey::from_parts(9, 2, vec![1, 2, 3], commitments.to_vec()).unwrap();
        let mut rng = ChaCha20Rng::from_seed([0xBA; 32]);
        let commitment = PreparedBurnCommitment::create(25, MAXIMUM_AMOUNT, &mut rng).unwrap();
        let ciphertext =
            PreparedBurnCiphertext::encrypt(25, MAXIMUM_AMOUNT, &epoch_key, &mut rng).unwrap();
        assert!(matches!(
            PreparedBurnBinding::new(24, &commitment, &ciphertext, &epoch_key),
            Err(BurnBindingError::AmountMismatch)
        ));
    }
}
