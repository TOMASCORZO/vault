//! Range-constrained private arithmetic for Vault transfer-v2 accounting.
//!
//! This module implements the arithmetic part of the mandatory second proof:
//! padded-action semantics, 64-bit ranges, public gas multiplication, exact
//! ceiling 0.5% burn, and conservation. It deliberately does not implement an
//! [`super::AccountingProofVerifier`]. The circuit cannot become consensus
//! eligible until its private values and taxable/change classification are
//! cryptographically linked to the Action statement, note commitments, burn
//! commitment, and threshold ciphertext.

use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector, TableColumn},
    poly::Rotation,
};
use pasta_curves::pallas;
use thiserror::Error;
use vault_protocol::ALLOWED_TRANSFER_V2_ACTION_COUNTS;

const BURN_DIVISOR: u64 = 200;
const RANGE_BITS: usize = 64;

/// Degree parameter large enough for every currently allowed action bucket.
pub const ACCOUNTING_ARITHMETIC_K: u32 = 12;

/// Native preparation failures. These checks give the prover an early,
/// deterministic error; identical relationships are independently constrained
/// in Halo2.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AccountingArithmeticError {
    /// The const-generic action count is not one of the consensus buckets.
    #[error("unsupported accounting action count")]
    UnsupportedActionCount,
    /// The private dummy marker does not exactly match zero input and output,
    /// or a dummy carries a taxable marker.
    #[error("accounting dummy marker is inconsistent with its values")]
    InvalidDummyAction,
    /// Gas units and fee per gas must both be non-zero.
    #[error("invalid accounting gas parameters")]
    InvalidGas,
    /// A sum, product, or rounded burn exceeds 64-bit monetary arithmetic.
    #[error("accounting arithmetic overflow")]
    ArithmeticOverflow,
    /// Inputs do not exactly fund outputs, burn, and gas.
    #[error("accounting witness does not conserve value")]
    InvalidConservation,
}

/// Private amount data for one fixed-shape action slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountingActionWitness {
    input: u64,
    output: u64,
    enabled: bool,
    taxable: bool,
}

impl AccountingActionWitness {
    /// Creates an enabled action. `taxable` must eventually be derived from the
    /// proven recipient/sender relationship; it is not accepted as an
    /// unconstrained consensus label by any verifier in this repository.
    #[must_use]
    pub const fn enabled(input: u64, output: u64, taxable: bool) -> Self {
        Self {
            input,
            output,
            enabled: true,
            taxable,
        }
    }

    /// Creates a value-free padding slot.
    #[must_use]
    pub const fn dummy() -> Self {
        Self {
            input: 0,
            output: 0,
            enabled: false,
            taxable: false,
        }
    }

    /// Hidden input amount.
    #[must_use]
    pub const fn input(self) -> u64 {
        self.input
    }

    /// Hidden paired-output amount.
    #[must_use]
    pub const fn output(self) -> u64 {
        self.output
    }

    /// Whether this is a non-padding action.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }

    /// Whether this output contributes to the burn base.
    #[must_use]
    pub const fn is_taxable(self) -> bool {
        self.taxable
    }
}

/// Fully checked witness for the arithmetic component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAccountingArithmetic<const N: usize> {
    actions: [AccountingActionWitness; N],
    gas_units: u64,
    fee_per_gas: u64,
    total_inputs: u64,
    total_outputs: u64,
    taxable: u64,
    gas_fee: u64,
    burn: u64,
}

impl<const N: usize> PreparedAccountingArithmetic<N> {
    /// Checks the native oracle and prepares the same values for Halo2.
    pub fn new(
        actions: [AccountingActionWitness; N],
        gas_units: u64,
        fee_per_gas: u64,
    ) -> Result<Self, AccountingArithmeticError> {
        if !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&N) {
            return Err(AccountingArithmeticError::UnsupportedActionCount);
        }
        if gas_units == 0 || fee_per_gas == 0 {
            return Err(AccountingArithmeticError::InvalidGas);
        }
        if actions.iter().any(|action| {
            action.enabled != (action.input != 0 || action.output != 0)
                || (!action.enabled && action.taxable)
        }) {
            return Err(AccountingArithmeticError::InvalidDummyAction);
        }

        let total_inputs = checked_sum(actions.iter().map(|action| action.input))?;
        let total_outputs = checked_sum(actions.iter().map(|action| action.output))?;
        let taxable = checked_sum(
            actions
                .iter()
                .map(|action| if action.taxable { action.output } else { 0 }),
        )?;
        let gas_fee = gas_units
            .checked_mul(fee_per_gas)
            .ok_or(AccountingArithmeticError::ArithmeticOverflow)?;
        let quotient = taxable / BURN_DIVISOR;
        let remainder = taxable % BURN_DIVISOR;
        let burn = quotient
            .checked_add(u64::from(remainder != 0))
            .ok_or(AccountingArithmeticError::ArithmeticOverflow)?;
        let required = total_outputs
            .checked_add(burn)
            .and_then(|value| value.checked_add(gas_fee))
            .ok_or(AccountingArithmeticError::ArithmeticOverflow)?;
        if total_inputs != required {
            return Err(AccountingArithmeticError::InvalidConservation);
        }

        Ok(Self {
            actions,
            gas_units,
            fee_per_gas,
            total_inputs,
            total_outputs,
            taxable,
            gas_fee,
            burn,
        })
    }

    /// Exact hidden burn derived as `ceil(taxable / 200)`.
    #[must_use]
    pub const fn burn(&self) -> u64 {
        self.burn
    }

    /// Total public gas fee funded by the hidden inputs.
    #[must_use]
    pub const fn gas_fee(&self) -> u64 {
        self.gas_fee
    }

    /// Builds a witness-bearing arithmetic circuit.
    #[must_use]
    pub fn circuit(&self) -> AccountingArithmeticCircuit<N> {
        AccountingArithmeticCircuit {
            witness: Some(self.clone()),
        }
    }

    /// Public instances derived independently by the verifier from effects.
    #[must_use]
    pub fn public_inputs(&self) -> Vec<Vec<pallas::Base>> {
        vec![vec![
            pallas::Base::from(self.gas_units),
            pallas::Base::from(self.fee_per_gas),
        ]]
    }
}

fn checked_sum(mut values: impl Iterator<Item = u64>) -> Result<u64, AccountingArithmeticError> {
    values.try_fold(0_u64, |sum, value| {
        sum.checked_add(value)
            .ok_or(AccountingArithmeticError::ArithmeticOverflow)
    })
}

/// Fixed circuit shape for one allowed padded action bucket.
#[derive(Clone, Debug)]
pub struct AccountingArithmeticCircuit<const N: usize> {
    pub(crate) witness: Option<PreparedAccountingArithmetic<N>>,
}

#[derive(Clone, Debug)]
pub struct AccountingArithmeticConfig {
    advice: [Column<Advice>; 8],
    pub(crate) instance: Column<Instance>,
    q_action: Selector,
    q_derive_enabled: Selector,
    q_first: Selector,
    q_step: Selector,
    q_gas: Selector,
    q_tax: Selector,
    q_conservation: Selector,
    q_range: Selector,
    remainder_table: TableColumn,
}

impl<const N: usize> Circuit<pallas::Base> for AccountingArithmeticCircuit<N> {
    type Config = AccountingArithmeticConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { witness: None }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advice = std::array::from_fn(|_| meta.advice_column());
        let instance = meta.instance_column();
        for column in advice {
            meta.enable_equality(column);
        }
        meta.enable_equality(instance);

        let q_action = meta.selector();
        let q_derive_enabled = meta.selector();
        let q_first = meta.selector();
        let q_step = meta.selector();
        let q_gas = meta.selector();
        // This selector participates in both gates and a conditional lookup.
        let q_tax = meta.complex_selector();
        let q_conservation = meta.selector();
        let q_range = meta.selector();
        let remainder_table = meta.lookup_table_column();

        meta.create_gate("action values, dummy, and taxable output", |meta| {
            let q = meta.query_selector(q_action);
            let input = meta.query_advice(advice[0], Rotation::cur());
            let output = meta.query_advice(advice[1], Rotation::cur());
            let enabled = meta.query_advice(advice[2], Rotation::cur());
            let taxable = meta.query_advice(advice[3], Rotation::cur());
            let taxable_output = meta.query_advice(advice[4], Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(pallas::Base::ONE);
            vec![
                q.clone() * enabled.clone() * (one.clone() - enabled.clone()),
                q.clone() * taxable.clone() * (one.clone() - taxable.clone()),
                q.clone() * (one.clone() - enabled.clone()) * input,
                q.clone() * (one.clone() - enabled.clone()) * output.clone(),
                q.clone() * (one - enabled) * taxable.clone(),
                q * (output * taxable - taxable_output),
            ]
        });

        meta.create_gate("dummy marker derived from zero values", |meta| {
            let q = meta.query_selector(q_derive_enabled);
            let input = meta.query_advice(advice[0], Rotation::cur());
            let output = meta.query_advice(advice[1], Rotation::cur());
            let enabled = meta.query_advice(advice[2], Rotation::cur());
            let inverse = meta.query_advice(advice[3], Rotation::cur());
            // Both terms are independently constrained to 64 bits below, so
            // their sum is below 2^65 and cannot wrap in the Pallas base field.
            // It is zero exactly when both unsigned values are zero.
            let sum = input + output;
            let one = halo2_proofs::plonk::Expression::Constant(pallas::Base::ONE);
            vec![
                q.clone() * (sum.clone() * inverse - enabled.clone()),
                q * sum * (one - enabled),
            ]
        });

        meta.create_gate("first action accumulators", |meta| {
            let q = meta.query_selector(q_first);
            let input = meta.query_advice(advice[0], Rotation::cur());
            let output = meta.query_advice(advice[1], Rotation::cur());
            let taxable_output = meta.query_advice(advice[4], Rotation::cur());
            let input_acc = meta.query_advice(advice[5], Rotation::cur());
            let output_acc = meta.query_advice(advice[6], Rotation::cur());
            let taxable_acc = meta.query_advice(advice[7], Rotation::cur());
            vec![
                q.clone() * (input_acc - input),
                q.clone() * (output_acc - output),
                q * (taxable_acc - taxable_output),
            ]
        });

        meta.create_gate("rolling action accumulators", |meta| {
            let q = meta.query_selector(q_step);
            let input = meta.query_advice(advice[0], Rotation::cur());
            let output = meta.query_advice(advice[1], Rotation::cur());
            let taxable_output = meta.query_advice(advice[4], Rotation::cur());
            let input_acc = meta.query_advice(advice[5], Rotation::cur());
            let output_acc = meta.query_advice(advice[6], Rotation::cur());
            let taxable_acc = meta.query_advice(advice[7], Rotation::cur());
            let previous_input = meta.query_advice(advice[5], Rotation::prev());
            let previous_output = meta.query_advice(advice[6], Rotation::prev());
            let previous_taxable = meta.query_advice(advice[7], Rotation::prev());
            vec![
                q.clone() * (input_acc - previous_input - input),
                q.clone() * (output_acc - previous_output - output),
                q * (taxable_acc - previous_taxable - taxable_output),
            ]
        });

        meta.create_gate("public gas multiplication", |meta| {
            let q = meta.query_selector(q_gas);
            let units = meta.query_advice(advice[0], Rotation::cur());
            let price = meta.query_advice(advice[1], Rotation::cur());
            let fee = meta.query_advice(advice[2], Rotation::cur());
            vec![q * (units * price - fee)]
        });

        meta.create_gate("exact ceiling half-percent burn", |meta| {
            let q_selector = meta.query_selector(q_tax);
            let taxable = meta.query_advice(advice[0], Rotation::cur());
            let quotient = meta.query_advice(advice[1], Rotation::cur());
            let remainder = meta.query_advice(advice[2], Rotation::cur());
            let nonzero = meta.query_advice(advice[3], Rotation::cur());
            let inverse = meta.query_advice(advice[4], Rotation::cur());
            let burn = meta.query_advice(advice[5], Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(pallas::Base::ONE);
            let divisor =
                halo2_proofs::plonk::Expression::Constant(pallas::Base::from(BURN_DIVISOR));
            vec![
                q_selector.clone() * (taxable - divisor * quotient.clone() - remainder.clone()),
                q_selector.clone() * nonzero.clone() * (one.clone() - nonzero.clone()),
                q_selector.clone() * (remainder.clone() * inverse - nonzero.clone()),
                q_selector.clone() * remainder * (one - nonzero.clone()),
                q_selector * (burn - quotient - nonzero),
            ]
        });

        meta.lookup(|meta| {
            let q = meta.query_selector(q_tax);
            let remainder = meta.query_advice(advice[2], Rotation::cur());
            vec![(q * remainder, remainder_table)]
        });

        meta.create_gate("exact conservation", |meta| {
            let q = meta.query_selector(q_conservation);
            let inputs = meta.query_advice(advice[0], Rotation::cur());
            let outputs = meta.query_advice(advice[1], Rotation::cur());
            let burn = meta.query_advice(advice[2], Rotation::cur());
            let gas = meta.query_advice(advice[3], Rotation::cur());
            vec![q * (inputs - outputs - burn - gas)]
        });

        meta.create_gate("canonical unsigned 64-bit decomposition", |meta| {
            let q = meta.query_selector(q_range);
            let accumulator = meta.query_advice(advice[0], Rotation::cur());
            let bit = meta.query_advice(advice[1], Rotation::cur());
            let next = meta.query_advice(advice[0], Rotation::next());
            let one = halo2_proofs::plonk::Expression::Constant(pallas::Base::ONE);
            let two = halo2_proofs::plonk::Expression::Constant(pallas::Base::from(2));
            vec![
                q.clone() * (accumulator - bit.clone() - two * next),
                q * bit.clone() * (one - bit),
            ]
        });

        AccountingArithmeticConfig {
            advice,
            instance,
            q_action,
            q_derive_enabled,
            q_first,
            q_step,
            q_gas,
            q_tax,
            q_conservation,
            q_range,
            remainder_table,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        self.synthesize_with_summary(config, &mut layouter)
            .map(|_| ())
    }
}

impl<const N: usize> AccountingArithmeticCircuit<N> {
    pub(crate) fn synthesize_with_summary(
        &self,
        config: AccountingArithmeticConfig,
        layouter: &mut impl Layouter<pallas::Base>,
    ) -> Result<SummaryCells, Error> {
        layouter.assign_table(
            || "canonical burn remainder [0, 200)",
            |mut table| {
                for remainder in 0..BURN_DIVISOR {
                    table.assign_cell(
                        || "remainder",
                        config.remainder_table,
                        remainder as usize,
                        || Value::known(pallas::Base::from(remainder)),
                    )?;
                }
                Ok(())
            },
        )?;

        let witness = self.witness.as_ref();
        let action_cells = layouter.assign_region(
            || "padded action arithmetic",
            |mut region| {
                let mut input_sum = 0_u64;
                let mut output_sum = 0_u64;
                let mut taxable_sum = 0_u64;
                let mut inputs = Vec::with_capacity(N);
                let mut outputs = Vec::with_capacity(N);
                let mut enabled_flags = Vec::with_capacity(N);
                let mut taxable_flags = Vec::with_capacity(N);
                let mut last_accumulators = None;
                for index in 0..N {
                    config.q_action.enable(&mut region, index)?;
                    if index == 0 {
                        config.q_first.enable(&mut region, index)?;
                    } else {
                        config.q_step.enable(&mut region, index)?;
                    }
                    let action = witness.map(|prepared| prepared.actions[index]);
                    let input = action.map_or(0, |value| value.input);
                    let output = action.map_or(0, |value| value.output);
                    let enabled = action.is_some_and(|value| value.enabled);
                    let taxable = action.is_some_and(|value| value.taxable);
                    let taxable_output = if taxable { output } else { 0 };
                    input_sum = input_sum.wrapping_add(input);
                    output_sum = output_sum.wrapping_add(output);
                    taxable_sum = taxable_sum.wrapping_add(taxable_output);

                    let input_cell = assign_u64(
                        &mut region,
                        config.advice[0],
                        index,
                        "input",
                        action.map(|_| input),
                    )?;
                    let output_cell = assign_u64(
                        &mut region,
                        config.advice[1],
                        index,
                        "output",
                        action.map(|_| output),
                    )?;
                    let enabled_cell = assign_bool(
                        &mut region,
                        config.advice[2],
                        index,
                        "enabled",
                        action.map(|_| enabled),
                    )?;
                    let taxable_cell = assign_bool(
                        &mut region,
                        config.advice[3],
                        index,
                        "taxable",
                        action.map(|_| taxable),
                    )?;
                    assign_u64(
                        &mut region,
                        config.advice[4],
                        index,
                        "taxable output",
                        action.map(|_| taxable_output),
                    )?;
                    let input_acc = assign_u64(
                        &mut region,
                        config.advice[5],
                        index,
                        "input accumulator",
                        action.map(|_| input_sum),
                    )?;
                    let output_acc = assign_u64(
                        &mut region,
                        config.advice[6],
                        index,
                        "output accumulator",
                        action.map(|_| output_sum),
                    )?;
                    let taxable_acc = assign_u64(
                        &mut region,
                        config.advice[7],
                        index,
                        "taxable accumulator",
                        action.map(|_| taxable_sum),
                    )?;
                    inputs.push((input_cell, action.map(|_| input)));
                    outputs.push((output_cell, action.map(|_| output)));
                    enabled_flags.push(enabled_cell);
                    taxable_flags.push(taxable_cell);
                    last_accumulators = Some((input_acc, output_acc, taxable_acc));
                }
                let (input_acc, output_acc, taxable_acc) =
                    last_accumulators.ok_or(Error::Synthesis)?;
                Ok(ActionCells {
                    inputs,
                    outputs,
                    enabled_flags,
                    taxable_flags,
                    input_acc,
                    output_acc,
                    taxable_acc,
                })
            },
        )?;

        layouter.assign_region(
            || "derive dummy markers from linked values",
            |mut region| {
                for index in 0..N {
                    config.q_derive_enabled.enable(&mut region, index)?;
                    action_cells.inputs[index].0.copy_advice(
                        || "input",
                        &mut region,
                        config.advice[0],
                        index,
                    )?;
                    action_cells.outputs[index].0.copy_advice(
                        || "output",
                        &mut region,
                        config.advice[1],
                        index,
                    )?;
                    action_cells.enabled_flags[index].copy_advice(
                        || "derived enabled marker",
                        &mut region,
                        config.advice[2],
                        index,
                    )?;
                    let values = action_cells.inputs[index]
                        .1
                        .zip(action_cells.outputs[index].1);
                    assign_base(
                        &mut region,
                        config.advice[3],
                        index,
                        "input-plus-output inverse",
                        values.map(|(input, output)| {
                            let sum = pallas::Base::from(input) + pallas::Base::from(output);
                            Option::<pallas::Base>::from(sum.invert()).unwrap_or(pallas::Base::ZERO)
                        }),
                    )?;
                }
                Ok(())
            },
        )?;

        let summary = layouter.assign_region(
            || "gas, burn, and conservation",
            |mut region| {
                config.q_gas.enable(&mut region, 0)?;
                let gas_units = assign_u64(
                    &mut region,
                    config.advice[0],
                    0,
                    "gas units",
                    witness.map(|value| value.gas_units),
                )?;
                let fee_per_gas = assign_u64(
                    &mut region,
                    config.advice[1],
                    0,
                    "fee per gas",
                    witness.map(|value| value.fee_per_gas),
                )?;
                let gas_fee = assign_u64(
                    &mut region,
                    config.advice[2],
                    0,
                    "gas fee",
                    witness.map(|value| value.gas_fee),
                )?;

                config.q_tax.enable(&mut region, 1)?;
                let taxable = assign_u64(
                    &mut region,
                    config.advice[0],
                    1,
                    "taxable total",
                    witness.map(|value| value.taxable),
                )?;
                let quotient_value = witness.map(|value| value.taxable / BURN_DIVISOR);
                let remainder_value = witness.map(|value| value.taxable % BURN_DIVISOR);
                let quotient = assign_u64(
                    &mut region,
                    config.advice[1],
                    1,
                    "burn quotient",
                    quotient_value,
                )?;
                assign_u64(
                    &mut region,
                    config.advice[2],
                    1,
                    "burn remainder",
                    remainder_value,
                )?;
                let remainder_nonzero = remainder_value.map(|value| value != 0);
                assign_bool(
                    &mut region,
                    config.advice[3],
                    1,
                    "remainder non-zero",
                    remainder_nonzero,
                )?;
                assign_base(
                    &mut region,
                    config.advice[4],
                    1,
                    "remainder inverse",
                    remainder_value.map(|value| {
                        if value == 0 {
                            pallas::Base::ZERO
                        } else {
                            Option::<pallas::Base>::from(pallas::Base::from(value).invert())
                                .expect("a non-zero field element is invertible")
                        }
                    }),
                )?;
                let burn = assign_u64(
                    &mut region,
                    config.advice[5],
                    1,
                    "burn",
                    witness.map(|value| value.burn),
                )?;

                config.q_conservation.enable(&mut region, 2)?;
                let total_inputs = assign_u64(
                    &mut region,
                    config.advice[0],
                    2,
                    "total inputs",
                    witness.map(|value| value.total_inputs),
                )?;
                let total_outputs = assign_u64(
                    &mut region,
                    config.advice[1],
                    2,
                    "total outputs",
                    witness.map(|value| value.total_outputs),
                )?;
                let conservation_burn = assign_u64(
                    &mut region,
                    config.advice[2],
                    2,
                    "conservation burn",
                    witness.map(|value| value.burn),
                )?;
                let conservation_gas = assign_u64(
                    &mut region,
                    config.advice[3],
                    2,
                    "conservation gas",
                    witness.map(|value| value.gas_fee),
                )?;

                region.constrain_equal(action_cells.input_acc.cell(), total_inputs.cell())?;
                region.constrain_equal(action_cells.output_acc.cell(), total_outputs.cell())?;
                region.constrain_equal(action_cells.taxable_acc.cell(), taxable.cell())?;
                region.constrain_equal(gas_fee.cell(), conservation_gas.cell())?;
                region.constrain_equal(burn.cell(), conservation_burn.cell())?;

                Ok(SummaryCells {
                    action_inputs: action_cells
                        .inputs
                        .iter()
                        .map(|(cell, _)| cell.clone())
                        .collect(),
                    action_outputs: action_cells
                        .outputs
                        .iter()
                        .map(|(cell, _)| cell.clone())
                        .collect(),
                    taxable_flags: action_cells.taxable_flags.clone(),
                    gas_units,
                    fee_per_gas,
                    gas_fee,
                    taxable,
                    quotient,
                    burn,
                    total_inputs,
                    total_outputs,
                })
            },
        )?;

        layouter.constrain_instance(summary.gas_units.cell(), config.instance, 0)?;
        layouter.constrain_instance(summary.fee_per_gas.cell(), config.instance, 1)?;

        for (index, (cell, value)) in action_cells.inputs.iter().enumerate() {
            range_u64(
                layouter.namespace(|| format!("range input {index}")),
                &config,
                cell,
                *value,
            )?;
        }
        for (index, (cell, value)) in action_cells.outputs.iter().enumerate() {
            range_u64(
                layouter.namespace(|| format!("range output {index}")),
                &config,
                cell,
                *value,
            )?;
        }
        let ranged = [
            (
                &summary.gas_units,
                witness.map(|value| value.gas_units),
                "gas units",
            ),
            (
                &summary.fee_per_gas,
                witness.map(|value| value.fee_per_gas),
                "fee per gas",
            ),
            (
                &summary.gas_fee,
                witness.map(|value| value.gas_fee),
                "gas fee",
            ),
            (
                &summary.taxable,
                witness.map(|value| value.taxable),
                "taxable",
            ),
            (
                &summary.quotient,
                witness.map(|value| value.taxable / BURN_DIVISOR),
                "burn quotient",
            ),
            (&summary.burn, witness.map(|value| value.burn), "burn"),
            (
                &summary.total_inputs,
                witness.map(|value| value.total_inputs),
                "total inputs",
            ),
            (
                &summary.total_outputs,
                witness.map(|value| value.total_outputs),
                "total outputs",
            ),
        ];
        for (cell, value, label) in ranged {
            range_u64(
                layouter.namespace(|| format!("range {label}")),
                &config,
                cell,
                value,
            )?;
        }
        Ok(summary)
    }
}

type BaseCell = AssignedCell<pallas::Base, pallas::Base>;

struct ActionCells {
    inputs: Vec<(BaseCell, Option<u64>)>,
    outputs: Vec<(BaseCell, Option<u64>)>,
    enabled_flags: Vec<BaseCell>,
    taxable_flags: Vec<BaseCell>,
    input_acc: BaseCell,
    output_acc: BaseCell,
    taxable_acc: BaseCell,
}

pub(crate) struct SummaryCells {
    pub(crate) action_inputs: Vec<BaseCell>,
    pub(crate) action_outputs: Vec<BaseCell>,
    pub(crate) taxable_flags: Vec<BaseCell>,
    gas_units: BaseCell,
    fee_per_gas: BaseCell,
    gas_fee: BaseCell,
    taxable: BaseCell,
    quotient: BaseCell,
    pub(crate) burn: BaseCell,
    total_inputs: BaseCell,
    total_outputs: BaseCell,
}

fn assign_u64(
    region: &mut halo2_proofs::circuit::Region<'_, pallas::Base>,
    column: Column<Advice>,
    row: usize,
    label: &'static str,
    value: Option<u64>,
) -> Result<BaseCell, Error> {
    assign_base(region, column, row, label, value.map(pallas::Base::from))
}

fn assign_bool(
    region: &mut halo2_proofs::circuit::Region<'_, pallas::Base>,
    column: Column<Advice>,
    row: usize,
    label: &'static str,
    value: Option<bool>,
) -> Result<BaseCell, Error> {
    assign_u64(region, column, row, label, value.map(u64::from))
}

fn assign_base(
    region: &mut halo2_proofs::circuit::Region<'_, pallas::Base>,
    column: Column<Advice>,
    row: usize,
    label: &'static str,
    value: Option<pallas::Base>,
) -> Result<BaseCell, Error> {
    region.assign_advice(
        || label,
        column,
        row,
        || value.map_or_else(Value::unknown, Value::known),
    )
}

fn range_u64(
    mut layouter: impl Layouter<pallas::Base>,
    config: &AccountingArithmeticConfig,
    original: &BaseCell,
    value: Option<u64>,
) -> Result<(), Error> {
    layouter.assign_region(
        || "64-bit decomposition",
        |mut region| {
            let mut first = None;
            for bit_index in 0..RANGE_BITS {
                config.q_range.enable(&mut region, bit_index)?;
                let accumulator = value.map(|number| number >> bit_index);
                let accumulator_cell = assign_u64(
                    &mut region,
                    config.advice[0],
                    bit_index,
                    "range accumulator",
                    accumulator,
                )?;
                if bit_index == 0 {
                    first = Some(accumulator_cell);
                }
                assign_u64(
                    &mut region,
                    config.advice[1],
                    bit_index,
                    "range bit",
                    accumulator.map(|number| number & 1),
                )?;
            }
            assign_u64(
                &mut region,
                config.advice[0],
                RANGE_BITS,
                "range terminal zero",
                value.map(|_| 0),
            )?;
            region.constrain_equal(original.cell(), first.ok_or(Error::Synthesis)?.cell())?;
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;

    use super::*;

    fn valid_witness() -> PreparedAccountingArithmetic<2> {
        // 5,000 taxable output => 25 burn; 2 * 13 => 26 gas.
        PreparedAccountingArithmetic::new(
            [
                AccountingActionWitness::enabled(5_051, 5_000, true),
                AccountingActionWitness::dummy(),
            ],
            2,
            13,
        )
        .unwrap()
    }

    #[test]
    fn native_oracle_rejects_bad_dummy_overflow_and_non_conservation() {
        assert_eq!(
            PreparedAccountingArithmetic::new(
                [
                    AccountingActionWitness::enabled(0, 0, false),
                    AccountingActionWitness::dummy(),
                ],
                1,
                1,
            ),
            Err(AccountingArithmeticError::InvalidDummyAction)
        );
        assert_eq!(
            PreparedAccountingArithmetic::new(
                [
                    AccountingActionWitness {
                        input: 1,
                        output: 0,
                        enabled: false,
                        taxable: false,
                    },
                    AccountingActionWitness::dummy(),
                ],
                1,
                1,
            ),
            Err(AccountingArithmeticError::InvalidDummyAction)
        );
        assert_eq!(
            PreparedAccountingArithmetic::new(
                [
                    AccountingActionWitness::dummy(),
                    AccountingActionWitness::dummy()
                ],
                u64::MAX,
                2,
            ),
            Err(AccountingArithmeticError::ArithmeticOverflow)
        );
        assert_eq!(
            PreparedAccountingArithmetic::new(
                [
                    AccountingActionWitness::enabled(5_050, 5_000, true),
                    AccountingActionWitness::dummy(),
                ],
                2,
                13,
            ),
            Err(AccountingArithmeticError::InvalidConservation)
        );
    }

    #[test]
    fn halo2_enforces_padding_gas_ceiling_burn_and_conservation() {
        let witness = valid_witness();
        let prover = MockProver::run(
            ACCOUNTING_ARITHMETIC_K,
            &witness.circuit(),
            witness.public_inputs(),
        )
        .unwrap();
        prover.assert_satisfied();

        let wrong_public_gas = vec![vec![pallas::Base::from(3), pallas::Base::from(13)]];
        let prover = MockProver::run(
            ACCOUNTING_ARITHMETIC_K,
            &witness.circuit(),
            wrong_public_gas,
        )
        .unwrap();
        assert!(prover.verify().is_err());

        let mut wrong_burn = witness.clone();
        wrong_burn.burn -= 1;
        let prover = MockProver::run(
            ACCOUNTING_ARITHMETIC_K,
            &wrong_burn.circuit(),
            wrong_burn.public_inputs(),
        )
        .unwrap();
        assert!(prover.verify().is_err());

        let mut wrong_taxable = witness;
        wrong_taxable.actions[0].taxable = false;
        let prover = MockProver::run(
            ACCOUNTING_ARITHMETIC_K,
            &wrong_taxable.circuit(),
            wrong_taxable.public_inputs(),
        )
        .unwrap();
        assert!(prover.verify().is_err());

        let mut wrong_dummy = valid_witness();
        wrong_dummy.actions[1].enabled = true;
        let prover = MockProver::run(
            ACCOUNTING_ARITHMETIC_K,
            &wrong_dummy.circuit(),
            wrong_dummy.public_inputs(),
        )
        .unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn ceiling_rule_covers_all_remainder_boundaries() {
        for taxable in [0, 1, 199, 200, 201, 399, 400] {
            let burn = taxable / BURN_DIVISOR + u64::from(taxable % BURN_DIVISOR != 0);
            let gas_units = 1;
            let fee_per_gas = 1;
            let input = taxable + burn + 1;
            let witness = PreparedAccountingArithmetic::new(
                [
                    AccountingActionWitness::enabled(input, taxable, true),
                    AccountingActionWitness::dummy(),
                ],
                gas_units,
                fee_per_gas,
            )
            .unwrap();
            assert_eq!(witness.burn(), burn);
            MockProver::run(
                ACCOUNTING_ARITHMETIC_K,
                &witness.circuit(),
                witness.public_inputs(),
            )
            .unwrap()
            .assert_satisfied();
        }
    }

    fn assert_bucket<const N: usize>() {
        let mut actions = [AccountingActionWitness::dummy(); N];
        actions[0] = AccountingActionWitness::enabled(5_051, 5_000, true);
        let witness = PreparedAccountingArithmetic::new(actions, 2, 13).unwrap();
        MockProver::run(
            ACCOUNTING_ARITHMETIC_K,
            &witness.circuit(),
            witness.public_inputs(),
        )
        .unwrap()
        .assert_satisfied();
    }

    #[test]
    fn fixed_k_supports_every_consensus_action_bucket() {
        assert_bucket::<2>();
        assert_bucket::<4>();
        assert_bucket::<8>();
        assert_bucket::<16>();
    }
}
