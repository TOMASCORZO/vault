use std::fmt;

use crate::LedgerError;

/// Number of atomic units in one VLT.
pub const ATOMIC_UNITS_PER_VLT: u128 = 1_000_000_000;

/// Protocol burn rate: 50 basis points, or 0.5%.
pub const BURN_BASIS_POINTS: u16 = 50;

const BURN_DIVISOR: u128 = 200;

/// A non-negative VLT amount expressed in atomic units.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Amount(u128);

impl Amount {
    /// Zero VLT.
    pub const ZERO: Self = Self(0);

    /// Creates an amount from atomic units.
    #[must_use]
    pub const fn from_atomic(value: u128) -> Self {
        Self(value)
    }

    /// Converts a whole-number VLT amount to atomic units.
    pub fn from_whole_vlt(value: u128) -> Result<Self, LedgerError> {
        value
            .checked_mul(ATOMIC_UNITS_PER_VLT)
            .map(Self)
            .ok_or(LedgerError::ArithmeticOverflow)
    }

    /// Returns the amount in atomic units.
    #[must_use]
    pub const fn atomic(self) -> u128 {
        self.0
    }

    /// Checked addition.
    pub fn checked_add(self, rhs: Self) -> Result<Self, LedgerError> {
        self.0
            .checked_add(rhs.0)
            .map(Self)
            .ok_or(LedgerError::ArithmeticOverflow)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, rhs: Self) -> Result<Self, LedgerError> {
        self.0
            .checked_sub(rhs.0)
            .map(Self)
            .ok_or(LedgerError::ArithmeticUnderflow)
    }

    /// Whether this amount is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / ATOMIC_UNITS_PER_VLT;
        let fractional = self.0 % ATOMIC_UNITS_PER_VLT;

        if fractional == 0 {
            return write!(formatter, "{whole} VLT");
        }

        let padded = format!("{fractional:09}");
        let trimmed = padded.trim_end_matches('0');
        write!(formatter, "{whole}.{trimmed} VLT")
    }
}

/// Calculates the mandatory 0.5% burn, rounded up to one atomic unit.
///
/// Rounding upward prevents splitting a payment into dust transfers to avoid
/// the burn. The sender pays this amount in addition to the recipient amount.
pub fn burn_for(transfer_amount: Amount) -> Result<Amount, LedgerError> {
    if transfer_amount.is_zero() {
        return Err(LedgerError::ZeroTransfer);
    }

    let quotient = transfer_amount.atomic() / BURN_DIVISOR;
    let remainder = transfer_amount.atomic() % BURN_DIVISOR;
    let rounded = if remainder == 0 {
        quotient
    } else {
        quotient
            .checked_add(1)
            .ok_or(LedgerError::ArithmeticOverflow)?
    };

    Ok(Amount::from_atomic(rounded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burns_exactly_half_a_percent_for_whole_tokens() {
        let transfer = Amount::from_whole_vlt(1_000).expect("valid amount");
        let burn = burn_for(transfer).expect("valid burn");
        assert_eq!(burn, Amount::from_whole_vlt(5).expect("valid amount"));
    }

    #[test]
    fn rounds_dust_burn_up() {
        let burn = burn_for(Amount::from_atomic(1)).expect("valid burn");
        assert_eq!(burn, Amount::from_atomic(1));
    }

    #[test]
    fn formats_atomic_amounts() {
        assert_eq!(Amount::from_atomic(1_500_000_000).to_string(), "1.5 VLT");
        assert_eq!(Amount::from_atomic(42).to_string(), "0.000000042 VLT");
    }
}
