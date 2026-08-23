use std::collections::{BTreeMap, BTreeSet};

use crate::{Amount, LedgerError, burn_for};

/// Transparent stand-in for a future one-time or shielded owner key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AccountId(pub u64);

/// Transparent stand-in for a future note commitment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NoteId(pub u64);

/// A transparent note used only by the H0 accounting model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Note {
    id: NoteId,
    owner: AccountId,
    amount: Amount,
}

impl Note {
    /// Note identifier.
    #[must_use]
    pub const fn id(self) -> NoteId {
        self.id
    }

    /// Account that can consume this reference note.
    #[must_use]
    pub const fn owner(self) -> AccountId {
        self.owner
    }

    /// Clear-text amount in this reference note.
    #[must_use]
    pub const fn amount(self) -> Amount {
        self.amount
    }
}

/// Immutable genesis parameters for the H0 model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisConfig {
    /// Absolute issuance ceiling.
    pub max_supply: Amount,
    /// Amount issued into the genesis note.
    pub initial_supply: Amount,
    /// Owner of the genesis note.
    pub genesis_owner: AccountId,
}

/// A transfer request in the transparent accounting model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRequest {
    /// Account authorizing all input notes.
    pub sender: AccountId,
    /// Account receiving the requested amount.
    pub recipient: AccountId,
    /// Validator receiving the gas payment.
    pub validator: AccountId,
    /// Notes consumed atomically by the transfer.
    pub input_notes: Vec<NoteId>,
    /// Exact amount delivered to the recipient.
    pub amount: Amount,
    /// Gas paid separately from the burn.
    pub gas_fee: Amount,
}

/// Result of a successful transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferReceipt {
    /// Newly created recipient note.
    pub recipient_note: NoteId,
    /// Sender change note, when inputs exceeded the debit.
    pub change_note: Option<NoteId>,
    /// Validator gas note, omitted for zero gas.
    pub validator_note: Option<NoteId>,
    /// Supply permanently removed by this transfer.
    pub burned: Amount,
    /// Gas transferred to the validator.
    pub gas_fee: Amount,
    /// Recipient amount plus burn and gas.
    pub total_debit: Amount,
    /// Supply remaining after the burn.
    pub circulating_supply: Amount,
}

/// Deterministic, transparent state machine for validating Vault economics.
#[derive(Clone, Debug)]
pub struct Ledger {
    max_supply: Amount,
    total_issued: Amount,
    circulating_supply: Amount,
    total_burned: Amount,
    total_validator_fees: Amount,
    notes: BTreeMap<NoteId, Note>,
    spent_notes: BTreeSet<NoteId>,
    next_note_id: u64,
}

impl Ledger {
    /// Creates a ledger with at most one genesis note.
    pub fn new(config: GenesisConfig) -> Result<Self, LedgerError> {
        if config.initial_supply > config.max_supply {
            return Err(LedgerError::SupplyAboveCap {
                initial_supply: config.initial_supply,
                max_supply: config.max_supply,
            });
        }

        let mut notes = BTreeMap::new();
        let next_note_id = if config.initial_supply.is_zero() {
            0
        } else {
            let genesis_note = Note {
                id: NoteId(0),
                owner: config.genesis_owner,
                amount: config.initial_supply,
            };
            notes.insert(genesis_note.id, genesis_note);
            1
        };

        let ledger = Self {
            max_supply: config.max_supply,
            total_issued: config.initial_supply,
            circulating_supply: config.initial_supply,
            total_burned: Amount::ZERO,
            total_validator_fees: Amount::ZERO,
            notes,
            spent_notes: BTreeSet::new(),
            next_note_id,
        };
        ledger.audit()?;
        Ok(ledger)
    }

    /// Identifier of the genesis note, when genesis issued a non-zero supply.
    #[must_use]
    pub fn genesis_note(&self) -> Option<NoteId> {
        self.notes.contains_key(&NoteId(0)).then_some(NoteId(0))
    }

    /// Fixed maximum supply.
    #[must_use]
    pub const fn max_supply(&self) -> Amount {
        self.max_supply
    }

    /// Total amount ever issued by this H0 model.
    #[must_use]
    pub const fn total_issued(&self) -> Amount {
        self.total_issued
    }

    /// Issued supply that has not been burned.
    #[must_use]
    pub const fn circulating_supply(&self) -> Amount {
        self.circulating_supply
    }

    /// Cumulative supply burned by transfers.
    #[must_use]
    pub const fn total_burned(&self) -> Amount {
        self.total_burned
    }

    /// Cumulative gas transferred to validators.
    #[must_use]
    pub const fn total_validator_fees(&self) -> Amount {
        self.total_validator_fees
    }

    /// Returns a note whether it is spent or unspent.
    #[must_use]
    pub fn note(&self, id: NoteId) -> Option<Note> {
        self.notes.get(&id).copied()
    }

    /// Whether a note has already been consumed.
    #[must_use]
    pub fn is_spent(&self, id: NoteId) -> bool {
        self.spent_notes.contains(&id)
    }

    /// Sum of an account's unspent reference notes.
    pub fn balance(&self, owner: AccountId) -> Result<Amount, LedgerError> {
        self.notes
            .values()
            .filter(|note| note.owner == owner && !self.spent_notes.contains(&note.id))
            .try_fold(Amount::ZERO, |total, note| total.checked_add(note.amount))
    }

    /// Atomically consumes notes and creates recipient, change, and gas notes.
    pub fn execute_transfer(
        &mut self,
        request: TransferRequest,
    ) -> Result<TransferReceipt, LedgerError> {
        // H0 favors an explicit pre-transition audit over throughput. Production
        // nodes will rely on authenticated state roots and transactional writes.
        self.audit()?;

        if request.amount.is_zero() {
            return Err(LedgerError::ZeroTransfer);
        }
        if request.input_notes.is_empty() {
            return Err(LedgerError::MissingInputs);
        }

        let mut unique_inputs = BTreeSet::new();
        let mut available = Amount::ZERO;
        for note_id in &request.input_notes {
            if !unique_inputs.insert(*note_id) {
                return Err(LedgerError::DuplicateInput(*note_id));
            }
            if self.spent_notes.contains(note_id) {
                return Err(LedgerError::NoteAlreadySpent(*note_id));
            }
            let note = self
                .notes
                .get(note_id)
                .ok_or(LedgerError::UnknownNote(*note_id))?;
            if note.owner != request.sender {
                return Err(LedgerError::WrongOwner {
                    note: *note_id,
                    expected: request.sender,
                    actual: note.owner,
                });
            }
            available = available.checked_add(note.amount)?;
        }

        let burned = burn_for(request.amount)?;
        let total_debit = request
            .amount
            .checked_add(burned)?
            .checked_add(request.gas_fee)?;
        if available < total_debit {
            return Err(LedgerError::InsufficientFunds {
                available,
                required: total_debit,
            });
        }
        let change = available.checked_sub(total_debit)?;

        // Reserve identifiers before mutating state so allocation failure is atomic.
        let output_count =
            1_u64 + u64::from(!change.is_zero()) + u64::from(!request.gas_fee.is_zero());
        let reserved_next_note_id = self
            .next_note_id
            .checked_add(output_count)
            .ok_or(LedgerError::ArithmeticOverflow)?;

        let recipient_note = NoteId(self.next_note_id);
        let mut next_note_id = self.next_note_id + 1;
        let change_note = if change.is_zero() {
            None
        } else {
            let id = NoteId(next_note_id);
            next_note_id += 1;
            Some(id)
        };
        let validator_note = if request.gas_fee.is_zero() {
            None
        } else {
            let id = NoteId(next_note_id);
            next_note_id += 1;
            Some(id)
        };

        let new_circulating_supply = self.circulating_supply.checked_sub(burned)?;
        let new_total_burned = self.total_burned.checked_add(burned)?;
        let new_total_validator_fees = self.total_validator_fees.checked_add(request.gas_fee)?;
        let remaining_after_inputs = self.circulating_supply.checked_sub(available)?;
        let new_output_total = request
            .amount
            .checked_add(change)?
            .checked_add(request.gas_fee)?;
        if remaining_after_inputs.checked_add(new_output_total)? != new_circulating_supply
            || new_circulating_supply.checked_add(new_total_burned)? != self.total_issued
        {
            return Err(LedgerError::InvariantViolation);
        }

        for note_id in unique_inputs {
            self.spent_notes.insert(note_id);
        }
        self.notes.insert(
            recipient_note,
            Note {
                id: recipient_note,
                owner: request.recipient,
                amount: request.amount,
            },
        );
        if let Some(id) = change_note {
            self.notes.insert(
                id,
                Note {
                    id,
                    owner: request.sender,
                    amount: change,
                },
            );
        }
        if let Some(id) = validator_note {
            self.notes.insert(
                id,
                Note {
                    id,
                    owner: request.validator,
                    amount: request.gas_fee,
                },
            );
        }

        debug_assert_eq!(next_note_id, reserved_next_note_id);
        self.next_note_id = reserved_next_note_id;
        self.circulating_supply = new_circulating_supply;
        self.total_burned = new_total_burned;
        self.total_validator_fees = new_total_validator_fees;
        debug_assert!(self.audit().is_ok());

        Ok(TransferReceipt {
            recipient_note,
            change_note,
            validator_note,
            burned,
            gas_fee: request.gas_fee,
            total_debit,
            circulating_supply: self.circulating_supply,
        })
    }

    /// Verifies conservation of all issued supply.
    pub fn audit(&self) -> Result<(), LedgerError> {
        if self.total_issued > self.max_supply {
            return Err(LedgerError::InvariantViolation);
        }

        let unspent = self
            .notes
            .values()
            .filter(|note| !self.spent_notes.contains(&note.id))
            .try_fold(Amount::ZERO, |total, note| total.checked_add(note.amount))?;

        if unspent != self.circulating_supply
            || self.circulating_supply.checked_add(self.total_burned)? != self.total_issued
        {
            return Err(LedgerError::InvariantViolation);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: AccountId = AccountId(1);
    const BOB: AccountId = AccountId(2);
    const VALIDATOR: AccountId = AccountId(3);

    fn vlt(value: u128) -> Amount {
        Amount::from_whole_vlt(value).expect("test amount should fit")
    }

    fn ledger() -> Ledger {
        Ledger::new(GenesisConfig {
            max_supply: vlt(100_000_000),
            initial_supply: vlt(1_000_000),
            genesis_owner: ALICE,
        })
        .expect("valid genesis")
    }

    #[test]
    fn rejects_genesis_supply_above_cap() {
        let result = Ledger::new(GenesisConfig {
            max_supply: vlt(10),
            initial_supply: vlt(11),
            genesis_owner: ALICE,
        });
        assert!(matches!(result, Err(LedgerError::SupplyAboveCap { .. })));
    }

    #[test]
    fn burns_supply_and_pays_gas_to_validator() {
        let mut ledger = ledger();
        let gas = Amount::from_atomic(10_000);
        let receipt = ledger
            .execute_transfer(TransferRequest {
                sender: ALICE,
                recipient: BOB,
                validator: VALIDATOR,
                input_notes: vec![NoteId(0)],
                amount: vlt(1_000),
                gas_fee: gas,
            })
            .expect("valid transfer");

        assert_eq!(receipt.burned, vlt(5));
        assert_eq!(ledger.balance(BOB).expect("valid balance"), vlt(1_000));
        assert_eq!(ledger.balance(VALIDATOR).expect("valid balance"), gas);
        assert_eq!(ledger.total_burned(), vlt(5));
        assert_eq!(ledger.total_validator_fees(), gas);
        assert_eq!(ledger.circulating_supply(), vlt(999_995));
        ledger.audit().expect("supply must balance");
    }

    #[test]
    fn rejects_double_spend() {
        let mut ledger = ledger();
        let request = TransferRequest {
            sender: ALICE,
            recipient: BOB,
            validator: VALIDATOR,
            input_notes: vec![NoteId(0)],
            amount: vlt(1),
            gas_fee: Amount::ZERO,
        };
        ledger
            .execute_transfer(request.clone())
            .expect("first spend succeeds");
        let second = ledger.execute_transfer(request);
        assert_eq!(second, Err(LedgerError::NoteAlreadySpent(NoteId(0))));
    }

    #[test]
    fn rejects_duplicate_input_in_one_transfer() {
        let mut ledger = ledger();
        let result = ledger.execute_transfer(TransferRequest {
            sender: ALICE,
            recipient: BOB,
            validator: VALIDATOR,
            input_notes: vec![NoteId(0), NoteId(0)],
            amount: vlt(1),
            gas_fee: Amount::ZERO,
        });
        assert_eq!(result, Err(LedgerError::DuplicateInput(NoteId(0))));
    }

    #[test]
    fn rejects_inputs_owned_by_another_account() {
        let mut ledger = ledger();
        let result = ledger.execute_transfer(TransferRequest {
            sender: BOB,
            recipient: ALICE,
            validator: VALIDATOR,
            input_notes: vec![NoteId(0)],
            amount: vlt(1),
            gas_fee: Amount::ZERO,
        });
        assert!(matches!(result, Err(LedgerError::WrongOwner { .. })));
    }

    #[test]
    fn insufficient_transfer_does_not_mutate_state() {
        let mut ledger = ledger();
        let before = ledger.clone();
        let result = ledger.execute_transfer(TransferRequest {
            sender: ALICE,
            recipient: BOB,
            validator: VALIDATOR,
            input_notes: vec![NoteId(0)],
            amount: vlt(1_000_000),
            gas_fee: Amount::ZERO,
        });
        assert!(matches!(result, Err(LedgerError::InsufficientFunds { .. })));
        assert_eq!(ledger.circulating_supply(), before.circulating_supply());
        assert!(!ledger.is_spent(NoteId(0)));
        ledger.audit().expect("failed transfer must be atomic");
    }
}
