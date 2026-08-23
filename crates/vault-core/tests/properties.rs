use proptest::prelude::*;
use vault_core::{AccountId, Amount, GenesisConfig, Ledger, NoteId, TransferRequest, burn_for};

const ALICE: AccountId = AccountId(1);

proptest! {
    #[test]
    fn burn_is_the_smallest_integer_covering_half_a_percent(
        atomic in 1_u128..1_000_000_000_000_000_000_u128,
    ) {
        let burn = burn_for(Amount::from_atomic(atomic))
            .expect("the generated amount is non-zero and bounded")
            .atomic();

        prop_assert!(burn * 200 >= atomic);
        prop_assert!((burn - 1) * 200 < atomic);
    }

    #[test]
    fn arbitrary_transfer_sequences_preserve_supply(
        whole_amounts in prop::collection::vec(1_u64..=10_000, 1..64),
        gas_atomic in 0_u64..=10_000,
    ) {
        let initial = Amount::from_whole_vlt(1_000_000).expect("bounded test amount");
        let mut ledger = Ledger::new(GenesisConfig {
            max_supply: Amount::from_whole_vlt(100_000_000).expect("bounded test amount"),
            initial_supply: initial,
            genesis_owner: ALICE,
        })
        .expect("valid generated ledger");
        let mut inputs = vec![NoteId(0)];
        let mut expected_burn = Amount::ZERO;

        for whole_amount in whole_amounts {
            let amount = Amount::from_whole_vlt(u128::from(whole_amount))
                .expect("bounded generated amount");
            let receipt = ledger
                .execute_transfer(TransferRequest {
                    sender: ALICE,
                    recipient: ALICE,
                    validator: ALICE,
                    input_notes: inputs,
                    amount,
                    gas_fee: Amount::from_atomic(u128::from(gas_atomic)),
                })
                .expect("generated transfer is covered by the initial supply");

            expected_burn = expected_burn
                .checked_add(receipt.burned)
                .expect("bounded cumulative burn");
            inputs = vec![receipt.recipient_note];
            inputs.extend(receipt.change_note);
            inputs.extend(receipt.validator_note);

            ledger.audit().expect("every generated transition must conserve supply");
            prop_assert_eq!(ledger.total_burned(), expected_burn);
            prop_assert_eq!(
                ledger.circulating_supply(),
                initial.checked_sub(expected_burn).expect("burn remains below issuance")
            );
        }
    }
}
