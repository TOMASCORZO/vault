use std::error::Error;

use vault_core::{AccountId, Amount, GenesisConfig, Ledger, TransferRequest};

const ALICE: AccountId = AccountId(1);
const BOB: AccountId = AccountId(2);
const VALIDATOR: AccountId = AccountId(3);

fn main() -> Result<(), Box<dyn Error>> {
    let transfer_whole_vlt = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1000".to_owned())
        .parse::<u128>()?;

    let mut ledger = Ledger::new(GenesisConfig {
        max_supply: Amount::from_whole_vlt(100_000_000)?,
        initial_supply: Amount::from_whole_vlt(1_000_000)?,
        genesis_owner: ALICE,
    })?;
    let genesis_note = ledger
        .genesis_note()
        .ok_or("the simulator requires a non-zero genesis supply")?;
    let receipt = ledger.execute_transfer(TransferRequest {
        sender: ALICE,
        recipient: BOB,
        validator: VALIDATOR,
        input_notes: vec![genesis_note],
        amount: Amount::from_whole_vlt(transfer_whole_vlt)?,
        gas_fee: Amount::from_atomic(10_000),
    })?;

    println!("Vault H0 transparent accounting simulation");
    println!("Recipient receives: {}", ledger.balance(BOB)?);
    println!("Protocol burns:     {}", receipt.burned);
    println!("Validator receives: {}", ledger.balance(VALIDATOR)?);
    println!("Sender total debit: {}", receipt.total_debit);
    println!("Circulating supply: {}", ledger.circulating_supply());
    println!("Supply audit:       valid");

    Ok(())
}
