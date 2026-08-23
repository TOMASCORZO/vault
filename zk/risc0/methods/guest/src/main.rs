use risc0_zkvm::guest::env;
use vault_zk_accounting_core::AccountingClaim;

fn main() {
    let claim: AccountingClaim = env::read();
    let journal = claim
        .validate()
        .expect("Vault accounting constraints rejected the private witness");
    env::commit(&journal);
}

