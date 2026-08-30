use risc0_zkvm::guest::env;
use vault_zk_accounting_core::ReferenceClaim;

fn main() {
    let claim: ReferenceClaim = env::read();
    let journal = claim
        .validate()
        .expect("Vault accounting constraints rejected the private witness");
    env::commit(&journal);
}

