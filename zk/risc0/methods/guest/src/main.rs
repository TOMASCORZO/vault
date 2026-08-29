use risc0_zkvm::guest::env;
use vault_zk_transfer_core::TransferV2ReferenceClaim;

fn main() {
    let claim: TransferV2ReferenceClaim = env::read();
    let journal = claim
        .validate()
        .expect("Vault transfer-v2 reference constraints rejected the private witness");
    env::commit(&journal);
}
