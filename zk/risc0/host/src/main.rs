use vault_zk_risc0::{prove, reference_fixture, reference_image_id, verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = reference_fixture();
    let artifact = prove(&fixture.claim)?;
    let journal = verify(&fixture.effects, &artifact.proof)?;

    println!("Vault H1 RISC Zero transfer-v2 reference proof: verified");
    println!("image_id={}", hex(&reference_image_id()));
    println!("public_inputs={}", hex(&journal.public_inputs_digest));
    println!("proof_bytes={}", artifact.metrics.proof_bytes);
    println!("elapsed_ms={}", artifact.metrics.elapsed_ms);
    println!("segments={}", artifact.metrics.segments);
    println!("total_cycles={}", artifact.metrics.total_cycles);
    println!("user_cycles={}", artifact.metrics.user_cycles);
    println!("public_action_count={}", journal.action_count);
    println!("public_gas_fee={}", journal.gas_fee);

    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}
