use vault_protocol::{
    BalanceCommitment, BurnCommitment, ChainId, EncryptedBurn, EphemeralKey, GasParameters,
    NoteCommitment, Nullifier, ShieldedOutput, ShieldedState, ShieldedStateConfig,
    ShieldedTransfer, StateRoot, TRANSFER_V1_PROTOCOL_VERSION,
};
use vault_zk_accounting_core::{
    AccountingClaim, AccountingWitness, PublicBurn, PublicOutput, TransferPublicFields,
    balance_commitment, burn_commitment, burn_for,
};
use vault_zk_risc0::{Risc0AccountingVerifier, activated_circuit_id, prove, public_fields};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let witness = AccountingWitness {
        input_values: vec![10_065],
        recipient_output_values: vec![10_000],
        change_output_values: vec![5],
        balance_blinding: [0x71; 32],
        burn_blinding: [0x93; 32],
    };
    let mut public = TransferPublicFields {
        version: TRANSFER_V1_PROTOCOL_VERSION,
        chain_id: [0x11; 32],
        circuit_id: activated_circuit_id().into_bytes(),
        anchor: [0x22; 32],
        nullifiers: vec![[0x33; 32]],
        outputs: vec![
            PublicOutput {
                note_commitment: [0x44; 32],
                ephemeral_key: [0x55; 32],
                ciphertext: vec![0x66; 48],
            },
            PublicOutput {
                note_commitment: [0x77; 32],
                ephemeral_key: [0x88; 32],
                ciphertext: vec![0x99; 48],
            },
        ],
        balance_commitment: [0; 32],
        burn: PublicBurn {
            commitment: [0; 32],
            ciphertext: vec![0xaa; 48],
        },
        gas_units: 10,
        fee_per_gas: 1,
    };
    let burn = burn_for(10_000);
    let gas_fee = 10;
    public.balance_commitment = balance_commitment(&public, &witness, burn, gas_fee);
    public.burn.commitment = burn_commitment(burn, &witness.burn_blinding);

    let claim = AccountingClaim {
        public: public.clone(),
        witness,
    };
    let artifact = prove(&claim)?;
    let transfer = transfer_from(&public, artifact.proof.clone());
    assert_eq!(public_fields(&transfer), public);

    let mut state = ShieldedState::new(
        ShieldedStateConfig {
            chain_id: transfer.chain_id(),
            transfer_circuit_id: activated_circuit_id(),
            transfer_gas_units: 10,
            minimum_fee_per_gas: 1,
            recent_anchor_limit: 16,
        },
        Risc0AccountingVerifier,
        transfer.anchor(),
    )?;
    let applied = state.apply_transfer(&transfer)?;

    println!("Vault H1 RISC Zero accounting proof: verified");
    println!("circuit_id={}", activated_circuit_id());
    println!("public_inputs={}", applied.public_inputs);
    println!("proof_bytes={}", artifact.metrics.proof_bytes);
    println!("elapsed_ms={}", artifact.metrics.elapsed_ms);
    println!("segments={}", artifact.metrics.segments);
    println!("total_cycles={}", artifact.metrics.total_cycles);
    println!("user_cycles={}", artifact.metrics.user_cycles);
    println!("hidden_input_notes={}", artifact.journal.input_count);
    println!("hidden_output_notes={}", artifact.journal.output_count);
    println!("public_gas_fee={}", artifact.journal.gas_fee);

    Ok(())
}

fn transfer_from(public: &TransferPublicFields, proof: Vec<u8>) -> ShieldedTransfer {
    ShieldedTransfer::new(
        public.version,
        ChainId::new(public.chain_id),
        activated_circuit_id(),
        StateRoot::new(public.anchor),
        public
            .nullifiers
            .iter()
            .copied()
            .map(Nullifier::new)
            .collect(),
        public
            .outputs
            .iter()
            .map(|output| {
                ShieldedOutput::new(
                    NoteCommitment::new(output.note_commitment),
                    EphemeralKey::new(output.ephemeral_key),
                    output.ciphertext.clone(),
                )
            })
            .collect(),
        BalanceCommitment::new(public.balance_commitment),
        EncryptedBurn::new(
            BurnCommitment::new(public.burn.commitment),
            public.burn.ciphertext.clone(),
        ),
        GasParameters {
            units: public.gas_units,
            fee_per_gas: public.fee_per_gas,
        },
        proof,
    )
}
