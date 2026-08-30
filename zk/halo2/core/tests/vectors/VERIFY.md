# Halo2 transfer proof vectors v1

**Status:** production-intent evidence; non-activatable

These files are the C4 Halo2 half of Vault's real-proof vector set. They bind
the frozen C2 suite and all 2/4/8/16-action buckets. They do not substitute for
the still-missing RISC Zero transfer-v2 receipt/vector, comparative benchmark,
or independent review.

After fetching the locked dependencies once, verification itself requires no
network service:

```powershell
cd zk/halo2
cargo test --release --offline --locked -p vault-zk-halo2-core `
  transfer_circuit::tests::published_halo2_vectors_verify_offline_and_reject_mutations `
  -- --exact --nocapture
```

The verifier parses each canonical instance file, deterministically derives the
corresponding `k = 15` verifying key, accepts the committed proof, flips one
proof byte, and independently mutates every public-instance cell. Every
negative case must be rejected.

To reproduce the proof files from the deterministic fixture, set
`VAULT_HALO2_VECTOR_DIR` to an empty output directory and run the all-bucket
release test. Compare every byte length and SHA-256 digest with
`manifest-v1.json` before replacing a published vector. A mismatch is a review
event, not a reason to update the manifest automatically.
