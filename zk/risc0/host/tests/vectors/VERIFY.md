# RISC Zero transfer-v2 receipt vector v1

**Status:** production-intent evidence; non-activatable

The 298 MiB receipt is a GitHub release asset rather than a Git object. Download
the four evidence files once:

```bash
mkdir -p /tmp/vault-risc0-c4
gh release download c4-risc0-transfer-v2-v1 \
  --repo TOMASCORZO/vault \
  --dir /tmp/vault-risc0-c4
```

After the locked Rust dependencies have been fetched once, verification itself
uses Cargo offline mode and no prover or GPU:

```bash
./scripts/verify-zk-risc0-c4-vector.sh \
  /tmp/vault-risc0-c4/vault-c1-transfer-v2.receipt.bin
```

The verifier enforces the exact byte length and SHA-256 from `manifest-v1.json`,
reconstructs the deterministic fixture, verifies the Composite receipt against
the reviewed guest ID, and checks the authenticated journal. It must then reject
an altered public-input digest, one changed receipt byte, and a truncated
receipt.

This vector is evidence for C4, not an activatable consensus proof. Its
311,977,650 bytes exceed Vault's current 2,097,152-byte proof limit. Activation
requires a proof format and resource policy that satisfy the consensus bound;
the limit must not be silently raised to fit this reference artifact.
