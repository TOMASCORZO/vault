# Shielded Transfer V1 — Pre-Codec Consensus Specification

**Status:** H1 executable boundary; accounting-only research proof implemented,
complete private-transfer proof not implemented.  
**Implementation:** `crates/vault-protocol`.

Normative terms **MUST**, **MUST NOT**, and **SHOULD** describe intended
consensus behavior. Network serialization is not yet frozen; the proof-bound
field order and domain strings are frozen for H1 test vectors.

## Envelope

```text
version: u16
chain_id: 32 bytes
circuit_id: 32 bytes
anchor: 32 bytes
nullifiers: 1..16 × 32 bytes
outputs: 1..16 × {
  note_commitment: 32 bytes
  ephemeral_key: 32 bytes
  ciphertext: 1..4096 bytes
}
balance_commitment: 32 bytes
burn: {
  commitment: 32 bytes
  ciphertext: 1..256 bytes
}
gas: {
  units: u64
  fee_per_gas: u64 atomic VLT
}
proof: 1..2 MiB
```

All-zero encodings for IDs, roots, commitments, nullifiers, and ephemeral keys
are reserved and MUST be rejected in v1. Final curve-element encodings will also
require canonical-field and subgroup checks in the cryptographic backend.

## Public-input binding

The H1 implementation uses BLAKE3 derive-key mode with domain:

```text
vault.protocol.transfer-v1.public-inputs.2026-08-21
```

It hashes fields in envelope order using little-endian integers. Variable-length
lists and byte strings are preceded by a little-endian `u64` length. Proof bytes
are excluded. The activated proof program MUST expose or constrain this digest
as its exact public statement.

BLAKE3 here provides transcript and transaction domain separation. It is not the
selected note commitment, nullifier PRF, Merkle hash, or value commitment.

The transaction ID uses derive-key domain:

```text
vault.protocol.transfer-v1.transaction-id.2026-08-21
```

and hashes the public-input digest followed by the length-prefixed proof bytes.

## Validation order

Nodes MUST reject in this order before state mutation:

1. protocol version, chain ID, and activated circuit ID;
2. recent-anchor membership;
3. input/output counts and reserved encodings;
4. duplicate and already-spent nullifiers;
5. duplicate or existing output commitments;
6. ciphertext and proof size limits;
7. exact gas units, minimum fee bid, and overflow;
8. cryptographic proof verification.

Only after all checks succeed may a node insert nullifiers and commitments.
There MUST be no fallible operation after the first state mutation.

## State-root handling

`vault-protocol` deliberately does not invent a Merkle construction. The
consensus application records the authenticated root produced by the selected
cryptographic state tree after a block. Transfer-v1 accepts only a bounded
window of recent roots to allow wallet latency without permitting indefinite
old-state proofs.

## Gas and burn

Transfer-v1 uses a consensus-fixed gas-unit count and a public fee-per-gas bid.
The private proof MUST show that native VLT inputs fund the computed fee. Gas is
credited to the block fee pool and is not burned.

The proof MUST independently enforce the 0.5% native VLT burn. Its plaintext is
not public; commitment and ciphertext consistency belong inside the proof
statement. Epoch aggregation is specified separately and remains unfinished.

The experimental RISC Zero guest proves conservation, burn, gas, and transcript
binding, but does not yet satisfy membership, authorization, per-note opening,
nullifier derivation, or burn-ciphertext consistency requirements. Its receipt
therefore MUST NOT be activated for a network holding funds. See
[`../research/RISC0-ACCOUNTING-V1.md`](../research/RISC0-ACCOUNTING-V1.md).

## Reference vector

The first byte-exact transcript vector is stored at
[`test-vectors/transfer-v1-001.json`](test-vectors/transfer-v1-001.json). CI
asserts its public-input digest and transaction ID so a field-order, length, or
domain change cannot occur silently.
