# Vault compact block and finalized wallet scan v1

**Status:** production-intent canonical codec, header binding, local scanner,
typed seed-import boundary, and first encrypted ShardTree database implemented;
recovery/network/review gates open
**Last updated:** 2026-09-02

## 1. Scope and privacy rule

A wallet discovers transfer-v2 notes by retrieving every finalized compact
block in sequence and trial-decrypting every encrypted output locally. It MUST
NOT ask a remote service whether an address, viewing key, nullifier, note
commitment, transaction, or output belongs to the wallet. Compact retrieval
still exposes network timing unless the future transport adds private,
padded retrieval; this codec alone does not provide network anonymity.

Decoding is not authentication. Before scanning, the wallet MUST compare the
compact commitment and all block/tree metadata with an independently verified
finalized consensus header. The current H1 code defines that boundary but does
not implement consensus finality or network retrieval.

## 2. Canonical wire encoding

All integers are unsigned little-endian. Truncation, trailing bytes, unknown
versions, non-canonical curve/field encodings, reserved zero identities,
duplicate transaction IDs, duplicate nullifiers, duplicate note commitments,
and non-canonical action order fail closed.

The fixed 198-byte block header is:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VCB1` |
| 4 | 2 | codec version `1` |
| 6 | 32 | Vault chain ID |
| 38 | 8 | non-zero finalized height |
| 46 | 32 | finalized block hash |
| 78 | 32 | exact parent block hash |
| 110 | 8 | pre-block note-tree size |
| 118 | 32 | pre-block note-tree root |
| 150 | 8 | post-block note-tree size |
| 158 | 32 | post-block note-tree root |
| 190 | 4 | transaction count |
| 194 | 4 | total action count |

Each compact transaction is:

| Bytes | Field |
|---:|---|
| 32 | content-derived complete transfer-v2 transaction ID |
| 1 | action count: exactly `2`, `4`, `8`, or `16` |
| variable | actions in the accepted transfer's canonical nullifier order |

Each action is exactly 788 bytes:

| Bytes | Field |
|---:|---|
| 32 | action nullifier; also the output note's `rho` domain input |
| 32 | output note commitment |
| 32 | output value commitment |
| 32 | output ephemeral key |
| 580 | complete authenticated recipient ciphertext |
| 80 | complete authenticated sender-recovery ciphertext |

Dummy actions remain present. Omitting them or any real output changes tree
size/root and the compact commitment. The codec strips proof bytes, signatures,
gas, burn data, and randomized spend keys because wallet discovery does not use
them; the transaction ID still binds the accepted complete transaction.

Absolute defensive limits are 8,192 transactions, 16,384 actions, and
13,181,126 encoded bytes. Decoding checks declared counts and the exact expected
length before allocating count-derived vectors. H2 consensus MAY activate a
smaller gas/block limit but MUST NOT exceed these codec bounds without a new
reviewed version.

## 3. Non-circular header commitment

The finalized header commits:

```text
BLAKE3-DERIVE(
  "vault.protocol.compact-block-v1.commitment.2026-08-23",
  canonical_compact_block_with_block_hash_field_omitted
)
```

The `block_hash` field is excluded because the block hash is derived from a
header that contains this compact commitment; including it would create a
circular definition. The finalized header independently authenticates its own
block hash, chain ID, height, parent, pre/post tree sizes and roots, and compact
commitment. `CompactBlock::authenticate` requires every field to match before
producing `AuthenticatedCompactBlock`.

A future header/light-client adapter MUST NOT construct
`FinalizedCompactBlockHeader` until consensus signatures/finality and the exact
activated header commitment have been verified. The Rust type records this
trust transition; calling its constructor is not itself a finality proof.

## 4. Local finalized scan transition

Given durable tip `(chain_id, height, block_hash, tree_frontier)`, scanning
requires:

1. the block network equals the wallet network;
2. `block.height = tip.height + 1` without overflow;
3. `block.parent_hash = tip.block_hash`;
4. pre-tree size/root equal the restored local frontier;
5. every output commitment appends in block/transaction/action order;
6. the derived post-tree size/root equal the authenticated header;
7. every output is trial-decrypted locally in bounded batches of at most 4,096
   outputs against both external and internal capabilities for at most eight
   full-viewing-key accounts (16 incoming keys);
8. matching notes retain a stable encrypted wallet account ID, key scope,
   transaction ID, action index, global tree position, exact encrypted output,
   authenticated private note, fixed memo, and locally derived future spend
   nullifier;
9. all public nullifiers are included in the store delta so owned notes can be
   marked spent without a wallet-specific remote query.

The scanner processes every output even after finding matches. Wallet-specific
match counts and positions are redacted from `Debug`, errors, and the public
success summary to reduce accidental logging. This does not prove constant-time
behavior; timing/cache benchmarks remain mandatory.

Only finalized blocks enter this durable path. Unfinalized wallet previews, if
later implemented, MUST remain separately staged and non-spendable. Reverting a
finalized compact block is treated as a consensus/finality failure, not an
ordinary wallet reorganization.

## 5. Durable store contract and open gates

`FinalizedWalletStore::commit_finalized_block` receives an opaque
`ScannedBlockUpdate`. In one serializable transaction it MUST:

- compare its current height, block hash, tree size, and tree root with every
  expected pre-state field;
- update the maintained shard tree and mark every detected note position;
- retain enough checkpoints and nodes to construct current spend witnesses;
- record every public nullifier and atomically mark locally owned notes spent;
- authenticate and encrypt private notes, memos, viewing-key association, and
  wallet metadata at rest;
- commit the new finalized tip only with all preceding changes;
- leave all state unchanged on definite failure and poison/close the handle if
  commit durability is uncertain.

No volatile or permissive store implementation is shipped. The first Unix
backend now uses SQLite rollback transactions, per-record XChaCha20-Poly1305,
keyed nullifier tags, the maintained Zcash `ShardTree` design, durable
checkpoints, owned-note mark reconciliation, monotonic-height rollback input,
and verified current spend-witness extraction. Its normative construction and
leakage are specified in [`WALLET_DB_V1.md`](WALLET_DB_V1.md).

Authenticated size-bucketed backup and fully validated non-empty database
restore are specified in [`WALLET_BACKUP_V1.md`](WALLET_BACKUP_V1.md). Explicit
birthday-frontier initialization is specified in
[`WALLET_RECOVERY_V1.md`](WALLET_RECOVERY_V1.md). Deterministic discovery now
scans up to 64 contiguous seed accounts in bounded primitive groups and commits
each durable update to the exact ordered account set. Its exact finalized target,
account-activity gap, and incomplete/complete/range-exhausted phase are encrypted
and atomic with the tip. The bounded synchronization coordinator specified in
[`WALLET_RECOVERY_SYNC_V1.md`](WALLET_RECOVERY_SYNC_V1.md) now retrieves exactly
the next durable height, requires an externally consensus-verified header,
authenticates hostile compact bytes, and commits before advancing. The
typed/checksummed seed-import boundary is implemented; concrete platform/hardware
custody, a validating node/light-client adapter, publisher-policy delivery and
rollback protection (authenticated birthday/target and successor-policy
packages, successor key removal, and a bounded Unix policy history are
implemented; the concrete protected rollback guard remains), backup
operations/drills, migrations,
hardware/keychain root-key and rollback state, exhaustive crash/power-loss
injection, long-history pruning and growth measurements,
file-size/access-pattern mitigation, private block retrieval, side-channel
benchmarks and internal security review remain activation gates.

## 6. Implemented evidence

The current tests cover byte-exact codec round trips, header/commitment
authentication, the intentional non-circular block-hash rule, tree replay,
truncation/trailing bytes, invalid versions/counts/buckets, resource limits,
duplicate nullifiers/commitments, ciphertext substitution, wrong post roots,
wrong network/height/parent/pre-tree state, external and internal account scopes,
future spend-nullifier recognition, unmatched outputs, exact note positions,
cross-primitive-batch account recovery, wrong account-set and target rejection,
durable incomplete recovery, trailing-gap exhaustion, bounded coordinator
interruption/resume, wrong source headers/parents/bytes,
private note persistence-codec validation, stale-tip atomic rollback, encrypted
database reopen, current witness verification, later spend marking, wrong key
and scope, secure-height rollback detection, ciphertext tampering, and owned-row
deletion reconciliation against ShardTree marks.

These are internal implementation tests, not an audit or a network privacy
claim.
