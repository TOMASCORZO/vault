# Vault finalized recovery synchronization v1

**Status:** production-intent bounded coordinator and source boundary
implemented; consensus/light-client adapters, private transport, benchmarks,
fault injection, and independent review remain activation gates  
**Last updated:** 2026-08-23

## 1. Purpose

The recovery database and scanner can prove that one supplied compact block is
canonical, header-authenticated, tree-consistent, scanned with the exact planned
accounts, and atomically committed. This specification defines the coordinator
that repeats that transition from the durable birthday tip to the exact recovery
target without trusting compact-block transport.

The coordinator deliberately does not claim to establish consensus finality.
It consumes a `FinalizedCompactBlockHeader` only after an external adapter has
verified consensus and finality. A production adapter must be backed by a
validating full node or reviewed light client. Matching answers from multiple
ordinary RPC servers improve fault detection and availability but do not, by
themselves, prove finality.

## 2. Source trust boundary

`FinalizedRecoverySource` has two operations for a requested height:

1. `finalized_header(height)` returns an independently verified finalized
   consensus header;
2. `compact_block_bytes(header, maximum_bytes)` returns untrusted canonical
   compact-block bytes for that exact header.

The source implementation MUST:

- verify the header through the activated consensus/finality rules before
  constructing `FinalizedCompactBlockHeader`;
- bind compact retrieval to the supplied header height and block hash;
- enforce `maximum_bytes` while reading, before buffering or allocating beyond
  the limit;
- classify transport, availability, and consensus-adapter failures without
  substituting an unverified fallback.

The coordinator independently rechecks returned length through the canonical
decoder. It then compares chain and requested height, decodes every bounded
field, authenticates every header field and the compact commitment, replays the
note tree, validates parent continuity, scans every output, and commits through
the encrypted store. Provider claims cannot bypass any of these checks.

No network/full-node implementation is included yet. Shipping a source that
wraps unauthenticated RPC data in the finalized-header type would violate this
specification and the production engineering standard.

## 3. Bounded advancement algorithm

`advance_seed_recovery(database, source, accounts, maximum_blocks)` performs:

1. reject zero work or more than
   `MAX_RECOVERY_BLOCKS_PER_ADVANCE = 4096`;
2. authenticate the durable recovery state;
3. return an idempotent zero-work result for `Complete` or
   `RequiresLargerAccountRange`, and reject a genesis `NotRequired` wallet;
4. compare the supplied deterministic accounts with the exact encrypted
   account-set commitment before any source request;
5. compute `next_height = durable_scanned_height + 1`;
6. request the verified finalized header for exactly that height;
7. reject another chain or height before requesting compact bytes;
8. request bytes with `MAX_COMPACT_BLOCK_BYTES` as a mandatory streaming bound;
9. canonically decode and authenticate the compact block against the header;
10. load the current tip again, replay and scan the block, and atomically commit
    notes, spends, tree state, tip, and recovery state;
11. authenticate the new recovery phase before requesting the next height;
12. stop on the caller work bound, exact target completion, or explicit account
    range exhaustion.

Every height is a separate SQLite transaction. The next block is never fetched
until the previous commit returned success and the new durable phase was read.
The database itself enforces the exact target hash/root and rejects advancement
past an exhausted range.

The 4096-block invocation bound controls accidental monopolization and arithmetic
resource use; it is not the recommended UI scheduling quantum. Applications
should use smaller batches for cancellation and responsiveness. Worst-case
block/account performance must be benchmarked before selecting production
defaults.

## 4. Interruption and error semantics

`WalletRecoveryCoordinatorError` includes the number of earlier blocks whose
commits returned definite success. The failing block is excluded. Source,
header, compact codec/authentication, scan, and store failures are classified
separately. Default `Display` and `Debug` redact inner provider and wallet
details; typed causes remain available to explicit caller handling.

If a store returns `Poisoned`, durability of the failing block can be uncertain.
The process MUST close the handle, reopen and fully validate the database, read
its authenticated tip/status, and only then retry. Ordinary source, header,
codec, authentication, or scan failures occur before mutation of the failing
height.

After a crash or normal interruption, a new coordinator invocation starts from
the authenticated database tip. It does not use an in-memory cursor or trust a
provider resume token. A source failure after one successful block therefore
leaves that block durable and resumes at its successor after reopen.

## 5. Privacy and metadata

The coordinator does not send addresses, account IDs, viewing keys, match
counts, or nullifiers of interest to the source. It retrieves complete compact
blocks and scans locally. Error diagnostics redact source text and wallet state.

This is not network anonymity. A source can observe IP address, requested
heights, timing, retry behavior, birthday/target interval, and bandwidth. The
number of local account batches can also be inferred by an endpoint observing
the wallet process. Private/padded retrieval, routing, caching, cover traffic,
and timing analysis remain separate H1 gates.

## 6. Current evidence

Integration tests cover:

- a bounded prefix committed before a later source failure;
- close, authenticated reopen, and exact next-height resumption;
- final target completion and idempotent post-completion calls;
- exact compact-byte read bound propagation;
- zero/oversized work bounds and ordinary genesis rejection;
- wrong seed account set rejected before any source request;
- wrong header height rejected before compact retrieval;
- malformed/tampered compact bytes rejected before mutation;
- a header-authenticated block with the wrong parent rejected by scanner
  continuity;
- typed failure progress counts and redacted default diagnostics.

These tests use an in-process scripted source only as an adversarial test double;
it is not compiled as a production source implementation and does not satisfy
the consensus adapter gate.

## 7. Remaining activation gates

- select and implement the validating full-node and/or light-client finality
  adapter after Vault consensus rules are frozen;
- define multi-provider inconsistency/quarantine behavior without treating
  provider quorum as consensus;
- implement response deadlines, cancellation, retry budgets, backoff, provider
  rotation, and anti-eclipse policy;
- implement private/padded compact retrieval and measure IP/timing correlation;
- benchmark maximum compact blocks across 1, 8, 20, and 64 accounts;
- inject process crash, connection truncation, disk-full, poisoned commit, and
  restart faults across long recoveries;
- add structured privacy-preserving operational metrics and incident runbooks;
- complete corpus fuzzing and independent consensus/network/wallet review.

No real funds may depend on this coordinator until these gates and the wider H1
release gates pass.
