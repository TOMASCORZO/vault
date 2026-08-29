# H1-A2 wallet custody and durability evidence

**Updated:** 2026-08-27
**Status:** local interfaces/harnesses complete; external/platform acceptance,
independent review, and activation remain open
**Scope:** H1 wallet activation hardening only; no node, finality, transport,
consensus, H2, or mainnet implementation

This record decomposes the existing H1-A2 row without expanding it. The actual
validating full-node/light-client recovery source, authenticated snapshot
network, and private compact-block transport remain H2. H1-A2 owns the local
fail-closed wallet boundary and the evidence required before it may be used.

## Finite H1-A2 work

| Area | Local completion evidence | External or platform evidence |
|---|---|---|
| Schema evolution | Explicit authenticated schema-1 to schema-2 migration, mandatory pre-migration backup, cross-version restore, no downgrade, interruption rollback | Maximum supported database migration under disk pressure and forced process/power interruption |
| Backup operations | Rotation/inventory policy, no-clobber multi-copy workflow, automated restore drill and authenticated post-restore comparison | Repeated drills across declared filesystems and storage providers |
| Retention and growth | Frozen checkpoint-retention/compaction policy and bounded long-history harness | Long-history storage, pruning, compaction, migration, backup, and restore measurements |
| Recovery trust and UX | Typed trusted checkpoint package rules and an incomplete/requires-larger-range product-state contract | Platform UX review and recovery drill; the real finalized source remains H2 |
| Custody and rollback | Root-key/seed import profile plus keychain or secure-element rollback protocol | Real supported OS keystores and physical hardware; a generic VM is insufficient |
| Fault and leakage | Deterministic codec/fault harnesses and measurement definitions | Crash, hard-reset, power-loss, disk-full, partial-write, timing, file-growth, page/cache, and crash-dump measurements on every declared platform |

## Completed local evidence

The historical database transition is schema 1 to schema 2; no artificial
schema 3 was introduced merely to exercise a migration framework.
`EncryptedWalletDb::migrate_legacy_v1` now:

1. authenticates an exact schema-1 database and its rollback floor;
2. requires a separate absent backup destination and publishes a complete
   authenticated legacy backup before mutation;
3. permits only genesis-origin legacy state, because schema-1 birthday state
   lacks the account-set and completeness record required to remain fail-closed;
4. streams keyed rows in key order rather than loading the complete database;
5. re-authenticates and reseals every private record under schema-2 AAD inside
   one exclusive SQLite transaction;
6. installs the exact schema-2 metadata constraint and canonical
   `NotRequired` recovery record;
7. rejects unknown schemas, reapplication, downgrade, wrong key/scope, and
   backup overwrite; and
8. restores an authenticated schema-1 backup only by migrating its temporary
   snapshot before publishing a new schema-2 destination.

Focused tests preserve a non-empty note, ShardTree witness, tip, checkpoints,
and backup identity across migration and restore. Injected failure after each
of nine logical stages leaves a fully valid schema-1 database with no partial
schema-2 table or version update.

Backup export now returns a redacted receipt binding backup ID, finalized
height, exact lengths, and a domain-separated complete-container digest.
Bounded copy verification rejects identity, length, or byte differences. The
restore-drill API uses the exact production restore path in protected disposable
storage and reports only authenticated height and restored length. The frozen
rotation profile requires three verified copies across two failure domains,
including one offline or immutable copy, plus a drill from a copied path before
an older generation may be retired. The core intentionally exposes no automatic
deletion API.

Checkpoint retention is immutable database policy in the inclusive range
1..4096. ShardTree keeps at most that many ordinary finalized checkpoints while
preserving reference/marked state needed by the authenticated birthday frontier
and unspent witnesses; open validation independently caps total checkpoint rows
and retained markers. `EncryptedWalletDb::compact` requires the operational
layer to have a current drilled backup, validates the complete database before
and after SQLite `VACUUM`, synchronizes the rewritten file, requires an empty
free list, and poisons the handle if a failed rewrite leaves state that cannot
be validated.

`scripts/benchmark-wallet-history.sh` is a bounded, no-overwrite synthetic
runner for 1..1,000,000 blocks, 1..4096 checkpoints, 2/4/8/16 actions, and either
fully unrelated or fully owned outputs. Each run creates the history, exports a
backup receipt, verifies an independent byte copy, drills the exact restore
path, compacts, records SQLite row/page/file measurements, and reopens with the
final height as rollback floor. A local M1/8 GiB smoke run with 32 unrelated
two-action blocks retained exactly eight ordinary checkpoints, completed in
6.43 seconds with 5,324,800 bytes maximum RSS, and reopened at height 32. An
eight-block owned-output profile persisted 16 authenticated note rows, retained
exactly four checkpoints, completed the full workflow in 2.36 seconds, and
reopened at height 8. These are runner checks, not target-host acceptance.

The schema migration has its own ignored, opt-in acceptance test wrapped by
`scripts/benchmark-wallet-migration.sh`. It builds a bounded owned-note history,
converts it to a fully authenticated schema-1 fixture without exposing any
runtime downgrade API, invokes the public migration, then restores the retained
legacy backup through the current path. A two-block local smoke run preserved
four notes and passed migration plus restore.

`scripts/fault-wallet-process-crash.sh` starts a sustained synthetic writer,
waits until the real SQLite rollback journal is observable, sends `SIGKILL`
only to that worker, and fully reopens/reconciles the database after every
attempt. Three local attempts each recovered at the last durable height, then a
normal commit advanced and reopened at height 1. The Linux-only
`scripts/fault-wallet-disk-full-linux.sh` additionally creates a guarded 256 MiB
ext4 loop filesystem and exercises ENOSPC during commit, backup, restore, and
compaction; it refuses ordinary paths and has not been executed on this Mac.
`scripts/measure-wallet-leakage-linux.sh` freezes paired `perf` profiles for
owned/unrelated outputs and 2/16 actions, including time, RSS, page faults,
cache events, file/page growth, checkpoints, shards, and note rows. It measures
the explicitly non-secret metadata boundary; it does not claim constant-time
wallet storage.

Recovery now exposes `WalletRecoveryProductState`: only `Ready` permits a final
balance or spend witness; scanning, a required larger range, and a range beyond
the reviewed 64-account bound are distinct fail-closed states. The checkpoint
ceremony requires visible network/birthday/target/source provenance and never
treats ordinary RPC agreement as finality. Actual consensus verification and
distribution remain H2/release integration.

The local custody protocol is frozen in
`docs/specs/WALLET_CUSTODY_V1.md`. A random zeroizing database root key is
separate from seed material. The exact rollback anchor binds database identity,
network, wallet, height, block hash, tree size, and root. A canonical 90-byte
stable/pending record plus atomic rollback-resistant CAS wraps each SQLite
commit in prepare/commit/finalize. Tests inject failure after the database
commit, resolve only the unambiguous pending state, and reject replacement by
the prior fully valid database. Generic keychain/secure-element traits are
implemented; real platform adapters and hardware evidence remain open.

The approved human seed boundary is English BIP-39. New wallets generate 24
words from 256 bits of OS entropy; imports accept only checksum-valid standard
word counts; NFKD passphrases are explicit; mnemonic, passphrase, and 64-byte
seed types redact and zeroize. The official vector and invalid-checksum tests
pass, and the six-package dependency addition passed the enforced offline
RustSec audit. Platform secret-entry/confirmation and hardware import remain
external product gates.

## Local H1-A2 boundary

No additional local feature is added to A2 before target-hardware execution.
Owned-machine hard-reset/power-loss orchestration, partial-write/device
faulting, physical keystore/secret-entry execution, large runs, and independent
review remain in the consolidated H1 acceptance campaign. Work may continue
with local H1-A3;
the long owned-host campaign must not begin until the remaining A3 interfaces
are ready.

## Exclusions

This work does not add a network source, trust ordinary RPC finality, weaken the
birthday rule, import real seed material, activate spending, or claim power-loss
durability from unit tests. No real funds are authorized.
