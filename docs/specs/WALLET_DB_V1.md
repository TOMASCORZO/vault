# Vault encrypted finalized-wallet database v1

**Status:** production-intent Unix database, authenticated backup/restore,
finalized birthday frontier, durable seed-recovery state, schema-1 to schema-2
migration, bounded checkpoint retention, and validated compaction; seed
custody, future-schema, platform-keystore, executed external fault/side-channel,
and independent-review gates remain open
**Last updated:** 2026-08-27

## 1. Security boundary

The v1 wallet database atomically persists the finalized compact-block scan tip,
owned notes, spend state, and a depth-32 ShardTree witness structure. It protects
wallet-private row contents against offline disclosure and undetected byte-level
substitution under an uncompromised 32-byte root key. It does not hide the
SQLite schema, file size, table cardinalities, shard indices, checkpoint
heights, open/commit timing, page access, or backup age.

The root key is never stored in this database. `WalletRootKey` and
`WalletRootKeyStore` define the independent random zeroizing key and protected
platform slot, but real platform adapters are not implemented yet. The legacy
raw open path accepts a monotonic minimum finalized height; this detects only
restoration below that caller-provided floor and cannot make the floor
rollback-resistant. Production integration must use the exact-anchor two-phase
`RollbackProtectedWalletDb` protocol specified in
[`WALLET_CUSTODY_V1.md`](WALLET_CUSTODY_V1.md).

Only authenticated finalized blocks enter this store. Unfinalized notes and
ordinary chain reorganization are outside this state machine.

## 2. Filesystem lifecycle

`create` and `open` are separate operations. `create` refuses an existing path;
`open` refuses a missing path. The current profile is Unix-only and requires:

- an absolute path whose existing parent is already canonical;
- a parent directory owned by the effective user and not writable by group or
  world;
- an effective-user-owned `0600` regular database file with one hard link;
- SQLite `SQLITE_OPEN_NOFOLLOW` plus a sibling owner-only file lock opened with
  `O_NOFOLLOW | O_CLOEXEC` and held exclusively for the handle lifetime;
- explicit failure for symlinks, hard links, unsafe permissions, concurrent
  access, missing state, or an existing create target.

Normal initialization accepts only height-zero with an empty note tree.
Non-empty databases enter either through the authenticated container and
complete validation specified in [`WALLET_BACKUP_V1.md`](WALLET_BACKUP_V1.md),
or through the explicit finalized birthday boundary in
[`WALLET_RECOVERY_V1.md`](WALLET_RECOVERY_V1.md). Later empty-tree heights also
require that explicit boundary. Silently treating an arbitrary frontier as
complete witness state is forbidden.

## 3. Key hierarchy and record envelope

Creation samples a random non-zero 32-byte `database_id`. The metadata row stores
that ID, the chain ID, random wallet-instance ID, maximum note value, and bounded
checkpoint policy. Two 32-byte subkeys are derived independently with BLAKE3
derive-key mode:

```text
K_enc = BLAKE3-DERIVE(
  "vault.wallet-db-v1.master-key.2026-08-23",
  root_key || database_id || chain_id || wallet_id ||
  maximum_note_value_be64 || max_checkpoints_be64
)

K_index = BLAKE3-DERIVE(
  "vault.wallet-db-v1.nullifier-index-key.2026-08-23",
  same_input
)
```

Binding the public policy metadata into both keys makes metadata substitution
invalidate every authenticated record. A fixed key-check plaintext is sealed
at creation and authenticated before any private row is accepted on open.

Every encrypted record is:

| Bytes | Field |
|---:|---|
| 1 | envelope version `1` |
| 24 | fresh OS-random XChaCha20 nonce |
| variable | XChaCha20-Poly1305 ciphertext and 16-byte tag |

The associated data is length-unambiguous:

```text
"vault.wallet-db-v1.record-aad.2026-08-23" ||
schema_version_be32 || database_id || chain_id || wallet_id ||
record_kind_u8 || record_key_length_be16 || record_key
```

Record kinds separate key check, finalized tip, immutable recovery origin,
mutable authenticated recovery progress, tree shard, cap, checkpoint,
retained-checkpoint marker, and owned note. Plaintexts
are bounded to 8 MiB. Authentication failure, unknown
version, truncation, trailing bytes, invalid flags, excessive tree nodes, or
non-canonical field encodings fails closed.

The lookup key for an owned note is not its public nullifier. It is:

```text
tag = BLAKE3-KEYED(
  K_index,
  "vault.wallet-db-v1.nullifier-tag.2026-08-23" || spend_nullifier
)
```

The note payload redundantly contains and authenticates that nullifier. Opening
the database recomputes every tag and rejects mismatches.

## 4. SQLite durability profile

The database pins bundled SQLite through `rusqlite` and configures:

- rollback journal mode `DELETE`, not WAL;
- `synchronous=EXTRA` and `fullfsync=ON`;
- foreign keys enabled, trusted schema disabled, defensive mode enabled;
- secure deletion enabled and temporary storage kept in memory;
- zero busy timeout because the sibling process lock establishes one writer;
- parent-directory sync after initial creation.

The selected rollback profile avoids a persistent WAL sidecar and requests a
directory sync after journal unlink. A commit error or rollback error poisons
the handle because its durable outcome is treated as uncertain. A definite
pre-commit error explicitly rolls back and leaves the handle usable only when
rollback succeeds.

## 5. Atomic finalized transition

For each authenticated `ScannedBlockUpdate`, one immediate SQL transaction:

1. decrypts the current tip and compares exact expected height, parent hash,
   pre-tree size, and pre-tree root;
2. inserts every canonical note commitment in block order into a depth-32,
   shard-height-16 ShardTree;
3. marks every locally owned position and creates a checkpoint identified by
   finalized block height at the block's last leaf;
4. recomputes the checkpoint root and compares it with the independently
   authenticated compact-block post root;
5. encrypts each detected note, including local account ID, external/internal
   scope, position, creating transaction/action, note commitment, action
   nullifier, future spend nullifier, private note, and fixed memo;
6. hashes every public block nullifier into the private lookup domain, marks a
   matching note spent, and schedules its ShardTree mark for removal at the
   current checkpoint;
7. encrypts and replaces the new finalized tip; and
8. commits all rows or none.

Incoming scan accounts always derive both external and internal incoming keys
from a full viewing key. A matching note's future spend nullifier is derived
locally before persistence. Duplicate account IDs, duplicate incoming
capabilities, excessive accounts, and duplicate derived owned nullifiers are
rejected before a database update is produced.

## 6. Opening and witness extraction

Every open performs SQLite `quick_check`, exact schema-version and scope checks,
key-check authentication, tip decryption, ShardTree maximum-position and root
reconstruction, latest-checkpoint comparison, and a full owned-note
reconciliation. Reconciliation decrypts every note row, recomputes its private
tag, validates its private note commitment and `rho`, and requires the set of
effective unspent notes to equal the ShardTree marked positions after applying
checkpoint mark removals. Deleting an unspent note row therefore fails open
validation instead of silently losing spendable balance.

The database also authenticates exactly one encrypted origin record. Genesis
requires height zero and an empty frontier. Birthday origin requires a positive
height, is bound to the database network, cannot be ahead of the current tip,
and must equal the complete current tip when their heights match. The public
`birthday_checkpoint` accessor returns this original canonical frontier for
future deterministic rescans without exposing it through `Debug`.

Schema version 2 additionally stores exactly one encrypted `wallet_recovery`
record. Genesis encodes `NotRequired`; birthday recovery binds the exact target,
ordered account IDs and viewing-key-set commitment, account gap, activity mask,
and durable phase. The record changes atomically with every scan commit. Open
rejects origin/recovery mismatches, impossible phases or masks, and target/gap
inconsistency. Spend-witness extraction is disabled until the authenticated
phase is complete. Full construction and recovery semantics are specified in
[`WALLET_RECOVERY_V1.md`](WALLET_RECOVERY_V1.md).

### 6.1 Schema-1 to schema-2 migration

`EncryptedWalletDb::migrate_legacy_v1` is the only public in-place migration
entry point. It accepts exactly schema 1, authenticates the complete legacy
state under schema-1 record AAD, requires a genesis origin, and publishes a
non-overwriting authenticated legacy backup before beginning the database
transaction. A missing, unsafe, or existing backup destination prevents any
migration write.

Inside one exclusive SQLite transaction, every encrypted tip, origin, note,
shard, cap, checkpoint, retained-checkpoint marker, and key-check record is
opened under schema-1 AAD and resealed with fresh randomness under schema-2
AAD. The metadata table is replaced with its exact schema-2 constraint, a
canonical encrypted `NotRequired` recovery record is inserted, and both public
schema version fields advance to 2. Any error rolls the complete transaction
back; an uncertain rollback returns `Poisoned`. The published schema-1 backup
is deliberately retained.

Schema-1 birthday databases are not migrated. They predate the authenticated
target, account-set commitment, account-gap, activity mask, and completion
phase needed by schema 2, so inventing `NotRequired` would make incomplete
recovery appear spendable. They must instead be recovered into a new database
from a conservative authenticated birthday. Unknown schemas, attempts to apply
the legacy migration to schema 2, and downgrade attempts fail closed.

Restoring an authenticated schema-1 backup with the current implementation
validates and migrates the temporary snapshot before its no-clobber publication.
The original backup remains unchanged, and the restored destination is always
schema 2.

### 6.2 Checkpoint retention and compaction

`max_checkpoints` is immutable authenticated database policy in 1..4096 and is
passed directly to ShardTree for every create, open, validation, witness, and
commit operation. It caps ordinary finalized checkpoints; required reference
and mark state for the authenticated origin and unspent-note witnesses is not
discarded merely to meet that ordinary count. Full validation separately
rejects more than 8192 checkpoint rows or more than 4096 retained-checkpoint
markers, checks every checkpoint codec and mark removal, reconstructs the tree,
and reconciles the effective marked positions with all decrypted unspent notes.

`EncryptedWalletDb::compact` is the only compaction entry point. The operational
layer MUST first create, byte-verify, and successfully drill a current backup.
The method fully validates the open state, records file/page/free-list sizes,
runs SQLite `VACUUM` under the existing exclusive wallet lock, synchronizes the
database file, validates the complete state again, and requires a zero free
list. A definite `VACUUM` failure returns `DatabaseFailure` only if the original
database still validates; an invalid post-failure state permanently poisons the
handle. Compaction never changes the logical tip, notes, witnesses, recovery
state, origin, or retention policy and can require temporary space comparable
to the database.

`witness_for_spend` accepts a known owned spend nullifier, rejects missing or
spent notes, derives the depth-32 path at the exact finalized tip checkpoint,
converts it into Vault's canonical membership-path type, and verifies the note
commitment against the returned anchor before releasing the private witness.
The returned type redacts all fields from `Debug`.

## 7. Explicit remaining gates

This implementation is not release-ready. H1 still requires:

- real hardware/keychain root-key and rollback-state adapters on every declared
  platform, plus physical failure evidence for the implemented exact-anchor
  protocol;
- approved seed custody/import, trusted birthday/target distribution,
  a validating full-node/light-client recovery source, private retrieval,
  product incomplete-recovery UX, policy above 64 accounts, executed scheduled
  backup rotation/restore drills, protected multi-copy inventory,
  and disaster-recovery documentation;
- an explicit reviewed path and fixtures for every future schema version; the
  implemented 1-to-2 path does not authorize downgrade or skipping versions;
- target-host long-history/pruning/compaction measurements and external
  migration/backup/restore stress execution;
- sustained process-crash plus power-loss, disk-full, partial-write, filesystem,
  and SQLite fault injection on every declared platform;
- private/padded compact-block retrieval and access-pattern/timing/cache
  measurements; row encryption does not make node traffic anonymous;
- memory-locking/crash-dump policy and review of unavoidable plaintext copies;
- corpus fuzzing of all encrypted codecs and independent wallet/storage review.

No real funds may use this database until these gates and the wider H1/H2
release gates pass.

## 8. Current internal evidence

Tests cover exact ShardTree/checkpoint codec round trips, every truncated prefix,
trailing bytes, duplicate mark positions, external and internal note discovery,
future-nullifier derivation, atomic stale-tip rollback, exclusive locking, wrong
root key, wrong network/wallet scope, secure-height rollback detection,
authenticated tip tampering, owned-row deletion reconciliation, reopen after
spend, current witness verification, and absence of known private memo/nullifier
patterns in the committed database file. Backup tests additionally cover a
non-empty witness round trip and later spend, hidden header metadata, wrong
keys/scopes/floors, corruption, truncation, appending, splicing, padding, and
no-overwrite behavior. These tests are internal evidence, not an audit or a
power-loss guarantee. Birthday tests additionally bind the frontier to a
finalized header, reject the ordinary-create bypass and mismatched snapshots,
recover a later note, advance its witness, persist/reopen the origin, and reject
origin ciphertext tampering. Seed-recovery tests additionally cover deterministic
multi-batch account derivation, wrong account-set and target rollback, resumable
incomplete state, spend blocking, conservative gap completion, explicit range
exhaustion, backup preservation, and recovery-record authentication.
Migration tests additionally cover a required no-clobber backup, non-empty
note/witness preservation, schema-1 backup restore into schema 2, refusal to
reapply the legacy migration, and atomic rollback after each of nine logical
migration stages.
Backup-operation tests additionally bind a published receipt to exact copied
bytes, reject a damaged copy, and complete the exact restore path in protected
disposable storage. Compaction tests preserve a current spend witness and
require non-increasing file/page counts after complete revalidation. The
bounded long-history, owned-note, legacy-migration, process-crash, ENOSPC, and
Linux `perf` harnesses are specified in
[`../research/H1-A2-WALLET-HARDENING.md`](../research/H1-A2-WALLET-HARDENING.md);
small local runner checks are not external acceptance evidence.
