# Vault wallet root-key and rollback custody v1

**Status:** production-intent BIP-39 seed boundary, root-key types, and
two-phase rollback protocol implemented; platform keychain/secure-element
adapters, physical fault tests, memory locking, crash-dump policy, rotation,
and independent review remain open
**Last updated:** 2026-08-27

## 1. Security boundary

Wallet seed material authorizes funds. The wallet database root key authorizes
only decryption of one encrypted database and its backups. They MUST be
independent: the root key is a fresh non-zero 32-byte operating-system CSPRNG
output and MUST NOT be derived from a seed, mnemonic, password, account key, or
viewing key. Compromise of the root key reveals wallet-private database state
but does not by itself create spend authorization; compromise of the seed is a
funds compromise.

`WalletRootKey` is non-`Clone`, redacts `Debug`, rejects zero, and zeroizes its
process copy on drop. `WalletRootKeyStore` defines a no-clobber protected slot
that stores/loads this key. The interface does not claim that every keychain is
sufficient. A platform adapter must document application/user access control,
authentication prompts, device-lock behavior, cloud synchronization and backup,
exportability, deletion, process-memory lifetime, and crash-dump exposure.

Arbitrary passwords or unchecked mnemonic text MUST NOT be passed directly to
`VaultSpendingKey::derive`. The selected checksum, normalization, KDF, language,
and confirmation boundary is specified in
[`WALLET_SEED_V1.md`](WALLET_SEED_V1.md). Hardware import and platform ceremony
evidence remain open.

## 2. Exact rollback anchor

`EncryptedWalletDb::rollback_anchor` computes:

```text
BLAKE3-DeriveKey(
  "vault.wallet.rollback-anchor-v1.2026-08-27",
  database_id || chain_id || wallet_id ||
  finalized_height_be64 || finalized_block_hash ||
  note_tree_size_be64 || note_tree_root
)
```

The public redacted `WalletRollbackAnchor` carries only the exact finalized
height and this 32-byte commitment. Unlike the older minimum-height argument,
it detects another database identity, network/wallet mixup, a different fork or
tree at the same height, and every older or unrelated otherwise valid snapshot.
The 32-byte database ID is random and remains inside the commitment.

## 3. Protected state record

One rollback-resistant slot stores the complete 90-byte canonical
`WalletRollbackState`:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 1 | version, exactly `1` |
| 1 | 8 | non-zero secure generation |
| 9 | 8 | stable finalized height |
| 17 | 32 | stable rollback-anchor commitment |
| 49 | 1 | pending flag, `0` or `1` |
| 50 | 8 | pending successor height or zero |
| 58 | 32 | pending successor commitment or zero |

Absent pending bytes must all be zero. A present pending anchor must be the
exact next height and differ from stable. Unknown versions, wrong lengths, zero
generation/commitments, skipped heights, and non-canonical absence fail closed.
The record intentionally contains no root key.

`WalletSecureRollbackStore` is bound by its adapter instance to exactly one
wallet slot. `load` returns the whole record. `compare_and_swap(expected,
replacement)` must atomically and durably replace it only when the complete
stored bytes equal `expected`, and must resist host-controlled rollback. A
plain file, preferences database, ordinary SQLite table, or keychain record
that can be restored with a host backup does not meet this contract without a
separate monotonic hardware generation.

## 4. Two-phase finalized commit

`RollbackProtectedWalletDb` is the production storage wrapper. Enrollment is
allowed only into an empty secure slot and must happen immediately during a new
wallet or independently trusted recovery ceremony. Enrolling an already exposed
database could bless a rollback and is forbidden operationally.

For every finalized block:

1. authenticate the database tip and require it to equal secure `stable`;
2. reject a stale scanner parent before touching secure state;
3. compute the exact next rollback anchor;
4. CAS `stable/no-pending` to `stable/pending-next` with a new generation;
5. execute the complete SQLite finalized-block transaction;
6. on definite SQLite rollback, CAS to the old stable anchor with no pending
   and another generation;
7. on successful SQLite commit, CAS to `stable=next/no-pending` with another
   generation; and
8. poison the wrapper on any uncertain database or secure-store outcome.

After restart:

- database equals stable, no pending: open;
- database equals pending: the database commit definitely reached the pending
  state, so finalize the secure record by CAS and open;
- database equals stable while pending exists: stop as
  `AmbiguousPendingTransition`; clearing it could accept a committed-then-
  rolled-back database;
- database matches neither: report rollback and stop.

This deliberately favors fund safety over availability. An ambiguous case
requires trusted recovery/restore, never a “reset security state” button.
Compaction may run through the wrapper because it cannot change the anchor; the
wrapper checks exact anchor equality afterward.

## 5. Recovery and backup interaction

The rollback slot is not portable backup content. On ordinary reopen and restore
the database must match the protected exact anchor, not only a caller-supplied
minimum height. Restoring an older valid backup therefore fails while the slot
survives. Disaster recovery onto replacement hardware requires an explicit
trusted ceremony: authenticate the selected backup, establish its relation to
independently finalized history, rescan as needed, create/drill a new backup,
then enroll an empty replacement secure slot. Existing secure state must never
be silently overwritten to make an old backup open.

After seed recovery reaches `Complete`, the application finalizes the secure
anchor and creates/drills a backup. `InProgress`,
`RequiresLargerAccountRange`, ambiguous rollback state, or a missing adapter
never authorizes spending.

## 6. Evidence and remaining platform gates

Internal tests cover canonical rollback-state encoding, every truncated prefix,
non-canonical absence, skipped pending heights, an injected secure-store failure
after a successful database commit, automatic pending finalization on reopen,
and rejection after replacing the database with the earlier valid snapshot.
These prove the state machine, not a platform's hardware guarantees.

Before real funds, each supported platform still requires:

- a reviewed `WalletRootKeyStore` and `WalletSecureRollbackStore` adapter;
- proof that CAS/generation cannot be rolled back by OS restore, cloud sync,
  VM snapshot, user backup, or privileged host storage replacement;
- device-lock, authentication-prompt, uninstall/reinstall, account migration,
  and lost-device behavior;
- hard reset/power loss between every prepare/database/finalize boundary;
- memory-locking feasibility, swap/hibernation/crash-dump controls, and review of
  unavoidable root-key/seed/plaintext copies;
- no-clobber enrollment, rotation/revocation, hardware replacement, and disaster
  recovery drills; and
- independent custody/storage review.

A generic rented VM cannot satisfy these physical/platform claims. No real
funds are authorized until the declared adapters and wider H1 gates pass.
