# Vault encrypted wallet backup v1

**Status:** production-intent implementation and adversarial tests complete; operational recovery gates remain  
**Last updated:** 2026-08-23

## 1. Purpose and non-goals

Wallet backup v1 creates one portable authenticated container from a consistent
SQLite snapshot of the finalized wallet database. It restores a non-empty
ShardTree, notes, spends, checkpoints, and finalized scan tip without accepting
an unauthenticated frontier.

The public prefix exposes only format information, a fresh random backup ID and
nonce prefix, and the 1 MiB size bucket already implied by total file length.
Network, persistent wallet/database identifiers, exact snapshot length,
configuration, finalized height, and tip hash are in the encrypted manifest.
Independent exports are not linkable by those fields; byte-for-byte copies of
one backup remain trivially linkable.

The format does not hide that a backup exists, its bucketed size, creation or
access timing, destination path, or host/network metadata around storage. It is
not seed backup, social recovery, cloud synchronization, or a substitute for
multiple independently verified copies.

## 2. Snapshot and filesystem rules

Export requires the wallet root key again and constant-time checks that it
derives both live database subkeys before creating any destination. It uses
SQLite's online backup API to copy the authenticated database into an
owner-only temporary file. The source handle already holds Vault's exclusive
wallet lock. The snapshot is streamed into a second same-directory temporary
file, synchronized, and published with no-clobber semantics. An existing backup
target is never replaced. Before copying, the checked SQLite page-count ×
page-size value must be non-zero and within the 64 GiB profile; the resulting
snapshot length must equal that preflight value.

Restore requires an absent destination under an absolute canonical directory
owned by the effective user and not writable by group or world. Input and lock
files must be owner-owned regular files with one link and no group/world access;
opening follows neither symlinks nor unsafe permissions. Restore holds the
destination sibling lock throughout publication and final reopen, decrypts to
an owner-only same-directory temporary file, authenticates every chunk, opens
and fully validates the recovered database, then publishes without clobbering
and synchronizes the parent directory. Failure before publication leaves the
database destination absent. Temporary files are deleted on drop.

The current profile is Unix-only because it depends on Unix ownership,
permission, link, no-follow, advisory-lock, and directory-sync behavior.

## 3. Public prefix and encrypted manifest

All integers are unsigned big-endian. The first 64 bytes are public:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VWB1` |
| 4 | 2 | container version `1` |
| 6 | 2 | complete header bytes, exactly `272` |
| 8 | 32 | fresh random non-zero backup ID |
| 40 | 16 | fresh random nonce prefix |
| 56 | 8 | padded chunk count |

Bytes 64 through 271 contain a 192-byte manifest encrypted with a 16-byte
XChaCha20-Poly1305 tag. The authenticated plaintext is:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 2 | manifest version `1` |
| 2 | 2 | manifest plaintext bytes, exactly `192` |
| 4 | 32 | wallet database ID |
| 36 | 32 | Vault chain ID |
| 68 | 32 | random wallet-instance ID |
| 100 | 8 | maximum accepted note value |
| 108 | 8 | maximum ordinary ShardTree checkpoints |
| 116 | 8 | finalized tip height |
| 124 | 32 | finalized tip block hash |
| 156 | 8 | exact SQLite snapshot bytes |
| 164 | 4 | plaintext chunk bytes, exactly `65,536` |
| 168 | 8 | padded chunk count, repeated and authenticated |
| 176 | 16 | reserved, all zero |

The snapshot is non-empty and no larger than 64 GiB. Its exact chunk count is
`ceil(snapshot_bytes / 65,536)`. The padded count is the smallest multiple of 16
not below that value and is at least 16. Public and authenticated counts must
match that canonical result. This rounds plaintext to 1 MiB buckets.

Malformed versions, lengths, bounds, reserved bytes, IDs, counts, or complete
file lengths are rejected. Parser-controlled allocation remains bounded to one
fixed chunk.

## 4. Key separation and AEAD

Each export samples a fresh `backup_id` and derives directly from the already
uniform 32-byte wallet root key:

```text
K_backup = BLAKE3-DERIVE(
  "vault.wallet-backup-v1.key.2026-08-23",
  root_key || backup_id
)
```

The root key is not a human password; password-based wrapping and recovery are
separate layers. `K_backup` is zeroized after use.

The 16-byte nonce prefix is concatenated with an unsigned 64-bit big-endian
counter to form each 24-byte XChaCha20 nonce. Counter `2^64 - 1` is reserved for
the manifest; chunk counters start at zero. The public prefix is the manifest's
associated data. The complete 272-byte header plus the chunk index is each
chunk's associated data:

```text
header || chunk_index_be64
```

Every plaintext chunk is exactly 65,536 bytes. Bytes beyond the SQLite snapshot,
including all padding chunks, come from the operating-system CSPRNG before
encryption. Each ciphertext chunk is 65,552 bytes. Compression is forbidden
because content-dependent size would leak information.

The complete file length is exactly:

```text
272 + padded_chunk_count * 65,552
```

## 5. Restore validation and rollback

The caller supplies the expected chain ID, wallet-instance ID, root key, and a
minimum finalized height obtained from separately protected monotonic state.
Restore validates only public resource bounds before deriving `K_backup`; it
authenticates and parses the private manifest before reporting scope or rollback
status and before writing snapshot bytes.

Every data and padding chunk is then authenticated. Only the exact declared
snapshot length is written. Before publication, normal wallet database open
validation MUST pass: SQLite integrity and schema, key check, database scope and
policy, encrypted tip and recovery origin, ShardTree root and maximum position,
checkpoint tip, retained markers, and complete owned-note/mark reconciliation.
Database ID, policy, exact tip height, and tip block hash MUST equal the
encrypted manifest.

A correct monotonic floor detects restoration below the last externally
recorded height. The container cannot prevent rollback if an attacker can also
roll back that external state. Hardware/keychain rollback state and its atomic
update protocol remain an H1 activation gate.

## 6. Bounds and failure behavior

- maximum snapshot plaintext: 64 GiB;
- chunk plaintext: 65,536 bytes;
- padding quantum: 16 chunks / 1 MiB;
- maximum authenticated plaintext or ciphertext held in memory: one chunk plus
  fixed header overhead;
- no overwrite of backup or restored database targets;
- any entropy, snapshot, I/O, sync, parse, authentication, validation,
  publication, or directory-sync error fails closed;
- incomplete containers and temporary restored snapshots are never opened as
  the live wallet path.

An error after no-clobber publication but before directory sync has an uncertain
durability outcome and MUST be reported. The exact destination may exist and
must be revalidated instead of blindly retried or overwritten.

## 7. Implemented verification

Automated tests cover a non-empty external/internal wallet round trip, current
Merkle witnesses, a later spend and durable reopen, wrong export/restore root
keys, wrong network scope, rollback floor, existing targets, owner-only modes,
header privacy, malformed/truncated/appended containers, manifest corruption,
first and padding chunk corruption, and cross-backup chunk splicing. Unit tests
cover canonical bucket bounds, prefix/manifest codecs, reserved bytes, and nonce
and associated-data separation.

## 8. Remaining recovery gates

This format does not yet provide seed/key recovery, backup rotation policy,
multi-copy inventory, cloud-provider privacy, deletion verification, damaged
backup repair, cross-version migration, key rotation, secure rollback-floor
updates, user confirmation UX, crash injection at every publication boundary,
or scheduled restore drills. Those controls and independent review remain
mandatory before real funds.
