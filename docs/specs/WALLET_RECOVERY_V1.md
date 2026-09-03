# Vault wallet seed and birthday recovery v1

**Status:** production-intent typed seed-import boundary, deterministic account
discovery, finalized target, durable progress, and birthday-frontier initialization
implemented; authenticated birthday and target distribution are implemented;
authenticated policy updates and the crash-consistent Unix policy log are
implemented; platform custody/rollback guards, publisher operations,
operational UX, fault injection, and internal security review remain activation
gates
**Last updated:** 2026-09-02

## 1. Purpose and safety boundary

Recovery creates a new encrypted wallet database at a finalized note-tree
frontier immediately before the first block that must be scanned. It derives a
bounded contiguous set of seed accounts, scans every finalized compact block to
an independently known target, and records whether the result is complete.

A birthday is an availability assertion, not a performance hint. Selecting a
checkpoint after the first possible incoming or change output can permanently
omit funds. Vault cannot infer first address exposure from the seed. Production
UX MUST choose a conservative birthday, warn on overrides, and offer genesis
recovery when provenance is uncertain.

The implementation accepts seed material transiently but never stores it. Each
derived spending key is converted immediately to a full viewing key and dropped;
the recovery account container retains only viewing capabilities, which cannot
authorize spends and are zeroized by their underlying types on drop. The typed
seed boundary, package checksum, and scoped custodian callback are implemented;
hardware/platform custody, memory locking, and crash-dump controls remain
separate gates.

### 1.1 Seed import and custody boundary

`WalletSeedMaterial` owns exactly 32 bytes of nonzero entropy in a non-clonable,
redacted, zeroizing value. Generation consumes a cryptographic RNG once and
fails closed on all-zero output. An already authenticated platform custodian may
provide exact entropy through `from_custodian_entropy`; interactive or file
entry instead uses `import_recovery_package`.

The version-1 recovery package is exactly 72 bytes:

```text
"VSEED001" || entropy_32 || BLAKE3-DERIVE(
  "vault.wallet.seed-recovery-package-v1.2026-09-02",
  "VSEED001" || entropy_32
)
```

The checksum detects accidental truncation, trailing data, version confusion,
and mutation before derivation. It is neither encryption nor authentication
against an attacker who can replace the whole package. Exported packages contain
the seed in plaintext and belong only on an approved offline custody medium.

The deterministic codec vector uses entropy byte `a1` repeated 32 times and
produces checksum
`39f4d9f6a3ae31098d09c8d7054311ce60f6efba2ca52280e4c7ae96978118ad`.
The test pins the complete 72-byte package and rejects mutation of every byte.

`WalletSeedCustodian::use_seed` lends a reference for one scoped operation.
`WalletRecoveryAccounts::derive_from_custodian` validates public resource limits
before requesting access and retains only viewing capabilities. Concrete OS
keystore and hardware implementations are later platform gates.

## 2. Trusted finalized boundaries

`WalletBirthdayCheckpoint::from_finalized_header` accepts a caller-verified
`FinalizedCompactBlockHeader` and canonical depth-32 `NoteTreeSnapshot`. It
restores the frontier and requires exact equality with the header post-tree size
and root, then binds chain ID, height, and block hash. The header type is an
assertion boundary; an unauthenticated RPC response MUST NOT construct it.

The checkpoint is the last excluded block:

```text
first_scan_height = checkpoint_height + 1
```

`WalletRecoveryPlan::new` additionally binds the exact independently finalized
target block hash, height, post-tree size, and post-tree root. The target must be
strictly after the birthday, on the same chain, and cannot regress tree size.
Reaching the same height on another fork or with another root is rejected and
rolled back atomically.

Ordinary `EncryptedWalletDb::create` accepts only the empty height-zero genesis
tip. Every non-genesis start must use `create_from_recovery_plan`; there is no
lower-level birthday creation API that can bypass account and completeness
tracking.

### 2.1 Authenticated checkpoint distribution

`CheckpointDistributionDraft` encodes a validated birthday frontier and its
claimed finalized boundary as:

```text
"VCKPT001" || chain_id_32 || height_be64 || block_hash_32 ||
tree_size_be64 || tree_root_32 || leaf_present_u8 || leaf_32 ||
ommer_count_u8 || ommers_32_each
```

Between 1 and 8 canonical records are then appended:

```text
signature_count_u8 || ordered(
  publisher_id_32 || ed25519_signature_64
)
```

Publisher IDs are BLAKE3 derive-key hashes of separately configured Ed25519
verification keys under
`vault.wallet.checkpoint-publisher-id-v1.2026-09-02`. The trust policy pins a
network, a unique publisher set, and a nonzero threshold. Verification uses
strict Ed25519 checks, requires strictly ordered unique known IDs, validates the
bounded depth-32 frontier, and rejects truncation, trailing data, unknown keys,
weak keys, insufficient signatures, and every signed-field mutation.

Publisher threshold authenticates distribution only. The verifier also requires
an independently consensus-verified `FinalizedCompactBlockHeader` whose network,
height, block hash, post-tree size, and post-tree root exactly match the package.
Provider or publisher agreement is never promoted to consensus finality. Target
checkpoints use a distinct signing domain and omit the birthday frontier:

```text
"VTARG001" || chain_id_32 || height_be64 || block_hash_32 ||
tree_size_be64 || tree_root_32
```

`verify_recovery_target_distribution` applies the same threshold and exact
independent-finality checks. Its result can enter
`WalletRecoveryPlan::new_with_authenticated_target`; the birthday and target
types cannot be interchanged.

`CheckpointPolicyUpdateDraft` encodes a complete successor as:

```text
"VPOLY001" || chain_id_32 || predecessor_generation_be64 ||
predecessor_policy_id_32 || successor_generation_be64 || threshold_u8 ||
publisher_count_u8 || ordered(publisher_verifying_key_32)
```

The active predecessor threshold signs those exact bytes using the same ordered
signature-record format. `verify_checkpoint_policy_update` requires the exact
network, predecessor generation and predecessor policy ID, validates every new
key, and constructs only a strictly newer complete policy. Omitted keys are
revoked. The stable policy ID commits to the network, generation, threshold,
count, and canonical key order under
`vault.wallet.checkpoint-policy-id-v1.2026-09-02`.

`CheckpointPolicyBootstrapDraft` encodes the generation-1 root as:

```text
"VBOOT001" || chain_id_32 || generation_be64(1) || threshold_u8 ||
publisher_count_u8 || ordered(publisher_verifying_key_32) ||
ceremony_nonce_32 || policy_id_32
```

Keys are ordered by their derived publisher IDs. Every configured publisher,
not merely the operational threshold, must sign these exact bytes to prove key
possession and agreement on the ceremony transcript. The nonce must be nonzero
and unique to the ceremony. `verify_checkpoint_policy_bootstrap` reconstructs
the policy, validates all signatures, and requires the encoded ID to equal a
separately supplied expected policy ID. The deterministic two-of-three vector
is 499 bytes and has BLAKE3 hash
`f6bc8a6b6e706d19ae2b810dc5efd8b6979a87ea6660bafc058174fd5330d317`;
its test rejects every single-byte mutation, every truncated prefix, and
trailing data.

The package proves possession, not the real-world identity or independence of
its publishers. The expected policy ID MUST be pinned through the approved
release manifest or independent operator-confirmation channel before the
package is accepted. `CheckpointPolicyStore::create_from_bootstrap_package` and
`CheckpointPolicyStore::open_from_bootstrap_package` enforce this verification
at the persistent-store boundary; no public bare-policy initialization path is
exposed.

The deterministic two-of-three generation-1 to generation-2 update vector is
379 bytes and has BLAKE3 hash
`687555c09469a235a1b48f08293bf318e39cb568733998d8e4599837b332a666`.
Its test rejects every single-byte mutation, every truncated prefix, and
trailing data.

`CheckpointPolicyStore` retains up to 64 authenticated updates from an
independently pinned bootstrap policy in a single-owner Unix file. Each atomic
replacement is synced with its parent directory. On every open it verifies the
complete signature chain rather than trusting the checksum. Its checksum only
detects corruption; authentication comes from the predecessor signatures.
State and lock files are owner-only; relative paths, unsafe parent permissions,
symlinks, hard-linked/non-regular state, concurrent owners, truncation, trailing
bytes, and oversized histories fail closed.

The store requires a `CheckpointPolicyRollbackGuard` implemented by approved
platform storage. The guard anchors both generation and exact policy ID, not
only a numeric floor. The protected anchor must occur in the replayed lineage,
which rejects an older valid file, same-generation equivocation, and a higher
branch that skips a previously anchored policy. Installation writes the signed
log before advancing the protected anchor; any uncertain file or guard failure
poisons the handle, and reopening replays the durable log before retrying the
anchor. Concrete keychain/secure-element guard implementations, the real
publisher selection/key-custody/release-pinning ceremony, 64-update
compaction/re-bootstrap, and operational rotation drills remain activation
gates.

The deterministic empty-frontier two-of-three test package is 347 bytes and has
BLAKE3 hash
`ed559ebbce82263c23f7b2e284d37d1c86bbf1d122dec8cc2fac72aefcae0a22`.
The test rejects mutation at every byte and every truncated prefix.

## 3. Deterministic account discovery

`WalletRecoveryAccounts::derive(seed_material, chain_id, account_count)` derives
the contiguous account range `0..account_count` through the typed seed boundary
and network-separated `VaultSpendingKey` derivation. Within an account, one full
viewing key covers all diversified external recipient addresses and the internal
change scope, so address indices do not use a separate gap rule.

For every account the wallet derives a stable private `WalletAccountId` from:

```text
BLAKE3-DeriveKey(
  "vault.wallet.recovery-account-id-v1.2026-08-23",
  chain_id || account_index_be32 || rejection_counter_u8 || full_viewing_key
)
```

The identifier is stored only inside encrypted wallet state. Recovery also
commits to the ordered indices, account IDs, and full viewing keys under the
domain `vault.wallet.scan-account-set-v1.2026-08-23`. Every scanned block carries
this commitment in its opaque store update. During recovery, the database
rejects an update produced with a different seed, account count, ordering, ID,
or viewing capability—even if that block happened to contain no matching note.

The primitive accepts at most 16 incoming viewing capabilities per call. Each
account contributes two, so the wallet evaluates groups of eight accounts. A
complete block scan executes up to eight primitive groups, giving the current
global bound of 64 accounts. All groups scan all outputs in fixed bounded output
batches; a match never short-circuits later groups. Exceeding 64 is rejected
before scanning. This is a production resource bound, not a claim that 64 is
universally sufficient; performance benchmarks and a reviewed wider/multipass
policy remain gates.

## 4. Conservative account-gap rule

The caller selects `account_count` and a nonzero `gap_limit <= account_count`.
Vault does not stop historical scanning after observing an unused account. Every
configured account is tested against every output through the exact finalized
target. Only then does it evaluate completeness:

```text
trailing_unused = account_count                         if no account was used
                  account_count - highest_used - 1      otherwise

complete = trailing_unused >= gap_limit
```

An account becomes used when any authenticated note for its private account ID
is recovered. The bit remains set even if the note is spent later. If activity
is too near the upper bound, the durable phase becomes
`RequiresLargerAccountRange`; it never silently reports a final balance. The
caller must create a new destination from the same conservative birthday with a
larger plan and rescan. If the 64-account bound is exhausted, recovery remains
failed closed until a wider reviewed implementation exists.

A gap rule cannot prove that an unknown high account was never used. It is an
explicit wallet policy whose assumptions must be shown to the user and covered
by application-specific recovery documentation.

## 5. ShardTree initialization

The canonical birthday frontier is converted to
`incrementalmerkletree::Frontier` and inserted with:

```text
Retention::Checkpoint {
    id: checkpoint_height,
    marking: Marking::Reference,
}
```

`Reference` prevents imported ommers needed by future witnesses from being
pruned. Historical leaves are not marked spendable; the birthday asserts that
no owned note exists before it. New authenticated notes are marked normally.

Initialization atomically writes schema, metadata, encrypted tip, immutable
origin, recovery state, tree cap, shards, and checkpoint. Before commit, Vault
recomputes maximum position and checkpoint root and requires exact equality with
the birthday. Existing destinations are never opened or replaced.

## 6. Authenticated durable progress

Every database contains one encrypted `wallet_origin` row and one encrypted
`wallet_recovery` row under distinct AEAD record domains. Genesis uses
`NotRequired`. Seed recovery stores:

- phase: `InProgress`, `Complete`, or `AccountRangeExhausted`;
- current finalized height and block hash, cross-binding progress to the
  separately authenticated wallet tip against valid-old-row splicing;
- exact finalized target height, block hash, tree size, and tree root;
- ordered private account IDs and the exact scan-account-set commitment;
- gap limit and a bounded 64-bit used-account mask.

The canonical recovery codec rejects unknown versions/phases, zero or duplicate
IDs, invalid roots, out-of-range masks, invalid counts/gaps, truncation, and
trailing bytes. The row is resealed with fresh XChaCha20-Poly1305 randomness in
the same SQLite transaction as each finalized tip, note, spend, tree, and
checkpoint update.

On open, Vault authenticates both records and validates origin/tip ordering,
target monotonicity, phase/tip consistency, the exact target when present, gap
semantics, ShardTree root/position/checkpoint state, and note/mark
reconciliation. `recovery_status()` exposes an authenticated redacted phase and
explicit progress fields. `witness_for_spend` refuses to release a witness until
recovery is complete, preventing partial state from entering the signing path.
An exhausted database also refuses future block commits.

Streaming backup includes the complete encrypted state. Restore validates it
before no-clobber publication, so an interrupted recovery can be backed up,
restored, and resumed without being relabeled complete.

## 7. Required operational procedure

1. Import a checksum-valid recovery package or obtain typed seed material from
   an approved custodian. Never treat the recovery-package checksum as encryption
   or authenticity.
2. Independently authenticate a conservative birthday header and frontier.
3. Independently authenticate a recent finalized target header.
4. Choose a documented account count and trailing gap within the 64-account
   bound; derive `WalletRecoveryAccounts` and its `WalletRecoveryPlan`.
5. Create a new destination with `create_from_recovery_plan`.
6. Use the bounded coordinator and a consensus-verifying
   `FinalizedRecoverySource` to fetch every height without gaps. The coordinator
   decodes and authenticates hostile compact bytes, replays the exact tree
   transition, scans the planned accounts, and commits before requesting the
   successor. See [`WALLET_RECOVERY_SYNC_V1.md`](WALLET_RECOVERY_SYNC_V1.md).
7. Treat `InProgress` and `RequiresLargerAccountRange` as non-final. Do not show
   a definitive balance or build spends.
8. After `Complete`, verify recovered note witnesses, advance the external
   monotonic rollback floor, and create and test an authenticated backup.

## 8. Leakage and remaining gates

The origin, account IDs, activity mask, target, and progress are encrypted; the
portable backup hides them. Live SQLite still exposes schema, checkpoint row
identifiers, file growth, and access timing. Compact-block retrieval can reveal
the birthday/target interval unless padded and relayed. A full viewing key also
reveals account history if the endpoint holding it is compromised.

Still required before real funds:

- concrete approved platform/hardware custody, hardware-backed derivation,
  memory locking, crash-dump policy, and an offline recovery-package ceremony;
- concrete rollback-resistant platform guard storage, real publisher
  selection/key custody/release pinning and policy-log compaction ceremonies,
  operational rotation/revocation drills, and a
  conservative user-facing override ceremony (authenticated successor-policy
  delivery, proof-of-possession bootstrap packages with an external policy-ID
  pin, bounded Unix history, birthday/target package formats, threshold
  verification, independent-finality matching, and successor key removal are
  implemented);
- a concrete validating full-node/light-client source plus private/padded
  compact-block transport; ordinary RPC agreement is not consensus finality;
- reviewed product UX that never presents incomplete recovery as final;
- durable backup inventory, retention/deletion policy, and scheduled restore
  drill alerting (verified no-clobber export plus a complete temporary restore
  drill are implemented);
- benchmarked policy for more than 64 accounts and worst-case scan CPU/memory;
- large-history, shard-boundary, pruning, and finalized-source adversarial tests;
- crash, power-loss, disk-full, partial-write, and interrupted-recovery fault
  injection on every declared platform;
- private/padded compact retrieval and access-pattern/timing measurements;
- versioned migrations, recovery drills, corpus fuzzing, and independent
  wallet/storage review.

No real funds may use this path until these gates and the wider H1/H2 release
gates pass.
