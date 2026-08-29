# Vault wallet seed and birthday recovery v1

**Status:** production-intent deterministic account discovery, finalized target,
durable progress, and birthday-frontier initialization implemented; custody,
checkpoint distribution, operational UX, fault injection, and independent review
remain activation gates  
**Last updated:** 2026-08-27

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

The implementation accepts seed bytes transiently but never stores them. Each
derived spending key is converted immediately to a full viewing key and dropped;
the recovery account container retains only viewing capabilities, which cannot
authorize spends and are zeroized by their underlying types on drop. Approved
seed entry, hardware custody, memory-locking, and crash-dump controls remain
separate gates.

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

## 3. Deterministic account discovery

`WalletRecoveryAccounts::derive(seed, chain_id, account_count)` derives the
contiguous account range `0..account_count` using the network-separated
`VaultSpendingKey` derivation. Within an account, one full viewing key covers all
diversified external recipient addresses and the internal change scope, so
address indices do not use a separate gap rule.

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

`WalletRecoveryStatus::product_state()` is the mandatory fail-closed product
mapping. `Scanning` forbids a final balance and spending.
`RestartWithLargerAccountRange` supplies the minimum contiguous account count
that can satisfy the observed highest account plus the configured trailing gap.
If that minimum exceeds 64, `UnsupportedAccountRange` stops instead of
proposing a futile rescan. Only `Ready` passes the recovery gate, and even then
current finalized synchronization remains a separate H2 requirement.

Streaming backup includes the complete encrypted state. Restore validates it
before no-clobber publication, so an interrupted recovery can be backed up,
restored, and resumed without being relabeled complete.

## 7. Required operational procedure

1. Obtain seed material through an approved custody ceremony.
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
   rollback anchor through the two-phase custody protocol in
   [`WALLET_CUSTODY_V1.md`](WALLET_CUSTODY_V1.md), and create and test an
   authenticated backup.

### 7.1 Checkpoint provenance and product ceremony

The birthday frontier and target header are accepted only after a configured
trust path has established their consensus/finality provenance. Multiple
ordinary RPC responses are availability/cross-check evidence, not finality.
The product must display network identity, checkpoint/target heights, the
source class (local validating node, reviewed light client, or authenticated
offline checkpoint package), and whether the birthday was conservative or
manually overridden. A manual birthday override requires an explicit warning
that omitted earlier outputs cannot be discovered from the resulting database
and must always offer genesis recovery.

An offline package must be versioned, network/genesis-bound, integrity-
authenticated by the deployment trust root, and contain the exact finalized
birthday header/frontier plus target header used to build
`WalletRecoveryPlan`. Its parser must reproduce the existing typed header,
frontier, and plan validation; it cannot create a weaker constructor. Selecting
the deployment trust root, signing/revocation format, consensus validation that
produces the package, and network distribution remain outside this local H1
interface and must be completed with H2/release governance.

## 8. Leakage and remaining gates

The origin, account IDs, activity mask, target, and progress are encrypted; the
portable backup hides them. Live SQLite still exposes schema, checkpoint row
identifiers, file growth, and access timing. Compact-block retrieval can reveal
the birthday/target interval unless padded and relayed. A full viewing key also
reveals account history if the endpoint holding it is compromised.

Still required before real funds:

- approved seed import/custody, hardware-backed derivation, memory locking, and
  crash-dump policy;
- trusted birthday/target distribution with multi-source verification and a
  conservative user-facing override ceremony;
- a concrete validating full-node/light-client source plus private/padded
  compact-block transport; ordinary RPC agreement is not consensus finality;
- platform review of the typed product UX and conservative override ceremony;
- benchmarked policy for more than 64 accounts and worst-case scan CPU/memory;
- large-history, shard-boundary, pruning, and finalized-source adversarial tests;
- crash, power-loss, disk-full, partial-write, and interrupted-recovery fault
  injection on every declared platform;
- private/padded compact retrieval and access-pattern/timing measurements;
- future versioned migrations, scheduled recovery drills, corpus fuzzing, and independent
  wallet/storage review.

No real funds may use this path until these gates and the wider H1/H2 release
gates pass.
