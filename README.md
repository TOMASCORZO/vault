# Vault

Vault is a production-intent, privacy-first blockchain project for programmable
money, private smart contracts, permissionless exchange, and durable
applications. New work is governed by the
[`Vault Production Engineering Standard`](docs/PRODUCTION_STANDARD.md): no
disposable MVPs or simplified security paths are accepted as deliverables.

> **Current status: pre-mainnet H1 foundation with legacy research
> components.** This repository is not a live blockchain, does not yet provide
> end-to-end transaction privacy and must not be used with real funds.

Production intent describes the engineering target, not the current maturity.
Every component must earn release-candidate and mainnet-eligible status through
specification, adversarial testing, realistic benchmarks, reproducible builds,
public security reports, and resolution of known critical findings.

## What exists today

- A versioned protocol direction in [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md).
- An explicit threat model in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
- A milestone roadmap in [`docs/ROADMAP.md`](docs/ROADMAP.md).
- A deterministic Rust reference model for:
  - fixed maximum supply;
  - a 0.5% transfer burn paid in addition to the recipient amount;
  - gas paid to a validator rather than burned;
  - note consumption and double-spend rejection;
  - conservation-of-supply auditing.
- A fail-closed H1 protocol boundary for:
  - chain and circuit domain separation;
  - recent state anchors, note commitments, and nullifiers;
  - cross-chain replay and double-spend rejection;
  - proof, ciphertext, input, and output resource limits;
  - injection of a production proof verifier without compiling a mock verifier.
- A production-intent privacy foundation that:
  - derives Vault keys separately by network and account;
  - creates diversified external and internal addresses;
  - separates spending, full, incoming, and outgoing viewing capabilities;
  - constructs binding note and value commitments plus deterministic nullifiers;
  - signs each spend under a fresh randomized RedPallas validating key;
  - encrypts fixed-size authenticated notes and supports sender recovery;
  - maintains a canonical depth-32 commitment-tree frontier and membership paths;
  - batch-scans incoming notes locally under bounded resource limits;
  - rejects malformed keys, commitments, nullifiers, and ephemeral keys.
- A production-intent transfer-v2 boundary that:
  - pairs spends and fixed-size Orchard outputs in padded 2/4/8/16-action bundles;
  - canonically parses nullifiers, value commitments, note fields, and randomized keys;
  - binds every effect to the proof digest and one RedPallas signature per action;
  - rejects truncation, trailing bytes, alternate ordering, duplicate keys, and oversized input;
  - atomically derives the post-transfer note-tree root after fail-closed verification;
  - pins hidden-burn payloads to a scheme, threshold key, and epoch.
- A canonical private output-authorization path that:
  - encodes a fixed 1,455-byte signer packet, never intended for consensus or broadcast;
  - independently reconstructs the Ironwood note, commitments, ephemeral key,
    recipient ciphertext, and sender-recovery ciphertext from trusted intent;
  - recognizes only non-zero external payment, non-zero signer-owned internal
    change, or zero signer-owned dummy classifications;
  - opens a transfer-v2 signing session only after exact chain, circuit, burn
    scheme/key/epoch, action bucket, gas, fee ceilings, and every sorted output
    token match;
  - rejects substituted/reordered outputs, wrong spending accounts, wrong
    randomized keys, and altered policy fields before releasing a signature.
- A production-intent paired signer transport that:
  - performs first contact with pinned `Noise_XX_25519_ChaChaPoly_BLAKE2s`,
    a transcript-derived 128-bit fingerprint, explicit OOB confirmation, and a
    canonical peer record that cannot open a channel while unconfirmed;
  - stores confirmed records in a constant-size XChaCha20-Poly1305 registry,
    retains permanent revocation tombstones, rotates to fresh confirmed
    identities atomically, exposes KK construction only for active peers, and
    never auto-recreates missing lifecycle state during normal startup;
  - uses pinned `Noise_KK_25519_ChaChaPoly_BLAKE2s` for pre-paired identities
    separated from all VLT keys;
  - binds a signer-generated challenge and durable monotonic counter to the
    Noise handshake hash, exact policy, effects, and ordered private packets;
  - carries canonical bounded request/response codecs for all 2/4/8/16 buckets;
  - poisons the connection on authentication, replay, ordering, or codec
    failure and releases no partial or duplicate action signature;
  - durably reserves and consumes exact challenges in an exclusive,
    crash-consistent, corruption-detecting Unix store before signing, with
    separate create/open operations that forbid a silent counter reset;
  - still requires independent pairing/store review, rollback-resistant
    hardware and non-Unix profiles, keychain/hardware integrations, active
    session shutdown, and trusted confirmation/revocation UX before activation.
- A production-intent finalized wallet scanning boundary that:
  - defines a bounded canonical compact block carrying every full encrypted
    output and public nullifier, without wallet-specific server queries;
  - authenticates a non-circular compact commitment against caller-verified
    finalized header fields before scanning;
  - independently replays the exact note-tree transition and trial-decrypts
    every output locally in bounded batches;
  - scans external recipients and internal change from full viewing accounts,
    and derives the exact future nullifier needed to recognize a later spend;
  - emits an opaque all-or-nothing store delta and redacts note-match metadata
    from default diagnostics and success summaries;
  - commits to an encrypted transactional SQLite/ShardTree database with keyed
    nullifier tags, authenticated reopen, current witness extraction,
    owned-row reconciliation, and an explicit rollback floor;
  - exports a size-bucketed authenticated backup whose wallet identity, exact
    size, policy, and tip remain encrypted, and restores non-empty witness state
    only after complete database validation without overwriting a destination;
  - initializes recovery only from a finalized-header-bound birthday frontier,
    retains its witness-critical nodes, persists the origin encrypted, and
    rejects non-genesis starts through the ordinary creation API;
  - derives up to 64 contiguous seed accounts without retaining spending keys,
    scans them in bounded primitive batches, commits every block to the exact
    account set, and persists an authenticated incomplete/complete/range-exhausted
    recovery phase against an exact finalized target and trailing account gap;
  - advances recovery from the durable tip through a bounded coordinator that
    accepts only externally verified finalized headers, decodes hostile compact
    bytes under an explicit read bound, commits one height at a time, reports
    partial success, and resumes exactly after reopen;
  - still requires a concrete validating full-node/light-client adapter,
    approved seed custody, trusted checkpoint distribution, migrations, backup
    operations and drills, secure key/counter
    storage, fault injection, private retrieval, growth/side-channel benchmarks,
    and review.
- An isolated RISC Zero 3.0.6 research backend that:
  - generated and verified a real accounting proof with development mode disabled;
  - recomputes the complete consensus public-input transcript inside the guest;
  - proves checked conservation, exact 0.5% burn, and gas funding over hidden values;
  - feeds its receipt through the normal fail-closed `ShieldedState` adapter;
  - records reproducible proof size, cycle count, and CPU latency.
- An isolated production-candidate Halo2 backend that:
  - uses Ironwood V3 and the pinned hardened `PostNu6_3` Action circuit;
  - generated a real 7,264-byte two-action proof for membership, ownership,
    nullifiers, note openings, `rho`, `rk`, and net value;
  - constrains 64-bit amounts, dummy slots, public gas, exact ceiling 0.5% burn,
    and conservation for padded 2/4/8/16-action buckets;
  - passes the exact arithmetic burn cell into its value commitment and both
    threshold-ElGamal ciphertext equations;
  - generated and verified a real 5,504-byte proof of the current combined
    accounting/burn shape;
  - composes the hardened Action, accounting, and burn equations in one
    monolithic circuit using the exact Action `v_old`/`v_new` cells;
  - privately permits zero-tax change only when all four expanded-receiver
    coordinates equal those of the paired consumed note;
  - generated and verified a real 9,504-byte proof of that first monolithic
    shape and rejects both cross-statement value substitution and external
    outputs falsely labelled as change;
  - derives the private dummy marker from zero linked input/output values;
  - reconstructs `scheme_id`, `key_id`, epoch, burn points, and the exact
    `PK_epoch` coordinates from the activated DKG descriptor;
  - binds the complete 256-bit canonical effects digest as two lossless public
    limbs, so chain, circuit, all ciphertexts, gas, and action bytes are part of
    the monolithic proof statement;
  - rejects prover preparation when the encrypted output differs from the one
    constructed with the private note;
  - generated and verified a real 9,600-byte proof of the resulting shape;
  - remains fail-closed and non-activatable until signer transport/UX profiles,
    all-bucket vectors, benchmarks, and internal security gates are complete.

The transparent reference model validates accounting rules before those rules
are moved into zero-knowledge circuits. Its numeric note identifiers and clear
amounts are intentionally not production cryptography.

## Run it

Rust 1.85.1 or newer is required.

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p vault-sim -- 1000
```

The experimental zkVM workspace has an independent Rust 1.90 MSRV and requires
the pinned RISC Zero guest Rust 1.97.0. Its slower quality and real-proof
commands are:

```bash
./scripts/check-zk-risc0.sh
./scripts/prove-zk-risc0.sh
```

The optional simulator argument is a whole-number VLT transfer. The example
starts with a 1,000,000 VLT genesis note and transfers 1,000 VLT.

## Repository layout

```text
crates/vault-core   Economic state-machine reference
crates/vault-burn  Threshold homomorphic burn encryption and decryption shares
crates/vault-privacy  Production-intent Orchard keys and encrypted notes
crates/vault-protocol  H1 shielded transaction and verifier boundary
crates/vault-signer  Paired Noise transport and channel-bound signing sessions
crates/vault-wallet  Finalized scanning and encrypted transactional witness store
crates/vault-sim   Small executable scenario
docs/               Protocol, risks, and roadmap
zk/halo2/          Isolated specialized Action and accounting/burn backend
zk/risc0/           Isolated real-proof accounting research backend
```

## Immediate next milestone

H1 now has a real monolithic proof in which the Action note values directly
feed accounting and a privately exempt output must be exact paired-address
change, dummy state is derived from linked values, the activated epoch DKG
descriptor selects the exact burn key, and all canonical effects are bound by
a lossless 256-bit digest instance. The independent local signer path now
reconstructs every output byte and refuses signatures unless the complete
transfer matches an exact policy. A confirmed XX-to-KK Noise lifecycle and
canonical anti-replay request/response session now carry that flow. The Unix
signer path durably reserves the exact challenge before exposure and consumes
it before signing. Confirmed peer state is encrypted at rest and retains
revocation/rotation history. Finalized compact blocks now have a canonical
header commitment, exact tree replay, complete local trial-decryption path, and
a first encrypted transactional ShardTree database that maintains current spend
witnesses and fails closed on key/scope/tip/owned-row inconsistencies. Its V1
backup container now hides persistent wallet metadata, authenticates every
size-bucketed chunk, restores a non-empty wallet and refuses overwrite. Explicit
birthday recovery now binds a canonical frontier to a finalized header, retains
the imported ommers as ShardTree references, and persists its origin encrypted.
Deterministic recovery now derives a bounded contiguous account range, scans all
accounts through an exact finalized target, rejects the wrong key set per block,
persists restart-safe progress, blocks witnesses while incomplete, and refuses
to claim completeness when the trailing account gap is exhausted. A bounded
coordinator now retrieves each next height through an explicit consensus-finality
source boundary, treats compact bytes as hostile, commits every height before
requesting its successor, records partial success, and resumes from authenticated
state after reopen. A real validating full-node/light-client adapter is still
blocked on the unfinished consensus layer; RPC agreement is explicitly not
treated as finality. The next wallet blocks are approved seed custody, private
and padded retrieval, migration, pruning/compaction, secure key and rollback-counter integration,
crash/power-loss fault injection, restore drills, and
access-pattern/timing measurements. Adversarial signer testing,
keychain-backed trusted pairing/payment/revocation UX, active-session shutdown,
secure-element rollback protection, hardware/multisignature/delegated-prover
adapters, and fixed vectors plus performance coverage remain mandatory.
No suite ID or consensus verifier is issued until those gates, benchmarks, and
internal security reviews are complete. Threshold DKG lifecycle, bounded aggregate
recovery, network privacy, complete wallet recovery, and durable-state operations
also remain required. See [`OUTPUT_AUTHORIZATION_V1.md`](docs/specs/OUTPUT_AUTHORIZATION_V1.md).
Signer transport details: [`SIGNER_TRANSPORT_V1.md`](docs/specs/SIGNER_TRANSPORT_V1.md).
Wallet scanning details: [`COMPACT_BLOCK_V1.md`](docs/specs/COMPACT_BLOCK_V1.md).
Wallet database details: [`WALLET_DB_V1.md`](docs/specs/WALLET_DB_V1.md).
Wallet backup details: [`WALLET_BACKUP_V1.md`](docs/specs/WALLET_BACKUP_V1.md).
Wallet birthday recovery: [`WALLET_RECOVERY_V1.md`](docs/specs/WALLET_RECOVERY_V1.md).
Wallet recovery synchronization:
[`WALLET_RECOVERY_SYNC_V1.md`](docs/specs/WALLET_RECOVERY_SYNC_V1.md).

Run the same quality gate used by CI with `./scripts/check.sh`.
After installing `cargo-audit`, scan the exact lockfile with
`./scripts/audit.sh`.

Spanish project summary: [`docs/RESUMEN_ES.md`](docs/RESUMEN_ES.md).
Measured ZK report:
[`docs/research/RISC0-ACCOUNTING-V1.md`](docs/research/RISC0-ACCOUNTING-V1.md).
Known ZK dependency blockers:
[`docs/audits/zk-risc0-dependency-audit-2026-08-21.md`](docs/audits/zk-risc0-dependency-audit-2026-08-21.md).
Halo2 dependency audit:
[`docs/audits/zk-halo2-dependency-audit-2026-08-22.md`](docs/audits/zk-halo2-dependency-audit-2026-08-22.md).
Privacy architecture and remaining anonymity surfaces:
[`docs/architecture/PRIVACY.md`](docs/architecture/PRIVACY.md).
