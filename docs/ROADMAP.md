# Vault Engineering Roadmap

Dates are intentionally absent until benchmarks and staffing are known. A
milestone exits only when its tests and review requirements are satisfied.
All milestones are governed by the
[`Vault Production Engineering Standard`](PRODUCTION_STANDARD.md). Milestones
deliver production-intent components; exploratory comparisons are isolated
decision evidence and never count as deployable features.

## H0 — Economic reference model

**Goal:** freeze unambiguous accounting semantics before cryptography.

- [x] Rust workspace and executable simulator.
- [x] Immutable maximum supply at genesis.
- [x] Exact-recipient transfer semantics.
- [x] 0.5% burn with dust-safe rounding.
- [x] Gas transferred to a validator.
- [x] Note consumption and double-spend rejection.
- [x] Conservation-of-supply audit and unit tests.
- [x] Initial protocol and threat-model drafts.

**Exit criterion:** formatting, lint, and all workspace tests pass.

## H1 — Private-transfer production foundation

**Goal:** prove the H0 invariants without exposing owners or amounts.

Remaining work is classified and bounded by the
[`H1 finite closure matrix`](H1_CLOSURE_MATRIX.md). H2 consensus integration and
later milestones do not expand H1 cryptographic implementation.

- [x] Add typed note commitments, nullifiers, state anchors, and circuit IDs.
- [x] Add fail-closed proof-verifier integration and transaction domain separation.
- [x] Add pre-verification limits for proof, ciphertext, inputs, and outputs.
- [x] Define circuit statements for authorization, conservation, burn, and gas.
- [x] Add property-based accounting tests and continuous-integration gates.
- [x] Select and implement reviewed note encryption and view-key derivation
  using Ironwood V3, including canonical codec, sender recovery, local trial
  decryption, output reconstruction, and proof-statement integration.
- [x] Implement the production-intent depth-32 note-tree frontier, canonical
  roots, restorable snapshots, and native membership verification.
- [x] Implement bounded batched local trial decryption for incoming notes.
- [x] Implement randomized RedPallas spend authorization bound to Vault network
  and transaction effects, with `rk`, note ownership, and authorization bound
  by the hardened Action circuit.
- [x] Implement an accounting-only reference statement in a maintained zkVM.
- [x] Generate, verify, and benchmark one real fail-closed RISC Zero receipt.
- [x] Extend the reference statement with membership, authorization,
  nullifiers, note openings, and encryption consistency.
- [x] Specify and implement transfer-v2 actions using canonical
  `vault-privacy` commitments, value commitments, and fixed-size ciphertexts.
- [x] Migrate note encryption to Ironwood V3 and pin the hardened `PostNu6_3`
  Action verifying-key description.
- [x] Generate and negatively test a canonical real two-action Halo2 proof for
  membership, ownership, nullifier, note opening, `rho`, `rk`, and net value.
- [x] Add a canonical composite proof envelope that cannot reach the consensus
  verifier without a second accounting/burn proof verifier.
- [x] Implement the pinned 64-byte Pallas homomorphic burn ciphertext,
  canonical epoch-key descriptor, aggregation, DLEQ shares, and interpolation.
- [x] Implement and negatively test the range-constrained Halo2 arithmetic for
  dummy slots, gas, exact ceiling 0.5% burn, and conservation in every action
  bucket (kept non-activatable as a standalone component).
- [x] Bind that exact arithmetic burn cell to its Orchard value commitment and
  both Pallas threshold-ElGamal equations in one Halo2 circuit shape.
- [x] Compose the hardened Action and accounting/burn constraints so the exact
  Action `v_old`/`v_new` cells feed accounting, and constrain private zero-tax
  change to the paired consumed note's expanded receiver.
- [x] Derive the private accounting dummy marker exactly from zero linked input
  and output values; reject both non-empty dummy and empty enabled slots.
- [x] Reconstruct the activated burn scheme, key ID, epoch, ciphertext points,
  and exact `PK_epoch` coordinates from the canonical DKG descriptor used by
  validators.
- [x] Bind the complete canonical 256-bit transfer-v2 effects digest as two
  lossless 128-bit Halo2 public limbs and reject effects/output divergence in
  the production-intent prover preparation path.
- [x] Implement the bounded canonical compact-block codec, non-circular
  finalized-header commitment, complete local trial decryption, and exact
  note-tree transition replay.
- [x] Define the all-or-nothing finalized wallet-store update boundary and
  remove wallet-specific match metadata from default diagnostics/summaries.
- [x] Require full scan accounts, cover external and internal scopes, derive
  each owned note's future spend nullifier, and reject duplicate account or
  viewing capabilities before persistence.
- [x] Implement the first Unix encrypted transactional SQLite/ShardTree wallet
  database with keyed nullifier tags, atomic spend marking, authenticated open,
  current witness extraction, owned-note/mark reconciliation, and an explicit
  monotonic rollback floor.
- [x] Implement a streaming authenticated size-bucketed wallet backup with an
  encrypted identity/tip manifest, no-clobber publication, full non-empty
  ShardTree restore validation, scope binding, and rollback-floor enforcement.
- [x] Implement explicit birthday-frontier initialization bound to a finalized
  header, ShardTree reference retention, encrypted origin persistence, mandatory
  gap-free continuation, and ordinary-create bypass rejection.
- [x] Implement deterministic bounded seed-account discovery, multi-batch scans,
  exact account-set/target binding, durable resumable recovery phases, conservative
  trailing-gap completion, and fail-closed witness/range behavior.
- [x] Implement bounded finalized-recovery coordination with an explicit
  consensus-verified header source boundary, hostile compact-byte decoding,
  one-height durable commits, partial-success accounting, and exact reopen/resume.
- [ ] Finish the remaining A1 wallet-custody and recovery-operation checkpoints
  enumerated in the activation-hardening ledger below.
- [x] Implement the canonical independent output-authorization packet,
  byte-exact Ironwood reconstruction, and policy-bound local transfer-v2
  signing session.
- [x] Implement the paired Noise KK signer channel, channel-bound anti-replay
  transcript, canonical request/response codecs, and one-shot signing state.
- [x] Implement first-contact Noise XX pairing, human-verifiable transcript
  fingerprints, a canonical confirmed-peer record, and a type-level gate that
  prevents unconfirmed peers from opening KK.
- [x] Persist confirmed peers in a fixed-size authenticated encrypted registry;
  retain revocation tombstones, rotate identities atomically, and make the
  registry the only public constructor path into KK.
- [x] Implement the first crash-consistent Unix replay store with exact pending
  challenges, atomic replacement, directory sync, exclusive locking, and
  fail-closed corruption/path handling.
- [x] Separate explicit initialization from normal opening for both signer
  stores; reject duplicate initialization and fail closed on missing lifecycle
  or anti-replay state instead of silently resetting it.
- [ ] Finish the remaining A2/A3 platform privacy and signer-lifecycle
  checkpoints enumerated below.
- [ ] Complete A5 and activate a verifier only after all applicable wallet,
  platform, release, vector, benchmark, and internal security gates pass.
- [x] Benchmark at least two maintained proof-system implementations.
- [x] Define proof parameter and trusted-setup assumptions for both backends;
  both use transparent parameter generation, while reproducible artifact and
  activation evidence remains gated by the H1 closure matrix.
- [x] Publish the first deterministic envelope transcript vector.
- [x] Publish real-proof positive and negative test vectors for both backends.
- [x] Design epoch burn aggregation and low-volume privacy handling.

### H1 completion ledger

This ledger is the detailed continuation checklist. It records implemented
production-intent work separately from activation gates so completed
cryptographic scope is not reopened by later platform or H2 integration work.
The specifications, tests, evidence files, and
[`H1_CLOSURE_MATRIX.md`](H1_CLOSURE_MATRIX.md) remain authoritative.

For planning only, as of 2026-09-02, the bounded cryptographic implementation is
100% complete and H1 including activation hardening is estimated at roughly 65%.
This estimate is not derived from checkbox counts and is not a release or safety
claim. A5 remains deliberately at 0% until the applicable A1-A4 gates pass.

#### C1-C6 — cryptographic implementation: complete

- [x] **C1 — RISC Zero transfer-v2 reference.** Implement the typed statement
  for owned note openings, depth-32 membership, spend authorization,
  nullifiers, `ak + alpha`, value commitments, exact encrypted outputs,
  receiver-derived change classification, gas, conservation, ceiling burn,
  burn commitment, threshold ciphertext, and canonical effects equality.
  Native negative tests, Halo2/native differentials, Linux guest reproduction,
  and host gates pass. An H100 generated and reopened a real 311,977,650-byte
  Composite receipt in 1,329,338 ms for 1,162,870,784 cycles. Evidence:
  [`C1_RISC0_CUDA_2026-08-31.md`](evidence/C1_RISC0_CUDA_2026-08-31.md).
- [x] **C2 — Halo2 transfer circuit.** Freeze one monolithic statement for the
  padded 2/4/8/16-action buckets at transparent `k = 15`; bind Action ownership,
  note values, membership, nullifiers, dummy rules, gas, exact 0.5% ceiling
  burn, conservation, DKG epoch key, both threshold-ElGamal equations,
  ciphertexts, private change receiver, and the complete 256-bit effects
  digest. Real proofs pass for every bucket and every public-instance cell plus
  private classification/value boundaries are negatively tested. The pinned
  suite ID is
  `991523426f81b2350b1b08a7e2de9f60e334f344e40c23904c6dd8db5937c83a`.
- [x] **C3 — setup assumptions.** Specify transparent parameter generation,
  provenance, integrity identities, regeneration, rotation, activation and
  deactivation without a toxic-waste ceremony. See
  [`PROOF_SETUP.md`](architecture/PROOF_SETUP.md).
- [x] **C4 — real proof vectors.** Commit four 9,664-byte Halo2 proofs with
  canonical public instances and offline mutation verification. Publish the
  RISC Zero Composite receipt and provenance in release
  `c4-risc0-transfer-v2-v1`; the offline verifier accepts the receipt and
  rejects changed public input, proof bytes, and truncation. The Composite
  receipt exceeds the 2,097,152-byte consensus proof limit, so this evidence
  closes C4 without making RISC Zero activatable.
- [x] **C5 — hidden burn aggregation policy.** Freeze greater-than-two-thirds
  DKG thresholding, deterministic collection windows, a 256-ciphertext and
  64-block disclosure floor, indefinite low-volume carry under same-key
  resharing, verified share selection, bounded stall/recovery, and monotonic
  public supply upper-bound updates. Network DKG and consensus persistence are
  H2/A4/A5 integration, not reopened C5 work. See
  [`BURN_AGGREGATION_V1.md`](specs/BURN_AGGREGATION_V1.md).
- [x] **C6 — proof-system comparison.** Benchmark Halo2 repeatedly for every
  action bucket and two-worker 16-action concurrency on the Apple M1. Measure
  RISC Zero Composite proving on H100 and Succinct compression on RTX 5090. The
  5090 produced a verified 223,530-byte Succinct receipt in 660.343 seconds,
  with a 716.23-second complete negative-test run, 2,652 MiB peak GPU memory,
  and 2,059,940 KiB peak host RSS. Select Halo2 for the base layer and reject
  RISC Zero 3.0.6 for activation. No further comparison GPU rental is pending.
  Evidence: [`C6_PROOF_BENCHMARK_2026-08-31.md`](evidence/C6_PROOF_BENCHMARK_2026-08-31.md)
  and [`C6_RISC0_SUCCINCT_CUDA_2026-09-02.md`](evidence/C6_RISC0_SUCCINCT_CUDA_2026-09-02.md).

#### A1 — wallet custody and recovery operations: in progress

Implemented production-intent foundation:

- [x] Canonical bounded compact blocks, non-circular header commitments,
  independently finalized-header boundary, complete local trial decryption,
  exact note-tree transition replay, and gap-free finalized scanning.
- [x] Atomic opaque wallet-store updates with both external and internal scopes,
  future nullifier derivation, duplicate capability rejection, and no
  wallet-match metadata in default diagnostics.
- [x] Unix encrypted transactional SQLite/ShardTree storage with keyed
  nullifier tags, authenticated open, spend marking, witness extraction,
  note/mark reconciliation, exclusive locking, and an external monotonic-height
  floor.
- [x] Streaming authenticated 1 MiB-size-bucketed backup with encrypted scope
  and tip, no-clobber publication, full non-empty ShardTree restoration,
  rollback-floor enforcement, corruption/truncation/splicing tests, and
  owner-only Unix paths.
- [x] Birthday-frontier initialization bound to an independently finalized
  header, retained frontier references, encrypted origin, mandatory continuous
  scanning, and rejection of ordinary-create bypasses.
- [x] Deterministic recovery of up to 64 contiguous seed accounts, both key
  scopes, exact account-set and target binding, durable resumable phases,
  conservative trailing-account gap, and explicit range exhaustion.
- [x] Bounded recovery coordinator that requests only the next finalized
  height, authenticates hostile compact bytes, commits each height durably,
  reports partial success, and resumes exactly after reopening.
- [x] Typed non-clonable/redacted/zeroizing 32-byte seed material, CSPRNG
  generation, exact checksummed 72-byte offline package, mutation rejection,
  and a scoped custodian callback that does not retain spending keys.
- [x] Distinct threshold-authenticated birthday (`VCKPT001`) and recovery-target
  (`VTARG001`) packages with 1-8 Ed25519 publishers, strict canonical records,
  exact independent-finality matching, and type separation preventing a target
  from being used as a birthday frontier.
- [x] Predecessor-authenticated successor-policy packages (`VPOLY001`) that
  replace the full key set, revoke omitted publishers, bind network,
  generation, threshold, canonical keys, and exact predecessor policy ID, and
  reject mutation of every byte. The deterministic 379-byte update vector has
  BLAKE3 hash
  `687555c09469a235a1b48f08293bf318e39cb568733998d8e4599837b332a666`.
- [x] Canonical generation-1 bootstrap packages (`VBOOT001`) that bind network,
  threshold, canonical publisher keys, a nonzero ceremony nonce, and policy ID;
  require proof-of-possession signatures from every publisher; and verify
  against a separately pinned expected policy ID before policy-store creation
  or opening. The deterministic 499-byte vector has BLAKE3 hash
  `f6bc8a6b6e706d19ae2b810dc5efd8b6979a87ea6660bafc058174fd5330d317`.
- [x] Bounded crash-consistent Unix checkpoint-policy history replayed from a
  pinned bootstrap, with atomic replacement, file/directory sync, owner-only
  paths, exclusive locking, an exact generation-plus-policy-ID rollback-anchor
  interface, and rejection of valid-file rollback, same-generation
  equivocation, skipped anchored branches, corruption, and uncertain failures.
- [x] Verified backup rotation primitive: export to a fresh destination,
  restore through the complete production validation path in a protected
  temporary directory, compare height and byte sizes, clean drill artifacts,
  preserve every older copy, and retain a failed new copy for quarantine.

Remaining A1 checkpoints:

- [ ] **A1-CP1 — concrete rollback guard.** Implement and test at least one
  approved keychain/secure-element/TPM-backed `CheckpointPolicyRollbackGuard`
  that durably scopes and protects both generation and exact policy ID.
- [ ] **A1-CP2 — checkpoint bootstrap ceremony.** The canonical artifact,
  all-publisher proof of possession, external policy-ID verification, and
  policy-store enforcement are implemented. Still define and execute actual
  publisher selection, offline key custody, threshold approval, binary or
  release-manifest pinning, independent operator confirmation, and recovery
  from a lost bootstrap artifact.
- [ ] **A1-CP3 — checkpoint history compaction.** Define and test the explicit
  re-bootstrap/compaction ceremony before the 64-update bound, preserving the
  protected lineage without accepting an older or alternate branch.
- [ ] **A1-CP4 — publisher operations.** Run reproducible rotation, ordinary
  revocation, compromised-key, lost-key, unavailable-quorum, equivocation, and
  rollback drills; document alerts, emergency response, and distribution
  availability.
- [ ] **A1-CP5 — birthday override UX.** Default to a conservative birthday,
  offer genesis recovery when provenance is uncertain, warn that a later
  checkpoint can omit funds, and require explicit confirmation without ever
  presenting publisher quorum as consensus finality.
- [ ] **A1-CUSTODY — concrete seed custody.** Implement an approved platform or
  hardware custodian, authenticated unlock, memory locking where available,
  crash-dump controls, hardware-backed derivation profile, offline package
  ceremony, and loss/restore exercises.
- [ ] **A1-UX — incomplete recovery states.** Product surfaces must distinguish
  `InProgress`, `Complete`, and `RequiresLargerAccountRange`, suppress final
  balances/spending before completion, and guide safe restart or wider account
  recovery.
- [ ] **A1-BACKUP — operations.** Add durable multi-copy inventory, independent
  media/provider placement, retention and explicit deletion policy, scheduling,
  missed/failed-drill alerts, quarantine workflow, and disaster-recovery
  exercises. The verified export and restore-drill primitive is complete.
- [ ] **A1-MIGRATION — versioned wallet migrations.** Implement forward,
  downgrade-rejection, interrupted-migration, backup-before-upgrade, rollback,
  and restored-old-version tests for every persisted wallet format.
- [ ] **A1-TREE — ShardTree checkpoint lifecycle.** Measure and bound
  long-history growth; implement safe checkpoint/reference pruning and database
  compaction without deleting witness-critical birthday frontier data. This is
  separate from publisher checkpoint-package history.
- [ ] **A1-FAULTS — storage fault injection.** Test crash, power loss, disk full,
  short/partial write, sync failure, interrupted backup/restore/recovery, and
  uncertain publication boundaries on every declared platform.
- [ ] **A1-SCALE — measured recovery policy.** Benchmark worst-case CPU, memory,
  storage and duration; decide and test a reviewed path beyond the present
  64-account bound; add large-history and shard-boundary adversarial corpora.

H2 dependency, explicitly not A1 scope: the production full-node/light-client
adapter behind `FinalizedRecoverySource`, real consensus finality, snapshots,
and private network transport. A1 defines and tests the fail-closed boundary;
it must not replace H2 with trusted RPC agreement.

#### A2 — wallet privacy and platform storage: in progress

Implemented production-intent foundation:

- [x] Local scanning of complete finalized compact blocks in fixed bounded
  cryptographic batches, including both recipient and internal-change scopes.
- [x] Encrypted authenticated wallet records and keyed local indices; wallet
  identifiers, notes, recovery progress, origin, account activity, and tip are
  not exposed in default logs or remote queries.
- [x] Portable backup hides exact snapshot size and wallet/network/tip metadata;
  only a 1 MiB size bucket and ordinary filesystem/network metadata remain
  observable.
- [x] Typed external rollback-floor boundaries exist for wallet databases,
  backup restore, and checkpoint-policy history.

Remaining A2 checkpoints:

- [ ] Implement private and padded compact-block retrieval so peers/providers do
  not learn the wallet birthday, target interval, matches, or stopping point.
- [ ] Implement concrete keychain/secure-element protection for wallet database
  keys, backup keys, finalized-height floor, and checkpoint-policy anchor.
- [ ] Implement and conformance-test non-Unix platform stores with equivalent
  ownership, no-follow, locking, atomicity, durability, and rollback guarantees.
- [ ] Benchmark file growth, query/access timing, retrieval bandwidth, padding,
  endpoint correlation, and declared metadata leakage under realistic and
  adversarial histories.

#### A3 — signer lifecycle and hardware profiles: in progress

Implemented production-intent foundation:

- [x] Canonical independent output-authorization packet, byte-exact Ironwood
  output reconstruction, classification rules, and policy-bound local
  transfer-v2 signing session.
- [x] Mutually authenticated Noise KK signer channel bound to network, peer,
  channel and anti-replay transcript, with canonical bounded request/response
  codecs and one-shot signing state.
- [x] Noise XX first-contact pairing, human-verifiable transcript fingerprints,
  confirmed peer records, and a type-level gate preventing unconfirmed peers
  from entering KK.
- [x] Fixed-size authenticated encrypted peer registry with exclusive locking,
  revocation tombstones, atomic identity rotation, scope binding, and registry-
  only construction of paired KK channels.
- [x] Crash-consistent Unix replay store with durable pending challenges,
  monotonic counters, atomic replacement, directory sync, exclusive locking,
  corruption/path rejection, and explicit create-versus-open lifecycle.

Remaining A3 checkpoints:

- [ ] Complete the project-controlled adversarial review of pairing, session,
  peer registry, replay store, and their combined lifecycle; resolve every
  critical/high finding and retain regression tests.
- [ ] Implement trusted confirmation/revocation UI, active-session shutdown on
  peer revocation or identity rotation, and safe recovery from interrupted
  pairing.
- [ ] Implement secure-element rollback counters and equivalent non-Unix signer
  stores; test host-controlled rollback, clone, power-loss, and concurrent-owner
  attacks.
- [ ] Implement reviewed hardware-wallet/custodian adapters and key ceremonies
  without exporting spending authority to the online wallet.
- [ ] Specify and implement multisignature and delegated-proving profiles with
  explicit trust, privacy, availability, revocation, and recovery models.

#### A4 — release engineering: in progress

Implemented production-intent foundation:

- [x] Pin Rust/dependency/toolchain inputs, proof setup assumptions, circuit and
  suite identities, canonical transcript/vector manifests, hashes, and offline
  positive/negative verification procedures.
- [x] Publish reproducible C4 proof evidence and GPU-independent offline
  verifiers; retain exact H100/RTX 5090 receipts and provenance outside the Git
  size limit in immutable release assets.
- [x] Provide fail-closed CUDA runbooks and prebuilt architecture-specific
  runners; verify reviewed image ID and artifacts before proving. C1/C6 GPU work
  is finished and must not be rerun for ordinary development.
- [x] Persist the canonical 2,097,306-byte Halo2 parameter envelope with a
  compile-time pinned SHA-256, bounded loading, mutation tests, and three
  new-process M1 cold loads averaging 741.055 ms. Evidence:
  [`A4_HALO2_PARAMETERS_2026-09-02.md`](evidence/A4_HALO2_PARAMETERS_2026-09-02.md).
- [x] Maintain workspace formatting, tests, Clippy with warnings denied,
  rustdoc warnings denied, dependency review, deterministic vectors, and
  affected release-proof suites as project-controlled gates.

Remaining A4 checkpoints:

- [ ] Implement stable reviewed Halo2 verifying-key/proving-key serialization
  and cold loading. `halo2_proofs 0.3.5` exposes no stable API; opaque memory
  dumps are forbidden. Re-derive deterministically until a reviewed format or
  dependency upgrade is selected.
- [ ] Freeze reproducible release builds, artifact signing, provenance/SBOM,
  dependency and license policy, supported host matrix, and clean-machine
  reproduction for the selected Halo2 path.
- [ ] Freeze operational proof/key resource limits, concurrency defaults,
  timeout/cancellation behavior, observability without privacy leakage, and
  failure/degradation policy.
- [ ] Write and test versioned activation, deactivation, rollback, circuit/key
  rotation, compatibility, and migration procedures for every activatable H1
  component.

#### A5 — verifier activation decision: not started

- [ ] Re-run and archive every applicable A1-A4 acceptance suite against one
  frozen release commit and artifact set.
- [ ] Resolve all known critical/high internal findings and publish residual
  limitations; external review may supplement but is not a mandatory gate.
- [ ] Approve the exact Halo2 suite ID, circuit IDs, parameter/VK artifacts,
  proof-size/resource limits, and supported transaction buckets.
- [ ] Wire activation only through the composite fail-closed verifier path;
  verify that no single proof component, mock, fallback, or oversized backend
  can become activatable.
- [ ] Exercise activation/deactivation/rollback and incompatible-version
  rejection before changing the maturity label. Until then no verifier is
  activated and no real funds are permitted.

**Exit criterion:** reproducible proofs verify all invariants; no production or
security claim is made.

## H2 — Local devnet

**Goal:** order and finalize private transfers across independent nodes.

- Integrate a mature BFT consensus engine.
- Define mempool privacy and transaction propagation.
- Implement proof verification, state roots, snapshots, and light clients.
- Meter resources and benchmark adversarial load.
- Build CLI wallet and local multi-node orchestration.

## H3 — VaultVM developer preview

**Goal:** private programmable applications.

**Entry criterion:** the private-transfer proof, note encryption, wallet
scanning, and network-origin defenses have passed their H1/H2 review gates.
Contracts must not bypass or weaken the base privacy model.

- Rust-like contract SDK with explicit public/private types.
- Contract composition, events, upgrade declarations, and resource limits.
- Standard assets, escrow, multisignature policy, and marketplace primitives.
- Audit tooling, fuzzing, and reproducible builds.

## H4 — VaultSwap and Vault Instant

**Goal:** permissionless internal markets and external purchase routes.

- Compare private AMM and frequent batch auction simulations.
- Implement solver discovery, signed quotes, bonds, and timeout handling.
- Build and audit native BTC-to-VLT atomic swaps.
- Add one smart-contract-chain adapter only after BTC testing.
- Add paymaster-based onboarding and all-inclusive fee quotes.

## H5 — VaultStore and Vault Market

**Goal:** durable applications and commerce.

- Content addressing, erasure coding, storage proofs, and endowment simulation.
- `vault://` resolver, local gateway, and static application publishing.
- Private orders, encrypted digital delivery, escrow, and seller bonds.
- Gateway/content policy design and abuse-resistance review.

## H6 — Public testnet and mainnet readiness

- Multiple independent implementations or client diversity plan.
- Incentivized adversarial testnet.
- Publish reproducible adversarial suites and security reports for cryptography,
  consensus, wallet, and cross-chain code.
- Reproducible builds, hardware-wallet support, incident response, and bug bounty.
- Final genesis allocation, emission, legal analysis, and public risk disclosures.

Mainnet is not an exit criterion until all critical findings are resolved and
the network can operate without infrastructure controlled by a single entity.
