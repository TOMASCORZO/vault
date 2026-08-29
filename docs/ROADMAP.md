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

The remaining scope is frozen and classified in
[`H1_CLOSURE_MATRIX.md`](H1_CLOSURE_MATRIX.md). The cryptographic implementation
items H1-C1 through H1-C4 are distinct from activation hardening, H2
consensus/network integration, and later mainnet eligibility. Unchecked umbrella
entries below are governed by that matrix and do not authorize work outside it.

- [x] Add typed note commitments, nullifiers, state anchors, and circuit IDs.
- [x] Add fail-closed proof-verifier integration and transaction domain separation.
- [x] Add pre-verification limits for proof, ciphertext, inputs, and outputs.
- [x] Define circuit statements for authorization, conservation, burn, and gas.
- [x] Add property-based accounting tests and continuous-integration gates.
- [x] Select and implement reviewed note encryption and view-key derivation
  (production-intent crate; proof and codec integration remain blocked).
- [x] Implement the production-intent depth-32 note-tree frontier, canonical
  roots, restorable snapshots, and native membership verification.
- [x] Implement bounded batched local trial decryption for incoming notes.
- [x] Implement randomized RedPallas spend authorization bound to Vault network
  and transaction effects (circuit ownership binding remains pending).
- [x] Implement an accounting-only reference statement in a maintained zkVM.
- [x] Generate, verify, and benchmark one real fail-closed RISC Zero receipt.
- [x] **H1-C1:** Extend the transfer-v2 reference statement with membership,
  ownership/authorization, nullifiers, note and commitment openings, encryption
  consistency, exact accounting/burn, and descriptor-bound burn encryption.
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
- [ ] **H1-A2 / H2:** Complete approved seed custody/import, trusted birthday and target
  checkpoint distribution, a real validating full-node/light-client adapter,
  private/padded retrieval, product incomplete-recovery UX, backup rotation and restore drills,
  versioned migrations, checkpoint pruning/compaction and long-history growth,
  keychain/secure-element key plus rollback state, multi-platform stores,
  crash/power-loss/disk-full fault injection, private block retrieval, and
  privacy-side-channel benchmarks.
  The H1-A2/H2 boundary and finite local evidence are tracked in
  [`research/H1-A2-WALLET-HARDENING.md`](research/H1-A2-WALLET-HARDENING.md).
  The real schema-1 to schema-2 wallet migration is now backup-first, atomic,
  non-downgrading, interruption-tested, and supported during authenticated
  legacy-backup restore. Backup receipts, copy verification, a no-deletion
  rotation profile, and exact-path restore drills are now defined and tested.
  Immutable bounded checkpoint retention and fully revalidated compaction are
  now implemented. Bounded long-history/owned-note/migration runners, a
  journal-observed process-crash controller, a guarded Linux ENOSPC campaign,
  and paired Linux `perf` leakage profiles are ready; their small local smoke
  checks do not replace external execution. The fail-closed recovery product
  mapping and exact-anchor secure CAS rollback protocol are now implemented and
  tested; real keychain/secure-element adapters remain platform gates. The
  approved English BIP-39 generation/import boundary, explicit passphrase,
  official vector, redaction, and zeroization are now implemented. Local H1-A2
  interfaces/harnesses are complete; external/platform execution and review
  remain open while local work proceeds to H1-A3. Real finalized
  node/light-client sources and private
  compact-block transport remain H2.
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
- [ ] **H1-A3:** Independently review pairing and both Unix stores; implement keychain and
  trusted confirmation/revocation UX adapters, active-session shutdown,
  secure-element rollback counters, other platform stores, hardware adapters,
  multisignature, and delegated-proving profiles.
  Registry-issued handshakes and transports now share a peer lifecycle gate:
  revocation and rotation shut down the old active sessions, and uncertain
  registry persistence shuts down every session before the poisoned handle can
  be reused. Pairing, transfer preparation, revocation and rotation now also
  require explicit trusted confirmation traits with no permissive default or
  raw public bypass. Canonical protected-identity and secure replay-state
  records now also have no-clobber/open separation and enforced atomic CAS
  wrappers; the ordinary Unix replay file remains explicitly non-rollback-
  resistant. These close only the local active-session, product-boundary and
  platform-contract items. The multisignature profile now also freezes the
  exact-threshold roster, per-action agreement, one-use nonce/abort rules and
  final standard-signature session gate without enabling the audit-blocked
  FROST feature. Concrete FROST/platform adapters and UX remain external
  evidence. The delegated-proving profile now also freezes per-job exact
  authorization, unavoidable complete-witness and account full-viewing
  disclosure, rollback-resistant lifecycle/revocation and mandatory local proof
  verification without activating a transport or granting spending authority.
  Its bounded VDPW/VDPR/VDPS codecs and complete deterministic 2/4/8/16 signer,
  ciphertext, multisig-agreement and proving corpus now reproduce byte-for-byte;
  pinned local fuzz and latency/memory runners are ready. Dedicated remote
  transport/store, suite adapters, reviewed FROST, platform/device evidence,
  sustained target campaigns and endpoint review remain open. The exhausted
  finite local sequence and external evidence split are tracked in
  [`research/H1-A3-SIGNER-HARDENING.md`](research/H1-A3-SIGNER-HARDENING.md).
- [ ] **H1-A4:** Activate a verifier only after all proof, wallet, vector, benchmark, and
  independent-review gates pass.
- [ ] **H1-A1:** Benchmark the selected Halo2 implementation and retain the
  terminated RISC Zero proving attempt as comparative evidence, not an
  activation gate. Opt-in local all-bucket verification/RSS tooling, one
  repeated 2-Action proving measurement plus one 4/8/16 sample, same-builder
  byte reproduction, malformed-envelope corpus, deactivation-boundary exercise,
  and a fresh dependency scan are recorded in
  [`research/H1-A1-PROOF-ENGINEERING.md`](research/H1-A1-PROOF-ENGINEERING.md).
  A one-time in-memory PK/VK reconstruction design is now selected and rejects
  parameter or pinned-VK fingerprint mismatches without inventing an upstream
  key format. A pinned AddressSanitizer/libFuzzer harness now covers raw and
  structured composite-envelope decoding; its five-minute local smoke run was
  clean but is not sustained acceptance evidence. A pinned three-lockfile
  RustSec gate now denies all findings except the exact inactive
  `RUSTSEC-2023-0089` warning and fails if its package becomes active.
  Target-hardware/all-bucket proving, sustained fuzzing, two isolated clean
  same-host builds, and full-bound burn recovery remain open, so H1-A1 is not
  complete.
  Current burn-table scaling projects about
  11.94 GB RSS at the full bound and rejects the local 8 GiB host for that gate;
  no alternative algorithm or lower bound was adopted. A canonical
  4,637,240,716-byte full-bound cache format now persists only the policy-bound
  baby-step sequence and rebuilds the same `HashMap`; bounded restart reached
  1.405 s at 4,194,304 steps, while the full digest and resource acceptance
  remain external. Two clean local Halo2 target trees now reproduce identical
  `rlib` and setup-manifest binaries, but
  repeatability on the declared owned acceptance host remains open; the
  project explicitly accepts that this is not independent reproduction.
  All external acceptance work is accumulated in
  [`research/H1-EXTERNAL-ACCEPTANCE-CAMPAIGN.md`](research/H1-EXTERNAL-ACCEPTANCE-CAMPAIGN.md)
  for one coordinated run on the declared owned acceptance host after every
  local runner is ready.
  A deterministic mixed-bucket validator runner now covers declared common,
  balanced, and maximum-heavy 2/4/8/16 profiles; its local smoke result is not
  target-hardware acceptance.
- [x] **H1-C2:** Define and reproduce proof-system setup and lifecycle
  assumptions, including transparent parameters, all-bucket candidate VK
  fingerprints, upgrade/deactivation rules, the non-selected RISC Zero role,
  and separate DKG trust.
- [x] Publish the first deterministic envelope transcript vector.
- [x] **H1-C3:** Publish fixed real-proof positive and mutation vectors for the
  selected Halo2 2/4/8/16-Action transfer shapes. RISC Zero remains a
  non-consensus reference and its receipt is not a gate.
- [x] **H1-C4:** Freeze epoch burn aggregation and low-volume privacy handling.
- [ ] **H1-A4:** Commission an external cryptography design review.

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
- Independent audits of cryptography, consensus, wallet, and cross-chain code.
- Reproducible builds, hardware-wallet support, incident response, and bug bounty.
- Final genesis allocation, emission, legal analysis, and public risk disclosures.

Mainnet is not an exit criterion until all critical findings are resolved and
the network can operate without infrastructure controlled by a single entity.
