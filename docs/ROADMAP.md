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
  (production-intent crate; proof and codec integration remain blocked).
- [x] Implement the production-intent depth-32 note-tree frontier, canonical
  roots, restorable snapshots, and native membership verification.
- [x] Implement bounded batched local trial decryption for incoming notes.
- [x] Implement randomized RedPallas spend authorization bound to Vault network
  and transaction effects (circuit ownership binding remains pending).
- [x] Implement an accounting-only reference statement in a maintained zkVM.
- [x] Generate, verify, and benchmark one real fail-closed RISC Zero receipt.
- [ ] Extend the reference statement with membership, authorization,
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
- [ ] Complete approved seed custody/import, trusted birthday and target
  checkpoint distribution (the real validating full-node/light-client adapter
  is H2 and consumes the fail-closed H1 boundary),
  private/padded retrieval, product incomplete-recovery UX, backup rotation and restore drills,
  versioned migrations, checkpoint pruning/compaction and long-history growth,
  keychain/secure-element key plus rollback state, multi-platform stores,
  crash/power-loss/disk-full fault injection, private block retrieval, and
  privacy-side-channel benchmarks.
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
- [ ] Adversarially review and test pairing and both Unix stores; implement keychain and
  trusted confirmation/revocation UX adapters, active-session shutdown,
  secure-element rollback counters, other platform stores, hardware adapters,
  multisignature, and delegated-proving profiles.
- [ ] Activate a verifier only after all proof, wallet, vector, benchmark, and
  internal security gates pass.
- [ ] Benchmark at least two maintained proof-system implementations.
- [x] Define proof parameter and trusted-setup assumptions for both backends;
  both use transparent parameter generation, while reproducible artifact and
  activation evidence remains gated by the H1 closure matrix.
- [x] Publish the first deterministic envelope transcript vector.
- [ ] Publish real-proof positive and negative test vectors for both backends.
- Design epoch burn aggregation and low-volume privacy handling.

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
