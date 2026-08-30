# Vault Project Handoff

**Updated:** 2026-08-30
**Current milestone:** H1 — private-transfer production foundation  
**Maturity:** production-intent, unaudited, not activated, not safe for real funds

## Start here

This file exists so development can continue safely after a ChatGPT/Codex account,
task, or session change. Do not infer project status from a prompt such as
"continue". Before changing code:

1. Read `AGENTS.md`, `docs/PRODUCTION_STANDARD.md`, `docs/ROADMAP.md`, and the
   specifications for the component being changed.
2. Inspect the complete working tree and version-control state.
3. Run `./scripts/check.sh` and record any baseline failure before editing.
4. State the exact roadmap item and maturity classification being advanced.
5. Keep the change inside that item; do not create a prototype or silently add a
   trusted, mock, fail-open, or unbounded production path.

## Product objective

Vault is intended to become a privacy-first, permissionless blockchain with a
maximum supply of 21 million VLT, exact 0.5% transfer burn, metered execution,
private programmable contracts, permissionless exchange and BTC routes, and
durable application storage. These are roadmap objectives, not current claims.
Absolute anonymity, permanence, low fees, throughput, decentralization, or safety
must not be claimed until the corresponding model, implementation, measurements,
operational evidence, and independent reviews exist.

The user explicitly rejected disposable MVPs and demo-only security. All work must
target the deployable architecture while remaining honest about incomplete gates.

## Current implementation state

The repository contains substantial production-intent H1 work, including:

- canonical transfer-v2 actions, Ironwood V3 note encryption, note commitments,
  nullifiers, Merkle membership, randomized authorization, and fixed ciphertexts;
- a real Halo2 Action proof and composed accounting/burn constraints covering
  dummy actions, gas, conservation, exact ceiling 0.5% burn, change policy, burn
  ciphertext consistency, DKG descriptor binding, and the transfer effects digest;
- a fail-closed composite proof envelope that cannot be activated with only one
  proof component;
- canonical compact blocks, finalized-header authentication, local trial
  decryption, note-tree replay, encrypted transactional wallet storage, backups,
  birthday-frontier recovery, deterministic seed account discovery, and bounded
  restart-safe recovery coordination;
- output authorization, Noise XX pairing and KK signer transport, an encrypted
  peer registry, and crash-consistent Unix replay protection.

The latest completed block is the bounded wallet recovery coordinator in
`crates/vault-wallet/src/recovery.rs`, specified by
`docs/specs/WALLET_RECOVERY_SYNC_V1.md`. It authenticates hostile compact-block
bytes against an explicitly consensus-verified header-source boundary and commits
one height at a time. The production full-node/light-client adapter does not yet
exist.

The current cryptographic blocks are C1 and C2 in
`docs/H1_CLOSURE_MATRIX.md`. The isolated RISC Zero core has a versioned
transfer-v2 statement that reconstructs canonical effects, owned input-note
openings, Merkle membership, public nullifiers, `ak + alpha`, net-value
commitments, exact encrypted outputs, receiver-derived classification, gas,
conservation, ceiling burn, its commitment, and its threshold-ElGamal
ciphertext. Linux guest compilation, host tests, strict Clippy/rustdoc, positive
and burn-evasion differentials, and repeated image-ID reproduction passed. The
reviewed transfer-v2 image ID is
`cb95069bf50d37a3e6a9f0fd1519a5676d634c28c6f5a59a335511427cadd032`.
A real local CPU receipt run was interrupted after roughly five hours and
produced no receipt artifact; remote proving is unavailable. C1 therefore
remains open only on real-receipt evidence.

C2 is complete at the implementation-evidence boundary. The monolithic Halo2
2/4/8/16-action shapes use deterministic transparent parameters at `k = 15`
and suite ID
`991523426f81b2350b1b08a7e2de9f60e334f344e40c23904c6dd8db5937c83a`.
Real release proofs for every bucket passed on the Ryzen host, as did mutation
of every two-action public-instance cell and the private classification/value
negative matrix. This does not close C4 vectors, C6 comparative benchmarks, C7
review, or verifier activation.

The Halo2 half of C4 is now committed under
`zk/halo2/core/tests/vectors`: four 9,664-byte real proofs, canonical public
instances, a SHA-256/toolchain manifest, deterministic reproduction, and an
offline verifier that rejects a changed proof byte and every public-instance
cell mutation. C4 remains in progress because the RISC Zero vector depends on
the missing C1 real receipt.

The last fully reported gates passed 119 workspace tests, formatting, Clippy with
warnings denied, and rustdoc. Release-sensitive crate testing reported 74 tests.
The dependency audit saw 171 dependencies, no known vulnerability, and one allowed
inactive unmaintained `atomic-polyfill 1.0.3` warning. Re-run the gates rather than
assuming these numbers remain current.

## H1 scope correction

Earlier development mixed three different meanings of "finish H1": cryptographic
implementation, activation hardening, and mainnet eligibility. This caused broad
roadmap items to be decomposed only after prior work was reported complete. Do not
continue that pattern.

- **H1 cryptographic implementation** closes when reproducible proofs and vectors
  verify all H0 private-transfer invariants under the selected construction.
- **H1 activation hardening** includes wallet/key custody, private retrieval,
  platform adapters, operational fault testing, benchmarks, and independent
  review. These gates can block activation without making the cryptographic scope
  infinite.
- **H2 integration** owns real consensus, finality, nodes, snapshots, and light
  clients. A concrete recovery source backed by those mechanisms cannot be closed
  independently inside H1; H1 defines and tests its fail-closed boundary.
- **H3 contracts** remain blocked until the private-transfer, wallet-scanning, and
  network-origin entry gates stated in the roadmap are satisfied. Contract work
  must never weaken base-layer privacy.

Before further implementation, reconcile the unchecked H1 roadmap entries into a
finite closure matrix using those four classifications. In particular, resolve the
remaining reference-statement constraints, trusted-setup assumptions if any,
real-proof positive and negative vectors, burn aggregation/low-volume privacy, and
review/benchmark gates without treating later consensus integration as new H1
cryptographic scope.

## Non-negotiable handoff rules

- Do not describe Vault, H1, or any component as production-ready merely because
  its implementation or tests exist. Use the maturity labels in the production
  standard.
- Do not use real funds.
- Do not start contracts merely because a wallet subtask finished.
- Do not claim "100% anonymous". State separately what is cryptographically hidden
  and what network, endpoint, timing, recovery, or side-channel metadata remains.
- Do not replace real proof verification, consensus, custody, BTC interoperability,
  or durable storage with a mock or centralized shortcut.
- Preserve existing worktree changes. No commit existed when this handoff was
  written, so all repository files were untracked and especially vulnerable to
  accidental loss.

## Suggested first prompt in a new account

> Open `/Users/tomascorzo/vault`. Read `AGENTS.md` and every document it requires.
> Inspect the entire working tree and run the baseline gates. Summarize the current
> H1 implementation, its honest maturity, and the finite remaining H1 closure
> matrix before editing. Then continue only the next cryptographic H1 item from
> that matrix. Do not create prototypes, expand H1 with H2/mainnet work, start
> contracts, use real funds, or claim production readiness.
