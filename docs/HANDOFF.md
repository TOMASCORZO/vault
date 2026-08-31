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

### Repository continuation point

The authoritative continuation branch is `codex/c1-transfer-v2` on
`https://github.com/TOMASCORZO/vault`. Its latest published commits are:

```text
f285eaa Publish Halo2 transfer proof vectors
f92df9b Freeze all Halo2 transfer buckets
5bed963 Enable remote C1 proving with Bonsai
c825bf6 Advance H1 cryptography and storage hardening
```

On another machine or account, fetch and switch to that branch before making
changes:

```bash
git fetch origin
git switch codex/c1-transfer-v2
git pull --ff-only
```

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
and burn-evasion differentials, and repeated WSL image-ID reproduction passed.
The external CUDA build subsequently exposed absolute source paths in RISC Zero
3.0.6 guest panic metadata, so the canonical `/workspace/vault` evidence build
is pinned to reviewed transfer-v2 image ID
`85170f11445f10ba9b26e4ca96f29600fe4e30410081905f519a99449dd2d128`.
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

The latest Halo2 gate on the Windows Ryzen host passed formatting, workspace
check, Clippy with warnings denied, rustdoc, 22 release library tests, and two
real-proof integration tests. This includes real 2/4/8/16-action proofs, the
fixed suite-ID reproduction, the committed-vector offline verifier, every
public-instance mutation, accounting/burn proof verification, and the hardened
Action proof. The Linux RISC Zero gate separately passed ten core tests, three
host tests, guest compilation, Clippy, rustdoc, image-ID reproduction, and the
native/Halo2 differentials. The prior root baseline passed 119 workspace tests.
Re-run the gate affected by a change rather than assuming these counts remain
current.

## Device transition: Ryzen to Apple M1

Development can continue on the M1. The stronger Ryzen device has completed the
heavy evidence needed for the current implementation step:

- real Halo2 proofs for every 2/4/8/16-action bucket at `k = 15`;
- all-bucket deterministic VK/suite-ID reproduction;
- generation and offline positive/negative verification of all committed
  Halo2 C4 vectors;
- Linux compilation and repeated image-ID reproduction for the RISC Zero
  transfer-v2 guest;
- the full affected formatting, check, Clippy, rustdoc, native, differential,
  and release-test gates.

No additional test on this Ryzen machine blocks continued implementation on the
M1. Work that is safe and useful on the M1 includes C5's normative burn
aggregation/low-volume design, C4/C6 tooling and documentation, ordinary Rust
tests, and the applicable A1-A4 hardening tasks.

Two heavy evidence items are still genuinely open, but neither should be
silently replaced or repeatedly started during normal M1 development:

1. C1/C4 need one real RISC Zero transfer-v2 receipt and its published vector.
   The Ryzen CPU attempt ran for roughly five hours before interruption and
   produced no artifact. Development-mode execution is not a receipt. Run this
   only when a maintained remote prover or a deliberately provisioned proving
   machine is available.
2. C6 needs a planned repeated comparative benchmark of at least two maintained
   proof implementations, including peak memory, concurrency, and all buckets.
   The existing Ryzen measurements are engineering evidence, not that final
   benchmark. It can be scheduled later on declared comparable hardware.

C7 remains external independent review. Do not mark C1, C4, C6, C7, or A5
complete merely because implementation continues successfully on the M1.

The branch now includes a host-only, opt-in `cuda-prover` feature and the
fail-closed external-GPU procedure in
`docs/runbooks/C1_RISC0_CUDA_PROVING.md`. Its scripts pin Ubuntu 24.04, CUDA
12.8, host Rust 1.90.0, `rzup` 0.5.2, guest Rust 1.97.0, a clean checkout, and
the reviewed guest image ID before proving. They generate, re-read, and verify
the saved receipt and record a hash, environment report, and metrics. This
procedure has not yet run on NVIDIA hardware and no C1 receipt exists; its
presence does not change the status of C1 or C4.

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

> Open `/Users/tomascorzo/vault`, fetch origin, switch to
> `codex/c1-transfer-v2`, and pull with `--ff-only`. Read `AGENTS.md` and every
> document it requires, especially `docs/HANDOFF.md` and
> `docs/H1_CLOSURE_MATRIX.md`. Preserve C2 as complete and C4 as in progress,
> with only its Halo2 half complete. C1/C4 remain blocked on a real RISC Zero
> receipt; do not substitute dev mode or automatically restart the multi-hour
> CPU prover.
> Continue the next locally actionable bounded item, normally C5, while keeping
> C1-C7 separate from A1-A5 and H2. Do not create prototypes, expand H1 with
> H2/mainnet work, start contracts, use real funds, or claim production
> readiness.
