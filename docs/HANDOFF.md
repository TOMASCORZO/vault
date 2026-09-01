# Vault Project Handoff

**Updated:** 2026-09-01
**Current milestone:** H1 — private-transfer production foundation  
**Maturity:** production-intent, not activated, not safe for real funds

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
ef71be9 Publish RISC Zero C4 vector verifier
f8031ed Use project test evidence as release authority
5860f46 Record successful C1 CUDA receipt evidence
d300b17 Pin canonical CUDA guest image ID
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
operational evidence, and reproducible project security gates exist.

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
On 2026-08-31 an NVIDIA H100 80 GB CUDA 12.8 run generated a real 311,977,650-byte
Composite receipt in 1,329,338 ms for 1,162,870,784 total cycles. It verified
immediately and again after reopening the saved artifact; the local copy's
SHA-256 matches the remote manifest. C1 is complete at the
implementation-evidence boundary. Exact provenance and remaining limitations
are recorded in `docs/evidence/C1_RISC0_CUDA_2026-08-31.md`.

C2 is complete at the implementation-evidence boundary. The monolithic Halo2
2/4/8/16-action shapes use deterministic transparent parameters at `k = 15`
and suite ID
`991523426f81b2350b1b08a7e2de9f60e334f344e40c23904c6dd8db5937c83a`.
Real release proofs for every bucket passed on the Ryzen host, as did mutation
of every two-action public-instance cell and the private classification/value
negative matrix. C6 comparative benchmarks and verifier activation remain open.

The Halo2 half of C4 is committed under
`zk/halo2/core/tests/vectors`: four 9,664-byte real proofs, canonical public
instances, a SHA-256/toolchain manifest, deterministic reproduction, and an
offline verifier that rejects a changed proof byte and every public-instance
cell mutation. The RISC Zero receipt and three provenance files are published
in GitHub release `c4-risc0-transfer-v2-v1`; its repository manifest pins the
canonical digest, exact toolchains, hashes, metrics, and size. The offline M1
verifier accepted the real receipt and rejected an altered public digest, an
altered proof byte, and truncation in 74.57 seconds. C4 is complete. The
311,977,650-byte receipt exceeds Vault's 2,097,152-byte consensus proof limit,
so this evidence does not make the RISC Zero backend activatable.

C5 is complete at the specification boundary. The normative policy in
`docs/specs/BURN_AGGREGATION_V1.md` freezes the greater-than-two-thirds DKG
threshold, deterministic collection windows, 256-ciphertext/64-block disclosure
floor, indefinite low-volume carry under same-key validator resharing, verified
share selection, bounded recovery/stall behavior, and monotonic public supply
upper-bound updates. The network DKG, persistence, recovery implementation, and
activation remain H2/A4/A5 work rather than reopening C5.

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
M1. Work that is safe and useful on the M1 includes C6 tooling and documentation, ordinary Rust
tests, and the applicable A1-A4 hardening tasks.

One cryptographic evidence item is still genuinely open:

1. C6 still needs persistent Halo2 key-load measurement and the prepared RISC
   Zero Succinct decision run. If Succinct fails the hard proof-size bound, the
   RISC Zero branch ends by documented rejection. If it fits, repeated
   2/4/8/16-action RISC Zero memory and concurrency measurements remain before
   comparative closure.

Do not mark C6 or A5 complete merely because implementation continues
successfully on the M1. External audit is optional and is not a closure gate;
the project-controlled reproducible suites are the acceptance authority.

The branch now includes a host-only, opt-in `cuda-prover` feature and the
fail-closed external-GPU procedure in
`docs/runbooks/C1_RISC0_CUDA_PROVING.md`. Its scripts pin Ubuntu 24.04, CUDA
12.8, host Rust 1.90.0, `rzup` 0.5.2, guest Rust 1.97.0, a clean checkout, and
the reviewed guest image ID before proving. They generate, re-read, and verify
the saved receipt and record a hash, environment report, and metrics. This
procedure completed on an NVIDIA H100. It produced the C1 receipt documented in
`docs/evidence/C1_RISC0_CUDA_2026-08-31.md`; C1 is complete at the
implementation-evidence boundary. The release asset and offline negative-vector
package complete C4; do not restart proving.

C6 is now in progress with reproducible local evidence. Halo2 has three real
release measurements for each 2/4/8/16-action bucket on the Apple M1, plus a
two-worker 16-action concurrency measurement and process peak-RSS capture. The
raw CSV and interpretation are in
`docs/evidence/C6_PROOF_BENCHMARK_2026-08-31.md`. A separate fail-closed CUDA
procedure in `docs/runbooks/C6_RISC0_SUCCINCT_CUDA.md` is prepared to compress
the already published Composite receipt into a Succinct receipt without
repeating base proving. It verifies the same reviewed guest and journal,
reopens the output, rejects mutations, and records VRAM, host RSS, time, size,
and the 2 MiB compatibility decision. This compression has not been run; do not
report a Succinct size or C6 closure until external evidence exists.

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
real-proof positive and negative vectors and benchmark gates without treating
later consensus integration as new H1
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
> `docs/H1_CLOSURE_MATRIX.md`. Preserve C1, C2, C4, and C5 as complete at their
> stated boundaries. The real RISC Zero
> receipt is published in release `c4-risc0-transfer-v2-v1`; do not restart
> proving. Continue the next locally actionable bounded item, normally C6,
> while keeping C1-C6 separate from A1-A5 and H2. Do not create prototypes,
> expand H1 with
> H2/mainnet work, start contracts, use real funds, or claim production
> readiness.
