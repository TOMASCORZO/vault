# RISC Zero Accounting V1 — Research Report

**Measured:** 2026-08-21  
**Status:** real proof verified end to end; accounting-only and not eligible for
consensus activation.

## Result

Vault now has a RISC Zero guest that privately proves a strict subset of the
transfer-v1 statement. The host serializes its cryptographic receipt into the
existing `ShieldedTransfer.proof` field. `Risc0AccountingVerifier` verifies the
guest image ID and authenticated journal, then the normal `ShieldedState`
applies replay, anchor, resource, gas, and atomic-state checks.

The measured example has one private input worth 10,065 atomic VLT and two
private outputs classified as 10,000 recipient VLT plus 5 change VLT. The guest
proves:

```text
burn = ceil(10,000 / 200) = 50
gas  = 10 units × 1 atomic VLT = 10
10,065 inputs = 10,000 recipient + 5 change + 50 burn + 10 gas
```

Only note counts and gas are written to the public journal. Amounts and
blindings remain private to the prover.

## Measured proof

| Property | Result |
|---|---:|
| zkVM | RISC Zero 3.0.6, development mode disabled |
| Receipt | Composite STARK receipt, bincode encoded |
| Serialized proof | 256,266 bytes |
| Consensus maximum | 2,097,152 bytes |
| Proving time | 175,555 ms |
| Segments | 1 |
| Total cycles | 262,144 |
| User cycles | 138,802 |
| Guest image / circuit ID | `cbc62eceb28d36d56b9974e446625bdee6a5bc90dba873be3cf16a49c28e14d9` |
| Public-input digest | `85f459affdf26d6ab297fef4044a648fb4735ea7f228a61165c4c767c87541a1` |

Measurement host: Apple M1 MacBook Air, 8 CPU cores, 8 GB RAM, macOS 26.5.1,
host Rust 1.96.1, RISC Zero guest Rust 1.97.0. Compilation time is excluded
from the proving measurement. This canonical run was regenerated after the
`ruint` and `time` dependency remediations; its image ID supersedes the earlier
pre-remediation measurement.

The receipt is small enough for the current envelope, but CPU proving latency
is not acceptable for an interactive base-layer transfer. The backend remains
useful as an executable specification and a candidate for general private
programs, remote proving, or later aggregation. Transfer-v1 still needs a
specialized proof backend and comparative benchmarks.

## Constraints actually proven

1. The guest recomputes the complete transfer-v1 public-input digest from
   version, chain, circuit, anchor, nullifiers, outputs, ciphertexts,
   commitments, and gas. The verifier compares that journal digest with the
   consensus envelope.
2. Private input and output counts match the public envelope and stay within
   1..16.
3. Every sum and multiplication uses checked `u128` arithmetic.
4. Taxable value is the sum of values classified as recipient outputs.
5. Burn equals `ceil(taxable / 200)` exactly.
6. Gas equals public units multiplied by fee per gas.
7. Input value equals recipient outputs, change outputs, burn, and gas exactly.
8. Research balance and burn commitments open to the witnessed data using
   independent 256-bit blindings.
9. The receipt verifies against one pinned guest image and cannot use RISC
   Zero development-mode receipts.

The host dependency enables RISC Zero's `disable-dev-mode` feature. Vault also
rejects any process where `RISC0_DEV_MODE` is present before entering the SDK,
so a deployment misconfiguration fails closed with an error instead of an SDK
panic.

## Critical omissions

This proof is not a complete private transfer and must not protect real funds:

- no Merkle membership proof for input notes;
- no owner key or spending authorization;
- no derivation of public nullifiers from authenticated notes;
- no proof that individual public output commitments contain the witnessed
  values or owners;
- recipient/change classification is supplied by the prover and is therefore
  not trustworthy until change ownership is constrained;
- burn ciphertext is not linked to the witnessed burn and has no threshold
  encryption yet;
- BLAKE3 research commitments are neither the final algebraic commitments nor
  homomorphic;
- no note encryption, viewing keys, dummy-note indistinguishability, or
  multi-asset conservation;
- no protection against IP, timing, wallet, endpoint, or deposit-graph leaks.

The most important current attack is burn evasion by labelling a recipient
output as change. The production statement must derive internal change from an
authenticated spender key rather than trusting this classification.

## Transfer-v2 reference statement

On 2026-08-29 the isolated core added a versioned `TransferV2` reference claim.
It parses the exact canonical `TransferV2Effects` with the production codec and
reconstructs every private action from a validated Orchard FVK, private note,
depth-32 membership path, Action randomizer, net-value trapdoor, and fixed signer
output packet. It verifies ownership, membership for non-zero inputs, nullifier
derivation, `ak + alpha`, the public net commitment, note/value commitments,
ephemeral key, recipient ciphertext, sender-recovery ciphertext, and public
output `rho`. Payment/change/dummy classification is derived from the exact
opened input and output receivers; no standalone classification bit is accepted.

The same hidden taxable sum funds checked conservation and ceiling 0.5% burn.
The guest reconstructs the epoch DKG key ID, burn commitment, and both
threshold-ElGamal ciphertext equations from private openings. The journal
contains only the canonical effects digest, public action count, and public gas
fee; it does not disclose the taxable sum or burn. Ten native tests cover the
positive statement and negative membership, ownership, nullifier,
authorization, note/output, classification, commitment, ciphertext, burn,
epoch, gas, and conservation boundaries. Positive and burn-evasion fixtures
feed the same exact witness to the transparent reference statement and the
Halo2 monolithic circuit; both accept the positive vector and reject the evasion
vector.

The versioned guest entry point now distinguishes `AccountingV1` from
`TransferV2`, preventing silent reinterpretation of old host input. This changes
the guest image and therefore requires a newly reviewed image ID and real
receipt before the v2 increment has proof evidence.

### Windows reproduction status

The 2026-08-29 Ryzen/Windows run completed core tests, Clippy with warnings
denied, rustdoc, root gates, and the differential Halo2 vectors. Full
guest/workspace compilation under RISC Zero 3.0.6 still does not complete on
MSVC: upstream native circuit crates invoke generated C++20 constructs with
`/std:c++17`, and the methods build script encounters an unresolved zkVM
platform allocation symbol. No local security or verifier patch was introduced.
WSL 2.7.1 and Ubuntu are installed on the Windows Ryzen host. The pinned Linux
guest toolchain compiled the transfer-v2 guest twice to the same WSL image ID:

```text
cb95069bf50d37a3e6a9f0fd1519a5676d634c28c6f5a59a335511427cadd032
```

The later CUDA evidence build showed that RISC Zero 3.0.6 retains absolute Rust
source paths in guest panic metadata. The WSL ID is therefore reproducible only
inside that build root, not portable across checkout paths. With guest source
and lockfiles unchanged, the canonical `/workspace/vault` external build is
explicitly pinned to:

```text
85170f11445f10ba9b26e4ca96f29600fe4e30410081905f519a99449dd2d128
```

The Linux guest, host, formatting, Clippy, rustdoc, native reference, and
differential gates pass. A release CPU receipt attempt ran for roughly five
hours before its WSL process was interrupted and left no receipt artifact. On
2026-08-31 the canonical CUDA procedure subsequently generated a real Composite
receipt on an NVIDIA H100 and verified it twice against the reviewed image and
fixture. See [`../evidence/C1_RISC0_CUDA_2026-08-31.md`](../evidence/C1_RISC0_CUDA_2026-08-31.md)
for the exact artifact hash, environment, metrics, and remaining C4 publication
work. Development-mode execution is not counted as a substitute.

## Reproduction

RISC Zero components are pinned independently:

```text
risc0-zkvm = 3.0.6
risc0-build = 3.0.6
guest Rust = 1.97.0
experimental host MSRV = 1.90.0
rzup = 0.5.2 (tooling only)
```

After installing the pinned guest toolchain, run:

```bash
./scripts/check-zk-risc0.sh
./scripts/prove-zk-risc0.sh
```

The quality script builds and tests the real guest first. It sets
`RISC0_SKIP_BUILD=1` only during host-side Clippy and rustdoc because Clippy's
host compiler wrapper cannot compile the nested RISC-V standard library. Proof
generation never sets that variable.

For the opt-in transfer-v2 C1 receipt, a Bonsai account can replace the local
CPU prover without changing the guest ELF, reviewed image ID, journal checks,
or receipt verification. Keep credentials out of shell history and Git, export
them only in the proving terminal, and run:

```bash
export BONSAI_API_URL="<account URL>"
export BONSAI_API_KEY="<account key>"
export RISC0_PROVER=bonsai
export VAULT_C1_RECEIPT_PATH="/absolute/path/vault-c1-transfer-v2.receipt.bin"
cargo test --release --manifest-path zk/risc0/Cargo.toml \
  -p vault-zk-risc0 --test transfer_v2_receipt --locked -- \
  --ignored --nocapture
```

The evidence fixture contains deterministic synthetic notes and keys. Real
wallet witnesses must not be submitted to a third-party prover without a
separate privacy, retention, and trust decision. Free or trial Bonsai access is
account-dependent and is not assumed by this procedure.

For a deliberately provisioned Linux/NVIDIA host, use the pinned CUDA procedure
in [`../runbooks/C1_RISC0_CUDA_PROVING.md`](../runbooks/C1_RISC0_CUDA_PROVING.md).
The `cuda-prover` Cargo feature is host-only: the runbook regenerates the guest
and requires the reviewed image ID before starting the expensive proof. Its
proving script also reopens the saved receipt, verifies it against the exact
fixture, and records the receipt hash, environment, cycles, and timing needed
for C1/C4 evidence.

The experimental backend is an isolated Cargo workspace so its dependency and
compiler lifecycle cannot silently increase the root protocol MSRV.
The complete host adapter dependency graph was checked successfully with Rust
1.90.0 on 2026-08-21; the guest remains compiled by the independently pinned
RISC Zero Rust 1.97.0 toolchain.

## macOS CPU build patch

The RISC Zero 3.0.6 dependency graph selects `risc0-zkp` 3.0.5 and
`risc0-sys` 1.5.0. Their published macOS build paths attempt to compile or
include Metal assets even though the circuit crates select their CPU provers.
Vault vendors these two Apache-2.0 crates and makes the existing `metal` feature
control only the Metal build/HAL. CPU kernels, circuits, verifier, proof
algorithm, constants, and receipt format are unchanged. Each vendor directory
contains a `VAULT-PATCH.md` audit note.

This is a portability patch, not a security endorsement. It must be dropped
when upstream resolves the packaging behavior, followed by lockfile review,
differential tests, and a fresh benchmark.

## Dependency activation blocker

After compatible updates, RustSec still reports vulnerabilities inherited from
RISC Zero/Arkworks in `rsa` and `tracing-subscriber`, plus unmaintained
dependencies. The concrete paths, exposure analysis, and no-allowlist policy
are recorded in
[`../audits/zk-risc0-dependency-audit-2026-08-21.md`](../audits/zk-risc0-dependency-audit-2026-08-21.md).
These findings independently prohibit consensus activation.
