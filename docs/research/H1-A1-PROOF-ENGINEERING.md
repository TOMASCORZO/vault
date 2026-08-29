# H1-A1 proof-engineering evidence

**Updated:** 2026-08-27
**Status:** in progress; production-intent, unaudited, not activated
**Scope:** activation hardening only; no H2 consensus, network, DKG, or mainnet
work

This record tracks the finite H1-A1 gate without creating another H1
cryptographic statement item. The selected transfer backend remains Halo2. The
terminated RISC Zero attempt remains non-selected comparative evidence and is
not rerun by any command in this record.

## Reproducible tooling

`scripts/benchmark-zk-halo2.sh` runs one selected bucket per timed process and
reports:

- deterministic parameter generation plus VK construction;
- loading canonical serialized parameters plus deterministic VK
  reconstruction;
- repeated standalone verification;
- Halo2 batch verification of a declared repeated-vector workload;
- reusable prover-material construction and repeated proving when `prove` is
  explicitly requested;
- canonical proof length and process peak RSS from the host timing tool.

The benchmark is opt-in and is not called by `scripts/check.sh` or
`scripts/check-zk-halo2.sh`. Proving includes the immediate self-verification
performed by the hardened prover helper. The batch workload repeats the same
committed proof and public inputs; it measures the batch engine but is not a
claim about realistic block composition.

The pinned `halo2_proofs 0.3.5` API canonically serializes `Params`, but exposes
no canonical serialization for its PLONK `ProvingKey` or `VerifyingKey`.
Consequently the harness does not invent a key format: it measures parameter
loading followed by VK reconstruction, and labels persistent PK/VK caching as
unsupported. Introducing a persistent key cache requires an upstream-reviewed
serialization or a separately reviewed backend change, plus identity, digest,
permissions, provenance, and reconstruction checks.

H1-A1 therefore selects eager, one-time in-memory key reconstruction rather
than a persistent PK/VK cache. A validator derives transparent parameters and
its VK at process startup; a prover additionally derives its PK. Both parameter
bytes and the pinned VK representation are fingerprinted against the selected
`VaultTransferSuite`, and any mismatch aborts construction. The release
conformance gate now covers successful parameter loading plus rejection of a
corrupted, extended, or wrong-suite parameter artifact. The complete deployment
rule and the accepted local startup envelope are recorded in
[`../architecture/HALO2_SETUP_AND_LIFECYCLE.md`](../architecture/HALO2_SETUP_AND_LIFECYCLE.md#selected-h1-a1-startup-strategy).
Target-hardware repetition remains open; an invented persistent key format does
not.

`scripts/reproduce-zk-halo2-vectors.sh` regenerates every selected vector in a
fresh temporary directory, byte-compares each result against the committed
artifact, prints SHA-256, and removes the temporary directory. It cannot
overwrite the committed vectors. This is deterministic artifact reproduction,
not proof verification during normal transfer processing.

`scripts/reproduce-zk-halo2-build.sh` performs two complete release builds in
physically separate clean target directories, with the lockfile, offline mode,
incremental compilation disabled, a fixed `SOURCE_DATE_EPOCH`, and repository
path remapping. Both physical targets are exposed sequentially through one
stable logical `CARGO_TARGET_DIR`: direct distinct target paths were proven to
change 176 bytes of Rust `lib.rmeta` even though every native code object and
the final executable were identical. The stable path removes that environmental
input instead of ignoring the intermediate mismatch. A mismatch retains both
temporary trees for diagnosis; a successful run deletes them.

The 2026-08-26 local clean-target run reproduced both selected artifacts
byte-for-byte:

| Artifact | SHA-256 |
|---|---|
| `vault-zk-halo2-core.rlib` | `7313840d4fb3d5d9a7e43da2fd52b03bf711efa2769b5b6d05e6baf584050324` |
| `setup_manifest` | `5ce85faf32a2dc984c969c93c806144c9c5a6726fa59a7afc3be98bcd4787ee4` |

This establishes deterministic clean builds on one compiler/OS builder. The
2026-08-28 single-host amendment accepts this evidence shape after it is
repeated on the declared owned acceptance host. It does not establish
cross-host independence or a future distributable validator artifact, which
does not exist in H1.

## Preliminary local measurements

Host: Apple M1 MacBook Air, 8 GiB RAM, Darwin 25.5.0, arm64. Toolchain:
`rustc 1.96.1`; release profile; Halo2 lockfile unchanged. Each verification
row used three samples and a batch size of four. Timings include no compilation.

| Actions | `k` | Params | Generate params + VK | Load params + rebuild VK | Standalone verify median | Batch-4 median total | Process max RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 14 | 1,048,644 B | 20.857 s | 7.171 s | 129.659 ms | 173.250 ms | 127,320,064 B |
| 4 | 14 | 1,048,644 B | 30.046 s | 10.311 s | 147.770 ms | 234.109 ms | 114,950,144 B |
| 8 | 14 | 1,048,644 B | 30.352 s | 15.012 s | 134.106 ms | 219.436 ms | 138,346,496 B |
| 16 | 15 | 2,097,220 B | 53.874 s | 24.918 s | 236.361 ms | 376.437 ms | 269,369,344 B |

Local proving used three samples for the 2-Action bucket and one sample for each
larger bucket. Every proving duration includes immediate self-verification:

| Actions | Samples | Reusable prover-material build | Prove + self-verify | Process max RSS | macOS peak footprint |
|---:|---:|---:|---:|---:|---:|
| 2 | 3 | 34.417 s | 22.115 s median (21.196–25.420 s) | 1,117,257,728 B | 1,403,834,048 B |
| 4 | 1 | 36.054 s | 25.956 s | 1,135,181,824 B | 1,392,987,776 B |
| 8 | 1 | 37.422 s | 25.362 s | 1,060,225,024 B | 1,398,017,664 B |
| 16 | 1 | 80.800 s | 49.232 s | 1,199,996,928 B | 2,809,846,208 B |

These are meaningful local sender-resource warnings, not target-hardware
acceptance results. In particular, a single 4/8/16 sample is functional
coverage, not a statistically useful benchmark.

The same builder regenerated all four H1-C3 vectors byte-for-byte:

| Actions | SHA-256 |
|---:|---|
| 2 | `c49c5d0538ca151ece2acb7dec0f21c1fc470a2f218992b85b475f838de2ef33` |
| 4 | `6fe43d67c19227c379cefa472b87863e5bd8d07c01eee2fc2c6cb58e7310f0b1` |
| 8 | `b72c16b5685b14a9b0bd8f31d344b3804bce5f3935f269930c52f82117449468` |
| 16 | `f19b65e9c25482606a7f4237aff9c1ff4323983b4ccaefbf91704f5986e9dd74` |

## Aggregate-burn recovery scaling

`scripts/benchmark-burn-recovery.sh` builds the exact H1-C4 `HashMap` BSGS
table at declared bounded scales and recovers the maximum value in each range,
which forces the worst-case giant-step count. It uses the non-default
`reference-oracle` feature only to construct the known group message; it cannot
accept aggregates, ciphertexts, or shares and is absent from production paths.
The script refuses the full 144,913,768-step table unless the operator sets
`VAULT_H1_A1_ALLOW_FULL_BURN_BOUND=1` explicitly.

Local release measurements on the same M1 host were:

| Baby/giant steps | Inclusive maximum | Build | Worst recovery | Process max RSS |
|---:|---:|---:|---:|---:|
| 16,384 | 268,435,455 | 0.449 s | 0.246 s median, 3 samples | 3,178,496 B |
| 65,536 | 4,294,967,295 | 1.317 s | 1.105 s median, 3 samples | 7,208,960 B |
| 262,144 | 68,719,476,735 | 4.630 s | 4.610 s median, 3 samples | 23,330,816 B |
| 1,048,576 | 1,099,511,627,775 | 17.320 s | 17.770 s median, 3 samples | 87,818,240 B |
| 4,194,304 | 17,592,186,044,415 | 70.656 s | 69.241 s, 1 sample | 345,702,400 B |

The full table has a 5,796,550,720 B payload lower bound before hash-table
control bytes, spare capacity, allocator overhead, and point temporaries. A
linear projection from the 4,194,304-step run gives approximately 11.94 GB RSS,
2,441 s (40.7 minutes) to build, and 2,392 s (39.9 minutes) for a worst-case
recovery on this host. This projection is not a substitute for a full-bound
measurement, but it already exceeds the machine's 8 GiB physical memory and
makes a full local attempt unsafe.

Therefore the current in-memory `HashMap` representation is not accepted for an
8 GiB target. H1-A1 now retains that exact lookup algorithm but defines a
canonical restart artifact containing only compressed baby-step points in
increasing implicit index order. Its fixed header binds the encryption scheme,
aggregation policy, maximum, step count, and record size; BLAKE3 authenticates
the complete header and payload against both the embedded digest and a non-zero
caller-trusted digest. Rust's randomized `HashMap` representation is never
serialized. Corruption, another bound, wrong digest, truncation, or extension
fails closed before recovery.

Opt-in cache build/restart measurements on the same host were:

| Steps | Cache bytes | Build + write + sync | Validated restart | Worst recovery | Process max RSS | Cache digest |
|---:|---:|---:|---:|---:|---:|---|
| 16,384 | 524,428 | 0.458 s | 0.005 s | 0.397 s median, 3 samples | 3,751,936 B | `899ffff1...ed8eb` |
| 65,536 | 2,097,292 | 1.446 s | 0.010 s | 1.224 s median, 3 samples | 9,355,264 B | `42fd0d7e...222a` |
| 262,144 | 8,388,748 | 5.781 s | 0.041 s | 4.937 s, 1 sample | 27,557,888 B | `7d96dfb1...4a932` |
| 1,048,576 | 33,554,572 | 17.782 s | 0.444 s | 17.698 s, 1 sample | 91,979,776 B | `2f9c8887...0287c` |
| 4,194,304 | 134,217,868 | 72.663 s | 1.405 s | 67.346 s, 1 sample | 349,585,408 B | `93ec74b2...86665` |

The full canonical file length is exactly 4,637,240,716 bytes. Linear scaling
from the largest cache run projects about 12.08 GB RSS, 41.8 minutes to build
and synchronously write, 48.5 seconds to validate and reconstruct the map, and
38.8 minutes for worst-case recovery on this M1. These projections do not
replace two guarded full-bound target-hardware runs in fresh same-host cache
roots with matching digests. Changing the bounded algorithm or interval would
still require the separately reviewed H1-C4 policy replacement; the cache does
neither.

## Adversarial and lifecycle exercises

The canonical composite envelope now has a deterministic malformed-input
corpus covering every header byte, truncation, extension, zero/one/maximum
length fields, the protocol maximum, and 2,048 bounded pseudo-random malformed
inputs. The existing real-proof tests still reject transcript and public-field
mutations. A release test also admits one exact real composite proof while its
mandatory accounting verifier is active, disables that verifier without
changing the proof or circuit identity, and confirms fail-closed rejection.
This exercises the verifier dependency boundary only; governed activation,
cutoff heights, historical replay, and validator distribution remain H1-A4 and
H2 work.

The 2026-08-27 offline RustSec gate loaded 1,226 advisories and scanned all
three locked graphs: 171 root dependencies, 126 Halo2 release dependencies,
and 132 fuzz-only dependencies. It found no known vulnerability. The lockfiles
retain one narrowly allowed unmaintained warning, `RUSTSEC-2023-0089` for
`atomic-polyfill 1.0.3`.

`scripts/audit.sh` pins `cargo-audit 0.22.2`, denies every warning other than
that exact advisory, and separately requires `cargo tree --locked --target all
--edges all -i atomic-polyfill` to produce no active reverse dependency in each
workspace. Thus a new advisory, another warning, or activation of the optional
package fails the gate. `VAULT_AUDIT_OFFLINE=1` uses the already-provisioned
advisory database without network access. Any feature or lockfile change must
repeat this gate; the package is not represented as maintained or removed.

## Coverage-guided malformed-input fuzzing

`zk/halo2/fuzz` is an independent fuzz-only workspace so nightly, libFuzzer,
and sanitizer dependencies cannot enter the pinned Halo2 release workspace or
its normal gates. The first target exercises the public
`CompositeTransferProof::decode` and `ActionProof::from_bytes` boundaries for
all 2/4/8/16 Action counts. It feeds both raw input and deterministic mutations
of a structurally valid deep-path envelope, and asserts exact round trips plus
accounting-suite separation for every accepted value.

`scripts/fuzz-zk-halo2.sh` pins `cargo-fuzz 0.13.2`,
`nightly-2026-08-20`, and the fuzz lockfile. It performs `cargo fetch --locked`
before forcing the instrumented build and run into Cargo offline mode. The
target uses AddressSanitizer, a 16,384-byte input cap, a 4 GiB RSS limit, and a
10-second per-input timeout. The fuzz lockfile SHA-256 is
`20496d1caf24f8cf9fda812a5428f0524c6e8de9a331c05a188f9869bf98a0f3`.

The 2026-08-26 Apple M1 smoke campaign completed a 300-second run without a
crash, timeout, sanitizer finding, or saved crash artifact. A subsequent
10-second corpus-resume check recorded 158,901 executions, 14,445 executions
per second, 126 coverage counters, 218 features, and 367 MiB peak RSS, also
without a finding. The pinned nightly emits one known future-compatibility
warning in upstream `halo2_gadgets 0.5.0` for a trailing semicolon in a macro;
the stable release gate remains clean, and the warning must be reassessed with
any toolchain or dependency change.

An offline RustSec scan of the separate fuzz lockfile loaded the same 1,226
advisories and scanned 132 dependencies. It found no known vulnerability and
the same allowed inactive `RUSTSEC-2023-0089` unmaintained warning; fuzz-only
tooling is not silently treated as a release dependency.

Five minutes is harness validation, not the sustained fuzzing acceptance gate.
The target-hardware campaign must retain its complete command, duration,
corpus, sanitizer configuration, final statistics, and any minimized artifact.

## Heterogeneous validator workload

`scripts/benchmark-zk-halo2-heterogeneous.sh` builds all four exact verifier
materials once and dispatches one deterministic block workload across committed
2/4/8/16-Action proofs. It supplies three declared profiles (`common`,
`balanced`, and `max-heavy`), refuses a block too short to include every bucket
in its selected profile, records the exact sequence and bucket counts, and
rejects each vector's fixed malformed proof before timing. It is sequential
suite dispatch, not a claim of a cross-VK batch optimization or a measured
mainnet distribution.

The local Apple M1 smoke run used the common eight-proof sequence
`[2,2,2,2,4,4,8,16]`. One-time construction and identity validation of all
four verifier materials took 133,911.171 ms. The mixed block verified in
1,239.336 ms with 209,534,976 B process maximum RSS. This validates the runner
only; repeated target-validator measurements for all profiles remain external.

## Remaining H1-A1 gates

H1-A1 remains open. It cannot be checked complete until all of the following
evidence exists:

1. repeated proving and peak-memory measurements for all 2/4/8/16 buckets on
   declared target prover hardware;
2. standalone and realistic heterogeneous block-batch verification on declared
   target validator hardware using the now-frozen mixed-bucket runner;
3. sustained coverage-guided malformed-input fuzzing and sanitizer runs, beyond
   the deterministic in-tree corpus;
4. byte-identical artifact and build repeatability in two fresh isolated roots
   on the declared owned acceptance host; this deliberately does not claim
   independent host reproduction;
5. two full-bound target-hardware cache builds in fresh roots with matching
   digests, plus restart, memory, and recovery measurements for the now-defined
   canonical representation; the current `HashMap` evidence rejects an 8 GiB
   target.

The single-host waiver leaves common-mode CPU, firmware, OS, compiler,
filesystem and host-compromise failures outside the evidence. This accepted
assurance reduction must remain visible to H1-A4 reviewers and release users.

These are now external acceptance-campaign gates; no further local
implementation or design item remains inside H1-A1.

These are engineering and review gates. They do not authorize a verifier,
extend the proof statement, or pull consensus and mainnet work into H1.
