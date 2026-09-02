# C6 proof-system benchmark — 2026-08-31

**Status:** in progress; Halo2 selection measurements complete, one RISC Zero
Succinct classification run remains.

## Decision

The specialized Halo2 transfer circuit remains Vault's base-layer candidate.
The RISC Zero transfer-v2 implementation remains a reference backend and is
rejected for direct base-layer activation in its measured Composite form: its
311,977,650-byte receipt exceeds the 2,097,152-byte protocol limit, regardless
of proving speed.

This is not C6 closure until the prepared Succinct classification run and the
selection record are complete. Repeated RISC Zero proving, concurrency, and
4/8/16-action measurements will not be purchased for a candidate already
rejected by hard protocol and activation blockers. Stable Halo2 parameter/key
serialization and cold loading remain A4 release engineering, not missing C6
selection measurements. Missing RISC Zero measurements are reported as not
purchased, not inferred from the successful two-action receipt.

## Halo2 methodology

- Source commit before the benchmark changes: `bdeb7e1ffea3fdfb526e99f4960647b1a89decc7`.
- Backend: `halo2_proofs 0.3.5`, monolithic transfer suite
  `991523426f81b2350b1b08a7e2de9f60e334f344e40c23904c6dd8db5937c83a`,
  `k = 15`.
- Hardware: MacBook Air, Apple M1, 8 cores (4 performance and 4 efficiency),
  8 GB RAM; macOS 26.5.1.
- Toolchain: `rustc 1.96.1`, `cargo 1.96.1`.
- Three independent release-mode repetitions per bucket. Each repetition
  constructs the deterministic real fixture, derives parameters plus VK/PK,
  proves, and verifies. Compilation is cached and excluded from the internal
  operation timers.
- `/usr/bin/time -l` records peak resident memory for each three-repetition
  bucket process. It is a process peak, not a per-operation allocation trace.
- Raw measurements are committed in
  [`c6-halo2-m1-2026-08-31.csv`](c6-halo2-m1-2026-08-31.csv).

Run:

```bash
VAULT_C6_REPETITIONS=3 ./scripts/benchmark-zk-c6-halo2-macos.sh
```

| Actions | Keygen mean | Prove mean | Verify mean | Proof | Process peak RSS |
|---:|---:|---:|---:|---:|---:|
| 2 | 43.445 s | 37.243 s | 173.414 ms | 9,664 B | 2,081,914,880 B |
| 4 | 46.442 s | 37.667 s | 184.478 ms | 9,664 B | 2,208,169,984 B |
| 8 | 55.306 s | 37.341 s | 148.790 ms | 9,664 B | 1,760,526,336 B |
| 16 | 62.801 s | 33.117 s | 137.028 ms | 9,664 B | 1,506,328,576 B |

The non-monotonic proving and RSS results are retained exactly. They show
host scheduling, allocator, and warm-cache variance and must not be rewritten
as a scaling claim.

Two simultaneous 16-action workers also passed on the same M1:

```text
workers=2
wall_seconds=120
worker_1: keygen=78.653 s prove=40.890 s verify=111.877 ms peak_rss=906,936,320 B
worker_2: keygen=77.168 s prove=40.209 s verify=105.688 ms peak_rss=1,032,273,920 B
```

Reproduce with:

```bash
./scripts/benchmark-zk-c6-halo2-concurrency-macos.sh
```

## RISC Zero evidence and missing cells

The existing two-action H100/CUDA 12.8 run measured 1,329.338 seconds proving,
47.15 seconds saved-receipt verification, and a 311,977,650-byte Composite
receipt. It used 1,109 segments, 1,162,870,784 total cycles, and 1,032,338,164
user cycles. See [`C1_RISC0_CUDA_2026-08-31.md`](C1_RISC0_CUDA_2026-08-31.md).

That run did not capture peak host/GPU memory, repeated samples, concurrent
provers, key/method preparation or load latency, or the 4/8/16-action buckets.
Vault will not spend more rented GPU time merely to fill benchmark cells for a
receipt format that already violates the hard consensus envelope. A future
RISC Zero release or succinct wrapping path can reopen the comparison only
after it fits the protocol bound.

## Dependency and maintenance review

Both selected versions were the latest official tags on 2026-08-31, and both
official repositories were active and unarchived:

- Zcash `halo2_proofs 0.3.5`, tag dated 2026-08-03; the repository had a push
  on 2026-08-31. The current RustSec scan found no known vulnerability and one
  inactive optional-chain `atomic-polyfill` maintenance warning.
- RISC Zero `3.0.6`, release dated 2026-07-17; the repository had a push on
  2026-08-28. Its six published project advisories do not list 3.0.6 inside
  their vulnerable ranges, but Vault's resolved host lock still fails RustSec
  on transitive `rsa 0.9.10` and `tracing-subscriber 0.2.25`, plus maintenance
  warnings and a yanked target-specific package. This independently blocks
  activation.

Primary maintenance sources: [Zcash Halo2 repository](https://github.com/zcash/halo2),
[RISC Zero 3.0.6 release](https://github.com/risc0/risc0/releases/tag/v3.0.6),
and [RISC Zero security advisories](https://github.com/risc0/risc0/security/advisories).
Resolved dependency details remain in
[`../audits/zk-halo2-dependency-audit-2026-08-22.md`](../audits/zk-halo2-dependency-audit-2026-08-22.md)
and
[`../audits/zk-risc0-dependency-audit-2026-08-21.md`](../audits/zk-risc0-dependency-audit-2026-08-21.md).

## Exact remaining C6 work

The isolated CUDA procedure for the first RISC Zero decision gate is prepared
in [`../runbooks/C6_RISC0_SUCCINCT_CUDA.md`](../runbooks/C6_RISC0_SUCCINCT_CUDA.md).
It reuses the published Composite receipt rather than repeating base proving.
No Succinct measurement exists until that procedure actually completes.

The prerelease `c6-risc0-cuda-prebuild-v1` contains verified standalone
archives for Ada `sm_89` and Hopper `sm_90`, built from
`b4482a961f95ac74f6bf981a080ab047604bb516`. The `sm_120` attempt exhausted the
GitHub runner's RAM and is excluded; it is not required for the planned H100 or
L40S execution.

1. Run the single prebuilt Composite-to-Succinct classification gate on
   declared CUDA hardware and preserve its receipt, log, manifest, environment,
   and resource samples.
2. Re-run the dependency/advisory review at the selection commit and record the
   final selection of Halo2 and rejection of RISC Zero 3.0.6 for direct
   base-layer use.

Persistent Halo2 parameter/VK/PK artifacts and cold-load measurement remain
A4. No repeated RISC Zero all-bucket run is required unless a future maintained
version clears the present protocol and activation blockers and is nominated as
a selection candidate.

No verifier is activated by this report.
