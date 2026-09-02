# A4 Halo2 parameter persistence evidence — 2026-09-02

**Status:** partial A4 release-engineering evidence
**Maturity:** production-intent, non-activatable

## Implemented boundary

Vault now has a canonical, bounded artifact for the transparent parameters
shared by the selected monolithic Halo2 transfer suite. The loader checks the
fixed outer length before allocating or entering the Halo2 decoder, then checks
the format version, `k`, suite ID, declared payload length, compile-time
approved SHA-256, exact payload SHA-256, decoder consumption, and absence of
trailing bytes.

| Field | Value |
|---|---|
| Halo2 | `halo2_proofs 0.3.5` |
| Suite ID | `991523426f81b2350b1b08a7e2de9f60e334f344e40c23904c6dd8db5937c83a` |
| Degree | `k = 15` |
| Payload bytes | 2,097,220 |
| Complete artifact bytes | 2,097,306 |
| Payload SHA-256 | `e1fb29749c7bd0870768044d5329b4e293cb2d44dae24db2554605427b19d0dd` |

The release test round-tripped the artifact and rejected truncation, trailing
data, unknown magic/version, wrong degree/suite, wrong declared length, changed
embedded digest, and changed payload.

## Local measurement

Command:

```bash
VAULT_A4_REPETITIONS=3 ./scripts/benchmark-zk-a4-halo2-parameters-macos.sh
```

Declared host: Apple M1, 8 cores, 8 GiB RAM, arm64 macOS 26.5.1; Rust
1.96.1. Compilation was cached and excluded from operation timers.

| Operation | Elapsed |
|---|---:|
| Derive, encode, create-new write, and `fsync` | 21.402418 s |
| Load and validate, repetition 1 | 740.517 ms |
| Load and validate, repetition 2 | 739.828 ms |
| Load and validate, repetition 3 | 742.820 ms |
| Load mean | 741.055 ms |

These are new-process loads from a temporary file, but the operating-system
page cache is not forcibly dropped. They demonstrate the implementation path
and observed latency, not a physical cold-disk guarantee.

The final `cargo audit --file Cargo.lock` scan covered 130 dependencies against
1,239 RustSec advisories: 0 known vulnerabilities and the already accepted
`atomic-polyfill 1.0.3` unmaintained warning.

## Remaining A4 boundary

This does not close A4. `halo2_proofs 0.3.5` does not expose stable VK/PK
serialization, so Vault deliberately does not dump private Rust memory or call
deterministic derivation a load. Remaining work includes a reviewed VK/PK
format or audited dependency fork, two-builder digest reproduction, signed
artifact publication, key-to-vector proof correspondence, release build
reproduction, operational limits, and activation/deactivation migration
procedures.

No verifier is activated by this artifact.
