# Experimental RISC Zero dependency audit — 2026-08-21

**Scope:** `zk/risc0/Cargo.lock` and `zk/risc0/methods/guest/Cargo.lock`  
**Tool:** `cargo-audit 0.22.2`, RustSec database with 1,225 advisories  
**Decision:** backend remains ineligible for consensus activation.

**CUDA re-scan:** 2026-08-30, RustSec database with 1,226 advisories. Enabling
the host-only `risc0-zkvm/cuda` feature expands the locked optional dependency
graph but leaves the two known vulnerabilities below unchanged. The scan still
fails as required; the CUDA evidence path remains non-activatable.

## Remediation performed

The first scan found four vulnerabilities. Vault raised only the isolated ZK
workspace MSRV from Rust 1.85 to 1.90 and updated:

- `ruint` 1.17.2 → 1.20.0, resolving
  [RUSTSEC-2026-0220](https://rustsec.org/advisories/RUSTSEC-2026-0220);
- `time` 0.3.45 → 0.3.55, resolving
  [RUSTSEC-2026-0009](https://rustsec.org/advisories/RUSTSEC-2026-0009).

`ruint` is in `risc0-binfmt`, so its incorrect shift/overflow behavior was not
accepted even for a research backend. The root Vault workspace keeps its Rust
1.85 MSRV because the ZK workspace is deliberately isolated.

## Remaining host-lock vulnerabilities

### RUSTSEC-2023-0071 — `rsa` 0.9.10

- Severity: 5.9 medium.
- Path: `rzup 0.5.2` through RISC Zero build/proving dependencies.
- Upstream status: no fixed `rsa` release is available.
- Exposure here: `rzup` verifies distribution signatures; Vault does not use
  this dependency to hold a private RSA key. That reduces the relevance of a
  private-key timing recovery attack but does not remove the vulnerable crate
  or justify production activation.

Reference: [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071).

### RUSTSEC-2025-0055 — `tracing-subscriber` 0.2.25

- Path: `ark-relations 0.5.1` → Arkworks Groth16 → `risc0-groth16 3.0.5`.
- Fixed line: `tracing-subscriber >= 0.3.20`.
- Blocker: `ark-relations 0.5.1` declares the incompatible `0.2` line. A local
  semver-major substitution inside a cryptographic dependency was judged more
  dangerous than retaining the backend as research-only.
- Exposure here: the issue concerns ANSI control characters in logged
  user-controlled text. Vault does not treat prover logs as a trusted audit
  channel, but validators still cannot ship a dependency with an open advisory.

Reference: [RUSTSEC-2025-0055](https://rustsec.org/advisories/RUSTSEC-2025-0055).

The independently resolved guest lockfile contains the same
`tracing-subscriber` vulnerability but not `rsa`.

## Unmaintained dependency warnings

The host lock also reports:

- `atomic-polyfill` 1.0.3 through `heapless`/`postcard`;
- `bincode` 1.3.3 through RISC Zero and Vault receipt serialization;
- `derivative` 2.2.0 through Arkworks;
- `number_prefix` 0.4.0 through the CUDA-enabled
  `risc0-groth16`/`circom-witnesscalc` dependency graph, even though the C1 run
  requests a Composite receipt and never invokes Groth16 wrapping;
- `paste` 1.0.15 through Arkworks and RISC Zero.

The guest lock reports `derivative` and `paste`. These are warnings rather than
known vulnerabilities, but the final proof backend must remove, replace, or
obtain an audited maintenance plan for each one.

The host lock also contains the yanked target-specific `chacha20` 0.10.1
release. It predates the CUDA lock expansion and remains another reason the
backend cannot advance beyond isolated evidence without a reviewed dependency
upgrade.

## Activation gate

This backend MUST remain deactivated while either lockfile has an unreviewed
RustSec vulnerability. Upgrading RISC Zero or Arkworks requires:

1. exact dependency and license review;
2. removal or revalidation of the macOS build patches;
3. native/guest transcript differential tests;
4. regeneration of image ID and proof vectors;
5. malformed-receipt and development-mode tests;
6. a fresh performance benchmark and external cryptography review.

Reproduce both scans with `./scripts/audit-zk-risc0.sh`. A nonzero exit is
expected until the blockers above are resolved; it must never be allowlisted
as a passing production gate.
