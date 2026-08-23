# Halo2 dependency audit — 2026-08-22

This is point-in-time evidence, not a warranty that dependencies or the proof
system are safe.

Reverified after integrating the canonical local signer session through the
path dependencies; the resolved package count and advisory result are
unchanged.

```text
Tool: cargo-audit 0.22.2
Input: zk/halo2/Cargo.lock
RustSec advisories loaded: 1,225
Crate dependencies scanned: 126
Known vulnerabilities detected: 0
Allowed warnings: 1
```

The warning is `RUSTSEC-2023-0089` for unmaintained
`atomic-polyfill 1.0.3`. It exists in lockfile resolution through an inactive
optional dependency chain. `cargo tree -i atomic-polyfill --target all` prints
no active reverse dependency for the Halo2 workspace. Enabling new Orchard or
FROST features requires re-auditing this conclusion.

Commands used:

```bash
cd zk/halo2
cargo audit --file Cargo.lock
cargo tree -i atomic-polyfill --target all
```

The scan covers published RustSec advisories only. It does not review circuit
soundness, cryptographic assumptions, the local Orchard composition fork,
unknown vulnerabilities, build provenance, or Vault's own code. Those remain
separate release gates.
