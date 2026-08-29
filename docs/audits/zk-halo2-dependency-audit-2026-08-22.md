# Halo2 dependency audit — 2026-08-22

This is point-in-time evidence, not a warranty that dependencies or the proof
system are safe.

Reverified offline on 2026-08-27 during H1-A1 proof engineering. The release
workspace still resolves 126 packages and the advisory result is unchanged.
The same enforced run also scanned the independent 132-package fuzz lockfile.

```text
Tool: cargo-audit 0.22.2
Input: zk/halo2/Cargo.lock
RustSec advisories loaded: 1,226
Crate dependencies scanned: 126
Known vulnerabilities detected: 0
Allowed warnings: 1
```

The warning is `RUSTSEC-2023-0089` for unmaintained
`atomic-polyfill 1.0.3`. It exists in lockfile resolution through an inactive
optional dependency chain. `cargo tree --target all --edges all -i
atomic-polyfill` prints no active reverse dependency for the Halo2 workspace.
Enabling new Orchard or FROST features requires re-auditing this conclusion.

Enforced command used from the repository root:

```bash
VAULT_AUDIT_OFFLINE=1 ./scripts/audit.sh
```

The script pins `cargo-audit 0.22.2`, denies every warning other than the exact
advisory above, and applies the separate locked all-target inactivity check to
the root, Halo2 release, and fuzz graphs. Activation of `atomic-polyfill`, any
new warning, or any known vulnerability fails the gate.

The scan covers published RustSec advisories only. It does not review circuit
soundness, cryptographic assumptions, the local Orchard composition fork,
unknown vulnerabilities, build provenance, or Vault's own code. Those remain
separate release gates.
