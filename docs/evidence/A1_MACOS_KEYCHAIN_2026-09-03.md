# A1 macOS checkpoint-policy Keychain evidence — 2026-09-03

**Scope:** `A1-CP1` macOS rollback guard
**Maturity:** production-intent, not release candidate, not safe for real funds

## Implementation

`MacOsKeychainRollbackGuard` implements the existing
`CheckpointPolicyRollbackGuard` boundary with:

- a local generic-password item in macOS Keychain, explicitly marked
  non-synchronizing;
- service `org.vault.wallet.checkpoint-policy-anchor.v1` and a
  domain-separated account derived from network plus bootstrap policy ID;
- an exact 144-byte checksummed record binding network, bootstrap lineage,
  generation, and active policy ID;
- an absolute, same-user, non-group/world-writable lock directory and a
  scope-specific owner-only/no-follow cross-process lock;
- monotonic generation, same-generation policy-ID equality, and post-write
  Keychain read-back enforcement;
- no public reset/delete operation and opaque fail-closed platform errors.

Policy-store creation now establishes and verifies the external anchor before
publishing its file. Opening an existing file rejects a missing guard anchor.
Authenticated updates remain log-first and can advance an older anchor only
when that anchor occurs in the replayed signed lineage.

## Dependency record

- `security-framework 3.7.0`, MIT OR Apache-2.0,
  `https://github.com/kornelski/rust-security-framework`;
- `security-framework-sys 2.17.0`, MIT OR Apache-2.0, same upstream;
- target-gated to macOS and exactly pinned in the workspace manifest/lockfile;
- transitive additions: `core-foundation 0.10.1` and
  `core-foundation-sys 0.8.7`.

`cargo audit` scanned 185 locked dependencies. It reported only the repository's
already allowed `RUSTSEC-2023-0089` unmaintained warning for
`atomic-polyfill 1.0.3`; no new advisory was attributed to the Keychain
dependencies.

## Executed evidence on Apple M1

The real Keychain test passed initial absence, creation, idempotent reuse,
generation advancement, lower-generation rejection, same-generation alternate
policy rejection, reopening from a new adapter instance, and scope separation.
A complete policy-store integration test then installed generation 2, restored
the authentic generation-1 file, and observed `RollbackDetected` from the real
Keychain anchor. Tests delete only their random-scope Keychain entries.

Deterministic tests also passed mutation of every record byte, every truncated
prefix, appended data, relative/world-writable directories, and a symlinked
scope-lock path. Strict Clippy and rustdoc passed for `vault-wallet`. The final
workspace gate is recorded by the commit containing this evidence.

## Residual risk and next platform

This adapter protects against restoring ordinary wallet/policy files while the
local login Keychain remains authoritative. It is not a Secure Enclave monotonic
counter and does not promise survival against a privileged rollback or erasure
of the whole Keychain plus application state. Such a reset requires the explicit
wallet/bootstrap recovery ceremony.

The Data Protection Keychain call was tested but correctly rejected the unsigned
Rust test binary with OSStatus `-34018` because a required entitlement was
absent. That stronger profile must be enabled only for the final signed app with
reviewed application identifier/access-group entitlements, without runtime
fallback.

Windows TPM 2.0 parity is the next platform checkpoint. Its exact requirements
are in `docs/runbooks/CHECKPOINT_POLICY_ROLLBACK_GUARDS.md`; it requires no GPU.
