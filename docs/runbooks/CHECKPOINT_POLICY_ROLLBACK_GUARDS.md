# Checkpoint-policy rollback guards

**Maturity:** production-intent activation hardening; not a mainnet-safety claim

## macOS profile implemented

`MacOsKeychainRollbackGuard` stores the exact checkpoint-policy generation and
policy ID in the local macOS Keychain under service
`org.vault.wallet.checkpoint-policy-anchor.v1`. The item is explicitly
non-synchronizing. Its account name is a domain-separated BLAKE3 digest of the
network and generation-1 bootstrap policy ID, so lineages cannot alias.

The authenticated record is:

```text
"VPKCM001" || chain_id_32 || bootstrap_policy_id_32 ||
generation_be64 || current_policy_id_32 || checksum_32
```

The checksum is BLAKE3-derived under
`vault.wallet.macos-keychain-anchor-v1.2026-09-03`. Decoding is exact and
rejects wrong scope, zero generation, mutation, truncation, and extension.

The caller supplies one fixed absolute application-support directory owned by
the current user and not writable by group or other users. A scope-derived
owner-only, no-follow lock serializes the Keychain read/check/write/read-back
sequence across Vault processes. The guard rejects generation regression,
same-generation policy-ID replacement, unsafe lock paths, Keychain errors, and
failed write-back verification.

Policy-store creation now initializes the external anchor before publishing the
new policy file. Opening an existing policy file requires a pre-existing
external anchor. Consequently, deleting the Keychain item cannot silently turn
an existing file into a fresh lineage; opening fails closed. An update still
writes the authenticated policy log before advancing the anchor, permitting
recovery when an interruption leaves the log one valid generation ahead.

Run on macOS:

```bash
cargo test -p vault-wallet macos_keychain_guard -- --nocapture
cargo test -p vault-wallet checkpoint_policy_store -- --nocapture
```

The real-device test creates a random-scope Keychain item, exercises initial
load, idempotence, monotonic advancement, regression and equivocation rejection,
reopening, and scope isolation, then deletes only that test item. Parser tests
mutate every byte and reject every truncated prefix and extension. Unsafe
directory and symlinked-lock cases also fail closed. A real Keychain/store
integration test advances to generation 2, restores the valid generation-1
policy file, and confirms rollback rejection.

### macOS residual limits

This adapter separates the anchor from ordinary wallet and policy files and
protects it with the logged-in user's local Keychain. It is not a Secure
Enclave monotonic counter. A full privileged rollback or destruction of both
the login Keychain and application state is outside this adapter's guarantee
and requires the explicit wallet/bootstrap recovery ceremony. Availability
also requires an unlocked Keychain session.

The Data Protection Keychain variant was deliberately not enabled in the Rust
test binary: macOS rejected the unsigned test process with OSStatus `-34018`
(missing entitlement). Enabling that profile requires the final signed app
bundle, application identifier, and reviewed Keychain access-group entitlements;
there must be no automatic runtime fallback between profiles.

## Windows continuation checklist

Continue on the Windows device from `codex/c1-transfer-v2` after pulling the
commit that introduced `MacOsKeychainRollbackGuard`. Implement Windows as a
separate `cfg(target_os = "windows")` module; do not weaken or emulate the
macOS path and do not shell out to PowerShell or `tpmtool` from production code.

Required result:

1. Select and document the Windows trust primitive before coding. Prefer a TPM
   2.0 NV extend/counter design through native Windows APIs. Credential Manager
   or DPAPI alone encrypts data but does not prove freshness, so it is not a
   hardware rollback guarantee.
2. Implement `WindowsTpmRollbackGuard` against the existing
   `CheckpointPolicyRollbackGuard` trait. Bind every protected value to
   `chain_id`, bootstrap policy ID, generation, and current policy ID.
3. Use a machine/install-specific TPM namespace and non-exportable authorization
   material. Never place an authorization secret in source, arguments, logs, or
   the ordinary policy file. Absence after initialization must fail closed.
4. Serialize concurrent writers across processes and design an explicit pending
   journal for the non-atomic boundary between the signed policy log and TPM NV
   advancement. Recovery must distinguish the old committed state, the exact
   pending successor, and corruption; it must not skip or reset the protected
   lineage.
5. Reject regression, same-generation equivocation, wrong network/bootstrap,
   malformed NV data, unauthorized access, missing TPM, TPM clear/reset,
   lock contention, interrupted update, and read-back mismatch. There must be
   no software-only fallback in a TPM-required profile.
6. Add deterministic codec tests, every-byte mutation/truncation/extension
   tests, two-process contention, policy-file rollback, same-generation branch,
   deletion/reset, reboot persistence, and power/interruption recovery tests on
   real Windows TPM 2.0 hardware.
7. Run `cargo fmt --all -- --check`, the Windows wallet tests, workspace tests,
   strict Clippy, rustdoc with warnings denied, and the dependency/advisory
   check. Record Windows edition, build, Rust version, TPM manufacturer/firmware,
   API/backend, and exact results in a dated evidence document.
8. Update `docs/ROADMAP.md`, `docs/HANDOFF.md`, this runbook, and the recovery
   specification. Do not call the Windows profile complete until real TPM
   persistence and interruption tests pass.

The Windows work is platform parity. It does not reopen C1-C6 and requires no
GPU.
