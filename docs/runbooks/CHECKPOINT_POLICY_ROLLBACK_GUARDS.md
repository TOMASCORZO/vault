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

## Windows TPM profile implemented; reboot acceptance pending

`WindowsTpmRollbackGuard` is a separate `cfg(target_os = "windows")` adapter.
Production code uses native Windows TBS and the Microsoft Platform Crypto
Provider; it does not shell out to PowerShell or `tpmtool` and has no software
fallback.

The profile uses one SHA-256 TPM NV extend index from the TCG owner range. A
scope-derived, bounded 32-candidate search avoids occupied handles. A random
32-byte index authorization is encrypted by a user-scoped non-exportable
2048-bit RSA TPM key; plaintext authorization and authorization-bearing TPM
command buffers are zeroized. Provisioning retrieves Windows-managed storage
owner authorization and therefore runs elevated exactly once. Ordinary loads
and advances need no elevation.

State is published with write-through replacement and contains the exact
network, bootstrap policy ID, NV index, optional anchor, TPM digest, wrapped
authorization, and checksum. Before every extend, a separate write-through
pending record binds the old anchor/digest, exact successor, extend input, and
expected digest. Recovery accepts only the exact pre-extend or post-extend TPM
state. A scope-specific OS file lock serializes independent processes.

Completed requirements:

1. Exact scope binding, checked codecs, non-exportable authorization wrapping,
   owner-range NV selection, and elevated/idempotent provisioning are implemented.
2. Missing/reset NV state, wrong attributes, missing key, malformed state,
   regression, same-generation branch, skipped generation, contention, and
   read-back mismatch fail closed.
3. Every-byte mutation/truncation/extension, real two-process contention, both
   interruption states on live TPM, exact NV deletion/reset observation, and
   valid policy-file rollback tests pass.
4. Exact device, toolchain, commands, results, and residual risks are recorded
   in `docs/evidence/A1_WINDOWS_TPM_2026-09-03.md`.

To finish the sole remaining hardware gate, run phase one elevated, perform a
real Windows restart, then run phase two elevated. Do not run phase two without
the intervening reboot merely to obtain a passing result:

```powershell
cargo test -p vault-wallet --lib --no-run
# Run the emitted test executable elevated with:
# windows_tpm_guard::tests::real_tpm_reboot_persistence_phase_one --exact --ignored --nocapture
# Restart Windows.
# Run the same executable/test build elevated with:
# windows_tpm_guard::tests::real_tpm_reboot_persistence_phase_two_and_cleanup --exact --ignored --nocapture
```

Phase one intentionally leaves one isolated NV index, one test CNG key, and its
test directory under `%TEMP%`. Phase two must reopen and advance that exact
scope before deleting all three. If phase two fails, preserve the directory and
inspect it; never clear the TPM or bulk-delete keys/indices. After it passes,
run the final workspace, strict Clippy, rustdoc, and advisory gates before
checking `A1-CP1-WIN` complete.

The Windows work is platform parity. It does not reopen C1-C6 and requires no
GPU.
