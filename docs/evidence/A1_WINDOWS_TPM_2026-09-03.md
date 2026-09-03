# A1 Windows TPM rollback-guard evidence — 2026-09-03

**Checkpoint:** `A1-CP1-WIN`
**Maturity:** production-intent; implementation and live adversarial TPM tests pass,
but the final cross-reboot phase is still pending

## Device and toolchain

- Microsoft Windows 11 Home, version/build `10.0.26200`.
- TPM 2.0: Nuvoton `NTC` / `NPCT75x`, firmware `7.2.3.1`, spec
  `2.0, 0, 1.59`; present, ready, enabled, activated, owned; Windows managed
  authorization level `Full` and auto-provisioning enabled.
- Rust `1.98.0` (`x86_64-pc-windows-msvc`), Cargo `1.98.0`.
- Native backend: Windows TPM Base Services (TBS) for raw TPM 2.0 commands,
  Microsoft Platform Crypto Provider for the non-exportable RSA wrapping key,
  and `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` for state publication.

## Implemented boundary

`WindowsTpmRollbackGuard` uses a dedicated SHA-256 TPM NV extend index in the
TCG owner range. The index is selected from a scope-derived sequence with 32
bounded collision attempts. Its random 32-byte authorization is encrypted by a
user-scoped, non-exportable 2048-bit RSA key in the Microsoft Platform Crypto
Provider; only the ciphertext is stored. Provisioning is the only elevated
operation. Normal policy opens and advances run without elevation.

The exact state and pending records bind network, generation-1 bootstrap policy
ID, NV index, old/new generation and policy IDs, old/expected TPM digests, and
the transition input. Both codecs are bounded, domain-separated, checksummed,
and reject mutation, truncation, extension, and scope mismatch. A cross-process
scope lock serializes the state/TPM transaction. Authorization-bearing TPM
command buffers and decrypted authorization material are zeroized.

For an interrupted update, the pending journal accepts only two TPM states:

1. the exact old digest, in which case it performs the one pending extend; or
2. the exact expected successor digest, in which case it commits without a
   second extend.

Any other state fails closed. Missing NV state after an anchored lineage,
changed public attributes, missing CNG key, rollback, equivocation, skipped
generation, wrong scope, or read-back mismatch also fails closed. There is no
DPAPI, Credential Manager, file-only, or software fallback.

## Results completed on real hardware

- `cargo test -p vault-windows-platform -- --nocapture`: 2 passed. This opened
  real TBS, submitted TPM2 `GetCapability`, created/reopened/decrypted/deleted a
  real non-exportable Platform Crypto Provider key, and left no test key.
- `cargo test -p vault-wallet checkpoint_policy_store -- --nocapture`: 5 passed,
  1 real-TPM test ignored by default.
- `cargo test -p vault-wallet windows_tpm_guard -- --nocapture`: 4 passed; the
  live TPM, reboot phases, and subprocess helper are ignored by default.
- Elevated live guard test: passed. It provisioned one isolated NV index,
  advanced through three exact anchors, verified idempotence and reopen,
  rejected regression/equivocation and restored older state, exercised a real
  second-process lock contender, recovered both interruption boundaries, then
  deleted the exact NV index to model the observable post-clear state and
  verified fail-closed behavior. Exact test index, key, files, and directory
  were removed.
- Elevated policy-store integration: passed. It installed an authenticated
  generation-2 policy through the real TPM guard, restored the still-valid
  generation-1 policy file, and received `RollbackDetected`. Exact test index,
  key, files, and directory were removed.
- Strict affected Clippy passed with warnings denied.
- Full Windows workspace gate passed: formatting, 113 tests, strict Clippy for
  all targets, and rustdoc with warnings denied. Five hardware/phase tests are
  ignored by default and the two applicable live tests passed separately.
- WSL/Linux `cargo check --locked --workspace` and strict workspace/all-target
  Clippy passed, confirming the Windows-only crate does not break Linux builds.
- `cargo audit 0.22.2` found no vulnerability advisory in 187 locked
  dependencies. It reported the pre-existing allowed unmaintained warning
  `RUSTSEC-2023-0089` for target-specific `atomic-polyfill`; this change does not
  introduce that dependency.

The interruption cases above are deterministic process-crash boundary tests on
the real TPM, not a claim that AC power was physically removed at every CPU or
filesystem instruction.

## Remaining acceptance step

Phase one of the ignored cross-reboot sequence passed before a boot that Windows
reported as starting on `2026-08-29 20:13:38` local time. It intentionally left
the exact test state under `%TEMP%\Vault-A1-CP1-WIN-reboot-v1` and its isolated
TPM/CNG resources. Do not delete that directory or clear the TPM.

The ignored tests
`real_tpm_reboot_persistence_phase_one` and
`real_tpm_reboot_persistence_phase_two_and_cleanup` provide an explicit
cross-reboot sequence. Phase one leaves exactly one isolated test NV index,
non-exportable test key, and checksummed test state. After a real Windows
restart, phase two must reopen and advance the same anchor, then remove every
test artifact. `A1-CP1-WIN` remains unchecked until that sequence and the final
workspace/advisory gates are recorded. The immediate next action is a real
Windows restart followed by elevated phase two; phase two has not been run in
the current boot.

## Residual limits

- A process running as the same Windows user can ask the platform key to decrypt
  the NV authorization and can therefore destroy availability or advance the
  index incorrectly. It cannot use this adapter to roll the TPM digest backward.
- An administrator can clear the TPM or remove the NV index. Existing policy
  state then fails closed and requires the explicit bootstrap/recovery ceremony;
  the adapter does not silently recreate an anchored lineage.
- Windows owner authorization and elevation are required only for provision and
  exact acceptance-test cleanup. Enterprise command-blocking or TPM policy may
  intentionally refuse those operations.
- TPM NV endurance is finite. The checkpoint-policy log is already bounded to
  64 successor updates; compaction/re-bootstrap remains the separate `A1-CP3`
  operational gate.
- This closes neither concrete seed custody nor the wider A1/mainnet gates. No
  real funds may use the project.
