# Dependency Audit — 2026-08-21

This is point-in-time evidence, not a warranty that dependencies are safe.

Reverified on 2026-08-23 after the transfer-v2 monolithic public-input boundary,
canonical local signer session, confirmed Noise XX/KK lifecycle,
crash-consistent Unix signer stores, canonical compact block, finalized local
wallet scanner, and encrypted transactional ShardTree wallet database were
extended through authenticated streaming backup, non-empty restore, and
finalized birthday-frontier recovery initialization, then deterministic
multi-batch seed-account discovery, encrypted durable recovery progress, and the
bounded finalized-recovery coordinator/source boundary. The
vulnerability result and allowed inactive warning were unchanged; the current
workspace lockfile resolves 171 packages. The database added the directly
pinned `shardtree` and `rusqlite` graph described below.

```text
Tool: cargo-audit 0.22.2
Input: workspace Cargo.lock after wallet finalized-recovery coordinator integration
RustSec advisories loaded: 1,225
Crate dependencies scanned: 171
Known vulnerabilities detected: 0
Allowed warnings: 1
```

The warning is `RUSTSEC-2023-0089` for unmaintained `atomic-polyfill 1.0.3`.
It is present only in Cargo's lock resolution for an inactive optional chain:
`reddsa` FROST support → `frost-core` → `postcard` → `heapless` →
`atomic-polyfill`. `vault-privacy` builds Orchard with `default-features = false`
and only `std`; `cargo tree` confirms this chain is not in the compiled target
graph. Vault does not enable Orchard's `unstable-frost` feature. The warning
remains tracked because future feature changes could activate it.

Command:

```bash
./scripts/audit.sh
```

The audit covers published RustSec advisories only. It does not detect unknown
vulnerabilities, malicious-but-unreported packages, logic defects, unsafe build
infrastructure, compromised registries, or errors in Vault's own code. Every
future dependency change requires a fresh scan and dependency-review approval.

New privacy dependencies are pinned at `orchard = 0.15.5` and
`zcash_note_encryption = 0.4.2`. Orchard's default circuit and multicore features
are disabled in the wallet-facing crate. Version 0.15.5 includes canonical
proof-size and non-identity action-key hardening from the 2026 coordinated Zcash
disclosures, but this point-in-time scan does not replace a Vault integration
audit.

The signer transport pins `snow = 0.10.0` and `x25519-dalek = 2.0.1`.
`snow` declares Rust 1.85 and Apache-2.0 OR MIT licensing; Vault disables its
broad default feature set and enables only the resolver components required by
the selected `25519/ChaChaPoly/BLAKE2s` profile plus entropy for ephemeral
handshake keys. The active addition resolves through `curve25519-dalek 4.1.3`,
`chacha20poly1305 0.10.1`, and `blake2 0.10.6`; the latter two were already
present or share existing RustCrypto primitives. The MSRV check passes on Rust
1.85.1. This provenance and advisory scan do not replace an independent Noise
integration, pairing, key-storage, or side-channel review.

The encrypted peer registry now uses `chacha20poly1305 = 0.10.1` directly with
default features disabled and only `alloc` enabled. The package was already in
the active graph through the pinned Noise/privacy primitives, so making the
XChaCha20-Poly1305 storage use explicit did not increase the resolved package
count. It is RustCrypto software under Apache-2.0 OR MIT; it does not declare a
machine-readable MSRV, while the exact workspace passes Rust 1.85.1. Fresh
nonce generation, scope-separated key derivation, fixed-size envelope framing,
keychain integration, and filesystem rollback behavior still require an
independent implementation review.

The Unix replay profile pins `fs2 = 0.4.3` for advisory process locking and
`tempfile = 3.27.0` for same-directory temporary-file persistence. `fs2` is
MIT/Apache-2.0 but declares no machine-readable MSRV; the exact graph passes
Vault's Rust 1.85.1 test gate. `tempfile` is MIT OR Apache-2.0 and declares Rust
1.63. The direct `libc = 0.2.189` pin supplies the platform `O_NOFOLLOW` flag;
the workspace forbids unsafe code. `rustix = 1.1.4`, already present through
`tempfile`, is now also a direct Unix dependency with only `std` and `process`
enabled so ownership checks obtain the effective UID without local unsafe code.
The active store graph also includes `getrandom 0.4.3`; the Windows-only `winapi`
packages added to the lockfile are inactive. RustSec reports no known
vulnerability in this addition. This review does not establish filesystem
power-loss behavior, same-account process isolation, snapshot-rollback
resistance, or cross-platform durability; those require platform testing and
independent review.

The wallet witness backend pins `shardtree = 0.7.1`, maintained in Zcash's
`incrementalmerkletree` repository under MIT OR Apache-2.0 with declared Rust
1.64 MSRV. Version 0.7.1 includes the July 2026 checkpoint-truncation and cached
root consistency fixes. Vault uses depth 32, shard height 16, bounded ordinary
checkpoints, canonical encrypted tree/checkpoint codecs, and independently
compares the reconstructed root and maximum position with the authenticated
wallet tip. This reuse and advisory result do not replace fuzzing or an
independent review of Vault's `ShardStore` adapter.

Transactional persistence pins `rusqlite = 0.40.2` with default features off
and only bundled SQLite plus its online-backup API enabled, resolving through
`libsqlite3-sys 0.38.2` plus
seven small build/iterator/support packages. Rusqlite is MIT licensed and does
not declare a machine-readable MSRV; the exact graph compiles, tests, lints, and
documents under Vault's Rust 1.85.1 toolchain. The bundled build removes a
runtime dependency on an unknown system SQLite. Vault selects rollback-journal
`DELETE`, `synchronous=EXTRA`, `fullfsync`, defensive mode, no-follow opening,
and an exclusive sibling lock; crash/power-loss/disk-full fault injection and
platform filesystem validation remain mandatory.

The V1 backup container reuses the pinned BLAKE3, XChaCha20-Poly1305,
`tempfile`, `rustix`, and `rusqlite` graph; no new resolved package was added.
It streams a SQLite online snapshot through fixed authenticated chunks instead
of introducing an archive or compression dependency. Dependency reuse does not
replace cryptographic-format review, restore drills, or filesystem fault
injection.
