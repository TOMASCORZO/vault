# Proof parameter and setup assumptions

**Status:** specified; implementation remains production-intent and non-activatable
**Version:** 1
**Last updated:** 2026-08-30

## Scope

This document defines the setup assumptions for Vault's two H1 proof backends.
It records a reviewed non-activated Halo2 suite ID, but does not approve
consensus activation or replace proof-system and circuit review. The epoch
threshold burn key is a separate distributed-key lifecycle specified in
`BURN_ENCRYPTION.md`; it is not a proof-system structured reference string.

## Halo2 specialized transfer backend

Vault pins `halo2_proofs = 0.3.5`, the Pasta-cycle polynomial commitment used by
the vendored Orchard 0.15.5 circuit, and `PostNu6_3`. Its
`poly::commitment::Params::new(k)` derives every commitment generator by
hash-to-curve with the fixed `Halo2-Parameters` domain and an encoded generator
index. The additional blinding and challenge generators are derived by the same
fixed procedure. No secret scalar or ceremony transcript is an input.

Consequently this backend has a **transparent deterministic parameter
generation** assumption, not a structured trusted setup with toxic waste. Its
security still depends on all of the following:

- the pinned Halo2/Orchard implementation and its Fiat-Shamir transcript;
- the security of the selected Pasta curves, hash-to-curve construction, and
  discrete-log polynomial commitment;
- exact circuit shape, degree `k`, fixed columns, public-instance ordering, and
  verifying key;
- reproducible dependency source, compiler inputs, and generator derivation;
- rejection of insecure or unapproved Orchard circuit versions.

For the Orchard Action component, `k = 11` and the SHA-256 fingerprint of the
pinned `PostNu6_3` verifying-key description is:

```text
8d325ee6753c8effb7d5184bdd729255d2697dd1730c0278084cd91192020e90
```

The frozen monolithic Vault transfer shapes use `k = 15`, the smallest tested
degree supporting the maximum 16-action bucket. Parameters, VKs, and PKs are
derived deterministically for each of the 2/4/8/16-action shapes. The BLAKE3
derive-key digest of their pinned VK descriptions in ascending bucket order is:

```text
991523426f81b2350b1b08a7e2de9f60e334f344e40c23904c6dd8db5937c83a
```

The domain is
`vault.zk.halo2.monolithic-transfer-suite.2026-08-30`; each entry commits to
the little-endian `u16` bucket, little-endian `u64` pinned-description length,
and exact UTF-8 pinned description. Reproduction is locked to the repository
dependencies and toolchain because that debug representation is an input to
the identifier. C2 freezes this identity, while C4 must still publish canonical
serialized proof/vector artifacts and an offline verifier. The suite MUST remain
non-activatable until the remaining H1 closure and activation gates pass.

### Required production artifact procedure

For each approved action bucket, release engineering MUST:

1. build from the locked source and declared Rust target in an isolated,
   network-disabled reproduction step after dependencies are available;
2. deterministically derive parameters, VK, and PK for the exact circuit and
   `k` rather than accepting an opaque downloaded setup;
3. serialize each artifact canonically and publish its byte length plus a
   SHA-256 digest in the signed vector manifest;
4. reproduce the parameter and VK digests on at least two independent builders;
5. verify the PK corresponds to the published VK by creating and verifying the
   complete positive-vector set;
6. load artifacts only after checking the expected suite, length, and digest;
7. zeroize temporary witnesses and never interpret PK confidentiality as a
   security requirement—the PK is public but integrity-critical.

Any change to `k`, generator derivation, transcript, dependency version, circuit
shape, fixed columns, instance ordering, or VK creates a new suite. Silent
parameter substitution is forbidden.

## RISC Zero reference backend

Vault pins RISC Zero 3.0.6 and a guest image ID. This is a transparent
STARK/FRI-style zkVM backend and requires no per-circuit secret ceremony or
toxic-waste disposal. Verification trusts the pinned proof-system
implementation, its cryptographic constants and Fiat-Shamir construction, and
the exact guest image identified by the journal verifier.

An approved vector manifest MUST include the RISC Zero version, guest Rust
version, host target, guest image ID, public journal bytes and digest, receipt
encoding version, receipt length and SHA-256 digest. Development-mode receipts
remain forbidden. A guest image or proof-system change creates a new backend
version and requires new vectors, dependency audit, benchmarks, and review.

The existing accounting-only image and receipt are research artifacts. Their
parameter transparency does not cure the missing transfer constraints recorded
in `../research/RISC0-ACCOUNTING-V1.md`.

## Rotation, compromise, and deactivation

Because neither backend uses toxic waste, there is no secret setup material to
rotate or destroy. Parameter integrity, circuit soundness, and implementation
integrity can still fail. Consensus configuration MUST therefore bind one exact
composite circuit ID to its Action VK ID and accounting suite ID and MUST support
a governed future-height deactivation or migration. Nodes MUST reject unknown,
zero, malformed, or retired suite identifiers before expensive verification.

A parameter/VK mismatch, non-reproducible digest, proof-system vulnerability,
soundness finding, compromised release signing key, or unresolved critical/high
review finding blocks activation and triggers the incident/deactivation process.
Existing state must never be reinterpreted under replacement parameters; a new
suite requires explicit versioning and activation rules.

## Explicit non-claims

"No trusted setup" means only that proof parameters do not require a secret
ceremony. It does not mean that the circuits, dependencies, release artifacts,
hardware, wallet, burn DKG, consensus, or operations are trustless, audited, or
mainnet-ready.
