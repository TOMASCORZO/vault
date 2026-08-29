# Halo2 setup and lifecycle

**Normative H1-C2 record with H1-C3 addendum:** 2026-08-25
**Status:** selected transfer setup documented, reproducible, and vector-locked;
transfer suites are not reviewed or activated
**Maturity:** production-intent, unaudited, not safe for real funds

## 1. Scope and decision

Vault selects the specialized Halo2 construction in `zk/halo2` for H1 private
transfers. RISC Zero remains an isolated conformance oracle and is not a second
transfer backend. This record fixes the setup assumptions, current parameter
and verifying-key identities, reproduction procedure, and lifecycle rules. It
does not activate a verifier, implement governance, or authorize mainnet use.

The selected Halo2 polynomial commitment parameters are transparent. They are
derived deterministically and contain no secret contribution, ceremony output,
toxic waste, or validator-generated material. Proving and verifying keys are
then derived deterministically from those parameters and the witness-free
circuit shape. Proving-key custody is an integrity and availability concern,
not a trusted-setup secrecy assumption.

## 2. Selected construction and parameters

The workspace pins `halo2_proofs 0.3.5` with `batch`,
`floor-planner-v1-legacy-pdqsort`, and `multicore`, and pins
`halo2_gadgets 0.5.0`, `pasta_curves 0.5.2`, and the vendored
`orchard 0.15.5`. The commitment curve is Vesta (`EqAffine`) and its scalar
field is the Pallas base field used by the circuit.

`Params::<EqAffine>::new(k)` derives its generators with the
`Halo2-Parameters` hash-to-curve domain. Generator `i` uses the five-byte
message `0x00 || little_endian_u32(i)`; `w` and `u` use the one-byte messages
`0x01` and `0x02`. The Lagrange generators are derived from those generators
by the implementation's inverse FFT. No entropy or external parameter file is
accepted by this path.

The canonical parameter fingerprint is:

```text
BLAKE3 derive-key context = vault.zk.halo2.parameters.v1
input = little_endian_u64(len(Params::write bytes)) || Params::write bytes
```

| Use | `k` | Canonical bytes | Parameter fingerprint |
|---|---:|---:|---|
| Hardened Orchard `PostNu6_3` Action | 11 | 131,140 | `3809faf067490bd7a4cb30586acef438b1a835e156204ed6aeb735d0cf9d2f1f` |
| Transfer-v2 buckets 2, 4, and 8 | 14 | 1,048,644 | `a9415b7c41b8e8ab0a9b9219b423d4ef0984da3130f48b307250cb9c94cfa209` |
| Transfer-v2 bucket 16 | 15 | 2,097,220 | `250b53597cb342b5509343b50302d17e613507baa8e39c818fa4af258cd85a34` |

The 16-Action shape does not fit at `k = 14`; deterministic key generation
fails with `NotEnoughRowsAvailable`. The selected mapping is therefore `k = 14`
for 2/4/8 and `k = 15` for 16. `vault_transfer_k` and the witness-free circuit
constructor reject every non-canonical bucket instead of letting tooling assign
it an accidental identity.

`ACCOUNTING_ARITHMETIC_K = 12`, `BURN_BINDING_TEST_K = 14`, and the standalone
`ACCOUNTING_BURN_K = 14` are test-component sizes. Those standalone circuits
are deliberately non-activatable and have no selected suite or verifying key.

## 3. Verifying-key identities

### Fixed Action key

Every composed Action uses `OrchardCircuitVersion::PostNu6_3`. Its fixed
verifying-key identity is the SHA-256 digest of Orchard's canonical pinned
description at
`vendor/orchard/src/circuit_data/circuit_description_post_nu6_3`:

```text
8d325ee6753c8effb7d5184bdd729255d2697dd1730c0278084cd91192020e90
```

This value is also `ACTION_VERIFYING_KEY_ID`. It identifies the exact Action
constraint system and fixed columns, not merely the `PostNu6_3` label.

### Selected composed-transfer keys

For the composed transfer circuit, the reproducibility tool constructs each
witness-free canonical bucket, runs `keygen_vk`, formats `vk.pinned()` with the
pinned Halo2 implementation, and computes:

```text
BLAKE3 derive-key context = vault.zk.halo2.verifying-key.v1
input = little_endian_u64(len(pinned UTF-8 bytes)) || pinned UTF-8 bytes
```

| Action bucket | `k` | Pinned bytes | VK fingerprint |
|---:|---:|---:|---|
| 2 | 14 | 412,236 | `01827af9610efb6a76292477292deca75f7a5d2480f13f502fb6ec3f677b2df9` |
| 4 | 14 | 411,053 | `19da82d8087f4e3fa2bcb90d1eb18bd503fbe948a7a9128ea27923540201f43e` |
| 8 | 14 | 411,053 | `b8d1b7d00b237e1ca4649f3fba4a63fd2fe8002308d833f958309747aff2456e` |
| 16 | 15 | 411,053 | `23d1953c70e903194e65a19f6fd80f5beddb5477076e84dc04e263510ec2140c` |

These are the exact VKs used by the H1-C3 all-bucket conformance vectors. If
later work reveals a constraint or public-instance defect, the circuit must
change, this record must be amended, and every affected fingerprint, suite ID,
and vector must be regenerated. A changed key must never inherit an old
identifier.

### Vector-locked suite identities

H1-C3 derives one distinct identity per exact bucket from transfer-v2, Action
count, `k`, the fixed Action VK, parameter fingerprint, composed VK
fingerprint, transcript, and instance schema:

| Actions | Suite/circuit ID | Proof bytes |
|---:|---|---:|
| 2 | `ca5cd9ccbfa61d14eef161b6f6e752d4c14f7bd3b400061345dbc27f1c10f2dd` | 9,600 |
| 4 | `856a92a309c8261a44573f05be38258a5efcbdb1582c1138812d717c9720467a` | 9,600 |
| 8 | `185705dddefba9661c8b64dfbf370b1ae2b8fae1dcfb5f7fafcda3fc1f07a69c` | 9,600 |
| 16 | `2f354b5dc833e61d958b6b2ee40fd516044d6d2f49f9ca57357c10e382eddbb5` | 9,664 |

The exact fixtures, public instances, proof digests, mutations, and artifact
hashes are recorded in
[`../research/HALO2-TRANSFER-V2-VECTORS.md`](../research/HALO2-TRANSFER-V2-VECTORS.md).
These IDs are vector-locked test identities, not an activation allow-list.

## 4. Reproduction contract

The authoritative H1-C2 reproduction environment is:

- `rustc 1.96.1 (31fca3adb 2026-06-26)` and Cargo 1.96.1, pinned by
  `zk/halo2/rust-toolchain.toml`; the declared crate MSRV remains 1.85.1;
- `zk/halo2/Cargo.lock` SHA-256
  `b787893cec3c55be6852bb09d4729d1920dee4689974cab94500cb7820f19a0b`;
- `halo2_proofs 0.3.5` registry checksum
  `f5aca1c66059a919227dec97444a11a4350d2f9c820ca48690988f0aa0e81cbf`;
- `halo2_gadgets 0.5.0` registry checksum
  `fb2a697cad929f706b7987fe804ad57d43622cd37463ba7e4d662a926fdcfea3`;
- `pasta_curves 0.5.2` registry checksum
  `3437083215c505e867eea5478371feba43d7689d6d15ec0a209eb46fb0d4cda6`;
- the exact feature set named in section 2 and the vendored Orchard source.

For the current uncommitted H1 source snapshot, the shape-defining SHA-256
digests are:

| Source | SHA-256 |
|---|---|
| `zk/halo2/Cargo.toml` | `c9a355811cb643a935dfec518b0695ed389146af892b71cdc118be41f7de446e` |
| `zk/halo2/core/Cargo.toml` | `8cc01fc800d20aead32d284bd294b29a5b1db47daa780631def5e259346c3ef0` |
| `zk/halo2/rust-toolchain.toml` | `d378cc6bc4c46cf85f3bc26a191bcb13a6f9efab78f758b39029555f88dc6e79` |
| `zk/halo2/core/src/accounting.rs` | `9a52498e9726c9624affaf48599a0bca8ec8bb6bd7d70c183da9724640fd9f36` |
| `zk/halo2/core/src/burn_binding.rs` | `f726eeabf225b0343ae2776d1bc0b5ce193874efa978cb04d8168e3794ace2f5` |
| `zk/halo2/core/src/transfer_circuit.rs` | `6602c7016ab412bddbac94f6e863474abc9fe501b66c576ced74601ac7354c19` |
| `zk/halo2/core/src/suite.rs` | `7d9c0c0e241f8b9fa7ba6730e499e333f6c15bbd184f6228fc466ff7a0e8596b` |
| `zk/halo2/core/examples/setup_manifest.rs` | `e7696edc7f9e3b2f8fa12745df5a4acc097c1b51c3bec28d2af1ce970f857f0b` |
| `vendor/orchard/src/circuit.rs` | `eb28ba78b2b6729816e35bce823cd83124f6f93697eecae39071d596666ff8c9` |
| Orchard `PostNu6_3` pinned description | `8d325ee6753c8effb7d5184bdd729255d2697dd1730c0278084cd91192020e90` |

From the repository root, reproduce the setup with:

```sh
cd zk/halo2
cargo run --release --locked -p vault-zk-halo2-core --example setup_manifest
cd ../..
./scripts/check-zk-halo2.sh
```

An acceptable reproduction must regenerate every parameter and VK fingerprint
exactly and pass the Halo2 gate. Before activation, the same output must be
confirmed in two fresh isolated build/target roots on the declared owned
acceptance host. Copying a pre-generated parameter, PK, or VK file without
regenerating and checking its identity is insufficient. This same-host
repeatability is explicitly not independent reproduction and retains the
common-mode host/toolchain risk accepted in `docs/H1_CLOSURE_MATRIX.md`.

The proving key is deterministically derived by `keygen_pk` from the same
parameters, VK, and witness-free circuit. If a cached or distributed PK is
introduced, its canonical serialization, digest, origin, permissions, and
reconstruction check become mandatory manifest fields. Cached-key startup,
storage, peak memory, and rebuild timing remain H1-A1 performance work.

### Selected H1-A1 startup strategy

The selected pre-activation deployment design does not persist or distribute a
PLONK PK or VK. The pinned `halo2_proofs 0.3.5` release has no canonical PK/VK
serialization, and Vault does not define an ad hoc encoding for opaque upstream
types. Each process instead reconstructs its required material exactly once at
startup and retains it in memory:

1. derive `Params::<EqAffine>::new(k)` for the selected suite;
2. serialize those parameters only to recompute and compare the canonical
   parameter fingerprint above;
3. derive the VK with `keygen_vk` from the witness-free selected circuit and
   compare its pinned fingerprint with `VaultTransferSuite`;
4. on a prover only, derive the PK with `keygen_pk` from that validated material;
5. abort startup on any suite, parameter, circuit-shape, or VK mismatch.

Key reconstruction is eager, never performed per transfer, and a process does
not become eligible to prove or verify until every configured suite has passed
the identity checks. The serialized-parameter load path remains benchmark and
reconstruction evidence, not selected persistent deployment state. Local H1-A1
measurements accepted the one-time verifier reconstruction range of 20.857 to
53.874 seconds and prover-material reconstruction range of 34.417 to 80.800
seconds on the 8 GiB M1 host. Target-hardware repetition remains mandatory, but
the absence of a PK/VK cache is now an explicit bounded design rather than an
unfinished file format.

Introducing persistence later is a replacement of this startup design and must
first supply the reviewed canonical encoding, integrity, provenance,
permissions, atomic publication, corruption handling, and rebuild comparison
requirements stated above.

The proof transcript is the pinned Halo2 Blake2b transcript with
`Challenge255<EqAffine>`. Changing the transcript, curve, `k`, feature set,
floor planner, dependency version, circuit source, fixed columns, instance
column order, or canonical proof encoding creates a new setup identity.

## 5. Lifecycle and fail-closed rules

Each transfer setup moves only through these states:

1. **candidate** — parameters and VK reproduce, but no conformance-vector or
   review claim exists;
2. **vector-locked** — H1-C3 binds the exact setup, public instances, proof
   encoding, and positive/adversarial vectors for every bucket; this is the
   current state;
3. **reviewed** — H1-A1 and H1-A4 evidence and independent review are complete;
4. **activated** — a later governed consensus configuration explicitly admits
   the exact circuit identity at a defined height or epoch;
5. **deprecated/deactivated** — construction of new transfers stops at the
   governed boundary, while historical verification needed for replay and
   state reconstruction remains available.

Activation is an allow-list operation. Unknown, candidate, deprecated after its
cutoff, malformed, or mismatched identities fail closed. There is no automatic
downgrade, “latest” alias, RISC Zero fallback, verifier bypass, or reuse of an
old identity for changed semantics.

An upgrade must allocate a distinct circuit/suite identity and independently
repeat setup reproduction, vectors, resource bounds, and review. The activation
window must state whether old and new suites overlap and when wallets stop
constructing the old form. Emergency deactivation disables new acceptance of
the exact affected suite; it must not reinterpret existing proof bytes under a
replacement VK. Governance messages, validator distribution, height/epoch
plumbing, and historical-verifier retention implementation belong to H2 and
H1-A4, not H1-C2.

## 6. Why RISC Zero is not selected

The maintained RISC Zero guest is valuable as an independently structured
transfer-v2 conformance oracle. It is not selected for transfer proofs because
its VM and receipt lifecycle add a larger dependency and attack surface, the
historical accounting-only proof was 256,266 bytes and took about 176 seconds,
and the complete transfer-v2 proving attempt was stopped after about 2 hours 48
minutes without a receipt. It also has no consensus adapter in Vault.

That terminated run is negative performance evidence, not evidence that the
statement is invalid. A RISC Zero receipt is not required by H1-C2 or H1-C3,
and the zkVM must not be placed in the normal transfer flow as a fallback. Any
future unrelated use requires a new scoped decision and its own lifecycle.

## 7. DKG trust is separate

Halo2 setup and burn-key DKG solve different problems and share no secret.
Halo2 parameters and proof keys are deterministic and transparent. The burn
DKG instead produces an epoch-specific threshold-ElGamal public key and secret
shares held by validators. Its trust assumption is that fewer than the
configured threshold collude or disclose shares; a threshold can decrypt an
individual ciphertext, so threshold honesty and the H1-C4 aggregation policy
remain part of the privacy model.

The circuit binds the complete canonical Feldman-commitment descriptor through
its scheme ID, key ID, epoch, threshold, participants, coefficient commitments,
and reconstructed `PK_epoch`. The DKG contributes no Halo2 generator, trapdoor,
PK, or VK. Conversely, reproducing a Halo2 VK does not validate a DKG run.

H1-C4 owns aggregate opening, bounded discrete-log recovery, low-volume and
timeout policy, and malicious-share behavior. DKG networking, complaints,
resharing, validator rotation, share publication, consensus finality, and
equivocation handling remain H2. None of them is silently pulled into H1-C2.
