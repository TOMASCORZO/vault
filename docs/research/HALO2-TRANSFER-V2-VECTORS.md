# Halo2 transfer-v2 conformance vectors

**Generated:** 2026-08-25
**H1 item:** H1-C3
**Status:** all selected buckets have fixed real proofs; vector-locked,
unaudited, not activated, unsafe for real funds

## 1. Result and boundary

Vault now publishes one deterministic, self-contained Halo2 conformance vector
for each permitted transfer-v2 Action bucket: 2, 4, 8, and 16. Every positive
vector contains canonical effects, the complete synthetic private witness,
native Halo2 public-instance columns, and a real monolithic proof. Each also
defines an anchor-field mutation and a proof-byte mutation whose expected result
is rejection.

These vectors lock cryptographic test evidence; they do not install a consensus
adapter or activate their circuit IDs. The fixtures contain deliberately public
synthetic secrets and MUST NOT be used as wallet keys or with real funds. RISC
Zero receipts, performance acceptance, independent review, governance, H2
integration, and mainnet approval are outside H1-C3.

## 2. Locked suites and artifacts

The circuit ID is the H1-C3 suite identity derived by
`vault.zk.halo2.transfer-v2.monolithic-suite.v1`. It binds transfer-v2, Action
count, `k`, the fixed Action VK, transparent-parameter and composed-VK
fingerprints, the pinned Blake2b/Challenge255 transcript, and the public-instance
schema. The ID is vector-locked but not activated.

| Actions | `k` | Circuit/suite ID | Proof bytes | Proof section digest | Vector bytes | Vector SHA-256 |
|---:|---:|---|---:|---|---:|---|
| 2 | 14 | `ca5cd9ccbfa61d14eef161b6f6e752d4c14f7bd3b400061345dbc27f1c10f2dd` | 9,600 | `184f4a9f4b32031832cd848ad0901556479a9f3310165f73ad1a1ac0bee2f90a` | 20,714 | `c49c5d0538ca151ece2acb7dec0f21c1fc470a2f218992b85b475f838de2ef33` |
| 4 | 14 | `856a92a309c8261a44573f05be38258a5efcbdb1582c1138812d717c9720467a` | 9,600 | `6bd2ded26a0cb44455f398bc28fb605ddd90b8badcb43ab5590859e11b1b1093` | 30,192 | `6fe43d67c19227c379cefa472b87863e5bd8d07c01eee2fc2c6cb58e7310f0b1` |
| 8 | 14 | `185705dddefba9661c8b64dfbf370b1ae2b8fae1dcfb5f7fafcda3fc1f07a69c` | 9,600 | `b53225147e37cf67600a1c768ead0817c4ab0f6ec3963f9b8c59666bda29edf9` | 49,148 | `b72c16b5685b14a9b0bd8f31d344b3804bce5f3935f269930c52f82117449468` |
| 16 | 15 | `2f354b5dc833e61d958b6b2ee40fd516044d6d2f49f9ca57357c10e382eddbb5` | 9,664 | `34784aa4238caec4a1ad33d8f7e241ff9905369b880d04f4be3cf9f463017790` | 87,124 | `f19b65e9c25482606a7f4237aff9c1ff4323983b4ccaefbf91704f5986e9dd74` |

The proof digest is the vector section digest, not an untagged file hash:

```text
BLAKE3 derive-key context = vault.zk.halo2.transfer-v2-vector-section.v1
input = little_endian_u16(len("proof"))
     || "proof"
     || little_endian_u64(proof_length)
     || proof_bytes
```

The files are under `zk/halo2/core/vectors/transfer-v2/`. The same tagged rule
independently authenticates witness, effects, instances, proof, and mutated
effects before any cryptographic verification runs.

## 3. Canonical vector encoding

All integers are unsigned little-endian. Unknown versions, truncation, trailing
bytes, a zero mutation mask, an out-of-range mutation offset, or a section
digest mismatch are invalid.

```text
vector:
  magic                         [4] = "H2V1"
  version                       u16 = 1
  action_count                   u8
  k                             u32
  suite_id                     [32]
  proof_rng_seed               [32]
  section[5]:
    byte_length                 u32
    tagged_digest              [32]
  proof_mutation_offset         u32
  proof_mutation_xor             u8
  expected_positive              u8 = 1
  expected_field_mutation        u8 = 0
  expected_proof_mutation        u8 = 0
  witness              [declared length]
  canonical_effects     [declared length]
  public_instances      [declared length]
  proof                 [declared length]
  field_mutated_effects [declared length]
```

Section order and digest tags are exactly `witness`, `effects`, `instances`,
`proof`, and `mutated-effects`.

The public-instance section uses magic `H2I1`, version 1, Action count, column
count, then for each column a `u32` element count followed by canonical
32-byte little-endian Pallas-base-field representations. It contains exactly
two columns: ten Orchard instance values per Action, followed by the accounting,
gas, burn, epoch-key, and two complete-effects-digest limbs.

## 4. Synthetic witness fixture

The witness section uses magic `H2W1`, version 1, and binds the bucket, suite
ID, network, monetary maximum, fixture RNG seed, full viewing key, anchor, every
private Action witness, DKG descriptor, burn amount, burn-commitment trapdoor,
and burn-encryption randomness.

Each sorted Action entry contains its public nullifier, 115-byte private input
note, membership position and 32 authentication nodes, authorization randomizer,
net-value trapdoor, fixed 1,455-byte output-authorization packet with explicit
length, private input/output amounts, and taxable bit. This is enough private
material to independently reconstruct the selected statement; its exact bytes
are compared against the deterministic fixture on every vector test.

Every bucket proves the same economic operation:

```text
real input 0       = 5,051
external output   = 5,000
real input 1       = 1,000
internal change   = 1,000
dummy pairs        = bucket - 2, each 0 -> 0
taxable amount     = 5,000
burn               = ceil(5,000 / 200) = 25
gas                = 2 * 13 = 26
total inputs       = 6,051
total outputs      = 6,000
6,051              = 6,000 + 25 + 26
```

Actions are sorted by their derived nullifier before effects, accounting, and
circuit witnesses are assembled. Dummy Actions have distinct valid notes,
nullifiers, commitments, encryption, and authorization material while their
constrained values and accounting contribution are zero.

## 5. Positive and adversarial expectations

For every bucket, the test performs the following in order:

1. decode the bounded vector and verify every section digest;
2. reconstruct the deterministic fixture and compare witness, effects, and
   public instances byte for byte;
3. derive the selected transparent parameters and VK from the witness-free
   circuit;
4. verify the committed proof against effects-derived public instances;
5. replace the canonical anchor with the distinct canonical empty-tree anchor
   and require the unchanged proof to fail;
6. XOR the declared middle proof byte with `0x01` and require verification to
   fail.

The field mutation changes a real public Action instance as well as the complete
effects digest. The proof mutation remains length-canonical, so rejection comes
from Halo2 verification rather than a superficial length check.

## 6. Reproduction

From the repository root:

```sh
cd zk/halo2
cargo run --release --locked -p vault-zk-halo2-core \
  --example generate_transfer_vectors
cargo run --release --locked -p vault-zk-halo2-core \
  --example inspect_transfer_vectors
cargo test --release --locked -p vault-zk-halo2-core \
  --test conformance_vectors
cd ../..
./scripts/check-zk-halo2.sh
```

Generation uses the fixed proof seeds recorded inside each vector. Regeneration
must reproduce the complete vector SHA-256 values in section 2. A mismatch in
the fixture, circuit, parameter set, VK, transcript, instance order, proof RNG,
or encoding requires a new suite identity or an explicit reviewed explanation;
an existing vector must never be silently replaced.

H1-A1 still requires two isolated clean same-host builds, cached-key and
target-hardware measurements, malformed-input fuzzing, dependency remediation,
and release-artifact repeatability. This does not provide cross-host
reproducibility; the common-mode limitation is accepted and recorded in the H1
closure matrix. H1-A4 still requires independent cryptography review and
explicit activation/deactivation governance. Those omissions keep these suites
below release-candidate status.
