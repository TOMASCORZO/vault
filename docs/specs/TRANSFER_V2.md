# Vault transfer-v2 consensus envelope

**Maturity:** production-intent, not activated
**Codec version:** 2  
**Normative implementation:** `crates/vault-protocol/src/transfer_v2.rs`  
**State transition:** `crates/vault-protocol/src/state_v2.rs`

This document specifies the unique byte encoding and host-side state transition
for native-VLT shielded transfers. It does not claim that the transfer is safe:
the specialized circuit, burn-encryption construction, persistence layer,
benchmarks and internal security review remain release blockers.

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and
MAY are consensus requirements.

## 1. Design constraints

Transfer-v2 replaces transfer-v1's opaque commitments and variable note
ciphertexts with canonical `vault-privacy` values. A bundle:

- uses Ironwood V3 notes and the hardened Orchard-protocol Action construction;
- pairs exactly one spend with one output in every action;
- includes dummy actions in the same public shape as real actions;
- signs the complete public effects under a fresh randomized RedPallas key per
  action;
- binds those effects to an activated circuit ID and recent note-tree root;
- carries a fixed-size hidden-burn payload pinned to a scheme, threshold key,
  and epoch;
- has one canonical byte representation for network, storage, public-input
  hashing, and transaction identification.

The public action count leaks one padding bucket. Version 2 permits exactly 2,
4, 8, or 16 actions. Wallets MUST select the smallest bucket that contains all
real spends and outputs, fill every remaining position with circuit-valid dummy
actions, and sort all actions by canonical nullifier bytes. A different policy
requires a new activated version or an explicitly compatible specification.

## 2. Canonical encoding

All integers use unsigned little-endian encoding. No variable-length integer is
accepted. All point and field encodings MUST be canonical according to the
pinned Orchard/RedPallas implementation. Unknown versions, truncation, trailing
bytes, reserved zeros, and non-canonical encodings are invalid.

```text
effects_header:
  magic                         [4] = "VLT2"
  version                       u16 = 2
  chain_id                     [32]
  circuit_id                   [32]
  note_tree_anchor             [32]
  burn_scheme_id               [32]
  burn_key_id                  [32]
  burn_epoch                    u64
  burn_value_commitment        [32]
  burn_ciphertext              [64]
  gas_units                     u64
  fee_per_gas                   u64
  action_count                   u8

action[action_count]:           852 bytes each
  nullifier                    [32]
  randomized_spend_key         [32]
  net_value_commitment         [32]
  output_note_commitment       [32]
  output_value_commitment      [32]
  output_ephemeral_key         [32]
  recipient_ciphertext        [580]
  outgoing_ciphertext          [80]

authorizing_data:
  proof_length                  u32
  proof                [proof_length]
  spend_signature[action_count][64]
```

The effects header is 287 bytes. One two-action transaction with a 32-byte test
proof is 2,155 bytes. Production proof size is backend-dependent and MUST NOT
exceed 2 MiB. The absolute v2 decoder bound is 2,112,099 bytes. The decoder MUST
check this bound before allocating from attacker-controlled lengths.

Actions MUST be strictly sorted by nullifier bytes. Nullifiers, randomized spend
keys, output note commitments, output value commitments, and ephemeral keys
MUST be unique within a transaction. Randomized spend keys and ephemeral keys
MUST NOT be the identity. The burn scheme ID, burn key ID, burn commitment, and
burn ciphertext MUST NOT use their reserved empty representations.

## 3. Digests and authorization

The canonical effects and authorization digest is:

```text
BLAKE3-DERIVE(
  "vault.protocol.transfer-v2.public-inputs.2026-08-22",
  canonical_effects_bytes
)
```

Every action signs the same effects digest under its published randomized
RedPallas validating key. The signed message is separately derived by
`vault-privacy` from the 32-byte chain ID and public-input digest using:

```text
vault.privacy.spend-authorization-v1.2026-08-21
```

Signatures exclude proof bytes so proving MAY finish after the effects are
authorized. They MUST match the randomized keys already committed by the
effects. The transaction identifier covers the entire canonical encoding,
including the exact proof and signatures:

```text
BLAKE3-DERIVE(
  "vault.protocol.transfer-v2.transaction-id.2026-08-22",
  canonical_transaction_bytes
)
```

Changing proof bytes therefore changes txid but cannot change authorized
effects. Global nullifier rejection prevents accepting a second proof for the
same spend.

## 4. Required circuit statement

The activated circuit MUST independently constrain all host-parsed public
fields. For each non-dummy action it MUST prove:

1. membership of the input note in `note_tree_anchor`;
2. ownership by the spending key whose authorizing key is randomized into the
   public action key;
3. correct, domain-separated nullifier derivation;
4. correct opening of input, net-value, output-value, note, and burn
   commitments;
5. output `rho` equality to the paired action nullifier;
6. exact recipient and outgoing ciphertext construction or a reviewed
   proof-equivalent binding mechanism;
7. range constraints before every arithmetic operation;
8. proof-derived classification of external recipient and internal change;
9. exact native-VLT conservation including gas and the ceiling 0.5% burn;
10. equality of the encrypted burn plaintext and committed burn amount;
11. zero contribution and indistinguishable public shape for dummy actions;
12. recomputation of the transfer-v2 public-input digest inside the proof
    system or equivalent constraints over every field.

The specialized proof-verifier interface receives the complete typed effects,
not only this digest, so Halo2-style backends can construct their native public
instance columns. A backend that accepts only the digest MUST constrain the
same digest computation inside its proof.

Host signature checks do not prove note ownership; that remains an Action
circuit obligation. Canonical parsing alone also does not prove that a note
ciphertext carries the intended private data. Vault's selected
proof-equivalent policy therefore requires the proof to bind the complete
canonical effects digest and requires every signer to reconstruct and validate
the full output before authorizing that digest. The normative signer packet and
verification implementation are present with production intent, but durable
wallet, UX, vector, hardware, and internal-review gates remain open, so
transfer-v2 MUST NOT be activated. See
[`../architecture/NOTE_CIPHERTEXT_POLICY.md`](../architecture/NOTE_CIPHERTEXT_POLICY.md).

### 4.1 Composite proof encoding

The production-intent Halo2 backend reserves this exact payload inside the
outer `proof[proof_length]` bytes:

```text
magic                         [4] = "VZK2"
composite_version             u16 = 1
action_verifying_key_id      [32]
accounting_suite_id          [32]
action_count                   u8
action_proof_length           u32
accounting_proof_length       u32
action_proof       [action_proof_length]
accounting_proof [accounting_proof_length]
```

The Action verifying-key ID is the SHA-256 digest of the pinned Orchard 0.15.5
`PostNu6_3` verifying-key description. Action proof length MUST equal
`2720 + 2272 × action_count`; for two actions it is 7,264 bytes. The accounting
suite ID and proof MUST be non-zero/non-empty, all lengths MUST fit the outer
2 MiB limit, and trailing bytes are invalid. The activated circuit ID is a
domain-separated digest of the composite version and both suite IDs.

The Action proof alone is never a valid transfer-v2 proof. The consensus
adapter verifies both layers against the same complete effects and the
repository supplies no permissive accounting verifier.

The accounting implementation contains a range-constrained Halo2 circuit for
all four action buckets. Its first monolithic composition now reuses the exact
`v_old` and `v_new` cells already constrained by each hardened Action, and a
private zero-tax label enforces equality of all four old/new expanded-receiver
coordinates. It derives the private dummy marker exactly from zero linked input
and output values, and also proves rolling totals, public gas
multiplication, `taxable = 200q + r` with `r in [0, 200)`,
`burn = q + is_nonzero(r)`, exact conservation, and the burn commitment plus
both threshold-ElGamal equations from the same burn cell. The validator now
checks `scheme_id`, `key_id`, and epoch against the complete activated DKG
descriptor, reconstructs exact `PK_epoch` coordinates, and supplies the full
256-bit effects digest as two lossless public limbs constrained by Halo2. It is
not assigned a suite ID and cannot satisfy a consensus verifier until the
signer-side note-ciphertext policy, all-bucket vectors, benchmarks, and review
gates are complete.

A real two-action proof of the earlier accounting/burn-only shape is 5,504
bytes. The first monolithic Action/accounting/burn shape was 9,504 bytes; after
epoch-descriptor reconstruction and full effects-digest binding, the current
shape is 9,600 bytes and rejects proof-byte, Action-instance, and digest-instance
mutations. These sizes are engineering evidence only: neither proof is
consensus-valid and the monolithic shape may still change before review.

## 5. State transition

Before proof verification, consensus MUST reject:

- another chain, circuit, burn scheme, burn key, or burn epoch;
- an anchor outside the configured recent-root window;
- a nullifier already present in global state;
- a repeated or previously appended output commitment;
- invalid action signatures;
- a gas bid below the minimum or gas units different from
  `base_gas + per_action_gas * action_count`;
- a bundle that would exceed the depth-32 note-tree capacity.

Consensus then verifies the proof against the exact public-input digest. Only
after success may it atomically record every nullifier, append every real and
dummy output commitment in action order, publish the derived post-state root,
and credit the public gas fee. Any failure MUST leave all state unchanged. The
accepted-anchor window advances once per finalized block, not once per
transaction, so all transactions in a block may use the same eligible
pre-block root.

The H1 implementation starts from the canonical empty tree. Authenticated
durable restoration of the tree, commitment index, nullifier set, and recent
anchors is not implemented and remains an H2 blocker.

## 6. Burn encryption and activation

The selected production candidate is 64-byte exponential ElGamal over Pallas:

```text
C1 = [r]G
C2 = [burn]H + [r]PK_epoch
```

`G` is the Pallas generator and `H` is independently hash-to-curve derived.
Both components use canonical 32-byte compressed encodings. The frozen scheme
ID is:

```text
979c61f6d12a25da66d5cffc659cb996d6f2cb1291ad31ce9dc0e93146996f82
```

`burn_key_id` commits to the epoch, threshold, sorted Shamir evaluation points,
and all Feldman polynomial coefficient commitments; `burn_epoch` prevents
accepting a retired key. Ciphertexts aggregate by component-wise point addition.
The implementation validates keys, encrypts, parses, aggregates, produces and
verifies Chaum-Pedersen/DLEQ decryption shares, interpolates an exact threshold
subset, and proves the two per-transfer ciphertext equations against the exact
descriptor-derived epoch key. DKG, share-publication consensus, bounded
aggregate discrete-log recovery, rotation, low-volume policy, and activation
of the final verifier remain blockers.

Arbitrary 64-byte payloads are not valid merely because they parse. For this
scheme ID the codec requires two canonical Pallas points and non-identity `C1`;
the activated circuit must additionally prove both equations and equality with
the committed exact burn. See
[`../architecture/BURN_ENCRYPTION.md`](../architecture/BURN_ENCRYPTION.md).

Activation requires a governed height containing the exact codec version,
circuit ID, burn scheme ID, burn key ID, gas schedule, proof-size policy, and
recent-anchor window. Transfer-v1 MUST NOT acquire v2 meaning and MUST be
explicitly disabled before real funds can enter v2 state.

## 7. Frozen test vector

The deterministic two-action vector in `crates/vault-protocol/tests/transfer_v2.rs`
commits to:

```text
public_inputs = 5b46bbd5050150a9dceac4fdfb57922b60be3ab51879896fedab21a297a77237
transaction_id = a63b1f146782592d887951d0b21b815352ab84e078291f9867ce3482cdf10059
encoded_length = 2155
```

This pre-activation vector supersedes the Orchard-V2 fixture after the reviewed
Ironwood-V3 suite migration and correction of the fixture's net-value
commitments. Any post-activation semantic or codec change MUST use a new
domain/version and publish new cross-implementation vectors. Updating a vector
to conceal an accidental change is a consensus failure.
