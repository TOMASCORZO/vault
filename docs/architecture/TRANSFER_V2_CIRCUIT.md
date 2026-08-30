# Transfer-v2 specialized circuit

**Status:** production-intent implementation in progress; not activatable  
**Last updated:** 2026-08-30
**Code:** `zk/halo2/core`, `zk/halo2/core/src/accounting.rs`,
`crates/vault-privacy/src/circuit.rs`

## Frozen backend

Vault uses the Ironwood V3 instantiation of the Orchard protocol from
`orchard = 0.15.5` with `OrchardCircuitVersion::PostNu6_3`. The Action circuit
has degree parameter `k = 11`. Its exact pinned verifying-key description has
SHA-256:

```text
8d325ee6753c8effb7d5184bdd729255d2697dd1730c0278084cd91192020e90
```

This digest, not a mutable dependency label, is the Action verifying-key ID.
Ironwood V3 uses note plaintext lead byte `0x03`, supports cross-address
payments, and shares the hardened Action circuit. Vault MUST NOT generate new
proofs using `InsecurePreNu6_2` or silently substitute `FixedPostNu6_2`.

Vault now vendors a source-comparable fork of Orchard 0.15.5 from upstream
commit `29d1d55db62153dcaeef8ef631c8991c53ed1248`. Only `src/circuit.rs`
differs from the upstream `src/` tree: it exposes composition configuration,
one-time table loading, per-Action instance offsets, canonical instance values,
and typed handles to already-constrained values and receiver coordinates. The
Action equations and standalone proof APIs are unchanged. Provenance and fork
rules are recorded in `vendor/orchard/VAULT_FORK.md` and the local review record.

The circuit dependency graph is feature-gated out of the wallet-facing build.
The isolated `zk/halo2` workspace owns proving and verifying keys, canonical
proof parsing, and composite proof integration.

## Implemented Action statement

For every padded action, the real Halo2 proof currently constrains:

| Obligation | Status | Binding |
|---|---:|---|
| Input note opening | proven | address, value, `rho`, `psi`, `rcm` |
| Merkle membership | proven | input commitment to common public anchor |
| Ownership | proven | input address derived from witnessed full viewing key |
| Nullifier | proven | witnessed note and nullifier key to public `nf_old` |
| Spend randomization | proven | `rk = ak + [alpha]G`, non-identity public `rk` |
| Output note opening | proven | address, 64-bit value, new randomness to public `cmx` |
| Action linkage | proven | output `rho = nf_old` |
| Net value | proven | public `cv_net` commits to `v_old - v_new` and `rcv` |
| Enable/dummy semantics | proven for accounting | private marker equals nonzero input-or-output; Orchard flags remain public enabled |
| Canonical proof size | enforced | `2720 + 2272 × action_count` bytes |

The constructor independently rejects a wrong owner, path, anchor, output
`rho`, randomized key, or net commitment before proving. The prover then uses
public instances reconstructed independently from `TransferV2Effects`, and the
returned proof is verified against both representations.

The real two-action test proof is exactly 7,264 bytes. It verifies successfully
and fails after anchor mutation, transcript-byte mutation, or proof-length
mutation. With multicore enabled only in this prover workspace, one preliminary
local release run measured:

| Operation | Time |
|---|---:|
| Reusable prover key bundle derivation | 19.124 s |
| Reusable validator verifying-key derivation | 6.451 s |
| Two-action proof plus two self-verifications | 6.326 s |
| Standalone two-action verification | 80 ms |

These single-run measurements are evidence, not a final benchmark. Normal
operation must load reviewed persistent keys once rather than derive them per
transaction.

## Mandatory second statement

The Action proof is necessary but insufficient. It does not bind Vault's chain
ID, composite circuit ID, gas, output value commitment, note ciphertexts, burn
commitment, or burn ciphertext, and it has no cross-action arithmetic. A second
specialized proof MUST constrain all of the following against the same complete
`TransferV2Effects`:

1. each accounting witness opens the same public `cv_net` as the Action proof;
2. every output value used by accounting is bound to its public note commitment
   or to an additional commitment proven by the Action layer;
3. change is derived from the authorized sender, never selected by a free
   prover label;
4. dummy slots have zero input, output, taxable value, burn, and gas
   contribution while retaining the same public action shape;
5. all amounts are range-constrained before addition or multiplication;
6. `gas_fee = gas_units × fee_per_gas` with checked native-VLT bounds;
7. `taxable = 200q + r`, `0 <= r < 200`, and
   `burn = q + is_nonzero(r)`;
8. `sum(inputs) = sum(outputs) + burn + gas_fee` exactly;
9. the burn commitment opens to that exact `burn` with independent randomness;
10. the 64-byte Pallas ciphertext satisfies `C1 = [r]G` and
    `C2 = [burn]H + [r]PK_epoch` under the exact epoch key selected by
    `burn_scheme_id`, `burn_key_id`, and `burn_epoch`;
11. output note encryption, ephemeral key, recipient ciphertext, and sender
    recovery data are consistent with the proven note or a reviewed equivalent
    binding construction;
12. every remaining effect byte, including chain and version, is bound by the
    composite statement.

Recipient/change classification now has a constrained production-intent
candidate. For each Action, `taxable = 0` implies equality of all four affine
coordinates of the old and new expanded receivers `(g_d, pk_d)`. The bit and
coordinates remain private. The reverse implication is intentionally absent:
a same-receiver output may be marked taxable and overpay, but an unequal
receiver cannot be marked as exempt. This avoids an unsafe non-membership claim
over an account's unbounded diversifier space. Wallet, multi-input, dummy, and
metadata analysis remain required before this policy can be frozen.

### Implemented arithmetic component

The non-activatable `AccountingArithmeticCircuit<N>` now implements the exact
field arithmetic for every allowed padded bucket (`N = 2, 4, 8, 16`) with a
single tested degree parameter `k = 12`:

| Constraint | Implemented binding |
|---|---|
| Input and output amounts | canonical 64-bit bit decomposition |
| Action enable and taxable flags | boolean constraints |
| Dummy slots | enabled iff input or output is nonzero; disabled also forces non-taxable |
| Per-action taxable value | `taxable_output = output × taxable_flag` |
| Cross-action totals | constrained rolling input/output/taxable accumulators |
| Public gas | instance-bound `gas_units × fee_per_gas = gas_fee`, all 64-bit |
| Burn division | `taxable = 200q + r`, lookup-constrained `r in [0, 200)` |
| Ceiling | inverse-based `is_nonzero(r)` and `burn = q + is_nonzero(r)` |
| Conservation | `inputs = outputs + burn + gas_fee` |
| Burn commitment | same arithmetic `burn` cell in `[burn]V + [rcv]R` |
| Burn ciphertext C1 | `C1 = [r]G` against public affine coordinates |
| Burn ciphertext C2 | `C2 = [burn]H + [r]PK_epoch` using the same burn cell |
| Epoch descriptor | exact scheme, key ID, and epoch checked against the activated canonical DKG descriptor |
| Epoch key | affine coordinates independently reconstructed from that descriptor |
| Complete effects | full BLAKE3 digest preserved as two public 128-bit limbs |

The native constructor independently calculates the same result with checked
integer arithmetic and rejects overflow, malformed dummy slots, zero gas, and
non-conservation before proving. Negative Halo2 tests alter public gas, burn,
and taxable classification and are rejected; burn boundary cases cover 0, 1,
199, 200, 201, 399, and 400 atomic units.

`AccountingBurnCircuit<N>` now composes the arithmetic and Pallas ECC gadget by
passing the exact constrained `burn` cell, rather than duplicating an amount or
comparing host values. Positive tests open the commitment and both ciphertext
equations; changing the private burn or a public ciphertext coordinate fails.

The two-action combined circuit has also completed a real Halo2
`create_proof`/`verify_proof` round trip. One preliminary local release run
measured:

| Operation | Time / size |
|---|---:|
| Parameter + provisional VK/PK derivation | 21.891 s |
| Accounting/burn proof | 10.154 s |
| Standalone verification | 98 ms |
| Proof bytes | 5,504 |

Changing a transcript byte or a public ciphertext coordinate makes real
verification fail. These are single-run development measurements. The
accounting VK and suite ID are deliberately not frozen because adding the
remaining note/classification constraints will change the circuit shape.

This combined component is not yet an accounting proof suite. In particular,
the earlier standalone private `taxable` bit is intentionally not accepted by
any consensus verifier.

### Implemented monolithic Action linkage

`VaultTransferCircuit<N>` configures the hardened Action circuit once and
synthesizes each padded Action at a disjoint ten-row public-instance offset.
The fork returns its already-constrained `v_old`, `v_new`, `g_d`, and `pk_d`
cells. The parent circuit then:

1. equality-constrains every Action `v_old` to the corresponding accounting
   input cell;
2. equality-constrains every Action `v_new` to the corresponding accounting
   output cell;
3. applies `(1 - taxable) * (old_coordinate - new_coordinate) = 0` to all four
   expanded-receiver coordinates;
4. feeds the resulting accounting burn cell into the existing commitment and
   threshold-ElGamal equations;
5. constrains the two 128-bit limbs of the complete canonical effects digest as
   public instances.

This removes the known cross-proof substitution attack: redistributing private
inputs between Actions can still satisfy isolated totals, but fails the shared
cell equalities. A separate adversarial test constructs a transaction whose
Action values fund gas but no burn and labels an external output as change; its
standalone accounting is valid, while the monolithic proof fails the private
receiver constraint.

The first real two-Action proof of this provisional shape measured locally in
release mode:

| Operation | Time / size |
|---|---:|
| Parameters + provisional VK/PK | 33.769 s |
| Monolithic proof | 25.842 s |
| Standalone verification | 151 ms |
| Proof bytes | 9,504 |

Transcript-byte and public-instance mutations fail verification. These are
single-run engineering measurements, not performance claims. The VK and suite
ID remain deliberately unfrozen.

### Activated epoch descriptor and complete-effects binding

`VaultTransferPublicInputs<N>::from_effects` is the validator-side canonical
reconstruction boundary. It accepts typed `TransferV2Effects` and the epoch
descriptor selected by consensus, then fails closed unless:

- the Action count matches the fixed 2/4/8/16 circuit shape;
- `burn_scheme_id` is the one frozen threshold-ElGamal construction;
- `burn_key_id` equals the digest of the supplied complete DKG descriptor;
- `burn_epoch` equals that descriptor's epoch;
- every Action instance, burn commitment, `C1`, `C2`, and `PK_epoch` has a
  canonical non-identity representation accepted by the circuit policy.

It derives Action instances directly from effects, parses all four Pallas
points, and supplies the exact affine coordinates consumed by the ECC gadget.
Substituting another valid DKG result changes `key_id` and is rejected before
proving. Scheme, key-ID, epoch, ciphertext, and coordinate mutations have
dedicated negative tests.

The same reconstruction splits the canonical 32-byte
`TransferV2Effects::public_inputs_digest` into two little-endian 128-bit limbs.
Because each limb is below the Pallas base-field modulus, this mapping is
lossless; a round-trip test reconstructs all 256 original bits. The prepared
prover package retains those limbs, while the validator supplies its own
reconstruction as public instances. Halo2 equality constraints make a changed
note ciphertext, chain ID, circuit ID, or any other effect invalidate the
existing proof. The real-proof test mutates the digest instance and fails.

The production-intent prover also retains each exact `EncryptedNote` created
with its private note and rejects byte-level divergence from the public effects
before proof generation. This is construction hardening, not a claim that
Halo2 recomputes Ironwood authenticated encryption. The selected signer-side
equivalent mechanism and its remaining gates are specified in
[`NOTE_CIPHERTEXT_POLICY.md`](NOTE_CIPHERTEXT_POLICY.md).

The current two-Action shape, after epoch-descriptor reconstruction and full
effects-digest binding, measured in one local release run:

| Operation | Time / size |
|---|---:|
| Parameters + provisional VK/PK | 42.224 s |
| Monolithic proof | 36.099 s |
| Standalone verification | 173 ms |
| Proof bytes | 9,600 |

This superseded the 9,504-byte development shape. The final all-bucket freeze
below increased the degree from `k = 14` to `k = 15` after the 16-action gate
proved that `k = 14` had insufficient rows.

### Frozen all-bucket monolithic suite

The C2 release gate deterministically derives parameters and proving/verifying
keys for every consensus bucket at `k = 15`, creates and verifies one real proof
per bucket, and recomputes the pinned suite ID:

```text
991523426f81b2350b1b08a7e2de9f60e334f344e40c23904c6dd8db5937c83a
```

The derivation domain and exact byte framing are specified in
[`PROOF_SETUP.md`](PROOF_SETUP.md). A 2026-08-30 release run on an AMD Ryzen 7
7730U (8 cores/16 threads, 32 GiB RAM), Windows x86_64, Rust/Cargo 1.98.0,
reported:

| Padded actions | Parameters + VK/PK | Prove | Verify | Proof bytes |
|---:|---:|---:|---:|---:|
| 2 | 18.886 s | 12.484 s | 68.574 ms | 9,664 |
| 4 | 19.878 s | 12.378 s | 67.710 ms | 9,664 |
| 8 | 22.800 s | 12.118 s | 53.174 ms | 9,664 |
| 16 | 29.200 s | 11.773 s | 55.628 ms | 9,664 |

The real two-action fail-closed test mutates every public-instance cell in turn
and requires verification failure. Native and MockProver tests separately cover
the private classification boundary: external recipients cannot be claimed as
change, same-receiver change is accepted, taxable external payment is accepted,
dummy markers are value-derived, and shifted private accounting values cannot
reuse Action witnesses. These measurements freeze C2 evidence; they are not a
capacity claim or a substitute for C4 vectors, C6 repeated comparative
benchmarks, or C7 independent review.

The corresponding C4 Halo2 proof and public-instance artifacts, SHA-256
manifest, reproduction procedure, and offline mutation verifier are published
under [`../../zk/halo2/core/tests/vectors`](../../zk/halo2/core/tests/vectors/VERIFY.md).
This is only the Halo2 half of C4; the RISC Zero half cannot be published until
the C1 real receipt exists.

## Fail-closed composition

The canonical `VZK2` proof envelope contains the Action verifying-key ID, an
accounting-suite ID, padded action count, exact Action-proof length, and a
non-empty bounded accounting proof. The activated circuit ID is derived from
both suite IDs and the envelope version.

`CompositeTransferVerifier<A>` implements the consensus verifier only when an
`AccountingProofVerifier` is supplied. This repository provides no permissive
or placeholder accounting verifier. Therefore the implemented Action proof
cannot mutate shielded state, even if it verifies correctly. Contracts remain
blocked by the same gate.

## Remaining release gates

- freeze the implemented private recipient/change rule after wallet and
  metadata review;
- implement and review authenticated hardware and multiparty profiles around
  the local independent note-ciphertext validation session;
- add fixed vectors for action buckets 2, 4, 8, and 16;
- measure cached-key proving, standalone verification, peak memory, and batch
  verification on target validator hardware;
- fuzz malformed proof envelopes and native public-instance parsing;
- reproduce the verifying-key fingerprint and release artifacts in CI;
- complete independent circuit, cryptography, and consensus reviews.

No supply, anonymity, or mainnet-safety claim is valid until every gate above
is closed.
