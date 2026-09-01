# H1 Cryptographic Architecture

**Decision status:** Ironwood V3 note/key/encryption suite and hardened Halo2
Action circuit selected; transfer-v2 codec implemented; Vault accounting and
burn-encryption circuit not frozen.  
**Security status:** production-intent foundation, not activated.

## 1. State model

Vault adopts an append-only private-note model:

- a note commitment is appended to an authenticated state tree;
- spending reveals a deterministic nullifier, never the note or tree position;
- consensus rejects a nullifier already present in global state;
- the proof demonstrates membership, ownership, value conservation, burn, and
  correct output construction;
- encrypted note payloads allow recipients to discover and spend their notes;
- incoming, full, and outgoing viewing capabilities are separated.

This direction follows deployed design lessons rather than creating a new
privacy primitive. Orchard specifies commitments, a global commitment tree,
deterministic nullifiers, and viewing-key separation. Aztec similarly models
private contract state with append-only note and nullifier trees.

Primary references:

- [Orchard ZIP 224](https://zips.z.cash/zip-0224)
- [Orchard commitments](https://zcash.github.io/orchard/design/commitments.html)
- [Orchard nullifiers](https://zcash.github.io/orchard/design/nullifiers.html)
- [Aztec notes and nullifiers](https://docs.aztec.network/developers/docs/aztec-nr/framework-description/state_variables)

Vault will not copy constants, encodings, or key derivations without verifying
license compatibility, domain separation, security assumptions, and fit for a
multi-asset programmable system.

The production-intent key and note-encryption implementation is specified in
[`PRIVACY.md`](PRIVACY.md). It pins the maintained Ironwood/Orchard
implementation rather than reimplementing its primitives. Its real Halo2 Action
proof is connected to transfer-v2 through a composite, fail-closed proof format,
and the second layer now has real range-constrained accounting plus burn
commitment/threshold-ElGamal equations. A frozen non-activated monolithic circuit now
links Action note values, private change classification, and derived dummy
state to that accounting. Validator-side reconstruction binds the activated
epoch DKG descriptor to `PK_epoch`, while two lossless public limbs bind the
complete canonical effects digest. It remains fail-closed because the
signer-side ciphertext policy, vectors, benchmarks, and review gates are not
complete.

## 2. Candidate note witness

The transfer circuit is expected to consume private notes containing at least:

```text
protocol_version
asset_id
owner transmission key
value: u128 atomic units
rho: unique note-domain value
rseed: sender randomness
kind: recipient | internal change | contract custody | fee
memo_digest
```

The exact encoding is not frozen. `rho`, `rseed`, owner keys, and note
commitment must jointly prevent commitment collisions, duplicate nullifiers,
sender-chosen linkage, and Faerie-style attacks.

## 3. Transfer-v2 proof statement

### Public inputs

- protocol version, chain ID, and activated circuit ID;
- recent note-tree anchor;
- input nullifiers;
- output note commitments and encrypted-payload binding;
- value-balance commitment;
- hidden burn commitment and aggregate-encryption payload binding;
- deterministic gas units and fee per gas.

### Private witness

- input note plaintexts, commitment randomness, and authentication paths;
- spending authorization material;
- output note plaintexts and commitment randomness;
- recipient amount, internal change, burn, and funded gas;
- encryption randomness where circuit binding requires it.

### Required constraints

1. Every input note is a member of the anchored tree.
2. Each nullifier is correctly and uniquely derived from its input and key.
3. The prover is authorized to spend every non-dummy input.
4. Every amount is range-constrained before arithmetic.
5. Every output commitment opens to the witnessed output note.
6. Internal change is proven to derive from the sender account; a user cannot
   label another owner's output as untaxed change.
7. For externally transferred native VLT amount `A`, the circuit witnesses
   `A = 200q + r`, constrains `0 <= r < 200`, and sets
   `burn = q + is_nonzero(r)`.
8. Per-asset conservation holds. For native VLT:

   ```text
   sum(inputs) = sum(outputs) + burn + gas
   ```

9. Non-native assets cannot satisfy native VLT gas or burn obligations.
10. Value and burn commitments use independent randomness and domain tags.
11. Dummy notes contribute zero value and are indistinguishable at envelope level.
12. The public-input digest is computed inside the proven program or constrained
    by the specialized circuit, not merely trusted from the host.

The 0.5% rule covers base-layer VLT ownership changes. No blockchain can detect
an off-chain sale of a key or beneficial claim. Contract wrappers therefore
require explicit economic rules and cannot be advertised as making evasion
mathematically impossible.

## 4. Proof-system strategy

Vault uses a benchmark gate rather than selecting a proof system by reputation.

| Candidate | Strength | Principal concern | H1 role |
|---|---|---|---|
| Specialized PLONKish/Halo2-style circuit | Small, controllable money-transfer statement | High circuit engineering and audit burden | Production candidate for transfers |
| Maintained Rust zkVM | General private program execution and fast iteration | Proving cost, proof/version lifecycle, larger attack surface | Reference implementation and contract candidate |
| Recursive aggregation layer | Amortized validator verification | Added prover complexity and liveness dependency | Required benchmark |

The first RISC Zero 3.0.6 accounting receipt was generated and verified on
2026-08-21. It was 256,266 bytes and required 175.555 seconds on an 8 GB Apple
M1 CPU for 262,144 total cycles. This passes the envelope-size experiment but
fails the current latency bar for direct base-layer transfers. Full methodology
and omissions are recorded in
[`../research/RISC0-ACCOUNTING-V1.md`](../research/RISC0-ACCOUNTING-V1.md).

On 2026-08-22 the pinned `PostNu6_3` Halo2 Action circuit generated and verified
a real two-action proof of exactly 7,264 bytes. With multicore enabled only in
the prover workspace, one preliminary local release run measured 19.124 s for
the reusable prover key bundle, 6.451 s for the reusable validator VK, 6.326 s
for proving plus two immediate self-verifications, and 80 ms for standalone
verification. Repeated samples, peak memory, persistent-key startup, and target
validator hardware remain required before these are performance claims. Full
coverage and omissions are in [`TRANSFER_V2_CIRCUIT.md`](TRANSFER_V2_CIRCUIT.md).

The same day, the two-action accounting/burn shape generated and verified a
real 5,504-byte Halo2 proof. One preliminary release run measured 21.891 s for
parameter plus provisional key derivation, 10.154 s for proving, and 98 ms for
verification. Its VK is intentionally provisional: completing note/value and
classification bindings changes the shape and must precede a suite ID.

The first monolithic two-Action shape now reuses the exact `v_old`/`v_new`
cells constrained by the hardened Action circuit and privately enforces that a
zero-tax output has the same expanded receiver as its paired consumed note. A
real proof was 9,504 bytes; after deriving dummy state, one preliminary release
run measured 33.769 s for provisional key derivation, 25.842 s for proving, and
151 ms for verification.
Cross-statement value substitution and false external-as-change witnesses fail.
The subsequent shape reconstructs exact burn scheme/key/epoch coordinates and
constrains all 256 bits of the effects digest. Its real proof was 9,600 bytes;
one preliminary run measured 42.224 s for provisional key derivation, 36.099 s
for proving, and 173 ms for verification. Local signer-side note-ciphertext
reconstruction, confirmed Noise XX-to-KK pairing, and a channel-bound Noise
session backed by a crash-consistent Unix replay store are now implemented;
trusted UX, hardware rollback protection, hardware/multiparty adapters,
all-bucket vectors, and review gates still prevent assigning a suite ID.

RISC Zero demonstrates a transparent STARK-based RISC-V zkVM and private inputs,
but its version lifecycle and security advisories show why Vault must pin,
audit, and support verifier deactivation rather than embed “latest” blindly.

- [RISC Zero proof-system description](https://dev.risczero.com/proof-system-in-detail.pdf)
- [RISC Zero security advisories](https://github.com/risc0/risc0/security/advisories)

No proof backend is activated in consensus until it passes:

- positive and negative test vectors;
- differential tests against the transparent oracle;
- deterministic builds;
- proof malleability and malformed-input tests;
- memory, latency, and proof-size benchmarks;
- independent cryptography review.

Both selected backends use transparent parameter generation rather than a
secret structured setup. Exact assumptions, artifact integrity requirements,
and suite rotation rules are specified in [`PROOF_SETUP.md`](PROOF_SETUP.md).

## 5. Burn aggregation

Revealing a per-transaction burn reveals the private transfer amount because
`A` is approximately `200 × burn`. Transfer-v1 therefore exposes a hiding burn
commitment and a bounded ciphertext, while the proof enforces the burn equation.

The leading design candidate is additively homomorphic encryption to an
epoch-scoped threshold validator key:

1. each transaction proves its ciphertext and commitment encode the same burn;
2. validators aggregate ciphertexts without individual decryption;
3. an epoch aggregate is opened only after a minimum anonymity threshold;
4. a proof links the aggregate opening to the updated public supply statistic;
5. missed threshold shares trigger a defined recovery/liveness path, never a
   bypass of supply conservation.

The normative policy for DKG trust, same-key validator resharing, low-volume
carry, verified decryption shares, bounded recovery, and supply reporting is
frozen in [`../specs/BURN_AGGREGATION_V1.md`](../specs/BURN_AGGREGATION_V1.md).
Its network and persistence implementation remains open. Until it is activated,
exact circulating-supply publication is not guaranteed; non-inflation remains
enforced by transaction proofs.

## 6. Network and endpoint privacy

Zero knowledge does not hide IP addresses, timing, wallet compromise, source
chain deposits, or information voluntarily shared with a merchant. Wallet and
node design must separately cover privacy relays, transaction diffusion,
encrypted mempool research, remote-prover leakage, view-key handling, and
constant-time secret operations.
