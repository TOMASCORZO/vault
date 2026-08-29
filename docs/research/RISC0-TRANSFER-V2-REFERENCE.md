# RISC Zero transfer-v2 reference statement

**Statement version:** 1
**Maturity:** implemented, guest-compilable, and natively negatively tested;
non-selected and non-activatable
**H1 item:** H1-C1
**Code:** `zk/risc0`

## 1. Purpose and isolation

This statement is an executable reference for the exact
production-intent transfer-v2 invariants. It is not a prototype transaction
format and does not define alternative consensus semantics. The guest decodes
the normative `TransferV2Effects` codec and calls the same pinned Ironwood V3,
Orchard, Pallas, and burn-encryption primitives used by the specialized path.

The RISC Zero workspace remains excluded from the root workspace. It MUST NOT
implement `TransferV2ProofVerifier`, expose an activated circuit ID, or mutate
shielded state. A receipt would be research evidence only. RISC Zero is not the
selected transfer backend: its proving latency and dependency surface prohibit
activation, and H1 does not require spending more resources to produce a full
receipt for this unused path.

## 2. Public statement

The claim carries the exact canonical `TransferV2Effects::encode_canonical()`
bytes. Inside the guest:

1. the byte length is bounded by `TRANSFER_V2_MAX_EFFECT_BYTES`;
2. `TransferV2Effects::decode_canonical` rejects every alternate encoding;
3. the guest recomputes `TransferV2Effects::public_inputs_digest`; and
4. the journal commits to that 32-byte digest, the public padded action count,
   and the already-public gas fee.

The effects `circuit_id` remains the production statement's public field. It is
not replaced with the RISC Zero image ID. Receipt verification separately pins
the exact guest image, which prevents a receipt for another program from being
accepted as conformance evidence.

Spend signatures remain a host consensus check over the same effects digest.
The reference guest proves the private authorization relation
`rk = ak + [alpha]G`; duplicating public signature verification inside the guest
would not add a private invariant.

## 3. Private claim

For each public padded action, in canonical action order, the private claim
contains exactly:

- one serialized full viewing key;
- one fixed private Ironwood V3 input-note encoding;
- one depth-32 membership path and position;
- one non-zero spend randomizer `alpha`;
- one net-value commitment trapdoor; and
- one exact fixed-size output-authorization packet containing the output note,
  memo, output-value trapdoor, sender scope, and external/change/dummy class.

The claim also contains the complete canonical epoch DKG-result descriptor, the
burn-commitment trapdoor, and the threshold-ElGamal randomness. Secret material
is serialized only into the local zkVM input channel and MUST be zeroized on the
host where the pinned APIs permit it. It is never written to the journal.

## 4. Per-action validation

For each action, the guest MUST reject unless all of these hold:

1. the full viewing key, input note, path nodes, randomizer, trapdoors, public
   action fields, and private packet have canonical encodings;
2. the input recipient belongs to the witnessed full viewing key;
3. every non-zero input note is a member of the public common anchor;
4. the public nullifier is the exact keyed nullifier of that input note;
5. the public randomized key equals the full viewing key's `ak` randomized by
   the witnessed non-zero `alpha`;
6. the public net-value commitment opens to `input_value - output_value`;
7. the packet's output `rho` equals the same public action nullifier;
8. the output note commitment and output value commitment open to the packet's
   witnessed note and trapdoor;
9. the ephemeral key, fixed 580-byte recipient ciphertext, and fixed 80-byte
   outgoing ciphertext reconstruct byte-for-byte under Ironwood V3; and
10. an external output is non-zero and taxable, while zero-tax change is
    non-zero and has the exact same expanded receiver as the paired input;
    a dummy has zero input and output and the same receiver.

Membership is required only for a non-zero consumed note, matching the pinned
Action statement's dummy semantics. A zero-input/non-zero-output action remains
possible only as a taxable external output funded by the bundle's other real
inputs; it cannot claim change or dummy status.

## 5. Bundle accounting and hidden burn

All note values are canonical `u64` values not exceeding the fixed native-VLT
maximum of `21,000,000 × 10^9` atomic units. Sums and public gas multiplication
use checked `u128` arithmetic. The guest enforces:

```text
taxable = sum(external output values)
burn = taxable / 200 + (taxable % 200 != 0)
gas = gas_units * fee_per_gas
sum(inputs) = sum(outputs) + burn + gas
```

The complete DKG descriptor MUST reconstruct the public burn key ID, epoch, and
Pallas encryption key under the frozen scheme ID. The public burn value
commitment MUST open to the exact computed burn. The public 64-byte ciphertext
MUST satisfy, using the same burn and witnessed randomness:

```text
C1 = [r]G
C2 = [burn]H + [r]PK_epoch
```

This validates a transaction's descriptor-bound burn encryption. It does not
implement DKG, validator rotation, aggregate decryption, or the low-volume epoch
policy assigned to H1-C4/H2.

## 6. Bounds, errors, and versioning

- statement version is exactly `1`;
- action count is exactly one public 2/4/8/16 bucket and private witness count
  must match it;
- each path has exactly 32 canonical nodes;
- each output packet has exactly `OUTPUT_AUTHORIZATION_PACKET_BYTES` bytes;
- the DKG descriptor inherits the 512-participant bound and canonical sorting;
- no unchecked arithmetic or attacker-selected allocation is accepted after
  the bounded claim has been decoded; and
- detailed validation failures remain local, while a failed guest execution or
  receipt verification yields one opaque proof failure to callers.

Any statement, codec, dependency, or guest change produces a different image
ID. A future statement version requires a new specification plus native and
guest-build evidence; if real proving is ever reconsidered, its receipt must
also use the new image. Version 1 cannot be silently reinterpreted.

## 7. H1-C1 evidence gate

H1-C1 is complete when:

- native tests cover one valid two-action external-payment/change bundle;
- mutations of anchor/path, owner, nullifier, randomized key, net commitment,
  output note/value commitment, `rho`, ciphertexts, classification, gas,
  conservation, burn commitment, burn randomness, and epoch descriptor fail;
- the real guest builds under the pinned toolchain; and
- the report records the image ID, the terminated proving attempt, and why no
  receipt or activation path is required.

The pinned implementation currently builds as image
`bb591620a530ed746df42fa95445f188c806b605db8bf50514d91b33efab5256`.
Native tests exercise the positive two-action bundle and separate mutations of
the required membership, ownership, authorization, opening, encryption,
classification, accounting, burn, and epoch relations. The full isolated gate
passes eight host tests, one core arithmetic test, formatting, Clippy with
warnings denied, and rustdoc. It still emits the tracked future-compatibility
warning for transitive dependency `block 0.1.6`. These checks close H1-C1 but
do not satisfy any activation gate.

## 8. Full proving attempt and decision

`./scripts/prove-zk-risc0.sh` was run with development mode disabled on the
Apple M1 host on 2026-08-23. Compilation finished at 19:51:20 -03:00. The
proving process was intentionally terminated at 22:39:09 after approximately
2 hours 48 minutes without producing a receipt. At roughly 2 hours 41 minutes,
the process was still in the running state, using about 562% CPU and 6.2% of
memory, so the delay was active computation rather than an I/O wait or memory
failure.

No proof bytes, journal, segment count, or cycle count were emitted before
termination. This is a negative performance result, not a cryptographic proof
failure. Because RISC Zero has no consensus adapter and is not the selected
transfer backend, producing this receipt is not an H1 closure requirement. The
selected Halo2 path retains the real-proof and vector obligations. Do not run
the expensive RISC Zero prover as a routine gate; the native/guest-build oracle
may remain useful for isolated differential checks.
