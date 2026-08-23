# Vault output authorization packet v1

**Status:** production-intent codec, encrypted confirmed-peer lifecycle, Noise transport, and Unix replay store implemented; UX/hardware/review gates pending  
**Last updated:** 2026-08-23

## 1. Scope

`VAOP` v1 is the fixed private packet through which a transfer constructor
gives one signer enough information to reconstruct one Ironwood V3 output.
It is not a transaction, consensus object, proof input, or network message.
It contains recipient and amount metadata, `rseed`, the complete memo, and the
output value-commitment trapdoor. It MUST NOT enter a block, mempool, RPC log,
analytics system, crash report, or unencrypted storage.

The transport carrying this packet MUST provide peer authentication,
confidentiality, integrity, replay protection, explicit session binding, and
secure deletion appropriate to its wallet or hardware profile. The packet has
no standalone MAC because authentication belongs to that transport. A future
transport profile cannot change these bytes without assigning a new packet
version.

## 2. Canonical encoding

All integers are unsigned little-endian. Every field has fixed width. Decoders
MUST require exactly 1,455 bytes and reject truncation, trailing bytes, unknown
versions, non-canonical cryptographic encodings, and reserved enum values.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VAOP` |
| 4 | 2 | version `1` |
| 6 | 32 | Vault network/chain ID; zero is reserved |
| 38 | 1 | sender OVK scope: `0` external, `1` internal |
| 39 | 1 | output kind: `0` external payment, `1` internal change, `2` dummy |
| 40 | 43 | canonical diversified recipient address |
| 83 | 8 | output value |
| 91 | 32 | action nullifier, used as Ironwood `rho` |
| 123 | 32 | Ironwood V3 `rseed` |
| 155 | 512 | memo |
| 667 | 32 | non-zero canonical output value-commitment trapdoor |
| 699 | 32 | extracted note commitment `cmx` |
| 731 | 32 | output value commitment |
| 763 | 32 | deterministic ephemeral public key |
| 795 | 580 | authenticated recipient ciphertext |
| 1375 | 80 | authenticated outgoing-recovery ciphertext |

Classification is canonical: external payments and internal change have
non-zero values; dummy outputs have value zero. Internal change and dummy
recipients MUST be recognized as internal addresses by the signer's full
viewing key. External payments are not required to belong to the signer.

## 3. Independent validation algorithm

The signer obtains an `OutputAuthorizationIntent` from its own trusted policy
or user-confirmation surface, independently of the untrusted coordinator. For
each canonical action it then:

1. checks the exact network, sender scope, classification, recipient, value,
   nullifier, memo, wallet amount ceiling, and expected public output;
2. parses the nullifier as `rho`, validates `rseed`, and constructs the exact
   Ironwood V3 note;
3. recomputes `cmx` and the output value commitment from the disclosed
   non-zero trapdoor;
4. derives the ephemeral key and recomputes both authenticated ciphertexts
   under the exact sender OVK scope;
5. compares every byte and returns an opaque signer-bound authorization token
   only if all checks succeed.

The `TransferV2SignerPolicy` then checks the complete effects against the
approved chain ID, circuit ID, burn scheme, burn key ID, burn epoch, padded
action count, exact gas units, fee-per-gas ceiling, and total-fee ceiling. It
requires exactly one token matching each sorted action and retains those
tokens for the lifetime of the signing session. `sign_action` additionally
checks the matching randomized RedPallas key and that the token was produced
under the same full viewing key as the spending key.

No coordinator boolean such as `ciphertext_valid`, `is_change`, or
`fee_approved` is trusted. Any mismatch aborts before a signature is released.
The low-level RedPallas primitive alone does not provide these guarantees.

## 4. Deterministic codec vector

The positive v1 vector in `vault-privacy::signing::tests` uses:

- sender seed `[0x91; 32]`, network `[0x31; 32]`, account `0`;
- recipient seed `[0x92; 32]`, external diversifier index `7`;
- external sender OVK scope and external-payment classification;
- value `1,234`, action nullifier `[0x03; 32]`, memo `[0x4d; 512]`;
- `ChaCha20Rng` seed `[0xa4; 32]` for output construction.

The canonical packet length is 1,455 bytes. Its unkeyed BLAKE3 regression
digest is:

```text
9d865241263d1f25c8c31592197dc7d0857c822f5c4614aaed970773e6154123
```

This digest identifies test bytes only; it is not an authentication mechanism
or protocol hash. Tests also mutate each private construction field and each
public output component, exercise wrong networks/intents/owners/value ceilings,
and reject non-canonical length, enum, and zero-domain encodings.

## 5. Remaining activation work

The codec and paired Noise request/session path are implemented, but they do
not yet complete a hardware-wallet or multiparty product. Activation still
requires:

- independent review of the implemented first-contact pairing, encrypted peer
  registry, and Unix crash-consistent replay store, plus keychain integration,
  active-session shutdown, and rollback-resistant state for each hardware and
  additional software platform;
- a reviewed confirmation UX that derives intent independently and displays
  payments, total fees, burn policy, network, and change without metadata
  confusion;
- multisignature rules proving that every required signer validates the same
  action set and exact effects digest;
- full positive/negative corpus files for 2/4/8/16 action buckets, parser
  fuzzing, memory and latency benchmarks, secure-memory review, and external
  Ironwood/wallet review.

Until those gates close, `VAOP` v1 is engineering evidence and must not protect
real funds.

The exact paired channel and transcript are specified in
[`SIGNER_TRANSPORT_V1.md`](SIGNER_TRANSPORT_V1.md).
