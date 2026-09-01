# Transfer-v2 note-ciphertext policy

**Status:** canonical codec, encrypted confirmed-peer lifecycle, Noise transport, and Unix replay store implemented; UX/hardware/review gates open; not activatable  
**Last updated:** 2026-08-23

## Decision

Vault transfer-v2 follows the reviewed Orchard separation between consensus
validity and output-delivery validation:

1. The Halo2 Action statement proves the exact output note opening and its
   public note commitment `cmx`.
2. The monolithic Vault statement proves the same output value participates in
   conservation, gas, private change classification, and the exact 0.5% burn.
3. The verifier reconstructs the canonical 256-bit
   `TransferV2Effects::public_inputs_digest`; both 128-bit little-endian limbs
   are public Halo2 instances. This binds chain ID, circuit ID, anchor, burn
   descriptor and ciphertext, gas, every action, every output commitment,
   ephemeral key, recipient ciphertext, and outgoing ciphertext to the proof.
4. Every spend-authorization signature also covers that complete digest.
5. Before signing, each Vault signer MUST independently validate the output
   construction data it is authorizing: recipient, value, `rho`, `rseed`, memo,
   note commitment, output value commitment, ephemeral key, recipient
   ciphertext, outgoing-recovery ciphertext, change classification, gas, and
   burn policy.

The consensus circuit does not duplicate Ironwood's BLAKE2b-based key
derivation and authenticated note-encryption algorithm inside Halo2. That
would add a large, bespoke circuit surface without strengthening supply or
spend authorization: a party that controls every spending key can always
choose to make its own output unavailable, disclose its own data, or encode a
subliminal signal in transaction randomness. The deployed Orchard workflow
instead gives signers the output construction fields needed to verify
ciphertexts before authorizing the complete transaction.

This is the reviewed-equivalent mechanism permitted by the transfer-v2 proof
statement. It is not a shortcut that treats arbitrary ciphertext bytes as a
valid payment.

## Security boundary

The policy provides these properties in the implemented local path; hardware
and multiparty deployments inherit them only after their remaining transport
profiles and review gates are complete:

| Event | Required result |
|---|---|
| Third party changes any ciphertext or public effect | Existing proof and every Action signature fail |
| Coordinator substitutes a ciphertext before signing | Independent signer recomputation fails and no signature is released |
| Prover API receives effects different from its locally constructed output | Preparation fails before Halo2 proving |
| Sender deliberately authorizes an undecryptable recipient output | The committed value remains conserved but is potentially unspendable; this is not valid evidence of payment |
| Recipient receives a payment | Wallet accepts it only after authenticated decryption, commitment reconstruction, and finality |
| Outgoing recovery data is invalid | Sender recovery fails; it cannot grant authority over another note or change conservation |

An invalid note ciphertext cannot create VLT, evade gas or burn, change the
proven recipient, or make a note spendable by a different key. It can deny
delivery of a value that the spending owners authorized. Wallet and hardware
signer correctness therefore remain part of the security boundary and require
their own adversarial test suite.

The burn ciphertext has a different policy. Its plaintext changes the global
monetary accounting, so Halo2 proves both threshold-ElGamal equations from the
same constrained burn cell. Signer validation is not a substitute for that
circuit binding.

## Current implementation evidence

- `PreparedActionCircuit` retains the exact `EncryptedNote` produced with its
  private output and `PreparedVaultTransfer::new` rejects any byte-level
  divergence from `TransferV2Effects`.
- Validators reconstruct Action instances, gas, burn commitment, burn `C1` and
  `C2`, the activated epoch public key, and the two complete-effects digest
  limbs from typed effects rather than accepting prover-supplied vectors.
- The monolithic circuit constrains those digest limbs as public instances.
- Adversarial tests change a note-ciphertext byte, chain domain, burn
  ciphertext, scheme, key ID, epoch, epoch descriptor, proof byte, and public
  instance. The applicable constructor, mock circuit, or real verifier rejects
  each mutation.
- `OutputAuthorizationPacket` implements the exact 1,455-byte `VAOP` v1 private
  codec and rejects truncation, trailing bytes, unknown scope/kind encodings,
  zero networks, and malformed output encodings.
- `OutputAuthorizationPacket::verify` matches an independently supplied intent,
  reconstructs the Ironwood V3 note, `cmx`, output value commitment, ephemeral
  key, recipient ciphertext, and outgoing ciphertext, and emits only an opaque
  signer-bound token.
- Change and dummy authorizations require a recipient in the signer's internal
  scope; external/change must be non-zero and dummy must be zero.
- `TransferV2SignerPolicy` pins chain, circuit, burn scheme/key/epoch, action
  bucket, gas units, fee-per-gas, and total gas debit before creating an opaque
  session. The session requires one exact output token per sorted action and
  checks the action's randomized key and spending account before signing.
- Adversarial protocol tests reject missing or reordered tokens, a different
  spending account, a prepared authorization from another action, invalid
  action index, and every policy-domain or gas mutation.
- Positive protocol tests construct, independently validate, sign, and verify
  complete sessions for every activated 2/4/8/16-action padding bucket.
- `vault-signer` carries those packets through a mutually authenticated paired
  Noise KK channel, binds the Noise handshake hash into a signer-generated
  challenge and complete request transcript, requires an atomic durable replay
  guard, and returns a transcript/effects/signature-verified response.
- Confirmed peers are retained in a constant-size authenticated encrypted
  registry. Revoked static identities remain tombstoned, rotation installs a
  separately confirmed fresh identity atomically, and only an active registry
  entry can construct the public KK handshake path.

The exact local codec, validation algorithm, deterministic vector inputs, and
remaining transport obligations are specified in
[`../specs/OUTPUT_AUTHORIZATION_V1.md`](../specs/OUTPUT_AUTHORIZATION_V1.md).

## Activation gates

Before this policy can be frozen, Vault must:

- independently review the implemented first-contact pairing and Unix stores;
  add keychain, active-session shutdown, secure-element/non-Unix replay profiles and concrete
  hardware/multisignature/delegated-prover adapters around the paired channel;
- build a confirmation interface whose trusted intent source is independent of
  the coordinator packet and covers recipients, amounts, gas ceilings, network,
  burn policy, and change classification;
- define the exact dummy-output encryption policy and demonstrate that it does
  not create an avoidable distinguisher or subliminal-channel regression;
- publish deterministic positive and negative vectors for every ciphertext
  component and every 2/4/8/16 Action bucket;
- fuzz parsing and mutation boundaries and benchmark signer, prover, and
  validator paths;
- pass the project security review of the Ironwood integration, multi-party signing
  threat model, hardware-wallet interface, and recipient acceptance rules.

Until those gates close, a generated proof is engineering evidence only and
Vault must not be used with real funds.

## References

- [`TRANSFER_V2_CIRCUIT.md`](TRANSFER_V2_CIRCUIT.md)
- [`../specs/TRANSFER_V2.md`](../specs/TRANSFER_V2.md)
- [`../specs/OUTPUT_AUTHORIZATION_V1.md`](../specs/OUTPUT_AUTHORIZATION_V1.md)
- [`PRIVACY.md`](PRIVACY.md)
- [`../../vendor/orchard/src/pczt.rs`](../../vendor/orchard/src/pczt.rs)
- [ZIP 224: Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
