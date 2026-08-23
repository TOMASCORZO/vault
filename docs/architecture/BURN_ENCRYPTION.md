# Hidden burn encryption

**Status:** production-intent native construction implemented; circuit and
threshold lifecycle incomplete; not activatable  
**Last updated:** 2026-08-22  
**Code:** `crates/vault-burn`

## Purpose and privacy boundary

Publishing a burn amount reveals the approximate private payment amount because
Vault burns `ceil(payment / 200)`. Vault therefore encrypts each burn, aggregates
ciphertexts through an epoch, and intends to decrypt only the aggregate after a
minimum anonymity threshold.

Threshold encryption is not absolute privacy. A threshold of validators can
collude to decrypt an individual transaction, and a low-volume epoch can make an
aggregate identifying. The validator-corruption assumption, minimum aggregate
cardinality/value policy, epoch delay, and network metadata defenses must be
part of any privacy claim.

## Frozen candidate construction

The 64-byte payload is exponential ElGamal over the prime-order Pallas group:

```text
G  = canonical Pallas generator
H  = hash_to_curve(
       "vault.burn.pallas-threshold-elgamal-v1.message",
       "VLT burn amount generator"
     )
PK = [x]G

C1 = [r]G
C2 = [burn]H + [r]PK
```

`r` is a fresh non-zero scalar. `G` and `H` have independently derived unknown
discrete-log relation. `C1` and `C2` are canonical compressed Pallas points,
giving exactly 64 bytes. Individual `C1` and `C2` identities are excluded by
the encryptor; parsers always reject identity `C1` and non-canonical points.
The prover samples `r` uniformly from the Pallas base field and embeds its
canonical integer in the slightly larger Pallas scalar field. The excluded
fraction is below `2^-167`; this encoding lets Halo2 constrain the exact scalar
without non-native arithmetic. The burn-commitment trapdoor uses the same
reviewable policy.

The scheme identifier commits to the curve, both generators, equations, and
wire policy:

```text
979c61f6d12a25da66d5cffc659cb996d6f2cb1291ad31ce9dc0e93146996f82
```

The circuit must range-constrain `burn`, witness the same `r`, and constrain
both group equations. Native parsing or recomputation outside the proof is not
sufficient.

## Epoch public key

A reviewed DKG must output a degree `t-1` Shamir polynomial commitment:

```text
A_j = [a_j]G, j in 0..t
PK  = A_0
Y_i = sum_j [i^j] A_j
```

Participant IDs are non-zero, unique, and sorted. `Y_i` is derived rather than
trusted as a separate input. The epoch `key_id` commits to:

- the burn scheme ID and epoch;
- threshold `t`;
- the complete sorted participant ID set;
- every canonical Feldman coefficient commitment.

The native implementation rejects thresholds below two, threshold/count
mismatches, malformed commitments, identity epoch keys, identity derived share
keys, and more than 512 participants.

This describes the DKG result; it does not implement a DKG protocol. Vault must
select and review an asynchronous verifiable DKG suitable for validator churn.
The design evidence includes the high-threshold ADKG construction described in
[Das et al., 2022](https://eprint.iacr.org/2022/1389.pdf) and the DLEQ-based
verification approach in [EthDKG](https://eprint.iacr.org/2019/985.pdf).

## Aggregation and decryption

Ciphertexts are additively homomorphic:

```text
sum(C1_i) = [sum(r_i)]G
sum(C2_i) = [sum(burn_i)]H + [sum(r_i)]PK
```

Validators can therefore aggregate without opening individual burns. A
threshold subset publishes decryption shares for the aggregate only. Each
implemented share carries a domain-separated non-interactive
Chaum-Pedersen/DLEQ proof tying it to the public share key, epoch key ID, exact
aggregate ciphertext, and aggregate `C1`; accepting unverified shares would let
one participant corrupt the supply report. Recovery requires exactly `t`
strictly sorted, valid participant shares and interpolates them at zero.
Distributed ElGamal decryption and verifiable shares are treated in
[Verifiable Decryption in the Head](https://eprint.iacr.org/2021/558.pdf).

After interpolation, validators obtain `[aggregate_burn]H`, not the integer
directly. Aggregate recovery therefore needs a bounded discrete-log algorithm
and a consensus maximum. Its time/memory must be benchmarked for the maximum
epoch burn; an unbounded search is not an acceptable liveness dependency.

## Implemented and missing

Implemented:

- canonical DKG-result descriptor and deterministic key ID;
- canonical 64-byte ciphertext parser;
- fresh encryption with redacted/zeroized witness randomness;
- homomorphic aggregation;
- zeroized secret-share import checked against DKG commitments;
- DLEQ-proven aggregate decryption shares and deterministic interpolation;
- recovery of the exact aggregate message group element;
- deterministic scheme, key, and ciphertext vectors;
- malformed-key, malformed-ciphertext, amount-bound, and aggregation tests;
- typed transfer-v2 constructor and scheme-specific point validation.
- Halo2 gadget proving the burn commitment, `C1`, and `C2` equations from the
  exact same range-constrained burn cell produced by the 0.5% arithmetic;

Still mandatory:

- audited DKG, complaints, resharing, validator rotation, and transcript format;
- secret-share storage and erasure policy;
- consensus publication, finality, and equivocation rules for decryption shares;
- minimum-anonymity and timeout behavior;
- bounded discrete-log recovery and independent aggregate verification;
- integration of the gadget into the final note/value/change-classification
  statement and its reviewed verifying key;
- adversarial, side-channel, fuzz, benchmark, and independent cryptography
  reviews.

Until these are complete, this scheme ID must not appear in an activated state
configuration.
