# Hidden burn encryption

**Status:** production-intent native construction, circuit binding, and H1-C4
aggregate policy implemented; threshold lifecycle incomplete; not activatable
**Last updated:** 2026-08-25
**Code:** `crates/vault-burn`

## Purpose and privacy boundary

Publishing a burn amount reveals the approximate private payment amount because
Vault burns `ceil(payment / 200)`. Vault therefore encrypts each burn, aggregates
ciphertexts through an epoch, and decrypts only a policy-eligible aggregate.
The normative formation, privacy, carry-forward, malicious-share, and recovery
rules are in
[`../specs/BURN_AGGREGATION_V1.md`](../specs/BURN_AGGREGATION_V1.md).

Threshold encryption is not absolute privacy. A threshold of validators can
collude to decrypt an individual transaction, and a low-volume epoch can make an
aggregate identifying. The validator-corruption assumption, minimum aggregate
cardinality/window policy, epoch delay, and network metadata defenses must be
part of any privacy claim.

## Frozen construction

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
one participant corrupt the supply report. The public recovery path filters
invalid candidates, deduplicates participants, selects the lowest `t` valid
participant IDs, and passes exactly that sorted subset to interpolation at zero.
Distributed ElGamal decryption and verifiable shares are treated in
[Verifiable Decryption in the Head](https://eprint.iacr.org/2021/558.pdf).

After interpolation, validators obtain `[aggregate_burn]H`, not the integer
directly. H1-C4 selects deterministic baby-step/giant-step over the inclusive
21,000,000 VLT supply bound. The full table has 144,913,768 baby steps and the
same worst-case number of giant steps. This is finite and correct but not yet a
performance acceptance result: H1-A1 must benchmark build, cache integrity,
memory, restart, and latency before activation. An unbounded fallback or an
undeclared smaller bound is forbidden.

The first bounded H1-A1 scaling run reached 4,194,304 baby steps and measured
345.7 MB RSS, 70.7 seconds to build, and 69.2 seconds for the worst recovery on
an Apple M1/8 GiB host. Linear projection puts the current `HashMap` full table
near 11.94 GB RSS and roughly 40 minutes per build or worst recovery. The full
attempt was therefore not run on undersized hardware. Exact commands, smaller
scales, and caveats are recorded in
[`../research/H1-A1-PROOF-ENGINEERING.md`](../research/H1-A1-PROOF-ENGINEERING.md).
The subsequently selected cache artifact persists only the canonical compressed
point sequence in implicit index order, binds the exact encryption scheme,
aggregation policy, maximum, and dimensions, and authenticates header plus
payload with a caller-trusted BLAKE3 digest. It never serializes Rust's
randomized `HashMap`; restart streams the validated sequence into a new map.
The exact format is frozen in
[`../specs/BURN_AGGREGATION_V1.md`](../specs/BURN_AGGREGATION_V1.md#h1-a1-canonical-cache-artifact).
At the full bound the file is exactly 4,637,240,716 bytes. Bounded local runs
through 4,194,304 steps reproduced deterministic digests and reduced restart
to 1.405 seconds at that scale, but the full digest, actual memory, startup, and
worst recovery still require the declared external validator host. No
replacement algorithm has been accepted.

The native API admits shares only for an `OpenableBurnAggregate` containing at
least 128 unique finalized effects and spanning at least 16 public settlement
windows. Low-volume aggregates carry forward under the same key indefinitely;
a timeout never permits an individual or smaller aggregate decryption. The
aggregate ID binds exact membership, windows, key, and ciphertext sum, and each
DLEQ share binds that ID. Invalid shares are filtered, participants are
deduplicated, and the lowest valid threshold is selected deterministically.

## Implemented and missing

Implemented:

- canonical DKG-result descriptor and deterministic key ID;
- canonical 64-byte ciphertext parser;
- fresh encryption with redacted/zeroized witness randomness;
- homomorphic aggregation;
- zeroized secret-share import checked against DKG commitments;
- DLEQ-proven aggregate decryption shares and deterministic interpolation;
- recovery of the exact aggregate message group element;
- canonical aggregate membership and a frozen H1-C4 policy ID;
- type-gated 128-effect/16-window privacy eligibility and fail-closed
  carry-forward;
- deterministic bounded baby-step/giant-step integer recovery;
- canonical policy-bound recovery cache encoding with trusted digest checking;
- invalid-share filtering, participant deduplication, and deterministic
  threshold selection;
- deterministic scheme, key, and ciphertext vectors;
- malformed-key, malformed-ciphertext, amount-bound, and aggregation tests;
- typed transfer-v2 constructor and scheme-specific point validation;
- Halo2 gadget proving the burn commitment, `C1`, and `C2` equations from the
  exact same range-constrained burn cell produced by the 0.5% arithmetic and
  integrated into the vector-locked monolithic statement.

Still mandatory:

- audited DKG, complaints, resharing, validator rotation, and transcript format;
- secret-share storage and erasure policy;
- H2 finalized contribution admission, window/epoch scheduling, share
  publication/equivocation, and public-supply state integration;
- side-channel, fuzz, full-bound resource benchmark, and independent
  cryptography reviews.

Until these are complete, this scheme ID must not appear in an activated state
configuration.
