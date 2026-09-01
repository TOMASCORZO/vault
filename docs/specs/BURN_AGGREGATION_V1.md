# Vault hidden-burn aggregation policy v1

**Status:** specified; implementation and activation remain open
**Policy version:** 1
**Applies to:** transfer-v2 burn scheme
`979c61f6d12a25da66d5cffc659cb996d6f2cb1291ad31ce9dc0e93146996f82`

## 1. Purpose and security boundary

Every accepted transfer proof enforces the exact burn and conservation rules,
but the burn amount remains encrypted. This policy defines when ciphertexts may
be aggregated and opened, how validator shares rotate, and how the public supply
statistic advances without ever treating a missing aggregate as zero.

Burn disclosure is delayed accounting, not the source of monetary safety.
Transaction proofs prevent inflation even when aggregate recovery is delayed or
stalled. A displayed supply value MUST be labelled as an upper bound whenever
any accepted burn ciphertext has not reached a finalized aggregate report.

The words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and MAY
are normative.

## 2. Frozen v1 policy

| Parameter | v1 value |
|---|---:|
| Collection window | 4,096 finalized blocks |
| Minimum ciphertext count | 256 accepted transfer-v2 transactions |
| Minimum distinct-block span | 64 finalized blocks containing those transactions |
| Share publication deadline | 64 finalized blocks after sealing |
| Recovery deadline | 512 finalized blocks after sealing |
| Decryption threshold | `floor(2n / 3) + 1` of the burn-key committee |
| Concurrent open aggregates | 1 per burn-key lineage |

These values are consensus parameters under policy version 1. Changing any one
requires a new policy version, deterministic vectors, migration rules, and an
explicit activation height. Node-local configuration MUST NOT change them.

The count and block-span rules are necessary disclosure floors, not a claim that
256 transactions imply 256 independent users or unknown amounts. Zero-burn
transactions, Sybil activity, timing information, and external knowledge can
reduce the effective anonymity set. Vault MUST NOT advertise the numeric count
as a guaranteed anonymity set.

V1 deliberately has no minimum aggregate-value test. The value is hidden until
the aggregate is opened, so testing it before disclosure would require another
proof construction. Decrypting first and suppressing a small value would already
have disclosed it to the threshold participants.

## 3. Canonical accumulator

For each finalized block, nodes process accepted transfer-v2 transactions in
canonical block order and add each validated 64-byte burn ciphertext to the
active accumulator. The accumulator commits to:

- policy version and burn scheme ID;
- burn-key lineage and every authorized descriptor/key ID used;
- first and last finalized block heights;
- transaction count and distinct non-empty block count;
- component-wise Pallas ciphertext sum;
- an ordered hash of contributing transaction IDs.

Nodes MUST be able to reconstruct this state from finalized blocks. Arrival
order, mempool order, wall-clock time, and decryption-share arrival order MUST
NOT affect it.

At each 4,096-block boundary:

1. if no ciphertext has been accumulated, the empty state carries forward;
2. if either minimum is unmet, the same ciphertext and counts carry forward
   without publishing decryption shares;
3. if both minimums are met, the aggregate seals at that boundary and no later
   ciphertext may alter its identifier or sum.

There is no timeout that forces a low-volume aggregate to open. It continues
across collection windows until both disclosure floors are met. This prefers a
stale public supply statistic over disclosing a small batch.

Because v1 permits only one open aggregate per lineage, sealing pauses new
shielded-transfer acceptance until the report finalizes and the successor
`Collecting` state is active. Nodes MUST NOT append new ciphertexts to a sealed
aggregate or create an untracked parallel accumulator.

## 4. DKG and trust model

The burn-key committee is the finalized validator committee selected by the
consensus rules and MUST contain at least four participants. For committee size `n`, the threshold is
`floor(2n / 3) + 1`; no operator or governance action may lower it for an
existing lineage.

The initial key MUST be produced by a publicly verifiable dealerless DKG with:

- deterministic participant identifiers and qualified-set ordering;
- Feldman coefficient commitments matching the descriptor consumed by Vault;
- authenticated contributions, complaints, justifications, and exclusions;
- a transcript hash finalized by consensus before the key becomes acceptable;
- at least the threshold number of qualified participants;
- proof of possession or equivalent confirmation that qualified validators hold
  shares matching their public verification keys.

An invalid, incomplete, equivocated, or non-finalized transcript leaves the burn
key inactive. Vault MUST NOT fall back to one validator, a static operator key,
public burn amounts, or an all-zero key.

The confidentiality assumption is explicit: any threshold-sized coalition can
decrypt an aggregate and could collude to target individual ciphertexts outside
the protocol. Safety assumes fewer than the threshold shares are compromised in
one proactive-refresh period. Old shares MUST be erased after a finalized
refresh and the applicable recovery-retention boundary.

## 5. Validator rotation and low-volume carry

The burn-key lineage is decoupled from a validator-set epoch. Low-volume carry
MUST preserve the same Pallas encryption public key so ciphertexts remain
additively compatible.

Before a validator-set change, the old threshold committee MUST complete a
publicly verifiable proactive refresh/reshare to the successor committee while
preserving the encryption public key. The successor descriptor has a new key ID
and participant commitments. Consensus records both descriptors as consecutive
members of one lineage, and the accumulator MAY combine their ciphertexts only
after verifying that they commit to the same encryption public key and a
finalized reshare transcript.

If a valid same-key reshare cannot finish, Vault MUST pause acceptance of new
shielded transfers before the old descriptor retires. It MUST NOT:

- rotate to an unrelated key while silently dropping or stranding the carried
  aggregate;
- decrypt below the disclosure floors;
- copy a secret into a centralized recovery service;
- reinterpret a missing amount as zero.

Consensus and transparent operations may continue while shielded transfer
acceptance is paused. Recovery resumes only after a valid reshare or the current
aggregate completes under a threshold of authorized shares.

## 6. Share publication and malicious participants

Once an aggregate seals, authorized participants publish a share bound to the
policy version, lineage, descriptor/key ID, aggregate ID, aggregate ciphertext,
and participant ID. Every share MUST carry the implemented Chaum-Pedersen/DLEQ
proof against the participant verification key.

Nodes reject malformed, duplicate, unauthorized, wrong-aggregate, or invalid
shares. Conflicting signed messages from one participant are objective
equivocation evidence; punishment is a consensus/economics rule, not a reason
to accept either invalid share.

After the 64-block publication deadline, nodes deterministically select the
lowest participant IDs forming exactly one valid threshold subset. Because all
valid subsets interpolate the same secret, alternative valid subsets MUST yield
the same recovered group element. Any disagreement is a fatal implementation or
transcript error and places the burn subsystem in `Stalled`.

## 7. Missing shares and bounded recovery

Fewer than the threshold valid shares at the publication deadline enters
`Recovering`; it does not finalize a zero burn. Until 512 finalized blocks after
sealing, validators may republish the same valid shares from authenticated
backups and nodes continue collecting valid shares. The threshold and aggregate
remain immutable.

At the recovery deadline, failure to obtain a threshold enters `Stalled` and
pauses new shielded transfers. There is no emergency threshold reduction or
trusted plaintext override. The state exits `Stalled` only when the missing
valid shares become available or a previously authorized same-key recovery
transcript supplies a valid threshold.

After interpolation, the recovered point is `[B]H`. Recovery of integer `B` is
bounded to:

```text
0 <= B <= issued_supply - confirmed_burn_total
```

For the current monetary policy the initial upper bound is
21,000,000,000,000,000 atomic units. A proposer MAY use a precomputed
baby-step/giant-step table or another deterministic bounded discrete-log
algorithm. Consensus validation MUST NOT repeat that search: it checks the
proposed integer with one scalar multiplication, verifies `[B]H` equals the
recovered point, and enforces the remaining-supply bound.

Failure to recover an integer by the same 512-block deadline enters `Stalled`.
Unbounded search, wraparound, multiple accepted integers, or an operator-supplied
unverified amount are forbidden. C6/A4 measurements must establish practical
time and memory bounds before activation.

## 8. Supply-statistic update

A finalized aggregate report contains the aggregate ID, exact threshold share
subset, recovered point, recovered integer, policy version, and predecessor
report hash. Nodes independently reconstruct the ciphertext from finalized
transactions and verify every share before applying:

```text
confirmed_burn_total' = confirmed_burn_total + B
reported_supply_upper_bound = issued_supply - confirmed_burn_total'
```

Both arithmetic operations are checked and `confirmed_burn_total'` MUST NOT
exceed issued supply. An aggregate ID may update the statistic exactly once.
Reports are finalized in aggregate order; later reports cannot skip an earlier
sealed aggregate.

The published value is exact only when no accepted ciphertext is pending in a
collecting, sealed, recovering, or stalled aggregate. Otherwise interfaces MUST
display it as an upper bound and disclose the pending transaction count and
oldest pending height without estimating hidden amounts.

## 9. State machine and fail-closed activation

The only valid state progression is:

```text
PreparingKey -> Collecting -> Sealed -> Sharing -> Recovering -> Finalized
                                          |             |
                                          +----------> Stalled
```

`Recovering` may be skipped when a threshold and integer are available before
the publication deadline. `Stalled` is recoverable but has no timeout bypass.

Activation requires all of the following to be versioned and reproducible:

- policy serialization and policy ID;
- DKG and same-key reshare transcript codecs and verification;
- canonical accumulator and aggregate-report codecs;
- crash-consistent persistence and replay from finalized blocks;
- share equivocation, missing-share, rotation, low-volume, overflow, reorg, and
  stalled-state vectors;
- bounded integer-recovery implementation and declared hardware measurements;
- activation, deactivation, rollback, and migration procedures.

If any required policy, descriptor, transcript, accumulator, proof, share, or
report is absent or invalid, shielded transfer acceptance fails closed. No
development, mock, public-burn, trusted-dealer, or zero-burn fallback may be
compiled into an activatable path.

## 10. Implementation boundary

This document closes the C5 design decision. It does not claim the DKG network
protocol, reshare lifecycle, consensus accumulator, bounded discrete-log search,
or operational persistence is implemented. Those are activation work under H2
and A4/A5 and must pass the project-controlled reproducible test gates before
the burn scheme can be activated.
