# Burn aggregation policy v1

**Normative H1-C4 record:** 2026-08-25
**Policy ID:** `70bc5d1f3f22bda5c0c6c2e558d554e3187dd144e2bb1051699d5723d542a6e3`
**Maturity:** production-intent, internally checked, unaudited, not activated,
unsafe for real funds

## 1. Scope and boundary

This specification freezes the cryptographic transition from finalized
transfer-v2 burn ciphertexts to one public aggregate burn amount. It defines
canonical aggregate formation, privacy eligibility, timeout behavior,
threshold-share handling, bounded integer recovery, and failure behavior.

This specification does not define DKG networking, validator selection,
finality, share gossip or publication, block/epoch scheduling, slashing, or
public-supply state integration. Those are H2 consensus/network work. H1-A1
still owns full-bound resource benchmarks and artifact engineering; H1-A4 owns
independent cryptographic review and activation.

No API in `vault-burn` can produce a decryption share for an individual
`BurnCiphertext` or a low-volume raw sum. Shares accept only an
`OpenableBurnAggregate`, whose constructor is private to the policy transition.
This type boundary is defense in depth, not a defense against a threshold of
validators deliberately reconstructing the epoch secret outside Vault.

## 2. Frozen parameters

| Parameter | Value |
|---|---:|
| Encryption scheme ID | `979c61f6d12a25da66d5cffc659cb996d6f2cb1291ad31ce9dc0e93146996f82` |
| Minimum distinct transfer effects | 128 |
| Minimum public settlement-window span | 16 |
| Maximum contributions in one aggregate | 65,536 |
| Maximum recovered burn | 21,000,000,000,000,000 atomic units |
| Recovery algorithm | deterministic baby-step/giant-step |
| Full-bound baby/giant step count | 144,913,768 each |

The 128-effect and 16-window floors are public cardinality and delay floors,
not claims of 128 distinct people or an anonymity set of exactly 128. A single
adversary may create many transfers, and network/timing observations may reduce
effective anonymity. A private minimum monetary value cannot be tested before
decryption with the current statement without leaking a value bucket or adding
another proof. Policy v1 therefore uses observable effect count and window span
as its pre-opening volume rule and makes no stronger claim.

The maximum recovered burn is the complete 21 million VLT supply in atomic
units. It is the only smaller-message bound already implied by transaction
conservation and the immutable supply cap without changing the vector-locked
H1-C3 circuit. H2 must admit each finalized transfer effect exactly once; under
that rule an aggregate burn cannot exceed the starting supply. A result outside
the bound is invalid and must not update public supply state.

## 3. Contributions and canonical formation

H2 supplies a contribution only after successful transfer proof verification
and finality. Each contribution contains:

```text
effect_id          [32]  non-zero canonical transfer-effects identity
settlement_window  u64   public monotonically ordered window
epoch              u64   inherited from the validated DKG descriptor
key_id             [32]  inherited from the validated DKG descriptor
ciphertext         [64]  canonical Pallas burn ciphertext
```

All integer encodings below are unsigned little-endian. One aggregate accepts
only the frozen encryption scheme and one exact `(epoch, key_id)`. It rejects a
zero or repeated `effect_id`, a contribution at or before an already closed
window, a contribution before `first_window`, the wrong epoch/key, an empty
append, or more than 65,536 contributions. Append is atomic: any invalid member
leaves the aggregate unchanged.

Canonical contribution order is ascending lexicographic `effect_id` bytes.
The homomorphic ciphertext is the component-wise Pallas sum of the ciphertexts
in that canonical membership set. Point addition is order independent, but the
canonical order is required for a unique aggregate identity.

The aggregate ID is:

```text
BLAKE3 derive-key context =
  vault.burn.pallas-threshold-elgamal-v1.aggregate.v1

input = encryption_scheme_id                         [32]
     || epoch                                        u64
     || key_id                                      [32]
     || first_window                                 u64
     || closed_through                               u64
     || contribution_count                           u64
     || for each contribution in effect_id order:
          effect_id                                 [32]
       || settlement_window                          u64
       || ciphertext                                [64]
     || aggregate_ciphertext                        [64]
```

## 4. Window close, timeout, and carry-forward

`close_through(window)` accepts only a window strictly greater than the prior
closed window and not earlier than any included contribution. At each finalized
window boundary the later consensus layer must call this transition.

The aggregate becomes ready at the first close for which both are true:

```text
contribution_count >= 128
closed_through - first_window + 1 >= 16
```

Once ready, membership and windows are frozen and no further append or close is
accepted. Only then can the state convert to `OpenableBurnAggregate`.

If either floor is missing, the outcome is `CarryForward`. A timeout never
weakens the floor and never authorizes individual or low-cardinality shares.
The aggregate remains under the same epoch key and accepts only contributions
from later windows. Ciphertexts encrypted to different keys are never merged.

There is intentionally no forced-reveal timeout. If later validator rotation,
share loss, or insufficient activity prevents the same-key aggregate from
reaching threshold, exact public-supply settlement remains pending. H2 must
specify key retention and liveness handling, but it must not substitute an
individual decryption, a smaller anonymity floor, a trusted report, or an
unverified supply update.

## 5. Aggregate-only shares and malicious participants

Each share proves equality of discrete logarithms between the participant's
descriptor-derived verification key and its share of the exact aggregate
`C1`. The Fiat-Shamir transcript uses:

```text
vault.burn.pallas-threshold-elgamal-v1.aggregate-decryption-share.v1
```

and binds the encryption scheme, epoch key ID, complete aggregate ID,
aggregate ciphertext, participant ID, verification key, share point, and both
Chaum-Pedersen announcements. A proof for the same ciphertext sum but different
membership or windows is invalid.

Invalid or unknown-participant shares do not count toward threshold and cannot
poison a valid set. Recovery verifies every candidate, sorts valid shares by
participant ID and canonical proof bytes, deduplicates participants, and uses
the lowest `t` distinct participant IDs. Fewer than `t` valid participants is a
fail-closed pending state. Exactly `t` sorted shares are interpolated at zero;
the native implementation rejects missing, repeated, decreasing, or invalid
sets at that lower boundary.

Evidence publication, equivocation classification, penalties, deadlines, and
retry transport belong to H2. No such rule may cause an invalid share to be
accepted or a privacy floor to be bypassed.

## 6. Bounded discrete-log recovery

Threshold interpolation removes the ElGamal mask and returns
`[aggregate_burn]H`. Policy v1 recovers the integer with deterministic
baby-step/giant-step over the inclusive interval
`[0, 21_000_000_000_000_000]`.

For an explicit maximum `M`, the implementation stores
`m = ceil(sqrt(M + 1))` baby steps `iH`, then tests at most `m` giant steps
`Q - jmH`. A match is accepted only after recomputing `[candidate]H` and only
when `candidate <= M`. No match returns an error; there is no unbounded fallback.
This is the standard bounded-interval application of baby-step/giant-step,
whose time and memory are both `O(sqrt(M))`; improved interval variants are
surveyed by [Galbraith, Wang, and Zhang](https://eprint.iacr.org/2015/605.pdf).

At the full supply bound, `m = 144,913,768`. That table is intentionally not
built by the normal unit gate and this algorithm is not executed during normal
transfer construction or verification. H1-A1 must benchmark table build,
canonical cache integrity, memory, restart, and recovery latency on target
validator hardware. Failure to meet the resource gate requires a reviewed
bounded replacement and a new aggregation policy ID; it does not permit an
unbounded search or a lower undeclared maximum.

### H1-A1 canonical cache artifact

The cache is an engineering artifact for reconstructing the same in-memory
BSGS map; it is not a new recovery algorithm and does not change this policy
ID. Version 1 stores the already generated baby-step point sequence in implicit
increasing index order, avoiding any persistence of Rust's randomized
`HashMap` layout. All integer fields are unsigned little-endian:

```text
offset  bytes  field
0       4      magic = "VBRC"
4       2      version = 1
6       2      header_bytes = 104
8       32     BURN_ENCRYPTION_SCHEME_ID
40      32     BURN_AGGREGATION_POLICY_ID
72      8      inclusive maximum M
80      8      step_size = ceil(sqrt(M + 1))
88      8      record_count = step_size
96      2      record_bytes = 32
98      6      reserved = zero
104     32*m   record i = canonical compressed point [i]H
...     4      trailer magic = "VBRE"
...     32     content digest
```

The content digest is BLAKE3 derive-key mode with context
`vault.burn.bsgs-recovery-cache.v1` over the complete 104-byte header followed
by every record; the trailer is not hashed. A loader must compare the computed
digest both with the trailer and with a non-zero value obtained from trusted
activation configuration. The embedded digest alone is not authentication.
Wrong scheme, policy, maximum, dimensions, reserved bytes, duplicate records,
truncation, extension, or digest mismatch fails closed before recovery.

The full-bound artifact length is exactly 4,637,240,716 bytes. Loading streams
the authenticated records into the existing point-to-index `HashMap`; only the
canonical input sequence is persisted. A partial cache build is never a valid
artifact and must be discarded. H1-A1 must reproduce and freeze the full-bound
digest independently before activation.

The preliminary H1-A1 scaling record in
[`../research/H1-A1-PROOF-ENGINEERING.md`](../research/H1-A1-PROOF-ENGINEERING.md)
measured the current in-memory `HashMap` through 4,194,304 steps. Its linear
full-bound projection is approximately 11.94 GB RSS and 40 minutes each for
build and worst-case recovery on the local M1/8 GiB host. The full table was
not attempted because the projected RSS exceeds physical memory. This rejects
that host/representation combination; it does not change the algorithm, bound,
policy ID, or requirement for a target-hardware full run and independently
reproduced canonical-cache digest.

## 7. Deterministic and adversarial evidence

The native fixture uses epoch 9, threshold 2-of-3, deterministic encryption,
128 effects ordered by IDs 1 through 128, windows 100 through 115, amounts 50
and 25 followed by 126 zero amounts, and produces:

```text
aggregate_id = af940d5041dcec18841752660c5674afa3e7b89e0546c63596388c15eea504d4
recovered burn = 75
```

Tests cover exact recovery at 0, 1, step boundaries, and the inclusive maximum
of a bounded fixture; rejection immediately outside the bound; both privacy
floors independently; indefinite low-volume carry-forward; stale windows;
duplicate IDs; wrong keys; capacity overflow; malformed and insufficient
shares; invalid shares mixed with a valid threshold; and reuse of a valid share
against the same ciphertext sum with different membership.

The policy remains unaudited and non-activatable. These tests demonstrate the
specified native transition; they do not supply H2 finality, DKG operations,
network privacy, target-hardware performance acceptance, or independent review.
