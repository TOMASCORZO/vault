# Vault threshold signing profile v1

**Status:** production-intent participant-agreement and failure contracts
implemented; concrete FROST cryptography, key ceremony and platform adapters
not activated

**Last updated:** 2026-08-27

## 1. Scope and selected construction

Vault multisignature is a wallet signing profile, not a consensus extension.
The on-chain authorization remains the same 64-byte RedPallas SpendAuth
signature under the randomized action key `rk` already constrained by
transfer-v2. Validators learn neither the threshold nor the participant set.

The only selected threshold construction is re-randomized FROST for RedPallas
SpendAuth, following ZIP 312 and RFC 9591. It MUST use the account spend
validating key `ak` as its group key and the proof witness `alpha` to produce
the exact action key:

```text
rk = ak + alpha * G
```

The epoch burn-key DKG is unrelated and MUST NOT be reused. Burn DKG execution,
validator membership and finality remain H2. A multisig key ceremony operates
only on a wallet's RedPallas SpendAuth key package.

The current pinned `reddsa` FROST feature remains disabled. Enabling it would
activate a dependency chain retained in `Cargo.lock` only for resolution and
currently excluded by `scripts/audit.sh` because it reaches the allowed-but-
inactive `RUSTSEC-2023-0089` package. Its recommended randomizer-seed flow also
requires an integration proving that the resulting scalar is exactly the
`alpha` already bound by Vault's proof. Vault therefore freezes the product
contract without substituting a home-grown threshold implementation or a fake
share generator. A future adapter must use a reviewed dependency graph, prove
this exact randomizer compatibility and pass the full audit gate.

## 2. Enrollment policy

One immutable `MultisigPolicy` contains:

- a non-zero Vault network ID;
- the exact account-level RedPallas group validating key derived from the
  account full-viewing key;
- threshold `t`, with `2 <= t <= n`;
- between 2 and 16 strictly sorted non-zero participant IDs; and
- for every participant, one unique active `PairedPeerId` and one unique,
  canonical, non-identity RedPallas verifying share.

The bound of 16 matches the maximum active paired signer set. The policy codec
is `72 + 66*n` bytes, at most 1,128:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VMSP` |
| 4 | 2 | version `1` |
| 6 | 1 | threshold `t` |
| 7 | 1 | participant count `n` |
| 8 | 32 | network ID |
| 40 | 32 | account RedPallas group validating key `ak` |
| 72 | `66*n` | sorted entries: ID `u16`, peer ID `[32]`, verifying share `[32]` |

`MultisigPolicyId` is BLAKE3 derive-key mode over the complete canonical
encoding with domain `vault.signer.multisig.policy.v1`.

Parsing validates encodings, bounds, uniqueness and ordering. It cannot prove
that independently supplied shares interpolate to the group key. Before
enrollment, every concrete FROST adapter MUST validate the complete public key
package, and every participant MUST validate its secret key package, identifier,
threshold, group key and verifying share against that same package. Dealer
splitting, DKG, share repair, resharing and recovery are not implemented here.
Changing any roster, peer, share, threshold or group key creates a new policy
and requires a new trusted enrollment/recovery ceremony.

## 3. Attempt and round-one commitments

Every action is a separate two-round attempt with a fresh random non-zero
32-byte `MultisigAttemptId`. Vault selects exactly `t` participants, not a
super-threshold set. This removes ambiguous partial completion: every selected
participant is required, and any failure aborts that complete attempt.

Before exposing a round-one commitment, each selected participant MUST durably
reserve fresh FROST hiding and binding nonces under the tuple:

```text
(policy_id, attempt_id, signing_transcript_id, action_index, action_count)
```

All `2*t` public commitments must be mutually distinct, canonical, non-identity
Pallas points. `MultisigCommitmentSet` contains exactly `t` participant pairs,
strictly sorted by participant ID, and no participant outside the enrolled
policy. Its codec is `72 + 66*t` bytes, at most 1,128:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VMSC` |
| 4 | 2 | version `1` |
| 6 | 2 | commitment count, exactly `t` |
| 8 | 32 | policy ID |
| 40 | 32 | attempt ID |
| 72 | `66*t` | sorted entries: participant ID, hiding point, binding point |

Its domain-separated digest uses
`vault.signer.multisig.commitments.v1` over the complete encoding.

## 4. Round-two agreement

Before releasing a share, every selected signer independently validates the
same transfer request and constructs the exact `MultisigSigningAgreement`.
The agreement binds:

- policy and attempt IDs;
- the paired-channel `SigningTranscriptId` covering the challenge, signer
  policy, complete public effects and ordered private output packets;
- public-input/effects digest and its derived RedPallas authorization message;
- action index and complete padded 2/4/8/16 action count;
- exact threshold-sized selected participant set and round-one commitment-set
  digest;
- the action's `rk`; and
- a domain-separated commitment to the confidential proof/FROST `alpha`.

Construction rejects an `alpha` that does not randomize the policy group key to
the exact `rk` already bound by the action. The codec is `266 + 2*t` bytes, at
most 298:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VMSA` |
| 4 | 2 | version `1` |
| 6 | 1 | action index |
| 7 | 1 | action count |
| 8 | 1 | selected count, exactly `t` |
| 9 | 1 | reserved zero |
| 10 | 32 | policy ID |
| 42 | 32 | attempt ID |
| 74 | 32 | signing transcript ID |
| 106 | 32 | public-input/effects digest |
| 138 | 32 | exact RedPallas authorization digest |
| 170 | 32 | proof-bound randomized validating key `rk` |
| 202 | 32 | commitment to confidential `alpha` and attempt context |
| 234 | 32 | round-one commitment-set digest |
| 266 | `2*t` | strictly sorted selected participant IDs |

`MultisigAgreementId` uses BLAKE3 derive-key mode with domain
`vault.signer.multisig.agreement.v1` over the complete encoding. Each signer
must approve this exact ID through `TrustedMultisigAgreement`; the crate has no
auto-approve implementation. `ConfirmedMultisigAgreement` is a one-participant,
one-attempt, non-serializable token intended to be consumed by the concrete
FROST adapter before producing a share.

## 5. Failure and nonce rules

`MultisigParticipantRound` freezes these mandatory adapter semantics:

1. nonce secrets are generated with a CSPRNG and durably bound before public
   commitments leave the participant;
2. a nonce pair is used for at most one action, package and attempt, including
   across process/device restart;
3. signing receives the complete commitment set, requires the matching
   participant confirmation token, and independently reconstructs the
   agreement before using that set to calculate a share;
4. the nonce is atomically marked spent or irreversibly destroyed before a
   signature share is released;
5. abort also destroys every reserved nonce; an uncertain storage result fails
   closed and permanently forbids reuse;
6. timeout, unavailable/revoked selected peer, wrong policy/transcript/action,
   coordinator equivocation, altered participant set or commitments, invalid or
   duplicate share, aggregation failure, or final-signature failure aborts the
   whole exact-threshold attempt; and
7. retry creates a fresh attempt ID and fresh nonce pair for every newly
   selected participant. No commitment or share crosses attempts.

Dropping a failing selected participant from the same signing package is
forbidden. A retry may select another threshold-sized subset, but only under a
new attempt. Diagnostics and transport aborts remain opaque and must not reveal
which participant or private policy check failed to an unauthenticated peer.

## 6. Final authorization boundary

The concrete FROST coordinator may be untrusted for correctness and may cause
denial of service. It never receives secret shares. After aggregating, it must
produce the ordinary 64-byte RedPallas signature under the agreement's `rk`.

`BoundTransferV2SigningSession::attach_multisig_authorization` accepts that
signature only when the agreement has the session's exact transcript, effects,
authorization digest, action count/index and proof-bound key. The underlying
`PreparedTransferV2Authorization` independently verifies the standard signature
before retaining it. No threshold metadata or alternate signature format enters
the transaction or consensus verifier.

Local tests validate all three codecs, bounds, ordering, duplicate/unknown
participants, exact-threshold selection, attempt binding, transaction/action/
randomizer mutations, independent confirmation mismatch, and attachment of a
valid standard authorization to the real transfer session. The attachment test
uses an ordinary signing key solely to produce the same final RedPallas byte
format; it explicitly does not simulate FROST shares or count as FROST evidence.

## 7. Remaining activation evidence

Activation still requires:

- a reviewed RedPallas re-randomized FROST dependency without an active
  advisory exception and with exact Vault `alpha` compatibility;
- key-package creation/import, protected share custody, durable one-time nonce
  storage and participant/coordinator adapters;
- interoperable vectors for real FROST shares, aggregation and every
  abort/restart path. The existing A3-6 corpus freezes policy, round-one and
  agreement codecs plus the final ordinary RedPallas session format without
  fabricating threshold shares;
- physical hardware/keychain/secure-element tests plus bounded Linux
  crash/power-loss/fuzz/latency campaigns; and
- independent cryptographic, implementation and UX review.

Until those gates close, Vault multisignature must not protect real funds.

## 8. Normative references

- [ZIP 312: FROST for Spend Authorization Multisignatures](https://github.com/zcash/zips/blob/main/zips/zip-0312.rst)
- [RFC 9591: The Flexible Round-Optimized Schnorr Threshold Signature Scheme](https://www.rfc-editor.org/rfc/rfc9591)
- [Zcash Foundation `reddsa`](https://github.com/ZcashFoundation/reddsa)
