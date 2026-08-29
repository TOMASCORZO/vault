# Vault delegated transfer proving profile v1

**Status:** production-intent authorization, disclosure, VDPW/VDPR/VDPS
codecs, verification and revocation contracts implemented; remote transport,
platform adapters and external review not activated

**Last updated:** 2026-08-28

## 1. Scope and trust boundary

Delegated proving lets a wallet ask a separate machine to generate the already
selected monolithic Halo2 transfer-v2 proof. It does not select another proof
system, modify the circuit, authorize a spend, submit a transaction, or add a
network/consensus service. Local proving remains the mandatory default.

The prover is untrusted for correctness and availability: the wallet verifies
the returned proof locally against the exact canonical effects before it can be
used. The prover is necessarily trusted for confidentiality of every witness
value disclosed to it. Authentication and encryption protect the channel, not
the remote endpoint after decryption.

Delegation is therefore an explicit per-job opt-in. No background fallback may
silently move local proving to a third party, and failure must return to the
wallet without releasing a signature or accepting a partial proof.

## 2. Exact disclosure profile

Version 1 has one disclosure profile,
`CompleteTransferWitnessWithFullViewingKeyV1`. The current circuit requires
the remote prover to learn:

- every consumed and created note witness, including recipients, values,
  randomness and the input membership position/path;
- the complete private input/output, enabled/dummy, taxable/change and burn
  accounting relationship;
- the action randomizers `alpha`, net-value trapdoors, burn-commitment
  randomness and burn-encryption randomness; and
- `ak`, `nk` and `rivk`, the three components of the raw Orchard
  full-viewing key witnessed by the Action circuit.

The final item is the raw Orchard full-viewing key. `ak`, `nk` and `rivk`
together derive incoming and outgoing viewing keys, diversified addresses and
nullifiers for both external and internal scopes. The prover can therefore
discover, recover and link past and future account activity visible to that
full-viewing capability. Revocation cannot undo this knowledge. The
confirmation surface MUST state this consequence before every job.

The profile does not disclose the seed, spending authorization key, complete
spending key, signer transport private key, or a spend signature. It does
disclose the full viewing capability, including derivable outgoing viewing
keys, but proof generation alone still cannot authorize the transaction. A
later profile claiming less disclosure requires a separately reviewed circuit
or cryptographic construction; transport encryption or a promise to delete
data does not qualify.

## 3. Dedicated prover identity and policy

Prover transport keys are dedicated to this protocol. They MUST NOT be derived
from or reused as spending, viewing, signer Noise, multisignature, wallet
database, or node identities. The authenticated transport must bind the exact
32-byte public key recorded by the policy and supply a fresh non-zero 32-byte
channel binding for each job.

`DelegatedProvingPolicy` authorizes one exact network, transfer circuit, Halo2
suite, padded action count, prover key, witness bound, and exact expected proof
length. Its `VDPP` codec is 148 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VDPP` |
| 4 | 2 | version `1` |
| 6 | 1 | disclosure profile `1` |
| 7 | 1 | exact action count: 2, 4, 8 or 16 |
| 8 | 32 | non-zero network ID |
| 40 | 32 | non-zero transfer circuit ID |
| 72 | 32 | non-zero proof-suite ID |
| 104 | 32 | dedicated prover transport public key |
| 136 | 4 | maximum canonical witness-package bytes |
| 140 | 4 | exact expected proof bytes |
| 144 | 4 | reserved zero |

Canonical VDPW witnesses are absolutely bounded at 60,286 bytes before
allocation or cryptographic work. The policy may set a smaller witness bound.
Proofs retain the protocol-wide 2 MiB rejection ceiling, while current selected
Halo2 suites require their exact 9,600- or 9,664-byte proof length.

The policy ID uses BLAKE3 derive-key mode with domain
`vault.signer.delegated-proving.policy.v1`. The 128-bit display fingerprint uses
the separate domain `vault.signer.delegated-proving.fingerprint.v1`. Neither
unkeyed digest authenticates the endpoint; the paired transport does.

## 4. One exact authorization

Every job has a fresh random non-zero 32-byte ID and a non-zero durable
monotonic authorization counter. It binds the exact policy, channel, canonical
effects digest and canonical witness-package commitment. The witness commitment
uses BLAKE3 derive-key mode with domain
`vault.signer.delegated-proving.witness.v1` over the complete VDPW v1 package
encoding.

`DelegatedProvingAuthorization` has this fixed 184-byte `VDPA` codec:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VDPA` |
| 4 | 2 | version `1` |
| 6 | 1 | exact action count |
| 7 | 1 | disclosure profile `1` |
| 8 | 8 | non-zero durable authorization counter |
| 16 | 32 | policy ID |
| 48 | 32 | fresh job ID |
| 80 | 32 | authenticated channel binding |
| 112 | 32 | canonical transfer-v2 effects digest |
| 144 | 32 | complete witness-package commitment |
| 176 | 4 | exact witness-package byte length |
| 180 | 4 | exact expected proof byte length |

Construction receives the complete typed `TransferV2Effects` and rejects a
different network, circuit, action bucket or effects digest before approval.
The authorization ID uses BLAKE3 derive-key mode with domain
`vault.signer.delegated-proving.authorization.v1` over all 184 bytes.

`TrustedDelegatedProvingAuthorization` must independently display or verify the
prover fingerprint, network, circuit/suite, action count, channel binding,
effects digest, witness/proof sizes, job/counter, exact disclosure profile and
its persistent full-viewing consequence. The crate ships no auto-approve
implementation. Rejection changes no durable job state and releases no witness.

The canonical VDPW witness, self-contained VDPR request and contextual VDPS
response are implemented and frozen by
[`SIGNER_CORPUS_V1.md`](SIGNER_CORPUS_V1.md). VDPR contains exact VDPP, VDPA,
VLT2 and VDPW encodings. VDPS binds policy/job/authorization/effects identities
and proof length, but successful parsing never substitutes for local proof
verification.

## 5. Durable job lifecycle

Only one job may be active per policy. A concrete
`DelegatedProvingJobLifecycle` adapter MUST enforce this state machine in
rollback-resistant storage:

1. trusted approval is obtained for an exact proposed authorization;
2. its counter, job ID and authorization ID are atomically reserved before the
   authorization or witness is sent;
3. the authenticated channel key and channel binding are checked again;
4. phase `disclosed` is durably committed before any witness byte leaves the
   wallet;
5. the sent package is byte-exact, within policy bounds and hashes to the
   authorization's witness commitment;
6. a returned proof is accepted only through `DelegatedTransferProofVerifier`
   for the exact policy suite and effects;
7. the job is atomically closed before verified proof bytes are returned to
   transaction construction; and
8. every retry uses a fresh job ID, counter, channel and witness authorization.

Timeout, transport failure, peer revocation, package mismatch, malformed or
wrong-length proof, local verification failure, storage uncertainty, user
abort, or coordinator/prover equivocation aborts the complete job. No partial
proof or stale authorization is reusable. A failed or uncertain durable
transition permanently poisons the open lifecycle handle.

The lifecycle record must survive process/device restart and reject restoration
of an older valid state. A checksum, ordinary file rename, database transaction
or volatile mutex alone does not satisfy the rollback requirement. Concrete
platform storage remains an external A3 gate.

## 6. Local proof acceptance

`DelegatedTransferProofVerifier` is the only final adapter boundary. It receives
the exact selected suite ID, typed canonical effects and returned proof bytes.
The wrapper independently rechecks network, circuit, action count, effects
digest and exact proof length before invoking that adapter. The crate contains
no permissive verifier.

Successful verification yields a non-cloneable `VerifiedDelegatedTransferProof`
bound to the authorization and effects digest. This is not a spend
authorization: the separately confirmed RedPallas signer flow remains required.
Consensus still verifies the same proof bytes under the activated verifier.

## 7. Revocation and deletion limits

Active-job abort is always allowed as a safety action. Permanent policy
revocation requires `TrustedDelegatedProverRevocation` over the policy,
generation and optional active authorization. The lifecycle adapter closes the
active channel before durably committing the tombstone. Uncertain persistence
leaves the local channel closed and the handle poisoned.

Revocation blocks future local disclosure and rejects any later result from the
revoked job. It cannot erase a witness already decrypted by the prover, revoke
the account full-viewing capability already learned, or prove remote deletion.
Retention limits, logging, crash dumps, swap, backups and operator access
therefore remain explicit endpoint trust and audit requirements.

## 8. Remaining activation evidence

A3-5 and A3-6 freeze these contracts and their bounded local corpus. Activation
still requires:

- a dedicated mutually authenticated encrypted prover transport and durable
  policy/job store implementing the frozen lifecycle;
- a real adapter to every selected Halo2 suite and positive/negative proof
  evidence;
- endpoint memory, swap, crash-dump, log, deletion and rate-limit review;
- restart, rollback, timeout, revocation and equivocation fault campaigns; and
- independent privacy, cryptography and implementation review.

The committed A3-6 corpus, byte-reproduction script, parser tests, bounded
fuzzer and latency/memory runner are local engineering evidence only. The VDPS
context-negative vectors deliberately fail local proof verification; positive
real-proof acceptance remains in the H1-C3 suite corpus.

Until those gates close, delegated proving must not be used with real funds or
represented as a privacy-preserving third-party service.
