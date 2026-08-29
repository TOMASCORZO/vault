# H1-A3 signer and delegated-proving hardening

**Updated:** 2026-08-28
**Maturity:** production-intent, unaudited, not activated, unsafe for real funds

## Scope boundary

H1-A3 hardens the already selected signer construction. It does not add a new
proof system, consensus rule, network relay, node, finality mechanism, mainnet
configuration, or prototype path. Independent review remains human evidence and
cannot be replaced by an internal test or a statement in this repository.

The finite local sequence is:

1. **Complete locally:** close every registry-issued handshake and transport
   when its peer is revoked or rotated, and close all sessions after an
   uncertain registry persistence failure;
2. **Complete locally:** define the trusted pairing, transfer-intent and peer
   revocation/rotation boundaries independently of coordinator-controlled data;
3. **Complete locally:** define rollback-resistant replay/counter and
   protected-key adapter contracts for supported hardware and software
   platforms;
4. **Complete locally:** freeze multisignature participant agreement and
   failure rules without activating an unreviewed FROST dependency;
5. **Complete locally:** freeze delegated-proving authorization, disclosure,
   local-verification, lifecycle and revocation rules without activating a
   remote transport; and
6. **Complete locally:** publish complete deterministic ciphertext/signing/
   proving corpora and bounded local harnesses before external execution.

Platform adapters, physical-device evidence, external compute and independent
review follow only after their corresponding local interfaces and fixtures are
frozen. They are accumulated in
[`H1-EXTERNAL-ACCEPTANCE-CAMPAIGN.md`](H1-EXTERNAL-ACCEPTANCE-CAMPAIGN.md).

## A3-1 active-session shutdown

**Status:** local implementation and adversarial tests complete; independent
review and platform fault evidence open.

Every public KK constructor remains gated by `EncryptedPeerRegistry`. A
registry-issued `SignerHandshake` now carries a shared, peer-specific lifecycle
gate into `SignerTransport`. Each handshake or transport operation holds that
gate for the complete Noise state transition.

Revocation and rotation shut the old gate before attempting the durable
registry rewrite. Shutdown waits for an operation already in flight, then
permanently rejects later operations with the opaque `Closed` error. Therefore
no new operation can cross a successfully committed revocation boundary. A
failed or uncertain registry replacement poisons the registry and shuts every
gate, so an old in-memory channel cannot outlive uncertain lifecycle state.
Reopening an authenticated registry creates active gates only for durably active
entries; revoked tombstones remain shut down.

Tests cover:

- an established transport failing closed immediately after revocation;
- an established old transport failing closed after atomic rotation while the
  separately confirmed replacement can open a new channel; and
- all established transports failing closed after an injected registry
  persistence failure.

This is process-local revocation enforcement, not remote erasure of keys or
ciphertexts already held by a compromised peer. Trusted revocation UX,
hardware-backed state, platform adapters and external review remain required.

## A3-2 trusted confirmation boundaries

**Status:** platform-neutral contracts and fail-closed enforcement complete;
real trusted displays/input sources, accessibility review and independent review
remain platform evidence.

The signer crate supplies no permissive confirmation implementation:

- XX pairing consumes `TrustedPairingConfirmation`, which receives the exact
  role, network, local/remote static keys and fingerprint and must return the
  value independently observed from the other trusted surface;
- transfer preparation consumes `TrustedTransferIntentSource`. Only after the
  request challenge and complete public effects pass the local signer policy
  does the adapter receive network, circuit, burn scheme/key/epoch, padded
  action count, gas/fee, public-input digest and transcript ID. Recipient,
  value, classification and memo are returned from the independent source as
  zeroizing `ApprovedOutputIntent` values, never copied out of coordinator
  packets for confirmation; and
- peer revocation and rotation consume `TrustedPeerConfirmation`, which receives
  the authenticated network, local role, current fingerprint, optional fresh
  replacement fingerprint and registry generation before any shutdown or
  durable mutation occurs.

The former public raw entry points were replaced by these confirmed entry
points. Rejection neither consumes replay state nor changes peer lifecycle
state. A successful transfer still independently reconstructs every Ironwood
output and only then consumes the durable challenge. Tests bind all public
confirmation facts, reject a mismatched XX fingerprint, prove rejected
revocation leaves the active channel usable, and retain all earlier malformed
packet/policy/session cases.

These traits define the production boundary but do not claim that a terminal,
mobile screen, secure display, accessibility flow, or hardware button has been
implemented or reviewed. Those concrete adapters must be tested on their actual
devices and cannot be replaced by a generic VM.

## A3-3 protected keys and rollback-resistant replay

**Status:** canonical platform-neutral records, fail-closed wrappers and
adversarial local tests complete; concrete keychain/secure-element adapters and
physical-device evidence remain open.

`SignerProtectedKeyMaterial` binds one non-zero network and fixed
coordinator/signer role to three independently generated values: the Noise
static private key, peer-registry storage key, and registry substitution ID.
Its fixed 136-byte `VSKM` record is non-`Clone`, redacted in diagnostics, and
zeroizes both private keys on drop. `SignerProtectedKeyStore` requires one
application/user/wallet-bound protected slot with durable no-clobber creation;
`ProtectedSignerKeys` separates enrollment from normal opening, reads back and
constant-time checks a new record, and never regenerates missing material.
Plain files and password-derived storage do not satisfy the trait.

`SignerSecureReplayState` is a canonical 136-byte `VSRS` record containing a
secure transition generation, highest issued and consumed counters, and the
exact optional pending network/channel/session/counter binding. Every challenge
issue and consumption increments the transition generation.
`SignerSecureReplayStore` must atomically compare-and-swap this complete state,
survive restart and power loss, and reject restoration of an older valid value.
`RollbackProtectedReplayStore` enrolls/opens this state, reserves a challenge
before returning it, consumes only the byte-exact pending challenge, and
permanently poisons its handle on a failed or uncertain CAS. A secure-element
adapter may combine a monotonic counter with an authenticated sealed record,
but it must implement the same atomic semantics and declare counter endurance
and exhaustion behavior.

The existing `CrashConsistentReplayStore` remains useful for the explicitly
weaker Unix filesystem threat model. It detects corruption and survives
ordinary crashes, but no checksum or atomic rename can detect restoration of a
valid older snapshot. It is not an implementation of
`SignerSecureReplayStore` and is not described as hardware-backed.

Six new tests cover canonical key/state codecs, redaction, forbidden zero and
reserved fields, protected-slot no-clobber and missing-state failure, replay
state reopen, exact once-only consumption, abandoned challenge invalidation,
all four challenge bindings, concurrent CAS rejection, uncertain post-write
failure, and permanent poisoning. The in-memory adapters exist only inside the
tests and make no platform-security claim.

## A3-4 multisignature participant agreement

**Status:** production-intent policy, agreement, nonce-lifecycle contract and
final session gate complete locally; FROST cryptographic adapter, key ceremony,
protected share/nonce implementation and external review remain open.

The selected profile is re-randomized FROST for the existing RedPallas
SpendAuth signature. It adds no consensus encoding: the final transaction still
contains one ordinary 64-byte signature per action under the `rk` already bound
by the proof. The burn-key DKG is unrelated and remains outside A3.

The implemented boundary fixes:

- an immutable 2..16 participant policy with threshold `2 <= t <= n`, unique
  paired peer IDs and canonical RedPallas verifying shares;
- exactly `t` sorted participants per action-specific attempt, each with a
  fresh non-zero attempt ID and globally unique hiding/binding nonce
  commitments;
- one canonical agreement over the policy, attempt, paired signing transcript,
  effects/authorization digests, action position/count, selected set, complete
  commitment-set digest, proof-bound `rk`, and a commitment to the confidential
  `alpha`;
- independent `TrustedMultisigAgreement` confirmation with no permissive
  implementation; and
- a participant adapter contract requiring durable nonce reservation before
  commitment exposure, atomic burn before share release, burn on abort, and a
  wholly fresh attempt after any timeout, revocation, equivocation, invalid
  share, storage uncertainty, aggregation failure or final verification
  failure.

`BoundTransferV2SigningSession` now accepts an aggregated result only after the
agreement matches the already approved session and the ordinary RedPallas
signature independently verifies under the proof-bound action key. Four codec
and agreement tests plus one real session-path test pass. The session-path test
uses an ordinary signing key only to create the final standard signature format;
it does not simulate threshold shares and is not FROST evidence.

The current `reddsa` FROST feature was deliberately not enabled. The enforced
audit keeps its resolved `atomic-polyfill` chain inactive due
`RUSTSEC-2023-0089`, and a concrete adapter must also prove that its
re-randomization produces exactly the `alpha` already committed by Vault's
proof. Reimplementing FROST locally or bypassing either condition is forbidden.
The complete profile and remaining evidence are frozen in
[`../specs/MULTISIG_SIGNING_V1.md`](../specs/MULTISIG_SIGNING_V1.md).

## A3-5 delegated proving authorization and disclosure

**Status:** production-intent policy, per-job authorization, trusted disclosure
confirmation, canonical witness/request/response codecs, local proof gate and
revocation contracts complete locally; remote transport, durable platform
store, Halo2 suite adapters and external review remain open.

Local proving is the default. Delegation is an explicit opt-in for one exact
network, circuit, Halo2 suite, action bucket, dedicated prover identity,
canonical effects digest, witness commitment, proof length, fresh channel,
job ID and rollback-protected counter. The crate ships no permissive trusted
confirmation or proof verifier and activates no remote endpoint.

The selected monolithic circuit makes confidentiality delegation expensive:
the prover necessarily learns the complete transfer witness, including note
paths, recipients, values, randomness, private accounting and burn material,
plus `ak`, `nk` and `rivk`. Those last values are the raw Orchard full-viewing
key: they derive incoming/outgoing viewing keys, addresses and nullifiers for
both scopes and may expose/link past and future account activity. The prover
does not receive the seed, spending key or spend signature, so proof generation
does not authorize a transfer.
Encryption authenticates and protects the channel but cannot hide the witness
from the endpoint or make later revocation erase what it learned.

The fixed 148-byte `VDPP` policy and 184-byte `VDPA` authorization require
independent confirmation of that exact irreversible disclosure. A lifecycle
adapter must reserve before sending, durably record disclosure before the first
witness byte leaves, allow only one active job per policy, verify every returned
proof locally against the exact typed effects, close durably before returning a
verified proof and use a fresh job/counter/channel on every retry. Timeout,
equivocation, verification failure or storage uncertainty aborts and poisons
the unsafe handle. Permanent revocation closes the channel and blocks future
jobs but is explicitly not remote erasure.

Seven adversarial tests cover canonical policy, authorization, request and
response bindings,
explicit disclosure confirmation, exact local proof acceptance, and
generation/active-job-bound permanent revocation. The complete contract and
remaining activation evidence are frozen in
[`../specs/DELEGATED_PROVING_V1.md`](../specs/DELEGATED_PROVING_V1.md).

**A3-6 disclosure correction:** inventorying the actual canonical witness
showed that the earlier “scope incoming-viewing” wording understated the
capability. Orchard's serialized `ak || nk || rivk` is a full-viewing key and
derives OVKs as well as IVKs. The v1 profile and confirmation contract were
corrected before the A3-6 codec was implemented. This repairs the existing A3-5
privacy invariant; it does not add a proof, consensus, H2 or mainnet task.

## A3-6 deterministic corpus and bounded harnesses

**Status:** finite local implementation complete; sustained external execution
and independent review remain open.

VDPW v1 now serializes and strictly decodes the complete witness for every
2/4/8/16-Action shape. It checks a 60,286-byte absolute bound before
allocation, reconstructs VAOP outputs, `alpha`, net-value commitments,
accounting, burn commitment/ciphertext and epoch descriptor, then requires the
same public instances as independently decoded VLT2 effects. The committed
corpus witnesses use 5,680/11,004/21,652/42,948 bytes; the larger absolute bound
covers the 512-participant descriptor.

VDPR binds exact VDPP, VDPA, effects and VDPW bytes in a self-contained
zeroizing request. VDPS binds authorization, policy, job, effects and proof
length and can release a result only through the existing local verifier. The
committed VDPS examples reuse real H1-C3 proof bytes under different effects
and are explicitly classified as codec-positive/local-verifier-negative; no
new proving run or fake positive proof was introduced.

[`../specs/SIGNER_CORPUS_V1.md`](../specs/SIGNER_CORPUS_V1.md) freezes 176
artifacts across every bucket: VLT2, VAOP external/change/dummy, VSCH/VSRQ/VSRP
with real deterministic RedPallas signatures, VMSP/VMSC/VMSA without FROST
shares, VDPW/VDPP/VDPA/VDPR/VDPS, deterministic Noise KK flights and encrypted
challenge/request/response ciphertexts, plus malformed magic/tag negatives.
`scripts/reproduce-h1-a3-corpus.sh` regenerated all files byte-for-byte.

The pinned AddressSanitizer/libFuzzer target covers raw and structured VAOP,
VSCH, VSRQ, VMSP, VDPP, VDPR, VDPW and VLT2 inputs with a 65,536-byte maximum,
4 GiB RSS limit and 10-second per-input timeout. A 15-second local smoke run on
this arm64 macOS host executed 11,164 cases with 223 MB peak RSS and no crash,
timeout or sanitizer finding. The bounded release latency runner measured ten
decode/re-encode iterations per bucket at approximately 3.06/4.71/8.17/17.27
ms per iteration and about 3.4 MB process maximum RSS after compilation. These
small local samples validate the runners, not sustained or target-machine
acceptance.

The local A3 sequence is now exhausted. H1-A3 itself remains incomplete until
the platform, physical-device, reviewed FROST, remote-prover adapter/endpoint,
sustained-fuzz and independent-review evidence below is collected. No A4, H2 or
mainnet work is implied.

## External evidence classification

| Evidence | Where it must run | Current readiness |
|---|---|---|
| Root signer tests, Clippy and rustdoc | owned acceptance host in fresh clean roots | ready through the root gate; same-host limitation applies |
| Replay/registry crash, hard-reset and device-fault campaign | owned Linux acceptance host with the shared machine-specific reset/device plan | pending a consolidated A2/A3 controller |
| Bounded signer parser fuzz and latency/memory campaign | owned Linux acceptance host | corpus and pinned runners ready; sustained target run pending |
| Keychain, secure counter, hardware signer and trusted-display behavior | declared physical macOS/Windows/Linux/hardware devices | interfaces and canonical records frozen; adapters/evidence pending; generic VMs are insufficient |
| Pairing, store, UX, multisignature and delegated-proving review | independent human reviewers | multisig and delegated-proving contracts ready; concrete cryptographic/transport adapters and reviews pending; not a machine workload |

No GPU is required by this item, and none of these tests may use real funds.
