# A1-CP2 checkpoint bootstrap ceremony

**Maturity:** production-intent operational plan; ceremony tooling and the final
ceremony have not yet been completed

## Objective and boundary

This procedure establishes the generation-1 trust policy used to authenticate
Vault wallet-recovery checkpoint distribution. It does not authorize transfers,
hold wallet seeds, create VLT, replace consensus finality, or make Vault safe for
real funds.

The protocol boundary already implements canonical `VBOOT001` bootstrap bytes,
proof-of-possession signatures from every configured publisher, a separately
pinned policy ID, and policy-store enforcement. `A1-CP2` closes only after the
project has reproducible ceremony tooling, three genuinely independent
custodians, a frozen target-network chain ID, an executed ceremony, external pin
confirmation, durable public-artifact recovery, and complete evidence.

## Approved three-device profile

The initial profile is three independent publisher keys with a two-signature
operational threshold (`2-of-3`). All three keys must sign the generation-1
bootstrap as proof of possession. The later two-signature threshold applies to
checkpoint packages, not to initial bootstrap participation.

| Device | Custodian | Permanent secret | Ceremony responsibility |
| --- | --- | --- | --- |
| Signer A | Operator A | Publisher key A | Verify all fields and sign the exact draft |
| Signer B | Operator B | Publisher key B | Independently verify all fields and sign |
| Signer C | Operator C | Publisher key C | Independently verify all fields and sign |

Each operator must control a distinct physical device and its authentication.
Three keys or virtual machines controlled by one person, account, administrator,
or cloud provider are not independent custodians. A phone may replace Signer C
only after a dedicated Vault mobile signer implements and passes the same
non-export, offline, codec, backup, and recovery gates. The current approved
profile therefore assumes three laptops or equivalent reviewed signing devices.

No signer needs a GPU, high performance, continuous network access, or 24-hour
operation. Signers remain powered off and offline except during an approved
ceremony or later signing operation. Public coordination and GitHub publication
may use any ordinary online workstation because that machine must never receive
a private key. It is not counted as a signing device.

## Device requirements

Before generating a key, each operator must record and independently verify:

- physical custody and a unique operator authentication secret;
- a clean, supported, fully patched OS or reviewed read-only ceremony image;
- full-disk encryption and disabled unattended remote access;
- network radios and cables disabled for key generation and signing;
- verified SHA-256 of the exact reproducible Vault ceremony executable;
- OS cryptographic random-source availability;
- correct local time for the transcript only; time is not a signed trust input;
- two encrypted backup media, labeled without exposing the key or operator
  identity and stored in separate physical locations;
- a clean public-only transfer method. QR transfer is preferred for the small
  draft, public-key, and signature records. Removable media requires explicit
  malware controls and must never carry plaintext private-key material.

Private keys, backup passwords, recovery material, screen photographs, command
arguments, logs, crash dumps, clipboard contents, and GitHub artifacts must not
cross from a signer. Only a public key, publisher ID, signature, and redacted
operator attestation leave it.

## Prerequisites that block the final ceremony

The definitive ceremony must not begin until all of these values are frozen:

1. exact target environment (`testnet` or a later production network);
2. nonzero 32-byte `chain_id` tied to that network's reviewed configuration;
3. `2-of-3` threshold approval and three selected independent custodians;
4. ceremony tool source commit, reproducible binary hash, Rust toolchain, and
   supported signer platforms;
5. external pin destination: release manifest, shipped binary configuration, or
   both;
6. artifact retention locations and named recovery reviewers.

Vault does not yet have a frozen production `chain_id`. Disposable rehearsal
keys may be used before that decision, but a rehearsal cannot close `A1-CP2` and
its keys must never be promoted or reused for production.

## Engineering phase

Implement a small non-networked ceremony CLI with separate commands equivalent
to:

```text
keygen       generate one encrypted publisher key and public record
draft        build canonical unsigned VBOOT001 bytes from three public records
inspect      decode and display every field plus independent digests
sign         sign only after interactive field confirmation
assemble     canonically combine the three proof-of-possession signatures
verify       verify exact encoding, all signatures, chain ID, and policy-ID pin
manifest     emit the public reproducibility and artifact manifest
```

The CLI must use bounded exact codecs, never accept secrets on a command line,
zeroize plaintext key material, create files without overwrite, reject unsafe
permissions and paths, and keep signing code isolated from network and GitHub
logic. It must display human-comparable grouped encodings for `chain_id`, each
publisher ID, ceremony nonce, signing-bytes digest, policy ID, and final artifact
hash.

Required tests include deterministic public vectors plus rejection of every
single-byte mutation, truncation, extension, wrong network, zero/reused nonce,
duplicate or reordered publisher record, missing/duplicate/unknown signature,
wrong signer, altered threshold, policy-ID mismatch, unsafe secret path,
overwrite attempt, and secret-bearing diagnostic output.

## Rehearsal with disposable keys

Run one complete rehearsal before the definitive ceremony:

1. Provision Signers A, B, and C from the reviewed image and independently
   verify the ceremony binary hash.
2. Generate three disposable keys offline and export only public records.
3. Have each device contribute 32 random bytes. The coordinator combines all
   three contributions under a documented domain-separated hash to produce the
   32-byte ceremony nonce; no one device chooses it alone.
4. Build the draft for a clearly labeled non-production chain ID and threshold
   two. Record the exact source commit and signing-bytes digest.
5. On every signer, independently inspect and confirm the chain ID, generation
   1, threshold `2-of-3`, all three publisher IDs, nonce, and policy ID.
6. Sign the unchanged draft on all three devices. Export signatures only.
7. Assemble and verify the canonical bootstrap on an untrusted coordinator.
8. Mutate the artifact and each displayed field in turn and confirm fail-closed
   rejection.
9. Destroy rehearsal keys and their backups. Preserve only public evidence
   explicitly labeled `NON-PRODUCTION`.

Any field disagreement, hash mismatch, unexpected file, logging of secret data,
or signer that cannot independently inspect the draft aborts the rehearsal.

## Definitive ceremony

After prerequisites and rehearsal pass:

1. Reinstall or reimage all three signers; do not promote rehearsal keys.
2. Each operator independently generates one final private key and immediately
   creates two encrypted, verified backups. The original remains on its signer.
3. Exchange and compare the three public records through at least two channels.
4. Generate the nonce from fresh contributions by all three devices.
5. Build one draft bound to the exact frozen chain ID, generation 1, threshold
   two, and the complete publisher set.
6. Every operator independently inspects all fields and records the same grouped
   signing-bytes digest and policy ID before signing.
7. Obtain all three proof-of-possession signatures. An absent operator aborts
   bootstrap creation; the operational threshold does not waive this rule.
8. Assemble once and verify on all three signers plus a clean public verifier.
9. Produce `checkpoint-policy-bootstrap-v1.bin` and a canonical manifest that
   records its byte length, SHA-256, BLAKE3, chain ID, policy ID, threshold,
   ordered publisher IDs, ceremony nonce, source commit, binary hashes,
   toolchains, and redacted operator confirmations.
10. Each operator compares the policy ID over an independent channel. At least
    two confirmations must be captured outside the coordinator's filesystem.
11. Publish only the bootstrap, manifest, public confirmations, and verifier.
    Pin the exact policy ID through the approved release/binary channel.
12. Power down and physically store all signers and backup media. No private key
    is uploaded, copied to the coordinator, or retained in temporary transfer
    storage.

GitHub availability alone is not the trust root. A compromised release account
must not be able to replace both the bootstrap and the separately distributed
policy-ID pin.

## Lost-bootstrap recovery drill

The public bootstrap is essential but not secret. Complete this drill without
using any private publisher key:

1. Remove the coordinator's working copy without deleting the authoritative
   release or offline public copies.
2. Recover the artifact independently from the release and from separate public
   archival media.
3. Compare byte length, SHA-256, BLAKE3, chain ID, and policy ID against the
   external confirmations.
4. Verify all three proof-of-possession signatures with the clean verifier.
5. Initialize a fresh checkpoint policy store through an approved CP1 rollback
   guard and confirm the exact generation-1 anchor.
6. Demonstrate rejection of a modified artifact, a different release asset,
   the wrong network, and an incorrect external policy-ID pin.
7. Record recovery time, operator actions, and every source used.

Loss of a publisher private key and policy rotation are separate `A1-CP4`
exercises. This drill proves recovery of the public root artifact only.

## Closure evidence

`A1-CP2` may be checked complete only when the repository contains:

- reviewed ceremony CLI source and deterministic public vectors;
- a reproducible build manifest for every signer platform used;
- the signed three-device selection and `2-of-3` threat decision;
- rehearsal evidence and confirmation that rehearsal keys were destroyed;
- the final `VBOOT001` artifact, manifest, external policy-ID pin, and three
  proof-of-possession signatures;
- three independent operator confirmations without private identity leakage;
- successful clean-verifier and lost-bootstrap recovery evidence;
- passing formatting, workspace tests, strict Clippy, rustdoc, and advisory
  checks;
- explicit residual risks and an assertion that CP2 does not replace consensus,
  complete A1, or authorize real funds.

Until those artifacts exist, the canonical format is implemented but the
operational ceremony remains open.
