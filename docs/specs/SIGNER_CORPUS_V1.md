# Signer, ciphertext and delegated-proving corpus v1

**Status:** frozen H1-A3-6 engineering corpus; synthetic, unaudited, not an
activation artifact

## 1. Scope and safety boundary

The committed corpus is
[`test-vectors/h1-a3-v1`](test-vectors/h1-a3-v1). It covers every padded
2/4/8/16-Action bucket and the already selected H1 formats. All seeds, keys,
notes, paths, nonces and job identifiers are deterministic public test data.
They MUST NOT be reused for real funds, production identities, a DKG, FROST or
a delegated-prover endpoint.

This corpus freezes codecs and parser/resource boundaries. It does not activate
the signer, FROST, a remote prover, a network service, H2 or mainnet.

## 2. Inventory

Each bucket contains:

- canonical VLT2 public effects and one VDPW witness that reconstructs the
  exact selected monolithic transfer circuit;
- VAOP packets for every sorted Action, collectively covering external
  payment, internal change and true zero dummy outputs;
- VSCH, VSRQ and VSRP payloads with real deterministic RedPallas signatures;
- VMSP, VMSC and VMSA policy/round-one/agreement records. These are agreement
  vectors only: there are no synthetic FROST shares or claimed threshold
  signatures;
- VDPP, VDPA and VDPR records bound to the exact VDPW and effects;
- one VDPS codec vector whose proof bytes are copied from the already committed
  H1-C3 vector for a different effects statement; and
- deterministic Noise KK handshake flights plus encrypted VST1
  challenge/request/response records.

Every supported raw codec also has a malformed-magic negative. The Noise
request ciphertext has an authenticated-tag mutation. `MANIFEST.tsv` records
the relative path, format, expected result, exact length and BLAKE3 digest for
all 176 artifacts.

The VDPS entry is deliberately named `delegated-response-context-negative` and
has expectation `codec-accept-local-proof-reject-different-effects`. Its
envelope must decode in its declared job context, but mandatory local Halo2
verification must reject it. Positive real-proof verification remains the
separate frozen H1-C3 corpus in `zk/halo2/core/vectors/transfer-v2`. No new
proving run is hidden in A3-6.

## 3. Canonical delegated witness

VDPW v1 is a non-extensible zeroizing encoding:

| Field | Bytes |
|---|---:|
| magic `VDPW`, version, disclosure profile, Action count | 8 |
| network ID, circuit ID, public-effects digest | 96 |
| maximum private value | 8 |
| raw Orchard full-viewing key (`ak || nk || rivk`) | 96 |
| each private note, 32-level membership path, `alpha`, `rcv`, VAOP | 2,662 per Action |
| epoch, threshold, participant IDs and coefficient commitments | variable, bounded |
| burn commitment trapdoor and encryption randomness | 64 |

The 2/4/8/16 corpus witnesses are respectively 5,680, 11,004, 21,652 and
42,948 bytes. The absolute parser bound is 60,286 bytes, attained only by the
16-Action shape with the maximum 512-participant epoch descriptor. The decoder
checks this bound before allocation, rejects trailing/non-canonical data, and
reconstructs every note output, authorization randomizer, value commitment,
accounting classification, burn commitment and burn ciphertext against
independently decoded effects.

VDPW discloses the complete transfer witness and the durable account
full-viewing capability. It discloses no seed, spending key or spend signature.
This privacy cost is unavoidable for the selected monolithic circuit and is
not reduced by encrypting transport to the prover.

## 4. Request, response and transport rules

VDPR v1 is self-contained and binds canonical VDPP, VDPA, VLT2 effects and
VDPW bytes. Its decoder applies fixed maximums before copying the private
witness, revalidates all nested codecs and commitments, and requires byte-exact
canonical re-encoding.

VDPS v1 binds Action bucket, disclosure profile, authorization ID, policy ID,
job ID, effects digest and exact proof length. Parsing a VDPS is not proof
acceptance. Only the selected local verifier trait can produce a
`VerifiedDelegatedTransferProof`.

Noise vectors use fixed ephemeral secrets only through the non-default
`vault-signer/test-vector-generation` feature. The normal crate exposes no
deterministic handshake constructor. Production builds MUST keep that feature
disabled; production static and ephemeral keys MUST come from their approved
protected/CSPRNG paths.

## 5. Reproduction and bounded harnesses

`scripts/reproduce-h1-a3-corpus.sh` regenerates the complete directory in a
fresh temporary location and requires recursive byte equality. The generator
does no Halo2 proving.

`scripts/fuzz-signer-codecs.sh` pins `nightly-2026-08-20` and
`cargo-fuzz 0.13.2`, limits inputs to 65,536 bytes, RSS to 4 GiB, per-input time
to 10 seconds and total runtime to the caller's bounded value. Every run uses
a fresh temporary corpus, removes it on exit and leaves only crash artifacts
in the ignored artifact directory. Raw input plus structured mutations cover
VAOP, VSCH, VSRQ, VMSP, VDPP, VDPR, VDPW and VLT2.

`scripts/benchmark-signer-codecs.sh` accepts 1..10,000 iterations and measures
release VDPW, VDPR and VSRQ decode/re-encode latency for every bucket while the
platform time utility reports peak memory. These harnesses are local readiness
evidence; sustained sanitizer and target-platform measurements remain part of
the consolidated external campaign.

## 6. Acceptance and remaining gates

A3-6 local acceptance requires:

1. byte-exact corpus reproduction;
2. committed positive/context-negative decoding tests for all buckets;
3. exact VDPW reconstruction of the selected circuit public inputs;
4. bounded malformed-input and mutation tests without panic;
5. successful compilation of the pinned fuzz target; and
6. a clean bounded local sanitizer smoke run.

It does not satisfy independent review, sustained fuzzing, concrete protected
platform adapters, physical trusted displays, a reviewed FROST dependency,
delegated-prover transport/store/suite adapters, endpoint privacy review or
real device/fault evidence. Those remain activation gates and are grouped in
`docs/research/H1-EXTERNAL-ACCEPTANCE-CAMPAIGN.md`.
