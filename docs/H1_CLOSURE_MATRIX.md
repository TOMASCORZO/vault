# H1 finite closure matrix

**Status:** scope classification; no activation or production-readiness claim
**Maturity:** production-intent
**Last reconciled:** 2026-09-02

This matrix freezes the remaining H1 work identified by `HANDOFF.md`. A newly
discovered task does not expand H1 automatically. It must be assigned to one of
the four classes below. The frozen H1 cryptographic list changes only when a
missing invariant makes an existing H1 deliverable incorrect, and the reason
must be recorded here before implementation.

## H1 cryptographic implementation

H1 cryptographic implementation closes only when every `C` item below has its
listed evidence. Passing these gates does not activate a verifier.

| ID | Finite deliverable | Closure evidence | Status |
|---|---|---|---|
| C1 | Extend the isolated RISC Zero reference statement to transfer-v2 membership, ownership/spend authorization, nullifier derivation, note openings, output encryption consistency, gas, conservation, and exact burn. Remove prover-selected change classification. | Native negative tests for every invariant; a real receipt; journal/effects equality; differential vectors against the transparent oracle and Halo2 statement. | Complete at the implementation-evidence boundary: the typed statement, native negative matrix, journal/effects equality, differential vectors, Linux guest regeneration, host gates, reviewed image ID, and a real CUDA Composite receipt all passed. The receipt was verified immediately and again after reopening the saved artifact. See `evidence/C1_RISC0_CUDA_2026-08-31.md`. This does not activate the verifier or complete C4. |
| C2 | Freeze the monolithic Halo2 transfer statement for every padded 2/4/8/16-action bucket, including exact effects and ciphertext bindings already implemented. | Reproducible proving/verifying keys or deterministic derivation, fixed suite ID, positive proof per bucket, and negative mutations for every public field and private classification boundary. | Complete: deterministic transparent `k = 15` derivation and suite ID `991523426f81b2350b1b08a7e2de9f60e334f344e40c23904c6dd8db5937c83a` are pinned. Real release proofs verify for 2/4/8/16 actions; every public-instance cell is mutation-tested, and receiver/change, value-linkage, dummy, gas, burn, epoch-key, ciphertext, and complete-effects negative boundaries fail closed. |
| C3 | Define proof-system setup and parameter assumptions. | Versioned specification naming transparent versus structured setup, parameter provenance, integrity identifiers, generation/reproduction procedure, toxic-waste assumptions, rotation, and activation/deactivation rules. | Specified in `architecture/PROOF_SETUP.md`; implementation evidence remains under C2/C4/A4. |
| C4 | Publish real-proof positive and negative vectors for both backends. | Versioned manifest with hashes, exact toolchains, public inputs, expected acceptance/rejection, proof-size bounds, and an offline verifier. Large proof artifacts may be release artifacts when repository size policy forbids committing them. | Complete: Halo2 vectors are committed under `zk/halo2/core/tests/vectors`; the RISC Zero receipt and three provenance files are published in release `c4-risc0-transfer-v2-v1`, with the canonical digest, exact toolchains, hashes, size, metrics, and an offline verifier that accepts the receipt and rejects public-input, proof-byte, and truncation mutations. The 311,977,650-byte reference receipt exceeds the 2,097,152-byte consensus limit, so C4 evidence is complete but this backend remains non-activatable. |
| C5 | Decide epoch burn aggregation and low-volume privacy behavior without weakening conservation. | Normative design covering DKG trust, threshold shares, malicious/missing shares, validator rotation, minimum aggregate policy, low-volume carry/merge behavior, bounded recovery, supply-statistic update, and fail-closed activation. | Complete at the specification boundary: `specs/BURN_AGGREGATION_V1.md` freezes a greater-than-two-thirds threshold, deterministic accumulator, 256-ciphertext/64-block disclosure floor, indefinite low-volume carry under a same-key reshare lineage, verified share handling, bounded recovery/stall behavior, monotonic supply upper-bound update, and fail-closed activation. Network DKG, persistence, recovery implementation, and activation remain H2/A4/A5 work. |
| C6 | Benchmark at least two maintained proof implementations on declared hardware. | Repeated measurements of key preparation or load, proving, verification, peak memory, proof size, concurrency, and all action buckets for the selected candidate; dependency and maintenance review; documented selection or rejection. A rejected candidate need not receive larger-bucket or concurrency runs after a hard protocol or activation blocker is evidenced at the minimum bucket. | Complete: Halo2 is selected after three real measurements for every 2/4/8/16-action bucket and a two-worker 16-action concurrency run on declared M1 hardware. RISC Zero 3.0.6 is rejected for base-layer activation after its H100 Composite measurement, the verified RTX 5090 Succinct classification, and the final dependency scan. The 223,530-byte Succinct receipt fits the envelope, but wrapping does not remove the base-proving cost or resolved advisory blockers. Stable Halo2 key persistence/loading remains A4 release engineering. See `evidence/C6_PROOF_BENCHMARK_2026-08-31.md` and `evidence/C6_RISC0_SUCCINCT_CUDA_2026-09-02.md`. |

The Halo2 C2 closure freezes implementation shape and deterministic key
identity; it did not by itself publish C4 release vectors, satisfy C6
comparative benchmarking, or activate a verifier. The RISC
Zero transfer-v2 statement and real-receipt evidence complete C1. The separately
published positive/negative package completes C4. C6 is complete and selects
Halo2; verifier activation remains open under A5.

## H1 activation hardening

These items can block activation without reopening cryptographic scope:

| ID | Bounded workstream | Exit boundary |
|---|---|---|
| A1 | Wallet custody and recovery operations | Approved seed import/custody, authenticated checkpoint distribution, incomplete-recovery UX, rotation/restore drills, migrations, pruning/compaction, long-history growth, fault injection, and measured recovery behavior. |
| A2 | Wallet privacy and platform storage | Private and padded retrieval, keychain/secure-element keys and rollback state, multi-platform stores, private retrieval and side-channel benchmarks. |
| A3 | Signer lifecycle and hardware profiles | Independent pairing/store review, trusted confirmation/revocation UX, active-session shutdown, secure rollback counters, platform stores, hardware, multisignature, and delegated-proving profiles. |
| A4 | Release engineering | Reproducible builds and artifacts, dependency/advisory gates, persistent parameter/key loading, operational limits, activation/deactivation and migration procedures. |
| A5 | Verifier activation decision | All C1-C6 and applicable A1-A4 reproducible project evidence passes; an explicit suite and circuit ID are approved. No verifier is activatable before this decision. |

## H2 consensus and network integration

The following are not H1 cryptographic closure items:

- the validating full-node or light-client adapter behind the finalized-header
  source boundary;
- consensus finality, validator networking, mempool propagation, snapshots,
  state sync, light-client verification, and private block transport integrated
  with real nodes;
- multi-node adversarial load and Byzantine/finality testing.

H1 may specify and test fail-closed interfaces for those consumers. It must not
ship a trusted RPC shortcut or claim that RPC agreement is finality.

## Later milestones

Contracts, DEX/cross-chain routes, durable application storage, public testnet,
and mainnet operations remain H3-H6 work. They do not enter H1 merely because a
future feature needs private transfers.

## Change control

For each completed item, record the exact specification, code, vector or report,
commands run, declared hardware, and remaining activation blockers. An unchecked
roadmap umbrella may link here instead of being expanded indefinitely. External
review is optional supplementary evidence. Hardware availability or H2 consensus
dependencies must be reported as such and never replaced with a mock, trusted,
or fail-open path.

On 2026-08-31 the project owner removed external cryptographic review as a
mandatory closure item. The former C7 gate was deleted; Vault's reproducible
internal tests and documented security evidence are the acceptance authority.
This policy does not turn passing tests into a claim of absolute security.
