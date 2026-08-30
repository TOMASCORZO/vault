# H1 finite closure matrix

**Status:** scope classification; no activation or production-readiness claim
**Maturity:** production-intent
**Last reconciled:** 2026-08-29

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
| C1 | Extend the isolated RISC Zero reference statement to transfer-v2 membership, ownership/spend authorization, nullifier derivation, note openings, output encryption consistency, gas, conservation, and exact burn. Remove prover-selected change classification. | Native negative tests for every invariant; a real receipt; journal/effects equality; differential vectors against the transparent oracle and Halo2 statement. | In progress: the complete typed statement and native negative matrix are implemented; positive and burn-evasion differential vectors pass against Halo2. Linux guest regeneration, host gates, reviewed image ID, and a real transfer-v2 receipt remain open. |
| C2 | Freeze the monolithic Halo2 transfer statement for every padded 2/4/8/16-action bucket, including exact effects and ciphertext bindings already implemented. | Reproducible proving/verifying keys or deterministic derivation, fixed suite ID, positive proof per bucket, and negative mutations for every public field and private classification boundary. | Open |
| C3 | Define proof-system setup and parameter assumptions. | Versioned specification naming transparent versus structured setup, parameter provenance, integrity identifiers, generation/reproduction procedure, toxic-waste assumptions, rotation, and activation/deactivation rules. | Specified in `architecture/PROOF_SETUP.md`; implementation evidence remains under C2/C4/A4. |
| C4 | Publish real-proof positive and negative vectors for both backends. | Versioned manifest with hashes, exact toolchains, public inputs, expected acceptance/rejection, proof-size bounds, and an offline verifier. Large proof artifacts may be release artifacts when repository size policy forbids committing them. | Open |
| C5 | Decide epoch burn aggregation and low-volume privacy behavior without weakening conservation. | Normative design covering DKG trust, threshold shares, malicious/missing shares, validator rotation, minimum aggregate policy, low-volume carry/merge behavior, bounded recovery, supply-statistic update, and fail-closed activation. | Open |
| C6 | Benchmark at least two maintained proof implementations on declared hardware. | Repeated measurements of key preparation/load, proving, verification, peak memory, proof size, concurrency, and all action buckets; dependency and maintenance review; documented selection or rejection. | Open |
| C7 | Obtain independent cryptographic design review of the frozen statement, burn aggregation, setup assumptions, and vectors. | Versioned review report and disposition of every critical/high finding. This is externally blocked until C1-C6 are reviewable. | Blocked on C1-C6 |

The current Halo2 implementation is substantial evidence toward C2, but C2 is
not closed by a single two-action development proof. The current RISC Zero
accounting receipt is research evidence toward C1 and C6; its documented
omissions mean it is not a complete transfer reference statement.

## H1 activation hardening

These items can block activation without reopening cryptographic scope:

| ID | Bounded workstream | Exit boundary |
|---|---|---|
| A1 | Wallet custody and recovery operations | Approved seed import/custody, authenticated checkpoint distribution, incomplete-recovery UX, rotation/restore drills, migrations, pruning/compaction, long-history growth, fault injection, and measured recovery behavior. |
| A2 | Wallet privacy and platform storage | Private and padded retrieval, keychain/secure-element keys and rollback state, multi-platform stores, private retrieval and side-channel benchmarks. |
| A3 | Signer lifecycle and hardware profiles | Independent pairing/store review, trusted confirmation/revocation UX, active-session shutdown, secure rollback counters, platform stores, hardware, multisignature, and delegated-proving profiles. |
| A4 | Release engineering | Reproducible builds and artifacts, dependency/advisory gates, persistent parameter/key loading, operational limits, activation/deactivation and migration procedures. |
| A5 | Verifier activation decision | All C1-C7 and applicable A1-A4 evidence passes; an explicit suite and circuit ID are approved. No verifier is activatable before this decision. |

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
review, hardware availability, or H2 consensus dependencies must be reported as
such and never replaced with a mock, trusted, or fail-open path.
