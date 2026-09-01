# Vault Production Engineering Standard

## Project directive

Vault is intended to become a permissionless public network that can
compete technically with leading cryptocurrency systems. Starting on
2026-08-21, new deliverables must be designed and implemented for the deployable
architecture. A disposable MVP, demo-only implementation, or simplified
security model is not an accepted milestone outcome.

This directive does not imply that Vault is currently safe or deployable.
Production readiness is an evidence-based status earned separately by each
component and by the integrated network.

## Non-negotiable rules

1. **No temporary consensus or security paths.** Mock proof acceptance,
   bypassable authorization, trusted bridges disguised as decentralized
   infrastructure, demo keys, silent fail-open behavior, and unbounded resource
   use must never be activatable in a release build.
2. **Specify before activation.** Every consensus-affecting feature requires a
   normative specification, canonical encoding, domain separation, state
   transition rules, error behavior, resource limits, test vectors, versioning,
   and an activation and migration plan.
3. **Model the real threat.** Cryptography, privacy, networking, consensus,
   wallets, smart contracts, storage, markets, governance, supply, and
   cross-chain mechanisms require explicit assets, adversaries, trust
   assumptions, metadata leakage, failure modes, and recovery constraints.
4. **Use reviewed constructions.** Vault must not invent cryptography when a
   maintained, publicly analyzed construction exists. Dependency provenance,
   maintenance, licenses, security advisories, and reproducible pinning are
   release concerns, not cleanup work.
5. **Prove behavior under attack.** Relevant changes require positive, negative,
   property, fuzz, conformance, integration, load, and adversarial tests. Critical
   parsers and consensus transitions require deterministic cross-version vectors.
6. **Measure the complete system.** Throughput, finality, proof generation and
   verification, hardware requirements, state growth, bandwidth, storage,
   anonymity-set behavior, and user-visible fees must be benchmarked on declared
   hardware and realistic workloads. Unmeasured performance is not a claim.
7. **Plan operations and evolution.** Release work includes key management,
   observability without privacy leakage, backups, disaster recovery, incident
   response, compatible upgrades, rollback boundaries, and data migrations.
8. **Require reproducible project evidence.** Mainnet eligibility is decided
   from Vault's specifications, deterministic vectors, adversarial and fuzz
   tests, realistic benchmarks, reproducible builds, public security reports,
   and resolution of every known critical and high-severity finding. External
   audits may supplement this evidence but are not a mandatory release gate.

## Delivery classification

Every component must have one explicit maturity label:

- **Specified:** normative behavior and security requirements are reviewable;
  no implementation claim is made.
- **Production-intent:** implementation targets the deployable architecture but
  has not passed every release gate.
- **Release candidate:** scope is frozen and all internal gates, test vectors,
  benchmarks, and dependency checks pass.
- **Mainnet-eligible:** all project-controlled security and operational gates
  pass, known critical and high findings are resolved, reproducible artifacts
  exist, residual risks are public, and governance has approved activation.

The word "implemented" must always be accompanied by the relevant maturity
label when a reader could otherwise infer production safety.

## Exploratory work

Vault may need comparative cryptographic or systems research before choosing a
deployable construction. Such work is not a Vault feature and must:

- be isolated from every activatable release path;
- state exactly which production invariants it does and does not satisfy;
- have a time-bounded decision question and measurable acceptance criteria;
- end with a documented selection, rejection, or redesign decision;
- never be used with real assets or represented as deployed functionality.

Once a design is selected, implementation proceeds against the production
specification. Experimental code is removed, archived, or retained only as an
explicitly non-activatable test oracle.

## Mainnet release gates

Vault cannot be described as production-ready until, at minimum:

- the monetary policy and genesis allocation are frozen and mechanically
  enforced by consensus;
- end-to-end private transfers prove ownership, membership, nullifier
  correctness, conservation, fees, burn, output integrity, and encryption
  consistency without known metadata claims being overstated;
- independent nodes reach safe, live consensus under Byzantine and network
  fault testing;
- the VM is deterministic, metered, sandboxed, versioned, and supported by
  contract audit and fuzzing tools;
- wallet recovery, viewing permissions, hardware signing, and safe transaction
  construction pass their documented adversarial and fault-injection suites;
- DEX and cross-chain routes have explicit trust models and cannot create
  unbacked VLT or silently place custody in one operator;
- durable storage has measured replication, repair, funding, retrieval, and
  data-loss behavior; "forever" is not claimed without a sustainable mechanism;
- an adversarial public testnet, bug bounty, incident exercises, reproducible
  builds, release signing, and multiple independent operators have succeeded;
- applicable legal and regulatory analysis has been completed without weakening
  the protocol's published technical guarantees.

## Quality and complexity

Vault will not simplify away privacy, decentralization, correctness, durability,
or economic requirements to ship earlier. It will also not add complexity merely
to appear sophisticated. The standard is complete guarantees, explicit tradeoffs,
small auditable components, and evidence comparable to leading networks.

## Current repository status

The existing H0 reference ledger, H1 envelope, and isolated RISC Zero accounting
backend predate this directive and are not mainnet-eligible. They may inform and
test the production design, but their presence does not satisfy the release
gates above. The repository must continue to disclose this status until the
corresponding production-intent components replace or harden them.
