# Consensus and Deterministic Execution Direction

**Decision status:** CometBFT selected for devnet evaluation, not mainnet lock-in.

Vault should not invent a consensus protocol while simultaneously inventing a
private VM. CometBFT exposes ABCI 2.0 as a language-independent boundary between
BFT state-machine replication and application logic. Its application must be a
deterministic function of committed inputs; external RPC results can never be
read directly during state transition.

Primary references:

- [ABCI 2.0 specification](https://docs.cometbft.com/main/spec/abci/)
- [CometBFT application architecture](https://docs.cometbft.com/v0.38/app-dev/app-architecture)

## Proposed devnet split

```text
CometBFT process
  consensus, peer voting, block proposal, evidence
          │ ABCI 2.0 / protobuf
          ▼
Vault application
  structural validation → proof verification → nullifiers → commitments
          │
          ├── authenticated state database
          ├── snapshot/light-client service
          └── fee, staking, governance, and upgrade modules
```

## Consensus-critical rules

- The exact verifier binary, circuit ID, protocol version, gas schedule, and
  domain constants are activated at a known height.
- Structural and size validation precedes expensive proof verification.
- A failed proof or failed transaction performs no writes.
- Block execution order is deterministic even when proof verification is
  parallelized; conflicting nullifiers resolve by canonical transaction order.
- State roots, nullifiers, commitment positions, fees, and validator changes are
  part of the committed application hash.
- Bridges and oracles submit verifiable messages through consensus; application
  execution never calls a web API.
- Upgrades use delayed activation and retain old verifier data long enough for
  historical verification and light-client safety.

## Open risks

- BFT safety thresholds do not compensate for centralized stake distribution.
- Public mempools leak timing and enable censorship even with private amounts.
- Proof verification may dominate block time under adversarial load.
- Proposer control can still order or exclude transactions.
- Fast blocks must be benchmarked across continents and degraded networks.

H2 must test validator crashes, Byzantine proposals, malformed proofs, database
faults, state-sync corruption, long-range attacks, key compromise, and upgrade
failures before any performance claim is published.

