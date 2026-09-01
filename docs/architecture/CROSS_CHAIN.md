# Cross-Chain Acquisition and Asset Risk

Vault Instant is designed to let a user pay BTC or another admitted asset and
receive shielded VLT without requiring a centralized exchange account.

## Default route: liquidity network

```text
quote request → signed solver quote → both assets locked → atomic release
                                      └───────────────→ timed refunds on failure
```

The user does not “deposit BTC into Vault Core.” Native BTC remains on Bitcoin.
A solver receives BTC and delivers its own VLT liquidity. For Bitcoin, the
protocol should use script/adaptor-signature atomic swaps with explicit timeout,
fee-bump, reorganization, and refund behavior.

## Optional route: wrapped assets

Repeated trading may justify a shielded `vBTC` or `vETH`, but every wrapped
asset introduces a separate solvency and verification domain. Bridge compromise
must not mint native VLT or modify Vault Core supply.

Ethereum's bridge documentation distinguishes trusted external verifiers from
locally verified/light-client or liquidity-network designs and documents smart
contract, counterparty, and systemic wrapped-asset risks:
[bridge trade-offs](https://ethereum.org/developers/docs/bridges/).

## Admission gate for a source asset

An asset is not “supported” until all are complete:

- canonical chain and asset identification;
- finality and reorganization policy;
- lock/refund state machine and test vectors;
- independent solver implementations and minimum liquidity;
- quote expiry, slippage, and complete fee disclosure;
- chain-specific monitoring and incident playbook;
- per-route value caps and delayed increases;
- reproducible adversarial suites for every route and failure transition;
- wallet recovery tests for crashes at every protocol step.

## Censorship limits

Atomic swaps reduce custody and listing dependence, but cannot create liquidity,
hide the public Bitcoin leg, guarantee network access, or prevent interface and
app-store blocking. Solver discovery and the reference UI must therefore work
over an open P2P protocol and from a locally served application.
