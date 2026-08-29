# Vault Protocol — Technical Draft 0.1

**Status:** research draft, 21 August 2026  
**Network:** not launched  
**Ticker:** VLT (provisional)

## 1. Purpose

Vault is intended to be a privacy-first layer-one network for programmable
money, private applications, permissionless markets, cross-chain acquisition,
and durable web software. Privacy is mandatory for value transfers; selective
disclosure is performed by the user through view capabilities rather than a
global transparent mode.

The protocol does not promise absolute anonymity, guaranteed asset value, free
computation, or literal eternal storage. It aims to minimize observable
financial metadata while remaining independently verifiable.

## 2. Design principles

1. **Private by default:** senders, recipients, amounts, and private contract
   state are represented by commitments, ciphertext, nullifiers, and proofs.
2. **Publicly auditable rules:** program code, verification keys, protocol
   upgrades, and supply rules remain inspectable.
3. **No administrator mint key:** issuance cannot exceed the genesis cap.
4. **Modular resources:** execution, durable storage, and cross-chain liquidity
   have separate pricing and security boundaries.
5. **Local ownership:** users hold keys and can run an open-source wallet and
   gateway without a privileged company server.
6. **Measured claims:** throughput, finality, and cost become commitments only
   after reproducible benchmarks.

## 3. Proposed architecture

### 3.1 Vault Core

Vault Core orders transactions and finalizes state commitments through a
proof-of-stake BFT consensus. The initial target is 1–2 second blocks with
deterministic finality, subject to wide-area and adversarial benchmarks.
Validators are pseudonymous but their consensus keys and accountable stake are
public. User transaction identities are not.

### 3.2 VaultVM

VaultVM executes publicly auditable programs over private inputs and state. A
user or delegated prover executes a program and produces a zero-knowledge proof.
Validators verify the proof, nullifiers, state anchor, and resource limits
without learning the witness.

The first contract toolchain should use a constrained Rust-like language with
explicit `public` and `private` types. Solidity source compatibility may be
added through a compiler, but EVM bytecode compatibility is not an H1 goal.

Contracts can implement tokens, escrow, marketplaces, auctions, DAOs, lending,
subscriptions, games, and exchange logic. Programs cannot directly read the
internet; external facts require explicitly trusted or economically secured
oracles.

### 3.3 VaultStore

Large files do not enter the execution state. VaultStore chunks and
content-addresses web assets, applies erasure coding, and pays storage providers
against periodic proofs. An up-front endowment funds long-lived storage. Vault
Core stores manifests, content roots, payment commitments, and storage proofs.

Static HTML, JavaScript, WebAssembly, media, and software packages live in
VaultStore. Mutable application state lives in VaultVM. A wallet or gateway
resolves names such as `vault://application` without making a DNS name part of
the protocol's security model.

### 3.4 VaultSwap

VaultSwap is an internal private exchange. Its first market mechanism will be
selected after simulations comparing a shielded constant-product AMM with a
frequent batch auction. Batching is favored because a public reserve update can
otherwise reveal an isolated private trade and because batch clearing can
reduce front-running.

Liquidity providers must be compensated separately from execution gas. Pool
fees, price impact, and the VLT burn must always be displayed as separate costs.

### 3.5 Vault Instant

Vault Instant gives a one-step “pay external asset, receive shielded VLT” user
experience. It is a liquidity network, not an omnipotent deposit account.

1. A wallet requests signed quotes from independent solvers.
2. The user selects an asset, chain, amount, and quote.
3. Source funds and solver VLT are locked with refund conditions.
4. Successful settlement releases shielded VLT to the user.
5. Failure or expiry returns each side's funds.

Native BTC-to-VLT should use a non-custodial atomic-swap protocol. Smart-contract
chains can use audited escrow adapters and proof-of-finality clients. Wrapped
assets are optional for repeated trading but are not the default purchase path.
Every supported chain requires an adapter, finality policy, liquidity, test
vectors, monitoring, and an independent security review.

## 4. VLT economics

The final numeric supply cap and emission distribution remain governance-free
genesis parameters to be fixed before public testnet. The consensus rules are:

- `issued_supply <= maximum_supply` at all times;
- no post-genesis authority may change `maximum_supply`;
- a recipient receives the exact requested VLT amount;
- the sender additionally pays a 0.5% burn and execution gas;
- gas is transferred to validators and is not burned by the 0.5% rule;
- burned VLT can never be reissued.

For transfer amount `A` in atomic units:

```text
B = ceil(A / 200)
sender debit = A + B + gas
recipient credit = A
supply reduction = B
```

Rounding upward prevents dust splitting from bypassing the burn. Protocol rules
must define how contract-internal ownership changes are taxed; otherwise a
wrapper or claim token could economically transfer VLT without moving its base
note. No protocol can prevent all off-chain transfers of beneficial ownership.

Publishing each burn would reveal its associated private amount. The intended
private design therefore proves each burn inside the transfer circuit and
publishes only delayed, thresholded epoch aggregates with a supply-consistency
proof. The selected production-intent construction is threshold exponential
ElGamal over Pallas with a canonical epoch DKG descriptor; the per-transfer
circuit equations, descriptor binding, privacy-gated aggregate formation,
malicious-share filtering, and bounded recovery are implemented. DKG consensus,
finalized scheduling/publication, full-bound performance acceptance, public
supply integration, and independent review remain blockers.

The H0 implementation in `vault-core` is a transparent accounting oracle. It
checks the formula, note conservation, gas distribution, and double-spend
rejection before these invariants are encoded cryptographically.

## 5. Cost model

Vault separates four costs:

1. execution gas paid to validators;
2. the mandatory VLT burn;
3. liquidity-provider spread or pool fee;
4. source-chain miner or validator fees.

Vault can reduce its own verification cost with client-side proving, recursive
proof aggregation, parallel independent state, bounded program resources, and
separate storage. It cannot make Bitcoin or another source chain cheaper. A
paymaster may cover a new user's first Vault transaction and recover that cost
inside the cross-chain quote.

## 6. Commerce

Vault Market contracts provide listings, private orders, escrow, timeouts,
seller bonds, and optional arbitration. Digital goods can be delivered through
encrypted content capabilities. A physical seller necessarily learns delivery
information disclosed to it; the blockchain cannot make that counterparty
forget real-world data. Anonymous reputation also requires Sybil resistance,
such as bonds or privacy-preserving credentials.

## 7. Upgrade and governance constraints

Consensus and verification-key upgrades require delayed, publicly visible
activation and broad validator approval. Supply cap and ownership of burned
funds are not upgradeable. Application contracts explicitly declare whether
they are immutable or controlled by a delayed upgrade policy.

Emergency controls, if any, may stop a specific bridge adapter but cannot seize
shielded user notes or mint VLT. Bridge isolation prevents one compromised
external adapter from corrupting Vault Core.

## 8. Open protocol decisions

- proof system and recursion strategy after benchmarks;
- data-availability format for encrypted state;
- decentralized proving incentives;
- validator selection and stake distribution;
- numeric cap and emission schedule;
- epoch-burn aggregation without low-volume leakage;
- AMM versus batch-auction market design;
- Bitcoin atomic-swap construction and refund UX;
- durable-storage endowment assumptions;
- legal and content-serving policies by jurisdiction.
