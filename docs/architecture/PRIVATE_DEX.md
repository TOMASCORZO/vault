# Private DEX Direction

An ordinary AMM leaks individual trade sizes whenever a single reserve change
can be isolated. VaultSwap will therefore evaluate per-block batch execution
before adopting a direct Uniswap-style pool.

Penumbra's protocol documents the central constraint: zero-knowledge proofs can
hide user-local state but not global state unknown to the user. Its batch-swap
design aggregates trades, computes a clearing result, and lets each user claim
private outputs consistent with that public aggregate.

- [Penumbra batch swaps](https://protocol.penumbra.zone/main/dex/swap.html)
- [Penumbra swap-claim invariants](https://protocol.penumbra.zone/main/dex/action/swap_claim.html)

## VaultSwap candidate flow

1. A user consumes private input notes and creates an encrypted swap commitment.
2. Validators aggregate encrypted flow for each trading pair.
3. Only batch totals are threshold-decrypted after ordering is final.
4. The batch trades against public or committed liquidity at one clearing price.
5. Each user privately claims outputs by proving its committed contribution and
   the canonical batch result.
6. A swap nullifier prevents a second claim.

## Required properties

- Individual identity and amount are hidden within the batch anonymity set.
- Both trade directions use indistinguishable envelope shapes.
- No participant can choose a better clearing price after seeing ordered flow.
- Failed/partial liquidity has deterministic refund outputs.
- Fee funding permits automatic claims without linking another wallet input.
- Liquidity-provider risk, fees, and impermanent loss are explicit.
- A batch with too few participants is delayed, padded, or clearly warns that
  amount correlation is strong.
- VLT is burned exactly once on the VLT leg according to the base-layer rule.

## Unresolved decisions

- public concentrated-liquidity positions versus committed reserves;
- threshold-encryption DKG and validator rotation;
- maximum batch delay and minimum anonymity threshold;
- price limits and manipulation-resistant reference prices;
- treatment of LP deposits and withdrawals under the 0.5% burn;
- interaction between private routing and global solvency proofs.

