# Vault Orchard fork provenance

**Upstream:** <https://github.com/zcash/orchard>  
**Upstream release:** `0.15.5`  
**Upstream commit:** `29d1d55db62153dcaeef8ef631c8991c53ed1248`  
**License:** MIT OR Apache-2.0, unchanged from upstream  
**Vault maturity:** production-intent dependency fork; unaudited and not activated

Vault vendors the exact upstream release so its hardened `PostNu6_3` Action
circuit can participate in a larger circuit without duplicating private note
values. The fork MUST remain source-comparable with the commit above.

Vault-specific changes are restricted to the circuit-composition API:

- expose the existing Action circuit configuration through a documented
  constructor;
- allow one configured Action circuit to bind its public inputs at a caller
  supplied instance-row offset;
- return typed handles to the already-constrained old/new values and expanded
  receiver coordinates;
- expose the canonical Halo2 instance representation needed by the parent
  circuit.

The Action equations, constants, fixed bases, transcript, public-input order,
and historical proving/verifying APIs MUST remain unchanged. Every future
upstream update requires a recorded three-way diff, upstream test execution,
Vault conformance vectors, a new dependency review, and regeneration of any
affected verifying-key or suite identifiers. This fork does not by itself make
Vault or Orchard mainnet-eligible.
