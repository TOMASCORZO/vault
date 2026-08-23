# Orchard composition fork review record — 2026-08-22

**Maturity:** internal production-intent review; not an independent audit  
**Upstream:** <https://github.com/zcash/orchard>  
**Release:** `0.15.5`  
**Commit:** `29d1d55db62153dcaeef8ef631c8991c53ed1248`  
**License:** MIT OR Apache-2.0

## Decision

Vault requires the private note values and expanded receivers already proven by
the hardened `PostNu6_3` Action circuit. Assigning those values again in an
independent accounting proof permits a cross-statement witness-substitution
attack unless a binding commitment is reopened. Publishing receiver tags would
also add transaction metadata. Vault therefore selected a minimal local fork
that returns handles to the original constrained cells for monolithic
composition.

This is a dependency-maintenance decision, not a cryptographic redesign. The
upstream Action equations, constants, fixed bases, public-input ordering,
standalone proving/verifying APIs, and `PostNu6_3` behavior are retained.

## Recorded source delta

Comparison against the locally downloaded crates.io source for `orchard
0.15.5` reports exactly one differing file under `src/`:

```text
src/circuit.rs
```

Reference SHA-256 values at the time of this review:

```text
upstream src/circuit.rs  0b7820a9a4883a4167815ca4e9b309b1eb4ee12a591917f5343ba4e9f4075d3e
Vault src/circuit.rs     5fc076378b2957d75e63b65dc7d722f232191d7a05fd7539709303a75956a6f5
```

The Vault delta:

- exposes the existing circuit configuration for a parent circuit;
- separates one-time Sinsemilla table loading from per-Action synthesis;
- adds a caller-supplied public-instance row offset;
- returns typed handles to `v_old`, `v_new`, and the four affine coordinates of
  each old/new expanded receiver;
- exposes the existing canonical ten-row Action instance representation.

## Security invariants

- Standalone Orchard synthesis still loads the same table and calls the same
  base plus `PostNu6_3` cross-address checks at offset zero.
- Every previous absolute instance row is translated only by a single supplied
  offset; the relative ten-row ordering is unchanged.
- No witness value is made public. Returned handles exist only during circuit
  synthesis.
- The parent equality-constrains Action values to range-checked accounting
  cells; it does not copy host values into an unrelated witness.
- A private zero-tax label conditionally constrains equality of all four
  expanded-receiver coordinates. Taxable same-receiver outputs are permitted;
  exempt unequal-receiver outputs are not.
- No suite ID, verifying-key fingerprint, or consensus adapter is assigned to
  the provisional monolithic shape.

## Evidence completed

- Root non-circuit users compile against the vendored crate.
- The isolated Halo2 workspace compiles the forked circuit API.
- Existing standalone real Action proof remains part of the quality gate.
- Two-Action monolithic `MockProver` success case passes.
- Cross-statement accounting-value substitution fails.
- External-output-as-change classification fails.
- The private dummy marker is derived from the linked Action values and rejects
  an enabled all-zero slot.
- A real 9,504-byte first monolithic proof verifies; mutated transcript and
  public instance are rejected.
- The subsequent 9,600-byte shape also binds the descriptor-derived epoch key
  and complete effects digest; changing its digest instance is rejected.

## Remaining gates

- Produce and archive a machine-readable patch against the upstream commit.
- Run the complete upstream Orchard test suite for the vendored commit and
  document any feature-specific exclusions.
- Add deterministic monolithic vectors for buckets 2, 4, 8, and 16.
- Benchmark peak memory, persistent-key loading, batch verification, and all
  bucket sizes on declared target hardware.
- Review wallet construction and multi-input change semantics.
- Complete independent circuit and cryptography review before activation.
