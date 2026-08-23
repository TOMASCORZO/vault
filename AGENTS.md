# Vault repository instructions

These instructions apply to every change in this repository.

## Session continuity

Before planning or modifying Vault, read [`docs/HANDOFF.md`](docs/HANDOFF.md),
[`docs/ROADMAP.md`](docs/ROADMAP.md), and
[`docs/PRODUCTION_STANDARD.md`](docs/PRODUCTION_STANDARD.md). Treat the repository,
specifications, tests, and current version-control state as the source of truth;
chat history is supplementary and may be unavailable after an account or session
change.

Do not expand an H1 umbrella item after reporting it complete. First classify any
newly discovered work as one of: H1 cryptographic implementation, H1 activation
hardening, H2 consensus/network integration, or a later milestone. Update the
frozen closure list before implementation if and only if a missing invariant makes
an existing H1 deliverable incorrect; record the reason explicitly.

## Production intent is mandatory

Vault is being engineered for an eventual audited public mainnet, not as a
demo, tutorial, hackathon project, or disposable MVP. All new implementation
work must follow [`docs/PRODUCTION_STANDARD.md`](docs/PRODUCTION_STANDARD.md).

- Design every consensus, cryptographic, networking, wallet, VM, storage, DEX,
  and cross-chain component for the version intended to be deployed.
- Do not merge placeholder security, mock verification, trusted shortcuts,
  hidden centralization, hard-coded demo behavior, or an unauthenticated happy
  path into code that can be activated in a release.
- Do not call an incomplete component production-ready. Record missing
  invariants, threats, tests, benchmarks, audits, and operational controls.
- Keep exploratory comparisons quarantined from activatable production paths.
  They are evidence for a design decision, not a shipped Vault feature.
- Require specifications, threat analysis, deterministic behavior, adversarial
  tests, resource bounds, versioning, migration/activation plans, reproducible
  builds, observability, and rollback or recovery planning as applicable.
- Prefer the least complex design that completely satisfies the security and
  protocol requirements. Unnecessary complexity is a security liability; this
  rule forbids simplified guarantees, not clear implementations.
- Never use real funds or make safety, privacy, decentralization, permanence,
  throughput, or cost claims until the corresponding release gates and
  independent reviews have passed.

Current research code remains non-production and must not be silently promoted.
It may be retained as a test oracle or evaluation artifact only when its status
and isolation are explicit.
