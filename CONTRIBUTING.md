# Contributing

Vault currently accepts design and code work only under explicit coordination
with the repository owner. The project license has not been selected, so public
third-party contributions must not be merged until ownership and licensing
terms are documented.

All work is governed by
[`docs/PRODUCTION_STANDARD.md`](docs/PRODUCTION_STANDARD.md). Vault does not
accept disposable prototypes, demo-only paths, or simplified security models as
feature deliverables. Comparative research must remain explicitly isolated and
non-activatable until a production design is selected and passes its gates.

All changes must:

- keep consensus code deterministic and free of network/time/environment reads;
- avoid new cryptographic constructions;
- include negative and adversarial tests;
- preserve fail-closed verifier behavior;
- document new trust assumptions and consensus fields;
- pass `./scripts/check.sh`;
- avoid claims of production safety without external evidence;
- assign an explicit maturity label to new components;
- include resource bounds, versioning, and activation/migration behavior where
  the change can affect consensus or stored state;
- avoid placeholders or mocks that can be enabled in a release build.

Consensus changes require a specification update and a migration/activation
plan. Cryptographic changes additionally require test vectors and independent
review.
