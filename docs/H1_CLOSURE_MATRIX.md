# H1 finite closure matrix

**Frozen:** 2026-08-23
**Milestone:** H1 — private-transfer production foundation
**Maturity:** production-intent foundation; unaudited, not activated, unsafe for
real funds

**Amendment:** the 2026-08-23 full RISC Zero proving attempt was terminated
after approximately 2 hours 48 minutes. Because that backend has no consensus
adapter and is not selected for transfers, its receipt was removed from H1-C1,
H1-C3, and H1-A1 gates; real-proof obligations remain on the selected Halo2
construction.

**Single-host acceptance amendment (2026-08-28):** the project owner removed
the requirement for a second physical or rented build machine. H1-A1 now
requires two fresh isolated build/target roots and two fresh full-bound cache
runs on one declared owned acceptance host. Their artifact and cache digests
must match exactly. This is repeatability on one host, not independent
reproducibility. The accepted residual risk is a common-mode CPU, firmware,
operating-system, compiler/toolchain, filesystem or host-compromise error that
both runs fail to detect. A4 review material and every release claim MUST state
this limitation; no record may call the result cross-host or independently
reproduced.

**H1-C2 completion record (2026-08-25):** the transparent Vesta IPA parameters,
fixed Action VK, candidate composed-transfer VKs for all 2/4/8/16 buckets,
reproduction contract, lifecycle, non-selected RISC Zero role, and separate
DKG trust are frozen in
[`architecture/HALO2_SETUP_AND_LIFECYCLE.md`](architecture/HALO2_SETUP_AND_LIFECYCLE.md).
Setup reproduction exposed that 16 Actions do not fit at `k = 14`; the selected
mapping is `k = 14` for 2/4/8 and `k = 15` for 16. They were candidate identities
at H1-C2; H1-C3 now vector-locks them, while activation-hardening and consensus
activation remain open.

**H1-C3 completion record (2026-08-25):** fixed self-contained vectors now
cover the selected 2/4/8/16-Action Halo2 shapes. Each binds its synthetic private
witness, canonical effects, suite ID, native public instances, real proof bytes
and digest, an anchor mutation, a proof-byte mutation, and exact accept/reject
expectations. The generator and release-mode verifier are specified in
[`research/HALO2-TRANSFER-V2-VECTORS.md`](research/HALO2-TRANSFER-V2-VECTORS.md).
The suites are vector-locked but unaudited and not activated.

**H1-C4 completion record (2026-08-25):** the production-intent native policy
at [`specs/BURN_AGGREGATION_V1.md`](specs/BURN_AGGREGATION_V1.md) canonically
forms same-key aggregates, requires 128 unique effects across 16 public windows,
carries lower volume forward without forced reveal, prevents individual
ciphertexts from entering the share API, binds DLEQ shares to exact membership,
filters malicious shares, and recovers the total with deterministic bounded
baby-step/giant-step under the complete supply cap. Fixed and adversarial native
tests cover the transition. Full-bound resource acceptance, independent review,
and every H2 scheduling/publication/finality adapter remain open.

**H1-A1 progress record (2026-08-27):** an opt-in release harness now measures
parameter/VK startup, parameter loading plus deterministic VK reconstruction,
reusable proving, standalone and batch verification, proof size, and process
peak RSS without entering normal gates or transfer processing. The same builder
reproduced all four H1-C3 vectors byte-for-byte; a structured malformed corpus,
fail-closed verifier-dependency deactivation exercise, and fresh RustSec scan
pass. One-time PK/VK reconstruction is selected instead of an invented key
format; a pinned AddressSanitizer fuzz harness passed its local smoke run; and a
canonical policy-bound burn cache now passes bounded integrity/restart tests.
The dependency gate scans the root, Halo2 release, and fuzz lockfiles, denies
all but one exact inactive warning, and separately fails if its package enters
an active graph. A deterministic validator runner now dispatches declared
mixed 2/4/8/16 block profiles through all four exact verifier materials.
H1-A1 remains open for all-bucket target-hardware proving, realistic
heterogeneous batches, sustained fuzzing, two isolated clean same-host builds,
and the full-bound burn cache/digest/resource run. See
[`research/H1-A1-PROOF-ENGINEERING.md`](research/H1-A1-PROOF-ENGINEERING.md).
The subsequent bounded burn run reached 4,194,304 steps and projects the current
in-memory table at about 11.94 GB RSS for the full bound, so an 8 GiB target is
explicitly not accepted and the guarded full attempt was not run.
Two separate clean local target trees also reproduced the selected Halo2 `rlib`
and setup-manifest executable byte-for-byte after normalizing the logical build
path. Under the single-host amendment, this is the required build-repeatability
shape, subject to repetition on the declared acceptance host and the recorded
common-mode limitation.

**H1-A2 progress record (2026-08-27):** the actual historical schema-1 to
schema-2 wallet transition is now explicit, backup-first, atomic, and
non-downgrading. It re-authenticates and reseals all private records under the
new schema AAD, preserves a non-empty spend witness, upgrades authenticated
legacy backups before destination publication, and rolls back cleanly after
each of nine injected migration stages. Schema-1 birthday state is rejected
because its missing recovery-completeness record cannot be reconstructed
safely. Backup receipts now bind exact copy bytes; the restore-drill API uses
the production restore path; and the rotation profile prevents automatic or
premature deletion of the last verified generations. Remaining H1-A2 work is finite in
[`research/H1-A2-WALLET-HARDENING.md`](research/H1-A2-WALLET-HARDENING.md), and
target-hardware compute is accumulated in one coordinated owned-host campaign.

**H1-A3 progress record (2026-08-28):** every registry-issued handshake and
transport now carries a peer lifecycle gate. Revocation and rotation shut the
old gate before the durable lifecycle transition, while uncertain persistence
poisons the registry and shuts every active session. Tests cover established
revoked and rotated transports plus all-session shutdown on injected I/O
failure. This closes only the local active-session item; the remaining bounded
A3 sequence is tracked in
[`research/H1-A3-SIGNER-HARDENING.md`](research/H1-A3-SIGNER-HARDENING.md).
The local trusted confirmation boundary now also removes raw public approval,
revocation, and rotation entry points: XX pairing, independently sourced
transfer intents, and authenticated peer lifecycle mutations require explicit
adapter traits with no permissive implementation. Concrete platform UX and
independent review remain open. The protected-key and rollback-resistant replay
interfaces are now frozen as canonical 136-byte records with no-clobber
enrollment, missing-state failure, complete-state secure CAS and poison-on-
uncertainty enforcement. Real keychain/secure-element adapters and device
evidence remain open; the Unix replay file is not claimed to resist rollback.
The local multisignature item now freezes a re-randomized RedPallas FROST
profile, exact-threshold participant/commitment sets, complete transaction and
action agreement, independent participant confirmation, one-use nonce/abort
rules, and final standard-signature verification. It does not activate the
currently audit-blocked FROST dependency or claim key-ceremony/share evidence.
The delegated-proving item now freezes one exact per-job authorization and
disclosure profile, dedicated endpoint/channel bindings, rollback-resistant
job/revocation semantics and mandatory local proof verification. Its explicit
privacy cost is the complete transfer witness plus the durable account
full-viewing capability, including derivable IVKs, OVKs, addresses and
nullifiers; no seed, spending authority or signature is delegated, and
revocation cannot undo earlier disclosure. This corrects an A3-5 privacy
invariant found while inventorying the A3-6 witness. A3-6 now also freezes the
bounded VDPW/VDPR/VDPS codecs, 176 deterministic all-bucket artifacts, exact
byte reproduction, malformed/context-negative corpus, pinned parser fuzzer and
latency/memory runner. No prover transport is activated, and the finite local
A3 sequence is exhausted.

This matrix gives the remaining H1 work a finite boundary. Completion of the
cryptographic implementation column does not imply activation, release
readiness, or mainnet eligibility. New work may amend this list only when a
missing invariant makes an existing H1 deliverable incorrect; the amendment
must record that invariant and its reason before implementation.

## H1 cryptographic implementation

These are the only remaining items that can expand the H1 private-transfer
proof statement.

| ID | Closure item | Done when | Explicitly excluded |
|---|---|---|---|
| H1-C1 | Transfer-v2 reference statement parity | The isolated maintained-zkVM oracle decodes the canonical transfer-v2 effects inside the guest and validates real-input membership and ownership, nullifier and randomized authorization-key derivation, input/net/output/burn commitment openings, output `rho`, exact Ironwood output encryption, proof-derived external/change/dummy classification, gas, exact ceiling burn, conservation, and the descriptor-bound threshold-ElGamal opening. Native positive and adversarial cases pass and the pinned guest builds. A full proving attempt is recorded but is not a closure gate because this backend is not selected for transfers. | A real RISC Zero receipt, consensus adapter, verifier activation, node/finality integration, network transport, wallet UX, and performance acceptance. |
| H1-C2 | Proof-system setup and lifecycle assumptions | One normative record identifies every selected Halo2 setup parameter, whether it is transparent or requires trusted material, the source and digest of fixed parameters and verifying keys, reproducibility requirements, upgrade/deactivation rules, the reason RISC Zero is not selected for transfers, and the distinct DKG trust assumptions. | Governance implementation, validator distribution, ceremonies for later systems, and mainnet approval. |
| H1-C3 | Real-proof conformance vectors | Fixed positive and field/proof-mutation vectors exist for the final selected Halo2 transfer shape, covering every 2/4/8/16 action bucket. Vectors bind canonical effects, witness/input fixture, suite ID, public instances, proof digest/length, and expected verification result. | RISC Zero receipts, independent audit, and performance acceptance. |
| H1-C4 | Epoch-burn privacy decision | A reviewed specification freezes aggregate formation, a bounded aggregate discrete-log recovery algorithm and maximum, minimum anonymity/volume policy, timeout/carry-forward behavior, malicious-share handling, and the rule that individual ciphertexts are never decrypted. Native deterministic and adversarial tests cover the frozen cryptographic transition. | DKG networking, validator-set consensus, finality, share gossip/publication, and epoch scheduling, which belong to H2. |

H1 cryptographic implementation is closed because H1-C1 through H1-C4 are
complete and reproducible proofs/vectors cover every H0 private-transfer
invariant. This closes only the finite cryptographic column: H1-A1 through
H1-A4 remain mandatory, and the status remains below release candidate.

## H1 activation hardening

These bounded gates may block activation but do not add new cryptographic
statement obligations.

| ID | Closure item | Included work |
|---|---|---|
| H1-A1 | Proof engineering gates | Benchmark the selected specialized implementation; cached-key startup, proving, standalone and batch verification, proof size, peak memory, malformed-input fuzzing, deterministic builds, dependency remediation, artifact reproduction, and verifier deactivation exercises. The non-selected zkVM's terminated proving attempt is recorded evidence, not an activation gate. |
| H1-A2 | Wallet custody and durability gates | Approved seed import/custody, trusted checkpoint distribution, incomplete-recovery UX, backup rotation/restore drills, migrations, pruning/compaction, long-history growth, keychain/secure-element key and rollback state, supported platform stores, disk-full/crash/power-loss injection, and privacy-side-channel measurements. |
| H1-A3 | Signer and delegated-proving gates | Independent pairing/store review, trusted confirmation and revocation UX, active-session shutdown, hardware-backed rollback, supported platform/hardware adapters, multisignature and delegated-proving profiles, and complete ciphertext/signing vectors. |
| H1-A4 | Review and activation gate | Independent cryptography design review, resolution of all critical/high findings in H1 scope, final suite freeze, and an explicit governed activation/deactivation plan. No verifier is activated before H1-C1..C4 and H1-A1..A4 pass. |

Current A2 local evidence includes the authenticated schema-1 to schema-2
migration, backup receipts/copy checks/restore drills, a no-deletion rotation
profile, immutable checkpoint retention, validated compaction, bounded
history/migration/process-crash/ENOSPC/leakage harnesses, a fail-closed recovery
product mapping, and the exact-anchor two-phase rollback protocol. Large Linux
runs, hard-reset/device faults, real custody adapters, seed-entry/confirmation
platform review, and independent review remain open; no real funds are
authorized.

Current A3 local evidence also freezes active-session shutdown, independent
trusted confirmation, protected-key/rollback contracts, the multisignature
agreement/nonce lifecycle, and the delegated-proving authorization,
irreversible disclosure, local-verification and revocation boundary. No FROST
engine or remote prover transport is activated. The A3-6 deterministic corpora
and bounded harnesses are complete locally; platform, sustained external-
compute, endpoint and independent-review evidence remains mandatory.

## Classified outside H1

| Classification | Work moved out of H1 closure |
|---|---|
| H2 consensus/network integration | A real validating full-node/light-client recovery source, consensus and finality, authenticated snapshots, anti-eclipse policy, private/padded block retrieval transport, retry/deadline policy, DKG protocol execution, validator rotation, burn-share publication/equivocation rules, and aggregate-supply state transitions. H1 defines and tests fail-closed interfaces only. |
| Later/mainnet eligibility | Public testnet operations, independent implementation/client diversity, economic/genesis governance, release signing, incident response, bug bounty, legal analysis, and integrated mainnet audits. |

Contracts, DEX, cross-chain, and durable application storage remain H3 or later
and cannot be pulled into any H1 item above.
