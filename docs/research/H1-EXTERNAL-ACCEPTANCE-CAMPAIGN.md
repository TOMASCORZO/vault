# Consolidated H1 external acceptance campaign

**Updated:** 2026-08-29
**Status:** preparation only; do not start the long or destructive owned-host
run until every required harness below is marked ready
**Scope:** one coordinated owned-target-hardware run for H1-A1 through H1-A3
evidence; H1-A4 independent human review is not a compute workload

The purpose of this record is to avoid fragmented acceptance runs. Local
design, fixtures, bounds, and deterministic harnesses must be complete first.
The campaign then prepares the owned acceptance machine once, records immutable
environment data, runs the complete matrix and copies evidence off-host.

## Infrastructure bundle

No GPU is required.

| Host | Minimum profile | Planned use | Execution window |
|---|---|---|---|
| Owned acceptance host | dedicated x86_64 Linux, 16 vCPU, 64 GiB RAM, 500 GB local NVMe, hardware virtualization exposed | all Halo2 prover/validator measurements, 24-hour sanitizer fuzzing, two clean build/cache runs, full burn cache, wallet long-history/fault/storage campaign | one coordinated operator-scheduled window |
| Supported platform devices | actual declared macOS/Windows/Linux keystores and selected secure element or hardware wallet | key custody, rollback state, filesystem semantics, crash-dump policy, signer hardware paths | separate physical/platform campaign; cannot be replaced by the acceptance host |

The 500 GB owned-host disk permits a 64 GiB wallet snapshot, encrypted backup,
rollback journal or migration copy, restored database, build trees, fuzz corpus,
and the 4,637,240,716-byte burn cache to coexist without invalidating disk-full
tests. Acceptance must record the exact CPU model, memory, disk model/filesystem,
kernel, libc, compiler, Cargo, lockfile digests, commit/tree digest, and stable
machine identifier before execution.

## Single-host assurance limitation

By owner decision dated 2026-08-28, no second machine is required. Build,
vector and full-bound cache checks are repeated in two fresh isolated roots on
the owned host. Matching results demonstrate same-host repeatability only.
They do not detect common-mode CPU, firmware, OS, compiler/toolchain,
filesystem or host-compromise failures. H1-A4 review and release disclosures
must carry this accepted residual risk and must not describe the evidence as
independent or cross-host reproduction.

## Readiness and run matrix

| Gate | Harness | Host | Readiness |
|---|---|---|---|
| Read-only owned-host preflight | `scripts/preflight-h1-acceptance-host.sh` | candidate owned host | ready; validates Linux/x86_64, CPU, RAM, disk, virtualization and pinned tools without running a workload |
| Root/Halo2 release gates and RustSec | `scripts/check.sh`, `scripts/check-zk-halo2.sh`, offline `scripts/audit.sh` | owned host, repeated in clean roots | ready |
| Repeated Halo2 proving and standalone verification for 2/4/8/16 | `scripts/benchmark-zk-halo2.sh` | owned host | ready |
| Declared heterogeneous validator block profiles | `scripts/benchmark-zk-halo2-heterogeneous.sh` with saved workload manifest | owned host | ready |
| Sustained malformed-proof fuzzing | `scripts/fuzz-zk-halo2.sh 86400` with pinned nightly/libFuzzer/ASan | owned host | ready |
| Build and vector repeatability | `scripts/reproduce-zk-halo2-build.sh`, `scripts/reproduce-zk-halo2-vectors.sh`; compare two clean-root hashes | owned host | ready; same-host limitation applies |
| Full-bound burn cache/digest/restart/recovery | guarded `scripts/benchmark-burn-recovery.sh` at 144,913,768 steps, repeated in a fresh cache root | owned host | ready; same-host limitation applies |
| Wallet long history, pruning, compaction, backup and restore | `scripts/benchmark-wallet-history.sh` with unrelated and owned profiles | owned host | ready; local smoke passed |
| Wallet schema-1 migration and cross-version restore | `scripts/benchmark-wallet-migration.sh` | owned host | ready; local smoke passed |
| Wallet backup rotation and restore drill | long-history runner plus receipt/copy/drill inventory workflow | owned host plus off-host evidence destination | ready locally; off-host copy destination pending |
| Wallet process crash during active rollback journal | `scripts/fault-wallet-process-crash.sh` | owned host | ready; three-attempt local smoke passed |
| Wallet ENOSPC during commit/backup/restore/compaction | guarded `scripts/fault-wallet-disk-full-linux.sh` on its own ext4 image | owned host | ready for Linux; intentionally not run on local Mac |
| Hard reset, power loss, and partial-write/device faults | sustained fault worker plus owned-machine reset controller and disposable block-device fault layer | owned host | pending machine-specific controller/device plan |
| Wallet timing/file/page/cache leakage measurements | `scripts/measure-wallet-leakage-linux.sh` paired `perf` profiles | owned host | ready for Linux; local compiler/lint gate passed |
| Keystore, secure rollback, BIP-39 entry, trusted signer confirmation and additional platform stores | platform-specific H1-A2/H1-A3 adapters implementing the frozen traits/state machines | physical/platform devices | wallet custody plus protected signer key/replay and confirmation interfaces ready; adapters pending; the acceptance host cannot substitute for these devices |
| RedPallas FROST key package, protected shares/nonces, aggregation, and abort/restart/participant-fault matrix | reviewed multisignature dependency plus physical signer adapters; bounded controller campaign on owned host | physical devices plus owned host | policy/agreement/session and no-fake-share corpus ready; dependency replacement, real share/aggregation vectors and adapters pending; threshold shares must not be simulated |
| Delegated proving transport/store, rollback/revocation/equivocation and endpoint retention/memory/log leakage | owned host plus declared endpoint | owned host and reviewed endpoint | A3-5 contracts plus A3-6 witness/request/response codecs and corpus ready; concrete adapters, positive suite-result integration and bounded controller pending |
| Pairing/store independent review and cryptography review | review packet and human reviewers | none | H1-A3/H1-A4; not a machine test |
| Signer registry/replay crash, hard-reset and device faults | consolidated A2/A3 owned-machine reset and disposable-device controller | owned host | pending shared controller; do not run piecemeal |
| Signer parser fuzz and latency/memory profiles | bounded A3 corpus and runner | owned host | ready; 15-second local sanitizer smoke clean, sustained target run pending |

## Commands already frozen for H1-A1

After provisioning dependencies and before disabling Cargo network access:

```bash
VAULT_H1_ACCEPTANCE_MACHINE_ID=vault-acceptance-01 \
VAULT_H1_ACCEPTANCE_ROOT=/absolute/evidence \
  ./scripts/preflight-h1-acceptance-host.sh
./scripts/check.sh
./scripts/check-zk-halo2.sh
VAULT_AUDIT_OFFLINE=1 ./scripts/audit.sh
./scripts/benchmark-zk-halo2.sh verify 10 32 2 4 8 16
./scripts/benchmark-zk-halo2.sh prove 10 1 2 4 8 16
./scripts/benchmark-zk-halo2-heterogeneous.sh common 10 32
./scripts/benchmark-zk-halo2-heterogeneous.sh balanced 10 32
./scripts/benchmark-zk-halo2-heterogeneous.sh max-heavy 10 30
./scripts/fuzz-zk-halo2.sh 86400
./scripts/reproduce-zk-halo2-build.sh
./scripts/reproduce-zk-halo2-vectors.sh
mkdir -p /absolute/evidence/burn-cache
VAULT_H1_A1_ALLOW_FULL_BURN_BOUND=1 \
VAULT_H1_A1_BURN_CACHE_DIR=/absolute/evidence/burn-cache \
  ./scripts/benchmark-burn-recovery.sh 3 144913768
```

The preflight is read-only: it does not build, fuzz, mount, format, fill or
delete anything. Its machine ID is an operator-defined non-secret label, not a
hardware serial. A pass does not authorize the guarded destructive campaigns;
their exact markers and acknowledgements remain mandatory.

### Current development host is not the acceptance host

The 2026-08-29 preflight on the active Codex machine correctly failed: macOS
Darwin/arm64, Apple M1 with 8 logical CPUs, 8 GiB RAM, a roughly 245 GB
filesystem and about 20.7 GB available. Linux `perf`/`taskset`, ext4 tooling,
GNU `time -v` and `/dev/kvm` are absent. No long, full-bound or destructive
acceptance workload was started. The separate owned powerful machine must run
and pass the preflight before it is declared as the acceptance host.

After deleting the first temporary build/cache roots, the owned host repeats
the build/vector commands and the guarded full-bound burn command in fresh
roots with one recovery sample. The two full cache digests must match exactly.
A successful command without complete stdout/stderr, `/usr/bin/time -v`,
environment inventory, artifact digest, and off-host copy is not acceptance
evidence. Matching same-host results must not be labeled independent.

## Commands frozen for H1-A2 compute

Each command receives a distinct owner-only evidence directory. All fixtures
contain public deterministic keys and authorize no funds.

```bash
mkdir -m 700 /absolute/evidence/wallet-history-unrelated
VAULT_H1_A2_WALLET_WORK_DIR=/absolute/evidence/wallet-history-unrelated \
  ./scripts/benchmark-wallet-history.sh 100000 100 2 unrelated

mkdir -m 700 /absolute/evidence/wallet-history-max-block
VAULT_H1_A2_WALLET_WORK_DIR=/absolute/evidence/wallet-history-max-block \
  ./scripts/benchmark-wallet-history.sh 10000 4096 16 unrelated

mkdir -m 700 /absolute/evidence/wallet-history-owned
VAULT_H1_A2_WALLET_WORK_DIR=/absolute/evidence/wallet-history-owned \
  ./scripts/benchmark-wallet-history.sh 100000 100 2 owned

mkdir -m 700 /absolute/evidence/wallet-migration
VAULT_H1_A2_MIGRATION_DIR=/absolute/evidence/wallet-migration \
  ./scripts/benchmark-wallet-migration.sh 100000 2 100

mkdir -m 700 /absolute/evidence/wallet-process-crash
VAULT_H1_A2_WALLET_FAULT_DIR=/absolute/evidence/wallet-process-crash \
  ./scripts/fault-wallet-process-crash.sh 1000 16 100

mkdir -m 700 /absolute/evidence/wallet-leakage
VAULT_H1_A2_WALLET_LEAKAGE_ROOT=/absolute/evidence/wallet-leakage \
VAULT_H1_A2_MEASUREMENT_CPU=2 \
  ./scripts/measure-wallet-leakage-linux.sh 10000 5 100
```

The disk-full run uses an isolated filesystem image and deliberately consumes
its free space. The operator must create only the dedicated marker below; the
script refuses unmarked or ambiguously named roots and never formats a host
device.

```bash
mkdir -m 700 /absolute/evidence/vault-h1-a2-disk-full-primary
printf '%s\n' vault-h1-a2-disposable-root-v1 \
  > /absolute/evidence/vault-h1-a2-disk-full-primary/.vault-h1-a2-disposable-root
chmod 600 /absolute/evidence/vault-h1-a2-disk-full-primary/.vault-h1-a2-disposable-root
VAULT_H1_A2_DISK_FULL_ROOT=/absolute/evidence/vault-h1-a2-disk-full-primary \
VAULT_H1_A2_ALLOW_DISPOSABLE_VOLUME=I_UNDERSTAND_THIS_CREATES_A_DISPOSABLE_FILESYSTEM \
  ./scripts/fault-wallet-disk-full-linux.sh
```

The three history profiles are bounded stress workloads, not an invented
mainnet block distribution. The paired leakage profiles intentionally hold
block count constant while varying public action count and private ownership.
No result can upgrade the documented metadata leakage into a confidentiality
claim.

## Owned-machine decision

No compute host will be rented. H1-A1 compute harnesses, all local H1-A2
interfaces and history/migration/backup/process-crash/ENOSPC/leakage runners,
and A3-6 corpora/harnesses are ready. The owned-machine-specific consolidated
A2/A3 hard-reset/device-fault plan must still be frozen first. H1-A3
active-session shutdown, trusted confirmation, protected custody/replay,
multisignature agreement and delegated-proving authorization/disclosure
contracts are complete locally and add no separate compute host. The actual
delegated transport/store and endpoint campaign remain grouped with the same
acceptance window. The FROST adapter
still needs a reviewed dependency and actual signer devices; its bounded fault
corpus remains grouped with the same campaign. H1-A3 may add platform-specific
evidence but must not silently convert physical keystore or secure-element
requirements into generic host tests. Once every owned-host row is ready,
execute the matrix in one
operator-controlled window. The single-host common-mode risk remains accepted,
documented and subject to A4 review.
