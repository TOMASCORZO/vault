# C6 RISC Zero Succinct compression runbook

**Scope:** one decision-gate conversion of the published two-action Composite
receipt to a Succinct receipt

**Maturity:** isolated C6 evidence; non-activatable

**Pinned backend:** RISC Zero 3.0.6
**Reviewed guest ID:**
`85170f11445f10ba9b26e4ca96f29600fe4e30410081905f519a99449dd2d128`

This run does not repeat guest execution or the 1.16-billion-cycle base proof.
It cryptographically compresses the already published 311,977,650-byte
Composite receipt through RISC Zero recursion, verifies the resulting Succinct
receipt against the same guest and transfer-v2 journal, rejects public-input,
proof-byte, and truncation mutations, and compares its exact encoded size with
Vault's 2,097,152-byte protocol bound.

## Decision boundary

- If the Succinct receipt exceeds 2,097,152 bytes or compression fails under
  the pinned backend, reject RISC Zero 3.0.6 for direct base-layer transfers and
  do not purchase all-bucket runs.
- If it fits, retain RISC Zero as a benchmark candidate. Before C6 can close,
  prepare 4/8/16-action fixtures locally and plan repeated all-bucket proving,
  memory, and concurrency measurements.

Either outcome is evidence. A successful small receipt does not activate the
backend or resolve its dependency advisories.

## Rent only after the branch is published

Use one non-preemptible Linux x86_64 host with:

- one NVIDIA GPU with at least 32 GiB VRAM;
- at least 64 GiB system RAM and 16 vCPUs;
- at least 100 GiB free SSD;
- Ubuntu 24.04 and the CUDA 12.8 development toolkit, including `nvcc`;
- SSH access and enough uninterrupted time for an unmeasured recursion run.

The prior H100 evidence did not record peak VRAM for this different workload,
so 32 GiB is a measured hypothesis, not a guarantee. Do not choose a spot or
preemptible host for the first run.

## Prepare the canonical host

The checkout path remains part of the reviewed guest build identity:

```bash
sudo mkdir -p /workspace
sudo chown "$(id -u):$(id -g)" /workspace
cd /workspace
git clone --branch codex/c1-transfer-v2 --single-branch \
  https://github.com/TOMASCORZO/vault.git
cd vault
./scripts/setup-zk-risc0-cuda-host.sh
export PATH="${HOME}/.cargo/bin:${PATH}"
```

Confirm a clean, exact checkout:

```bash
git status --short --branch
git rev-parse HEAD
```

## Obtain the already published Composite receipt

Do not generate it again:

```bash
sudo mkdir -p /mnt/vault-evidence
sudo chown "$(id -u):$(id -g)" /mnt/vault-evidence
curl --fail --location \
  https://github.com/TOMASCORZO/vault/releases/download/c4-risc0-transfer-v2-v1/vault-c1-transfer-v2.receipt.bin \
  --output /mnt/vault-evidence/vault-c1-transfer-v2.receipt.bin
sha256sum /mnt/vault-evidence/vault-c1-transfer-v2.receipt.bin
```

The required SHA-256 is:

```text
12c952e2da0466d7047586404b15c7ad6fa59675bb8c975019b4645dca7e6e96
```

The compression script independently checks both this hash and the exact
311,977,650-byte length before starting CUDA work.

## Run compression

```bash
export VAULT_C6_COMPOSITE_RECEIPT_PATH=/mnt/vault-evidence/vault-c1-transfer-v2.receipt.bin
export VAULT_C6_SUCCINCT_RECEIPT_PATH=/mnt/vault-evidence/vault-c6-transfer-v2.succinct.receipt.bin

tmux new-session -d -s vault-c6 './scripts/compress-zk-risc0-succinct-cuda.sh'
tmux attach-session -t vault-c6
```

Detach with `Ctrl-b d`. The script samples utilization and VRAM every
two seconds and records GNU `time -v` host-resource metrics. It refuses to
overwrite any evidence file and forces the local cryptographic prover with
development mode unset.

## Files that must leave the rented host

Copy these six new files before destroying the instance:

```text
vault-c6-transfer-v2.succinct.receipt.bin
vault-c6-transfer-v2.succinct.receipt.bin.log
vault-c6-transfer-v2.succinct.receipt.bin.environment.txt
vault-c6-transfer-v2.succinct.receipt.bin.manifest.txt
vault-c6-transfer-v2.succinct.receipt.bin.gpu.csv
vault-c6-transfer-v2.succinct.receipt.bin.resources.txt
```

The original Composite receipt is already published and need not be downloaded
again. Verify the copied output hash against the generated manifest, then
destroy the rented instance and its storage.

## What counts as a pass

The log must show:

- `input_receipt_kind=composite` and `output_receipt_kind=succinct`;
- the reviewed guest ID and canonical public-input digest;
- successful verification after reopening the saved output;
- rejection of the wrong public digest, a changed proof byte, and truncation;
- `test result: ok`;
- exact output bytes and compression elapsed milliseconds.

The manifest separately records whether the Succinct receipt fits the protocol
size bound. That boolean is a selection result, not a substitute for the
cryptographic checks above.
