# C1 RISC Zero CUDA evidence runbook

**Scope:** C1 real-receipt evidence and the RISC Zero half of C4

**Maturity:** production-intent, unaudited, non-activatable

**Pinned backend:** RISC Zero 3.0.6, Composite receipt
**Reviewed guest ID:**
`cb95069bf50d37a3e6a9f0fd1519a5676d634c28c6f5a59a335511427cadd032`

This runbook produces one receipt for Vault's deterministic synthetic
transfer-v2 evidence fixture. It must not be used with wallet data or real
funds. Completion supplies C1 evidence; it does not activate a verifier or
close C4 until the resulting artifact is published with its negative vectors.

## Rent this host

Use one non-preemptible Linux x86_64 host with:

- one NVIDIA A100 or H100 with 80 GiB VRAM;
- at least 120 GiB system RAM and 16 vCPUs;
- at least 100 GiB of free persistent SSD;
- Ubuntu 22.04 with the CUDA 12.8.1 **development** toolkit (`nvcc` included);
- SSH access and billing that permits at least two uninterrupted hours.

Do not select a runtime-only CUDA image, a spot/preemptible instance, or an
image where `nvcc --version` is unavailable. The repository preflight requires
at least 20,000 MiB VRAM, 60,000 MiB RAM, and 40 GiB free disk, but the larger
values above preserve build and proving margin.

## First 25 minutes: install the pinned tools

Start from the provider's CUDA 12.8.1 development image. After the CUDA
preparation commit has been pushed, install `git`, clone the exact published
branch, and run the idempotent setup script:

```bash
sudo apt-get update
sudo apt-get install -y git
git clone --branch codex/c1-transfer-v2 --single-branch \
  https://github.com/TOMASCORZO/vault.git
cd vault

./scripts/setup-zk-risc0-cuda-host.sh
export PATH="${HOME}/.cargo/bin:${PATH}"
```

Check the installed environment after setup:

```bash
nvidia-smi
nvcc --version
rzup --version
rzup show
rustup run 1.90.0 rustc --version
```

The expected versions are CUDA 12.8, `rzup 0.5.2`, host Rust 1.90.0, and RISC
Zero guest Rust 1.97.0. Do not upgrade RISC Zero or regenerate the fixture with
a different dependency lock during this evidence run.

## Confirm the exact published branch

After setup, confirm the checkout before spending time on compilation:

```bash
git status --short --branch
git rev-parse HEAD
```

The checkout must be clean. Record the commit printed by `git rev-parse`; the
proving script records it again in the evidence manifest.

## Generate the receipt

Choose an absolute path on persistent storage. The script refuses to overwrite
an existing receipt or evidence file.

```bash
sudo mkdir -p /mnt/vault-evidence
sudo chown "$(id -u):$(id -g)" /mnt/vault-evidence

export VAULT_C1_RECEIPT_PATH=/mnt/vault-evidence/vault-c1-transfer-v2.receipt.bin
tmux new-session -d -s vault-c1 './scripts/prove-zk-risc0-cuda.sh'
tmux attach-session -t vault-c1
```

Detach from `tmux` with `Ctrl-b d`. In a second SSH session, confirm that the
GPU is active:

```bash
watch -n 5 nvidia-smi
```

The script performs these gates in order:

1. checks OS, architecture, clean Git state, driver, CUDA, VRAM, RAM, disk, and
   pinned Rust toolchains;
2. builds with the opt-in `cuda-prover` feature;
3. regenerates the guest and rejects an image-ID mismatch before proving;
4. generates and immediately verifies the real Composite receipt;
5. reads the saved receipt back from disk and verifies it again against the
   deterministic fixture, including a wrong-public-digest rejection;
6. writes a SHA-256 manifest and a non-secret environment report.

`RISC0_DEV_MODE` must remain unset. The script forces `RISC0_PROVER=local` and
one CUDA device. It never invokes Bonsai or submits the fixture to a third
party.

## Files that must leave the rented host

Do not terminate the host until all four files have been copied elsewhere:

```text
vault-c1-transfer-v2.receipt.bin
vault-c1-transfer-v2.receipt.bin.log
vault-c1-transfer-v2.receipt.bin.environment.txt
vault-c1-transfer-v2.receipt.bin.manifest.txt
```

The log must contain `test result: ok`, the reviewed guest ID, proof size,
elapsed time, segment count, total cycles, and user cycles. Compare the receipt
hash with the manifest after download.

On the M1, verify the downloaded receipt independently:

```bash
./scripts/verify-zk-risc0-c1-receipt.sh \
  /absolute/path/vault-c1-transfer-v2.receipt.bin
```

Only after this verification should the receipt, canonical public inputs,
manifest, exact toolchain record, proof-size bound, and negative cases be
published as the RISC Zero half of C4.

## Time budget and failure rules

- Allocate the first 25–40 minutes to installation and the CUDA preflight.
- The preflight compiles the CUDA host and guest, so the proving command reuses
  a warm Cargo target directory.
- Preserve the `.environment.txt` file if preflight fails and the `.log` file
  if proving fails; they are diagnostic evidence, not closure evidence.
- Do not switch to development mode, change the guest, loosen verification, or
  upgrade dependencies to rescue a run.
- If the host is approaching its billing limit without a receipt, extend the
  same non-preemptible instance when economical. Interrupting the test produces
  no usable C1 artifact.
