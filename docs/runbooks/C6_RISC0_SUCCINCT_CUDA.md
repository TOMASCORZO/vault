# C6 RISC Zero Succinct compression runbook

**Scope:** one decision-gate conversion of the published two-action Composite
receipt to a Succinct receipt

**Maturity:** isolated C6 evidence; non-activatable

**Pinned backend:** RISC Zero 3.0.6
**Reviewed guest ID:**
`85170f11445f10ba9b26e4ca96f29600fe4e30410081905f519a99449dd2d128`

This run does not repeat guest execution or the 1.16-billion-cycle base proof.
It compresses the published 311,977,650-byte Composite receipt, verifies the
Succinct result and negative mutations, and compares its encoded size with
Vault's 2,097,152-byte protocol bound.

## Exact remaining C6 boundary

Halo2's C6 selection measurements are complete: three repetitions for every
2/4/8/16-action bucket, verification, proof size, process peak RSS, transparent
key preparation, and a two-worker concurrency run. Stable parameter/VK/PK
serialization and cold loading are release engineering under A4, not another
C6 proof-system selection experiment.

The only external-compute task remaining for C6 is this one Succinct run. RISC
Zero 3.0.6 is already rejected for direct base-layer selection because its
measured Composite proof violates the protocol limit, its measured base proof
took 1,329.338 seconds, and its resolved host lock has activation-blocking
advisories. The Succinct run determines whether its wrapping path also violates
the size bound. It does not justify purchasing repeated 4/8/16-action or
concurrency runs for a rejected candidate.

## Free preparation — finish before renting

Never compile or install Rust on a billed GPU host.

1. Push the exact source commit.
2. Run `.github/workflows/c6-risc0-cuda-prebuild.yml`. It builds at the
   canonical `/workspace/vault` path inside
   `nvidia/cuda:12.8.1-devel-ubuntu24.04`, reproduces the reviewed guest ID, and
   uploads separate standalone bundles for Ada `sm_89`, Hopper `sm_90`, and
   Blackwell `sm_120`. Explicit targets are required because GitHub exposes no
   GPU for RISC Zero's default `nvcc -arch=native` detection.
3. Choose the bundle matching the exact rented GPU, then download and verify
   that CI artifact on the development machine.
4. Publish the verified archive as prerelease
   `c6-risc0-cuda-prebuild-v1` before starting a rental.
5. Confirm that both release URLs below return successfully and retain their
   expected SHA-256 values.

The paid host downloads only:

- the prebuilt test archive, expected to be tens of megabytes; and
- the already published 311,977,650-byte Composite receipt.

The prebuilt runner requires no repository clone, `apt`, Rust, `rzup`, Cargo,
`nvcc`, or compilation.

## Rental profile

Use one non-preemptible Linux x86_64 host with:

- one NVIDIA GPU with at least 32 GiB VRAM;
- at least 64 GiB system RAM and 16 vCPUs;
- 30 GiB disk (the prebuilt path uses well below this; the margin covers the
  CUDA image and output);
- the exact `nvidia/cuda:12.8.1-devel-ubuntu24.04` image or a compatible CUDA
  12.8 image confirmed by the bundle's `ldd.txt`;
- SSH access.

Select the archive by compute capability: RTX 4090/L4/L40/L40S use `sm_89`,
H100/H200 use `sm_90`, and RTX 5090/Blackwell use `sm_120`. Do not use a bundle
for a different architecture; the runner rejects a mismatch before proving.

The first recursion run has no measured peak VRAM, so 32 GiB is a hypothesis,
not a guarantee. Do not use a spot/preemptible host.

## Paid phase — no setup or compilation

Start billing only after the prerelease and receipt URLs are ready. On the
rented host:

```bash
mkdir -p /workspace/c6 /workspace/evidence
cd /workspace/c6

curl --fail --location \
  https://github.com/TOMASCORZO/vault/releases/download/c6-risc0-cuda-prebuild-v1/vault-c6-risc0-cuda-prebuild-sm_120.tar.gz \
  --output vault-c6-risc0-cuda-prebuild-sm_120.tar.gz &
bundle_download_pid=$!
curl --fail --location \
  https://github.com/TOMASCORZO/vault/releases/download/c4-risc0-transfer-v2-v1/vault-c1-transfer-v2.receipt.bin \
  --output /workspace/evidence/vault-c1-transfer-v2.receipt.bin &
receipt_download_pid=$!
wait "$bundle_download_pid" "$receipt_download_pid"

curl --fail --location \
  https://github.com/TOMASCORZO/vault/releases/download/c6-risc0-cuda-prebuild-v1/vault-c6-risc0-cuda-prebuild-sm_120.tar.gz.sha256 \
  --output vault-c6-risc0-cuda-prebuild-sm_120.tar.gz.sha256
sha256sum --check vault-c6-risc0-cuda-prebuild-sm_120.tar.gz.sha256
echo '12c952e2da0466d7047586404b15c7ad6fa59675bb8c975019b4645dca7e6e96  /workspace/evidence/vault-c1-transfer-v2.receipt.bin' |
  sha256sum --check
tar -xzf vault-c6-risc0-cuda-prebuild-sm_120.tar.gz
nvidia-smi
```

The example uses `sm_120`; substitute `sm_89` or `sm_90` in all four archive
references when that is the selected GPU's capability.

Run the prebuilt test directly:

```bash
export VAULT_C6_TEST_BINARY_PATH=/workspace/c6/c6-prebuild/vault-c6-risc0-succinct-test
export VAULT_C6_BUNDLE_MANIFEST_PATH=/workspace/c6/c6-prebuild/build.manifest.txt
export VAULT_C6_COMPOSITE_RECEIPT_PATH=/workspace/evidence/vault-c1-transfer-v2.receipt.bin
export VAULT_C6_SUCCINCT_RECEIPT_PATH=/workspace/evidence/vault-c6-transfer-v2.succinct.receipt.bin

/workspace/c6/c6-prebuild/run-zk-risc0-succinct-prebuilt-cuda.sh
```

The runner refuses an incorrect binary, input receipt, architecture, memory
profile, development mode, or existing output. It forces the local
cryptographic prover and samples host RSS and GPU utilization/VRAM every two
seconds.

## Time and cost control

Expected billed setup is only boot/SSH plus roughly 400 MB of parallel
downloads and a sub-minute preflight. Compression time is deliberately not
estimated until measured; it should dominate the rental. Do not rebuild the
base receipt, clone the repository, update packages, or troubleshoot a build on
the GPU. If the preflight fails, stop and destroy the host rather than repairing
it under billing.

After the runner exits, immediately copy these five files off the host:

```text
vault-c6-transfer-v2.succinct.receipt.bin
vault-c6-transfer-v2.succinct.receipt.bin.log
vault-c6-transfer-v2.succinct.receipt.bin.environment.txt
vault-c6-transfer-v2.succinct.receipt.bin.manifest.txt
vault-c6-transfer-v2.succinct.receipt.bin.resources.csv
```

Verify the copied output hash against the generated manifest, then destroy the
instance and its attached storage. The original Composite receipt does not need
to be copied back.

## What counts as valid evidence

The log must show the reviewed guest ID and public-input digest, a verified
Succinct receipt after reopening, rejection of a wrong public digest, a changed
proof byte and truncation, and `test result: ok`. The manifest records exact
input/output hashes and bytes, compression time, peak GPU memory, peak host RSS,
and whether the result fits the protocol bound.

Either size result is useful evidence; neither activates a verifier.
