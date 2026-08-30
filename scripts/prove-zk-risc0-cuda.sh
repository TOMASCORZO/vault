#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
host_toolchain="${VAULT_RISC0_HOST_TOOLCHAIN:-1.90.0}"
receipt_path="${VAULT_C1_RECEIPT_PATH:-}"

fail() {
  echo "CUDA proving failed: $*" >&2
  exit 1
}

[[ -n "$receipt_path" ]] || fail "VAULT_C1_RECEIPT_PATH must be an absolute output path"
[[ "$receipt_path" == /* ]] || fail "VAULT_C1_RECEIPT_PATH must be absolute"
[[ -z "${RISC0_DEV_MODE+x}" ]] || fail "RISC0_DEV_MODE must be unset"

log_path="${receipt_path}.log"
environment_path="${receipt_path}.environment.txt"
manifest_path="${receipt_path}.manifest.txt"
for output_path in "$receipt_path" "$log_path" "$environment_path" "$manifest_path"; do
  [[ ! -e "$output_path" ]] || fail "refusing to overwrite $output_path"
done
mkdir -p "$(dirname "$receipt_path")"

{
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  "$repository_root/scripts/check-zk-risc0-cuda-host.sh"
} | tee "$environment_path"

export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}"
export RISC0_PROVER=local
export VAULT_C1_RECEIPT_PATH="$receipt_path"

cd "$repository_root/zk/risc0"
{
  echo "proving_started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "cuda_visible_devices=$CUDA_VISIBLE_DEVICES"
  cargo +"$host_toolchain" test \
    --release \
    --locked \
    -p vault-zk-risc0 \
    --features cuda-prover \
    --test transfer_v2_receipt \
    proves_and_verifies_real_transfer_v2_receipt \
    -- \
    --ignored \
    --exact \
    --nocapture
  echo "proving_finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee "$log_path"

[[ -s "$receipt_path" ]] || fail "the test completed without a non-empty receipt"

VAULT_C1_RECEIPT_VERIFY_PATH="$receipt_path" \
  cargo +"$host_toolchain" test \
  --release \
  --locked \
  -p vault-zk-risc0 \
  --features cuda-prover \
  --test transfer_v2_receipt \
  verifies_saved_real_transfer_v2_receipt \
  -- \
  --ignored \
  --exact \
  --nocapture 2>&1 | tee -a "$log_path"

receipt_sha256="$(sha256sum "$receipt_path" | awk '{ print $1 }')"
receipt_bytes="$(wc -c < "$receipt_path" | tr -d ' ')"
cuda_release="$(nvcc --version | sed -n 's/.*release \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | tail -n 1)"
{
  echo "schema=vault-c1-risc0-transfer-v2-receipt-evidence-v1"
  echo "repository_commit=$(git -C "$repository_root" rev-parse HEAD)"
  echo "receipt_file=$(basename "$receipt_path")"
  echo "receipt_bytes=$receipt_bytes"
  echo "receipt_sha256=$receipt_sha256"
  echo "reviewed_guest_id=cb95069bf50d37a3e6a9f0fd1519a5676d634c28c6f5a59a335511427cadd032"
  echo "risc0_zkvm=3.0.6"
  echo "host_toolchain=$host_toolchain"
  echo "guest_toolchain=1.97.0"
  echo "cuda_release=$cuda_release"
  echo "completed_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$manifest_path"

cat "$manifest_path"
echo "C1 receipt generated and independently re-read from disk successfully."
echo "Copy these four files before terminating the rented host:"
echo "  $receipt_path"
echo "  $log_path"
echo "  $environment_path"
echo "  $manifest_path"
