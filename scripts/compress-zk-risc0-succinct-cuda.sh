#!/usr/bin/env bash
set -euo pipefail

export PATH="${HOME}/.cargo/bin:${PATH}"

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
host_toolchain="${VAULT_RISC0_HOST_TOOLCHAIN:-1.90.0}"
input_path="${VAULT_C6_COMPOSITE_RECEIPT_PATH:-}"
output_path="${VAULT_C6_SUCCINCT_RECEIPT_PATH:-}"
expected_input_bytes="311977650"
expected_input_sha256="12c952e2da0466d7047586404b15c7ad6fa59675bb8c975019b4645dca7e6e96"
protocol_max_bytes="2097152"

fail() {
  echo "C6 RISC Zero succinct compression failed: $*" >&2
  exit 1
}

[[ -n "$input_path" ]] || fail "VAULT_C6_COMPOSITE_RECEIPT_PATH is required"
[[ -n "$output_path" ]] || fail "VAULT_C6_SUCCINCT_RECEIPT_PATH is required"
[[ "$input_path" == /* ]] || fail "the input receipt path must be absolute"
[[ "$output_path" == /* ]] || fail "the output receipt path must be absolute"
[[ "$input_path" != "$output_path" ]] || fail "input and output paths must differ"
[[ -s "$input_path" ]] || fail "the input receipt does not exist or is empty"
[[ -z "${RISC0_DEV_MODE+x}" ]] || fail "RISC0_DEV_MODE must be unset"

log_path="${output_path}.log"
environment_path="${output_path}.environment.txt"
manifest_path="${output_path}.manifest.txt"
gpu_metrics_path="${output_path}.gpu.csv"
resource_path="${output_path}.resources.txt"
for artifact_path in \
  "$output_path" \
  "$log_path" \
  "$environment_path" \
  "$manifest_path" \
  "$gpu_metrics_path" \
  "$resource_path"; do
  [[ ! -e "$artifact_path" ]] || fail "refusing to overwrite $artifact_path"
done
mkdir -p "$(dirname "$output_path")"

actual_input_bytes="$(wc -c < "$input_path" | tr -d '[:space:]')"
[[ "$actual_input_bytes" == "$expected_input_bytes" ]] || \
  fail "input receipt has $actual_input_bytes bytes; expected $expected_input_bytes"
actual_input_sha256="$(sha256sum "$input_path" | awk '{ print $1 }')"
[[ "$actual_input_sha256" == "$expected_input_sha256" ]] || \
  fail "input receipt SHA-256 is $actual_input_sha256; expected $expected_input_sha256"

{
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "input_receipt_file=$(basename "$input_path")"
  echo "input_receipt_bytes=$actual_input_bytes"
  echo "input_receipt_sha256=$actual_input_sha256"
  export VAULT_CUDA_MIN_VRAM_MIB="${VAULT_CUDA_MIN_VRAM_MIB:-30000}"
  "$repository_root/scripts/check-zk-risc0-cuda-host.sh"
} | tee "$environment_path"

export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}"
export RISC0_PROVER=local
export VAULT_C6_COMPOSITE_RECEIPT_PATH="$input_path"
export VAULT_C6_SUCCINCT_RECEIPT_PATH="$output_path"

echo 'timestamp,index,name,utilization_gpu_percent,memory_used_mib,memory_total_mib' \
  > "$gpu_metrics_path"
monitor_gpu() {
  while true; do
    nvidia-smi -i "$CUDA_VISIBLE_DEVICES" \
      --query-gpu=timestamp,index,name,utilization.gpu,memory.used,memory.total \
      --format=csv,noheader,nounits >> "$gpu_metrics_path" 2>/dev/null || true
    sleep 2
  done
}
monitor_gpu &
monitor_pid="$!"
stop_monitor() {
  kill "$monitor_pid" 2>/dev/null || true
  wait "$monitor_pid" 2>/dev/null || true
}
trap stop_monitor EXIT INT TERM

cd "$repository_root/zk/risc0"
set +e
{
  echo "compression_started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "cuda_visible_devices=$CUDA_VISIBLE_DEVICES"
  /usr/bin/time -v -o "$resource_path" \
    cargo +"$host_toolchain" test \
      --release \
      --locked \
      -p vault-zk-risc0 \
      --features cuda-prover \
      --test transfer_v2_receipt \
      compresses_published_composite_to_succinct_and_rejects_mutations \
      -- \
      --ignored \
      --exact \
      --nocapture
  test_status="$?"
  if ((test_status == 0)); then
    echo "compression_finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi
  exit "$test_status"
} 2>&1 | tee "$log_path"
compression_status="${PIPESTATUS[0]}"
set -e
stop_monitor
trap - EXIT INT TERM
((compression_status == 0)) || fail "compression test exited with status $compression_status"

[[ -s "$output_path" ]] || fail "compression completed without a non-empty output receipt"
output_bytes="$(wc -c < "$output_path" | tr -d '[:space:]')"
output_sha256="$(sha256sum "$output_path" | awk '{ print $1 }')"
compression_elapsed_ms="$(sed -n 's/^compression_elapsed_ms=//p' "$log_path" | tail -n 1)"
[[ "$compression_elapsed_ms" =~ ^[0-9]+$ ]] || fail "compression time is missing from the log"
gpu_samples="$(awk 'END { print NR - 1 }' "$gpu_metrics_path")"
[[ "$gpu_samples" =~ ^[0-9]+$ ]] || fail "GPU sample count is invalid"
((gpu_samples > 0)) || fail "no GPU samples were recorded"
peak_gpu_memory_mib="$(awk -F',' '
  NR > 1 {
    gsub(/[[:space:]]/, "", $5)
    if ($5 + 0 > maximum) maximum = $5 + 0
  }
  END { print maximum + 0 }
' "$gpu_metrics_path")"
peak_host_rss_kib="$(awk -F':' '
  /Maximum resident set size/ {
    gsub(/[[:space:]]/, "", $2)
    print $2
  }
' "$resource_path")"
[[ "$peak_host_rss_kib" =~ ^[0-9]+$ ]] || fail "peak host RSS is missing"
if ((output_bytes <= protocol_max_bytes)); then
  protocol_size_compatible=true
else
  protocol_size_compatible=false
fi

cuda_release="$(nvcc --version | sed -n 's/.*release \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | tail -n 1)"
{
  echo "schema=vault-c6-risc0-succinct-compression-evidence-v1"
  echo "repository_commit=$(git -C "$repository_root" rev-parse HEAD)"
  echo "input_receipt_file=$(basename "$input_path")"
  echo "input_receipt_bytes=$actual_input_bytes"
  echo "input_receipt_sha256=$actual_input_sha256"
  echo "output_receipt_file=$(basename "$output_path")"
  echo "output_receipt_kind=succinct"
  echo "output_receipt_bytes=$output_bytes"
  echo "output_receipt_sha256=$output_sha256"
  echo "protocol_max_proof_bytes=$protocol_max_bytes"
  echo "protocol_size_compatible=$protocol_size_compatible"
  echo "compression_elapsed_ms=$compression_elapsed_ms"
  echo "gpu_samples=$gpu_samples"
  echo "peak_gpu_memory_mib=$peak_gpu_memory_mib"
  echo "peak_host_rss_kib=$peak_host_rss_kib"
  echo "reviewed_guest_id=85170f11445f10ba9b26e4ca96f29600fe4e30410081905f519a99449dd2d128"
  echo "risc0_zkvm=3.0.6"
  echo "host_toolchain=$host_toolchain"
  echo "cuda_release=$cuda_release"
  echo "completed_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$manifest_path"

cat "$manifest_path"
echo "Copy the output receipt and its five sidecar files before destroying the host."
