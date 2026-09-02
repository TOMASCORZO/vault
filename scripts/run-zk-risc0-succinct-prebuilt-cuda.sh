#!/usr/bin/env bash
set -euo pipefail

binary_path="${VAULT_C6_TEST_BINARY_PATH:-}"
bundle_manifest_path="${VAULT_C6_BUNDLE_MANIFEST_PATH:-}"
input_path="${VAULT_C6_COMPOSITE_RECEIPT_PATH:-}"
output_path="${VAULT_C6_SUCCINCT_RECEIPT_PATH:-}"
expected_input_bytes="311977650"
expected_input_sha256="12c952e2da0466d7047586404b15c7ad6fa59675bb8c975019b4645dca7e6e96"
protocol_max_bytes="2097152"
selected_gpu="${CUDA_VISIBLE_DEVICES:-0}"

fail() {
  echo "C6 prebuilt Succinct run failed: $*" >&2
  exit 1
}

manifest_value() {
  local key="$1"
  sed -n "s/^${key}=//p" "$bundle_manifest_path" | tail -n 1
}

for command_name in awk date head nvidia-smi sed sha256sum sleep tr uname wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done
[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "$(uname -m)" == "x86_64" ]] || fail "x86_64 is required"
[[ -z "${RISC0_DEV_MODE+x}" ]] || fail "RISC0_DEV_MODE must be unset"
[[ "$selected_gpu" != *,* ]] || fail "select exactly one CUDA device"
[[ -n "$binary_path" && -x "$binary_path" ]] || fail "VAULT_C6_TEST_BINARY_PATH must name the executable"
[[ -n "$bundle_manifest_path" && -s "$bundle_manifest_path" ]] || \
  fail "VAULT_C6_BUNDLE_MANIFEST_PATH must name the build manifest"
[[ -n "$input_path" && -s "$input_path" ]] || \
  fail "VAULT_C6_COMPOSITE_RECEIPT_PATH must name the published receipt"
[[ -n "$output_path" ]] || fail "VAULT_C6_SUCCINCT_RECEIPT_PATH is required"
[[ "$binary_path" == /* ]] || fail "the test binary path must be absolute"
[[ "$bundle_manifest_path" == /* ]] || fail "the build manifest path must be absolute"
[[ "$input_path" == /* ]] || fail "the input receipt path must be absolute"
[[ "$output_path" == /* ]] || fail "the output receipt path must be absolute"
[[ "$input_path" != "$output_path" ]] || fail "input and output paths must differ"

[[ "$(manifest_value schema)" == "vault-c6-risc0-cuda-prebuild-v1" ]] || \
  fail "unknown prebuild manifest schema"
expected_binary_sha256="$(manifest_value binary_sha256)"
[[ "$expected_binary_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "invalid binary hash in build manifest"
actual_binary_sha256="$(sha256sum "$binary_path" | awk '{ print $1 }')"
[[ "$actual_binary_sha256" == "$expected_binary_sha256" ]] || fail "test binary hash mismatch"

expected_cuda_arch="$(manifest_value cuda_arch)"
[[ "$expected_cuda_arch" =~ ^sm_[0-9]+$ ]] || fail "invalid CUDA architecture in build manifest"
gpu_compute_capability="$(
  nvidia-smi -i "$selected_gpu" --query-gpu=compute_cap --format=csv,noheader,nounits |
    tr -d '[:space:].' |
    head -n 1
)"
[[ "$gpu_compute_capability" =~ ^[0-9]+$ ]] || fail "could not read GPU compute capability"
actual_cuda_arch="sm_${gpu_compute_capability}"
[[ "$actual_cuda_arch" == "$expected_cuda_arch" ]] || \
  fail "bundle targets $expected_cuda_arch but selected GPU is $actual_cuda_arch"

actual_input_bytes="$(wc -c < "$input_path" | tr -d '[:space:]')"
[[ "$actual_input_bytes" == "$expected_input_bytes" ]] || \
  fail "input receipt has $actual_input_bytes bytes; expected $expected_input_bytes"
actual_input_sha256="$(sha256sum "$input_path" | awk '{ print $1 }')"
[[ "$actual_input_sha256" == "$expected_input_sha256" ]] || fail "input receipt hash mismatch"

gpu_memory_mib="$(
  nvidia-smi -i "$selected_gpu" --query-gpu=memory.total --format=csv,noheader,nounits |
    tr -d '[:space:]' |
    head -n 1
)"
[[ "$gpu_memory_mib" =~ ^[0-9]+$ ]] || fail "could not read GPU memory"
((gpu_memory_mib >= 30000)) || fail "GPU has ${gpu_memory_mib} MiB; at least 30000 MiB is required"
system_memory_mib="$(( $(awk '/MemTotal:/ { print $2 }' /proc/meminfo) / 1024 ))"
((system_memory_mib >= 60000)) || fail "host has ${system_memory_mib} MiB RAM; at least 60000 MiB is required"

log_path="${output_path}.log"
environment_path="${output_path}.environment.txt"
manifest_path="${output_path}.manifest.txt"
resource_path="${output_path}.resources.csv"
for artifact_path in "$output_path" "$log_path" "$environment_path" "$manifest_path" "$resource_path"; do
  [[ ! -e "$artifact_path" ]] || fail "refusing to overwrite $artifact_path"
done
mkdir -p "$(dirname "$output_path")"

{
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "source_commit=$(manifest_value source_commit)"
  echo "binary_sha256=$actual_binary_sha256"
  echo "input_receipt_sha256=$actual_input_sha256"
  echo "host=$(uname -a)"
  echo "system_memory_mib=$system_memory_mib"
  echo "cuda_visible_devices=$selected_gpu"
  echo "cuda_arch=$actual_cuda_arch"
  echo "gpu:"
  nvidia-smi -i "$selected_gpu" \
    --query-gpu=index,name,memory.total,driver_version \
    --format=csv,noheader
} > "$environment_path"

export CUDA_VISIBLE_DEVICES="$selected_gpu"
export RISC0_PROVER=local
export VAULT_C6_COMPOSITE_RECEIPT_PATH="$input_path"
export VAULT_C6_SUCCINCT_RECEIPT_PATH="$output_path"

"$binary_path" \
  compresses_published_composite_to_succinct_and_rejects_mutations \
  --ignored \
  --exact \
  --nocapture > "$log_path" 2>&1 &
test_pid="$!"

echo 'timestamp_utc,host_rss_kib,host_hwm_kib,gpu_index,gpu_name,gpu_utilization_percent,gpu_memory_used_mib,gpu_memory_total_mib' \
  > "$resource_path"
while [[ -r "/proc/$test_pid/stat" ]]; do
  process_state="$(awk '{ print $3 }' "/proc/$test_pid/stat" 2>/dev/null || true)"
  [[ "$process_state" != "Z" ]] || break
  host_rss_kib="$(awk '/VmRSS:/ { print $2 }' "/proc/$test_pid/status" 2>/dev/null || true)"
  host_hwm_kib="$(awk '/VmHWM:/ { print $2 }' "/proc/$test_pid/status" 2>/dev/null || true)"
  gpu_sample="$(
    nvidia-smi -i "$selected_gpu" \
      --query-gpu=index,name,utilization.gpu,memory.used,memory.total \
      --format=csv,noheader,nounits 2>/dev/null |
      head -n 1
  )"
  if [[ -n "$host_rss_kib" && -n "$host_hwm_kib" && -n "$gpu_sample" ]]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$host_rss_kib,$host_hwm_kib,$gpu_sample" \
      >> "$resource_path"
  fi
  sleep 2
done

set +e
wait "$test_pid"
test_status="$?"
set -e
cat "$log_path"
((test_status == 0)) || fail "compression test exited with status $test_status"
[[ -s "$output_path" ]] || fail "compression completed without an output receipt"

resource_samples="$(awk 'END { print NR - 1 }' "$resource_path")"
((resource_samples > 0)) || fail "no resource samples were recorded"
peak_host_rss_kib="$(awk -F',' 'NR > 1 && $3 + 0 > maximum { maximum = $3 + 0 } END { print maximum + 0 }' "$resource_path")"
peak_gpu_memory_mib="$(awk -F',' 'NR > 1 { gsub(/[[:space:]]/, "", $7); if ($7 + 0 > maximum) maximum = $7 + 0 } END { print maximum + 0 }' "$resource_path")"
output_bytes="$(wc -c < "$output_path" | tr -d '[:space:]')"
output_sha256="$(sha256sum "$output_path" | awk '{ print $1 }')"
compression_elapsed_ms="$(sed -n 's/^compression_elapsed_ms=//p' "$log_path" | tail -n 1)"
[[ "$compression_elapsed_ms" =~ ^[0-9]+$ ]] || fail "compression time is missing"
if ((output_bytes <= protocol_max_bytes)); then
  protocol_size_compatible=true
else
  protocol_size_compatible=false
fi

{
  echo "schema=vault-c6-risc0-succinct-compression-evidence-v1"
  echo "source_commit=$(manifest_value source_commit)"
  echo "binary_sha256=$actual_binary_sha256"
  echo "input_receipt_bytes=$actual_input_bytes"
  echo "input_receipt_sha256=$actual_input_sha256"
  echo "output_receipt_kind=succinct"
  echo "output_receipt_bytes=$output_bytes"
  echo "output_receipt_sha256=$output_sha256"
  echo "protocol_max_proof_bytes=$protocol_max_bytes"
  echo "protocol_size_compatible=$protocol_size_compatible"
  echo "compression_elapsed_ms=$compression_elapsed_ms"
  echo "resource_samples=$resource_samples"
  echo "peak_gpu_memory_mib=$peak_gpu_memory_mib"
  echo "peak_host_rss_kib=$peak_host_rss_kib"
  echo "completed_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$manifest_path"

cat "$manifest_path"
echo "Copy the output receipt and its four sidecar files before destroying the host."
