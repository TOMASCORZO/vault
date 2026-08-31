#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
host_toolchain="${VAULT_RISC0_HOST_TOOLCHAIN:-1.90.0}"
pinned_cuda_release="12.8"
minimum_vram_mib="${VAULT_CUDA_MIN_VRAM_MIB:-20000}"
minimum_ram_mib="${VAULT_CUDA_MIN_RAM_MIB:-60000}"
minimum_disk_gib="${VAULT_CUDA_MIN_DISK_GIB:-40}"
selected_gpu="${CUDA_VISIBLE_DEVICES:-0}"

fail() {
  echo "CUDA preflight failed: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

[[ "$(uname -s)" == "Linux" ]] || fail "the evidence run requires Linux"
[[ "$(uname -m)" == "x86_64" ]] || fail "the evidence run requires x86_64"
[[ -z "${RISC0_DEV_MODE+x}" ]] || fail "RISC0_DEV_MODE must be unset"
[[ "$selected_gpu" != *,* ]] || fail "select exactly one CUDA device"

for command_name in cargo c++ git nvidia-smi nvcc rustc rustup rzup sha256sum; do
  require_command "$command_name"
done

os_id="$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"' | head -n 1)"
os_version="$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"' | head -n 1)"
if [[ "$os_id" != "ubuntu" || "$os_version" != "22.04" ]]; then
  [[ "${VAULT_ALLOW_OTHER_OS:-0}" == "1" ]] ||
    fail "Ubuntu 22.04 is pinned; found ${os_id:-unknown} ${os_version:-unknown}"
fi

if [[ "${VAULT_ALLOW_DIRTY_PROVING:-0}" != "1" ]]; then
  [[ -z "$(git -C "$repository_root" status --porcelain --untracked-files=all)" ]] ||
    fail "the repository must be clean; commit or remove local files first"
fi

cuda_release="$(nvcc --version | sed -n 's/.*release \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | tail -n 1)"
[[ -n "$cuda_release" ]] || fail "could not determine the CUDA toolkit release"
if [[ "$cuda_release" != "$pinned_cuda_release" && "${VAULT_ALLOW_OTHER_CUDA:-0}" != "1" ]]; then
  fail "CUDA $pinned_cuda_release is pinned for this run; found $cuda_release"
fi

gpu_memory_mib="$(
  nvidia-smi -i "$selected_gpu" --query-gpu=memory.total --format=csv,noheader,nounits |
    tr -d ' ' |
    head -n 1
)"
[[ "$gpu_memory_mib" =~ ^[0-9]+$ ]] || fail "could not read NVIDIA GPU memory"
((gpu_memory_mib >= minimum_vram_mib)) ||
  fail "GPU has ${gpu_memory_mib} MiB; at least ${minimum_vram_mib} MiB is required"

system_memory_mib="$(( $(awk '/MemTotal:/ { print $2 }' /proc/meminfo) / 1024 ))"
((system_memory_mib >= minimum_ram_mib)) ||
  fail "host has ${system_memory_mib} MiB RAM; at least ${minimum_ram_mib} MiB is required"

available_disk_gib="$(( $(df -Pk "$repository_root" | awk 'NR == 2 { print $4 }') / 1024 / 1024 ))"
((available_disk_gib >= minimum_disk_gib)) ||
  fail "only ${available_disk_gib} GiB is free; at least ${minimum_disk_gib} GiB is required"

rustup run "$host_toolchain" rustc --version >/dev/null 2>&1 ||
  fail "Rust host toolchain $host_toolchain is not installed"
[[ "$(rzup --version)" == "rzup 0.5.2" ]] || fail "rzup 0.5.2 is required"
rzup show | grep -Eq '^\*?[[:space:]]*1\.97\.0$' ||
  fail "RISC Zero guest Rust 1.97.0 is not installed with rzup"

echo "repository_commit=$(git -C "$repository_root" rev-parse HEAD)"
echo "host=$(uname -a)"
echo "os=$os_id $os_version"
echo "host_toolchain=$(rustup run "$host_toolchain" rustc --version)"
echo "cargo=$(cargo +"$host_toolchain" --version)"
echo "rzup=$(rzup --version)"
echo "cuda_release=$cuda_release"
echo "nvcc=$(nvcc --version | tail -n 1)"
echo "cuda_visible_devices=$selected_gpu"
echo "system_memory_mib=$system_memory_mib"
echo "available_disk_gib=$available_disk_gib"
echo "gpus:"
nvidia-smi -i "$selected_gpu" \
  --query-gpu=index,name,memory.total,driver_version \
  --format=csv,noheader

cd "$repository_root/zk/risc0"
cargo +"$host_toolchain" test \
  --release \
  --locked \
  -p vault-zk-risc0 \
  --features cuda-prover \
  --lib \
  guest_image_id_changes_require_explicit_review \
  -- \
  --nocapture

echo "CUDA preflight passed; the generated guest matches the reviewed image ID."
