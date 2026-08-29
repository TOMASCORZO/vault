#!/usr/bin/env bash
set -euo pipefail

samples="${1:-3}"
shift "$(( $# > 0 ? 1 : 0 ))"
step_sizes=("$@")
if [[ "${#step_sizes[@]}" -eq 0 ]]; then
  step_sizes=(16384 65536 262144 1048576)
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
benchmark_binary="$repo_root/target/release/examples/h1_a1_burn_recovery"
full_step_size=144913768
cache_dir="${VAULT_H1_A1_BURN_CACHE_DIR:-}"

if [[ -n "$cache_dir" && ( ! -d "$cache_dir" || ! -w "$cache_dir" ) ]]; then
  echo "VAULT_H1_A1_BURN_CACHE_DIR must name an existing writable directory" >&2
  exit 2
fi

uname -a
rustc -Vv
if [[ "$(uname -s)" == "Darwin" ]]; then
  sysctl -n machdep.cpu.brand_string
  sysctl -n hw.memsize
elif command -v lscpu >/dev/null 2>&1; then
  lscpu
fi

cd "$repo_root"
cargo build --release --locked -p vault-burn --features reference-oracle \
  --example h1_a1_burn_recovery

for step_size in "${step_sizes[@]}"; do
  if ! [[ "$step_size" =~ ^[0-9]+$ ]] || [[ "$step_size" -eq 0 ]]; then
    echo "step sizes must be positive integers" >&2
    exit 2
  fi
  if [[ "$step_size" -gt "$full_step_size" ]]; then
    echo "step size exceeds the frozen full-bound table" >&2
    exit 2
  fi
  if [[ "$step_size" -eq "$full_step_size" \
      && "${VAULT_H1_A1_ALLOW_FULL_BURN_BOUND:-0}" != "1" ]]; then
    echo "refusing full-bound burn benchmark without VAULT_H1_A1_ALLOW_FULL_BURN_BOUND=1" >&2
    exit 2
  fi
  maximum="$((step_size * step_size - 1))"
  if [[ "$maximum" -gt 21000000000000000 ]]; then
    maximum=21000000000000000
  fi
  command=(
    "$benchmark_binary"
    --maximum "$maximum"
    --amount "$maximum"
    --samples "$samples"
  )
  if [[ -n "$cache_dir" ]]; then
    cache_path="$cache_dir/burn-recovery-$step_size.vbrc"
    if [[ -e "$cache_path" ]]; then
      echo "refusing to overwrite recovery cache: $cache_path" >&2
      exit 2
    fi
    command+=(--cache "$cache_path")
  fi
  if [[ "$(uname -s)" == "Darwin" ]]; then
    /usr/bin/time -l "${command[@]}"
  else
    /usr/bin/time -v "${command[@]}"
  fi
done
