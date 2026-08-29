#!/usr/bin/env bash
set -euo pipefail

mode="${1:-verify}"
samples="${2:-5}"
batch_size="${3:-8}"
shift "$(( $# < 3 ? $# : 3 ))"

if [[ "$mode" != "verify" && "$mode" != "prove" ]]; then
  echo "usage: $0 [verify|prove] [samples] [batch-size] [2 4 8 16]" >&2
  exit 2
fi

buckets=("$@")
if [[ "${#buckets[@]}" -eq 0 ]]; then
  buckets=(2 4 8 16)
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
halo2_root="$repo_root/zk/halo2"
benchmark_binary="$halo2_root/target/release/examples/h1_a1_benchmark"

uname -a
rustc -Vv
if [[ "$(uname -s)" == "Darwin" ]]; then
  sysctl -n machdep.cpu.brand_string
  sysctl -n hw.memsize
elif command -v lscpu >/dev/null 2>&1; then
  lscpu
fi

cd "$halo2_root"
cargo build --release --locked -p vault-zk-halo2-core --example h1_a1_benchmark

for bucket in "${buckets[@]}"; do
  command=(
    "$benchmark_binary"
    --bucket "$bucket"
    --samples "$samples"
    --batch-size "$batch_size"
  )
  if [[ "$mode" == "prove" ]]; then
    command+=(--prove)
  fi
  if [[ "$(uname -s)" == "Darwin" ]]; then
    /usr/bin/time -l "${command[@]}"
  else
    /usr/bin/time -v "${command[@]}"
  fi
done
