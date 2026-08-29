#!/usr/bin/env bash
set -euo pipefail

iterations="${1:-100}"
if [[ ! "$iterations" =~ ^[1-9][0-9]*$ ]] || (( iterations > 10000 )); then
  echo "usage: $0 [iterations: 1..10000]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command=(
  cargo run --release
  --manifest-path "$repo_root/zk/halo2/Cargo.toml"
  -p vault-zk-halo2-core
  --example h1_a3_codec_benchmark
  -- "$iterations"
)

uname -a
rustc -Vv
echo "iterations=$iterations max_iterations=10000"
if [[ "$(uname -s)" == "Darwin" ]]; then
  /usr/bin/time -l "${command[@]}"
elif [[ -x /usr/bin/time ]]; then
  /usr/bin/time -v "${command[@]}"
else
  time "${command[@]}"
fi
