#!/usr/bin/env bash
set -euo pipefail

profile="${1:-common}"
samples="${2:-5}"
block_size="${3:-32}"

if [[ "$profile" != "common" && "$profile" != "balanced" && "$profile" != "max-heavy" ]]; then
  echo "usage: $0 [common|balanced|max-heavy] [samples] [block-size]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
halo2_root="$repo_root/zk/halo2"
benchmark_binary="$halo2_root/target/release/examples/h1_a1_heterogeneous_validator"

uname -a
rustc -Vv
if [[ "$(uname -s)" == "Darwin" ]]; then
  sysctl -n machdep.cpu.brand_string
  sysctl -n hw.memsize
elif command -v lscpu >/dev/null 2>&1; then
  lscpu
fi

cd "$halo2_root"
cargo build --release --locked -p vault-zk-halo2-core \
  --example h1_a1_heterogeneous_validator

command=(
  "$benchmark_binary"
  --profile "$profile"
  --samples "$samples"
  --block-size "$block_size"
)
if [[ "$(uname -s)" == "Darwin" ]]; then
  /usr/bin/time -l "${command[@]}"
else
  /usr/bin/time -v "${command[@]}"
fi
