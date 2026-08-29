#!/usr/bin/env bash
set -euo pipefail

seconds="${1:-300}"
toolchain="${VAULT_H1_A1_FUZZ_TOOLCHAIN:-nightly-2026-08-20}"
expected_cargo_fuzz="cargo-fuzz 0.13.2"

if [[ ! "$seconds" =~ ^[1-9][0-9]*$ ]] || (( seconds > 604800 )); then
  echo "usage: $0 [seconds: 1..604800]" >&2
  exit 2
fi

if ! rustup toolchain list | grep -Eq "^${toolchain}(-|[[:space:]])"; then
  echo "missing pinned fuzz toolchain: $toolchain" >&2
  echo "install it explicitly with: rustup toolchain install $toolchain --profile minimal" >&2
  exit 1
fi

if ! cargo_fuzz_version="$(cargo fuzz --version 2>/dev/null)"; then
  echo "missing cargo-fuzz $expected_cargo_fuzz" >&2
  echo "install it explicitly with: cargo install cargo-fuzz --version 0.13.2 --locked" >&2
  exit 1
fi
if [[ "$cargo_fuzz_version" != "$expected_cargo_fuzz" ]]; then
  echo "unexpected cargo-fuzz version: $cargo_fuzz_version" >&2
  echo "required: $expected_cargo_fuzz" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_root="$repo_root/zk/halo2/fuzz"

uname -a
rustc "+$toolchain" -Vv
echo "$cargo_fuzz_version"
echo "target=composite_transfer_proof_decode seconds=$seconds max_len=16384 rss_limit_mb=4096 timeout_seconds=10"

cd "$fuzz_root"
cargo "+$toolchain" fetch --locked
CARGO_NET_OFFLINE=true cargo "+$toolchain" fuzz run composite_transfer_proof_decode -- \
  "-max_total_time=$seconds" \
  -max_len=16384 \
  -rss_limit_mb=4096 \
  -timeout=10 \
  -print_final_stats=1
