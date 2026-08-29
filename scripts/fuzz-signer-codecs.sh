#!/usr/bin/env bash
set -euo pipefail

seconds="${1:-300}"
toolchain="${VAULT_H1_A3_FUZZ_TOOLCHAIN:-nightly-2026-08-20}"
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
  echo "missing $expected_cargo_fuzz" >&2
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
run_corpus="$(mktemp -d "${TMPDIR:-/tmp}/vault-h1-a3-fuzz.XXXXXX")"
trap 'rm -rf "$run_corpus"' EXIT

uname -a
rustc "+$toolchain" -Vv
echo "$cargo_fuzz_version"
echo "target=signer_codec_decode seconds=$seconds max_len=65536 rss_limit_mb=4096 timeout_seconds=10"
echo "ephemeral_corpus=$run_corpus"

cd "$fuzz_root"
cargo "+$toolchain" fetch --locked
CARGO_NET_OFFLINE=true cargo "+$toolchain" fuzz run signer_codec_decode "$run_corpus" -- \
  "-max_total_time=$seconds" \
  -max_len=65536 \
  -rss_limit_mb=4096 \
  -timeout=10 \
  -print_final_stats=1
