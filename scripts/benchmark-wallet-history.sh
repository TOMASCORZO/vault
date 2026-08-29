#!/usr/bin/env bash
set -euo pipefail

blocks="${1:-10000}"
max_checkpoints="${2:-100}"
actions_per_block="${3:-2}"
ownership="${4:-unrelated}"
work_dir="${VAULT_H1_A2_WALLET_WORK_DIR:-}"

if [[ -z "$work_dir" || ! -d "$work_dir" || ! -w "$work_dir" ]]; then
  echo "VAULT_H1_A2_WALLET_WORK_DIR must name an existing writable directory" >&2
  exit 2
fi
if [[ "$ownership" != "unrelated" && "$ownership" != "owned" ]]; then
  echo "ownership must be unrelated or owned" >&2
  exit 2
fi

for artifact in wallet-history.sqlite3 wallet-history.vwb wallet-history-copy.vwb; do
  if [[ -e "$work_dir/$artifact" ]]; then
    echo "refusing to overwrite wallet history artifact: $work_dir/$artifact" >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$repo_root/target/release/examples/h1_a2_wallet_history"

uname -a
rustc -Vv
df -h "$work_dir"
if [[ "$(uname -s)" == "Darwin" ]]; then
  sysctl -n machdep.cpu.brand_string
  sysctl -n hw.memsize
elif command -v lscpu >/dev/null 2>&1; then
  lscpu
fi

cd "$repo_root"
cargo build --release --locked -p vault-wallet --example h1_a2_wallet_history
command=(
  "$binary"
  --directory "$work_dir"
  --blocks "$blocks"
  --max-checkpoints "$max_checkpoints"
  --actions-per-block "$actions_per_block"
  --ownership "$ownership"
)
if [[ "$(uname -s)" == "Darwin" ]]; then
  /usr/bin/time -l "${command[@]}"
else
  /usr/bin/time -v "${command[@]}"
fi
