#!/usr/bin/env bash
set -euo pipefail

blocks="${1:-10000}"
actions_per_block="${2:-2}"
max_checkpoints="${3:-100}"
work_dir="${VAULT_H1_A2_MIGRATION_DIR:-}"

if [[ ! "$blocks" =~ ^[1-9][0-9]*$ ]] || (( blocks > 1000000 )); then
  echo "blocks must be in 1..1000000" >&2
  exit 2
fi
if [[ ! "$actions_per_block" =~ ^(2|4|8|16)$ ]]; then
  echo "actions per block must be 2, 4, 8, or 16" >&2
  exit 2
fi
if [[ ! "$max_checkpoints" =~ ^[1-9][0-9]*$ ]] || (( max_checkpoints > 4096 )); then
  echo "maximum checkpoints must be in 1..4096" >&2
  exit 2
fi
if [[ -z "$work_dir" || ! -d "$work_dir" || ! -w "$work_dir" ]]; then
  echo "VAULT_H1_A2_MIGRATION_DIR must name an existing writable directory" >&2
  exit 2
fi

for artifact in \
  wallet-migration.sqlite3 \
  wallet-migration.sqlite3.lock \
  wallet-migration-v1.vwb \
  wallet-migration-v1.vwb.lock \
  wallet-migration-restored.sqlite3 \
  wallet-migration-restored.sqlite3.lock; do
  if [[ -e "$work_dir/$artifact" ]]; then
    echo "refusing to overwrite migration artifact: $work_dir/$artifact" >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command=(
  cargo test --release --locked -p vault-wallet
  storage::tests::h1_a2_external_legacy_migration_campaign
  -- --ignored --exact --nocapture
)

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
cargo test --release --locked -p vault-wallet --no-run
export VAULT_H1_A2_MIGRATION_BLOCKS="$blocks"
export VAULT_H1_A2_MIGRATION_ACTIONS="$actions_per_block"
export VAULT_H1_A2_MIGRATION_CHECKPOINTS="$max_checkpoints"
if [[ "$(uname -s)" == "Darwin" ]]; then
  /usr/bin/time -l "${command[@]}"
else
  /usr/bin/time -v "${command[@]}"
fi
