#!/usr/bin/env bash
set -euo pipefail

iterations="${1:-100}"
actions_per_block="${2:-16}"
max_checkpoints="${3:-100}"
work_dir="${VAULT_H1_A2_WALLET_FAULT_DIR:-}"

if [[ ! "$iterations" =~ ^[1-9][0-9]*$ ]] || (( iterations > 10000 )); then
  echo "iterations must be in 1..10000" >&2
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
  echo "VAULT_H1_A2_WALLET_FAULT_DIR must name an existing writable directory" >&2
  exit 2
fi

database="$work_dir/wallet-fault.sqlite3"
journal="$database-journal"
run_log="$work_dir/wallet-fault-run.log"
for artifact in "$database" "$database.lock" "$journal" "$run_log"; do
  if [[ -e "$artifact" ]]; then
    echo "refusing to overwrite wallet fault artifact: $artifact" >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$repo_root/target/release/examples/h1_a2_wallet_fault"

uname -a | tee -a "$run_log"
rustc -Vv | tee -a "$run_log"
df -h "$work_dir" | tee -a "$run_log"
if [[ "$(uname -s)" == "Darwin" ]]; then
  sysctl -n machdep.cpu.brand_string | tee -a "$run_log"
  sysctl -n hw.memsize | tee -a "$run_log"
elif command -v lscpu >/dev/null 2>&1; then
  lscpu | tee -a "$run_log"
fi

cd "$repo_root"
cargo build --release --locked -p vault-wallet --example h1_a2_wallet_fault
"$binary" init --directory "$work_dir" --max-checkpoints "$max_checkpoints" \
  | tee -a "$run_log"

for ((attempt = 1; attempt <= iterations; attempt++)); do
  "$binary" write-loop --directory "$work_dir" --blocks 1000000 \
    --actions-per-block "$actions_per_block" >>"$run_log" 2>&1 &
  worker_pid=$!
  journal_observed=0
  for ((poll = 0; poll < 20000; poll++)); do
    if [[ -e "$journal" ]]; then
      journal_observed=1
      break
    fi
    if ! kill -0 "$worker_pid" 2>/dev/null; then
      break
    fi
    sleep 0.001
  done
  if (( journal_observed == 0 )); then
    kill -KILL "$worker_pid" 2>/dev/null || true
    wait "$worker_pid" 2>/dev/null || true
    echo "attempt $attempt did not observe an active rollback journal" >&2
    exit 1
  fi
  kill -KILL "$worker_pid"
  wait "$worker_pid" 2>/dev/null || true
  printf 'attempt=%s journal_observed=1 ' "$attempt" | tee -a "$run_log"
  "$binary" validate --directory "$work_dir" | tee -a "$run_log"
done

"$binary" write-loop --directory "$work_dir" --blocks 1 \
  --actions-per-block "$actions_per_block" | tee -a "$run_log"
"$binary" validate --directory "$work_dir" | tee -a "$run_log"
echo "process_crash_campaign_complete iterations=$iterations" | tee -a "$run_log"
