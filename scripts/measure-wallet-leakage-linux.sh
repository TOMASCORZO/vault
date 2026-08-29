#!/usr/bin/env bash
set -euo pipefail

blocks="${1:-10000}"
repetitions="${2:-5}"
max_checkpoints="${3:-100}"
measurement_root="${VAULT_H1_A2_WALLET_LEAKAGE_ROOT:-}"
measurement_cpu="${VAULT_H1_A2_MEASUREMENT_CPU:-2}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this acceptance harness requires Linux perf" >&2
  exit 2
fi
if ! command -v perf >/dev/null 2>&1 || ! command -v taskset >/dev/null 2>&1; then
  echo "perf and taskset are required" >&2
  exit 2
fi
if [[ ! "$blocks" =~ ^[1-9][0-9]*$ ]] || (( blocks > 1000000 )); then
  echo "blocks must be in 1..1000000" >&2
  exit 2
fi
if [[ ! "$repetitions" =~ ^[1-9][0-9]*$ ]] || (( repetitions > 20 )); then
  echo "repetitions must be in 1..20" >&2
  exit 2
fi
if [[ ! "$max_checkpoints" =~ ^[1-9][0-9]*$ ]] || (( max_checkpoints > 4096 )); then
  echo "maximum checkpoints must be in 1..4096" >&2
  exit 2
fi
if [[ ! "$measurement_cpu" =~ ^[0-9]+$ ]]; then
  echo "measurement CPU must be a non-negative integer" >&2
  exit 2
fi
if [[ -z "$measurement_root" || ! -d "$measurement_root" || ! -w "$measurement_root" ]]; then
  echo "VAULT_H1_A2_WALLET_LEAKAGE_ROOT must name an existing writable directory" >&2
  exit 2
fi

measurement_root="$(realpath "$measurement_root")"
environment_log="$measurement_root/environment.log"
manifest="$measurement_root/measurement-manifest.tsv"
if [[ -e "$environment_log" || -e "$manifest" ]]; then
  echo "refusing to overwrite leakage evidence" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$repo_root/target/release/examples/h1_a2_wallet_history"

uname -a | tee -a "$environment_log"
rustc -Vv | tee -a "$environment_log"
lscpu | tee -a "$environment_log"
df -h "$measurement_root" | tee -a "$environment_log"
cat /proc/sys/kernel/perf_event_paranoid | tee -a "$environment_log"

cd "$repo_root"
cargo build --release --locked -p vault-wallet --example h1_a2_wallet_history
printf 'run\trepetition\townership\tactions\tblocks\tcpu\tdirectory\n' >"$manifest"

profiles=(
  "unrelated 2"
  "owned 2"
  "unrelated 16"
  "owned 16"
)
for ((repetition = 1; repetition <= repetitions; repetition++)); do
  for profile in "${profiles[@]}"; do
    read -r ownership actions_per_block <<<"$profile"
    run="r${repetition}-${ownership}-a${actions_per_block}"
    run_dir="$measurement_root/$run"
    if [[ -e "$run_dir" ]]; then
      echo "refusing to overwrite measurement directory: $run_dir" >&2
      exit 2
    fi
    mkdir "$run_dir"
    chmod 0700 "$run_dir"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$run" "$repetition" "$ownership" "$actions_per_block" "$blocks" \
      "$measurement_cpu" "$run_dir" >>"$manifest"
    /usr/bin/time -v \
      perf stat -x, -o "$run_dir/perf.csv" \
        -e task-clock,cycles,instructions,cache-references,cache-misses,page-faults,context-switches \
        -- taskset -c "$measurement_cpu" "$binary" \
          --directory "$run_dir" \
          --blocks "$blocks" \
          --max-checkpoints "$max_checkpoints" \
          --actions-per-block "$actions_per_block" \
          --ownership "$ownership" >"$run_dir/run.log" 2>&1
  done
done

echo "wallet_leakage_campaign_complete runs=$((repetitions * 4))" \
  | tee -a "$environment_log"
