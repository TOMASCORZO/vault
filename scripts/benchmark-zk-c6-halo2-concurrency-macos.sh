#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_directory="${VAULT_C6_OUTPUT_DIRECTORY:-$repository_root/target/c6-halo2-concurrency-macos}"
bucket="${VAULT_C6_BUCKET:-16}"
workers="${VAULT_C6_WORKERS:-2}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This runner uses macOS /usr/bin/time -l; use declared macOS hardware."
  exit 1
fi
if [[ ! "$bucket" =~ ^(2|4|8|16)$ ]]; then
  echo "VAULT_C6_BUCKET must select 2, 4, 8, or 16."
  exit 1
fi
if [[ ! "$workers" =~ ^[0-9]+$ ]] || (( workers < 2 || workers > 8 )); then
  echo "VAULT_C6_WORKERS must be an integer from 2 through 8."
  exit 1
fi

mkdir -p "$output_directory"
cd "$repository_root"

started="$(date +%s)"
pids=()
for ((worker = 1; worker <= workers; worker++)); do
  (
    VAULT_C6_BUCKET="$bucket" VAULT_C6_REPETITIONS=1 \
      /usr/bin/time -l -o "$output_directory/worker-$worker.time.txt" \
      cargo test --release --manifest-path zk/halo2/Cargo.toml \
        -p vault-zk-halo2-core c6_halo2_bucket_benchmark --locked -- \
        --ignored --nocapture >"$output_directory/worker-$worker.log" 2>&1
  ) &
  pids+=("$!")
done
for pid in "${pids[@]}"; do
  wait "$pid"
done
finished="$(date +%s)"

{
  echo "backend=halo2"
  echo "bucket=$bucket"
  echo "workers=$workers"
  echo "wall_seconds=$((finished - started))"
  for ((worker = 1; worker <= workers; worker++)); do
    peak_rss="$(awk '/maximum resident set size/ {print $1}' \
      "$output_directory/worker-$worker.time.txt")"
    metric="$(sed -n 's/^.*VAULT_C6_METRIC /VAULT_C6_METRIC /p' \
      "$output_directory/worker-$worker.log")"
    echo "worker=$worker peak_rss_bytes=$peak_rss $metric"
  done
} >"$output_directory/concurrency.txt"

cat "$output_directory/concurrency.txt"
