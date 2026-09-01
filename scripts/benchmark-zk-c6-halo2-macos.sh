#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_directory="${VAULT_C6_OUTPUT_DIRECTORY:-$repository_root/target/c6-halo2-macos}"
repetitions="${VAULT_C6_REPETITIONS:-3}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This runner uses macOS /usr/bin/time -l; use declared macOS hardware."
  exit 1
fi
if [[ ! "$repetitions" =~ ^[0-9]+$ ]] || (( repetitions < 1 || repetitions > 20 )); then
  echo "VAULT_C6_REPETITIONS must be an integer from 1 through 20."
  exit 1
fi

mkdir -p "$output_directory"
cd "$repository_root"

{
  date -u '+measured_at_utc=%Y-%m-%dT%H:%M:%SZ'
  git rev-parse 'HEAD'
  rustc --version
  cargo --version
  system_profiler SPHardwareDataType | \
    sed -E '/Serial Number|Hardware UUID|Provisioning UDID|Activation Lock/d'
  sw_vers
} >"$output_directory/environment.txt"

for bucket in 2 4 8 16; do
  log="$output_directory/halo2-bucket-$bucket.log"
  time_log="$output_directory/halo2-bucket-$bucket.time.txt"
  VAULT_C6_BUCKET="$bucket" VAULT_C6_REPETITIONS="$repetitions" \
    /usr/bin/time -l -o "$time_log" \
    cargo test --release --manifest-path zk/halo2/Cargo.toml \
      -p vault-zk-halo2-core c6_halo2_bucket_benchmark --locked -- \
      --ignored --nocapture 2>&1 | tee "$log"
done

{
  echo 'backend,bucket,repetition,keygen_ms,prove_ms,verify_us,proof_bytes,peak_rss_bytes'
  for bucket in 2 4 8 16; do
    peak_rss="$(awk '/maximum resident set size/ {print $1}' \
      "$output_directory/halo2-bucket-$bucket.time.txt")"
    sed -n 's/^.*VAULT_C6_METRIC /VAULT_C6_METRIC /p' \
      "$output_directory/halo2-bucket-$bucket.log" | \
      awk -v rss="$peak_rss" '{
        for (i = 2; i <= NF; i++) {
          split($i, value, "="); fields[value[1]] = value[2]
        }
        print fields["backend"] "," fields["bucket"] "," fields["repetition"] "," \
          fields["keygen_ms"] "," fields["prove_ms"] "," fields["verify_us"] "," \
          fields["proof_bytes"] "," rss
        delete fields
      }'
  done
} >"$output_directory/measurements.csv"

echo "C6 Halo2 evidence written to $output_directory"
