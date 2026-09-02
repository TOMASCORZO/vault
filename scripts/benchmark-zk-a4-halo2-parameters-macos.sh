#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repetitions="${VAULT_A4_REPETITIONS:-3}"
[[ "$repetitions" =~ ^[1-9][0-9]*$ ]] || {
  echo "VAULT_A4_REPETITIONS must be a positive integer" >&2
  exit 1
}
((repetitions <= 20)) || {
  echo "VAULT_A4_REPETITIONS must not exceed 20" >&2
  exit 1
}

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/vault-a4-params.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
artifact_path="$temporary_directory/vault-halo2-transfer-params-v1.bin"

cd "$repository_root/zk/halo2"
echo "VAULT_A4_PARAMETER_HOST=$(uname -a)"
echo "VAULT_A4_PARAMETER_RUST=$(rustc --version)"
echo "VAULT_A4_PARAMETER_REPETITIONS=$repetitions"
VAULT_A4_PARAMETER_MODE=derive \
VAULT_A4_PARAMETER_PATH="$artifact_path" \
cargo test --release --locked -p vault-zk-halo2-core \
  artifacts::tests::a4_parameter_artifact_file_benchmark \
  -- --ignored --exact --nocapture

for repetition in $(seq 1 "$repetitions"); do
  echo "VAULT_A4_PARAMETER_REPETITION=$repetition"
  VAULT_A4_PARAMETER_MODE=load \
  VAULT_A4_PARAMETER_PATH="$artifact_path" \
  cargo test --release --locked -p vault-zk-halo2-core \
    artifacts::tests::a4_parameter_artifact_file_benchmark \
    -- --ignored --exact --nocapture
done
