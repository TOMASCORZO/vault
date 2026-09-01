#!/usr/bin/env bash
set -euo pipefail

export PATH="${HOME}/.cargo/bin:${PATH}"

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
host_toolchain="${VAULT_RISC0_HOST_TOOLCHAIN:-1.90.0}"
receipt_path="${1:-}"
expected_bytes="311977650"
expected_sha256="12c952e2da0466d7047586404b15c7ad6fa59675bb8c975019b4645dca7e6e96"

fail() {
  echo "RISC Zero C4 vector verification failed: $*" >&2
  exit 1
}

[[ -n "$receipt_path" ]] || fail "usage: $0 /absolute/path/vault-c1-transfer-v2.receipt.bin"
[[ "$receipt_path" == /* ]] || fail "receipt path must be absolute"
[[ -s "$receipt_path" ]] || fail "receipt does not exist or is empty: $receipt_path"
[[ -z "${RISC0_DEV_MODE+x}" ]] || fail "RISC0_DEV_MODE must be unset"

actual_bytes="$(wc -c < "$receipt_path" | tr -d '[:space:]')"
[[ "$actual_bytes" == "$expected_bytes" ]] || \
  fail "receipt size is $actual_bytes; expected $expected_bytes"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "$receipt_path" | awk '{ print $1 }')"
else
  actual_sha256="$(shasum -a 256 "$receipt_path" | awk '{ print $1 }')"
fi
[[ "$actual_sha256" == "$expected_sha256" ]] || \
  fail "receipt SHA-256 is $actual_sha256; expected $expected_sha256"

cd "$repository_root/zk/risc0"
export RISC0_SKIP_BUILD=1
VAULT_C4_RECEIPT_VERIFY_PATH="$receipt_path" \
  cargo +"$host_toolchain" test \
  --release \
  --offline \
  --locked \
  -p vault-zk-risc0 \
  --test transfer_v2_receipt \
  published_risc0_vector_verifies_offline_and_rejects_mutations \
  -- \
  --ignored \
  --exact \
  --nocapture

echo "RISC Zero C4 receipt accepted; public-input, proof-byte, and truncation mutations rejected."
echo "$actual_sha256  $receipt_path"
