#!/usr/bin/env bash
set -euo pipefail

export PATH="${HOME}/.cargo/bin:${PATH}"

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
host_toolchain="${VAULT_RISC0_HOST_TOOLCHAIN:-1.90.0}"
receipt_path="${1:-}"

[[ -n "$receipt_path" ]] || {
  echo "usage: $0 /absolute/path/vault-c1-transfer-v2.receipt.bin" >&2
  exit 1
}
[[ "$receipt_path" == /* ]] || {
  echo "receipt path must be absolute" >&2
  exit 1
}
[[ -s "$receipt_path" ]] || {
  echo "receipt does not exist or is empty: $receipt_path" >&2
  exit 1
}
[[ -z "${RISC0_DEV_MODE+x}" ]] || {
  echo "RISC0_DEV_MODE must be unset" >&2
  exit 1
}

VAULT_RISC0_HOST_TOOLCHAIN="$host_toolchain" \
  exec "$repository_root/scripts/verify-zk-risc0-c4-vector.sh" "$receipt_path"
