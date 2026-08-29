#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
halo2_root="$repo_root/zk/halo2"
committed="$halo2_root/core/vectors/transfer-v2"
artifact_dir="$(mktemp -d "${TMPDIR:-/tmp}/vault-halo2-vectors.XXXXXX")"
trap 'rm -rf -- "${artifact_dir:?}"' EXIT

cd "$halo2_root"
cargo run --release --locked -p vault-zk-halo2-core \
  --example generate_transfer_vectors -- "$artifact_dir"

for bucket in 2 4 8 16; do
  expected="$committed/transfer-v2-$bucket.bin"
  reproduced="$artifact_dir/transfer-v2-$bucket.bin"
  cmp "$expected" "$reproduced"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$reproduced"
  else
    shasum -a 256 "$reproduced"
  fi
done

echo "all selected Halo2 vectors reproduced byte-for-byte"
