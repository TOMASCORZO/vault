#!/usr/bin/env bash
set -euo pipefail

a3_repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
a3_committed_dir="$a3_repo_dir/docs/specs/test-vectors/h1-a3-v1"
a3_tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/vault-h1-a3-corpus.XXXXXX")"
trap 'rm -rf -- "$a3_tmp_dir"' EXIT

cargo run \
  --manifest-path "$a3_repo_dir/zk/halo2/Cargo.toml" \
  -p vault-zk-halo2-core \
  --example generate_h1_a3_corpus \
  -- "$a3_tmp_dir"

diff -ru -- "$a3_committed_dir" "$a3_tmp_dir"
echo "H1-A3 corpus reproduced byte-for-byte."
