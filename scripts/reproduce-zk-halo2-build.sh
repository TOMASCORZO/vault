#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
halo2_root="$repo_root/zk/halo2"
reproduction_root="$(mktemp -d "${TMPDIR:-/tmp}/vault-halo2-build.XXXXXX")"
keep_reproduction=0
stable_target="$reproduction_root/active-target"
cleanup() {
  if [[ "$keep_reproduction" -eq 1 ]]; then
    echo "mismatched artifacts retained at $reproduction_root" >&2
  else
    rm -rf -- "${reproduction_root:?}"
  fi
}
trap cleanup EXIT

build_once() {
  local label="$1"
  local target_dir="$reproduction_root/$label-target"
  local artifact_dir="$reproduction_root/$label-artifacts"
  mkdir -p "$artifact_dir" "$target_dir"
  ln -s "$target_dir" "$stable_target"

  CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR="$stable_target" \
  SOURCE_DATE_EPOCH=1787616000 \
  RUSTFLAGS="--remap-path-prefix=$repo_root=/workspace/vault" \
    cargo build --release --locked --offline -p vault-zk-halo2-core \
      --example setup_manifest

  local library
  library="$(find "$stable_target/release/deps" -maxdepth 1 -type f \
    -name 'libvault_zk_halo2_core-*.rlib' -print -quit)"
  if [[ -z "$library" ]]; then
    echo "selected Halo2 rlib was not produced" >&2
    exit 1
  fi
  cp "$library" "$artifact_dir/vault-zk-halo2-core.rlib"
  cp "$stable_target/release/examples/setup_manifest" "$artifact_dir/setup_manifest"
  mv "$stable_target" "$reproduction_root/$label-target-link"
}

cd "$halo2_root"
rustc -Vv
cargo -V
build_once first
build_once second

reproduced=1
for artifact in vault-zk-halo2-core.rlib setup_manifest; do
  first="$reproduction_root/first-artifacts/$artifact"
  second="$reproduction_root/second-artifacts/$artifact"
  if ! cmp "$first" "$second"; then
    reproduced=0
    keep_reproduction=1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$first" "$second"
  else
    shasum -a 256 "$first" "$second"
  fi
done

if [[ "$reproduced" -ne 1 ]]; then
  echo "selected Halo2 build artifacts are not yet byte-reproducible" >&2
  exit 1
fi
echo "selected Halo2 build artifacts reproduced byte-for-byte on two clean local target directories"
