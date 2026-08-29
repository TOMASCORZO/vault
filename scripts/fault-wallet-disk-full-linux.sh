#!/usr/bin/env bash
set -euo pipefail

disposable_root="${VAULT_H1_A2_DISK_FULL_ROOT:-}"
authorization="${VAULT_H1_A2_ALLOW_DISPOSABLE_VOLUME:-}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this acceptance harness requires Linux" >&2
  exit 2
fi
if [[ "$authorization" != "I_UNDERSTAND_THIS_CREATES_A_DISPOSABLE_FILESYSTEM" ]]; then
  echo "set VAULT_H1_A2_ALLOW_DISPOSABLE_VOLUME to the documented exact value" >&2
  exit 2
fi
if [[ -z "$disposable_root" || ! -d "$disposable_root" || ! -w "$disposable_root" ]]; then
  echo "VAULT_H1_A2_DISK_FULL_ROOT must name an existing writable directory" >&2
  exit 2
fi

disposable_root="$(realpath "$disposable_root")"
if [[ "$disposable_root" == "/" || "$disposable_root" != *vault-h1-a2-disk-full-* ]]; then
  echo "disposable root must be a dedicated path containing vault-h1-a2-disk-full-" >&2
  exit 2
fi
marker="$disposable_root/.vault-h1-a2-disposable-root"
if [[ ! -f "$marker" ]] || [[ "$(<"$marker")" != "vault-h1-a2-disposable-root-v1" ]]; then
  echo "disposable root marker is missing or invalid" >&2
  exit 2
fi

image="$disposable_root/wallet-fault-volume.ext4"
mount_dir="$disposable_root/mount"
evidence_log="$disposable_root/wallet-disk-full-run.log"
for artifact in "$image" "$mount_dir" "$evidence_log"; do
  if [[ -e "$artifact" ]]; then
    echo "refusing to overwrite disk-full artifact: $artifact" >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$repo_root/target/release/examples/h1_a2_wallet_fault"
mounted=0
cleanup_mount() {
  if (( mounted == 1 )); then
    sudo umount "$mount_dir" || true
  fi
}
trap cleanup_mount EXIT

uname -a | tee -a "$evidence_log"
rustc -Vv | tee -a "$evidence_log"
lsblk -o NAME,MODEL,SIZE,FSTYPE,MOUNTPOINTS | tee -a "$evidence_log"

cd "$repo_root"
cargo build --release --locked -p vault-wallet --example h1_a2_wallet_fault
truncate -s 256M "$image"
/sbin/mkfs.ext4 -q -F "$image"
mkdir "$mount_dir"
sudo mount -o loop,nosuid,nodev,noexec "$image" "$mount_dir"
mounted=1
sudo chown "$(id -u):$(id -g)" "$mount_dir"
chmod 0700 "$mount_dir"

"$binary" init --directory "$mount_dir" --max-checkpoints 100 | tee -a "$evidence_log"
"$binary" write-loop --directory "$mount_dir" --blocks 8 --actions-per-block 16 \
  | tee -a "$evidence_log"
"$binary" backup --directory "$mount_dir" | tee -a "$evidence_log"

filler="$mount_dir/disk-full-filler"
fill_volume() {
  local available_kib
  local fill_kib
  available_kib="$(df -Pk "$mount_dir" | awk 'NR == 2 {print $4}')"
  if (( available_kib <= 8 )); then
    echo "disposable volume has insufficient free space before filling" >&2
    exit 1
  fi
  fill_kib=$((available_kib - 4))
  fallocate -l "${fill_kib}K" "$filler"
  sync -f "$filler"
  df -Pk "$mount_dir" | tee -a "$evidence_log"
}
release_volume() {
  truncate -s 0 "$filler"
  sync -f "$filler"
}
expect_storage_failure() {
  local operation="$1"
  shift
  fill_volume
  set +e
  "$@" >>"$evidence_log" 2>&1
  local status=$?
  set -e
  release_volume
  if (( status == 0 )); then
    echo "$operation unexpectedly succeeded on the full volume" >&2
    exit 1
  fi
  echo "operation=$operation expected_failure_status=$status" | tee -a "$evidence_log"
}

expect_storage_failure commit \
  "$binary" write-loop --directory "$mount_dir" --blocks 1 --actions-per-block 16
"$binary" validate --directory "$mount_dir" | tee -a "$evidence_log"

expect_storage_failure backup \
  "$binary" backup-pressure --directory "$mount_dir"
if [[ -e "$mount_dir/wallet-fault-pressure.vwb" ]]; then
  echo "failed backup published a destination" >&2
  exit 1
fi
"$binary" validate --directory "$mount_dir" | tee -a "$evidence_log"

expect_storage_failure restore \
  "$binary" restore --directory "$mount_dir"
if [[ -e "$mount_dir/wallet-fault-restored.sqlite3" ]]; then
  echo "failed restore published a destination" >&2
  exit 1
fi
"$binary" validate --directory "$mount_dir" | tee -a "$evidence_log"

expect_storage_failure compact \
  "$binary" compact --directory "$mount_dir"
"$binary" validate --directory "$mount_dir" | tee -a "$evidence_log"
"$binary" compact --directory "$mount_dir" | tee -a "$evidence_log"
"$binary" write-loop --directory "$mount_dir" --blocks 1 --actions-per-block 16 \
  | tee -a "$evidence_log"
"$binary" validate --directory "$mount_dir" | tee -a "$evidence_log"
echo "disk_full_campaign_complete image=$image" | tee -a "$evidence_log"
