#!/usr/bin/env bash
set -euo pipefail

# Read-only preflight for the single owned H1 acceptance host. This script does
# not build, fuzz, mount, format, fill, or delete anything.

minimum_cpus=16
minimum_memory_bytes=$((64 * 1024 * 1024 * 1024))
minimum_disk_bytes=500000000000
recommended_free_bytes=400000000000
expected_fuzz_toolchain="nightly-2026-08-20"
expected_cargo_fuzz="cargo-fuzz 0.13.2"
expected_cargo_audit="cargo-audit-audit 0.22.2"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
acceptance_root="${VAULT_H1_ACCEPTANCE_ROOT:-$repo_root}"
machine_id="${VAULT_H1_ACCEPTANCE_MACHINE_ID:-}"
failures=0
warnings=0

pass() {
  echo "PASS $*"
}

fail() {
  echo "FAIL $*" >&2
  failures=$((failures + 1))
}

warn() {
  echo "WARN $*" >&2
  warnings=$((warnings + 1))
}

require_command() {
  local command_name="$1"
  if command -v "$command_name" >/dev/null 2>&1; then
    pass "command=$command_name path=$(command -v "$command_name")"
  else
    fail "missing_command=$command_name"
  fi
}

echo "H1_ACCEPTANCE_PREFLIGHT_V1"
echo "safety=read-only"

if [[ "$machine_id" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
  pass "machine_id=$machine_id"
else
  fail "VAULT_H1_ACCEPTANCE_MACHINE_ID must match [A-Za-z0-9._-]{1,64}"
fi

if [[ -d "$acceptance_root" ]]; then
  acceptance_root="$(cd "$acceptance_root" && pwd -P)"
  pass "acceptance_root=$acceptance_root"
  if [[ -w "$acceptance_root" ]]; then
    pass "acceptance_root_writable=yes"
  else
    fail "acceptance_root_writable=no"
  fi
else
  fail "VAULT_H1_ACCEPTANCE_ROOT must name an existing directory"
fi

os_name="$(uname -s)"
architecture="$(uname -m)"
echo "observed_os=$os_name"
echo "observed_architecture=$architecture"
if [[ "$os_name" == "Linux" ]]; then
  pass "operating_system=Linux"
else
  fail "operating_system=$os_name required=Linux"
fi
if [[ "$architecture" == "x86_64" ]]; then
  pass "architecture=x86_64"
else
  fail "architecture=$architecture required=x86_64"
fi

cpu_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)"
echo "observed_logical_cpus=$cpu_count"
if [[ "$cpu_count" =~ ^[0-9]+$ ]] && (( cpu_count >= minimum_cpus )); then
  pass "logical_cpus=$cpu_count minimum=$minimum_cpus"
else
  fail "logical_cpus=$cpu_count minimum=$minimum_cpus"
fi

memory_bytes=0
if [[ -r /proc/meminfo ]]; then
  memory_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  if [[ "$memory_kib" =~ ^[0-9]+$ ]]; then
    memory_bytes=$((memory_kib * 1024))
  fi
elif command -v sysctl >/dev/null 2>&1; then
  memory_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
fi
echo "observed_memory_bytes=$memory_bytes"
if [[ "$memory_bytes" =~ ^[0-9]+$ ]] && (( memory_bytes >= minimum_memory_bytes )); then
  pass "memory_bytes=$memory_bytes minimum=$minimum_memory_bytes"
else
  fail "memory_bytes=$memory_bytes minimum=$minimum_memory_bytes"
fi

if [[ -d "$acceptance_root" ]]; then
  read -r filesystem_kib available_kib < <(
    df -Pk "$acceptance_root" | awk 'NR == 2 {print $2, $4}'
  )
  filesystem_bytes=$((filesystem_kib * 1024))
  available_bytes=$((available_kib * 1024))
  echo "observed_filesystem_bytes=$filesystem_bytes"
  echo "observed_available_bytes=$available_bytes"
  if (( filesystem_bytes >= minimum_disk_bytes )); then
    pass "filesystem_bytes=$filesystem_bytes minimum=$minimum_disk_bytes"
  else
    fail "filesystem_bytes=$filesystem_bytes minimum=$minimum_disk_bytes"
  fi
  if (( available_bytes >= recommended_free_bytes )); then
    pass "available_bytes=$available_bytes recommended=$recommended_free_bytes"
  else
    warn "available_bytes=$available_bytes recommended=$recommended_free_bytes"
  fi
fi

for command_name in \
  cargo rustc rustup git rg cargo-audit perf taskset lscpu lsblk realpath \
  truncate fallocate mount umount sudo; do
  require_command "$command_name"
done
if [[ -x /sbin/mkfs.ext4 ]]; then
  pass "command=mkfs.ext4 path=/sbin/mkfs.ext4"
else
  fail "missing_command=/sbin/mkfs.ext4"
fi
if [[ -x /usr/bin/time ]] && /usr/bin/time -v true >/dev/null 2>&1; then
  pass "gnu_time=/usr/bin/time"
else
  fail "gnu_time=/usr/bin/time must support -v"
fi

if [[ -e /dev/kvm ]]; then
  pass "hardware_virtualization=/dev/kvm"
else
  fail "hardware_virtualization=/dev/kvm missing"
fi

if rustup toolchain list 2>/dev/null | grep -Eq "^${expected_fuzz_toolchain}(-|[[:space:]])"; then
  pass "fuzz_toolchain=$expected_fuzz_toolchain"
else
  fail "fuzz_toolchain=$expected_fuzz_toolchain missing"
fi

actual_cargo_fuzz="$(cargo fuzz --version 2>/dev/null || true)"
if [[ "$actual_cargo_fuzz" == "$expected_cargo_fuzz" ]]; then
  pass "cargo_fuzz=$actual_cargo_fuzz"
else
  fail "cargo_fuzz=${actual_cargo_fuzz:-missing} expected=$expected_cargo_fuzz"
fi

actual_cargo_audit="$(cargo audit --version 2>/dev/null || true)"
if [[ "$actual_cargo_audit" == "$expected_cargo_audit" ]]; then
  pass "cargo_audit=$actual_cargo_audit"
else
  fail "cargo_audit=${actual_cargo_audit:-missing} expected=$expected_cargo_audit"
fi

if [[ "$os_name" == "Linux" ]] && \
  grep -Eq '(^|[[:space:]])(vmx|svm)($|[[:space:]])' /proc/cpuinfo 2>/dev/null; then
  pass "cpu_virtualization_flag=present"
elif [[ "$os_name" == "Linux" ]]; then
  fail "cpu_virtualization_flag=missing"
fi

echo "summary_failures=$failures"
echo "summary_warnings=$warnings"
if (( failures > 0 )); then
  echo "H1 acceptance host preflight failed; no acceptance workload was run." >&2
  exit 1
fi

echo "H1 acceptance host preflight passed; destructive campaigns still require their exact guards."
