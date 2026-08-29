#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "cargo-audit is required: cargo install cargo-audit --locked" >&2
  exit 1
fi

expected_audit_version="cargo-audit-audit 0.22.2"
actual_audit_version="$(cargo audit --version)"
if [[ "${actual_audit_version}" != "${expected_audit_version}" ]]; then
  echo "expected ${expected_audit_version}, found ${actual_audit_version}" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

audit_args=(
  --deny warnings
  --ignore RUSTSEC-2023-0089
)

if [[ "${VAULT_AUDIT_OFFLINE:-0}" == "1" ]]; then
  audit_args+=(--no-fetch --stale)
fi

audit_workspace() {
  local label="$1"
  local manifest="$2"
  local lockfile="$3"
  local active_graph

  echo "Auditing ${label} (${lockfile})"
  cargo audit "${audit_args[@]}" --file "${lockfile}"

  if ! active_graph="$(
    cargo tree \
      --locked \
      --manifest-path "${manifest}" \
      --target all \
      --edges all \
      -i atomic-polyfill \
      2>/dev/null
  )"; then
    echo "failed to inspect the active dependency graph for ${label}" >&2
    exit 1
  fi

  if [[ -n "${active_graph}" ]]; then
    echo "RUSTSEC-2023-0089 is allowed only while atomic-polyfill is inactive" >&2
    echo "${active_graph}" >&2
    exit 1
  fi

  echo "${label}: no known vulnerability or non-allowlisted warning; atomic-polyfill inactive"
}

audit_workspace "root workspace" "Cargo.toml" "Cargo.lock"
audit_workspace "Halo2 release workspace" "zk/halo2/Cargo.toml" "zk/halo2/Cargo.lock"
audit_workspace "Halo2 fuzz workspace" "zk/halo2/fuzz/Cargo.toml" "zk/halo2/fuzz/Cargo.lock"
