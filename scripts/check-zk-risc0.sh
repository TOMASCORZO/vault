#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root/zk/risc0"

cargo fmt --all -- --check
cargo test --workspace --all-targets --locked

# Clippy's host rustc wrapper cannot compile the nested RISC-V guest standard
# library. The preceding test builds the real guest; these two static-analysis
# phases skip only ELF regeneration and never generate or verify a receipt.
RISC0_SKIP_BUILD=1 cargo clippy --workspace --all-targets --locked -- -D warnings
RISC0_SKIP_BUILD=1 RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
