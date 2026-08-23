#!/usr/bin/env bash
set -uo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failed=0

cd "$repository_root/zk/risc0"
cargo audit --file Cargo.lock || failed=1

cd "$repository_root/zk/risc0/methods/guest"
cargo audit --file Cargo.lock || failed=1

exit "$failed"

