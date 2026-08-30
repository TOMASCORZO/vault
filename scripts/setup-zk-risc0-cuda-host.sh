#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "CUDA host setup failed: $*" >&2
  exit 1
}

[[ "$(uname -s)" == "Linux" ]] || fail "the setup requires Linux"
[[ "$(uname -m)" == "x86_64" ]] || fail "the setup requires x86_64"
command -v nvcc >/dev/null 2>&1 ||
  fail "choose a CUDA development image with nvcc already installed"
command -v nvidia-smi >/dev/null 2>&1 ||
  fail "the NVIDIA driver tools are not available"

if ((EUID == 0)); then
  package_command=()
else
  command -v sudo >/dev/null 2>&1 || fail "sudo is required for package installation"
  package_command=(sudo)
fi

"${package_command[@]}" apt-get update
"${package_command[@]}" apt-get install -y \
  build-essential \
  ca-certificates \
  clang \
  cmake \
  curl \
  git \
  libclang-dev \
  libssl-dev \
  ninja-build \
  pkg-config \
  protobuf-compiler \
  tmux

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
    sh -s -- -y --profile minimal
fi
export PATH="${HOME}/.cargo/bin:${PATH}"

rustup toolchain install 1.90.0 --profile minimal
if ! command -v rzup >/dev/null 2>&1 || [[ "$(rzup --version)" != "rzup 0.5.2" ]]; then
  cargo +1.90.0 install rzup --version 0.5.2 --locked --force
fi
if ! rzup show | grep -Eq '^\*?[[:space:]]*1\.97\.0$'; then
  rzup install rust 1.97.0
fi

echo "CUDA host tools installed:"
rustup run 1.90.0 rustc --version
cargo +1.90.0 --version
rzup --version
rzup show
nvcc --version | tail -n 1
nvidia-smi --query-gpu=index,name,memory.total,driver_version --format=csv,noheader
