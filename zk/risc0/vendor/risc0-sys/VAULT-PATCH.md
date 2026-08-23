# Vault patch to risc0-sys 1.5.0

Source: the `risc0-sys` 1.5.0 crate published by RISC Zero under Apache-2.0.

Vault changes one build-script condition: Metal kernel compilation on macOS is
now gated by the crate's existing `metal` feature. Upstream 1.5.0 otherwise
invokes `xcrun metal` even when that feature is disabled. No Rust library,
cryptographic circuit, CPU kernel, generated constant, or protocol parameter is
modified.

The companion patch to `risc0-zkp` gates inclusion of its Metal HAL the same
way. Both patches must be removed and this backend re-benchmarked when an
upstream release fixes the unconditional Metal build.
