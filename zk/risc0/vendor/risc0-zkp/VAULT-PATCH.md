# Vault patch to risc0-zkp 3.0.5

Source: the `risc0-zkp` 3.0.5 crate selected internally by `risc0-zkvm`
3.0.6 and published by RISC Zero under Apache-2.0.

Vault makes the crate's existing `metal` feature control both inclusion of the
Metal HAL and lookup of its compiled asset. Upstream performs both operations
for every Apple Silicon proof build, even while its circuit crates select the
CPU prover and their Metal prover paths are disabled.

No CPU HAL, proof algorithm, verifier, circuit, generated constant, security
parameter, or receipt format is modified.
