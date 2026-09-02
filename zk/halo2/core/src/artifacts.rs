//! Canonical integrity envelope for Vault's transparent Halo2 parameters.
//!
//! `halo2_proofs` 0.3.5 exposes stable parameter serialization, but not public
//! VK/PK serialization. This module therefore persists only the transparent
//! parameters and does not pretend that deterministic VK/PK derivation is a
//! cold load. The latter remains an explicit A4 release-engineering gate.

use std::{
    fs::File,
    io::{self, Cursor, Read},
    path::Path,
};

use halo2_proofs::{pasta::EqAffine, poly::commitment::Params};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::transfer_circuit::{MONOLITHIC_TRANSFER_SUITE_ID, VAULT_TRANSFER_K};

const PARAMETER_MAGIC: [u8; 8] = *b"VHPRM001";
const PARAMETER_VERSION: u16 = 1;
const PARAMETER_HEADER_BYTES: usize = 8 + 2 + 4 + 32 + 8 + 32;

/// Canonical byte length of `Params<EqAffine>` at the reviewed `k = 15`.
pub const VAULT_TRANSFER_PARAMETER_PAYLOAD_BYTES: usize =
    4 + (((1_usize << VAULT_TRANSFER_K) * 2 + 2) * 32);

/// SHA-256 of the canonical deterministic `Params<EqAffine>::new(15)` bytes.
///
/// This value is filled from the locked dependency implementation and checked
/// by the reproduction test below.
pub const VAULT_TRANSFER_PARAMETER_PAYLOAD_SHA256: [u8; 32] = [
    0xe1, 0xfb, 0x29, 0x74, 0x9c, 0x7b, 0xd0, 0x87, 0x07, 0x68, 0x04, 0x4d, 0x53, 0x29, 0xb4, 0xe2,
    0x93, 0xcb, 0x2d, 0x44, 0xda, 0xe2, 0x4d, 0xb2, 0x55, 0x46, 0x05, 0x42, 0x7b, 0x19, 0xd0, 0xdd,
];

/// Complete canonical parameter artifact length, including its fixed header.
pub const VAULT_TRANSFER_PARAMETER_ARTIFACT_BYTES: usize =
    PARAMETER_HEADER_BYTES + VAULT_TRANSFER_PARAMETER_PAYLOAD_BYTES;

/// Fail-closed parameter artifact parsing or generation failure.
#[derive(Debug, Error)]
pub enum VaultParameterArtifactError {
    /// The artifact length differs from the single reviewed shape.
    #[error("non-canonical Vault parameter artifact length")]
    Length,
    /// The artifact magic or format version is unknown.
    #[error("unknown Vault parameter artifact format")]
    Format,
    /// The artifact names another circuit suite or degree.
    #[error("Vault parameter artifact suite mismatch")]
    Suite,
    /// The payload digest differs from the approved deterministic parameters.
    #[error("Vault parameter artifact digest mismatch")]
    Digest,
    /// The bounded artifact could not be read or Halo2 rejected its payload.
    #[error("Vault parameter artifact I/O or decoding failed: {0}")]
    Io(#[source] io::Error),
}

/// Integrity-checked transparent parameters for the monolithic transfer suite.
#[derive(Debug)]
pub struct VaultTransferParameters(Params<EqAffine>);

impl VaultTransferParameters {
    /// Returns the loaded parameters to the pinned Halo2 prover or verifier.
    #[must_use]
    pub fn params(&self) -> &Params<EqAffine> {
        &self.0
    }

    /// Loads one exact-size artifact without allocating from untrusted length
    /// fields. A concurrent truncation or extension also fails closed.
    pub fn load_artifact_file(path: impl AsRef<Path>) -> Result<Self, VaultParameterArtifactError> {
        let mut file = File::open(path).map_err(VaultParameterArtifactError::Io)?;
        let length = file
            .metadata()
            .map_err(VaultParameterArtifactError::Io)?
            .len();
        if length != u64::try_from(VAULT_TRANSFER_PARAMETER_ARTIFACT_BYTES).expect("fits u64") {
            return Err(VaultParameterArtifactError::Length);
        }
        let mut artifact = vec![0; VAULT_TRANSFER_PARAMETER_ARTIFACT_BYTES];
        match file.read_exact(&mut artifact) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(VaultParameterArtifactError::Length);
            }
            Err(error) => return Err(VaultParameterArtifactError::Io(error)),
        }
        let mut trailing = [0];
        if file
            .read(&mut trailing)
            .map_err(VaultParameterArtifactError::Io)?
            != 0
        {
            return Err(VaultParameterArtifactError::Length);
        }
        Self::load_artifact(&artifact)
    }

    /// Deterministically derives and serializes the approved parameter artifact.
    pub fn derive_artifact() -> Result<Vec<u8>, VaultParameterArtifactError> {
        let params = Params::<EqAffine>::new(VAULT_TRANSFER_K);
        let payload = serialize_params(&params)?;
        if payload.len() != VAULT_TRANSFER_PARAMETER_PAYLOAD_BYTES
            || sha256(&payload) != VAULT_TRANSFER_PARAMETER_PAYLOAD_SHA256
        {
            return Err(VaultParameterArtifactError::Digest);
        }

        let mut artifact = Vec::with_capacity(VAULT_TRANSFER_PARAMETER_ARTIFACT_BYTES);
        artifact.extend_from_slice(&PARAMETER_MAGIC);
        artifact.extend_from_slice(&PARAMETER_VERSION.to_le_bytes());
        artifact.extend_from_slice(&VAULT_TRANSFER_K.to_le_bytes());
        artifact.extend_from_slice(&MONOLITHIC_TRANSFER_SUITE_ID);
        artifact.extend_from_slice(
            &u64::try_from(payload.len())
                .expect("parameter payload length fits u64")
                .to_le_bytes(),
        );
        artifact.extend_from_slice(&VAULT_TRANSFER_PARAMETER_PAYLOAD_SHA256);
        artifact.extend_from_slice(&payload);
        Ok(artifact)
    }

    /// Loads parameters only after checking every bounded framing and integrity
    /// field against the compile-time approved suite.
    pub fn load_artifact(bytes: &[u8]) -> Result<Self, VaultParameterArtifactError> {
        if bytes.len() != VAULT_TRANSFER_PARAMETER_ARTIFACT_BYTES {
            return Err(VaultParameterArtifactError::Length);
        }

        let mut offset = 0;
        if take::<8>(bytes, &mut offset)? != PARAMETER_MAGIC
            || u16::from_le_bytes(take(bytes, &mut offset)?) != PARAMETER_VERSION
        {
            return Err(VaultParameterArtifactError::Format);
        }
        if u32::from_le_bytes(take(bytes, &mut offset)?) != VAULT_TRANSFER_K
            || take::<32>(bytes, &mut offset)? != MONOLITHIC_TRANSFER_SUITE_ID
        {
            return Err(VaultParameterArtifactError::Suite);
        }
        if usize::try_from(u64::from_le_bytes(take(bytes, &mut offset)?)).ok()
            != Some(VAULT_TRANSFER_PARAMETER_PAYLOAD_BYTES)
        {
            return Err(VaultParameterArtifactError::Length);
        }
        if take::<32>(bytes, &mut offset)? != VAULT_TRANSFER_PARAMETER_PAYLOAD_SHA256 {
            return Err(VaultParameterArtifactError::Digest);
        }

        let payload = &bytes[offset..];
        if sha256(payload) != VAULT_TRANSFER_PARAMETER_PAYLOAD_SHA256 {
            return Err(VaultParameterArtifactError::Digest);
        }
        let mut reader = Cursor::new(payload);
        let params =
            Params::<EqAffine>::read(&mut reader).map_err(VaultParameterArtifactError::Io)?;
        if params.k() != VAULT_TRANSFER_K
            || usize::try_from(reader.position()).ok() != Some(payload.len())
        {
            return Err(VaultParameterArtifactError::Suite);
        }
        Ok(Self(params))
    }
}

fn serialize_params(params: &Params<EqAffine>) -> Result<Vec<u8>, VaultParameterArtifactError> {
    let mut payload = Vec::with_capacity(VAULT_TRANSFER_PARAMETER_PAYLOAD_BYTES);
    params
        .write(&mut payload)
        .map_err(VaultParameterArtifactError::Io)?;
    Ok(payload)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], VaultParameterArtifactError> {
    let end = offset
        .checked_add(N)
        .ok_or(VaultParameterArtifactError::Length)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(VaultParameterArtifactError::Length)?
        .try_into()
        .map_err(|_| VaultParameterArtifactError::Length)?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, io::Write, time::Instant};

    use super::*;

    #[test]
    fn parameter_artifact_round_trip_and_mutations_fail_closed() {
        let derive_started = Instant::now();
        let artifact = VaultTransferParameters::derive_artifact().unwrap();
        let derive_elapsed = derive_started.elapsed();
        assert_eq!(artifact.len(), VAULT_TRANSFER_PARAMETER_ARTIFACT_BYTES);

        let load_started = Instant::now();
        let loaded = VaultTransferParameters::load_artifact(&artifact).unwrap();
        let load_elapsed = load_started.elapsed();
        assert_eq!(loaded.params().k(), VAULT_TRANSFER_K);
        assert_eq!(
            serialize_params(loaded.params()).unwrap(),
            artifact[PARAMETER_HEADER_BYTES..]
        );

        assert!(matches!(
            VaultTransferParameters::load_artifact(&artifact[..artifact.len() - 1]),
            Err(VaultParameterArtifactError::Length)
        ));
        let mut trailing = artifact.clone();
        trailing.push(0);
        assert!(matches!(
            VaultTransferParameters::load_artifact(&trailing),
            Err(VaultParameterArtifactError::Length)
        ));

        for offset in [0, 8] {
            let mut mutated = artifact.clone();
            mutated[offset] ^= 1;
            assert!(matches!(
                VaultTransferParameters::load_artifact(&mutated),
                Err(VaultParameterArtifactError::Format)
            ));
        }
        for offset in [10, 14] {
            let mut mutated = artifact.clone();
            mutated[offset] ^= 1;
            assert!(matches!(
                VaultTransferParameters::load_artifact(&mutated),
                Err(VaultParameterArtifactError::Suite)
            ));
        }
        let mut wrong_length = artifact.clone();
        wrong_length[46] ^= 1;
        assert!(matches!(
            VaultTransferParameters::load_artifact(&wrong_length),
            Err(VaultParameterArtifactError::Length)
        ));
        for offset in [54, PARAMETER_HEADER_BYTES] {
            let mut mutated = artifact.clone();
            mutated[offset] ^= 1;
            assert!(matches!(
                VaultTransferParameters::load_artifact(&mutated),
                Err(VaultParameterArtifactError::Digest)
            ));
        }

        eprintln!(
            "VAULT_A4_PARAMETER_METRIC derive_ms={} load_ms={} artifact_bytes={}",
            derive_elapsed.as_millis(),
            load_elapsed.as_millis(),
            artifact.len()
        );
    }

    #[test]
    #[ignore = "A4 parameter persistence benchmark runs only through its script"]
    fn a4_parameter_artifact_file_benchmark() {
        let mode = std::env::var("VAULT_A4_PARAMETER_MODE")
            .expect("VAULT_A4_PARAMETER_MODE must be derive or load");
        let path = std::env::var_os("VAULT_A4_PARAMETER_PATH")
            .expect("VAULT_A4_PARAMETER_PATH is required");
        match mode.as_str() {
            "derive" => {
                let started = Instant::now();
                let artifact = VaultTransferParameters::derive_artifact().unwrap();
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .unwrap();
                file.write_all(&artifact).unwrap();
                file.sync_all().unwrap();
                eprintln!(
                    "VAULT_A4_PARAMETER_FILE_METRIC mode=derive elapsed_us={} artifact_bytes={}",
                    started.elapsed().as_micros(),
                    artifact.len()
                );
            }
            "load" => {
                let started = Instant::now();
                let loaded = VaultTransferParameters::load_artifact_file(&path).unwrap();
                assert_eq!(loaded.params().k(), VAULT_TRANSFER_K);
                eprintln!(
                    "VAULT_A4_PARAMETER_FILE_METRIC mode=load elapsed_us={} artifact_bytes={}",
                    started.elapsed().as_micros(),
                    VAULT_TRANSFER_PARAMETER_ARTIFACT_BYTES
                );
            }
            _ => panic!("VAULT_A4_PARAMETER_MODE must be derive or load"),
        }
    }
}
