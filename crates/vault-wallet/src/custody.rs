//! Typed, transient wallet-seed import and custody boundary.
//!
//! Seed material is never printable or clonable through this API. The recovery
//! package is an error-detecting offline interchange format, not encrypted
//! storage; callers must keep every exported copy inside an approved custody
//! ceremony. Platform keystores and hardware-backed custodians implement
//! [`WalletSeedCustodian`] without exposing raw seed bytes to recovery code.

use core::fmt;

use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::WalletRecoveryError;

const WALLET_SEED_PACKAGE_MAGIC: [u8; 8] = *b"VSEED001";
const WALLET_SEED_PACKAGE_CHECKSUM_DOMAIN: &str =
    "vault.wallet.seed-recovery-package-v1.2026-09-02";

/// Exact entropy bytes accepted by the version-1 Vault wallet-seed boundary.
pub const WALLET_SEED_ENTROPY_BYTES: usize = 32;
/// Exact bytes in a version-1 checksum-protected recovery package.
pub const WALLET_SEED_RECOVERY_PACKAGE_BYTES: usize =
    WALLET_SEED_PACKAGE_MAGIC.len() + WALLET_SEED_ENTROPY_BYTES + 32;

/// A malformed or unsafe wallet-seed recovery package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletSeedImportError {
    /// Length, version, checksum, or seed entropy was rejected.
    InvalidRecoveryPackage,
}

impl fmt::Display for WalletSeedImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("wallet seed recovery package is invalid")
    }
}

impl std::error::Error for WalletSeedImportError {}

/// Owned, transient 256-bit Vault wallet-seed material.
///
/// The value cannot be cloned, compared, formatted, or exported as a bare byte
/// slice. Its storage is zeroized on drop. Memory locking and crash-dump
/// exclusion remain platform-custodian requirements rather than properties of
/// this portable Rust value.
pub struct WalletSeedMaterial(Zeroizing<[u8; WALLET_SEED_ENTROPY_BYTES]>);

impl fmt::Debug for WalletSeedMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletSeedMaterial(REDACTED)")
    }
}

impl WalletSeedMaterial {
    /// Generates fresh nonzero 256-bit seed material from a cryptographic RNG.
    /// A zero result fails closed instead of hiding a defective RNG with retries.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, WalletSeedImportError> {
        let mut entropy = Zeroizing::new([0; WALLET_SEED_ENTROPY_BYTES]);
        rng.fill_bytes(entropy.as_mut());
        Self::from_custodian_entropy(entropy)
    }

    /// Accepts entropy already authenticated by an approved custodian.
    ///
    /// Interactive/file import must instead use [`Self::import_recovery_package`]
    /// so accidental mutations are detected before account derivation.
    pub fn from_custodian_entropy(
        entropy: Zeroizing<[u8; WALLET_SEED_ENTROPY_BYTES]>,
    ) -> Result<Self, WalletSeedImportError> {
        if bool::from(entropy.as_ref().ct_eq(&[0; WALLET_SEED_ENTROPY_BYTES])) {
            return Err(WalletSeedImportError::InvalidRecoveryPackage);
        }
        Ok(Self(entropy))
    }

    /// Imports and consumes one exact version-1 checksum-protected package.
    ///
    /// The supplied package buffer is zeroized on every return path.
    pub fn import_recovery_package(
        package: Zeroizing<Vec<u8>>,
    ) -> Result<Self, WalletSeedImportError> {
        if package.len() != WALLET_SEED_RECOVERY_PACKAGE_BYTES {
            return Err(WalletSeedImportError::InvalidRecoveryPackage);
        }
        let entropy_offset = WALLET_SEED_PACKAGE_MAGIC.len();
        let checksum_offset = entropy_offset + WALLET_SEED_ENTROPY_BYTES;
        if !bool::from(package[..entropy_offset].ct_eq(WALLET_SEED_PACKAGE_MAGIC.as_slice())) {
            return Err(WalletSeedImportError::InvalidRecoveryPackage);
        }
        let entropy = Zeroizing::new(
            package[entropy_offset..checksum_offset]
                .try_into()
                .map_err(|_| WalletSeedImportError::InvalidRecoveryPackage)?,
        );
        let expected_checksum = seed_package_checksum(&entropy);
        if !bool::from(package[checksum_offset..].ct_eq(&expected_checksum)) {
            return Err(WalletSeedImportError::InvalidRecoveryPackage);
        }
        Self::from_custodian_entropy(entropy)
    }

    /// Creates a zeroizing offline recovery package with mutation detection.
    ///
    /// The returned bytes contain the seed in plaintext. They must never be
    /// logged, sent to a network service, or persisted outside an approved
    /// offline custody medium.
    #[must_use]
    pub fn export_recovery_package(&self) -> Zeroizing<Vec<u8>> {
        let mut package = Zeroizing::new(Vec::with_capacity(WALLET_SEED_RECOVERY_PACKAGE_BYTES));
        package.extend_from_slice(&WALLET_SEED_PACKAGE_MAGIC);
        package.extend_from_slice(self.0.as_ref());
        package.extend_from_slice(&seed_package_checksum(&self.0));
        package
    }

    pub(crate) fn expose_for_derivation(&self) -> &[u8; WALLET_SEED_ENTROPY_BYTES] {
        &self.0
    }
}

fn seed_package_checksum(entropy: &[u8; WALLET_SEED_ENTROPY_BYTES]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(WALLET_SEED_PACKAGE_CHECKSUM_DOMAIN);
    hasher.update(&WALLET_SEED_PACKAGE_MAGIC);
    hasher.update(entropy);
    *hasher.finalize().as_bytes()
}

/// Custodian that lends seed access only for one scoped operation.
///
/// Implementations may unlock an OS keystore, hardware device, or separately
/// reviewed encrypted container. They must invoke the operation at most once,
/// retain custody themselves, and zeroize transient source buffers.
pub trait WalletSeedCustodian {
    /// Custodian-specific access failure, kept distinct from recovery failure.
    type Error;

    /// Runs one operation while the seed is available without returning it.
    fn use_seed<T>(
        &mut self,
        operation: impl FnOnce(&WalletSeedMaterial) -> T,
    ) -> Result<T, Self::Error>;
}

/// Failure to access a custodian or derive the bounded recovery account set.
pub enum WalletSeedCustodyError<CustodianError> {
    /// The external custodian refused or failed access.
    Custodian(CustodianError),
    /// Wallet recovery rejected the requested account derivation.
    Recovery(WalletRecoveryError),
}

impl<CustodianError> fmt::Debug for WalletSeedCustodyError<CustodianError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletSeedCustodyError(REDACTED)")
    }
}

impl<CustodianError> fmt::Display for WalletSeedCustodyError<CustodianError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("wallet seed custody operation failed")
    }
}

impl<CustodianError: std::error::Error + 'static> std::error::Error
    for WalletSeedCustodyError<CustodianError>
{
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use vault_protocol::ChainId;

    use super::*;
    use crate::{MAX_SCAN_ACCOUNTS, WalletRecoveryAccounts};

    struct MemoryCustodian {
        seed: WalletSeedMaterial,
        uses: usize,
    }

    impl WalletSeedCustodian for MemoryCustodian {
        type Error = Infallible;

        fn use_seed<T>(
            &mut self,
            operation: impl FnOnce(&WalletSeedMaterial) -> T,
        ) -> Result<T, Self::Error> {
            self.uses += 1;
            Ok(operation(&self.seed))
        }
    }

    #[test]
    fn canonical_package_round_trips_and_every_byte_is_bound() {
        const EXPECTED_PACKAGE: [u8; WALLET_SEED_RECOVERY_PACKAGE_BYTES] = [
            0x56, 0x53, 0x45, 0x45, 0x44, 0x30, 0x30, 0x31, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
            0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
            0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0x39, 0xf4,
            0xd9, 0xf6, 0xa3, 0xae, 0x31, 0x09, 0x8d, 0x09, 0xc8, 0xd7, 0x05, 0x43, 0x11, 0xce,
            0x60, 0xf6, 0xef, 0xba, 0x2c, 0xa5, 0x22, 0x80, 0xe4, 0xc7, 0xae, 0x96, 0x97, 0x81,
            0x18, 0xad,
        ];
        let seed = WalletSeedMaterial::from_custodian_entropy(Zeroizing::new([0xA1; 32])).unwrap();
        assert_eq!(format!("{seed:?}"), "WalletSeedMaterial(REDACTED)");
        let package = seed.export_recovery_package();
        assert_eq!(package.len(), WALLET_SEED_RECOVERY_PACKAGE_BYTES);
        assert_eq!(package.as_slice(), EXPECTED_PACKAGE);

        let imported = WalletSeedMaterial::import_recovery_package(package.clone()).unwrap();
        assert_eq!(
            seed.export_recovery_package().as_slice(),
            imported.export_recovery_package().as_slice()
        );
        let chain_id = ChainId::new([0x39; 32]);
        let original_accounts = WalletRecoveryAccounts::derive(&seed, chain_id, 3).unwrap();
        let imported_accounts = WalletRecoveryAccounts::derive(&imported, chain_id, 3).unwrap();
        for account in 0..3 {
            assert_eq!(
                original_accounts.account_id(account),
                imported_accounts.account_id(account)
            );
        }

        for index in 0..package.len() {
            let mut mutated = package.clone();
            mutated[index] ^= 1;
            assert_eq!(
                WalletSeedMaterial::import_recovery_package(mutated).unwrap_err(),
                WalletSeedImportError::InvalidRecoveryPackage
            );
        }
        for length in [0, package.len() - 1] {
            assert_eq!(
                WalletSeedMaterial::import_recovery_package(Zeroizing::new(
                    package[..length].to_vec()
                ))
                .unwrap_err(),
                WalletSeedImportError::InvalidRecoveryPackage
            );
        }
        let mut trailing = package.to_vec();
        trailing.push(0);
        assert_eq!(
            WalletSeedMaterial::import_recovery_package(Zeroizing::new(trailing)).unwrap_err(),
            WalletSeedImportError::InvalidRecoveryPackage
        );
    }

    #[test]
    fn generation_produces_an_importable_nonzero_package() {
        let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
        let generated = WalletSeedMaterial::generate(&mut rng).unwrap();
        WalletSeedMaterial::import_recovery_package(generated.export_recovery_package()).unwrap();
    }

    #[test]
    fn zero_entropy_is_rejected_even_with_a_valid_checksum() {
        let zero = Zeroizing::new([0; WALLET_SEED_ENTROPY_BYTES]);
        assert_eq!(
            WalletSeedMaterial::from_custodian_entropy(zero).unwrap_err(),
            WalletSeedImportError::InvalidRecoveryPackage
        );

        let mut package = Zeroizing::new(Vec::with_capacity(WALLET_SEED_RECOVERY_PACKAGE_BYTES));
        package.extend_from_slice(&WALLET_SEED_PACKAGE_MAGIC);
        package.extend_from_slice(&[0; WALLET_SEED_ENTROPY_BYTES]);
        package.extend_from_slice(&seed_package_checksum(&[0; WALLET_SEED_ENTROPY_BYTES]));
        assert_eq!(
            WalletSeedMaterial::import_recovery_package(package).unwrap_err(),
            WalletSeedImportError::InvalidRecoveryPackage
        );
    }

    #[test]
    fn custodian_derivation_uses_seed_once_and_validates_public_limits_first() {
        let chain_id = ChainId::new([0x42; 32]);
        let mut custodian = MemoryCustodian {
            seed: WalletSeedMaterial::from_custodian_entropy(Zeroizing::new([0xA1; 32])).unwrap(),
            uses: 0,
        };
        let accounts =
            WalletRecoveryAccounts::derive_from_custodian(&mut custodian, chain_id, 3).unwrap();
        assert_eq!(custodian.uses, 1);
        assert_eq!(accounts.account_count(), 3);

        let error = WalletRecoveryAccounts::derive_from_custodian(
            &mut custodian,
            chain_id,
            MAX_SCAN_ACCOUNTS + 1,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            WalletSeedCustodyError::Recovery(WalletRecoveryError::InvalidAccountCount)
        ));
        assert_eq!(format!("{error:?}"), "WalletSeedCustodyError(REDACTED)");
        assert_eq!(custodian.uses, 1);
    }
}
