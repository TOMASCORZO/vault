//! macOS Keychain rollback anchor.
//!
//! The anchor is stored outside the wallet database in a non-synchronizing
//! Keychain item. A scope-specific owner-only file lock
//! serializes legitimate Vault processes while the Keychain record is checked
//! and advanced.

use core::fmt;
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use security_framework::passwords::{
    PasswordOptions, generic_password, set_generic_password_options,
};
use security_framework_sys::base::errSecItemNotFound;
use subtle::ConstantTimeEq;
use vault_protocol::ChainId;

use crate::{
    CheckpointPolicyAnchor, CheckpointPolicyRollbackGuard, CheckpointPolicyRollbackGuardError,
};

const KEYCHAIN_SERVICE: &str = "org.vault.wallet.checkpoint-policy-anchor.v1";
const RECORD_MAGIC: [u8; 8] = *b"VPKCM001";
const RECORD_CHECKSUM_DOMAIN: &str = "vault.wallet.macos-keychain-anchor-v1.2026-09-03";
const RECORD_BODY_BYTES: usize = 8 + 32 + 32 + 8 + 32;
const RECORD_BYTES: usize = RECORD_BODY_BYTES + 32;

/// macOS rollback guard backed by a non-synchronizing local Keychain item.
///
/// `lock_directory` must be one fixed, absolute, owner-controlled application
/// directory shared by every Vault process. The lock prevents concurrent
/// read-modify-write races; the Keychain item remains the authoritative anchor.
pub struct MacOsKeychainRollbackGuard {
    lock_directory: PathBuf,
}

impl fmt::Debug for MacOsKeychainRollbackGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacOsKeychainRollbackGuard")
            .field("lock_directory", &"REDACTED")
            .finish()
    }
}

impl MacOsKeychainRollbackGuard {
    /// Opens the platform guard using an existing protected application directory.
    pub fn new(
        lock_directory: impl AsRef<Path>,
    ) -> Result<Self, CheckpointPolicyRollbackGuardError> {
        let requested = lock_directory.as_ref();
        if !requested.is_absolute() {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        let canonical =
            fs::canonicalize(requested).map_err(|_| CheckpointPolicyRollbackGuardError)?;
        let metadata = fs::metadata(&canonical).map_err(|_| CheckpointPolicyRollbackGuardError)?;
        if !metadata.is_dir()
            || metadata.permissions().mode() & 0o022 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        Ok(Self {
            lock_directory: canonical,
        })
    }

    fn with_scope_lock<T>(
        &self,
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
        operation: impl FnOnce() -> Result<T, CheckpointPolicyRollbackGuardError>,
    ) -> Result<T, CheckpointPolicyRollbackGuardError> {
        let account = keychain_account(chain_id, bootstrap_policy_id);
        let lock_path = self
            .lock_directory
            .join(format!("checkpoint-policy-{account}.lock"));
        reject_link_or_non_file(&lock_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|_| CheckpointPolicyRollbackGuardError)?;
        validate_and_harden_lock(&file)?;
        file.try_lock_exclusive()
            .map_err(|_| CheckpointPolicyRollbackGuardError)?;
        reject_link_or_non_file(&lock_path)?;
        operation()
    }
}

impl CheckpointPolicyRollbackGuard for MacOsKeychainRollbackGuard {
    fn load_anchor(
        &mut self,
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
    ) -> Result<Option<CheckpointPolicyAnchor>, CheckpointPolicyRollbackGuardError> {
        self.with_scope_lock(chain_id, bootstrap_policy_id, || {
            read_anchor(chain_id, bootstrap_policy_id)
        })
    }

    fn advance_anchor(
        &mut self,
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
        anchor: CheckpointPolicyAnchor,
    ) -> Result<(), CheckpointPolicyRollbackGuardError> {
        self.with_scope_lock(chain_id, bootstrap_policy_id, || {
            if chain_id.is_zero() || anchor.generation() == 0 {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            let current = read_anchor(chain_id, bootstrap_policy_id)?;
            if let Some(current) = current {
                if anchor.generation() < current.generation()
                    || (anchor.generation() == current.generation()
                        && anchor.policy_id() != current.policy_id())
                {
                    return Err(CheckpointPolicyRollbackGuardError);
                }
                if anchor == current {
                    return Ok(());
                }
            }
            write_anchor(chain_id, bootstrap_policy_id, anchor)?;
            if read_anchor(chain_id, bootstrap_policy_id)? != Some(anchor) {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            Ok(())
        })
    }
}

fn password_options(account: &str) -> PasswordOptions {
    let mut options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, account);
    options.set_access_synchronized(Some(false));
    options
}

fn read_anchor(
    chain_id: ChainId,
    bootstrap_policy_id: [u8; 32],
) -> Result<Option<CheckpointPolicyAnchor>, CheckpointPolicyRollbackGuardError> {
    let account = keychain_account(chain_id, bootstrap_policy_id);
    match generic_password(password_options(&account)) {
        Ok(bytes) => decode_record(&bytes, chain_id, bootstrap_policy_id).map(Some),
        Err(error) if error.code() == errSecItemNotFound => Ok(None),
        Err(_) => Err(CheckpointPolicyRollbackGuardError),
    }
}

fn write_anchor(
    chain_id: ChainId,
    bootstrap_policy_id: [u8; 32],
    anchor: CheckpointPolicyAnchor,
) -> Result<(), CheckpointPolicyRollbackGuardError> {
    let account = keychain_account(chain_id, bootstrap_policy_id);
    set_generic_password_options(
        &encode_record(chain_id, bootstrap_policy_id, anchor),
        password_options(&account),
    )
    .map_err(|_| CheckpointPolicyRollbackGuardError)
}

fn encode_record(
    chain_id: ChainId,
    bootstrap_policy_id: [u8; 32],
    anchor: CheckpointPolicyAnchor,
) -> [u8; RECORD_BYTES] {
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(&RECORD_MAGIC);
    bytes[8..40].copy_from_slice(chain_id.as_bytes());
    bytes[40..72].copy_from_slice(&bootstrap_policy_id);
    bytes[72..80].copy_from_slice(&anchor.generation().to_be_bytes());
    bytes[80..112].copy_from_slice(&anchor.policy_id());
    let checksum = record_checksum(&bytes[..RECORD_BODY_BYTES]);
    bytes[RECORD_BODY_BYTES..].copy_from_slice(&checksum);
    bytes
}

fn decode_record(
    bytes: &[u8],
    expected_chain_id: ChainId,
    expected_bootstrap_policy_id: [u8; 32],
) -> Result<CheckpointPolicyAnchor, CheckpointPolicyRollbackGuardError> {
    if bytes.len() != RECORD_BYTES
        || !bool::from(bytes[..8].ct_eq(&RECORD_MAGIC))
        || !bool::from(bytes[8..40].ct_eq(expected_chain_id.as_bytes()))
        || !bool::from(bytes[40..72].ct_eq(&expected_bootstrap_policy_id))
        || !bool::from(
            bytes[RECORD_BODY_BYTES..].ct_eq(&record_checksum(&bytes[..RECORD_BODY_BYTES])),
        )
    {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    let generation = u64::from_be_bytes(
        bytes[72..80]
            .try_into()
            .map_err(|_| CheckpointPolicyRollbackGuardError)?,
    );
    if generation == 0 {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    let policy_id = bytes[80..112]
        .try_into()
        .map_err(|_| CheckpointPolicyRollbackGuardError)?;
    Ok(CheckpointPolicyAnchor::from_parts(generation, policy_id))
}

fn record_checksum(bytes: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key(RECORD_CHECKSUM_DOMAIN)
        .update(bytes)
        .finalize()
        .as_bytes()
}

fn keychain_account(chain_id: ChainId, bootstrap_policy_id: [u8; 32]) -> String {
    let mut hasher =
        blake3::Hasher::new_derive_key("vault.wallet.macos-keychain-account-v1.2026-09-03");
    hasher.update(chain_id.as_bytes());
    hasher.update(&bootstrap_policy_id);
    let mut account = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in hasher.finalize().as_bytes() {
        account.push(char::from(HEX[usize::from(byte >> 4)]));
        account.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    account
}

fn reject_link_or_non_file(path: &Path) -> Result<(), CheckpointPolicyRollbackGuardError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(CheckpointPolicyRollbackGuardError)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CheckpointPolicyRollbackGuardError),
    }
}

fn validate_and_harden_lock(file: &File) -> Result<(), CheckpointPolicyRollbackGuardError> {
    let metadata = file
        .metadata()
        .map_err(|_| CheckpointPolicyRollbackGuardError)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| CheckpointPolicyRollbackGuardError)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use security_framework::passwords::delete_generic_password_options;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        CheckpointPolicyBootstrapDraft, CheckpointPolicyStore, CheckpointPolicyStoreError,
        CheckpointPolicyUpdateDraft, CheckpointPublisherSignature, CheckpointTrustPolicy,
        checkpoint_publisher_id,
    };

    struct KeychainCleanup {
        account: String,
    }

    impl Drop for KeychainCleanup {
        fn drop(&mut self) {
            let _ = delete_generic_password_options(password_options(&self.account));
        }
    }

    fn unique_scope() -> (ChainId, [u8; 32], KeychainCleanup) {
        let mut chain = [0; 32];
        let mut bootstrap = [0; 32];
        OsRng.fill_bytes(&mut chain);
        OsRng.fill_bytes(&mut bootstrap);
        if chain == [0; 32] {
            chain[0] = 1;
        }
        let chain_id = ChainId::new(chain);
        let cleanup = KeychainCleanup {
            account: keychain_account(chain_id, bootstrap),
        };
        (chain_id, bootstrap, cleanup)
    }

    fn signatures(signing_bytes: &[u8], keys: &[SigningKey]) -> Vec<CheckpointPublisherSignature> {
        keys.iter()
            .map(|key| {
                CheckpointPublisherSignature::new(
                    checkpoint_publisher_id(key.verifying_key().to_bytes()),
                    key.sign(signing_bytes).to_bytes(),
                )
            })
            .collect()
    }

    #[test]
    fn canonical_record_rejects_every_mutation_truncation_and_extension() {
        let chain_id = ChainId::new([0xA1; 32]);
        let bootstrap = [0xB1; 32];
        let anchor = CheckpointPolicyAnchor::from_parts(7, [0xC1; 32]);
        let encoded = encode_record(chain_id, bootstrap, anchor);
        assert_eq!(
            decode_record(&encoded, chain_id, bootstrap).unwrap(),
            anchor
        );

        for index in 0..encoded.len() {
            let mut mutated = encoded;
            mutated[index] ^= 1;
            assert!(decode_record(&mutated, chain_id, bootstrap).is_err());
        }
        for length in 0..encoded.len() {
            assert!(decode_record(&encoded[..length], chain_id, bootstrap).is_err());
        }
        let mut extended = encoded.to_vec();
        extended.push(0);
        assert!(decode_record(&extended, chain_id, bootstrap).is_err());
    }

    #[test]
    fn lock_directory_and_scope_lock_reject_unsafe_paths() {
        assert!(MacOsKeychainRollbackGuard::new("relative").is_err());

        let directory = tempdir().unwrap();
        let unsafe_directory = directory.path().join("unsafe");
        fs::create_dir(&unsafe_directory).unwrap();
        fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(MacOsKeychainRollbackGuard::new(&unsafe_directory).is_err());

        let safe_directory = directory.path().join("safe");
        fs::create_dir(&safe_directory).unwrap();
        fs::set_permissions(&safe_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let chain_id = ChainId::new([0xD1; 32]);
        let bootstrap = [0xD2; 32];
        let account = keychain_account(chain_id, bootstrap);
        let target = safe_directory.join("target");
        fs::write(&target, []).unwrap();
        symlink(
            &target,
            safe_directory.join(format!("checkpoint-policy-{account}.lock")),
        )
        .unwrap();
        let mut guard = MacOsKeychainRollbackGuard::new(&safe_directory).unwrap();
        assert!(guard.load_anchor(chain_id, bootstrap).is_err());
    }

    #[test]
    fn real_keychain_guard_is_monotonic_scoped_and_persistent() {
        let directory = tempdir().unwrap();
        let (chain_id, bootstrap, _cleanup) = unique_scope();
        let first = CheckpointPolicyAnchor::from_parts(1, [0xC1; 32]);
        let second = CheckpointPolicyAnchor::from_parts(2, [0xC2; 32]);
        let alternate_second = CheckpointPolicyAnchor::from_parts(2, [0xC3; 32]);
        let mut guard = MacOsKeychainRollbackGuard::new(directory.path()).unwrap();

        assert_eq!(guard.load_anchor(chain_id, bootstrap).unwrap(), None);
        guard.advance_anchor(chain_id, bootstrap, first).unwrap();
        assert_eq!(guard.load_anchor(chain_id, bootstrap).unwrap(), Some(first));
        guard.advance_anchor(chain_id, bootstrap, first).unwrap();
        guard.advance_anchor(chain_id, bootstrap, second).unwrap();
        assert!(guard.advance_anchor(chain_id, bootstrap, first).is_err());
        assert!(
            guard
                .advance_anchor(chain_id, bootstrap, alternate_second)
                .is_err()
        );

        let mut reopened = MacOsKeychainRollbackGuard::new(directory.path()).unwrap();
        assert_eq!(
            reopened.load_anchor(chain_id, bootstrap).unwrap(),
            Some(second)
        );
        assert_eq!(reopened.load_anchor(chain_id, [0xFF; 32]).unwrap(), None);
    }

    #[test]
    fn real_keychain_anchor_rejects_a_restored_older_policy_file() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("checkpoint-policy.bin");
        let mut chain = [0; 32];
        OsRng.fill_bytes(&mut chain);
        if chain == [0; 32] {
            chain[0] = 1;
        }
        let chain_id = ChainId::new(chain);
        let old_keys = [
            SigningKey::from_bytes(&[0x31; 32]),
            SigningKey::from_bytes(&[0x32; 32]),
            SigningKey::from_bytes(&[0x33; 32]),
        ];
        let new_keys = [
            SigningKey::from_bytes(&[0x32; 32]),
            SigningKey::from_bytes(&[0x34; 32]),
            SigningKey::from_bytes(&[0x35; 32]),
        ];
        let old_public = old_keys
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect::<Vec<_>>();
        let bootstrap = CheckpointTrustPolicy::new(chain_id, 2, old_public.clone()).unwrap();
        let bootstrap_id = bootstrap.policy_id();
        let _cleanup = KeychainCleanup {
            account: keychain_account(chain_id, bootstrap_id),
        };
        let bootstrap_draft =
            CheckpointPolicyBootstrapDraft::new(chain_id, 2, old_public, [0xB4; 32]).unwrap();
        let bootstrap_signatures = signatures(bootstrap_draft.signing_bytes(), &old_keys);
        let bootstrap_package = bootstrap_draft.assemble(bootstrap_signatures).unwrap();
        let mut guard = MacOsKeychainRollbackGuard::new(directory.path()).unwrap();
        let mut store = CheckpointPolicyStore::create_from_bootstrap_package(
            &path,
            &bootstrap_package,
            chain_id,
            bootstrap_id,
            &mut guard,
        )
        .unwrap();
        let generation_one_file = fs::read(&path).unwrap();

        let update_draft = CheckpointPolicyUpdateDraft::new(
            &bootstrap,
            2,
            2,
            new_keys
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
        )
        .unwrap();
        let update_signatures = signatures(update_draft.signing_bytes(), &old_keys[..2]);
        store
            .install_update(
                &update_draft.assemble(update_signatures).unwrap(),
                &mut guard,
            )
            .unwrap();
        drop(store);

        fs::write(&path, generation_one_file).unwrap();
        let mut reopened_guard = MacOsKeychainRollbackGuard::new(directory.path()).unwrap();
        assert_eq!(
            CheckpointPolicyStore::open_from_bootstrap_package(
                &path,
                &bootstrap_package,
                chain_id,
                bootstrap_id,
                &mut reopened_guard,
            )
            .unwrap_err(),
            CheckpointPolicyStoreError::RollbackDetected
        );
    }
}
