//! Streaming authenticated backup container for the encrypted wallet database.

use std::{
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    path::Path,
    time::Duration,
};

#[cfg(unix)]
use std::fs::OpenOptions;

use blake3::Hasher;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use rusqlite::backup::Backup;
use subtle::ConstantTimeEq;
use tempfile::{Builder, TempPath};
use vault_protocol::ChainId;
use zeroize::Zeroizing;

#[cfg(unix)]
use super::effective_user_id;
use super::{
    EncryptedWalletDb, MAX_CHECKPOINTS_LIMIT, WalletDatabaseConfig, WalletDbCrypto, WalletDbError,
    open_lock, open_sqlite, protected_parent, sync_parent, verify_database_file,
};
use crate::FinalizedWalletStore;

const BACKUP_MAGIC: &[u8; 4] = b"VWB1";
const BACKUP_VERSION: u16 = 1;
const PREFIX_BYTES: usize = 64;
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_PLAINTEXT_BYTES: usize = 192;
const MANIFEST_CIPHERTEXT_BYTES: usize = MANIFEST_PLAINTEXT_BYTES + 16;
const HEADER_BYTES: usize = PREFIX_BYTES + MANIFEST_CIPHERTEXT_BYTES;
const CHUNK_PLAINTEXT_BYTES: usize = 65_536;
const CHUNK_CIPHERTEXT_BYTES: usize = CHUNK_PLAINTEXT_BYTES + 16;
const PADDING_CHUNKS: u64 = 16;
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_CHUNKS: u64 = MAX_SNAPSHOT_BYTES / CHUNK_PLAINTEXT_BYTES as u64;
const BACKUP_KEY_DOMAIN: &str = "vault.wallet-backup-v1.key.2026-08-23";

/// Local completion information for one published backup.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WalletBackupSummary {
    finalized_height: u64,
    snapshot_bytes: u64,
    backup_bytes: u64,
}

impl core::fmt::Debug for WalletBackupSummary {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WalletBackupSummary(REDACTED)")
    }
}

impl WalletBackupSummary {
    /// Finalized wallet height captured in the snapshot.
    #[must_use]
    pub const fn finalized_height(self) -> u64 {
        self.finalized_height
    }

    /// Exact SQLite snapshot length before container padding.
    #[must_use]
    pub const fn snapshot_bytes(self) -> u64 {
        self.snapshot_bytes
    }

    /// Published authenticated container length.
    #[must_use]
    pub const fn backup_bytes(self) -> u64 {
        self.backup_bytes
    }
}

struct BackupPrefix {
    backup_id: [u8; 32],
    nonce_prefix: [u8; 16],
    chunk_count: u64,
}

impl core::fmt::Debug for BackupPrefix {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupPrefix(REDACTED)")
    }
}

impl BackupPrefix {
    fn encode(&self) -> [u8; PREFIX_BYTES] {
        let mut output = [0; PREFIX_BYTES];
        output[..4].copy_from_slice(BACKUP_MAGIC);
        output[4..6].copy_from_slice(&BACKUP_VERSION.to_be_bytes());
        output[6..8].copy_from_slice(
            &u16::try_from(HEADER_BYTES)
                .expect("fixed wallet backup header fits u16")
                .to_be_bytes(),
        );
        output[8..40].copy_from_slice(&self.backup_id);
        output[40..56].copy_from_slice(&self.nonce_prefix);
        output[56..64].copy_from_slice(&self.chunk_count.to_be_bytes());
        output
    }

    fn parse(bytes: &[u8; PREFIX_BYTES]) -> Result<Self, WalletDbError> {
        if &bytes[..4] != BACKUP_MAGIC
            || u16::from_be_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| WalletDbError::InvalidBackup)?,
            ) != BACKUP_VERSION
            || usize::from(u16::from_be_bytes(
                bytes[6..8]
                    .try_into()
                    .map_err(|_| WalletDbError::InvalidBackup)?,
            )) != HEADER_BYTES
        {
            return Err(WalletDbError::InvalidBackup);
        }
        let backup_id = bytes[8..40]
            .try_into()
            .map_err(|_| WalletDbError::InvalidBackup)?;
        let nonce_prefix = bytes[40..56]
            .try_into()
            .map_err(|_| WalletDbError::InvalidBackup)?;
        let chunk_count = u64::from_be_bytes(
            bytes[56..64]
                .try_into()
                .map_err(|_| WalletDbError::InvalidBackup)?,
        );
        if backup_id == [0; 32]
            || chunk_count < PADDING_CHUNKS
            || chunk_count % PADDING_CHUNKS != 0
            || chunk_count > MAX_CHUNKS
        {
            return Err(WalletDbError::InvalidBackup);
        }
        Ok(Self {
            backup_id,
            nonce_prefix,
            chunk_count,
        })
    }

    fn expected_file_bytes(&self) -> Result<u64, WalletDbError> {
        self.chunk_count
            .checked_mul(CHUNK_CIPHERTEXT_BYTES as u64)
            .and_then(|bytes| bytes.checked_add(HEADER_BYTES as u64))
            .ok_or(WalletDbError::InvalidBackup)
    }
}

struct BackupManifest {
    database_id: [u8; 32],
    chain_id: ChainId,
    wallet_id: [u8; 32],
    maximum_note_value: u64,
    max_checkpoints: usize,
    tip_height: u64,
    tip_hash: [u8; 32],
    snapshot_bytes: u64,
    chunk_count: u64,
}

impl core::fmt::Debug for BackupManifest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupManifest(REDACTED)")
    }
}

impl BackupManifest {
    fn encode(&self) -> Result<[u8; MANIFEST_PLAINTEXT_BYTES], WalletDbError> {
        let mut output = [0; MANIFEST_PLAINTEXT_BYTES];
        output[..2].copy_from_slice(&MANIFEST_VERSION.to_be_bytes());
        output[2..4].copy_from_slice(
            &u16::try_from(MANIFEST_PLAINTEXT_BYTES)
                .expect("fixed backup manifest fits u16")
                .to_be_bytes(),
        );
        output[4..36].copy_from_slice(&self.database_id);
        output[36..68].copy_from_slice(self.chain_id.as_bytes());
        output[68..100].copy_from_slice(&self.wallet_id);
        output[100..108].copy_from_slice(&self.maximum_note_value.to_be_bytes());
        output[108..116].copy_from_slice(
            &u64::try_from(self.max_checkpoints)
                .map_err(|_| WalletDbError::InvalidBackup)?
                .to_be_bytes(),
        );
        output[116..124].copy_from_slice(&self.tip_height.to_be_bytes());
        output[124..156].copy_from_slice(&self.tip_hash);
        output[156..164].copy_from_slice(&self.snapshot_bytes.to_be_bytes());
        output[164..168].copy_from_slice(
            &u32::try_from(CHUNK_PLAINTEXT_BYTES)
                .expect("fixed backup chunk size fits u32")
                .to_be_bytes(),
        );
        output[168..176].copy_from_slice(&self.chunk_count.to_be_bytes());
        Ok(output)
    }

    fn parse(bytes: &[u8; MANIFEST_PLAINTEXT_BYTES]) -> Result<Self, WalletDbError> {
        if u16::from_be_bytes(
            bytes[..2]
                .try_into()
                .map_err(|_| WalletDbError::InvalidBackup)?,
        ) != MANIFEST_VERSION
            || usize::from(u16::from_be_bytes(
                bytes[2..4]
                    .try_into()
                    .map_err(|_| WalletDbError::InvalidBackup)?,
            )) != MANIFEST_PLAINTEXT_BYTES
            || bytes[176..] != [0; MANIFEST_PLAINTEXT_BYTES - 176]
        {
            return Err(WalletDbError::InvalidBackup);
        }
        let database_id = bytes[4..36]
            .try_into()
            .map_err(|_| WalletDbError::InvalidBackup)?;
        let chain_bytes: [u8; 32] = bytes[36..68]
            .try_into()
            .map_err(|_| WalletDbError::InvalidBackup)?;
        let wallet_id = bytes[68..100]
            .try_into()
            .map_err(|_| WalletDbError::InvalidBackup)?;
        let maximum_note_value = u64::from_be_bytes(
            bytes[100..108]
                .try_into()
                .map_err(|_| WalletDbError::InvalidBackup)?,
        );
        let max_checkpoints_raw = u64::from_be_bytes(
            bytes[108..116]
                .try_into()
                .map_err(|_| WalletDbError::InvalidBackup)?,
        );
        let max_checkpoints =
            usize::try_from(max_checkpoints_raw).map_err(|_| WalletDbError::InvalidBackup)?;
        let tip_height = u64::from_be_bytes(
            bytes[116..124]
                .try_into()
                .map_err(|_| WalletDbError::InvalidBackup)?,
        );
        let tip_hash = bytes[124..156]
            .try_into()
            .map_err(|_| WalletDbError::InvalidBackup)?;
        let snapshot_bytes = u64::from_be_bytes(
            bytes[156..164]
                .try_into()
                .map_err(|_| WalletDbError::InvalidBackup)?,
        );
        let chunk_bytes = u32::from_be_bytes(
            bytes[164..168]
                .try_into()
                .map_err(|_| WalletDbError::InvalidBackup)?,
        );
        let chunk_count = u64::from_be_bytes(
            bytes[168..176]
                .try_into()
                .map_err(|_| WalletDbError::InvalidBackup)?,
        );

        if database_id == [0; 32]
            || chain_bytes == [0; 32]
            || wallet_id == [0; 32]
            || maximum_note_value == 0
            || maximum_note_value > i64::MAX as u64
            || max_checkpoints == 0
            || max_checkpoints > MAX_CHECKPOINTS_LIMIT
            || tip_hash == [0; 32]
            || snapshot_bytes == 0
            || snapshot_bytes > MAX_SNAPSHOT_BYTES
            || usize::try_from(chunk_bytes).ok() != Some(CHUNK_PLAINTEXT_BYTES)
            || chunk_count != padded_chunk_count(snapshot_bytes)?
            || chunk_count > MAX_CHUNKS
        {
            return Err(WalletDbError::InvalidBackup);
        }
        Ok(Self {
            database_id,
            chain_id: ChainId::new(chain_bytes),
            wallet_id,
            maximum_note_value,
            max_checkpoints,
            tip_height,
            tip_hash,
            snapshot_bytes,
            chunk_count,
        })
    }
}

fn padded_chunk_count(snapshot_bytes: u64) -> Result<u64, WalletDbError> {
    if snapshot_bytes == 0 || snapshot_bytes > MAX_SNAPSHOT_BYTES {
        return Err(WalletDbError::BackupTooLarge);
    }
    let exact = snapshot_bytes
        .checked_add(CHUNK_PLAINTEXT_BYTES as u64 - 1)
        .ok_or(WalletDbError::BackupTooLarge)?
        / CHUNK_PLAINTEXT_BYTES as u64;
    let padded = exact
        .checked_add(PADDING_CHUNKS - 1)
        .ok_or(WalletDbError::BackupTooLarge)?
        / PADDING_CHUNKS
        * PADDING_CHUNKS;
    Ok(padded.max(PADDING_CHUNKS))
}

fn derive_backup_key(root_key: &[u8; 32], backup_id: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Hasher::new_derive_key(BACKUP_KEY_DOMAIN);
    hasher.update(root_key);
    hasher.update(backup_id);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn backup_nonce(prefix: [u8; 16], counter: u64) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..16].copy_from_slice(&prefix);
    nonce[16..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn encrypt_manifest(
    key: &[u8; 32],
    nonce_prefix: [u8; 16],
    prefix: &[u8; PREFIX_BYTES],
    manifest: &[u8; MANIFEST_PLAINTEXT_BYTES],
) -> Result<[u8; MANIFEST_CIPHERTEXT_BYTES], WalletDbError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(&backup_nonce(nonce_prefix, u64::MAX)),
            Payload {
                msg: manifest,
                aad: prefix,
            },
        )
        .map_err(|_| WalletDbError::AuthenticationFailed)?
        .try_into()
        .map_err(|_| WalletDbError::InvalidBackup)
}

fn decrypt_manifest(
    key: &[u8; 32],
    nonce_prefix: [u8; 16],
    prefix: &[u8; PREFIX_BYTES],
    ciphertext: &[u8; MANIFEST_CIPHERTEXT_BYTES],
) -> Result<BackupManifest, WalletDbError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&backup_nonce(nonce_prefix, u64::MAX)),
            Payload {
                msg: ciphertext,
                aad: prefix,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| WalletDbError::AuthenticationFailed)?;
    let encoded: &[u8; MANIFEST_PLAINTEXT_BYTES] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| WalletDbError::InvalidBackup)?;
    BackupManifest::parse(encoded)
}

fn chunk_aad(header: &[u8; HEADER_BYTES], index: u64) -> [u8; HEADER_BYTES + 8] {
    let mut aad = [0; HEADER_BYTES + 8];
    aad[..HEADER_BYTES].copy_from_slice(header);
    aad[HEADER_BYTES..].copy_from_slice(&index.to_be_bytes());
    aad
}

fn ensure_missing(path: &Path) -> Result<(), WalletDbError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(WalletDbError::AlreadyExists),
        Err(_) => Err(WalletDbError::UnsafeFile),
    }
}

#[cfg(unix)]
fn open_backup_input(path: &Path) -> Result<File, WalletDbError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| WalletDbError::UnsafeFile)?;
    let metadata = file.metadata().map_err(|_| WalletDbError::UnsafeFile)?;
    if !metadata.is_file()
        || metadata.uid() != effective_user_id()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(WalletDbError::UnsafeFile);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_backup_input(_: &Path) -> Result<File, WalletDbError> {
    Err(WalletDbError::UnsupportedPlatform)
}

fn temporary_path(parent: &Path, prefix: &str) -> Result<TempPath, WalletDbError> {
    Builder::new()
        .prefix(prefix)
        .tempfile_in(parent)
        .map(|file| file.into_temp_path())
        .map_err(|_| WalletDbError::DatabaseFailure)
}

impl EncryptedWalletDb {
    /// Exports a consistent non-overwriting authenticated backup container.
    pub fn export_backup(
        &self,
        backup_path: &Path,
        root_key: &[u8; 32],
    ) -> Result<WalletBackupSummary, WalletDbError> {
        if self.poisoned {
            return Err(WalletDbError::Poisoned);
        }
        self.validate_open_state()?;
        let candidate = WalletDbCrypto::derive(
            root_key,
            self.crypto.database_id,
            self.crypto.chain_id,
            self.config.wallet_id,
            self.config.maximum_note_value,
            self.config.max_checkpoints,
        );
        if !bool::from(
            candidate.encryption_key[..].ct_eq(&self.crypto.encryption_key[..])
                & candidate.index_key[..].ct_eq(&self.crypto.index_key[..]),
        ) {
            return Err(WalletDbError::AuthenticationFailed);
        }
        let page_count: i64 = self
            .connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        let page_bytes: i64 = self
            .connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        let estimated_snapshot_bytes = u64::try_from(page_count)
            .ok()
            .and_then(|count| {
                u64::try_from(page_bytes)
                    .ok()
                    .and_then(|bytes| count.checked_mul(bytes))
            })
            .filter(|bytes| *bytes > 0 && *bytes <= MAX_SNAPSHOT_BYTES)
            .ok_or(WalletDbError::BackupTooLarge)?;
        let parent = protected_parent(backup_path)?;
        ensure_missing(backup_path)?;
        let _backup_lock = open_lock(backup_path)?;

        let snapshot_path = temporary_path(&parent, ".vault-wallet-snapshot-")?;
        let mut snapshot_connection = open_sqlite(snapshot_path.as_ref())?;
        let backup = Backup::new(&self.connection, &mut snapshot_connection)
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        backup
            .run_to_completion(256, Duration::from_millis(1), None)
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        drop(backup);
        drop(snapshot_connection);
        File::open(&*snapshot_path)
            .and_then(|file| file.sync_all())
            .map_err(|_| WalletDbError::DatabaseFailure)?;

        let snapshot_bytes = fs::metadata(&*snapshot_path)
            .map_err(|_| WalletDbError::DatabaseFailure)?
            .len();
        if snapshot_bytes != estimated_snapshot_bytes {
            return Err(WalletDbError::DatabaseFailure);
        }
        let chunk_count = padded_chunk_count(snapshot_bytes)?;
        let tip = self.load_tip()?;
        let mut backup_id = [0; 32];
        let mut nonce_prefix = [0; 16];
        OsRng
            .try_fill_bytes(&mut backup_id)
            .map_err(|_| WalletDbError::EntropyUnavailable)?;
        OsRng
            .try_fill_bytes(&mut nonce_prefix)
            .map_err(|_| WalletDbError::EntropyUnavailable)?;
        if backup_id == [0; 32] {
            return Err(WalletDbError::EntropyUnavailable);
        }
        let prefix = BackupPrefix {
            backup_id,
            nonce_prefix,
            chunk_count,
        };
        let manifest = BackupManifest {
            database_id: self.crypto.database_id,
            chain_id: self.crypto.chain_id,
            wallet_id: self.config.wallet_id,
            maximum_note_value: self.config.maximum_note_value,
            max_checkpoints: self.config.max_checkpoints,
            tip_height: tip.height(),
            tip_hash: tip.block_hash(),
            snapshot_bytes,
            chunk_count,
        };
        let encoded_prefix = prefix.encode();
        let backup_key = derive_backup_key(root_key, &backup_id);
        let encrypted_manifest = encrypt_manifest(
            &backup_key,
            nonce_prefix,
            &encoded_prefix,
            &manifest.encode()?,
        )?;
        let mut encoded_header = [0; HEADER_BYTES];
        encoded_header[..PREFIX_BYTES].copy_from_slice(&encoded_prefix);
        encoded_header[PREFIX_BYTES..].copy_from_slice(&encrypted_manifest);

        let mut input = open_backup_input(snapshot_path.as_ref())?;
        let mut output = Builder::new()
            .prefix(".vault-wallet-backup-")
            .tempfile_in(&parent)
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        output
            .write_all(&encoded_header)
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(backup_key.as_ref()));
        let mut remaining = snapshot_bytes;
        let mut plaintext = Zeroizing::new(vec![0; CHUNK_PLAINTEXT_BYTES]);
        for index in 0..chunk_count {
            OsRng
                .try_fill_bytes(&mut plaintext)
                .map_err(|_| WalletDbError::EntropyUnavailable)?;
            let read_bytes = usize::try_from(remaining.min(CHUNK_PLAINTEXT_BYTES as u64))
                .map_err(|_| WalletDbError::BackupTooLarge)?;
            if read_bytes > 0 {
                input
                    .read_exact(&mut plaintext[..read_bytes])
                    .map_err(|_| WalletDbError::DatabaseFailure)?;
                remaining -= read_bytes as u64;
            }
            let ciphertext = cipher
                .encrypt(
                    XNonce::from_slice(&backup_nonce(nonce_prefix, index)),
                    Payload {
                        msg: &plaintext,
                        aad: &chunk_aad(&encoded_header, index),
                    },
                )
                .map_err(|_| WalletDbError::DatabaseFailure)?;
            if ciphertext.len() != CHUNK_CIPHERTEXT_BYTES {
                return Err(WalletDbError::DatabaseFailure);
            }
            output
                .write_all(&ciphertext)
                .map_err(|_| WalletDbError::DatabaseFailure)?;
        }
        if remaining != 0 {
            return Err(WalletDbError::DatabaseFailure);
        }
        output
            .as_file_mut()
            .flush()
            .and_then(|_| output.as_file().sync_all())
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        let expected_file_bytes = prefix.expected_file_bytes()?;
        if output
            .as_file()
            .metadata()
            .map_err(|_| WalletDbError::DatabaseFailure)?
            .len()
            != expected_file_bytes
        {
            return Err(WalletDbError::DatabaseFailure);
        }
        let published =
            output
                .persist_noclobber(backup_path)
                .map_err(|error| match error.error.kind() {
                    ErrorKind::AlreadyExists => WalletDbError::AlreadyExists,
                    _ => WalletDbError::DatabaseFailure,
                })?;
        published
            .sync_all()
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        sync_parent(&parent)?;
        Ok(WalletBackupSummary {
            finalized_height: tip.height(),
            snapshot_bytes,
            backup_bytes: expected_file_bytes,
        })
    }

    /// Restores one authenticated backup to a new, never-overwritten database.
    pub fn restore_backup(
        backup_path: &Path,
        destination_path: &Path,
        root_key: &[u8; 32],
        expected_chain_id: ChainId,
        expected_wallet_id: [u8; 32],
        minimum_finalized_height: u64,
    ) -> Result<Self, WalletDbError> {
        protected_parent(backup_path)?;
        verify_database_file(backup_path)?;
        let _backup_lock = open_lock(backup_path)?;
        let mut input = open_backup_input(backup_path)?;
        let file_bytes = input
            .metadata()
            .map_err(|_| WalletDbError::InvalidBackup)?
            .len();
        let mut encoded_header = [0; HEADER_BYTES];
        input
            .read_exact(&mut encoded_header)
            .map_err(|_| WalletDbError::InvalidBackup)?;
        let encoded_prefix: &[u8; PREFIX_BYTES] = encoded_header[..PREFIX_BYTES]
            .try_into()
            .map_err(|_| WalletDbError::InvalidBackup)?;
        let encrypted_manifest: &[u8; MANIFEST_CIPHERTEXT_BYTES] = encoded_header[PREFIX_BYTES..]
            .try_into()
            .map_err(|_| WalletDbError::InvalidBackup)?;
        let prefix = BackupPrefix::parse(encoded_prefix)?;
        if file_bytes != prefix.expected_file_bytes()? {
            return Err(WalletDbError::InvalidBackup);
        }
        let backup_key = derive_backup_key(root_key, &prefix.backup_id);
        let manifest = decrypt_manifest(
            &backup_key,
            prefix.nonce_prefix,
            encoded_prefix,
            encrypted_manifest,
        )?;
        if manifest.chunk_count != prefix.chunk_count {
            return Err(WalletDbError::InvalidBackup);
        }
        if manifest.chain_id != expected_chain_id || manifest.wallet_id != expected_wallet_id {
            return Err(WalletDbError::ScopeMismatch);
        }
        if manifest.tip_height < minimum_finalized_height {
            return Err(WalletDbError::RollbackDetected);
        }

        let destination_parent = protected_parent(destination_path)?;
        ensure_missing(destination_path)?;
        let destination_lock = open_lock(destination_path)?;
        let mut restored = Builder::new()
            .prefix(".vault-wallet-restore-")
            .tempfile_in(&destination_parent)
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(backup_key.as_ref()));
        let mut remaining = manifest.snapshot_bytes;
        let mut ciphertext = vec![0; CHUNK_CIPHERTEXT_BYTES];
        for index in 0..prefix.chunk_count {
            input
                .read_exact(&mut ciphertext)
                .map_err(|_| WalletDbError::InvalidBackup)?;
            let plaintext = cipher
                .decrypt(
                    XNonce::from_slice(&backup_nonce(prefix.nonce_prefix, index)),
                    Payload {
                        msg: &ciphertext,
                        aad: &chunk_aad(&encoded_header, index),
                    },
                )
                .map(Zeroizing::new)
                .map_err(|_| WalletDbError::AuthenticationFailed)?;
            if plaintext.len() != CHUNK_PLAINTEXT_BYTES {
                return Err(WalletDbError::InvalidBackup);
            }
            let write_bytes = usize::try_from(remaining.min(CHUNK_PLAINTEXT_BYTES as u64))
                .map_err(|_| WalletDbError::InvalidBackup)?;
            if write_bytes > 0 {
                restored
                    .write_all(&plaintext[..write_bytes])
                    .map_err(|_| WalletDbError::DatabaseFailure)?;
                remaining -= write_bytes as u64;
            }
        }
        if remaining != 0 {
            return Err(WalletDbError::InvalidBackup);
        }
        restored
            .as_file_mut()
            .flush()
            .and_then(|_| restored.as_file().sync_all())
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        let restored_path = restored.into_temp_path();
        let validated = EncryptedWalletDb::open(
            restored_path.as_ref(),
            root_key,
            expected_chain_id,
            expected_wallet_id,
            minimum_finalized_height,
        )?;
        let validated_tip = validated.load_tip()?;
        if validated.crypto.database_id != manifest.database_id
            || validated.config
                != (WalletDatabaseConfig {
                    wallet_id: manifest.wallet_id,
                    maximum_note_value: manifest.maximum_note_value,
                    max_checkpoints: manifest.max_checkpoints,
                })
            || validated_tip.height() != manifest.tip_height
            || validated_tip.block_hash() != manifest.tip_hash
        {
            return Err(WalletDbError::InvalidBackup);
        }
        drop(validated);
        #[cfg(unix)]
        {
            let temporary_lock = super::lock_path(restored_path.as_ref())?;
            match fs::remove_file(temporary_lock) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(_) => return Err(WalletDbError::DatabaseFailure),
            }
        }
        restored_path
            .persist_noclobber(destination_path)
            .map_err(|error| match error.error.kind() {
                ErrorKind::AlreadyExists => WalletDbError::AlreadyExists,
                _ => WalletDbError::DatabaseFailure,
            })?;
        File::open(destination_path)
            .and_then(|file| file.sync_all())
            .map_err(|_| WalletDbError::DatabaseFailure)?;
        sync_parent(&destination_parent)?;
        EncryptedWalletDb::open_locked(
            destination_path,
            root_key,
            expected_chain_id,
            expected_wallet_id,
            minimum_finalized_height,
            destination_lock,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_rounding_is_canonical_and_bounded() {
        assert_eq!(padded_chunk_count(1).unwrap(), 16);
        assert_eq!(padded_chunk_count(16 * 65_536).unwrap(), 16);
        assert_eq!(padded_chunk_count(16 * 65_536 + 1).unwrap(), 32);
        assert_eq!(
            padded_chunk_count(MAX_SNAPSHOT_BYTES + 1).unwrap_err(),
            WalletDbError::BackupTooLarge
        );
    }

    #[test]
    fn prefix_and_manifest_round_trip_reject_noncanonical_encodings() {
        let prefix = BackupPrefix {
            backup_id: [5; 32],
            nonce_prefix: [6; 16],
            chunk_count: 16,
        };
        let encoded_prefix = prefix.encode();
        let decoded_prefix = BackupPrefix::parse(&encoded_prefix).unwrap();
        assert_eq!(decoded_prefix.chunk_count, 16);
        assert_eq!(decoded_prefix.expected_file_bytes().unwrap(), 1_049_104);

        let manifest = BackupManifest {
            database_id: [1; 32],
            chain_id: ChainId::new([2; 32]),
            wallet_id: [3; 32],
            maximum_note_value: 100,
            max_checkpoints: 10,
            tip_height: 5,
            tip_hash: [4; 32],
            snapshot_bytes: 4096,
            chunk_count: 16,
        };
        let encoded_manifest = manifest.encode().unwrap();
        let decoded_manifest = BackupManifest::parse(&encoded_manifest).unwrap();
        assert_eq!(decoded_manifest.database_id, manifest.database_id);
        assert_eq!(decoded_manifest.tip_height, manifest.tip_height);

        let mut wrong_version = encoded_prefix;
        wrong_version[5] = 2;
        assert_eq!(
            BackupPrefix::parse(&wrong_version).unwrap_err(),
            WalletDbError::InvalidBackup
        );
        let mut wrong_chunks = encoded_prefix;
        wrong_chunks[63] = 15;
        assert_eq!(
            BackupPrefix::parse(&wrong_chunks).unwrap_err(),
            WalletDbError::InvalidBackup
        );
        let mut nonzero_reserved = encoded_manifest;
        nonzero_reserved[191] = 1;
        assert_eq!(
            BackupManifest::parse(&nonzero_reserved).unwrap_err(),
            WalletDbError::InvalidBackup
        );
    }

    #[test]
    fn header_and_chunk_domains_do_not_share_nonces_or_aad() {
        let prefix = [7; 16];
        assert_ne!(backup_nonce(prefix, 0), backup_nonce(prefix, 1));
        assert_ne!(backup_nonce(prefix, 0), backup_nonce(prefix, u64::MAX));
        let header = [8; HEADER_BYTES];
        assert_ne!(chunk_aad(&header, 0), chunk_aad(&header, 1));
    }
}
