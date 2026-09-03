//! Crash-consistent authenticated checkpoint-policy history.
//!
//! Every stored successor is threshold-signed by its exact predecessor. A
//! platform [`CheckpointPolicyRollbackGuard`] additionally anchors the latest
//! generation and policy ID so restoring an older valid file or an equivocated
//! policy at the same generation fails closed.

use core::fmt;
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use subtle::ConstantTimeEq;
use tempfile::NamedTempFile;
use vault_protocol::ChainId;

use crate::{
    CheckpointTrustPolicy, MAX_CHECKPOINT_POLICY_UPDATE_BYTES, verify_checkpoint_policy_bootstrap,
    verify_checkpoint_policy_update,
};

#[cfg(unix)]
use fs2::FileExt;
#[cfg(unix)]
use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
};

const POLICY_LOG_MAGIC: [u8; 8] = *b"VPLG0001";
const POLICY_LOG_CHECKSUM_DOMAIN: &str = "vault.wallet.checkpoint-policy-log-v1.2026-09-02";
const POLICY_LOG_HEADER_BYTES: usize = 8 + 32 + 32 + 2;
const POLICY_LOG_CHECKSUM_BYTES: usize = 32;
const MAX_POLICY_UPDATES: usize = 64;
const MAX_POLICY_LOG_BYTES: usize = POLICY_LOG_HEADER_BYTES
    + MAX_POLICY_UPDATES * (2 + MAX_CHECKPOINT_POLICY_UPDATE_BYTES)
    + POLICY_LOG_CHECKSUM_BYTES;

/// Exact rollback anchor protected by an OS keystore or secure element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointPolicyAnchor {
    generation: u64,
    policy_id: [u8; 32],
}

impl CheckpointPolicyAnchor {
    /// Constructs the anchor for a verified policy.
    #[must_use]
    pub fn from_policy(policy: &CheckpointTrustPolicy) -> Self {
        Self {
            generation: policy.generation(),
            policy_id: policy.policy_id(),
        }
    }

    /// Monotonic policy generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Stable ID of the complete policy at this generation.
    #[must_use]
    pub const fn policy_id(self) -> [u8; 32] {
        self.policy_id
    }
}

/// Deliberately opaque failure from protected rollback storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointPolicyRollbackGuardError;

impl fmt::Display for CheckpointPolicyRollbackGuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("checkpoint policy rollback guard failed")
    }
}

impl std::error::Error for CheckpointPolicyRollbackGuardError {}

/// Platform boundary for rollback-resistant checkpoint-policy state.
///
/// An implementation must scope state by both `chain_id` and
/// `bootstrap_policy_id`, reject generation regression, and reject replacing a
/// policy ID at the same generation. `advance_anchor` must be durable before it
/// returns success.
pub trait CheckpointPolicyRollbackGuard {
    /// Reads the latest protected anchor, or `None` for a new lineage.
    fn load_anchor(
        &mut self,
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
    ) -> Result<Option<CheckpointPolicyAnchor>, CheckpointPolicyRollbackGuardError>;

    /// Durably advances to `anchor` without permitting rollback or equivocation.
    fn advance_anchor(
        &mut self,
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
        anchor: CheckpointPolicyAnchor,
    ) -> Result<(), CheckpointPolicyRollbackGuardError>;
}

/// Fail-closed checkpoint-policy history error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointPolicyStoreError {
    /// No reviewed crash-consistent file implementation exists on this platform.
    UnsupportedPlatform,
    /// The path is relative, unsafe, linked, or outside a protected directory.
    InvalidPath,
    /// Another process owns the policy-log lock.
    LockContended,
    /// Explicit initialization found an existing state file.
    StateAlreadyExists,
    /// Normal opening found no state file.
    StateMissing,
    /// The supplied generation-1 artifact failed pinned bootstrap verification.
    BootstrapRejected,
    /// Stored framing, checksum, update chain, or canonical encoding is invalid.
    CorruptState,
    /// The file belongs to another network or bootstrap policy lineage.
    ScopeMismatch,
    /// Protected state is newer or identifies another policy at this generation.
    RollbackDetected,
    /// A downloaded successor was not authorized by the active policy.
    UpdateRejected,
    /// The bounded history requires compaction before another update.
    HistoryFull,
    /// The protected platform rollback anchor could not be read or advanced.
    RollbackGuardFailure,
    /// A durability operation failed.
    IoFailure,
    /// An uncertain persistence or guard failure poisoned this handle.
    Poisoned,
}

impl fmt::Display for CheckpointPolicyStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedPlatform => "checkpoint policy store is unsupported on this platform",
            Self::InvalidPath => "checkpoint policy store path is invalid",
            Self::LockContended => "checkpoint policy store is already locked",
            Self::StateAlreadyExists => "checkpoint policy state already exists",
            Self::StateMissing => "checkpoint policy state is missing",
            Self::BootstrapRejected => "checkpoint policy bootstrap was rejected",
            Self::CorruptState => "checkpoint policy state is corrupt",
            Self::ScopeMismatch => "checkpoint policy state has the wrong scope",
            Self::RollbackDetected => "checkpoint policy rollback or equivocation was detected",
            Self::UpdateRejected => "checkpoint policy update was rejected",
            Self::HistoryFull => "checkpoint policy history is full",
            Self::RollbackGuardFailure => "checkpoint policy rollback guard failed",
            Self::IoFailure => "checkpoint policy durability operation failed",
            Self::Poisoned => "checkpoint policy store is poisoned",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CheckpointPolicyStoreError {}

/// Single-owner Unix store for an authenticated publisher-policy lineage.
///
/// The public policy history needs no encryption. Signatures authenticate every
/// transition; the checksum detects torn/corrupt files; the external guard
/// detects restoration of an older valid history. An install does not return
/// success until both the file and exact rollback anchor are durable.
pub struct CheckpointPolicyStore {
    file: LockedPolicyFile,
    chain_id: ChainId,
    bootstrap_policy_id: [u8; 32],
    updates: Vec<Vec<u8>>,
    anchors: Vec<CheckpointPolicyAnchor>,
    current: CheckpointTrustPolicy,
    poisoned: bool,
}

impl fmt::Debug for CheckpointPolicyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointPolicyStore")
            .field("chain_id", &self.chain_id)
            .field("generation", &self.current.generation())
            .field("updates", &self.updates.len())
            .field("path", &"REDACTED")
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl CheckpointPolicyStore {
    /// Verifies a generation-1 artifact against an external pin, then creates its lineage.
    pub fn create_from_bootstrap_package<G: CheckpointPolicyRollbackGuard>(
        path: impl AsRef<Path>,
        package: &[u8],
        expected_chain_id: ChainId,
        expected_policy_id: [u8; 32],
        guard: &mut G,
    ) -> Result<Self, CheckpointPolicyStoreError> {
        let bootstrap =
            verify_checkpoint_policy_bootstrap(package, expected_chain_id, expected_policy_id)
                .map_err(|_| CheckpointPolicyStoreError::BootstrapRejected)?;
        Self::create(path, bootstrap, guard)
    }

    /// Creates and anchors a new policy lineage without overwriting state.
    fn create<G: CheckpointPolicyRollbackGuard>(
        path: impl AsRef<Path>,
        bootstrap: CheckpointTrustPolicy,
        guard: &mut G,
    ) -> Result<Self, CheckpointPolicyStoreError> {
        let file = LockedPolicyFile::open(path).map_err(map_file_error)?;
        if file
            .read_bounded(MAX_POLICY_LOG_BYTES)
            .map_err(map_file_error)?
            .is_some()
        {
            return Err(CheckpointPolicyStoreError::StateAlreadyExists);
        }
        let chain_id = bootstrap.chain_id();
        let bootstrap_policy_id = bootstrap.policy_id();
        let bootstrap_anchor = CheckpointPolicyAnchor::from_policy(&bootstrap);
        let mut store = Self {
            file,
            chain_id,
            bootstrap_policy_id,
            updates: Vec::new(),
            anchors: vec![bootstrap_anchor],
            current: bootstrap,
            poisoned: false,
        };
        store
            .file
            .replace(&store.encode())
            .map_err(map_file_error)?;
        if let Err(error) = store.synchronize_guard(guard) {
            store.poisoned = true;
            return Err(error);
        }
        Ok(store)
    }

    /// Opens and verifies the complete chain from an independently pinned bootstrap.
    fn open<G: CheckpointPolicyRollbackGuard>(
        path: impl AsRef<Path>,
        bootstrap: CheckpointTrustPolicy,
        guard: &mut G,
    ) -> Result<Self, CheckpointPolicyStoreError> {
        let file = LockedPolicyFile::open(path).map_err(map_file_error)?;
        let bytes = file
            .read_bounded(MAX_POLICY_LOG_BYTES)
            .map_err(map_file_error)?
            .ok_or(CheckpointPolicyStoreError::StateMissing)?;
        let decoded = decode_log(&bytes, bootstrap)?;
        let mut store = Self {
            file,
            chain_id: decoded.chain_id,
            bootstrap_policy_id: decoded.bootstrap_policy_id,
            updates: decoded.updates,
            anchors: decoded.anchors,
            current: decoded.current,
            poisoned: false,
        };
        store.synchronize_guard(guard)?;
        Ok(store)
    }

    /// Verifies a pinned generation-1 artifact, then opens and replays its lineage.
    pub fn open_from_bootstrap_package<G: CheckpointPolicyRollbackGuard>(
        path: impl AsRef<Path>,
        package: &[u8],
        expected_chain_id: ChainId,
        expected_policy_id: [u8; 32],
        guard: &mut G,
    ) -> Result<Self, CheckpointPolicyStoreError> {
        let bootstrap =
            verify_checkpoint_policy_bootstrap(package, expected_chain_id, expected_policy_id)
                .map_err(|_| CheckpointPolicyStoreError::BootstrapRejected)?;
        Self::open(path, bootstrap, guard)
    }

    /// Verifies, persists, and rollback-anchors one complete successor update.
    pub fn install_update<G: CheckpointPolicyRollbackGuard>(
        &mut self,
        package: &[u8],
        guard: &mut G,
    ) -> Result<(), CheckpointPolicyStoreError> {
        if self.poisoned {
            return Err(CheckpointPolicyStoreError::Poisoned);
        }
        if self.updates.len() == MAX_POLICY_UPDATES {
            return Err(CheckpointPolicyStoreError::HistoryFull);
        }
        let successor = verify_checkpoint_policy_update(package, &self.current)
            .map_err(|_| CheckpointPolicyStoreError::UpdateRejected)?;
        let mut candidate_updates = self.updates.clone();
        candidate_updates.push(package.to_vec());
        let candidate_bytes =
            encode_log(self.chain_id, self.bootstrap_policy_id, &candidate_updates);
        if let Err(error) = self.file.replace(&candidate_bytes).map_err(map_file_error) {
            self.poisoned = true;
            return Err(error);
        }
        self.updates = candidate_updates;
        self.anchors
            .push(CheckpointPolicyAnchor::from_policy(&successor));
        self.current = successor;
        if let Err(error) = self.synchronize_guard(guard) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    /// Exact active policy after replaying every stored authenticated update.
    #[must_use]
    pub const fn current_policy(&self) -> &CheckpointTrustPolicy {
        &self.current
    }

    fn synchronize_guard<G: CheckpointPolicyRollbackGuard>(
        &mut self,
        guard: &mut G,
    ) -> Result<(), CheckpointPolicyStoreError> {
        let expected = CheckpointPolicyAnchor::from_policy(&self.current);
        if let Some(protected) = guard
            .load_anchor(self.chain_id, self.bootstrap_policy_id)
            .map_err(|_| CheckpointPolicyStoreError::RollbackGuardFailure)?
        {
            if !self.anchors.contains(&protected) {
                return Err(CheckpointPolicyStoreError::RollbackDetected);
            }
        }
        guard
            .advance_anchor(self.chain_id, self.bootstrap_policy_id, expected)
            .map_err(|_| CheckpointPolicyStoreError::RollbackGuardFailure)?;
        if guard
            .load_anchor(self.chain_id, self.bootstrap_policy_id)
            .map_err(|_| CheckpointPolicyStoreError::RollbackGuardFailure)?
            != Some(expected)
        {
            return Err(CheckpointPolicyStoreError::RollbackGuardFailure);
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        encode_log(self.chain_id, self.bootstrap_policy_id, &self.updates)
    }
}

fn encode_log(chain_id: ChainId, bootstrap_policy_id: [u8; 32], updates: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        POLICY_LOG_HEADER_BYTES
            + updates.iter().map(|update| update.len() + 2).sum::<usize>()
            + POLICY_LOG_CHECKSUM_BYTES,
    );
    bytes.extend_from_slice(&POLICY_LOG_MAGIC);
    bytes.extend_from_slice(chain_id.as_bytes());
    bytes.extend_from_slice(&bootstrap_policy_id);
    bytes.extend_from_slice(
        &u16::try_from(updates.len())
            .expect("bounded policy update count fits u16")
            .to_be_bytes(),
    );
    for update in updates {
        bytes.extend_from_slice(
            &u16::try_from(update.len())
                .expect("bounded policy update length fits u16")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(update);
    }
    let checksum = policy_log_checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    bytes
}

struct DecodedPolicyLog {
    chain_id: ChainId,
    bootstrap_policy_id: [u8; 32],
    updates: Vec<Vec<u8>>,
    anchors: Vec<CheckpointPolicyAnchor>,
    current: CheckpointTrustPolicy,
}

fn decode_log(
    bytes: &[u8],
    bootstrap: CheckpointTrustPolicy,
) -> Result<DecodedPolicyLog, CheckpointPolicyStoreError> {
    if bytes.len() < POLICY_LOG_HEADER_BYTES + POLICY_LOG_CHECKSUM_BYTES
        || bytes.len() > MAX_POLICY_LOG_BYTES
    {
        return Err(CheckpointPolicyStoreError::CorruptState);
    }
    let checksum_offset = bytes.len() - POLICY_LOG_CHECKSUM_BYTES;
    let expected_checksum = policy_log_checksum(&bytes[..checksum_offset]);
    if !bool::from(bytes[checksum_offset..].ct_eq(&expected_checksum)) {
        return Err(CheckpointPolicyStoreError::CorruptState);
    }
    let mut reader = PolicyLogReader::new(&bytes[..checksum_offset]);
    if reader.take::<8>()? != POLICY_LOG_MAGIC {
        return Err(CheckpointPolicyStoreError::CorruptState);
    }
    let chain_id = ChainId::new(reader.take()?);
    let bootstrap_policy_id = reader.take::<32>()?;
    if chain_id != bootstrap.chain_id() || bootstrap_policy_id != bootstrap.policy_id() {
        return Err(CheckpointPolicyStoreError::ScopeMismatch);
    }
    let update_count = usize::from(u16::from_be_bytes(reader.take()?));
    if update_count > MAX_POLICY_UPDATES {
        return Err(CheckpointPolicyStoreError::CorruptState);
    }
    let mut current = bootstrap;
    let mut anchors = vec![CheckpointPolicyAnchor::from_policy(&current)];
    let mut updates = Vec::with_capacity(update_count);
    for _ in 0..update_count {
        let length = usize::from(u16::from_be_bytes(reader.take()?));
        if length == 0 || length > MAX_CHECKPOINT_POLICY_UPDATE_BYTES {
            return Err(CheckpointPolicyStoreError::CorruptState);
        }
        let update = reader.take_slice(length)?.to_vec();
        current = verify_checkpoint_policy_update(&update, &current)
            .map_err(|_| CheckpointPolicyStoreError::CorruptState)?;
        anchors.push(CheckpointPolicyAnchor::from_policy(&current));
        updates.push(update);
    }
    if reader.remaining() != 0 {
        return Err(CheckpointPolicyStoreError::CorruptState);
    }
    Ok(DecodedPolicyLog {
        chain_id,
        bootstrap_policy_id,
        updates,
        anchors,
        current,
    })
}

fn policy_log_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(POLICY_LOG_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

struct PolicyLogReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PolicyLogReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], CheckpointPolicyStoreError> {
        self.take_slice(N)?
            .try_into()
            .map_err(|_| CheckpointPolicyStoreError::CorruptState)
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], CheckpointPolicyStoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CheckpointPolicyStoreError::CorruptState)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CheckpointPolicyStoreError::CorruptState)?;
        self.offset = end;
        Ok(value)
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyFileError {
    #[cfg(not(unix))]
    UnsupportedPlatform,
    InvalidPath,
    #[cfg(unix)]
    LockContended,
    CorruptFile,
    IoFailure,
}

struct LockedPolicyFile {
    path: PathBuf,
    _lock_file: File,
}

impl LockedPolicyFile {
    fn open(path: impl AsRef<Path>) -> Result<Self, PolicyFileError> {
        #[cfg(unix)]
        {
            Self::open_unix(path.as_ref())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(PolicyFileError::UnsupportedPlatform)
        }
    }

    #[cfg(unix)]
    fn open_unix(requested: &Path) -> Result<Self, PolicyFileError> {
        if !requested.is_absolute() {
            return Err(PolicyFileError::InvalidPath);
        }
        let file_name = requested
            .file_name()
            .ok_or(PolicyFileError::InvalidPath)?
            .to_os_string();
        let requested_parent = requested.parent().ok_or(PolicyFileError::InvalidPath)?;
        let parent =
            fs::canonicalize(requested_parent).map_err(|_| PolicyFileError::InvalidPath)?;
        if !parent.is_dir() {
            return Err(PolicyFileError::InvalidPath);
        }
        validate_parent_security(&parent)?;
        let path = parent.join(&file_name);
        reject_non_regular_or_symlink(&path)?;
        let mut lock_name = file_name;
        lock_name.push(".lock");
        let lock_path = parent.join(lock_name);
        reject_non_regular_or_symlink(&lock_path)?;
        let lock_file = open_owner_only_file(&lock_path, true)?;
        match lock_file.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(PolicyFileError::LockContended);
            }
            Err(_) => return Err(PolicyFileError::IoFailure),
        }
        reject_non_regular_or_symlink(&path)?;
        Ok(Self {
            path,
            _lock_file: lock_file,
        })
    }

    fn read_bounded(&self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, PolicyFileError> {
        #[cfg(unix)]
        {
            match fs::symlink_metadata(&self.path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(PolicyFileError::InvalidPath);
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(PolicyFileError::IoFailure),
            }
            let mut file = open_owner_only_file(&self.path, false)?;
            let length = usize::try_from(
                file.metadata()
                    .map_err(|_| PolicyFileError::IoFailure)?
                    .len(),
            )
            .map_err(|_| PolicyFileError::CorruptFile)?;
            if length > maximum_bytes {
                return Err(PolicyFileError::CorruptFile);
            }
            let mut bytes = vec![0; length];
            file.read_exact(&mut bytes)
                .map_err(|_| PolicyFileError::CorruptFile)?;
            let mut trailing = [0; 1];
            if file
                .read(&mut trailing)
                .map_err(|_| PolicyFileError::IoFailure)?
                != 0
            {
                return Err(PolicyFileError::CorruptFile);
            }
            Ok(Some(bytes))
        }
        #[cfg(not(unix))]
        {
            let _ = maximum_bytes;
            Err(PolicyFileError::UnsupportedPlatform)
        }
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), PolicyFileError> {
        let parent = self.path.parent().ok_or(PolicyFileError::InvalidPath)?;
        let mut temporary =
            NamedTempFile::new_in(parent).map_err(|_| PolicyFileError::IoFailure)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| PolicyFileError::IoFailure)?;
        }
        temporary
            .write_all(bytes)
            .map_err(|_| PolicyFileError::IoFailure)?;
        temporary
            .as_file_mut()
            .sync_all()
            .map_err(|_| PolicyFileError::IoFailure)?;
        let persisted = temporary
            .persist(&self.path)
            .map_err(|_| PolicyFileError::IoFailure)?;
        persisted
            .sync_all()
            .map_err(|_| PolicyFileError::IoFailure)?;
        sync_parent_directory(parent)
    }
}

#[cfg(unix)]
fn reject_non_regular_or_symlink(path: &Path) -> Result<(), PolicyFileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(PolicyFileError::InvalidPath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PolicyFileError::IoFailure),
    }
}

#[cfg(unix)]
fn open_owner_only_file(path: &Path, create: bool) -> Result<File, PolicyFileError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|_| PolicyFileError::IoFailure)?;
    validate_open_file(&file)?;
    harden_file_permissions(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_open_file(file: &File) -> Result<(), PolicyFileError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(|_| PolicyFileError::IoFailure)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(PolicyFileError::InvalidPath);
    }
    Ok(())
}

#[cfg(unix)]
fn harden_file_permissions(file: &File) -> Result<(), PolicyFileError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| PolicyFileError::IoFailure)
}

#[cfg(unix)]
fn validate_parent_security(parent: &Path) -> Result<(), PolicyFileError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(parent)
        .map_err(|_| PolicyFileError::InvalidPath)?
        .permissions()
        .mode();
    if mode & 0o022 != 0 {
        return Err(PolicyFileError::InvalidPath);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<(), PolicyFileError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PolicyFileError::IoFailure)
}

#[cfg(not(unix))]
fn sync_parent_directory(_: &Path) -> Result<(), PolicyFileError> {
    Err(PolicyFileError::UnsupportedPlatform)
}

fn map_file_error(error: PolicyFileError) -> CheckpointPolicyStoreError {
    match error {
        #[cfg(not(unix))]
        PolicyFileError::UnsupportedPlatform => CheckpointPolicyStoreError::UnsupportedPlatform,
        PolicyFileError::InvalidPath => CheckpointPolicyStoreError::InvalidPath,
        #[cfg(unix)]
        PolicyFileError::LockContended => CheckpointPolicyStoreError::LockContended,
        PolicyFileError::CorruptFile => CheckpointPolicyStoreError::CorruptState,
        PolicyFileError::IoFailure => CheckpointPolicyStoreError::IoFailure,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;

    use super::*;
    use crate::{
        CheckpointPolicyBootstrapDraft, CheckpointPolicyUpdateDraft, CheckpointPublisherSignature,
        checkpoint_publisher_id,
    };

    const NETWORK: ChainId = ChainId::new([0xA1; 32]);

    #[derive(Default)]
    struct MemoryGuard {
        scope: Option<(ChainId, [u8; 32])>,
        anchor: Option<CheckpointPolicyAnchor>,
        fail: bool,
    }

    impl CheckpointPolicyRollbackGuard for MemoryGuard {
        fn load_anchor(
            &mut self,
            chain_id: ChainId,
            bootstrap_policy_id: [u8; 32],
        ) -> Result<Option<CheckpointPolicyAnchor>, CheckpointPolicyRollbackGuardError> {
            if self.fail {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            if self
                .scope
                .is_some_and(|scope| scope != (chain_id, bootstrap_policy_id))
            {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            Ok(self.anchor)
        }

        fn advance_anchor(
            &mut self,
            chain_id: ChainId,
            bootstrap_policy_id: [u8; 32],
            anchor: CheckpointPolicyAnchor,
        ) -> Result<(), CheckpointPolicyRollbackGuardError> {
            if self.fail {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            if self
                .scope
                .is_some_and(|scope| scope != (chain_id, bootstrap_policy_id))
            {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            if let Some(current) = self.anchor
                && (anchor.generation < current.generation
                    || (anchor.generation == current.generation
                        && anchor.policy_id != current.policy_id))
            {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            self.scope = Some((chain_id, bootstrap_policy_id));
            self.anchor = Some(anchor);
            Ok(())
        }
    }

    fn policy(keys: &[SigningKey]) -> CheckpointTrustPolicy {
        CheckpointTrustPolicy::new(
            NETWORK,
            2,
            keys.iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
        )
        .unwrap()
    }

    fn update(
        current: &CheckpointTrustPolicy,
        current_keys: &[SigningKey],
        next_keys: &[SigningKey],
        next_generation: u64,
    ) -> Vec<u8> {
        let draft = CheckpointPolicyUpdateDraft::new(
            current,
            next_generation,
            2,
            next_keys
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
        )
        .unwrap();
        let signatures = current_keys[..2]
            .iter()
            .map(|key| {
                CheckpointPublisherSignature::new(
                    checkpoint_publisher_id(key.verifying_key().to_bytes()),
                    key.sign(draft.signing_bytes()).to_bytes(),
                )
            })
            .collect();
        draft.assemble(signatures).unwrap()
    }

    fn bootstrap_package(keys: &[SigningKey]) -> (Vec<u8>, [u8; 32]) {
        let bootstrap = policy(keys);
        let draft = CheckpointPolicyBootstrapDraft::new(
            NETWORK,
            2,
            keys.iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
            [0xB2; 32],
        )
        .unwrap();
        let signatures = keys
            .iter()
            .map(|key| {
                CheckpointPublisherSignature::new(
                    checkpoint_publisher_id(key.verifying_key().to_bytes()),
                    key.sign(draft.signing_bytes()).to_bytes(),
                )
            })
            .collect();
        (draft.assemble(signatures).unwrap(), bootstrap.policy_id())
    }

    #[test]
    fn store_initializes_only_from_the_pinned_bootstrap_artifact() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("checkpoint-policy.bin");
        let keys = [
            SigningKey::from_bytes(&[26; 32]),
            SigningKey::from_bytes(&[27; 32]),
            SigningKey::from_bytes(&[28; 32]),
        ];
        let (package, policy_id) = bootstrap_package(&keys);
        let mut guard = MemoryGuard::default();
        let store = CheckpointPolicyStore::create_from_bootstrap_package(
            &path, &package, NETWORK, policy_id, &mut guard,
        )
        .unwrap();
        assert_eq!(store.current_policy().policy_id(), policy_id);
        drop(store);

        let reopened = CheckpointPolicyStore::open_from_bootstrap_package(
            &path, &package, NETWORK, policy_id, &mut guard,
        )
        .unwrap();
        assert_eq!(reopened.current_policy().generation(), 1);
        drop(reopened);

        assert_eq!(
            CheckpointPolicyStore::open_from_bootstrap_package(
                &path, &package, NETWORK, [0xFF; 32], &mut guard,
            )
            .unwrap_err(),
            CheckpointPolicyStoreError::BootstrapRejected
        );
    }

    #[test]
    fn store_replays_authenticated_history_and_rejects_valid_rollback() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("checkpoint-policy.bin");
        let old_keys = [
            SigningKey::from_bytes(&[31; 32]),
            SigningKey::from_bytes(&[32; 32]),
            SigningKey::from_bytes(&[33; 32]),
        ];
        let next_keys = [
            SigningKey::from_bytes(&[32; 32]),
            SigningKey::from_bytes(&[34; 32]),
            SigningKey::from_bytes(&[35; 32]),
        ];
        let bootstrap = policy(&old_keys);
        let mut guard = MemoryGuard::default();
        let mut store =
            CheckpointPolicyStore::create(&path, bootstrap.clone(), &mut guard).unwrap();
        assert_eq!(store.current_policy().generation(), 1);
        assert_eq!(guard.anchor.unwrap().generation(), 1);
        let generation_one_file = fs::read(&path).unwrap();

        let package = update(&bootstrap, &old_keys, &next_keys, 2);
        store.install_update(&package, &mut guard).unwrap();
        let generation_two_id = store.current_policy().policy_id();
        assert_eq!(store.current_policy().generation(), 2);
        assert_eq!(guard.anchor.unwrap().policy_id(), generation_two_id);
        drop(store);

        let reopened = CheckpointPolicyStore::open(&path, bootstrap.clone(), &mut guard).unwrap();
        assert_eq!(reopened.current_policy().policy_id(), generation_two_id);
        drop(reopened);

        fs::write(&path, generation_one_file).unwrap();
        assert_eq!(
            CheckpointPolicyStore::open(&path, bootstrap, &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::RollbackDetected
        );
    }

    #[test]
    fn store_rejects_same_generation_equivocation_and_corruption() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("checkpoint-policy.bin");
        let old_keys = [
            SigningKey::from_bytes(&[41; 32]),
            SigningKey::from_bytes(&[42; 32]),
            SigningKey::from_bytes(&[43; 32]),
        ];
        let first_next_keys = [
            SigningKey::from_bytes(&[42; 32]),
            SigningKey::from_bytes(&[44; 32]),
            SigningKey::from_bytes(&[45; 32]),
        ];
        let alternate_next_keys = [
            SigningKey::from_bytes(&[42; 32]),
            SigningKey::from_bytes(&[46; 32]),
            SigningKey::from_bytes(&[47; 32]),
        ];
        let bootstrap = policy(&old_keys);
        let bootstrap_id = bootstrap.policy_id();
        let mut guard = MemoryGuard::default();
        let mut store =
            CheckpointPolicyStore::create(&path, bootstrap.clone(), &mut guard).unwrap();
        let first_update = update(&bootstrap, &old_keys, &first_next_keys, 2);
        store.install_update(&first_update, &mut guard).unwrap();
        drop(store);

        let alternate_update = update(&bootstrap, &old_keys, &alternate_next_keys, 2);
        let alternate_log = encode_log(NETWORK, bootstrap_id, &[alternate_update]);
        fs::write(&path, alternate_log).unwrap();
        assert_eq!(
            CheckpointPolicyStore::open(&path, bootstrap.clone(), &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::RollbackDetected
        );

        let skipping_update = update(&bootstrap, &old_keys, &alternate_next_keys, 3);
        let skipping_log = encode_log(NETWORK, bootstrap_id, &[skipping_update]);
        fs::write(&path, skipping_log).unwrap();
        assert_eq!(
            CheckpointPolicyStore::open(&path, bootstrap.clone(), &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::RollbackDetected
        );

        let valid_log = encode_log(NETWORK, bootstrap_id, &[first_update]);
        for index in 0..valid_log.len() {
            let mut mutated = valid_log.clone();
            mutated[index] ^= 1;
            fs::write(&path, mutated).unwrap();
            assert!(CheckpointPolicyStore::open(&path, bootstrap.clone(), &mut guard).is_err());
        }
        fs::write(&path, &valid_log[..valid_log.len() - 1]).unwrap();
        assert_eq!(
            CheckpointPolicyStore::open(&path, bootstrap, &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::CorruptState
        );
    }

    #[test]
    fn lifecycle_lock_scope_and_guard_failures_are_fail_closed() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("checkpoint-policy.bin");
        let keys = [
            SigningKey::from_bytes(&[51; 32]),
            SigningKey::from_bytes(&[52; 32]),
            SigningKey::from_bytes(&[53; 32]),
        ];
        let bootstrap = policy(&keys);
        let mut guard = MemoryGuard::default();
        let store = CheckpointPolicyStore::create(&path, bootstrap.clone(), &mut guard).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.with_file_name("checkpoint-policy.bin.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            CheckpointPolicyStore::create(&path, bootstrap.clone(), &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::LockContended
        );
        drop(store);
        assert_eq!(
            CheckpointPolicyStore::create(&path, bootstrap.clone(), &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::StateAlreadyExists
        );

        let wrong_bootstrap = CheckpointTrustPolicy::new(
            NETWORK,
            1,
            vec![SigningKey::from_bytes(&[54; 32]).verifying_key().to_bytes()],
        )
        .unwrap();
        assert_eq!(
            CheckpointPolicyStore::open(&path, wrong_bootstrap, &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::ScopeMismatch
        );
        assert_eq!(
            CheckpointPolicyStore::open("relative-policy.bin", bootstrap.clone(), &mut guard)
                .unwrap_err(),
            CheckpointPolicyStoreError::InvalidPath
        );

        let symlink_path = directory.path().join("linked-policy.bin");
        symlink(&path, &symlink_path).unwrap();
        assert_eq!(
            CheckpointPolicyStore::open(&symlink_path, bootstrap.clone(), &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::InvalidPath
        );

        guard.fail = true;
        assert_eq!(
            CheckpointPolicyStore::open(&path, bootstrap, &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::RollbackGuardFailure
        );
    }

    #[test]
    fn uncertain_guard_failure_poisoning_recovers_from_the_durable_log() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("checkpoint-policy.bin");
        let old_keys = [
            SigningKey::from_bytes(&[61; 32]),
            SigningKey::from_bytes(&[62; 32]),
            SigningKey::from_bytes(&[63; 32]),
        ];
        let next_keys = [
            SigningKey::from_bytes(&[62; 32]),
            SigningKey::from_bytes(&[64; 32]),
            SigningKey::from_bytes(&[65; 32]),
        ];
        let bootstrap = policy(&old_keys);
        let package = update(&bootstrap, &old_keys, &next_keys, 2);
        let mut guard = MemoryGuard::default();
        let mut store =
            CheckpointPolicyStore::create(&path, bootstrap.clone(), &mut guard).unwrap();

        guard.fail = true;
        assert_eq!(
            store.install_update(&package, &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::RollbackGuardFailure
        );
        assert_eq!(
            store.install_update(&package, &mut guard).unwrap_err(),
            CheckpointPolicyStoreError::Poisoned
        );
        drop(store);

        guard.fail = false;
        let reopened = CheckpointPolicyStore::open(&path, bootstrap, &mut guard).unwrap();
        assert_eq!(reopened.current_policy().generation(), 2);
        assert_eq!(guard.anchor.unwrap().generation(), 2);
    }
}
