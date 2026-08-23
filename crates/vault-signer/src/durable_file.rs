use core::fmt;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use tempfile::NamedTempFile;

#[cfg(unix)]
use fs2::FileExt;
#[cfg(unix)]
use std::{
    fs::OpenOptions,
    io::{self, Read},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableFileError {
    #[cfg(not(unix))]
    UnsupportedPlatform,
    InvalidPath,
    LockContended,
    CorruptFile,
    IoFailure,
}

/// Single-owner Unix file with a stable sibling lock and atomic replacement.
pub(crate) struct LockedAtomicFile {
    path: PathBuf,
    _lock_file: File,
}

impl fmt::Debug for LockedAtomicFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedAtomicFile")
            .field("path", &"REDACTED")
            .finish_non_exhaustive()
    }
}

impl LockedAtomicFile {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, DurableFileError> {
        #[cfg(unix)]
        {
            Self::open_unix(path.as_ref())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(DurableFileError::UnsupportedPlatform)
        }
    }

    #[cfg(unix)]
    fn open_unix(requested: &Path) -> Result<Self, DurableFileError> {
        if !requested.is_absolute() {
            return Err(DurableFileError::InvalidPath);
        }
        let file_name = requested
            .file_name()
            .ok_or(DurableFileError::InvalidPath)?
            .to_os_string();
        let requested_parent = requested.parent().ok_or(DurableFileError::InvalidPath)?;
        let parent =
            fs::canonicalize(requested_parent).map_err(|_| DurableFileError::InvalidPath)?;
        if !parent.is_dir() {
            return Err(DurableFileError::InvalidPath);
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
                return Err(DurableFileError::LockContended);
            }
            Err(_) => return Err(DurableFileError::IoFailure),
        }
        reject_non_regular_or_symlink(&path)?;
        Ok(Self {
            path,
            _lock_file: lock_file,
        })
    }

    /// Reads at most `maximum_bytes`, validating the opened inode before any
    /// size-derived allocation. A missing state file is returned as `None`.
    pub(crate) fn read_bounded(
        &self,
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, DurableFileError> {
        #[cfg(unix)]
        {
            self.read_bounded_unix(maximum_bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = maximum_bytes;
            Err(DurableFileError::UnsupportedPlatform)
        }
    }

    #[cfg(unix)]
    fn read_bounded_unix(&self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, DurableFileError> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(DurableFileError::InvalidPath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(DurableFileError::IoFailure),
        }

        let mut file = open_owner_only_file(&self.path, false)?;
        let metadata = file.metadata().map_err(|_| DurableFileError::IoFailure)?;
        let length = usize::try_from(metadata.len()).map_err(|_| DurableFileError::CorruptFile)?;
        if length > maximum_bytes {
            return Err(DurableFileError::CorruptFile);
        }
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)
            .map_err(|_| DurableFileError::CorruptFile)?;
        let mut trailing = [0; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| DurableFileError::IoFailure)?
            != 0
        {
            return Err(DurableFileError::CorruptFile);
        }
        Ok(Some(bytes))
    }

    /// Replaces the complete file through same-directory write, file sync,
    /// atomic rename, resulting-file sync, and parent-directory sync.
    pub(crate) fn replace(&self, bytes: &[u8]) -> Result<(), DurableFileError> {
        let parent = self.path.parent().ok_or(DurableFileError::InvalidPath)?;
        let mut temporary =
            NamedTempFile::new_in(parent).map_err(|_| DurableFileError::IoFailure)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| DurableFileError::IoFailure)?;
        }
        temporary
            .write_all(bytes)
            .map_err(|_| DurableFileError::IoFailure)?;
        temporary
            .as_file_mut()
            .sync_all()
            .map_err(|_| DurableFileError::IoFailure)?;
        let persisted = temporary
            .persist(&self.path)
            .map_err(|_| DurableFileError::IoFailure)?;
        persisted
            .sync_all()
            .map_err(|_| DurableFileError::IoFailure)?;
        sync_parent_directory(parent)
    }
}

#[cfg(unix)]
fn reject_non_regular_or_symlink(path: &Path) -> Result<(), DurableFileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(DurableFileError::InvalidPath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DurableFileError::IoFailure),
    }
}

#[cfg(unix)]
fn open_owner_only_file(path: &Path, create: bool) -> Result<File, DurableFileError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| DurableFileError::IoFailure)?;
    validate_open_file(&file)?;
    harden_file_permissions(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn harden_file_permissions(file: &File) -> Result<(), DurableFileError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| DurableFileError::IoFailure)
}

#[cfg(unix)]
fn validate_open_file(file: &File) -> Result<(), DurableFileError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(|_| DurableFileError::IoFailure)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(DurableFileError::InvalidPath);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_parent_security(parent: &Path) -> Result<(), DurableFileError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(parent)
        .map_err(|_| DurableFileError::InvalidPath)?
        .permissions()
        .mode();
    if mode & 0o022 != 0 {
        return Err(DurableFileError::InvalidPath);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<(), DurableFileError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DurableFileError::IoFailure)
}

#[cfg(not(unix))]
fn sync_parent_directory(_: &Path) -> Result<(), DurableFileError> {
    Err(DurableFileError::UnsupportedPlatform)
}
