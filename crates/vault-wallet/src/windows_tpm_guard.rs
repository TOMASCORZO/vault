//! Windows TPM 2.0 rollback guard for checkpoint-policy state.
//!
//! A TPM NV extend index commits every exact policy transition. The index
//! authorization is random, wrapped by a non-exportable Microsoft Platform
//! Crypto Provider key, and never written in plaintext. The ordinary journal
//! can be restored or corrupted, but it cannot roll the TPM digest backward.

use core::fmt;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tempfile::NamedTempFile;
use vault_protocol::ChainId;
use vault_windows_platform::{TbsContext, TpmRsaKey, replace_file_write_through, tbs_device_info};
use zeroize::Zeroizing;

use crate::{
    CheckpointPolicyAnchor, CheckpointPolicyRollbackGuard, CheckpointPolicyRollbackGuardError,
};

const STATE_MAGIC: [u8; 8] = *b"VWTPM001";
const PENDING_MAGIC: [u8; 8] = *b"VWTPJ001";
const STATE_CHECKSUM_DOMAIN: &str = "vault.wallet.windows-tpm-state-v1.2026-09-03";
const PENDING_CHECKSUM_DOMAIN: &str = "vault.wallet.windows-tpm-pending-v1.2026-09-03";
const SCOPE_DOMAIN: &str = "vault.wallet.windows-tpm-scope-v1.2026-09-03";
const KEY_NAME_DOMAIN: &str = "vault.wallet.windows-tpm-key-name-v1.2026-09-03";
const EXTEND_DOMAIN: &str = "vault.wallet.windows-tpm-extend-v1.2026-09-03";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_RS_PW: u32 = 0x4000_0009;
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
const TPM_CC_NV_EXTEND: u32 = 0x0000_0136;
const TPM_CC_NV_READ: u32 = 0x0000_014E;
const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
const TPM_RC_SUCCESS: u32 = 0;
const TPM_RC_HANDLE: u32 = 0x08B;
const TPM_RC_NV_UNINITIALIZED: u32 = 0x14A;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPMA_NV_AUTHWRITE: u32 = 1 << 2;
const TPMA_NV_NT_EXTEND: u32 = 4 << 4;
const TPMA_NV_AUTHREAD: u32 = 1 << 18;
const TPMA_NV_NO_DA: u32 = 1 << 25;
const TPMA_NV_WRITTEN: u32 = 1 << 29;
const NV_ATTRIBUTES: u32 = TPMA_NV_AUTHWRITE | TPMA_NV_NT_EXTEND | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA;
const NV_DIGEST_BYTES: usize = 32;
const NV_AUTH_BYTES: usize = 32;
const MAX_SEALED_AUTH_BYTES: usize = 512;
const MAX_STATE_BYTES: usize = 8 + 32 + 32 + 4 + 1 + 8 + 32 + 32 + 2 + 512 + 32;
const MAX_PENDING_BYTES: usize = 8 + 32 + 32 + 4 + (1 + 8 + 32) + 32 + (1 + 8 + 32) + 32 + 32 + 32;
const MAX_INDEX_ATTEMPTS: u32 = 32;
const OWNER_INDEX_BASE: u32 = 0x0180_0000;
const OWNER_INDEX_MASK: u32 = 0x003F_FFFF;

/// Windows TPM 2.0 implementation of the policy rollback boundary.
pub struct WindowsTpmRollbackGuard {
    directory: PathBuf,
}

impl fmt::Debug for WindowsTpmRollbackGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsTpmRollbackGuard")
            .field("directory", &"REDACTED")
            .finish()
    }
}

impl WindowsTpmRollbackGuard {
    /// Opens a fixed absolute, non-reparse application directory.
    pub fn new(directory: impl AsRef<Path>) -> Result<Self, CheckpointPolicyRollbackGuardError> {
        let requested = directory.as_ref();
        if !requested.is_absolute() {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        reject_reparse_point(requested, true)?;
        let canonical =
            fs::canonicalize(requested).map_err(|_| CheckpointPolicyRollbackGuardError)?;
        if !canonical.is_dir() {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        reject_reparse_point(&canonical, true)?;
        if !tbs_device_info()
            .map_err(|_| CheckpointPolicyRollbackGuardError)?
            .is_tpm20
        {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        Ok(Self {
            directory: canonical,
        })
    }

    /// Provisions one scope using Windows-managed owner authorization.
    ///
    /// This one-time operation must run elevated. It is idempotent after a
    /// completed provision and does not reset, clear, or take ownership of the
    /// TPM. Ordinary guard reads and advances do not require elevation.
    pub fn provision_scope(
        &mut self,
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
    ) -> Result<(), CheckpointPolicyRollbackGuardError> {
        self.with_scope_lock(chain_id, bootstrap_policy_id, |paths, scope| {
            if let Some(state) = read_state(&paths.state, chain_id, bootstrap_policy_id)? {
                let key = TpmRsaKey::open(&key_name(scope, &self.directory))
                    .map_err(|_| CheckpointPolicyRollbackGuardError)?;
                let authorization = key
                    .decrypt(&state.sealed_authorization)
                    .map_err(|_| CheckpointPolicyRollbackGuardError)?;
                validate_authorization(&authorization)?;
                let mut tpm = Tpm::open()?;
                match tpm.read_public(state.nv_index)? {
                    NvPublicState::Absent => {
                        if state.anchor.is_some() || state.nv_digest != [0; NV_DIGEST_BYTES] {
                            return Err(CheckpointPolicyRollbackGuardError);
                        }
                        let owner_authorization = tpm.owner_authorization()?;
                        tpm.define_extend_index(
                            state.nv_index,
                            &owner_authorization,
                            &authorization,
                        )?;
                    }
                    NvPublicState::Present(public) => validate_public(public, state.nv_index)?,
                }
                require_nv_matches_state(&mut tpm, &state, &authorization)?;
                return Ok(());
            }

            let key_name = key_name(scope, &self.directory);
            let key = match TpmRsaKey::create(&key_name) {
                Ok(key) => key,
                Err(_) => {
                    let stale = TpmRsaKey::open(&key_name)
                        .map_err(|_| CheckpointPolicyRollbackGuardError)?;
                    stale
                        .delete()
                        .map_err(|_| CheckpointPolicyRollbackGuardError)?;
                    TpmRsaKey::create(&key_name).map_err(|_| CheckpointPolicyRollbackGuardError)?
                }
            };
            let mut authorization = Zeroizing::new(vec![0_u8; NV_AUTH_BYTES]);
            OsRng.fill_bytes(&mut authorization);
            let sealed_authorization = key
                .encrypt(&authorization)
                .map_err(|_| CheckpointPolicyRollbackGuardError)?;
            let mut tpm = Tpm::open()?;
            let nv_index = select_free_index(&mut tpm, scope)?;
            let state = GuardState {
                chain_id,
                bootstrap_policy_id,
                nv_index,
                anchor: None,
                nv_digest: [0; NV_DIGEST_BYTES],
                sealed_authorization,
            };
            write_state(&paths.state, &state)?;

            let mut defined = false;
            let provision_result = (|| {
                let owner_authorization = tpm.owner_authorization()?;
                tpm.define_extend_index(nv_index, &owner_authorization, &authorization)?;
                defined = true;
                match tpm.read_public(nv_index)? {
                    NvPublicState::Present(public) => validate_public(public, nv_index)?,
                    NvPublicState::Absent => return Err(CheckpointPolicyRollbackGuardError),
                }
                require_nv_matches_state(&mut tpm, &state, &authorization)
            })();
            if provision_result.is_err() {
                if defined && let Ok(owner_authorization) = tpm.owner_authorization() {
                    let _ = tpm.undefine_index(nv_index, &owner_authorization);
                }
                let _ = fs::remove_file(&paths.state);
                let _ = key.delete();
            }
            provision_result
        })
    }

    fn with_scope_lock<T>(
        &self,
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
        operation: impl FnOnce(&ScopePaths, &[u8; 32]) -> Result<T, CheckpointPolicyRollbackGuardError>,
    ) -> Result<T, CheckpointPolicyRollbackGuardError> {
        let scope = scope_id(chain_id, bootstrap_policy_id);
        let paths = ScopePaths::new(&self.directory, &scope);
        let _lock = ScopeLock::acquire(&paths.lock)?;
        operation(&paths, &scope)
    }

    fn load_recovered_state(
        &self,
        paths: &ScopePaths,
        scope: &[u8; 32],
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
    ) -> Result<Option<GuardState>, CheckpointPolicyRollbackGuardError> {
        let Some(mut state) = read_state(&paths.state, chain_id, bootstrap_policy_id)? else {
            if read_optional_bounded(&paths.pending, MAX_PENDING_BYTES)?.is_some() {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            return Ok(None);
        };
        let key = TpmRsaKey::open(&key_name(scope, &self.directory))
            .map_err(|_| CheckpointPolicyRollbackGuardError)?;
        let authorization = key
            .decrypt(&state.sealed_authorization)
            .map_err(|_| CheckpointPolicyRollbackGuardError)?;
        validate_authorization(&authorization)?;
        let mut tpm = Tpm::open()?;
        match tpm.read_public(state.nv_index)? {
            NvPublicState::Present(public) => validate_public(public, state.nv_index)?,
            NvPublicState::Absent => return Err(CheckpointPolicyRollbackGuardError),
        }
        if let Some(pending) = read_pending(
            &paths.pending,
            chain_id,
            bootstrap_policy_id,
            state.nv_index,
        )? {
            if pending.old_anchor != state.anchor
                || !bool::from(pending.old_digest.ct_eq(&state.nv_digest))
            {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            let current = tpm.read_digest(state.nv_index, &authorization)?;
            if nv_state_matches(current, state.anchor, &state.nv_digest) {
                tpm.extend(state.nv_index, &authorization, &pending.extend_input)?;
                let advanced = tpm.read_digest(state.nv_index, &authorization)?;
                if advanced != NvDigestState::Value(pending.expected_digest) {
                    return Err(CheckpointPolicyRollbackGuardError);
                }
            } else if current != NvDigestState::Value(pending.expected_digest) {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            state.anchor = Some(pending.new_anchor);
            state.nv_digest = pending.expected_digest;
            write_state(&paths.state, &state)?;
            remove_optional_file(&paths.pending)?;
        } else {
            require_nv_matches_state(&mut tpm, &state, &authorization)?;
        }
        Ok(Some(state))
    }

    #[cfg(test)]
    pub(crate) fn cleanup_test_scope(
        &self,
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
    ) -> Result<(), CheckpointPolicyRollbackGuardError> {
        let scope = scope_id(chain_id, bootstrap_policy_id);
        let paths = ScopePaths::new(&self.directory, &scope);
        self.with_scope_lock(chain_id, bootstrap_policy_id, |paths, scope| {
            if let Some(state) = read_state(&paths.state, chain_id, bootstrap_policy_id)? {
                let mut tpm = Tpm::open()?;
                if tpm.read_public(state.nv_index)? != NvPublicState::Absent {
                    let owner_authorization = tpm.owner_authorization()?;
                    tpm.undefine_index(state.nv_index, &owner_authorization)?;
                }
                remove_optional_file(&paths.pending)?;
                remove_optional_file(&paths.state)?;
            }
            let key = TpmRsaKey::open(&key_name(scope, &self.directory))
                .map_err(|_| CheckpointPolicyRollbackGuardError)?;
            key.delete().map_err(|_| CheckpointPolicyRollbackGuardError)
        })?;
        remove_optional_file(&paths.lock)
    }
}

impl CheckpointPolicyRollbackGuard for WindowsTpmRollbackGuard {
    fn load_anchor(
        &mut self,
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
    ) -> Result<Option<CheckpointPolicyAnchor>, CheckpointPolicyRollbackGuardError> {
        self.with_scope_lock(chain_id, bootstrap_policy_id, |paths, scope| {
            self.load_recovered_state(paths, scope, chain_id, bootstrap_policy_id)
                .map(|state| state.and_then(|state| state.anchor))
        })
    }

    fn advance_anchor(
        &mut self,
        chain_id: ChainId,
        bootstrap_policy_id: [u8; 32],
        anchor: CheckpointPolicyAnchor,
    ) -> Result<(), CheckpointPolicyRollbackGuardError> {
        if anchor.generation() == 0 {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        self.with_scope_lock(chain_id, bootstrap_policy_id, |paths, scope| {
            let Some(mut state) =
                self.load_recovered_state(paths, scope, chain_id, bootstrap_policy_id)?
            else {
                return Err(CheckpointPolicyRollbackGuardError);
            };
            if let Some(current) = state.anchor {
                if current == anchor {
                    return Ok(());
                }
                if anchor.generation() != current.generation().saturating_add(1) {
                    return Err(CheckpointPolicyRollbackGuardError);
                }
            } else if anchor.generation() != 1 {
                return Err(CheckpointPolicyRollbackGuardError);
            }

            let key = TpmRsaKey::open(&key_name(scope, &self.directory))
                .map_err(|_| CheckpointPolicyRollbackGuardError)?;
            let authorization = key
                .decrypt(&state.sealed_authorization)
                .map_err(|_| CheckpointPolicyRollbackGuardError)?;
            validate_authorization(&authorization)?;
            let extend_input = extend_input(
                chain_id,
                bootstrap_policy_id,
                state.nv_index,
                state.anchor,
                &state.nv_digest,
                anchor,
            );
            let expected_digest = extended_digest(&state.nv_digest, &extend_input);
            let pending = PendingAdvance {
                chain_id,
                bootstrap_policy_id,
                nv_index: state.nv_index,
                old_anchor: state.anchor,
                old_digest: state.nv_digest,
                new_anchor: anchor,
                extend_input,
                expected_digest,
            };
            write_pending(&paths.pending, &pending)?;
            let mut tpm = Tpm::open()?;
            tpm.extend(state.nv_index, &authorization, &extend_input)?;
            let read_back = tpm.read_digest(state.nv_index, &authorization)?;
            if read_back != NvDigestState::Value(expected_digest) {
                return Err(CheckpointPolicyRollbackGuardError);
            }
            state.anchor = Some(anchor);
            state.nv_digest = expected_digest;
            write_state(&paths.state, &state)?;
            remove_optional_file(&paths.pending)?;
            Ok(())
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GuardState {
    chain_id: ChainId,
    bootstrap_policy_id: [u8; 32],
    nv_index: u32,
    anchor: Option<CheckpointPolicyAnchor>,
    nv_digest: [u8; NV_DIGEST_BYTES],
    sealed_authorization: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingAdvance {
    chain_id: ChainId,
    bootstrap_policy_id: [u8; 32],
    nv_index: u32,
    old_anchor: Option<CheckpointPolicyAnchor>,
    old_digest: [u8; NV_DIGEST_BYTES],
    new_anchor: CheckpointPolicyAnchor,
    extend_input: [u8; NV_DIGEST_BYTES],
    expected_digest: [u8; NV_DIGEST_BYTES],
}

struct ScopePaths {
    state: PathBuf,
    pending: PathBuf,
    lock: PathBuf,
}

impl ScopePaths {
    fn new(directory: &Path, scope: &[u8; 32]) -> Self {
        let suffix = hex(&scope[..16]);
        Self {
            state: directory.join(format!("checkpoint-policy-tpm-{suffix}.bin")),
            pending: directory.join(format!("checkpoint-policy-tpm-{suffix}.pending")),
            lock: directory.join(format!("checkpoint-policy-tpm-{suffix}.lock")),
        }
    }
}

struct ScopeLock {
    _file: File,
}

impl ScopeLock {
    fn acquire(path: &Path) -> Result<Self, CheckpointPolicyRollbackGuardError> {
        reject_reparse_point(path, false)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options
            .open(path)
            .map_err(|_| CheckpointPolicyRollbackGuardError)?;
        reject_reparse_point(path, true)?;
        file.try_lock_exclusive()
            .map_err(|_| CheckpointPolicyRollbackGuardError)?;
        Ok(Self { _file: file })
    }
}

fn scope_id(chain_id: ChainId, bootstrap_policy_id: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SCOPE_DOMAIN);
    hasher.update(chain_id.as_bytes());
    hasher.update(&bootstrap_policy_id);
    *hasher.finalize().as_bytes()
}

fn key_name(scope: &[u8; 32], directory: &Path) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(KEY_NAME_DOMAIN);
    hasher.update(scope);
    for unit in directory.as_os_str().encode_wide() {
        hasher.update(&unit.to_le_bytes());
    }
    format!(
        "Vault-A1-CP1-WIN-{}",
        hex(&hasher.finalize().as_bytes()[..16])
    )
}

fn extend_input(
    chain_id: ChainId,
    bootstrap_policy_id: [u8; 32],
    nv_index: u32,
    old_anchor: Option<CheckpointPolicyAnchor>,
    old_digest: &[u8; 32],
    new_anchor: CheckpointPolicyAnchor,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(EXTEND_DOMAIN);
    hasher.update(chain_id.as_bytes());
    hasher.update(&bootstrap_policy_id);
    hasher.update(&nv_index.to_be_bytes());
    encode_anchor_into(&mut hasher, old_anchor);
    hasher.update(old_digest);
    hasher.update(&new_anchor.generation().to_be_bytes());
    hasher.update(&new_anchor.policy_id());
    *hasher.finalize().as_bytes()
}

fn encode_anchor_into(hasher: &mut blake3::Hasher, anchor: Option<CheckpointPolicyAnchor>) {
    match anchor {
        Some(anchor) => {
            hasher.update(&[1]);
            hasher.update(&anchor.generation().to_be_bytes());
            hasher.update(&anchor.policy_id());
        }
        None => {
            hasher.update(&[0]);
            hasher.update(&[0; 8]);
            hasher.update(&[0; 32]);
        }
    }
}

fn extended_digest(old: &[u8; 32], input: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(old);
    hasher.update(input);
    hasher.finalize().into()
}

fn select_free_index(
    tpm: &mut Tpm,
    scope: &[u8; 32],
) -> Result<u32, CheckpointPolicyRollbackGuardError> {
    for counter in 0..MAX_INDEX_ATTEMPTS {
        let mut hasher = blake3::Hasher::new_derive_key(SCOPE_DOMAIN);
        hasher.update(scope);
        hasher.update(&counter.to_be_bytes());
        let digest = hasher.finalize();
        let offset =
            u32::from_be_bytes(digest.as_bytes()[..4].try_into().unwrap()) & OWNER_INDEX_MASK;
        let index = OWNER_INDEX_BASE | offset;
        if tpm.read_public(index)? == NvPublicState::Absent {
            return Ok(index);
        }
    }
    Err(CheckpointPolicyRollbackGuardError)
}

fn validate_authorization(authorization: &[u8]) -> Result<(), CheckpointPolicyRollbackGuardError> {
    if authorization.len() == NV_AUTH_BYTES {
        Ok(())
    } else {
        Err(CheckpointPolicyRollbackGuardError)
    }
}

fn validate_public(
    public: NvPublic,
    expected_index: u32,
) -> Result<(), CheckpointPolicyRollbackGuardError> {
    if public.index == expected_index
        && public.name_algorithm == TPM_ALG_SHA256
        && public.attributes & !TPMA_NV_WRITTEN == NV_ATTRIBUTES
        && public.authorization_policy_empty
        && public.data_size == NV_DIGEST_BYTES as u16
    {
        Ok(())
    } else {
        Err(CheckpointPolicyRollbackGuardError)
    }
}

fn require_nv_matches_state(
    tpm: &mut Tpm,
    state: &GuardState,
    authorization: &[u8],
) -> Result<(), CheckpointPolicyRollbackGuardError> {
    let current = tpm.read_digest(state.nv_index, authorization)?;
    if nv_state_matches(current, state.anchor, &state.nv_digest) {
        Ok(())
    } else {
        Err(CheckpointPolicyRollbackGuardError)
    }
}

fn nv_state_matches(
    current: NvDigestState,
    anchor: Option<CheckpointPolicyAnchor>,
    digest: &[u8; 32],
) -> bool {
    match (current, anchor) {
        (NvDigestState::Uninitialized, None) => digest == &[0; 32],
        (NvDigestState::Value(current), Some(_)) => bool::from(current.ct_eq(digest)),
        _ => false,
    }
}

fn encode_state(state: &GuardState) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_STATE_BYTES);
    bytes.extend_from_slice(&STATE_MAGIC);
    bytes.extend_from_slice(state.chain_id.as_bytes());
    bytes.extend_from_slice(&state.bootstrap_policy_id);
    bytes.extend_from_slice(&state.nv_index.to_be_bytes());
    push_anchor(&mut bytes, state.anchor);
    bytes.extend_from_slice(&state.nv_digest);
    bytes.extend_from_slice(
        &u16::try_from(state.sealed_authorization.len())
            .expect("bounded sealed authorization")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&state.sealed_authorization);
    append_checksum(&mut bytes, STATE_CHECKSUM_DOMAIN);
    bytes
}

fn decode_state(bytes: &[u8]) -> Result<GuardState, CheckpointPolicyRollbackGuardError> {
    verify_checksum(bytes, STATE_CHECKSUM_DOMAIN)?;
    let payload = &bytes[..bytes.len() - 32];
    let mut reader = Reader::new(payload);
    if reader.take::<8>()? != STATE_MAGIC {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    let chain_id = ChainId::new(reader.take::<32>()?);
    let bootstrap_policy_id = reader.take::<32>()?;
    let nv_index = u32::from_be_bytes(reader.take::<4>()?);
    let anchor = reader.take_anchor()?;
    let nv_digest = reader.take::<32>()?;
    let sealed_length = usize::from(u16::from_be_bytes(reader.take::<2>()?));
    if sealed_length == 0 || sealed_length > MAX_SEALED_AUTH_BYTES {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    let sealed_authorization = reader.take_slice(sealed_length)?.to_vec();
    if reader.remaining() != 0 {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    Ok(GuardState {
        chain_id,
        bootstrap_policy_id,
        nv_index,
        anchor,
        nv_digest,
        sealed_authorization,
    })
}

fn encode_pending(pending: &PendingAdvance) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_PENDING_BYTES);
    bytes.extend_from_slice(&PENDING_MAGIC);
    bytes.extend_from_slice(pending.chain_id.as_bytes());
    bytes.extend_from_slice(&pending.bootstrap_policy_id);
    bytes.extend_from_slice(&pending.nv_index.to_be_bytes());
    push_anchor(&mut bytes, pending.old_anchor);
    bytes.extend_from_slice(&pending.old_digest);
    push_anchor(&mut bytes, Some(pending.new_anchor));
    bytes.extend_from_slice(&pending.extend_input);
    bytes.extend_from_slice(&pending.expected_digest);
    append_checksum(&mut bytes, PENDING_CHECKSUM_DOMAIN);
    bytes
}

fn decode_pending(bytes: &[u8]) -> Result<PendingAdvance, CheckpointPolicyRollbackGuardError> {
    verify_checksum(bytes, PENDING_CHECKSUM_DOMAIN)?;
    let payload = &bytes[..bytes.len() - 32];
    let mut reader = Reader::new(payload);
    if reader.take::<8>()? != PENDING_MAGIC {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    let chain_id = ChainId::new(reader.take::<32>()?);
    let bootstrap_policy_id = reader.take::<32>()?;
    let nv_index = u32::from_be_bytes(reader.take::<4>()?);
    let old_anchor = reader.take_anchor()?;
    let old_digest = reader.take::<32>()?;
    let new_anchor = reader
        .take_anchor()?
        .ok_or(CheckpointPolicyRollbackGuardError)?;
    let extend_input = reader.take::<32>()?;
    let expected_digest = reader.take::<32>()?;
    if reader.remaining() != 0 {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    Ok(PendingAdvance {
        chain_id,
        bootstrap_policy_id,
        nv_index,
        old_anchor,
        old_digest,
        new_anchor,
        extend_input,
        expected_digest,
    })
}

fn push_anchor(bytes: &mut Vec<u8>, anchor: Option<CheckpointPolicyAnchor>) {
    match anchor {
        Some(anchor) => {
            bytes.push(1);
            bytes.extend_from_slice(&anchor.generation().to_be_bytes());
            bytes.extend_from_slice(&anchor.policy_id());
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; 8]);
            bytes.extend_from_slice(&[0; 32]);
        }
    }
}

fn append_checksum(bytes: &mut Vec<u8>, domain: &str) {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(bytes);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
}

fn verify_checksum(bytes: &[u8], domain: &str) -> Result<(), CheckpointPolicyRollbackGuardError> {
    if bytes.len() < 32 {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    let split = bytes.len() - 32;
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&bytes[..split]);
    if bool::from(hasher.finalize().as_bytes().ct_eq(&bytes[split..])) {
        Ok(())
    } else {
        Err(CheckpointPolicyRollbackGuardError)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], CheckpointPolicyRollbackGuardError> {
        self.take_slice(N)?
            .try_into()
            .map_err(|_| CheckpointPolicyRollbackGuardError)
    }

    fn take_slice(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], CheckpointPolicyRollbackGuardError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CheckpointPolicyRollbackGuardError)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CheckpointPolicyRollbackGuardError)?;
        self.offset = end;
        Ok(value)
    }

    fn take_anchor(
        &mut self,
    ) -> Result<Option<CheckpointPolicyAnchor>, CheckpointPolicyRollbackGuardError> {
        let present = self.take::<1>()?[0];
        let generation = u64::from_be_bytes(self.take::<8>()?);
        let policy_id = self.take::<32>()?;
        match (present, generation, policy_id) {
            (0, 0, policy_id) if policy_id == [0; 32] => Ok(None),
            (1, generation, policy_id) if generation != 0 => Ok(Some(
                CheckpointPolicyAnchor::from_parts(generation, policy_id),
            )),
            _ => Err(CheckpointPolicyRollbackGuardError),
        }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

fn read_state(
    path: &Path,
    chain_id: ChainId,
    bootstrap_policy_id: [u8; 32],
) -> Result<Option<GuardState>, CheckpointPolicyRollbackGuardError> {
    let Some(bytes) = read_optional_bounded(path, MAX_STATE_BYTES)? else {
        return Ok(None);
    };
    let state = decode_state(&bytes)?;
    if state.chain_id != chain_id || state.bootstrap_policy_id != bootstrap_policy_id {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    Ok(Some(state))
}

fn read_pending(
    path: &Path,
    chain_id: ChainId,
    bootstrap_policy_id: [u8; 32],
    nv_index: u32,
) -> Result<Option<PendingAdvance>, CheckpointPolicyRollbackGuardError> {
    let Some(bytes) = read_optional_bounded(path, MAX_PENDING_BYTES)? else {
        return Ok(None);
    };
    let pending = decode_pending(&bytes)?;
    if pending.chain_id != chain_id
        || pending.bootstrap_policy_id != bootstrap_policy_id
        || pending.nv_index != nv_index
    {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    Ok(Some(pending))
}

fn read_optional_bounded(
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, CheckpointPolicyRollbackGuardError> {
    reject_reparse_point(path, false)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CheckpointPolicyRollbackGuardError),
    };
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| CheckpointPolicyRollbackGuardError)?
            .len(),
    )
    .map_err(|_| CheckpointPolicyRollbackGuardError)?;
    if length > maximum {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)
        .map_err(|_| CheckpointPolicyRollbackGuardError)?;
    let mut trailing = [0; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| CheckpointPolicyRollbackGuardError)?
        != 0
    {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    Ok(Some(bytes))
}

fn write_state(path: &Path, state: &GuardState) -> Result<(), CheckpointPolicyRollbackGuardError> {
    replace_bounded(path, &encode_state(state), MAX_STATE_BYTES)
}

fn write_pending(
    path: &Path,
    pending: &PendingAdvance,
) -> Result<(), CheckpointPolicyRollbackGuardError> {
    replace_bounded(path, &encode_pending(pending), MAX_PENDING_BYTES)
}

fn replace_bounded(
    path: &Path,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), CheckpointPolicyRollbackGuardError> {
    if bytes.len() > maximum {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    reject_reparse_point(path, false)?;
    let parent = path.parent().ok_or(CheckpointPolicyRollbackGuardError)?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|_| CheckpointPolicyRollbackGuardError)?;
    temporary
        .write_all(bytes)
        .map_err(|_| CheckpointPolicyRollbackGuardError)?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|_| CheckpointPolicyRollbackGuardError)?;
    let temporary_path = temporary.into_temp_path();
    replace_file_write_through(&temporary_path, path)
        .map_err(|_| CheckpointPolicyRollbackGuardError)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| CheckpointPolicyRollbackGuardError)
}

fn remove_optional_file(path: &Path) -> Result<(), CheckpointPolicyRollbackGuardError> {
    reject_reparse_point(path, false)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CheckpointPolicyRollbackGuardError),
    }
}

fn reject_reparse_point(
    path: &Path,
    must_exist: bool,
) -> Result<(), CheckpointPolicyRollbackGuardError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || (!metadata.is_file() && !metadata.is_dir()) =>
        {
            Err(CheckpointPolicyRollbackGuardError)
        }
        Ok(_) => Ok(()),
        Err(error) if !must_exist && error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CheckpointPolicyRollbackGuardError),
    }
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(TABLE[usize::from(byte >> 4)]));
        output.push(char::from(TABLE[usize::from(byte & 0x0F)]));
    }
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NvPublic {
    index: u32,
    name_algorithm: u16,
    attributes: u32,
    authorization_policy_empty: bool,
    data_size: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NvPublicState {
    Absent,
    Present(NvPublic),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NvDigestState {
    Uninitialized,
    Value([u8; 32]),
}

struct Tpm {
    context: TbsContext,
}

impl Tpm {
    fn open() -> Result<Self, CheckpointPolicyRollbackGuardError> {
        Ok(Self {
            context: TbsContext::open().map_err(|_| CheckpointPolicyRollbackGuardError)?,
        })
    }

    fn owner_authorization(
        &mut self,
    ) -> Result<Zeroizing<Vec<u8>>, CheckpointPolicyRollbackGuardError> {
        self.context
            .storage_owner_auth()
            .map_err(|_| CheckpointPolicyRollbackGuardError)
    }

    fn read_public(
        &mut self,
        index: u32,
    ) -> Result<NvPublicState, CheckpointPolicyRollbackGuardError> {
        let mut command = command_header(TPM_ST_NO_SESSIONS, TPM_CC_NV_READ_PUBLIC);
        push_u32(&mut command, index);
        finish_command(&mut command)?;
        let response = self.submit(&command)?;
        let code = response_code(&response)?;
        if code == TPM_RC_HANDLE {
            return Ok(NvPublicState::Absent);
        }
        require_success(code)?;
        let mut reader = Reader::new(&response[10..]);
        let public_length = usize::from(u16::from_be_bytes(reader.take::<2>()?));
        let public_bytes = reader.take_slice(public_length)?;
        let mut public = Reader::new(public_bytes);
        let index = u32::from_be_bytes(public.take::<4>()?);
        let name_algorithm = u16::from_be_bytes(public.take::<2>()?);
        let attributes = u32::from_be_bytes(public.take::<4>()?);
        let policy_length = usize::from(u16::from_be_bytes(public.take::<2>()?));
        public.take_slice(policy_length)?;
        let data_size = u16::from_be_bytes(public.take::<2>()?);
        if public.remaining() != 0 {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        let name_length = usize::from(u16::from_be_bytes(reader.take::<2>()?));
        reader.take_slice(name_length)?;
        if reader.remaining() != 0 {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        Ok(NvPublicState::Present(NvPublic {
            index,
            name_algorithm,
            attributes,
            authorization_policy_empty: policy_length == 0,
            data_size,
        }))
    }

    fn read_digest(
        &mut self,
        index: u32,
        authorization: &[u8],
    ) -> Result<NvDigestState, CheckpointPolicyRollbackGuardError> {
        let mut command = Zeroizing::new(command_header(TPM_ST_SESSIONS, TPM_CC_NV_READ));
        push_u32(&mut command, index);
        push_u32(&mut command, index);
        push_password_session(&mut command, authorization)?;
        push_u16(&mut command, NV_DIGEST_BYTES as u16);
        push_u16(&mut command, 0);
        finish_command(&mut command)?;
        let response = self.submit(&command)?;
        let code = response_code(&response)?;
        if code == TPM_RC_NV_UNINITIALIZED {
            return Ok(NvDigestState::Uninitialized);
        }
        require_success(code)?;
        if response[..2] != TPM_ST_SESSIONS.to_be_bytes() {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        let mut reader = Reader::new(&response[10..]);
        let parameter_length = usize::try_from(u32::from_be_bytes(reader.take::<4>()?))
            .map_err(|_| CheckpointPolicyRollbackGuardError)?;
        if parameter_length != 2 + NV_DIGEST_BYTES {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        let data_length = usize::from(u16::from_be_bytes(reader.take::<2>()?));
        if data_length != NV_DIGEST_BYTES {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        let digest = reader.take::<NV_DIGEST_BYTES>()?;
        require_empty_auth_response(&mut reader)?;
        if reader.remaining() != 0 {
            return Err(CheckpointPolicyRollbackGuardError);
        }
        Ok(NvDigestState::Value(digest))
    }

    fn extend(
        &mut self,
        index: u32,
        authorization: &[u8],
        input: &[u8; 32],
    ) -> Result<(), CheckpointPolicyRollbackGuardError> {
        let mut command = Zeroizing::new(command_header(TPM_ST_SESSIONS, TPM_CC_NV_EXTEND));
        push_u32(&mut command, index);
        push_u32(&mut command, index);
        push_password_session(&mut command, authorization)?;
        push_u16(&mut command, input.len() as u16);
        command.extend_from_slice(input);
        finish_command(&mut command)?;
        let response = self.submit(&command)?;
        require_success(response_code(&response)?)
    }

    fn define_extend_index(
        &mut self,
        index: u32,
        owner_authorization: &[u8],
        index_authorization: &[u8],
    ) -> Result<(), CheckpointPolicyRollbackGuardError> {
        let mut command = Zeroizing::new(command_header(TPM_ST_SESSIONS, TPM_CC_NV_DEFINE_SPACE));
        push_u32(&mut command, TPM_RH_OWNER);
        push_password_session(&mut command, owner_authorization)?;
        push_u16(
            &mut command,
            u16::try_from(index_authorization.len())
                .map_err(|_| CheckpointPolicyRollbackGuardError)?,
        );
        command.extend_from_slice(index_authorization);
        push_u16(&mut command, 14);
        push_u32(&mut command, index);
        push_u16(&mut command, TPM_ALG_SHA256);
        push_u32(&mut command, NV_ATTRIBUTES);
        push_u16(&mut command, 0);
        push_u16(&mut command, NV_DIGEST_BYTES as u16);
        finish_command(&mut command)?;
        let response = self.submit(&command)?;
        require_success(response_code(&response)?)
    }

    fn undefine_index(
        &mut self,
        index: u32,
        owner_authorization: &[u8],
    ) -> Result<(), CheckpointPolicyRollbackGuardError> {
        let mut command = Zeroizing::new(command_header(TPM_ST_SESSIONS, TPM_CC_NV_UNDEFINE_SPACE));
        push_u32(&mut command, TPM_RH_OWNER);
        push_u32(&mut command, index);
        push_password_session(&mut command, owner_authorization)?;
        finish_command(&mut command)?;
        let response = self.submit(&command)?;
        require_success(response_code(&response)?)
    }

    fn submit(&mut self, command: &[u8]) -> Result<Vec<u8>, CheckpointPolicyRollbackGuardError> {
        self.context
            .submit(command)
            .map_err(|_| CheckpointPolicyRollbackGuardError)
    }
}

fn command_header(tag: u16, command_code: u32) -> Vec<u8> {
    let mut command = Vec::with_capacity(128);
    push_u16(&mut command, tag);
    push_u32(&mut command, 0);
    push_u32(&mut command, command_code);
    command
}

fn push_password_session(
    command: &mut Vec<u8>,
    authorization: &[u8],
) -> Result<(), CheckpointPolicyRollbackGuardError> {
    let authorization_length =
        u16::try_from(authorization.len()).map_err(|_| CheckpointPolicyRollbackGuardError)?;
    push_u32(command, 9 + u32::from(authorization_length));
    push_u32(command, TPM_RS_PW);
    push_u16(command, 0);
    command.push(0);
    push_u16(command, authorization_length);
    command.extend_from_slice(authorization);
    Ok(())
}

fn finish_command(command: &mut [u8]) -> Result<(), CheckpointPolicyRollbackGuardError> {
    let length = u32::try_from(command.len()).map_err(|_| CheckpointPolicyRollbackGuardError)?;
    command[2..6].copy_from_slice(&length.to_be_bytes());
    Ok(())
}

fn response_code(response: &[u8]) -> Result<u32, CheckpointPolicyRollbackGuardError> {
    if response.len() < 10 {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    let declared = usize::try_from(u32::from_be_bytes(
        response[2..6]
            .try_into()
            .map_err(|_| CheckpointPolicyRollbackGuardError)?,
    ))
    .map_err(|_| CheckpointPolicyRollbackGuardError)?;
    if declared != response.len() {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    Ok(u32::from_be_bytes(
        response[6..10]
            .try_into()
            .map_err(|_| CheckpointPolicyRollbackGuardError)?,
    ))
}

fn require_success(code: u32) -> Result<(), CheckpointPolicyRollbackGuardError> {
    if code == TPM_RC_SUCCESS {
        Ok(())
    } else {
        Err(CheckpointPolicyRollbackGuardError)
    }
}

fn require_empty_auth_response(
    reader: &mut Reader<'_>,
) -> Result<(), CheckpointPolicyRollbackGuardError> {
    if reader.take::<2>()? != [0, 0] {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    let attributes = reader.take::<1>()?[0];
    if attributes > 1 || reader.take::<2>()? != [0, 0] {
        return Err(CheckpointPolicyRollbackGuardError);
    }
    Ok(())
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tempfile::tempdir;

    use super::*;

    fn sample_state() -> GuardState {
        GuardState {
            chain_id: ChainId::new([0x11; 32]),
            bootstrap_policy_id: [0x22; 32],
            nv_index: 0x0180_1234,
            anchor: Some(CheckpointPolicyAnchor::from_parts(7, [0x33; 32])),
            nv_digest: [0x44; 32],
            sealed_authorization: vec![0x55; 256],
        }
    }

    #[test]
    fn state_codec_rejects_every_mutation_truncation_and_extension() {
        let state = sample_state();
        let encoded = encode_state(&state);
        assert_eq!(decode_state(&encoded).unwrap(), state);
        for index in 0..encoded.len() {
            let mut mutated = encoded.clone();
            mutated[index] ^= 1;
            assert!(decode_state(&mutated).is_err());
        }
        for length in 0..encoded.len() {
            assert!(decode_state(&encoded[..length]).is_err());
        }
        let mut extended = encoded;
        extended.push(0);
        assert!(decode_state(&extended).is_err());
    }

    #[test]
    fn pending_codec_rejects_every_mutation_truncation_and_extension() {
        let state = sample_state();
        let new_anchor = CheckpointPolicyAnchor::from_parts(8, [0x66; 32]);
        let input = extend_input(
            state.chain_id,
            state.bootstrap_policy_id,
            state.nv_index,
            state.anchor,
            &state.nv_digest,
            new_anchor,
        );
        let pending = PendingAdvance {
            chain_id: state.chain_id,
            bootstrap_policy_id: state.bootstrap_policy_id,
            nv_index: state.nv_index,
            old_anchor: state.anchor,
            old_digest: state.nv_digest,
            new_anchor,
            extend_input: input,
            expected_digest: extended_digest(&state.nv_digest, &input),
        };
        let encoded = encode_pending(&pending);
        assert_eq!(decode_pending(&encoded).unwrap(), pending);
        for index in 0..encoded.len() {
            let mut mutated = encoded.clone();
            mutated[index] ^= 1;
            assert!(decode_pending(&mutated).is_err());
        }
        for length in 0..encoded.len() {
            assert!(decode_pending(&encoded[..length]).is_err());
        }
        let mut extended = encoded;
        extended.push(0);
        assert!(decode_pending(&extended).is_err());
    }

    #[test]
    fn scope_lock_rejects_a_second_owner() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("guard.lock");
        let first = ScopeLock::acquire(&path).unwrap();
        assert!(ScopeLock::acquire(&path).is_err());
        drop(first);
        ScopeLock::acquire(&path).unwrap();
    }

    #[test]
    fn constructor_rejects_relative_and_reparse_paths() {
        assert!(WindowsTpmRollbackGuard::new("relative").is_err());
        let directory = tempdir().unwrap();
        let unsafe_path = directory.path().join("not-a-directory");
        fs::write(&unsafe_path, b"x").unwrap();
        assert!(WindowsTpmRollbackGuard::new(&unsafe_path).is_err());
    }

    #[test]
    #[ignore = "helper process for the elevated real TPM contention test"]
    fn real_tpm_scope_lock_child_fails_closed() {
        let directory = PathBuf::from(
            std::env::var_os("VAULT_WINDOWS_TPM_TEST_DIRECTORY")
                .expect("missing TPM test directory"),
        );
        let nonce = std::env::var("VAULT_WINDOWS_TPM_TEST_NONCE")
            .expect("missing TPM test nonce")
            .parse::<u128>()
            .expect("invalid TPM test nonce");
        let mut chain_bytes = [0xA1; 32];
        chain_bytes[..16].copy_from_slice(&nonce.to_be_bytes());
        let mut guard = WindowsTpmRollbackGuard::new(directory).unwrap();
        assert!(
            guard
                .load_anchor(ChainId::new(chain_bytes), [0xB2; 32])
                .is_err()
        );
    }

    #[test]
    #[ignore = "requires an elevated process and writes one isolated TPM NV test index"]
    fn real_tpm_guard_persists_advances_rejects_rollback_and_cleans_up() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("Vault-A1-CP1-WIN-{nonce}"));
        fs::create_dir(&directory).unwrap();
        let mut chain_bytes = [0xA1; 32];
        chain_bytes[..16].copy_from_slice(&nonce.to_be_bytes());
        let chain_id = ChainId::new(chain_bytes);
        let bootstrap_policy_id = [0xB2; 32];
        let first = CheckpointPolicyAnchor::from_parts(1, [0xC3; 32]);
        let second = CheckpointPolicyAnchor::from_parts(2, [0xD4; 32]);
        let third = CheckpointPolicyAnchor::from_parts(3, [0xE5; 32]);
        let alternate_third = CheckpointPolicyAnchor::from_parts(3, [0xF6; 32]);
        let mut guard = WindowsTpmRollbackGuard::new(&directory).unwrap();
        guard
            .provision_scope(chain_id, bootstrap_policy_id)
            .unwrap();
        assert_eq!(
            guard.load_anchor(chain_id, bootstrap_policy_id).unwrap(),
            None
        );
        guard
            .advance_anchor(chain_id, bootstrap_policy_id, first)
            .unwrap();
        assert_eq!(
            guard.load_anchor(chain_id, bootstrap_policy_id).unwrap(),
            Some(first)
        );
        let paths = ScopePaths::new(&directory, &scope_id(chain_id, bootstrap_policy_id));
        let generation_one_state = fs::read(&paths.state).unwrap();

        // An independent process cannot enter the same scope while its lock is held.
        let held_lock = ScopeLock::acquire(&paths.lock).unwrap();
        let contention = Command::new(std::env::current_exe().unwrap())
            .arg("windows_tpm_guard::tests::real_tpm_scope_lock_child_fails_closed")
            .arg("--exact")
            .arg("--ignored")
            .env("VAULT_WINDOWS_TPM_TEST_DIRECTORY", &directory)
            .env("VAULT_WINDOWS_TPM_TEST_NONCE", nonce.to_string())
            .status()
            .unwrap();
        assert!(contention.success());
        drop(held_lock);

        guard
            .advance_anchor(chain_id, bootstrap_policy_id, first)
            .unwrap();

        // Crash before NV_Extend: the exact pending successor is replayed once.
        let state = read_state(&paths.state, chain_id, bootstrap_policy_id)
            .unwrap()
            .unwrap();
        let input = extend_input(
            chain_id,
            bootstrap_policy_id,
            state.nv_index,
            state.anchor,
            &state.nv_digest,
            second,
        );
        write_pending(
            &paths.pending,
            &PendingAdvance {
                chain_id,
                bootstrap_policy_id,
                nv_index: state.nv_index,
                old_anchor: state.anchor,
                old_digest: state.nv_digest,
                new_anchor: second,
                extend_input: input,
                expected_digest: extended_digest(&state.nv_digest, &input),
            },
        )
        .unwrap();
        assert_eq!(
            guard.load_anchor(chain_id, bootstrap_policy_id).unwrap(),
            Some(second)
        );
        assert!(!paths.pending.exists());

        // Crash after NV_Extend but before state commit: recovery observes the
        // exact expected TPM digest and commits without extending twice.
        let state = read_state(&paths.state, chain_id, bootstrap_policy_id)
            .unwrap()
            .unwrap();
        let input = extend_input(
            chain_id,
            bootstrap_policy_id,
            state.nv_index,
            state.anchor,
            &state.nv_digest,
            third,
        );
        write_pending(
            &paths.pending,
            &PendingAdvance {
                chain_id,
                bootstrap_policy_id,
                nv_index: state.nv_index,
                old_anchor: state.anchor,
                old_digest: state.nv_digest,
                new_anchor: third,
                extend_input: input,
                expected_digest: extended_digest(&state.nv_digest, &input),
            },
        )
        .unwrap();
        let key = TpmRsaKey::open(&key_name(
            &scope_id(chain_id, bootstrap_policy_id),
            &guard.directory,
        ))
        .unwrap();
        let authorization = key.decrypt(&state.sealed_authorization).unwrap();
        let mut tpm = Tpm::open().unwrap();
        tpm.extend(state.nv_index, &authorization, &input).unwrap();
        assert_eq!(
            guard.load_anchor(chain_id, bootstrap_policy_id).unwrap(),
            Some(third)
        );
        assert!(!paths.pending.exists());
        assert!(
            guard
                .advance_anchor(chain_id, bootstrap_policy_id, first)
                .is_err()
        );
        assert!(
            guard
                .advance_anchor(chain_id, bootstrap_policy_id, alternate_third)
                .is_err()
        );
        drop(guard);

        let mut reopened = WindowsTpmRollbackGuard::new(&directory).unwrap();
        assert_eq!(
            reopened.load_anchor(chain_id, bootstrap_policy_id).unwrap(),
            Some(third)
        );
        fs::write(&paths.state, generation_one_state).unwrap();
        assert!(reopened.load_anchor(chain_id, bootstrap_policy_id).is_err());

        // Restore the current state by replaying the exact expected file from
        // the pending-free in-memory transition, solely so cleanup can identify
        // the test index. The rollback assertion above already failed closed.
        // A fresh real test scope prevents this operation from touching users.
        let mut tpm = Tpm::open().unwrap();
        let rolled = read_state(&paths.state, chain_id, bootstrap_policy_id)
            .unwrap()
            .unwrap();
        let key = TpmRsaKey::open(&key_name(
            &scope_id(chain_id, bootstrap_policy_id),
            &reopened.directory,
        ))
        .unwrap();
        let authorization = key.decrypt(&rolled.sealed_authorization).unwrap();
        let NvDigestState::Value(current_digest) =
            tpm.read_digest(rolled.nv_index, &authorization).unwrap()
        else {
            panic!("test NV index unexpectedly uninitialized")
        };
        let cleanup_state = GuardState {
            anchor: Some(third),
            nv_digest: current_digest,
            ..rolled
        };
        write_state(&paths.state, &cleanup_state).unwrap();

        // Exact NV deletion stands in for the observable result of TPM clear:
        // an existing journal must never be accepted as a fresh lineage.
        let owner_authorization = tpm.owner_authorization().unwrap();
        tpm.undefine_index(cleanup_state.nv_index, &owner_authorization)
            .unwrap();
        assert!(reopened.load_anchor(chain_id, bootstrap_policy_id).is_err());
        reopened
            .cleanup_test_scope(chain_id, bootstrap_policy_id)
            .unwrap();
        drop(reopened);
        remove_optional_file(&paths.lock).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    const REBOOT_CHAIN_ID: ChainId = ChainId::new([0xA7; 32]);
    const REBOOT_BOOTSTRAP_POLICY_ID: [u8; 32] = [0xB8; 32];

    fn reboot_test_directory() -> PathBuf {
        std::env::temp_dir().join("Vault-A1-CP1-WIN-reboot-v1")
    }

    #[test]
    #[ignore = "phase one intentionally leaves one isolated TPM NV test index until reboot"]
    fn real_tpm_reboot_persistence_phase_one() {
        let directory = reboot_test_directory();
        assert!(
            !directory.exists(),
            "reboot acceptance state already exists; run phase two before restarting phase one"
        );
        fs::create_dir(&directory).unwrap();
        let first = CheckpointPolicyAnchor::from_parts(1, [0xC9; 32]);
        let mut guard = WindowsTpmRollbackGuard::new(&directory).unwrap();
        guard
            .provision_scope(REBOOT_CHAIN_ID, REBOOT_BOOTSTRAP_POLICY_ID)
            .unwrap();
        guard
            .advance_anchor(REBOOT_CHAIN_ID, REBOOT_BOOTSTRAP_POLICY_ID, first)
            .unwrap();
        drop(guard);
        let mut reopened = WindowsTpmRollbackGuard::new(&directory).unwrap();
        assert_eq!(
            reopened
                .load_anchor(REBOOT_CHAIN_ID, REBOOT_BOOTSTRAP_POLICY_ID)
                .unwrap(),
            Some(first)
        );
    }

    #[test]
    #[ignore = "run elevated only after phase one and a real Windows reboot"]
    fn real_tpm_reboot_persistence_phase_two_and_cleanup() {
        let directory = reboot_test_directory();
        assert!(
            directory.is_dir(),
            "reboot acceptance state is absent; run phase one before reboot"
        );
        let first = CheckpointPolicyAnchor::from_parts(1, [0xC9; 32]);
        let second = CheckpointPolicyAnchor::from_parts(2, [0xDA; 32]);
        let mut guard = WindowsTpmRollbackGuard::new(&directory).unwrap();
        assert_eq!(
            guard
                .load_anchor(REBOOT_CHAIN_ID, REBOOT_BOOTSTRAP_POLICY_ID)
                .unwrap(),
            Some(first)
        );
        guard
            .advance_anchor(REBOOT_CHAIN_ID, REBOOT_BOOTSTRAP_POLICY_ID, second)
            .unwrap();
        drop(guard);
        let reopened = WindowsTpmRollbackGuard::new(&directory).unwrap();
        let mut verifier = reopened;
        assert_eq!(
            verifier
                .load_anchor(REBOOT_CHAIN_ID, REBOOT_BOOTSTRAP_POLICY_ID)
                .unwrap(),
            Some(second)
        );
        verifier
            .cleanup_test_scope(REBOOT_CHAIN_ID, REBOOT_BOOTSTRAP_POLICY_ID)
            .unwrap();
        drop(verifier);
        fs::remove_dir(&directory).unwrap();
    }
}
