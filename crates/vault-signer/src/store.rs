use core::fmt;
use std::path::Path;

use blake3::Hasher;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::durable_file::{DurableFileError, LockedAtomicFile};
use crate::{DurableReplayGuard, SessionChallenge, SessionError};

const STORE_MAGIC: [u8; 4] = *b"VSRG";
const STORE_VERSION: u16 = 1;
const STORE_CHECKSUM_DOMAIN: &str = "vault.signer.replay-store.v1";
const STORE_BODY_BYTES: usize = 128;
const STORE_CHECKSUM_BYTES: usize = 32;
/// Exact fixed byte length of one durable replay-store state file.
pub const REPLAY_STORE_STATE_BYTES: usize = STORE_BODY_BYTES + STORE_CHECKSUM_BYTES;

/// Fail-closed software replay-store error. Filesystem details and paths are
/// deliberately not retained so they cannot leak through wallet diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayStoreError {
    /// No reviewed crash-consistent implementation exists for this platform.
    UnsupportedPlatform,
    /// The state path is relative, lacks a filename, or has an invalid parent.
    InvalidPath,
    /// The requested network or channel binding cannot form a valid challenge.
    InvalidChallengeParameters,
    /// Another process already owns the exclusive store lock.
    LockContended,
    /// Explicit initialization was requested for an already initialized path.
    StateAlreadyExists,
    /// Normal opening found no durable state and must not reset replay history.
    StateMissing,
    /// Existing state is truncated, non-canonical, or checksum-invalid.
    CorruptState,
    /// The durable 64-bit challenge counter cannot increase further.
    CounterExhausted,
    /// The challenge is not the exact currently pending challenge.
    ReplayDetected,
    /// An operating-system durability operation failed.
    IoFailure,
    /// A prior uncertain persistence failure permanently poisoned this handle.
    Poisoned,
}

impl fmt::Display for ReplayStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedPlatform => "replay store is unsupported on this platform",
            Self::InvalidPath => "invalid replay-store path",
            Self::InvalidChallengeParameters => "invalid replay-store challenge parameters",
            Self::LockContended => "replay store is already locked",
            Self::StateAlreadyExists => "replay-store state already exists",
            Self::StateMissing => "replay-store state is missing",
            Self::CorruptState => "replay-store state is invalid",
            Self::CounterExhausted => "replay-store counter exhausted",
            Self::ReplayDetected => "replay-store challenge mismatch",
            Self::IoFailure => "replay-store durability operation failed",
            Self::Poisoned => "replay store is poisoned",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ReplayStoreError {}

#[derive(Clone)]
struct PendingChallenge {
    network_id: [u8; 32],
    channel_binding: [u8; 32],
    session_id: [u8; 32],
    counter: u64,
}

impl PendingChallenge {
    fn from_challenge(challenge: &SessionChallenge) -> Self {
        Self {
            network_id: challenge.network_id(),
            channel_binding: challenge.channel_binding(),
            session_id: *challenge.session_id(),
            counter: challenge.counter(),
        }
    }

    fn matches(&self, challenge: &SessionChallenge) -> bool {
        let expected = self.encode_binding();
        let actual = Self::from_challenge(challenge).encode_binding();
        bool::from(expected.ct_eq(&actual))
    }

    fn encode_binding(&self) -> [u8; 104] {
        let mut bytes = [0; 104];
        bytes[..32].copy_from_slice(&self.network_id);
        bytes[32..64].copy_from_slice(&self.channel_binding);
        bytes[64..96].copy_from_slice(&self.session_id);
        bytes[96..104].copy_from_slice(&self.counter.to_le_bytes());
        bytes
    }
}

#[derive(Clone, Default)]
struct ReplayState {
    highest_issued: u64,
    highest_consumed: u64,
    pending: Option<PendingChallenge>,
}

impl ReplayState {
    fn encode(&self) -> [u8; REPLAY_STORE_STATE_BYTES] {
        let mut bytes = [0; REPLAY_STORE_STATE_BYTES];
        bytes[..4].copy_from_slice(&STORE_MAGIC);
        bytes[4..6].copy_from_slice(&STORE_VERSION.to_le_bytes());
        bytes[6] = u8::from(self.pending.is_some());
        bytes[7] = 0;
        bytes[8..16].copy_from_slice(&self.highest_issued.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.highest_consumed.to_le_bytes());
        if let Some(pending) = &self.pending {
            bytes[24..56].copy_from_slice(&pending.network_id);
            bytes[56..88].copy_from_slice(&pending.channel_binding);
            bytes[88..120].copy_from_slice(&pending.session_id);
            bytes[120..128].copy_from_slice(&pending.counter.to_le_bytes());
        }
        let checksum = state_checksum(&bytes[..STORE_BODY_BYTES]);
        bytes[STORE_BODY_BYTES..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8; REPLAY_STORE_STATE_BYTES]) -> Result<Self, ReplayStoreError> {
        if bytes[..4] != STORE_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| ReplayStoreError::CorruptState)?,
            ) != STORE_VERSION
            || bytes[7] != 0
            || bytes[6] > 1
        {
            return Err(ReplayStoreError::CorruptState);
        }
        let checksum = state_checksum(&bytes[..STORE_BODY_BYTES]);
        if !bool::from(checksum.ct_eq(&bytes[STORE_BODY_BYTES..])) {
            return Err(ReplayStoreError::CorruptState);
        }
        let highest_issued = u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| ReplayStoreError::CorruptState)?,
        );
        let highest_consumed = u64::from_le_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| ReplayStoreError::CorruptState)?,
        );
        if highest_consumed > highest_issued {
            return Err(ReplayStoreError::CorruptState);
        }
        let pending = if bytes[6] == 1 {
            let pending = PendingChallenge {
                network_id: bytes[24..56]
                    .try_into()
                    .map_err(|_| ReplayStoreError::CorruptState)?,
                channel_binding: bytes[56..88]
                    .try_into()
                    .map_err(|_| ReplayStoreError::CorruptState)?,
                session_id: bytes[88..120]
                    .try_into()
                    .map_err(|_| ReplayStoreError::CorruptState)?,
                counter: u64::from_le_bytes(
                    bytes[120..128]
                        .try_into()
                        .map_err(|_| ReplayStoreError::CorruptState)?,
                ),
            };
            if pending.network_id == [0; 32]
                || pending.channel_binding == [0; 32]
                || pending.session_id == [0; 32]
                || pending.counter != highest_issued
                || pending.counter <= highest_consumed
            {
                return Err(ReplayStoreError::CorruptState);
            }
            Some(pending)
        } else {
            if highest_consumed != highest_issued || bytes[24..128] != [0; 104] {
                return Err(ReplayStoreError::CorruptState);
            }
            None
        };
        Ok(Self {
            highest_issued,
            highest_consumed,
            pending,
        })
    }
}

fn state_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(STORE_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Single-owner software counter and exact-challenge store.
///
/// Each transition uses write + file sync + atomic rename + parent-directory
/// sync. This gives crash consistency on Unix filesystems that honor those
/// primitives. The checksum detects torn/corrupt files, not an attacker who can
/// restore an older valid snapshot; such rollback resistance requires protected
/// storage or the hardware monotonic-counter profile.
pub struct CrashConsistentReplayStore {
    file: LockedAtomicFile,
    state: ReplayState,
    poisoned: bool,
}

impl fmt::Debug for CrashConsistentReplayStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrashConsistentReplayStore")
            .field("highest_issued", &self.state.highest_issued)
            .field("highest_consumed", &self.state.highest_consumed)
            .field("has_pending", &self.state.pending.is_some())
            .field("path", &"REDACTED")
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl CrashConsistentReplayStore {
    /// Explicitly initializes a new absolute state path and takes a
    /// non-blocking exclusive process lock for the lifetime of this value.
    /// Existing state is never overwritten or interpreted as a new wallet.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, ReplayStoreError> {
        let file = LockedAtomicFile::open(path).map_err(map_durable_error)?;
        if file
            .read_bounded(REPLAY_STORE_STATE_BYTES)
            .map_err(map_durable_error)?
            .is_some()
        {
            return Err(ReplayStoreError::StateAlreadyExists);
        }
        let state = ReplayState::default();
        file.replace(&state.encode()).map_err(map_durable_error)?;
        Ok(Self {
            file,
            state,
            poisoned: false,
        })
    }

    /// Opens one existing absolute state path and takes a non-blocking
    /// exclusive process lock for the lifetime of this value. Missing state
    /// fails closed instead of silently resetting the replay counter.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayStoreError> {
        let file = LockedAtomicFile::open(path).map_err(map_durable_error)?;
        let bytes = file
            .read_bounded(REPLAY_STORE_STATE_BYTES)
            .map_err(map_durable_error)?
            .ok_or(ReplayStoreError::StateMissing)?;
        let bytes: [u8; REPLAY_STORE_STATE_BYTES] = bytes
            .try_into()
            .map_err(|_| ReplayStoreError::CorruptState)?;
        let state = ReplayState::decode(&bytes)?;
        Ok(Self {
            file,
            state,
            poisoned: false,
        })
    }

    /// Reserves and durably persists the next exact challenge before returning
    /// it to the signer transport. Issuing a new challenge invalidates any
    /// abandoned pending challenge and advances the counter again.
    pub fn issue_challenge<R: RngCore + CryptoRng>(
        &mut self,
        network_id: [u8; 32],
        channel_binding: [u8; 32],
        rng: &mut R,
    ) -> Result<SessionChallenge, ReplayStoreError> {
        if self.poisoned {
            return Err(ReplayStoreError::Poisoned);
        }
        let counter = self
            .state
            .highest_issued
            .checked_add(1)
            .ok_or(ReplayStoreError::CounterExhausted)?;
        let challenge = SessionChallenge::generate(network_id, channel_binding, counter, rng)
            .map_err(|_| ReplayStoreError::InvalidChallengeParameters)?;
        let mut candidate = self.state.clone();
        candidate.highest_issued = counter;
        candidate.pending = Some(PendingChallenge::from_challenge(&challenge));
        self.commit(candidate)?;
        Ok(challenge)
    }

    /// Consumes only the currently pending byte-exact challenge and persists
    /// that transition before returning success.
    pub fn consume_challenge(
        &mut self,
        challenge: &SessionChallenge,
    ) -> Result<(), ReplayStoreError> {
        if self.poisoned {
            return Err(ReplayStoreError::Poisoned);
        }
        let pending = self
            .state
            .pending
            .as_ref()
            .ok_or(ReplayStoreError::ReplayDetected)?;
        if !pending.matches(challenge)
            || challenge.counter() != self.state.highest_issued
            || challenge.counter() <= self.state.highest_consumed
        {
            return Err(ReplayStoreError::ReplayDetected);
        }
        let mut candidate = self.state.clone();
        candidate.highest_consumed = challenge.counter();
        candidate.pending = None;
        self.commit(candidate)
    }

    /// Highest challenge counter durably reserved by this store.
    #[must_use]
    pub const fn highest_issued(&self) -> u64 {
        self.state.highest_issued
    }

    /// Highest exact challenge durably consumed by this store.
    #[must_use]
    pub const fn highest_consumed(&self) -> u64 {
        self.state.highest_consumed
    }

    fn commit(&mut self, candidate: ReplayState) -> Result<(), ReplayStoreError> {
        if let Err(error) = self
            .file
            .replace(&candidate.encode())
            .map_err(map_durable_error)
        {
            self.poisoned = true;
            return Err(error);
        }
        self.state = candidate;
        Ok(())
    }
}

impl DurableReplayGuard for CrashConsistentReplayStore {
    fn consume(&mut self, challenge: &SessionChallenge) -> Result<(), SessionError> {
        match self.consume_challenge(challenge) {
            Ok(()) => Ok(()),
            Err(ReplayStoreError::ReplayDetected) => Err(SessionError::ReplayDetected),
            Err(_) => Err(SessionError::ReplayStoreFailure),
        }
    }
}

fn map_durable_error(error: DurableFileError) -> ReplayStoreError {
    match error {
        #[cfg(not(unix))]
        DurableFileError::UnsupportedPlatform => ReplayStoreError::UnsupportedPlatform,
        DurableFileError::InvalidPath => ReplayStoreError::InvalidPath,
        DurableFileError::LockContended => ReplayStoreError::LockContended,
        DurableFileError::CorruptFile => ReplayStoreError::CorruptState,
        DurableFileError::IoFailure => ReplayStoreError::IoFailure,
    }
}
