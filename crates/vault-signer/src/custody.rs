//! Protected signer identity and rollback-resistant replay-state contracts.

use core::fmt;

use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    DurableReplayGuard, PeerRegistryId, PeerRegistryScope, PeerRegistryStorageKey,
    SessionChallenge, SessionError, SignerPairingRole, SignerTransportKeyPair,
};

const KEY_MATERIAL_MAGIC: [u8; 4] = *b"VSKM";
const KEY_MATERIAL_VERSION: u16 = 1;
/// Exact fixed length of one protected signer identity record.
pub const SIGNER_PROTECTED_KEY_MATERIAL_BYTES: usize = 136;

const REPLAY_STATE_MAGIC: [u8; 4] = *b"VSRS";
const REPLAY_STATE_VERSION: u16 = 1;
/// Exact fixed length of one rollback-resistant signer replay record.
pub const SIGNER_SECURE_REPLAY_STATE_BYTES: usize = 136;

/// Complete signer identity held by one protected platform slot.
///
/// The transport private key and peer-registry storage key are zeroized on
/// drop and this type is intentionally not `Clone`. The network, role, and
/// registry ID travel with the keys so an adapter cannot silently reuse key
/// bytes under another signer scope.
pub struct SignerProtectedKeyMaterial {
    network_id: [u8; 32],
    role: SignerPairingRole,
    transport: SignerTransportKeyPair,
    registry_storage_key: PeerRegistryStorageKey,
    registry_id: PeerRegistryId,
}

impl fmt::Debug for SignerProtectedKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignerProtectedKeyMaterial(REDACTED)")
    }
}

impl SignerProtectedKeyMaterial {
    /// Generates all independent signer identity material in one exact scope.
    pub fn generate<R: RngCore + CryptoRng>(
        network_id: [u8; 32],
        role: SignerPairingRole,
        rng: &mut R,
    ) -> Result<Self, SignerProtectedKeyMaterialError> {
        if network_id == [0; 32] {
            return Err(SignerProtectedKeyMaterialError::InvalidMaterial);
        }
        for _ in 0..=u16::MAX {
            let transport = SignerTransportKeyPair::generate(rng);
            if transport.export_private().as_ref() == [0; 32] {
                continue;
            }
            let registry_storage_key = PeerRegistryStorageKey::generate(rng)
                .map_err(|_| SignerProtectedKeyMaterialError::EntropyUnavailable)?;
            let registry_id = PeerRegistryId::generate(rng)
                .map_err(|_| SignerProtectedKeyMaterialError::EntropyUnavailable)?;
            return Self::from_parts(
                network_id,
                role,
                transport,
                registry_storage_key,
                registry_id,
            );
        }
        Err(SignerProtectedKeyMaterialError::EntropyUnavailable)
    }

    /// Combines independently restored keys and validates their exact scope.
    pub fn from_parts(
        network_id: [u8; 32],
        role: SignerPairingRole,
        transport: SignerTransportKeyPair,
        registry_storage_key: PeerRegistryStorageKey,
        registry_id: PeerRegistryId,
    ) -> Result<Self, SignerProtectedKeyMaterialError> {
        if network_id == [0; 32]
            || transport.export_private().as_ref() == [0; 32]
            || PeerRegistryScope::new(network_id, role, &transport, registry_id).is_err()
        {
            return Err(SignerProtectedKeyMaterialError::InvalidMaterial);
        }
        Ok(Self {
            network_id,
            role,
            transport,
            registry_storage_key,
            registry_id,
        })
    }

    /// Parses an exact protected record and zeroizes the caller-owned buffer.
    pub fn from_bytes(
        bytes: &mut [u8; SIGNER_PROTECTED_KEY_MATERIAL_BYTES],
    ) -> Result<Self, SignerProtectedKeyMaterialError> {
        let result = (|| {
            if bytes[..4] != KEY_MATERIAL_MAGIC
                || u16::from_le_bytes(
                    bytes[4..6]
                        .try_into()
                        .map_err(|_| SignerProtectedKeyMaterialError::InvalidMaterial)?,
                ) != KEY_MATERIAL_VERSION
                || bytes[7] != 0
            {
                return Err(SignerProtectedKeyMaterialError::InvalidMaterial);
            }
            let role = match bytes[6] {
                0 => SignerPairingRole::Coordinator,
                1 => SignerPairingRole::Signer,
                _ => return Err(SignerProtectedKeyMaterialError::InvalidMaterial),
            };
            let network_id = bytes[8..40]
                .try_into()
                .map_err(|_| SignerProtectedKeyMaterialError::InvalidMaterial)?;
            let transport = SignerTransportKeyPair::from_private(
                bytes[40..72]
                    .try_into()
                    .map_err(|_| SignerProtectedKeyMaterialError::InvalidMaterial)?,
            )
            .map_err(|_| SignerProtectedKeyMaterialError::InvalidMaterial)?;
            let registry_storage_key = PeerRegistryStorageKey::from_bytes(
                bytes[72..104]
                    .try_into()
                    .map_err(|_| SignerProtectedKeyMaterialError::InvalidMaterial)?,
            )
            .map_err(|_| SignerProtectedKeyMaterialError::InvalidMaterial)?;
            let registry_id = PeerRegistryId::from_bytes(
                bytes[104..136]
                    .try_into()
                    .map_err(|_| SignerProtectedKeyMaterialError::InvalidMaterial)?,
            )
            .map_err(|_| SignerProtectedKeyMaterialError::InvalidMaterial)?;
            Self::from_parts(
                network_id,
                role,
                transport,
                registry_storage_key,
                registry_id,
            )
        })();
        bytes.zeroize();
        result
    }

    /// Serializes the exact record for a protected platform adapter only.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; SIGNER_PROTECTED_KEY_MATERIAL_BYTES]> {
        let mut bytes = Zeroizing::new([0; SIGNER_PROTECTED_KEY_MATERIAL_BYTES]);
        bytes[..4].copy_from_slice(&KEY_MATERIAL_MAGIC);
        bytes[4..6].copy_from_slice(&KEY_MATERIAL_VERSION.to_le_bytes());
        bytes[6] = self.role as u8;
        bytes[8..40].copy_from_slice(&self.network_id);
        bytes[40..72].copy_from_slice(self.transport.export_private().as_ref());
        bytes[72..104].copy_from_slice(self.registry_storage_key.export().as_ref());
        bytes[104..136].copy_from_slice(&self.registry_id.to_bytes());
        bytes
    }

    /// Network domain bound to this protected identity.
    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Stable coordinator/signer role bound to this protected identity.
    #[must_use]
    pub const fn role(&self) -> SignerPairingRole {
        self.role
    }

    /// Dedicated Noise transport identity.
    #[must_use]
    pub const fn transport(&self) -> &SignerTransportKeyPair {
        &self.transport
    }

    /// Dedicated peer-registry encryption key.
    #[must_use]
    pub const fn registry_storage_key(&self) -> &PeerRegistryStorageKey {
        &self.registry_storage_key
    }

    /// Registry substitution-prevention domain.
    #[must_use]
    pub const fn registry_id(&self) -> PeerRegistryId {
        self.registry_id
    }

    /// Exact authenticated registry scope reconstructed from this record.
    pub fn registry_scope(&self) -> Result<PeerRegistryScope, SignerProtectedKeyMaterialError> {
        PeerRegistryScope::new(
            self.network_id,
            self.role,
            &self.transport,
            self.registry_id,
        )
        .map_err(|_| SignerProtectedKeyMaterialError::InvalidMaterial)
    }

    fn matches(&self, other: &Self) -> bool {
        bool::from(self.to_bytes().as_ref().ct_eq(other.to_bytes().as_ref()))
    }
}

/// Invalid or unavailable protected signer identity material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerProtectedKeyMaterialError {
    /// The canonical record or one of its keys/scopes is invalid.
    InvalidMaterial,
    /// The CSPRNG could not produce valid independent material.
    EntropyUnavailable,
}

impl fmt::Display for SignerProtectedKeyMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidMaterial => "protected signer key material is invalid",
            Self::EntropyUnavailable => "protected signer key entropy is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SignerProtectedKeyMaterialError {}

/// Protected platform slot for exactly one complete signer identity.
///
/// `create` must be no-clobber, durable, rollback-resistant, and bound to the
/// intended application, user, and wallet/signer slot. Implementations must
/// document authentication prompts, lock state, synchronization, backup,
/// recovery, process-memory exposure, and crash-dump behavior. Plain files and
/// password-derived storage do not satisfy this contract.
pub trait SignerProtectedKeyStore {
    /// Platform adapter failure.
    type Error: std::error::Error;

    /// Stores the complete record only when the protected slot is empty.
    fn create(&mut self, material: &SignerProtectedKeyMaterial) -> Result<bool, Self::Error>;

    /// Loads the complete record into zeroizing process memory.
    fn load(&mut self) -> Result<Option<SignerProtectedKeyMaterial>, Self::Error>;
}

/// Signer keys loaded through an enrolled protected platform slot.
pub struct ProtectedSignerKeys<S> {
    material: SignerProtectedKeyMaterial,
    store: S,
}

impl<S> fmt::Debug for ProtectedSignerKeys<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedSignerKeys(REDACTED)")
    }
}

impl<S: SignerProtectedKeyStore> ProtectedSignerKeys<S> {
    /// Enrolls a newly generated/recovered identity into an empty slot.
    pub fn enroll(
        material: SignerProtectedKeyMaterial,
        mut store: S,
    ) -> Result<Self, SignerProtectedKeyStoreError<S::Error>> {
        if store
            .load()
            .map_err(SignerProtectedKeyStoreError::SecureStore)?
            .is_some()
        {
            return Err(SignerProtectedKeyStoreError::AlreadyEnrolled);
        }
        if !store
            .create(&material)
            .map_err(SignerProtectedKeyStoreError::SecureStore)?
        {
            return Err(SignerProtectedKeyStoreError::ConcurrentModification);
        }
        let persisted = store
            .load()
            .map_err(SignerProtectedKeyStoreError::SecureStore)?
            .ok_or(SignerProtectedKeyStoreError::ConcurrentModification)?;
        if !material.matches(&persisted) {
            return Err(SignerProtectedKeyStoreError::ConcurrentModification);
        }
        Ok(Self {
            material: persisted,
            store,
        })
    }

    /// Opens an existing protected identity; missing state never regenerates.
    pub fn open(mut store: S) -> Result<Self, SignerProtectedKeyStoreError<S::Error>> {
        let material = store
            .load()
            .map_err(SignerProtectedKeyStoreError::SecureStore)?
            .ok_or(SignerProtectedKeyStoreError::NotEnrolled)?;
        Ok(Self { material, store })
    }

    /// Validated protected signer identity.
    #[must_use]
    pub const fn material(&self) -> &SignerProtectedKeyMaterial {
        &self.material
    }

    /// Returns the validated material and its platform adapter.
    #[must_use]
    pub fn into_parts(self) -> (SignerProtectedKeyMaterial, S) {
        (self.material, self.store)
    }
}

/// Failure while enrolling or opening protected signer keys.
pub enum SignerProtectedKeyStoreError<E> {
    /// Platform secure-store adapter failed.
    SecureStore(E),
    /// Enrollment found an existing protected record.
    AlreadyEnrolled,
    /// Normal opening found no protected record.
    NotEnrolled,
    /// No-clobber creation or read-back observed an unexpected value.
    ConcurrentModification,
}

impl<E> fmt::Debug for SignerProtectedKeyStoreError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SecureStore(_) => "SignerProtectedKeyStoreError::SecureStore(REDACTED)",
            Self::AlreadyEnrolled => "SignerProtectedKeyStoreError::AlreadyEnrolled",
            Self::NotEnrolled => "SignerProtectedKeyStoreError::NotEnrolled",
            Self::ConcurrentModification => "SignerProtectedKeyStoreError::ConcurrentModification",
        })
    }
}

impl<E> fmt::Display for SignerProtectedKeyStoreError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SecureStore(_) => "protected signer key store failed",
            Self::AlreadyEnrolled => "protected signer key slot is already enrolled",
            Self::NotEnrolled => "protected signer key slot is not enrolled",
            Self::ConcurrentModification => "protected signer key slot changed concurrently",
        };
        formatter.write_str(message)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SignerProtectedKeyStoreError<E> {}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SecurePendingChallenge {
    network_id: [u8; 32],
    channel_binding: [u8; 32],
    session_id: [u8; 32],
    counter: u64,
}

impl SecurePendingChallenge {
    fn from_challenge(challenge: &SessionChallenge) -> Self {
        Self {
            network_id: challenge.network_id(),
            channel_binding: challenge.channel_binding(),
            session_id: *challenge.session_id(),
            counter: challenge.counter(),
        }
    }

    fn matches(&self, challenge: &SessionChallenge) -> bool {
        let expected = self.binding();
        let actual = Self::from_challenge(challenge).binding();
        bool::from(expected.ct_eq(&actual))
    }

    fn binding(&self) -> [u8; 104] {
        let mut bytes = [0; 104];
        bytes[..32].copy_from_slice(&self.network_id);
        bytes[32..64].copy_from_slice(&self.channel_binding);
        bytes[64..96].copy_from_slice(&self.session_id);
        bytes[96..104].copy_from_slice(&self.counter.to_le_bytes());
        bytes
    }
}

/// Canonical complete replay state protected by one platform adapter.
///
/// Every issue and consumption transition increments `generation`. The secure
/// store protects this entire value atomically; the generation is not a host-
/// file checksum or a substitute for a hardware/platform rollback primitive.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SignerSecureReplayState {
    generation: u64,
    highest_issued: u64,
    highest_consumed: u64,
    pending: Option<SecurePendingChallenge>,
}

impl fmt::Debug for SignerSecureReplayState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignerSecureReplayState(REDACTED)")
    }
}

impl SignerSecureReplayState {
    const fn initial() -> Self {
        Self {
            generation: 1,
            highest_issued: 0,
            highest_consumed: 0,
            pending: None,
        }
    }

    /// Monotonic secure-state transition generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Highest challenge counter durably issued.
    #[must_use]
    pub const fn highest_issued(self) -> u64 {
        self.highest_issued
    }

    /// Highest exact challenge durably consumed.
    #[must_use]
    pub const fn highest_consumed(self) -> u64 {
        self.highest_consumed
    }

    /// Whether one exact issued challenge is pending consumption.
    #[must_use]
    pub const fn has_pending(self) -> bool {
        self.pending.is_some()
    }

    /// Exact canonical protected-platform encoding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; SIGNER_SECURE_REPLAY_STATE_BYTES] {
        let mut bytes = [0; SIGNER_SECURE_REPLAY_STATE_BYTES];
        bytes[..4].copy_from_slice(&REPLAY_STATE_MAGIC);
        bytes[4..6].copy_from_slice(&REPLAY_STATE_VERSION.to_le_bytes());
        bytes[6] = u8::from(self.pending.is_some());
        bytes[8..16].copy_from_slice(&self.generation.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.highest_issued.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.highest_consumed.to_le_bytes());
        if let Some(pending) = self.pending {
            bytes[32..64].copy_from_slice(&pending.network_id);
            bytes[64..96].copy_from_slice(&pending.channel_binding);
            bytes[96..128].copy_from_slice(&pending.session_id);
            bytes[128..136].copy_from_slice(&pending.counter.to_le_bytes());
        }
        bytes
    }

    /// Parses and validates the exact protected-platform encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignerSecureReplayStateError> {
        if bytes.len() != SIGNER_SECURE_REPLAY_STATE_BYTES
            || bytes[..4] != REPLAY_STATE_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| SignerSecureReplayStateError)?,
            ) != REPLAY_STATE_VERSION
            || bytes[6] > 1
            || bytes[7] != 0
        {
            return Err(SignerSecureReplayStateError);
        }
        let generation = u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| SignerSecureReplayStateError)?,
        );
        let highest_issued = u64::from_le_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| SignerSecureReplayStateError)?,
        );
        let highest_consumed = u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .map_err(|_| SignerSecureReplayStateError)?,
        );
        let pending = if bytes[6] == 1 {
            Some(SecurePendingChallenge {
                network_id: bytes[32..64]
                    .try_into()
                    .map_err(|_| SignerSecureReplayStateError)?,
                channel_binding: bytes[64..96]
                    .try_into()
                    .map_err(|_| SignerSecureReplayStateError)?,
                session_id: bytes[96..128]
                    .try_into()
                    .map_err(|_| SignerSecureReplayStateError)?,
                counter: u64::from_le_bytes(
                    bytes[128..136]
                        .try_into()
                        .map_err(|_| SignerSecureReplayStateError)?,
                ),
            })
        } else {
            if bytes[32..].iter().any(|byte| *byte != 0) {
                return Err(SignerSecureReplayStateError);
            }
            None
        };
        let state = Self {
            generation,
            highest_issued,
            highest_consumed,
            pending,
        };
        if !state.is_valid() {
            return Err(SignerSecureReplayStateError);
        }
        Ok(state)
    }

    fn is_valid(self) -> bool {
        if self.generation == 0 || self.highest_consumed > self.highest_issued {
            return false;
        }
        match self.pending {
            Some(pending) => {
                pending.network_id != [0; 32]
                    && pending.channel_binding != [0; 32]
                    && pending.session_id != [0; 32]
                    && pending.counter == self.highest_issued
                    && pending.counter > self.highest_consumed
            }
            None => self.highest_consumed == self.highest_issued,
        }
    }
}

/// Invalid canonical rollback-resistant signer replay record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerSecureReplayStateError;

impl fmt::Display for SignerSecureReplayStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secure signer replay state is invalid")
    }
}

impl std::error::Error for SignerSecureReplayStateError {}

/// Atomic, durable, rollback-resistant platform state for one signer slot.
///
/// `compare_and_swap` must replace the complete 136-byte logical state only
/// when it exactly equals `expected`, survive process/device restart and power
/// loss, and reject host-controlled restoration of any older valid state. A
/// plain file, file checksum, ordinary database transaction, or volatile lock
/// does not implement this contract. A secure-element adapter may combine a
/// monotonic counter with an authenticated sealed record, but must expose the
/// same atomic semantics and document counter lifetime/exhaustion.
pub trait SignerSecureReplayStore {
    /// Platform adapter failure.
    type Error: std::error::Error;

    /// Loads the complete protected state, or `None` for an unused slot.
    fn load(&mut self) -> Result<Option<SignerSecureReplayState>, Self::Error>;

    /// Atomically compares and replaces the complete protected state.
    fn compare_and_swap(
        &mut self,
        expected: Option<&SignerSecureReplayState>,
        replacement: &SignerSecureReplayState,
    ) -> Result<bool, Self::Error>;
}

/// Replay guard whose complete state is owned by a rollback-resistant adapter.
pub struct RollbackProtectedReplayStore<S> {
    store: S,
    state: SignerSecureReplayState,
    poisoned: bool,
}

impl<S> fmt::Debug for RollbackProtectedReplayStore<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RollbackProtectedReplayStore")
            .field("generation", &self.state.generation)
            .field("highest_issued", &self.state.highest_issued)
            .field("highest_consumed", &self.state.highest_consumed)
            .field("has_pending", &self.state.pending.is_some())
            .field("platform_state", &"REDACTED")
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl<S: SignerSecureReplayStore> RollbackProtectedReplayStore<S> {
    /// Enrolls one empty secure slot; existing state is never overwritten.
    pub fn enroll(mut store: S) -> Result<Self, SignerSecureReplayError<S::Error>> {
        if store
            .load()
            .map_err(SignerSecureReplayError::SecureStore)?
            .is_some()
        {
            return Err(SignerSecureReplayError::AlreadyEnrolled);
        }
        let state = SignerSecureReplayState::initial();
        if !store
            .compare_and_swap(None, &state)
            .map_err(SignerSecureReplayError::SecureStore)?
        {
            return Err(SignerSecureReplayError::ConcurrentModification);
        }
        if store.load().map_err(SignerSecureReplayError::SecureStore)? != Some(state) {
            return Err(SignerSecureReplayError::ConcurrentModification);
        }
        Ok(Self {
            store,
            state,
            poisoned: false,
        })
    }

    /// Opens enrolled secure state; missing state never resets replay history.
    pub fn open(mut store: S) -> Result<Self, SignerSecureReplayError<S::Error>> {
        let state = store
            .load()
            .map_err(SignerSecureReplayError::SecureStore)?
            .ok_or(SignerSecureReplayError::NotEnrolled)?;
        Ok(Self {
            store,
            state,
            poisoned: false,
        })
    }

    /// Reserves a fresh exact challenge through one secure CAS transition.
    pub fn issue_challenge<R: RngCore + CryptoRng>(
        &mut self,
        network_id: [u8; 32],
        channel_binding: [u8; 32],
        rng: &mut R,
    ) -> Result<SessionChallenge, SignerSecureReplayError<S::Error>> {
        if self.poisoned {
            return Err(SignerSecureReplayError::Poisoned);
        }
        let generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(SignerSecureReplayError::GenerationExhausted)?;
        let counter = self
            .state
            .highest_issued
            .checked_add(1)
            .ok_or(SignerSecureReplayError::CounterExhausted)?;
        let challenge = SessionChallenge::generate(network_id, channel_binding, counter, rng)
            .map_err(|_| SignerSecureReplayError::InvalidChallengeParameters)?;
        let candidate = SignerSecureReplayState {
            generation,
            highest_issued: counter,
            highest_consumed: self.state.highest_consumed,
            pending: Some(SecurePendingChallenge::from_challenge(&challenge)),
        };
        self.commit(candidate)?;
        Ok(challenge)
    }

    /// Consumes only the exact pending challenge through one secure CAS.
    pub fn consume_challenge(
        &mut self,
        challenge: &SessionChallenge,
    ) -> Result<(), SignerSecureReplayError<S::Error>> {
        if self.poisoned {
            return Err(SignerSecureReplayError::Poisoned);
        }
        let pending = self
            .state
            .pending
            .as_ref()
            .ok_or(SignerSecureReplayError::ReplayDetected)?;
        if !pending.matches(challenge)
            || challenge.counter() != self.state.highest_issued
            || challenge.counter() <= self.state.highest_consumed
        {
            return Err(SignerSecureReplayError::ReplayDetected);
        }
        let candidate = SignerSecureReplayState {
            generation: self
                .state
                .generation
                .checked_add(1)
                .ok_or(SignerSecureReplayError::GenerationExhausted)?,
            highest_issued: self.state.highest_issued,
            highest_consumed: challenge.counter(),
            pending: None,
        };
        self.commit(candidate)
    }

    /// Current complete protected state, for adapter lifecycle diagnostics.
    #[must_use]
    pub const fn state(&self) -> SignerSecureReplayState {
        self.state
    }

    fn commit(
        &mut self,
        candidate: SignerSecureReplayState,
    ) -> Result<(), SignerSecureReplayError<S::Error>> {
        match self.store.compare_and_swap(Some(&self.state), &candidate) {
            Ok(true) => {
                self.state = candidate;
                Ok(())
            }
            Ok(false) => {
                self.poisoned = true;
                Err(SignerSecureReplayError::ConcurrentModification)
            }
            Err(error) => {
                self.poisoned = true;
                Err(SignerSecureReplayError::SecureStore(error))
            }
        }
    }
}

impl<S: SignerSecureReplayStore> DurableReplayGuard for RollbackProtectedReplayStore<S> {
    fn consume(&mut self, challenge: &SessionChallenge) -> Result<(), SessionError> {
        match self.consume_challenge(challenge) {
            Ok(()) => Ok(()),
            Err(SignerSecureReplayError::ReplayDetected) => Err(SessionError::ReplayDetected),
            Err(_) => Err(SessionError::ReplayStoreFailure),
        }
    }
}

/// Rollback-resistant replay-store failure.
pub enum SignerSecureReplayError<E> {
    /// Platform secure-state adapter failed.
    SecureStore(E),
    /// Enrollment found an existing secure state.
    AlreadyEnrolled,
    /// Normal opening found no secure state.
    NotEnrolled,
    /// Secure CAS observed a different current state.
    ConcurrentModification,
    /// The challenge counter cannot increase further.
    CounterExhausted,
    /// The secure transition generation cannot increase further.
    GenerationExhausted,
    /// Network/channel inputs could not form a valid challenge.
    InvalidChallengeParameters,
    /// The challenge is not the exact currently pending challenge.
    ReplayDetected,
    /// A prior uncertain store transition poisoned this handle.
    Poisoned,
}

impl<E> fmt::Debug for SignerSecureReplayError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SecureStore(_) => "SignerSecureReplayError::SecureStore(REDACTED)",
            Self::AlreadyEnrolled => "SignerSecureReplayError::AlreadyEnrolled",
            Self::NotEnrolled => "SignerSecureReplayError::NotEnrolled",
            Self::ConcurrentModification => "SignerSecureReplayError::ConcurrentModification",
            Self::CounterExhausted => "SignerSecureReplayError::CounterExhausted",
            Self::GenerationExhausted => "SignerSecureReplayError::GenerationExhausted",
            Self::InvalidChallengeParameters => {
                "SignerSecureReplayError::InvalidChallengeParameters"
            }
            Self::ReplayDetected => "SignerSecureReplayError::ReplayDetected",
            Self::Poisoned => "SignerSecureReplayError::Poisoned",
        })
    }
}

impl<E> fmt::Display for SignerSecureReplayError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SecureStore(_) => "secure signer replay store failed",
            Self::AlreadyEnrolled => "secure signer replay slot is already enrolled",
            Self::NotEnrolled => "secure signer replay slot is not enrolled",
            Self::ConcurrentModification => "secure signer replay state changed concurrently",
            Self::CounterExhausted => "secure signer replay counter exhausted",
            Self::GenerationExhausted => "secure signer replay generation exhausted",
            Self::InvalidChallengeParameters => "invalid secure signer challenge parameters",
            Self::ReplayDetected => "secure signer challenge mismatch",
            Self::Poisoned => "secure signer replay store is poisoned",
        };
        formatter.write_str(message)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SignerSecureReplayError<E> {}
