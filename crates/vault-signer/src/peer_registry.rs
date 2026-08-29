use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

use blake3::Hasher;
use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::durable_file::{DurableFileError, LockedAtomicFile};
use crate::transport::SignerSessionGate;
use crate::{
    PAIRED_SIGNER_RECORD_BYTES, PairedSignerRecord, PairingFingerprint, PeerLifecycleAction,
    PeerLifecycleConfirmationFacts, SignerHandshake, SignerPairingRole, SignerTransportKeyPair,
    TrustedPeerConfirmation,
};

const REGISTRY_MAGIC: [u8; 4] = *b"VPRG";
const REGISTRY_VERSION: u16 = 1;
const REGISTRY_HEADER_BYTES: usize = 4 + 2 + 8 + 32 + 1 + 1 + 32 + 32 + 2;
const REGISTRY_ENTRY_BYTES: usize = 32 + 1 + 1 + 8 + 8 + PAIRED_SIGNER_RECORD_BYTES;
const ENVELOPE_MAGIC: [u8; 4] = *b"VPSE";
const ENVELOPE_VERSION: u16 = 1;
const ENVELOPE_ALGORITHM_XCHACHA20_POLY1305: u8 = 1;
const ENVELOPE_HEADER_BYTES: usize = 4 + 2 + 1 + 1 + 24 + 4;
const AEAD_TAG_BYTES: usize = 16;
const STORAGE_KEY_DERIVATION_DOMAIN: &str = "vault.signer.peer-registry.aead-key.v1";
const PEER_ID_DOMAIN: &str = "vault.signer.peer-id.v1";

/// Maximum retained active plus revoked peer identities. Revocation tombstones
/// are never silently discarded or reused.
pub const MAX_PAIRED_SIGNER_RECORDS: usize = 256;
/// Resource-policy cap on simultaneously active signer relationships.
pub const MAX_ACTIVE_PAIRED_SIGNERS: usize = 16;
const REGISTRY_PLAINTEXT_BYTES: usize =
    REGISTRY_HEADER_BYTES + REGISTRY_ENTRY_BYTES * MAX_PAIRED_SIGNER_RECORDS;
/// Exact constant byte length of the encrypted registry, independent of count.
pub const ENCRYPTED_PEER_REGISTRY_BYTES: usize =
    ENVELOPE_HEADER_BYTES + REGISTRY_PLAINTEXT_BYTES + AEAD_TAG_BYTES;

/// Opaque peer-registry failure. Cryptographic failures deliberately avoid
/// exposing which authenticated field was wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRegistryError {
    /// This platform has no reviewed durable-file profile.
    UnsupportedPlatform,
    /// The state path or its security properties are invalid.
    InvalidPath,
    /// Another process owns the stable registry lock.
    LockContended,
    /// Explicit initialization targeted an already initialized registry.
    StoreAlreadyExists,
    /// Normal opening found no registry and must not erase lifecycle history.
    StoreMissing,
    /// A caller supplied an all-zero storage key.
    InvalidStorageKey,
    /// Network, role, or local transport identity is invalid.
    InvalidScope,
    /// Envelope/registry framing or canonical state is invalid.
    InvalidStore,
    /// AEAD authentication failed, including when the wrong key/scope is used.
    AuthenticationFailed,
    /// The registry generation counter cannot advance.
    GenerationExhausted,
    /// The active or lifetime peer limit was reached.
    CapacityExceeded,
    /// This confirmed identity or remote static key is already tombstoned/known.
    PeerAlreadyKnown,
    /// The requested peer identifier does not exist.
    PeerNotFound,
    /// A revoked identity cannot open a channel or be revoked again.
    PeerRevoked,
    /// Rotation did not preserve the local network/role identity or fresh key.
    RotationRejected,
    /// Trusted peer-management confirmation rejected or failed.
    ConfirmationFailed,
    /// Entropy or AEAD processing could not produce the next envelope.
    CryptographicFailure,
    /// An operating-system durability operation failed.
    IoFailure,
    /// A prior uncertain persistence failure permanently poisoned this handle.
    Poisoned,
}

impl fmt::Display for PeerRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedPlatform => "peer registry is unsupported on this platform",
            Self::InvalidPath => "invalid peer-registry path",
            Self::LockContended => "peer registry is already locked",
            Self::StoreAlreadyExists => "peer-registry state already exists",
            Self::StoreMissing => "peer-registry state is missing",
            Self::InvalidStorageKey => "invalid peer-registry storage key",
            Self::InvalidScope => "invalid peer-registry scope",
            Self::InvalidStore => "invalid peer-registry state",
            Self::AuthenticationFailed => "peer-registry authentication failed",
            Self::GenerationExhausted => "peer-registry generation exhausted",
            Self::CapacityExceeded => "peer-registry capacity exceeded",
            Self::PeerAlreadyKnown => "peer identity is already known",
            Self::PeerNotFound => "peer identity was not found",
            Self::PeerRevoked => "peer identity is revoked",
            Self::RotationRejected => "peer rotation was rejected",
            Self::ConfirmationFailed => "trusted peer confirmation failed",
            Self::CryptographicFailure => "peer-registry cryptographic operation failed",
            Self::IoFailure => "peer-registry durability operation failed",
            Self::Poisoned => "peer registry is poisoned",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PeerRegistryError {}

/// Dedicated 256-bit secret supplied by an OS keychain, secure enclave, or
/// equivalent protected key store. It must not be password-derived without a
/// separately reviewed memory-hard KDF profile.
pub struct PeerRegistryStorageKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for PeerRegistryStorageKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerRegistryStorageKey(REDACTED)")
    }
}

impl PeerRegistryStorageKey {
    /// Generates a non-zero storage key with caller-supplied CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, PeerRegistryError> {
        for _ in 0..=u16::MAX {
            let mut key = [0; 32];
            rng.fill_bytes(&mut key);
            if key != [0; 32] {
                return Ok(Self(Zeroizing::new(key)));
            }
            key.zeroize();
        }
        Err(PeerRegistryError::CryptographicFailure)
    }

    /// Restores a protected storage key; the all-zero sentinel is forbidden.
    pub fn from_bytes(mut key: [u8; 32]) -> Result<Self, PeerRegistryError> {
        if key == [0; 32] {
            key.zeroize();
            return Err(PeerRegistryError::InvalidStorageKey);
        }
        Ok(Self(Zeroizing::new(key)))
    }

    /// Zeroizing copy for an explicitly protected backup/keychain adapter.
    #[must_use]
    pub fn export(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0)
    }
}

/// Fixed registry domain. A file belongs to one network, local role, and local
/// transport identity; cross-scope substitution fails AEAD authentication.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PeerRegistryScope {
    network_id: [u8; 32],
    role: SignerPairingRole,
    local_public: [u8; 32],
    registry_id: PeerRegistryId,
}

impl fmt::Debug for PeerRegistryScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRegistryScope")
            .field("role", &self.role)
            .field("identifiers", &"REDACTED")
            .finish()
    }
}

/// Random wallet/slot identifier that prevents valid ciphertext substitution
/// between registries sharing the same master key and transport scope.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PeerRegistryId([u8; 32]);

impl fmt::Debug for PeerRegistryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerRegistryId(REDACTED)")
    }
}

impl PeerRegistryId {
    /// Generates a non-zero identifier with caller-supplied CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, PeerRegistryError> {
        for _ in 0..=u16::MAX {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            if bytes != [0; 32] {
                return Ok(Self(bytes));
            }
            bytes.zeroize();
        }
        Err(PeerRegistryError::CryptographicFailure)
    }

    /// Restores the protected wallet metadata for this exact registry slot.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PeerRegistryError> {
        if bytes == [0; 32] {
            return Err(PeerRegistryError::InvalidScope);
        }
        Ok(Self(bytes))
    }

    /// Exact identifier bytes for protected wallet metadata backup.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl PeerRegistryScope {
    /// Constructs the exact local signer/coordinator scope.
    pub fn new(
        network_id: [u8; 32],
        role: SignerPairingRole,
        local: &SignerTransportKeyPair,
        registry_id: PeerRegistryId,
    ) -> Result<Self, PeerRegistryError> {
        if network_id == [0; 32] || local.public_key() == [0; 32] {
            return Err(PeerRegistryError::InvalidScope);
        }
        Ok(Self {
            network_id,
            role,
            local_public: local.public_key(),
            registry_id,
        })
    }

    /// Bound Vault network.
    #[must_use]
    pub const fn network_id(self) -> [u8; 32] {
        self.network_id
    }

    /// Bound local Noise role.
    #[must_use]
    pub const fn role(self) -> SignerPairingRole {
        self.role
    }

    /// Bound local static transport identity.
    #[must_use]
    pub const fn local_public_key(self) -> [u8; 32] {
        self.local_public
    }

    /// Caller-managed random wallet/slot identifier that prevents valid file
    /// substitution between registries sharing the same master key and scope.
    #[must_use]
    pub const fn registry_id(self) -> PeerRegistryId {
        self.registry_id
    }

    fn kdf_bytes(self) -> [u8; 97] {
        let mut bytes = [0; 97];
        bytes[..32].copy_from_slice(&self.network_id);
        bytes[32] = self.role as u8;
        bytes[33..65].copy_from_slice(&self.local_public);
        bytes[65..97].copy_from_slice(&self.registry_id.0);
        bytes
    }
}

/// Stable local identifier for one exact confirmed pairing record.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct PairedPeerId([u8; 32]);

impl PairedPeerId {
    /// Restores an identifier previously returned by this registry.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PeerRegistryError> {
        if bytes == [0; 32] {
            return Err(PeerRegistryError::PeerNotFound);
        }
        Ok(Self(bytes))
    }

    /// Exact identifier bytes for UI/storage references.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for PairedPeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedPeerId(REDACTED)")
    }
}

/// Durable lifecycle state. Revocation is represented by a retained tombstone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PairedPeerState {
    /// May open a confirmed KK handshake.
    Active = 0,
    /// Permanently blocked in this registry.
    Revoked = 1,
}

impl PairedPeerState {
    fn from_byte(value: u8) -> Result<Self, PeerRegistryError> {
        match value {
            0 => Ok(Self::Active),
            1 => Ok(Self::Revoked),
            _ => Err(PeerRegistryError::InvalidStore),
        }
    }
}

/// Redacted lifecycle view for trusted peer-management UX.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PairedPeerSummary {
    id: PairedPeerId,
    state: PairedPeerState,
    fingerprint: PairingFingerprint,
    created_generation: u64,
    revoked_generation: Option<u64>,
}

impl fmt::Debug for PairedPeerSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedPeerSummary")
            .field("state", &self.state)
            .field("created_generation", &self.created_generation)
            .field("revoked_generation", &self.revoked_generation)
            .field("identity", &"REDACTED")
            .finish()
    }
}

impl PairedPeerSummary {
    #[must_use]
    pub const fn id(self) -> PairedPeerId {
        self.id
    }

    #[must_use]
    pub const fn state(self) -> PairedPeerState {
        self.state
    }

    #[must_use]
    pub const fn fingerprint(self) -> PairingFingerprint {
        self.fingerprint
    }

    #[must_use]
    pub const fn created_generation(self) -> u64 {
        self.created_generation
    }

    #[must_use]
    pub const fn revoked_generation(self) -> Option<u64> {
        self.revoked_generation
    }
}

#[derive(Clone, Debug)]
struct PeerEntry {
    id: PairedPeerId,
    state: PairedPeerState,
    created_generation: u64,
    revoked_generation: u64,
    record: PairedSignerRecord,
}

impl PeerEntry {
    fn summary(&self) -> PairedPeerSummary {
        PairedPeerSummary {
            id: self.id,
            state: self.state,
            fingerprint: self.record.fingerprint(),
            created_generation: self.created_generation,
            revoked_generation: (self.revoked_generation != 0).then_some(self.revoked_generation),
        }
    }
}

#[derive(Clone, Debug)]
struct RegistryState {
    generation: u64,
    scope: PeerRegistryScope,
    entries: Vec<PeerEntry>,
}

impl RegistryState {
    fn empty(scope: PeerRegistryScope) -> Self {
        Self {
            generation: 1,
            scope,
            entries: Vec::new(),
        }
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(vec![0; REGISTRY_PLAINTEXT_BYTES]);
        bytes[..4].copy_from_slice(&REGISTRY_MAGIC);
        bytes[4..6].copy_from_slice(&REGISTRY_VERSION.to_le_bytes());
        bytes[6..14].copy_from_slice(&self.generation.to_le_bytes());
        bytes[14..46].copy_from_slice(&self.scope.network_id);
        bytes[46] = self.scope.role as u8;
        bytes[47] = 0;
        bytes[48..80].copy_from_slice(&self.scope.local_public);
        bytes[80..112].copy_from_slice(&self.scope.registry_id.0);
        bytes[112..114].copy_from_slice(
            &u16::try_from(self.entries.len())
                .expect("registry entry count is bounded")
                .to_le_bytes(),
        );
        let mut offset = REGISTRY_HEADER_BYTES;
        for entry in &self.entries {
            bytes[offset..offset + 32].copy_from_slice(&entry.id.0);
            bytes[offset + 32] = entry.state as u8;
            bytes[offset + 33] = 0;
            bytes[offset + 34..offset + 42]
                .copy_from_slice(&entry.created_generation.to_le_bytes());
            bytes[offset + 42..offset + 50]
                .copy_from_slice(&entry.revoked_generation.to_le_bytes());
            bytes[offset + 50..offset + REGISTRY_ENTRY_BYTES]
                .copy_from_slice(&entry.record.encode());
            offset += REGISTRY_ENTRY_BYTES;
        }
        bytes
    }

    fn decode(bytes: &[u8], expected_scope: PeerRegistryScope) -> Result<Self, PeerRegistryError> {
        if bytes.len() != REGISTRY_PLAINTEXT_BYTES
            || bytes[..4] != REGISTRY_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| PeerRegistryError::InvalidStore)?,
            ) != REGISTRY_VERSION
            || bytes[47] != 0
        {
            return Err(PeerRegistryError::InvalidStore);
        }
        let generation = u64::from_le_bytes(
            bytes[6..14]
                .try_into()
                .map_err(|_| PeerRegistryError::InvalidStore)?,
        );
        let network_id = bytes[14..46]
            .try_into()
            .map_err(|_| PeerRegistryError::InvalidStore)?;
        let role = match bytes[46] {
            0 => SignerPairingRole::Coordinator,
            1 => SignerPairingRole::Signer,
            _ => return Err(PeerRegistryError::InvalidStore),
        };
        let local_public = bytes[48..80]
            .try_into()
            .map_err(|_| PeerRegistryError::InvalidStore)?;
        let registry_id = PeerRegistryId::from_bytes(
            bytes[80..112]
                .try_into()
                .map_err(|_| PeerRegistryError::InvalidStore)?,
        )
        .map_err(|_| PeerRegistryError::InvalidStore)?;
        let scope = PeerRegistryScope {
            network_id,
            role,
            local_public,
            registry_id,
        };
        if scope != expected_scope || generation == 0 {
            return Err(PeerRegistryError::InvalidStore);
        }
        let count = usize::from(u16::from_le_bytes(
            bytes[112..114]
                .try_into()
                .map_err(|_| PeerRegistryError::InvalidStore)?,
        ));
        if count > MAX_PAIRED_SIGNER_RECORDS {
            return Err(PeerRegistryError::InvalidStore);
        }
        let used_end = REGISTRY_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(REGISTRY_ENTRY_BYTES)
                    .ok_or(PeerRegistryError::InvalidStore)?,
            )
            .ok_or(PeerRegistryError::InvalidStore)?;
        if bytes[used_end..].iter().any(|byte| *byte != 0) {
            return Err(PeerRegistryError::InvalidStore);
        }

        let mut entries = Vec::with_capacity(count);
        let mut offset = REGISTRY_HEADER_BYTES;
        for _ in 0..count {
            let id = PairedPeerId::from_bytes(
                bytes[offset..offset + 32]
                    .try_into()
                    .map_err(|_| PeerRegistryError::InvalidStore)?,
            )
            .map_err(|_| PeerRegistryError::InvalidStore)?;
            let state = PairedPeerState::from_byte(bytes[offset + 32])?;
            if bytes[offset + 33] != 0 {
                return Err(PeerRegistryError::InvalidStore);
            }
            let created_generation = u64::from_le_bytes(
                bytes[offset + 34..offset + 42]
                    .try_into()
                    .map_err(|_| PeerRegistryError::InvalidStore)?,
            );
            let revoked_generation = u64::from_le_bytes(
                bytes[offset + 42..offset + 50]
                    .try_into()
                    .map_err(|_| PeerRegistryError::InvalidStore)?,
            );
            let record =
                PairedSignerRecord::decode(&bytes[offset + 50..offset + REGISTRY_ENTRY_BYTES])
                    .map_err(|_| PeerRegistryError::InvalidStore)?;
            entries.push(PeerEntry {
                id,
                state,
                created_generation,
                revoked_generation,
                record,
            });
            offset += REGISTRY_ENTRY_BYTES;
        }
        let state = Self {
            generation,
            scope,
            entries,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), PeerRegistryError> {
        if self.generation == 0 || self.entries.len() > MAX_PAIRED_SIGNER_RECORDS {
            return Err(PeerRegistryError::InvalidStore);
        }
        let mut previous_id = None;
        let mut remote_keys = BTreeSet::new();
        let mut active_count = 0usize;
        for entry in &self.entries {
            if previous_id.is_some_and(|previous| previous >= entry.id)
                || entry.id != derive_peer_id(&entry.record)
                || entry.record.network_id() != self.scope.network_id
                || entry.record.role() != self.scope.role
                || entry.record.local_public_key() != self.scope.local_public
                || !remote_keys.insert(entry.record.remote_public_key())
                || entry.created_generation == 0
                || entry.created_generation > self.generation
            {
                return Err(PeerRegistryError::InvalidStore);
            }
            match entry.state {
                PairedPeerState::Active => {
                    if entry.revoked_generation != 0 {
                        return Err(PeerRegistryError::InvalidStore);
                    }
                    active_count += 1;
                }
                PairedPeerState::Revoked => {
                    if entry.revoked_generation < entry.created_generation
                        || entry.revoked_generation > self.generation
                    {
                        return Err(PeerRegistryError::InvalidStore);
                    }
                }
            }
            previous_id = Some(entry.id);
        }
        if active_count > MAX_ACTIVE_PAIRED_SIGNERS {
            return Err(PeerRegistryError::InvalidStore);
        }
        Ok(())
    }

    fn next_generation(&self) -> Result<u64, PeerRegistryError> {
        self.generation
            .checked_add(1)
            .ok_or(PeerRegistryError::GenerationExhausted)
    }

    fn ensure_new_record(
        &self,
        record: &PairedSignerRecord,
    ) -> Result<PairedPeerId, PeerRegistryError> {
        if record.network_id() != self.scope.network_id
            || record.role() != self.scope.role
            || record.local_public_key() != self.scope.local_public
        {
            return Err(PeerRegistryError::InvalidScope);
        }
        let id = derive_peer_id(record);
        if self.entries.iter().any(|entry| {
            entry.id == id || entry.record.remote_public_key() == record.remote_public_key()
        }) {
            return Err(PeerRegistryError::PeerAlreadyKnown);
        }
        Ok(id)
    }
}

/// Authenticated encrypted lifecycle registry for confirmed signer peers.
pub struct EncryptedPeerRegistry {
    file: LockedAtomicFile,
    aead_key: Zeroizing<[u8; 32]>,
    state: RegistryState,
    session_gates: BTreeMap<PairedPeerId, Arc<SignerSessionGate>>,
    poisoned: bool,
}

impl fmt::Debug for EncryptedPeerRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedPeerRegistry")
            .field("generation", &self.state.generation)
            .field("entry_count", &self.state.entries.len())
            .field("cryptographic_state", &"REDACTED")
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl EncryptedPeerRegistry {
    /// Explicitly creates one new fixed-size registry. Existing state is never
    /// overwritten or treated as a new wallet. The storage key remains outside
    /// the file and is reduced to a scope-separated in-memory AEAD subkey.
    pub fn create<R: RngCore + CryptoRng>(
        path: impl AsRef<Path>,
        storage_key: &PeerRegistryStorageKey,
        scope: PeerRegistryScope,
        rng: &mut R,
    ) -> Result<Self, PeerRegistryError> {
        let file = LockedAtomicFile::open(path).map_err(map_durable_error)?;
        let aead_key = derive_aead_key(storage_key, scope);
        if file
            .read_bounded(ENCRYPTED_PEER_REGISTRY_BYTES)
            .map_err(map_durable_error)?
            .is_some()
        {
            return Err(PeerRegistryError::StoreAlreadyExists);
        }
        let state = RegistryState::empty(scope);
        let envelope = seal_state(&state, &aead_key, rng)?;
        file.replace(&envelope).map_err(map_durable_error)?;
        Ok(Self {
            file,
            aead_key,
            state,
            session_gates: BTreeMap::new(),
            poisoned: false,
        })
    }

    /// Opens one existing fixed-size registry. Missing state fails closed so a
    /// deleted registry cannot silently discard revocation tombstones.
    pub fn open(
        path: impl AsRef<Path>,
        storage_key: &PeerRegistryStorageKey,
        scope: PeerRegistryScope,
    ) -> Result<Self, PeerRegistryError> {
        let file = LockedAtomicFile::open(path).map_err(map_durable_error)?;
        let aead_key = derive_aead_key(storage_key, scope);
        let envelope = file
            .read_bounded(ENCRYPTED_PEER_REGISTRY_BYTES)
            .map_err(map_durable_error)?
            .ok_or(PeerRegistryError::StoreMissing)?;
        let state = open_envelope(&envelope, &aead_key, scope)?;
        let session_gates = state
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.id,
                    SignerSessionGate::new(entry.state == PairedPeerState::Active),
                )
            })
            .collect();
        Ok(Self {
            file,
            aead_key,
            state,
            session_gates,
            poisoned: false,
        })
    }

    /// Current durable mutation generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.state.generation
    }

    /// Redacted lifecycle summaries in canonical peer-ID order.
    #[must_use]
    pub fn peers(&self) -> Vec<PairedPeerSummary> {
        self.state.entries.iter().map(PeerEntry::summary).collect()
    }

    /// Atomically adds an OOB-confirmed record. A remote static key is accepted
    /// only once over the registry lifetime, including revoked tombstones.
    pub fn add_confirmed<R: RngCore + CryptoRng>(
        &mut self,
        record: PairedSignerRecord,
        rng: &mut R,
    ) -> Result<PairedPeerId, PeerRegistryError> {
        self.ensure_usable()?;
        if self.state.entries.len() >= MAX_PAIRED_SIGNER_RECORDS
            || self.active_count() >= MAX_ACTIVE_PAIRED_SIGNERS
        {
            return Err(PeerRegistryError::CapacityExceeded);
        }
        let id = self.state.ensure_new_record(&record)?;
        let generation = self.state.next_generation()?;
        let mut candidate = self.state.clone();
        candidate.generation = generation;
        candidate.entries.push(PeerEntry {
            id,
            state: PairedPeerState::Active,
            created_generation: generation,
            revoked_generation: 0,
            record,
        });
        candidate.entries.sort_by_key(|entry| entry.id);
        self.commit(candidate, rng)?;
        self.session_gates.insert(id, SignerSessionGate::new(true));
        Ok(id)
    }

    /// Requires trusted confirmation, then atomically writes a permanent
    /// tombstone before returning success.
    pub fn revoke_confirmed<R, C>(
        &mut self,
        id: PairedPeerId,
        confirmation: &mut C,
        rng: &mut R,
    ) -> Result<(), PeerRegistryError>
    where
        R: RngCore + CryptoRng,
        C: TrustedPeerConfirmation,
    {
        self.ensure_usable()?;
        let index = self
            .state
            .entries
            .binary_search_by_key(&id, |entry| entry.id)
            .map_err(|_| PeerRegistryError::PeerNotFound)?;
        if self.state.entries[index].state == PairedPeerState::Revoked {
            return Err(PeerRegistryError::PeerRevoked);
        }
        let generation = self.state.next_generation()?;
        let facts = PeerLifecycleConfirmationFacts::new(
            PeerLifecycleAction::Revoke,
            self.state.scope.network_id,
            self.state.scope.role,
            id,
            self.state.entries[index].record.fingerprint(),
            None,
            self.state.generation,
        );
        confirmation
            .confirm_peer_lifecycle(&facts)
            .map_err(|_| PeerRegistryError::ConfirmationFailed)?;
        let mut candidate = self.state.clone();
        candidate.generation = generation;
        candidate.entries[index].state = PairedPeerState::Revoked;
        candidate.entries[index].revoked_generation = generation;
        self.session_gate(id)?.shut_down();
        self.commit(candidate, rng)
    }

    /// In one durable generation, tombstones an active peer and installs a
    /// freshly confirmed identity with a different remote static key.
    pub fn rotate_confirmed<R, C>(
        &mut self,
        old_id: PairedPeerId,
        replacement: PairedSignerRecord,
        confirmation: &mut C,
        rng: &mut R,
    ) -> Result<PairedPeerId, PeerRegistryError>
    where
        R: RngCore + CryptoRng,
        C: TrustedPeerConfirmation,
    {
        self.ensure_usable()?;
        if self.state.entries.len() >= MAX_PAIRED_SIGNER_RECORDS {
            return Err(PeerRegistryError::CapacityExceeded);
        }
        let old_index = self
            .state
            .entries
            .binary_search_by_key(&old_id, |entry| entry.id)
            .map_err(|_| PeerRegistryError::PeerNotFound)?;
        if self.state.entries[old_index].state != PairedPeerState::Active {
            return Err(PeerRegistryError::PeerRevoked);
        }
        let new_id = self
            .state
            .ensure_new_record(&replacement)
            .map_err(|error| match error {
                PeerRegistryError::InvalidScope | PeerRegistryError::PeerAlreadyKnown => {
                    PeerRegistryError::RotationRejected
                }
                other => other,
            })?;
        let generation = self.state.next_generation()?;
        let facts = PeerLifecycleConfirmationFacts::new(
            PeerLifecycleAction::Rotate,
            self.state.scope.network_id,
            self.state.scope.role,
            old_id,
            self.state.entries[old_index].record.fingerprint(),
            Some(replacement.fingerprint()),
            self.state.generation,
        );
        confirmation
            .confirm_peer_lifecycle(&facts)
            .map_err(|_| PeerRegistryError::ConfirmationFailed)?;
        let mut candidate = self.state.clone();
        candidate.generation = generation;
        candidate.entries[old_index].state = PairedPeerState::Revoked;
        candidate.entries[old_index].revoked_generation = generation;
        candidate.entries.push(PeerEntry {
            id: new_id,
            state: PairedPeerState::Active,
            created_generation: generation,
            revoked_generation: 0,
            record: replacement,
        });
        candidate.entries.sort_by_key(|entry| entry.id);
        self.session_gate(old_id)?.shut_down();
        self.commit(candidate, rng)?;
        self.session_gates
            .insert(new_id, SignerSessionGate::new(true));
        Ok(new_id)
    }

    /// Creates KK only for an active registry entry and the exact protected
    /// local key. Revoked records cannot be extracted and opened separately.
    pub fn open_handshake(
        &self,
        id: PairedPeerId,
        local: &SignerTransportKeyPair,
    ) -> Result<SignerHandshake, PeerRegistryError> {
        self.ensure_usable()?;
        let entry = self
            .state
            .entries
            .binary_search_by_key(&id, |entry| entry.id)
            .map(|index| &self.state.entries[index])
            .map_err(|_| PeerRegistryError::PeerNotFound)?;
        if entry.state != PairedPeerState::Active {
            return Err(PeerRegistryError::PeerRevoked);
        }
        let session_gate = Arc::clone(self.session_gate(id)?);
        entry
            .record
            .open_handshake(local)
            .map(|handshake| handshake.bind_session_gate(session_gate))
            .map_err(|_| PeerRegistryError::InvalidScope)
    }

    fn session_gate(&self, id: PairedPeerId) -> Result<&Arc<SignerSessionGate>, PeerRegistryError> {
        self.session_gates
            .get(&id)
            .ok_or(PeerRegistryError::InvalidStore)
    }

    fn shut_down_all_sessions(&self) {
        for gate in self.session_gates.values() {
            gate.shut_down();
        }
    }

    fn active_count(&self) -> usize {
        self.state
            .entries
            .iter()
            .filter(|entry| entry.state == PairedPeerState::Active)
            .count()
    }

    fn ensure_usable(&self) -> Result<(), PeerRegistryError> {
        if self.poisoned {
            Err(PeerRegistryError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn commit<R: RngCore + CryptoRng>(
        &mut self,
        candidate: RegistryState,
        rng: &mut R,
    ) -> Result<(), PeerRegistryError> {
        candidate.validate()?;
        let envelope = seal_state(&candidate, &self.aead_key, rng)?;
        if let Err(error) = self.file.replace(&envelope).map_err(map_durable_error) {
            self.poisoned = true;
            self.shut_down_all_sessions();
            return Err(error);
        }
        self.state = candidate;
        Ok(())
    }
}

fn derive_peer_id(record: &PairedSignerRecord) -> PairedPeerId {
    let mut hasher = Hasher::new_derive_key(PEER_ID_DOMAIN);
    hasher.update(&record.encode());
    PairedPeerId(*hasher.finalize().as_bytes())
}

fn derive_aead_key(
    storage_key: &PeerRegistryStorageKey,
    scope: PeerRegistryScope,
) -> Zeroizing<[u8; 32]> {
    let mut hasher = Hasher::new_derive_key(STORAGE_KEY_DERIVATION_DOMAIN);
    hasher.update(storage_key.0.as_ref());
    hasher.update(&scope.kdf_bytes());
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn seal_state<R: RngCore + CryptoRng>(
    state: &RegistryState,
    aead_key: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<u8>, PeerRegistryError> {
    let mut nonce = [0; 24];
    let mut found_nonce = false;
    for _ in 0..=u16::MAX {
        rng.fill_bytes(&mut nonce);
        if nonce != [0; 24] {
            found_nonce = true;
            break;
        }
    }
    if !found_nonce {
        nonce.zeroize();
        return Err(PeerRegistryError::CryptographicFailure);
    }

    let mut header = [0; ENVELOPE_HEADER_BYTES];
    header[..4].copy_from_slice(&ENVELOPE_MAGIC);
    header[4..6].copy_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    header[6] = ENVELOPE_ALGORITHM_XCHACHA20_POLY1305;
    header[7] = 0;
    header[8..32].copy_from_slice(&nonce);
    header[32..36].copy_from_slice(
        &u32::try_from(REGISTRY_PLAINTEXT_BYTES)
            .expect("registry plaintext length is fixed")
            .to_le_bytes(),
    );
    let mut plaintext = state.encode();
    let cipher = XChaCha20Poly1305::new_from_slice(aead_key)
        .map_err(|_| PeerRegistryError::CryptographicFailure)?;
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &header, plaintext.as_mut())
        .map_err(|_| PeerRegistryError::CryptographicFailure)?;
    nonce.zeroize();

    let mut envelope = Vec::with_capacity(ENCRYPTED_PEER_REGISTRY_BYTES);
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&plaintext);
    envelope.extend_from_slice(&tag);
    debug_assert_eq!(envelope.len(), ENCRYPTED_PEER_REGISTRY_BYTES);
    Ok(envelope)
}

fn open_envelope(
    envelope: &[u8],
    aead_key: &[u8; 32],
    scope: PeerRegistryScope,
) -> Result<RegistryState, PeerRegistryError> {
    if envelope.len() != ENCRYPTED_PEER_REGISTRY_BYTES
        || envelope[..4] != ENVELOPE_MAGIC
        || u16::from_le_bytes(
            envelope[4..6]
                .try_into()
                .map_err(|_| PeerRegistryError::InvalidStore)?,
        ) != ENVELOPE_VERSION
        || envelope[6] != ENVELOPE_ALGORITHM_XCHACHA20_POLY1305
        || envelope[7] != 0
        || usize::try_from(u32::from_le_bytes(
            envelope[32..36]
                .try_into()
                .map_err(|_| PeerRegistryError::InvalidStore)?,
        ))
        .map_err(|_| PeerRegistryError::InvalidStore)?
            != REGISTRY_PLAINTEXT_BYTES
    {
        return Err(PeerRegistryError::InvalidStore);
    }
    let nonce: [u8; 24] = envelope[8..32]
        .try_into()
        .map_err(|_| PeerRegistryError::InvalidStore)?;
    if nonce == [0; 24] {
        return Err(PeerRegistryError::InvalidStore);
    }
    let ciphertext_end = ENVELOPE_HEADER_BYTES + REGISTRY_PLAINTEXT_BYTES;
    let mut plaintext = Zeroizing::new(envelope[ENVELOPE_HEADER_BYTES..ciphertext_end].to_vec());
    let tag = Tag::from_slice(&envelope[ciphertext_end..]);
    let cipher = XChaCha20Poly1305::new_from_slice(aead_key)
        .map_err(|_| PeerRegistryError::AuthenticationFailed)?;
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &envelope[..ENVELOPE_HEADER_BYTES],
            plaintext.as_mut(),
            tag,
        )
        .map_err(|_| PeerRegistryError::AuthenticationFailed)?;
    RegistryState::decode(&plaintext, scope)
}

fn map_durable_error(error: DurableFileError) -> PeerRegistryError {
    match error {
        #[cfg(not(unix))]
        DurableFileError::UnsupportedPlatform => PeerRegistryError::UnsupportedPlatform,
        DurableFileError::InvalidPath => PeerRegistryError::InvalidPath,
        DurableFileError::LockContended => PeerRegistryError::LockContended,
        DurableFileError::CorruptFile => PeerRegistryError::InvalidStore,
        DurableFileError::IoFailure => PeerRegistryError::IoFailure,
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    use super::*;
    use crate::{
        PairingConfirmationFacts, SignerConfirmationError, SignerPairingHandshake,
        SignerTransportKeyPair, TrustedPairingConfirmation,
    };

    const NETWORK: [u8; 32] = [0x31; 32];

    struct TestPairingConfirmation(PairingFingerprint);

    impl TrustedPairingConfirmation for TestPairingConfirmation {
        fn confirm_pairing(
            &mut self,
            _facts: &PairingConfirmationFacts,
        ) -> Result<PairingFingerprint, SignerConfirmationError> {
            Ok(self.0)
        }
    }

    fn state_with_one_peer() -> (RegistryState, PeerRegistryScope) {
        let mut rng = ChaCha20Rng::from_seed([0xa1; 32]);
        let local = SignerTransportKeyPair::generate(&mut rng);
        let remote = SignerTransportKeyPair::generate(&mut rng);
        let mut coordinator = SignerPairingHandshake::coordinator(&local, NETWORK).unwrap();
        let mut signer = SignerPairingHandshake::signer(&remote, NETWORK).unwrap();
        let first = coordinator.write_message().unwrap();
        signer.read_message(&first).unwrap();
        let second = signer.write_message().unwrap();
        coordinator.read_message(&second).unwrap();
        let third = coordinator.write_message().unwrap();
        signer.read_message(&third).unwrap();
        let coordinator = coordinator.finish().unwrap();
        let signer = signer.finish().unwrap();
        let fingerprint = coordinator.fingerprint();
        assert_eq!(fingerprint, signer.fingerprint());
        let record = coordinator
            .confirm(&mut TestPairingConfirmation(fingerprint))
            .unwrap();
        let scope = PeerRegistryScope::new(
            NETWORK,
            SignerPairingRole::Coordinator,
            &local,
            PeerRegistryId::from_bytes([0x61; 32]).unwrap(),
        )
        .unwrap();
        let id = derive_peer_id(&record);
        let state = RegistryState {
            generation: 2,
            scope,
            entries: vec![PeerEntry {
                id,
                state: PairedPeerState::Active,
                created_generation: 2,
                revoked_generation: 0,
                record,
            }],
        };
        state.validate().unwrap();
        (state, scope)
    }

    #[test]
    fn plaintext_registry_codec_rejects_every_noncanonical_state_class() {
        let (state, scope) = state_with_one_peer();
        let encoded = state.encode();
        let decoded = RegistryState::decode(&encoded, scope).unwrap();
        assert_eq!(decoded.generation, 2);
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.encode().as_slice(), encoded.as_slice());
        assert_eq!(
            RegistryState::decode(&encoded[..encoded.len() - 1], scope).unwrap_err(),
            PeerRegistryError::InvalidStore
        );

        for index in [0, 4, 14, 46, 47, 48, 80] {
            let mut modified = encoded.to_vec();
            modified[index] ^= 1;
            assert_eq!(
                RegistryState::decode(&modified, scope).unwrap_err(),
                PeerRegistryError::InvalidStore,
                "header mutation at {index} was accepted"
            );
        }

        let mut zero_generation = encoded.to_vec();
        zero_generation[6..14].fill(0);
        assert_eq!(
            RegistryState::decode(&zero_generation, scope).unwrap_err(),
            PeerRegistryError::InvalidStore
        );

        let mut excessive_count = encoded.to_vec();
        excessive_count[112..114].copy_from_slice(&257u16.to_le_bytes());
        assert_eq!(
            RegistryState::decode(&excessive_count, scope).unwrap_err(),
            PeerRegistryError::InvalidStore
        );

        let entry = REGISTRY_HEADER_BYTES;
        for index in [entry, entry + 32, entry + 33, entry + 34, entry + 50] {
            let mut modified = encoded.to_vec();
            modified[index] ^= 1;
            assert_eq!(
                RegistryState::decode(&modified, scope).unwrap_err(),
                PeerRegistryError::InvalidStore,
                "entry mutation at {index} was accepted"
            );
        }

        let mut active_with_revocation = encoded.to_vec();
        active_with_revocation[entry + 42..entry + 50].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(
            RegistryState::decode(&active_with_revocation, scope).unwrap_err(),
            PeerRegistryError::InvalidStore
        );

        let mut nonzero_padding = encoded.to_vec();
        nonzero_padding[REGISTRY_HEADER_BYTES + REGISTRY_ENTRY_BYTES] = 1;
        assert_eq!(
            RegistryState::decode(&nonzero_padding, scope).unwrap_err(),
            PeerRegistryError::InvalidStore
        );
    }
}
