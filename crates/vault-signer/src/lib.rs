//! Authenticated, channel-bound signing transport for Vault transfer-v2.
//!
//! This production-intent crate is deliberately outside consensus. It uses a
//! pinned Noise XX first-contact ceremony, a fixed-size authenticated encrypted
//! peer lifecycle registry that gates Noise KK, permanent revocation tombstones,
//! and a crash-consistent Unix replay store. It binds the resulting handshake
//! hash into a one-shot transfer authorization transcript. Trusted UX,
//! rollback-resistant hardware profiles, additional platform stores, and
//! external review remain activation gates; this crate must not yet protect
//! real funds.

mod durable_file;
mod pairing;
mod peer_registry;
mod session;
mod store;
mod transport;

pub use pairing::{
    PAIRED_SIGNER_RECORD_BYTES, PairedSignerRecord, PairingFingerprint,
    SIGNER_PAIRING_NOISE_PROTOCOL, SignerPairingError, SignerPairingHandshake, SignerPairingRole,
    UnconfirmedSignerPairing,
};
pub use peer_registry::{
    ENCRYPTED_PEER_REGISTRY_BYTES, EncryptedPeerRegistry, MAX_ACTIVE_PAIRED_SIGNERS,
    MAX_PAIRED_SIGNER_RECORDS, PairedPeerId, PairedPeerState, PairedPeerSummary, PeerRegistryError,
    PeerRegistryId, PeerRegistryScope, PeerRegistryStorageKey,
};

pub use session::{
    BoundTransferV2Authorizations, BoundTransferV2SigningSession, DurableReplayGuard,
    SIGNER_AUTHORIZATION_REQUEST_MAX_BYTES, SIGNER_AUTHORIZATION_RESPONSE_MAX_BYTES,
    SessionChallenge, SessionError, SignerAuthorizationRequest, SigningTranscriptId,
};
pub use store::{CrashConsistentReplayStore, REPLAY_STORE_STATE_BYTES, ReplayStoreError};
pub use transport::{
    MAX_SIGNER_MESSAGE_BYTES, MAX_SIGNER_PLAINTEXT_BYTES, SIGNER_NOISE_PROTOCOL, SignerHandshake,
    SignerTransport, SignerTransportError, SignerTransportKeyPair, SignerTransportMessage,
    SignerTransportMessageKind,
};
