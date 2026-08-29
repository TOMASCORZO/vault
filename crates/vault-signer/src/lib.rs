//! Authenticated, channel-bound signing transport for Vault transfer-v2.
//!
//! This production-intent crate is deliberately outside consensus. It uses a
//! pinned Noise XX first-contact ceremony, a fixed-size authenticated encrypted
//! peer lifecycle registry that gates Noise KK, permanent revocation tombstones,
//! active-session shutdown, mandatory trusted-confirmation traits, and a
//! crash-consistent Unix replay store, and platform-neutral contracts for
//! protected keys, rollback-resistant replay state, and exact-threshold
//! multisignature agreement and nonce lifecycles. It also freezes explicit
//! per-job delegated-proving disclosure, rollback/revocation, and local proof
//! verification without implementing a remote prover transport. It binds the
//! resulting handshake hash into a one-shot transfer authorization transcript
//! and admits only a final standard RedPallas signature that verifies for the
//! agreed action. The concrete FROST implementation remains disabled, and
//! trusted UX, keychain/secure-element/hardware/prover adapters plus external
//! review remain activation gates; this crate must not yet protect real funds.

mod confirmation;
mod custody;
mod delegated_proving;
mod durable_file;
mod multisig;
mod pairing;
mod peer_registry;
mod session;
mod store;
mod transport;

pub use confirmation::{
    ApprovedOutputIntent, PairingConfirmationFacts, PeerLifecycleAction,
    PeerLifecycleConfirmationFacts, SignerConfirmationError, TransferConfirmationFacts,
    TrustedPairingConfirmation, TrustedPeerConfirmation, TrustedTransferIntentSource,
};
pub use custody::{
    ProtectedSignerKeys, RollbackProtectedReplayStore, SIGNER_PROTECTED_KEY_MATERIAL_BYTES,
    SIGNER_SECURE_REPLAY_STATE_BYTES, SignerProtectedKeyMaterial, SignerProtectedKeyMaterialError,
    SignerProtectedKeyStore, SignerProtectedKeyStoreError, SignerSecureReplayError,
    SignerSecureReplayState, SignerSecureReplayStateError, SignerSecureReplayStore,
};
pub use delegated_proving::{
    ConfirmedDelegatedProverRevocation, ConfirmedDelegatedProvingAuthorization,
    DELEGATED_PROVING_AUTHORIZATION_BYTES, DELEGATED_PROVING_POLICY_BYTES,
    DELEGATED_PROVING_REQUEST_MAX_BYTES, DELEGATED_PROVING_RESPONSE_MAX_BYTES,
    DELEGATED_PROVING_WITNESS_MAX_BYTES, DelegatedProverChannelBinding, DelegatedProverFingerprint,
    DelegatedProverId, DelegatedProverRevocationFacts, DelegatedProverRevocationId,
    DelegatedProvingAuthorization, DelegatedProvingAuthorizationFacts,
    DelegatedProvingAuthorizationId, DelegatedProvingDisclosure, DelegatedProvingError,
    DelegatedProvingJobId, DelegatedProvingJobLifecycle, DelegatedProvingPolicy,
    DelegatedProvingPolicyId, DelegatedProvingRequest, DelegatedProvingResponse,
    DelegatedTransferProofVerifier, DelegatedWitnessCommitment, DelegatedWitnessPackage,
    TrustedDelegatedProverRevocation, TrustedDelegatedProvingAuthorization,
    VerifiedDelegatedTransferProof,
};
pub use multisig::{
    ConfirmedMultisigAgreement, MAX_MULTISIG_PARTICIPANTS, MIN_MULTISIG_PARTICIPANTS,
    MULTISIG_COMMITMENT_SET_MAX_BYTES, MULTISIG_POLICY_MAX_BYTES,
    MULTISIG_SIGNING_AGREEMENT_MAX_BYTES, MultisigAgreementFacts, MultisigAgreementId,
    MultisigAttemptId, MultisigCommitmentSet, MultisigError, MultisigNonceCommitment,
    MultisigParticipant, MultisigParticipantId, MultisigParticipantRound, MultisigPolicy,
    MultisigPolicyId, MultisigSigningAgreement, TrustedMultisigAgreement,
};
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
