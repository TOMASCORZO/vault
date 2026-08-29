use core::fmt;

use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, OutputAuthorizationIntent, OutputKind, VaultAddress,
};
use vault_protocol::PublicInputDigest;
use zeroize::{Zeroize, Zeroizing};

use crate::{PairedPeerId, PairingFingerprint, SignerPairingRole, SigningTranscriptId};

/// Fail-closed result from a trusted display or independent intent source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerConfirmationError {
    /// The user or local policy explicitly rejected the operation.
    Rejected,
    /// The trusted surface or protected intent source is unavailable.
    Unavailable,
    /// A trusted source returned an internally invalid output intent.
    InvalidIntent,
}

impl fmt::Display for SignerConfirmationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Rejected => "trusted signer confirmation was rejected",
            Self::Unavailable => "trusted signer confirmation is unavailable",
            Self::InvalidIntent => "trusted signer intent is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SignerConfirmationError {}

/// Public, policy-validated facts a trusted surface must confirm.
///
/// Recipient, amount, classification and memo are deliberately absent: the
/// adapter supplies those independently through [`ApprovedOutputIntent`]
/// instead of learning them from coordinator-controlled packets.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TransferConfirmationFacts {
    network_id: [u8; 32],
    circuit_id: [u8; 32],
    burn_scheme_id: [u8; 32],
    burn_key_id: [u8; 32],
    burn_epoch: u64,
    action_count: usize,
    gas_units: u64,
    fee_per_gas: u64,
    total_gas_fee: u128,
    public_inputs_digest: PublicInputDigest,
    transcript_id: SigningTranscriptId,
}

impl fmt::Debug for TransferConfirmationFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferConfirmationFacts")
            .field("action_count", &self.action_count)
            .field("gas_units", &self.gas_units)
            .field("fee_per_gas", &self.fee_per_gas)
            .field("total_gas_fee", &self.total_gas_fee)
            .field("domain_identifiers", &"REDACTED")
            .finish()
    }
}

impl TransferConfirmationFacts {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        network_id: [u8; 32],
        circuit_id: [u8; 32],
        burn_scheme_id: [u8; 32],
        burn_key_id: [u8; 32],
        burn_epoch: u64,
        action_count: usize,
        gas_units: u64,
        fee_per_gas: u64,
        total_gas_fee: u128,
        public_inputs_digest: PublicInputDigest,
        transcript_id: SigningTranscriptId,
    ) -> Self {
        Self {
            network_id,
            circuit_id,
            burn_scheme_id,
            burn_key_id,
            burn_epoch,
            action_count,
            gas_units,
            fee_per_gas,
            total_gas_fee,
            public_inputs_digest,
            transcript_id,
        }
    }

    #[must_use]
    pub const fn network_id(self) -> [u8; 32] {
        self.network_id
    }

    #[must_use]
    pub const fn circuit_id(self) -> [u8; 32] {
        self.circuit_id
    }

    #[must_use]
    pub const fn burn_scheme_id(self) -> [u8; 32] {
        self.burn_scheme_id
    }

    #[must_use]
    pub const fn burn_key_id(self) -> [u8; 32] {
        self.burn_key_id
    }

    #[must_use]
    pub const fn burn_epoch(self) -> u64 {
        self.burn_epoch
    }

    #[must_use]
    pub const fn action_count(self) -> usize {
        self.action_count
    }

    #[must_use]
    pub const fn gas_units(self) -> u64 {
        self.gas_units
    }

    #[must_use]
    pub const fn fee_per_gas(self) -> u64 {
        self.fee_per_gas
    }

    #[must_use]
    pub const fn total_gas_fee(self) -> u128 {
        self.total_gas_fee
    }

    #[must_use]
    pub const fn public_inputs_digest(self) -> PublicInputDigest {
        self.public_inputs_digest
    }

    #[must_use]
    pub const fn transcript_id(self) -> SigningTranscriptId {
        self.transcript_id
    }
}

/// One payment/change/dummy intent supplied by an independent trusted source.
///
/// The coordinator-controlled network and action nullifier are added only
/// after policy validation. Private recipient, amount and memo are redacted and
/// zeroized on drop.
pub struct ApprovedOutputIntent {
    sender_scope: KeyScope,
    kind: OutputKind,
    recipient: Zeroizing<[u8; 43]>,
    value: u64,
    memo: Zeroizing<[u8; MEMO_BYTES]>,
}

impl fmt::Debug for ApprovedOutputIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedOutputIntent")
            .field("kind", &self.kind)
            .field("private_fields", &"REDACTED")
            .finish()
    }
}

impl Drop for ApprovedOutputIntent {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl ApprovedOutputIntent {
    /// Builds one independently sourced intent with canonical value semantics.
    pub fn new(
        sender_scope: KeyScope,
        kind: OutputKind,
        recipient: VaultAddress,
        mut value: u64,
        memo: [u8; MEMO_BYTES],
    ) -> Result<Self, SignerConfirmationError> {
        let recipient = Zeroizing::new(recipient.to_bytes());
        let memo = Zeroizing::new(memo);
        if matches!(
            kind,
            OutputKind::ExternalPayment | OutputKind::InternalChange
        ) && value == 0
            || kind == OutputKind::Dummy && value != 0
        {
            value.zeroize();
            return Err(SignerConfirmationError::InvalidIntent);
        }
        Ok(Self {
            sender_scope,
            kind,
            recipient,
            value,
            memo,
        })
    }

    pub(crate) fn bind(
        &self,
        network_id: [u8; 32],
        action_nullifier: ActionNullifier,
    ) -> Result<OutputAuthorizationIntent, SignerConfirmationError> {
        let recipient = VaultAddress::from_bytes(*self.recipient)
            .map_err(|_| SignerConfirmationError::InvalidIntent)?;
        OutputAuthorizationIntent::new(
            network_id,
            self.sender_scope,
            self.kind,
            recipient,
            self.value,
            action_nullifier,
            *self.memo,
        )
        .map_err(|_| SignerConfirmationError::InvalidIntent)
    }
}

/// Trusted product boundary for one complete transfer approval.
///
/// Implementations MUST obtain the returned output intents from a source that
/// is independent of the coordinator request and MUST display or enforce every
/// public fact before returning success. This crate supplies no permissive
/// implementation.
pub trait TrustedTransferIntentSource {
    fn confirm_transfer(
        &mut self,
        facts: &TransferConfirmationFacts,
    ) -> Result<Vec<ApprovedOutputIntent>, SignerConfirmationError>;
}

/// Exact XX transcript facts presented on a trusted pairing surface.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PairingConfirmationFacts {
    role: SignerPairingRole,
    network_id: [u8; 32],
    local_public_key: [u8; 32],
    remote_public_key: [u8; 32],
    fingerprint: PairingFingerprint,
}

impl fmt::Debug for PairingConfirmationFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingConfirmationFacts")
            .field("role", &self.role)
            .field("identity", &"REDACTED")
            .finish()
    }
}

impl PairingConfirmationFacts {
    pub(crate) const fn new(
        role: SignerPairingRole,
        network_id: [u8; 32],
        local_public_key: [u8; 32],
        remote_public_key: [u8; 32],
        fingerprint: PairingFingerprint,
    ) -> Self {
        Self {
            role,
            network_id,
            local_public_key,
            remote_public_key,
            fingerprint,
        }
    }

    #[must_use]
    pub const fn role(self) -> SignerPairingRole {
        self.role
    }

    #[must_use]
    pub const fn network_id(self) -> [u8; 32] {
        self.network_id
    }

    #[must_use]
    pub const fn local_public_key(self) -> [u8; 32] {
        self.local_public_key
    }

    #[must_use]
    pub const fn remote_public_key(self) -> [u8; 32] {
        self.remote_public_key
    }

    #[must_use]
    pub const fn fingerprint(self) -> PairingFingerprint {
        self.fingerprint
    }
}

/// Trusted product boundary for the independent XX fingerprint comparison.
///
/// Implementations MUST obtain the returned fingerprint from the peer's
/// trusted display or another independent authenticated channel. The crate
/// provides no implementation that echoes its own fingerprint.
pub trait TrustedPairingConfirmation {
    fn confirm_pairing(
        &mut self,
        facts: &PairingConfirmationFacts,
    ) -> Result<PairingFingerprint, SignerConfirmationError>;
}

/// Exact peer lifecycle operation presented to a trusted management surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerLifecycleAction {
    Revoke,
    Rotate,
}

/// Authenticated peer facts that must be confirmed before lifecycle mutation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PeerLifecycleConfirmationFacts {
    action: PeerLifecycleAction,
    network_id: [u8; 32],
    local_role: SignerPairingRole,
    peer_id: PairedPeerId,
    current_fingerprint: PairingFingerprint,
    replacement_fingerprint: Option<PairingFingerprint>,
    current_generation: u64,
}

impl fmt::Debug for PeerLifecycleConfirmationFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerLifecycleConfirmationFacts")
            .field("action", &self.action)
            .field("current_generation", &self.current_generation)
            .field("peer_identity", &"REDACTED")
            .finish()
    }
}

impl PeerLifecycleConfirmationFacts {
    pub(crate) const fn new(
        action: PeerLifecycleAction,
        network_id: [u8; 32],
        local_role: SignerPairingRole,
        peer_id: PairedPeerId,
        current_fingerprint: PairingFingerprint,
        replacement_fingerprint: Option<PairingFingerprint>,
        current_generation: u64,
    ) -> Self {
        Self {
            action,
            network_id,
            local_role,
            peer_id,
            current_fingerprint,
            replacement_fingerprint,
            current_generation,
        }
    }

    #[must_use]
    pub const fn action(self) -> PeerLifecycleAction {
        self.action
    }

    #[must_use]
    pub const fn network_id(self) -> [u8; 32] {
        self.network_id
    }

    #[must_use]
    pub const fn local_role(self) -> SignerPairingRole {
        self.local_role
    }

    #[must_use]
    pub const fn peer_id(self) -> PairedPeerId {
        self.peer_id
    }

    #[must_use]
    pub const fn current_fingerprint(self) -> PairingFingerprint {
        self.current_fingerprint
    }

    #[must_use]
    pub const fn replacement_fingerprint(self) -> Option<PairingFingerprint> {
        self.replacement_fingerprint
    }

    #[must_use]
    pub const fn current_generation(self) -> u64 {
        self.current_generation
    }
}

/// Trusted product boundary for revocation and rotation confirmation.
///
/// The crate provides no default acceptance implementation.
pub trait TrustedPeerConfirmation {
    fn confirm_peer_lifecycle(
        &mut self,
        facts: &PeerLifecycleConfirmationFacts,
    ) -> Result<(), SignerConfirmationError>;
}
