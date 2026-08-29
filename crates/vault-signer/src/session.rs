use core::fmt;

use blake3::Hasher;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use vault_privacy::{
    OUTPUT_AUTHORIZATION_PACKET_BYTES, OutputAuthorizationPacket, PreparedSpendAuthorization,
    SpendAuthorization, SpendAuthorizationDigest, VaultFullViewingKey, VaultSpendingKey,
    VerifiedOutputAuthorization,
};
use vault_protocol::{
    ProtocolError, PublicInputDigest, TRANSFER_V2_MAX_EFFECT_BYTES, TransferV2Effects,
    TransferV2SignerPolicy,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    MultisigCommitmentSet, MultisigPolicy, MultisigSigningAgreement, TransferConfirmationFacts,
    TrustedTransferIntentSource,
};

const CHALLENGE_MAGIC: [u8; 4] = *b"VSCH";
const CHALLENGE_VERSION: u16 = 1;
const CHALLENGE_BYTES: usize = 4 + 2 + 32 + 32 + 32 + 8;
const TRANSCRIPT_DOMAIN: &str = "vault.signer.transfer-v2.transcript.v1";
const REQUEST_MAGIC: [u8; 4] = *b"VSRQ";
const REQUEST_VERSION: u16 = 1;
const REQUEST_FIXED_BYTES: usize = 4 + 2 + CHALLENGE_BYTES + 32 + 4 + 1;
const RESPONSE_MAGIC: [u8; 4] = *b"VSRP";
const RESPONSE_VERSION: u16 = 1;
const RESPONSE_FIXED_BYTES: usize = 4 + 2 + 32 + 32 + 1;
const SPEND_AUTHORIZATION_BYTES: usize = 64;
/// Absolute pre-allocation bound for a 16-action signer request.
pub const SIGNER_AUTHORIZATION_REQUEST_MAX_BYTES: usize =
    REQUEST_FIXED_BYTES + TRANSFER_V2_MAX_EFFECT_BYTES + OUTPUT_AUTHORIZATION_PACKET_BYTES * 16;
/// Absolute decoder bound for a 16-action signer response.
pub const SIGNER_AUTHORIZATION_RESPONSE_MAX_BYTES: usize =
    RESPONSE_FIXED_BYTES + SPEND_AUTHORIZATION_BYTES * 16;

/// Signer-session failure. Transport responses should collapse these into the
/// opaque `Abort` message to avoid exposing wallet policy details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// Challenge bytes or reserved fields are invalid.
    InvalidChallenge,
    /// Challenge belongs to another authenticated Noise channel.
    ChannelBindingMismatch,
    /// Challenge belongs to another Vault network.
    NetworkMismatch,
    /// Session identifier/counter was already consumed.
    ReplayDetected,
    /// Durable replay storage could not atomically record consumption.
    ReplayStoreFailure,
    /// Session packet count is inconsistent with the effects.
    PacketCountMismatch { expected: usize, actual: usize },
    /// Request framing, lengths, or nested canonical objects are invalid.
    InvalidRequest,
    /// Request names a policy other than the signer's locally approved policy.
    PolicyMismatch,
    /// Trusted user intents do not cover the exact action count.
    IntentCountMismatch { expected: usize, actual: usize },
    /// Trusted confirmation rejected, failed, or returned invalid intent.
    ConfirmationFailed,
    /// A private output packet failed independent reconstruction.
    InvalidOutputAuthorization,
    /// Response framing, transcript, effects digest, or signature is invalid.
    InvalidResponse,
    /// Requested action was already signed in this one-shot session.
    ActionAlreadySigned { index: usize },
    /// Multisig agreement differs from the prepared transaction or action key.
    InvalidMultisigAgreement,
    /// Not every action has been authorized, so the session cannot finish.
    IncompleteSession,
    /// The underlying transfer-v2 policy or signature validation failed.
    Protocol(ProtocolError),
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidChallenge => "invalid signer session challenge",
            Self::ChannelBindingMismatch => "signer session belongs to another channel",
            Self::NetworkMismatch => "signer session belongs to another network",
            Self::ReplayDetected => "signer session challenge was already consumed",
            Self::ReplayStoreFailure => "durable signer replay store failed",
            Self::PacketCountMismatch { .. } => "signer packet count mismatch",
            Self::InvalidRequest => "invalid signer authorization request",
            Self::PolicyMismatch => "signer request policy mismatch",
            Self::IntentCountMismatch { .. } => "signer intent count mismatch",
            Self::ConfirmationFailed => "trusted signer confirmation failed",
            Self::InvalidOutputAuthorization => "signer output reconstruction failed",
            Self::InvalidResponse => "invalid signer authorization response",
            Self::ActionAlreadySigned { .. } => "signer action was already authorized",
            Self::InvalidMultisigAgreement => "invalid multisig signing agreement",
            Self::IncompleteSession => "signer session is incomplete",
            Self::Protocol(_) => "transfer-v2 signer policy rejected the request",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SessionError {}

impl From<ProtocolError> for SessionError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Signer-generated freshness challenge bound to one completed Noise handshake.
pub struct SessionChallenge {
    network_id: [u8; 32],
    channel_binding: [u8; 32],
    session_id: Zeroizing<[u8; 32]>,
    counter: u64,
}

impl fmt::Debug for SessionChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionChallenge")
            .field("counter", &self.counter)
            .field("session_id", &"REDACTED")
            .finish_non_exhaustive()
    }
}

impl Drop for SessionChallenge {
    fn drop(&mut self) {
        self.network_id.zeroize();
        self.channel_binding.zeroize();
        self.counter.zeroize();
    }
}

impl SessionChallenge {
    /// Creates a signer-side challenge. `counter` must come from durable,
    /// monotonically increasing device state.
    pub fn generate<R: RngCore + CryptoRng>(
        network_id: [u8; 32],
        channel_binding: [u8; 32],
        counter: u64,
        rng: &mut R,
    ) -> Result<Self, SessionError> {
        if network_id == [0; 32] || channel_binding == [0; 32] || counter == 0 {
            return Err(SessionError::InvalidChallenge);
        }
        for _ in 0..=u16::MAX {
            let mut session_id = [0; 32];
            rng.fill_bytes(&mut session_id);
            if session_id != [0; 32] {
                return Ok(Self {
                    network_id,
                    channel_binding,
                    session_id: Zeroizing::new(session_id),
                    counter,
                });
            }
        }
        Err(SessionError::InvalidChallenge)
    }

    /// Exact fixed-size challenge codec sent as the first encrypted message.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(CHALLENGE_BYTES));
        bytes.extend_from_slice(&CHALLENGE_MAGIC);
        bytes.extend_from_slice(&CHALLENGE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.channel_binding);
        bytes.extend_from_slice(self.session_id.as_ref());
        bytes.extend_from_slice(&self.counter.to_le_bytes());
        debug_assert_eq!(bytes.len(), CHALLENGE_BYTES);
        bytes
    }

    /// Parses an exact challenge echoed by the coordinator over the same channel.
    pub fn decode(bytes: &[u8]) -> Result<Self, SessionError> {
        if bytes.len() != CHALLENGE_BYTES
            || bytes[..4] != CHALLENGE_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| SessionError::InvalidChallenge)?,
            ) != CHALLENGE_VERSION
        {
            return Err(SessionError::InvalidChallenge);
        }
        let network_id = bytes[6..38]
            .try_into()
            .map_err(|_| SessionError::InvalidChallenge)?;
        let channel_binding = bytes[38..70]
            .try_into()
            .map_err(|_| SessionError::InvalidChallenge)?;
        let session_id = bytes[70..102]
            .try_into()
            .map_err(|_| SessionError::InvalidChallenge)?;
        let counter = u64::from_le_bytes(
            bytes[102..110]
                .try_into()
                .map_err(|_| SessionError::InvalidChallenge)?,
        );
        if network_id == [0; 32]
            || channel_binding == [0; 32]
            || session_id == [0; 32]
            || counter == 0
        {
            return Err(SessionError::InvalidChallenge);
        }
        Ok(Self {
            network_id,
            channel_binding,
            session_id: Zeroizing::new(session_id),
            counter,
        })
    }

    /// Opaque random identifier retained by the durable replay store.
    #[must_use]
    pub fn session_id(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.session_id)
    }

    /// Durable monotonic device counter.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    pub(crate) const fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    pub(crate) const fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }
}

/// Exact encrypted request payload containing public effects and one secret
/// output packet per canonically sorted action.
pub struct SignerAuthorizationRequest {
    challenge: SessionChallenge,
    policy_digest: [u8; 32],
    effects: TransferV2Effects,
    packets: Vec<OutputAuthorizationPacket>,
}

impl fmt::Debug for SignerAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignerAuthorizationRequest")
            .field("action_count", &self.packets.len())
            .field("private_packets", &"REDACTED")
            .finish()
    }
}

impl SignerAuthorizationRequest {
    /// Constructs a request for one exact policy/effects/packet set.
    pub fn new(
        challenge: &SessionChallenge,
        policy: &TransferV2SignerPolicy,
        effects: TransferV2Effects,
        packets: Vec<OutputAuthorizationPacket>,
    ) -> Result<Self, SessionError> {
        if packets.len() != effects.actions().len() {
            return Err(SessionError::PacketCountMismatch {
                expected: effects.actions().len(),
                actual: packets.len(),
            });
        }
        Ok(Self {
            challenge: SessionChallenge::decode(challenge.encode().as_ref())?,
            policy_digest: policy.signer_policy_digest(),
            effects,
            packets,
        })
    }

    /// Serializes the complete request into a zeroizing allocation suitable
    /// only as an encrypted Noise authorization-request payload.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let effects = self.effects.encode_canonical();
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            REQUEST_FIXED_BYTES
                + effects.len()
                + OUTPUT_AUTHORIZATION_PACKET_BYTES * self.packets.len(),
        ));
        bytes.extend_from_slice(&REQUEST_MAGIC);
        bytes.extend_from_slice(&REQUEST_VERSION.to_le_bytes());
        bytes.extend_from_slice(self.challenge.encode().as_ref());
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(
            &u32::try_from(effects.len())
                .expect("effects size is bounded")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&effects);
        bytes.push(u8::try_from(self.packets.len()).expect("at most 16 packets"));
        for packet in &self.packets {
            bytes.extend_from_slice(packet.encode().as_ref());
        }
        debug_assert!(bytes.len() <= SIGNER_AUTHORIZATION_REQUEST_MAX_BYTES);
        bytes
    }

    /// Parses a complete request with an absolute bound before nested allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, SessionError> {
        if bytes.len() > SIGNER_AUTHORIZATION_REQUEST_MAX_BYTES
            || bytes.len() < REQUEST_FIXED_BYTES
            || bytes[..4] != REQUEST_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| SessionError::InvalidRequest)?,
            ) != REQUEST_VERSION
        {
            return Err(SessionError::InvalidRequest);
        }
        let mut offset = 6;
        let challenge_end = offset + CHALLENGE_BYTES;
        let challenge = SessionChallenge::decode(
            bytes
                .get(offset..challenge_end)
                .ok_or(SessionError::InvalidRequest)?,
        )?;
        offset = challenge_end;
        let policy_end = offset + 32;
        let policy_digest = bytes
            .get(offset..policy_end)
            .ok_or(SessionError::InvalidRequest)?
            .try_into()
            .map_err(|_| SessionError::InvalidRequest)?;
        offset = policy_end;
        let effects_len_end = offset + 4;
        let effects_length = usize::try_from(u32::from_le_bytes(
            bytes
                .get(offset..effects_len_end)
                .ok_or(SessionError::InvalidRequest)?
                .try_into()
                .map_err(|_| SessionError::InvalidRequest)?,
        ))
        .map_err(|_| SessionError::InvalidRequest)?;
        if effects_length > TRANSFER_V2_MAX_EFFECT_BYTES {
            return Err(SessionError::InvalidRequest);
        }
        offset = effects_len_end;
        let effects_end = offset
            .checked_add(effects_length)
            .ok_or(SessionError::InvalidRequest)?;
        let effects = TransferV2Effects::decode_canonical(
            bytes
                .get(offset..effects_end)
                .ok_or(SessionError::InvalidRequest)?,
        )
        .map_err(|_| SessionError::InvalidRequest)?;
        offset = effects_end;
        let packet_count = usize::from(*bytes.get(offset).ok_or(SessionError::InvalidRequest)?);
        offset += 1;
        if packet_count != effects.actions().len() {
            return Err(SessionError::PacketCountMismatch {
                expected: effects.actions().len(),
                actual: packet_count,
            });
        }
        let packet_bytes = packet_count
            .checked_mul(OUTPUT_AUTHORIZATION_PACKET_BYTES)
            .ok_or(SessionError::InvalidRequest)?;
        if offset.checked_add(packet_bytes) != Some(bytes.len()) {
            return Err(SessionError::InvalidRequest);
        }
        let mut packets = Vec::with_capacity(packet_count);
        for _ in 0..packet_count {
            let end = offset + OUTPUT_AUTHORIZATION_PACKET_BYTES;
            packets.push(
                OutputAuthorizationPacket::decode(
                    bytes.get(offset..end).ok_or(SessionError::InvalidRequest)?,
                )
                .map_err(|_| SessionError::InvalidRequest)?,
            );
            offset = end;
        }
        Ok(Self {
            challenge,
            policy_digest,
            effects,
            packets,
        })
    }

    /// Exact public effects carried inside the private request.
    #[must_use]
    pub const fn effects(&self) -> &TransferV2Effects {
        &self.effects
    }

    /// Transcript expected back from the signer for this exact request.
    #[must_use]
    pub fn transcript_id(&self) -> SigningTranscriptId {
        let packet_digests: Vec<_> = self
            .packets
            .iter()
            .map(OutputAuthorizationPacket::transport_digest)
            .collect();
        derive_transcript_from_digests(
            &self.challenge,
            self.policy_digest,
            self.effects.public_inputs_digest(),
            &packet_digests,
        )
    }
}

/// Mandatory wallet/hardware boundary for atomic durable replay rejection.
///
/// An implementation MUST atomically persist `(session_id, counter)` before
/// returning `Ok(())`, reject any reused or non-increasing counter according to
/// its device policy, survive restart, and fail closed on I/O. Rollback
/// resistance is platform-specific: software files require a protected storage
/// root, while the hardware profile requires a monotonic secure element.
pub trait DurableReplayGuard {
    /// Atomically consumes one challenge or returns a fail-closed session error.
    fn consume(&mut self, challenge: &SessionChallenge) -> Result<(), SessionError>;
}

/// Domain-separated identifier of one exact channel, challenge, policy,
/// effects statement, and ordered private packet set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningTranscriptId([u8; 32]);

impl SigningTranscriptId {
    /// Restores exact transcript bytes carried by a canonical nested protocol.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exact transcript bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// One-shot channel-bound wrapper around the protocol signing session.
pub struct BoundTransferV2SigningSession {
    inner: vault_protocol::PreparedTransferV2Authorization,
    transcript_id: SigningTranscriptId,
    authorizations: Vec<Option<SpendAuthorization>>,
}

impl fmt::Debug for BoundTransferV2SigningSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundTransferV2SigningSession")
            .field("transcript_id", &self.transcript_id)
            .field("action_count", &self.authorizations.len())
            .field("authorizations", &"REDACTED")
            .finish()
    }
}

impl BoundTransferV2SigningSession {
    /// Full hardware/local-IPC entry point: matches the echoed signer challenge,
    /// local policy, trusted intents and reconstructed packets before consuming
    /// durable replay state.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_confirmed_request<G, C>(
        expected_channel_binding: [u8; 32],
        issued_challenge: &SessionChallenge,
        replay_guard: &mut G,
        policy: &TransferV2SignerPolicy,
        request: SignerAuthorizationRequest,
        full_viewing_key: &VaultFullViewingKey,
        confirmation: &mut C,
        maximum_value: u64,
    ) -> Result<Self, SessionError>
    where
        G: DurableReplayGuard,
        C: TrustedTransferIntentSource,
    {
        let issued = issued_challenge.encode();
        let echoed = request.challenge.encode();
        if !bool::from(issued[..].ct_eq(&echoed[..])) {
            return Err(SessionError::InvalidChallenge);
        }
        if issued_challenge.channel_binding != expected_channel_binding {
            return Err(SessionError::ChannelBindingMismatch);
        }
        if issued_challenge.network_id != *request.effects.chain_id().as_bytes() {
            return Err(SessionError::NetworkMismatch);
        }
        if request.policy_digest != policy.signer_policy_digest() {
            return Err(SessionError::PolicyMismatch);
        }
        policy.validate_effects(&request.effects)?;
        let gas = request.effects.gas();
        let facts = TransferConfirmationFacts::new(
            *request.effects.chain_id().as_bytes(),
            *request.effects.circuit_id().as_bytes(),
            request.effects.burn().scheme_id(),
            request.effects.burn().key_id(),
            request.effects.burn().epoch(),
            request.effects.actions().len(),
            gas.units,
            gas.fee_per_gas,
            gas.total_fee()?,
            request.effects.public_inputs_digest(),
            request.transcript_id(),
        );
        let approved = confirmation
            .confirm_transfer(&facts)
            .map_err(|_| SessionError::ConfirmationFailed)?;
        if approved.len() != request.effects.actions().len() {
            return Err(SessionError::IntentCountMismatch {
                expected: request.effects.actions().len(),
                actual: approved.len(),
            });
        }
        let mut output_authorizations = Vec::with_capacity(request.packets.len());
        for ((packet, approved), action) in request
            .packets
            .iter()
            .zip(&approved)
            .zip(request.effects.actions())
        {
            let intent = approved
                .bind(*request.effects.chain_id().as_bytes(), action.nullifier())
                .map_err(|_| SessionError::ConfirmationFailed)?;
            output_authorizations.push(
                packet
                    .verify(full_viewing_key, &intent, action.output(), maximum_value)
                    .map_err(|_| SessionError::InvalidOutputAuthorization)?,
            );
        }
        Self::prepare(
            expected_channel_binding,
            issued_challenge,
            replay_guard,
            policy,
            &request.effects,
            output_authorizations,
        )
    }

    /// Validates the exact channel/network binding, complete signer policy and
    /// ordered packet set, then atomically consumes replay state.
    pub(crate) fn prepare<G: DurableReplayGuard>(
        expected_channel_binding: [u8; 32],
        challenge: &SessionChallenge,
        replay_guard: &mut G,
        policy: &TransferV2SignerPolicy,
        effects: &TransferV2Effects,
        output_authorizations: Vec<VerifiedOutputAuthorization>,
    ) -> Result<Self, SessionError> {
        if challenge.channel_binding != expected_channel_binding {
            return Err(SessionError::ChannelBindingMismatch);
        }
        if challenge.network_id != *effects.chain_id().as_bytes() {
            return Err(SessionError::NetworkMismatch);
        }
        if output_authorizations.len() != effects.actions().len() {
            return Err(SessionError::PacketCountMismatch {
                expected: effects.actions().len(),
                actual: output_authorizations.len(),
            });
        }
        let transcript_id = derive_transcript(
            challenge,
            policy.signer_policy_digest(),
            effects.public_inputs_digest(),
            &output_authorizations,
        );
        let inner = policy.prepare(effects, output_authorizations)?;
        replay_guard.consume(challenge)?;
        let authorizations = vec![None; effects.actions().len()];
        Ok(Self {
            inner,
            transcript_id,
            authorizations,
        })
    }

    /// Exact channel-bound transcript confirmed by the signer UI.
    #[must_use]
    pub const fn transcript_id(&self) -> SigningTranscriptId {
        self.transcript_id
    }

    /// Freezes one exact action-specific multisig agreement after the complete
    /// transfer request has passed the same policy/output/replay checks as a
    /// single-signer session.
    pub fn multisig_agreement(
        &self,
        action_index: usize,
        policy: &MultisigPolicy,
        commitments: &MultisigCommitmentSet,
        prepared: &PreparedSpendAuthorization,
    ) -> Result<MultisigSigningAgreement, SessionError> {
        let expected_key = self.inner.randomized_validating_key(action_index)?;
        if prepared.randomized_verification_key() != expected_key.to_bytes() {
            return Err(SessionError::InvalidMultisigAgreement);
        }
        let agreement = MultisigSigningAgreement::new(
            policy,
            commitments,
            self.transcript_id,
            self.inner.public_inputs_digest(),
            action_index,
            self.inner.action_count(),
            prepared,
        )
        .map_err(|_| SessionError::InvalidMultisigAgreement)?;
        if agreement.authorization_digest() != self.inner.authorization_digest() {
            return Err(SessionError::InvalidMultisigAgreement);
        }
        Ok(agreement)
    }

    /// Attaches a reviewed adapter's final aggregated RedPallas signature only
    /// when its complete agreement and proof-bound action key match this session.
    pub fn attach_multisig_authorization(
        &mut self,
        agreement: &MultisigSigningAgreement,
        authorization: SpendAuthorization,
    ) -> Result<(), SessionError> {
        let action_index = agreement.action_index();
        let slot = self.authorizations.get(action_index).ok_or({
            ProtocolError::InvalidAuthorizationIndex {
                index: action_index,
                action_count: self.authorizations.len(),
            }
        })?;
        if slot.is_some() {
            return Err(SessionError::ActionAlreadySigned {
                index: action_index,
            });
        }
        if agreement.transcript_id() != self.transcript_id
            || agreement.action_count() != self.inner.action_count()
            || agreement.public_inputs_digest() != self.inner.public_inputs_digest()
            || agreement.authorization_digest() != self.inner.authorization_digest()
            || agreement.randomized_validating_key()
                != self
                    .inner
                    .randomized_validating_key(action_index)?
                    .to_bytes()
        {
            return Err(SessionError::InvalidMultisigAgreement);
        }
        self.inner
            .validate_action_authorization(action_index, &authorization)?;
        self.authorizations[action_index] = Some(authorization);
        Ok(())
    }

    /// Signs one action at most once in this session.
    pub fn sign_action<R: RngCore + CryptoRng>(
        &mut self,
        action_index: usize,
        spending_key: &VaultSpendingKey,
        prepared: &PreparedSpendAuthorization,
        rng: &mut R,
    ) -> Result<(), SessionError> {
        let slot = self.authorizations.get(action_index).ok_or({
            ProtocolError::InvalidAuthorizationIndex {
                index: action_index,
                action_count: self.authorizations.len(),
            }
        })?;
        if slot.is_some() {
            return Err(SessionError::ActionAlreadySigned {
                index: action_index,
            });
        }
        let authorization = self
            .inner
            .sign_action(action_index, spending_key, prepared, rng)?;
        self.authorizations[action_index] = Some(authorization);
        Ok(())
    }

    /// Consumes a complete session and releases the exact ordered signatures
    /// together with the transcript ID that must frame the encrypted response.
    pub fn finish(self) -> Result<BoundTransferV2Authorizations, SessionError> {
        let authorizations = self
            .authorizations
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(SessionError::IncompleteSession)?;
        Ok(BoundTransferV2Authorizations {
            transcript_id: self.transcript_id,
            public_inputs: self.inner.public_inputs_digest(),
            authorizations,
        })
    }
}

/// Completed response payload inputs for the exact encrypted signer session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundTransferV2Authorizations {
    transcript_id: SigningTranscriptId,
    public_inputs: PublicInputDigest,
    authorizations: Vec<SpendAuthorization>,
}

impl BoundTransferV2Authorizations {
    /// Session transcript echoed in the authenticated response.
    #[must_use]
    pub const fn transcript_id(&self) -> SigningTranscriptId {
        self.transcript_id
    }

    /// Exact effects digest authorized by all returned signatures.
    #[must_use]
    pub const fn public_inputs_digest(&self) -> PublicInputDigest {
        self.public_inputs
    }

    /// Ordered transfer-v2 authorizations.
    #[must_use]
    pub fn authorizations(&self) -> &[SpendAuthorization] {
        &self.authorizations
    }

    /// Consumes the response and releases the canonical signature vector.
    #[must_use]
    pub fn into_authorizations(self) -> Vec<SpendAuthorization> {
        self.authorizations
    }

    /// Canonical encrypted response payload. It contains only public transcript,
    /// effects digest, and signatures but still belongs inside the paired channel.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            RESPONSE_FIXED_BYTES + SPEND_AUTHORIZATION_BYTES * self.authorizations.len(),
        );
        bytes.extend_from_slice(&RESPONSE_MAGIC);
        bytes.extend_from_slice(&RESPONSE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.transcript_id.0);
        bytes.extend_from_slice(self.public_inputs.as_bytes());
        bytes.push(u8::try_from(self.authorizations.len()).expect("at most 16 actions"));
        for authorization in &self.authorizations {
            bytes.extend_from_slice(&authorization.signature());
        }
        debug_assert!(bytes.len() <= SIGNER_AUTHORIZATION_RESPONSE_MAX_BYTES);
        bytes
    }

    /// Parses and verifies a response against the exact expected session and
    /// effects before releasing any signature to the coordinator.
    pub fn decode(
        bytes: &[u8],
        expected_transcript: SigningTranscriptId,
        effects: &TransferV2Effects,
    ) -> Result<Self, SessionError> {
        if bytes.len() > SIGNER_AUTHORIZATION_RESPONSE_MAX_BYTES
            || bytes.len() < RESPONSE_FIXED_BYTES
            || bytes[..4] != RESPONSE_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| SessionError::InvalidResponse)?,
            ) != RESPONSE_VERSION
        {
            return Err(SessionError::InvalidResponse);
        }
        let transcript_id = SigningTranscriptId(
            bytes[6..38]
                .try_into()
                .map_err(|_| SessionError::InvalidResponse)?,
        );
        if transcript_id != expected_transcript {
            return Err(SessionError::InvalidResponse);
        }
        let public_inputs = PublicInputDigest::new(
            bytes[38..70]
                .try_into()
                .map_err(|_| SessionError::InvalidResponse)?,
        );
        if public_inputs != effects.public_inputs_digest() {
            return Err(SessionError::InvalidResponse);
        }
        let action_count = usize::from(bytes[70]);
        let expected_length = RESPONSE_FIXED_BYTES
            .checked_add(
                action_count
                    .checked_mul(SPEND_AUTHORIZATION_BYTES)
                    .ok_or(SessionError::InvalidResponse)?,
            )
            .ok_or(SessionError::InvalidResponse)?;
        if action_count != effects.actions().len() || bytes.len() != expected_length {
            return Err(SessionError::InvalidResponse);
        }
        let digest = SpendAuthorizationDigest::derive(
            *effects.chain_id().as_bytes(),
            *public_inputs.as_bytes(),
        )
        .map_err(|_| SessionError::InvalidResponse)?;
        let mut authorizations = Vec::with_capacity(action_count);
        let mut offset = RESPONSE_FIXED_BYTES;
        for action in effects.actions() {
            let end = offset + SPEND_AUTHORIZATION_BYTES;
            let signature = bytes
                .get(offset..end)
                .ok_or(SessionError::InvalidResponse)?
                .try_into()
                .map_err(|_| SessionError::InvalidResponse)?;
            let authorization = SpendAuthorization::from_parts(
                action.randomized_verification_key().to_bytes(),
                signature,
            )
            .map_err(|_| SessionError::InvalidResponse)?;
            if !authorization.verify(digest) {
                return Err(SessionError::InvalidResponse);
            }
            authorizations.push(authorization);
            offset = end;
        }
        Ok(Self {
            transcript_id,
            public_inputs,
            authorizations,
        })
    }
}

fn derive_transcript(
    challenge: &SessionChallenge,
    policy_digest: [u8; 32],
    public_inputs: PublicInputDigest,
    authorizations: &[VerifiedOutputAuthorization],
) -> SigningTranscriptId {
    let packet_digests: Vec<_> = authorizations
        .iter()
        .map(VerifiedOutputAuthorization::packet_digest)
        .collect();
    derive_transcript_from_digests(challenge, policy_digest, public_inputs, &packet_digests)
}

fn derive_transcript_from_digests(
    challenge: &SessionChallenge,
    policy_digest: [u8; 32],
    public_inputs: PublicInputDigest,
    packet_digests: &[[u8; 32]],
) -> SigningTranscriptId {
    let challenge_bytes = challenge.encode();
    let mut hasher = Hasher::new_derive_key(TRANSCRIPT_DOMAIN);
    hasher.update(challenge_bytes.as_ref());
    hasher.update(&policy_digest);
    hasher.update(public_inputs.as_bytes());
    hasher.update(&[u8::try_from(packet_digests.len()).expect("at most 16 actions")]);
    for digest in packet_digests {
        hasher.update(digest);
    }
    SigningTranscriptId(*hasher.finalize().as_bytes())
}
