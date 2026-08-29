//! Canonical participant agreement for threshold RedPallas signing.
//!
//! This module freezes the Vault product boundary around a future reviewed
//! re-randomized FROST adapter. It does not implement threshold cryptography or
//! enable Orchard's unstable FROST feature. The only result accepted by the
//! transfer session remains a standard RedPallas authorization verified under
//! the action key already bound by the proof.

use core::fmt;
use std::collections::BTreeSet;

use blake3::Hasher;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use vault_privacy::{
    PreparedSpendAuthorization, RandomizedSpendValidatingKey, SpendAuthorizationDigest,
    VaultFullViewingKey,
};
use vault_protocol::PublicInputDigest;

use crate::{PairedPeerId, SignerConfirmationError, SigningTranscriptId};

const POLICY_MAGIC: [u8; 4] = *b"VMSP";
const POLICY_VERSION: u16 = 1;
const POLICY_HEADER_BYTES: usize = 72;
const POLICY_PARTICIPANT_BYTES: usize = 66;
const POLICY_ID_DOMAIN: &str = "vault.signer.multisig.policy.v1";

const COMMITMENT_MAGIC: [u8; 4] = *b"VMSC";
const COMMITMENT_VERSION: u16 = 1;
const COMMITMENT_HEADER_BYTES: usize = 72;
const COMMITMENT_ENTRY_BYTES: usize = 66;
const COMMITMENT_ID_DOMAIN: &str = "vault.signer.multisig.commitments.v1";

const AGREEMENT_MAGIC: [u8; 4] = *b"VMSA";
const AGREEMENT_VERSION: u16 = 1;
const AGREEMENT_HEADER_BYTES: usize = 266;
const AGREEMENT_ID_DOMAIN: &str = "vault.signer.multisig.agreement.v1";
const RANDOMIZER_COMMITMENT_DOMAIN: &str = "vault.signer.multisig.randomizer.v1";

/// Minimum useful threshold and roster size in the Vault multisig profile.
pub const MIN_MULTISIG_PARTICIPANTS: usize = 2;
/// Maximum roster size, matching the active paired-signer bound.
pub const MAX_MULTISIG_PARTICIPANTS: usize = 16;
/// Maximum canonical policy descriptor length.
pub const MULTISIG_POLICY_MAX_BYTES: usize =
    POLICY_HEADER_BYTES + POLICY_PARTICIPANT_BYTES * MAX_MULTISIG_PARTICIPANTS;
/// Maximum canonical round-one commitment-set length.
pub const MULTISIG_COMMITMENT_SET_MAX_BYTES: usize =
    COMMITMENT_HEADER_BYTES + COMMITMENT_ENTRY_BYTES * MAX_MULTISIG_PARTICIPANTS;
/// Maximum canonical signing-agreement length.
pub const MULTISIG_SIGNING_AGREEMENT_MAX_BYTES: usize =
    AGREEMENT_HEADER_BYTES + 2 * MAX_MULTISIG_PARTICIPANTS;

/// Stable non-zero FROST participant identifier in the Vault profile.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MultisigParticipantId(u16);

impl MultisigParticipantId {
    /// Creates a non-zero participant identifier.
    pub fn new(value: u16) -> Result<Self, MultisigError> {
        if value == 0 {
            return Err(MultisigError::InvalidParticipant);
        }
        Ok(Self(value))
    }

    /// Exact unsigned identifier mapped into the FROST scalar field.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// One enrolled FROST participant and its paired transport identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MultisigParticipant {
    id: MultisigParticipantId,
    peer_id: PairedPeerId,
    verifying_share: [u8; 32],
}

impl fmt::Debug for MultisigParticipant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultisigParticipant")
            .field("id", &self.id)
            .field("identities", &"REDACTED")
            .finish()
    }
}

impl MultisigParticipant {
    /// Binds a canonical non-identity RedPallas verifying share to one peer.
    pub fn new(
        id: MultisigParticipantId,
        peer_id: PairedPeerId,
        verifying_share: [u8; 32],
    ) -> Result<Self, MultisigError> {
        RandomizedSpendValidatingKey::from_bytes(verifying_share)
            .map_err(|_| MultisigError::InvalidParticipant)?;
        Ok(Self {
            id,
            peer_id,
            verifying_share,
        })
    }

    /// FROST identifier.
    #[must_use]
    pub const fn id(self) -> MultisigParticipantId {
        self.id
    }

    /// Confirmed paired transport identity assigned at enrollment.
    #[must_use]
    pub const fn peer_id(self) -> PairedPeerId {
        self.peer_id
    }

    /// Canonical RedPallas public verifying share.
    #[must_use]
    pub const fn verifying_share(self) -> [u8; 32] {
        self.verifying_share
    }
}

/// Digest of one exact multisig roster, threshold, network and group key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MultisigPolicyId([u8; 32]);

impl MultisigPolicyId {
    /// Exact policy digest bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for MultisigPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MultisigPolicyId(REDACTED)")
    }
}

/// Canonical immutable participant policy for one threshold account.
#[derive(Clone, Eq, PartialEq)]
pub struct MultisigPolicy {
    network_id: [u8; 32],
    group_validating_key: [u8; 32],
    threshold: u8,
    participants: Vec<MultisigParticipant>,
}

impl fmt::Debug for MultisigPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultisigPolicy")
            .field("threshold", &self.threshold)
            .field("participant_count", &self.participants.len())
            .field("key_material", &"REDACTED")
            .finish()
    }
}

impl MultisigPolicy {
    /// Creates a policy bound to the exact account full-viewing key.
    pub fn new(
        network_id: [u8; 32],
        threshold: u8,
        full_viewing_key: &VaultFullViewingKey,
        participants: Vec<MultisigParticipant>,
    ) -> Result<Self, MultisigError> {
        Self::from_group_key(
            network_id,
            full_viewing_key.spend_validating_key(),
            threshold,
            participants,
        )
    }

    fn from_group_key(
        network_id: [u8; 32],
        group_validating_key: [u8; 32],
        threshold: u8,
        participants: Vec<MultisigParticipant>,
    ) -> Result<Self, MultisigError> {
        let threshold_usize = usize::from(threshold);
        if network_id == [0; 32]
            || participants.len() < MIN_MULTISIG_PARTICIPANTS
            || participants.len() > MAX_MULTISIG_PARTICIPANTS
            || threshold_usize < MIN_MULTISIG_PARTICIPANTS
            || threshold_usize > participants.len()
            || RandomizedSpendValidatingKey::from_bytes(group_validating_key).is_err()
            || participants.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(MultisigError::InvalidPolicy);
        }
        let mut peers = BTreeSet::new();
        let mut shares = BTreeSet::new();
        if participants.iter().any(|participant| {
            !peers.insert(participant.peer_id) || !shares.insert(participant.verifying_share)
        }) {
            return Err(MultisigError::InvalidPolicy);
        }
        Ok(Self {
            network_id,
            group_validating_key,
            threshold,
            participants,
        })
    }

    /// Parses the canonical bounded policy descriptor.
    pub fn decode(bytes: &[u8]) -> Result<Self, MultisigError> {
        if bytes.len() < POLICY_HEADER_BYTES
            || bytes.len() > MULTISIG_POLICY_MAX_BYTES
            || bytes[..4] != POLICY_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| MultisigError::InvalidPolicy)?,
            ) != POLICY_VERSION
        {
            return Err(MultisigError::InvalidPolicy);
        }
        let threshold = bytes[6];
        let participant_count = usize::from(bytes[7]);
        let expected_length = POLICY_HEADER_BYTES
            .checked_add(
                participant_count
                    .checked_mul(POLICY_PARTICIPANT_BYTES)
                    .ok_or(MultisigError::InvalidPolicy)?,
            )
            .ok_or(MultisigError::InvalidPolicy)?;
        if participant_count > MAX_MULTISIG_PARTICIPANTS || bytes.len() != expected_length {
            return Err(MultisigError::InvalidPolicy);
        }
        let network_id = bytes[8..40]
            .try_into()
            .map_err(|_| MultisigError::InvalidPolicy)?;
        let group_validating_key = bytes[40..72]
            .try_into()
            .map_err(|_| MultisigError::InvalidPolicy)?;
        let mut participants = Vec::with_capacity(participant_count);
        let mut offset = POLICY_HEADER_BYTES;
        for _ in 0..participant_count {
            let id = MultisigParticipantId::new(u16::from_le_bytes(
                bytes[offset..offset + 2]
                    .try_into()
                    .map_err(|_| MultisigError::InvalidPolicy)?,
            ))?;
            let peer_id = PairedPeerId::from_bytes(
                bytes[offset + 2..offset + 34]
                    .try_into()
                    .map_err(|_| MultisigError::InvalidPolicy)?,
            )
            .map_err(|_| MultisigError::InvalidPolicy)?;
            let verifying_share = bytes[offset + 34..offset + 66]
                .try_into()
                .map_err(|_| MultisigError::InvalidPolicy)?;
            participants.push(
                MultisigParticipant::new(id, peer_id, verifying_share)
                    .map_err(|_| MultisigError::InvalidPolicy)?,
            );
            offset += POLICY_PARTICIPANT_BYTES;
        }
        Self::from_group_key(network_id, group_validating_key, threshold, participants)
    }

    /// Canonical variable-length descriptor, bounded at 1,128 bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            POLICY_HEADER_BYTES + POLICY_PARTICIPANT_BYTES * self.participants.len(),
        );
        bytes.extend_from_slice(&POLICY_MAGIC);
        bytes.extend_from_slice(&POLICY_VERSION.to_le_bytes());
        bytes.push(self.threshold);
        bytes.push(u8::try_from(self.participants.len()).expect("participant bound is 16"));
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.group_validating_key);
        for participant in &self.participants {
            bytes.extend_from_slice(&participant.id.0.to_le_bytes());
            bytes.extend_from_slice(&participant.peer_id.to_bytes());
            bytes.extend_from_slice(&participant.verifying_share);
        }
        bytes
    }

    /// Domain-separated identity of this complete immutable policy.
    #[must_use]
    pub fn policy_id(&self) -> MultisigPolicyId {
        let mut hasher = Hasher::new_derive_key(POLICY_ID_DOMAIN);
        hasher.update(&self.encode());
        MultisigPolicyId(*hasher.finalize().as_bytes())
    }

    /// Network domain for every threshold signing attempt.
    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Account-level RedPallas group key.
    #[must_use]
    pub const fn group_validating_key(&self) -> [u8; 32] {
        self.group_validating_key
    }

    /// Required signer count.
    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Strictly sorted complete roster.
    #[must_use]
    pub fn participants(&self) -> &[MultisigParticipant] {
        &self.participants
    }

    fn contains(&self, id: MultisigParticipantId) -> bool {
        self.participants
            .binary_search_by_key(&id, |participant| participant.id)
            .is_ok()
    }
}

/// Unique non-zero identifier for one action-specific threshold attempt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MultisigAttemptId([u8; 32]);

impl MultisigAttemptId {
    /// Generates a fresh non-zero identifier from a CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, MultisigError> {
        for _ in 0..=u16::MAX {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            if bytes != [0; 32] {
                return Ok(Self(bytes));
            }
        }
        Err(MultisigError::EntropyUnavailable)
    }

    /// Restores a previously generated non-zero attempt ID.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, MultisigError> {
        if bytes == [0; 32] {
            return Err(MultisigError::InvalidAgreement);
        }
        Ok(Self(bytes))
    }

    /// Exact attempt identifier bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for MultisigAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MultisigAttemptId(REDACTED)")
    }
}

/// One participant's action-specific FROST round-one commitment pair.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MultisigNonceCommitment {
    participant_id: MultisigParticipantId,
    hiding: [u8; 32],
    binding: [u8; 32],
}

impl fmt::Debug for MultisigNonceCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultisigNonceCommitment")
            .field("participant_id", &self.participant_id)
            .field("commitments", &"REDACTED")
            .finish()
    }
}

impl MultisigNonceCommitment {
    /// Validates two distinct, non-identity canonical Pallas commitments.
    pub fn new(
        participant_id: MultisigParticipantId,
        hiding: [u8; 32],
        binding: [u8; 32],
    ) -> Result<Self, MultisigError> {
        if hiding == binding
            || RandomizedSpendValidatingKey::from_bytes(hiding).is_err()
            || RandomizedSpendValidatingKey::from_bytes(binding).is_err()
        {
            return Err(MultisigError::InvalidCommitment);
        }
        Ok(Self {
            participant_id,
            hiding,
            binding,
        })
    }

    /// Participant that durably owns the secret nonce pair.
    #[must_use]
    pub const fn participant_id(self) -> MultisigParticipantId {
        self.participant_id
    }

    /// Canonical hiding nonce commitment.
    #[must_use]
    pub const fn hiding(self) -> [u8; 32] {
        self.hiding
    }

    /// Canonical binding nonce commitment.
    #[must_use]
    pub const fn binding(self) -> [u8; 32] {
        self.binding
    }
}

/// Exact-threshold, action-specific round-one commitment set.
#[derive(Clone, Eq, PartialEq)]
pub struct MultisigCommitmentSet {
    policy_id: MultisigPolicyId,
    attempt_id: MultisigAttemptId,
    commitments: Vec<MultisigNonceCommitment>,
}

impl fmt::Debug for MultisigCommitmentSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultisigCommitmentSet")
            .field("participant_count", &self.commitments.len())
            .field("commitments", &"REDACTED")
            .finish()
    }
}

impl MultisigCommitmentSet {
    /// Freezes exactly `threshold` sorted participants for one fresh attempt.
    pub fn new(
        policy: &MultisigPolicy,
        attempt_id: MultisigAttemptId,
        commitments: Vec<MultisigNonceCommitment>,
    ) -> Result<Self, MultisigError> {
        let mut nonce_points = BTreeSet::new();
        if commitments.len() != usize::from(policy.threshold)
            || commitments
                .windows(2)
                .any(|pair| pair[0].participant_id >= pair[1].participant_id)
            || commitments
                .iter()
                .any(|commitment| !policy.contains(commitment.participant_id))
            || commitments.iter().any(|commitment| {
                !nonce_points.insert(commitment.hiding) || !nonce_points.insert(commitment.binding)
            })
        {
            return Err(MultisigError::InvalidCommitment);
        }
        Ok(Self {
            policy_id: policy.policy_id(),
            attempt_id,
            commitments,
        })
    }

    /// Parses and revalidates an exact commitment set against its policy.
    pub fn decode(bytes: &[u8], policy: &MultisigPolicy) -> Result<Self, MultisigError> {
        if bytes.len() < COMMITMENT_HEADER_BYTES
            || bytes.len() > MULTISIG_COMMITMENT_SET_MAX_BYTES
            || bytes[..4] != COMMITMENT_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| MultisigError::InvalidCommitment)?,
            ) != COMMITMENT_VERSION
        {
            return Err(MultisigError::InvalidCommitment);
        }
        let count = usize::from(u16::from_le_bytes(
            bytes[6..8]
                .try_into()
                .map_err(|_| MultisigError::InvalidCommitment)?,
        ));
        let expected_length = COMMITMENT_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(COMMITMENT_ENTRY_BYTES)
                    .ok_or(MultisigError::InvalidCommitment)?,
            )
            .ok_or(MultisigError::InvalidCommitment)?;
        let encoded_policy = MultisigPolicyId(
            bytes[8..40]
                .try_into()
                .map_err(|_| MultisigError::InvalidCommitment)?,
        );
        if bytes.len() != expected_length || encoded_policy != policy.policy_id() {
            return Err(MultisigError::InvalidCommitment);
        }
        let attempt_id = MultisigAttemptId::from_bytes(
            bytes[40..72]
                .try_into()
                .map_err(|_| MultisigError::InvalidCommitment)?,
        )
        .map_err(|_| MultisigError::InvalidCommitment)?;
        let mut commitments = Vec::with_capacity(count);
        let mut offset = COMMITMENT_HEADER_BYTES;
        for _ in 0..count {
            let participant_id = MultisigParticipantId::new(u16::from_le_bytes(
                bytes[offset..offset + 2]
                    .try_into()
                    .map_err(|_| MultisigError::InvalidCommitment)?,
            ))
            .map_err(|_| MultisigError::InvalidCommitment)?;
            let hiding = bytes[offset + 2..offset + 34]
                .try_into()
                .map_err(|_| MultisigError::InvalidCommitment)?;
            let binding = bytes[offset + 34..offset + 66]
                .try_into()
                .map_err(|_| MultisigError::InvalidCommitment)?;
            commitments.push(MultisigNonceCommitment::new(
                participant_id,
                hiding,
                binding,
            )?);
            offset += COMMITMENT_ENTRY_BYTES;
        }
        Self::new(policy, attempt_id, commitments)
    }

    /// Canonical bounded commitment-set encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            COMMITMENT_HEADER_BYTES + COMMITMENT_ENTRY_BYTES * self.commitments.len(),
        );
        bytes.extend_from_slice(&COMMITMENT_MAGIC);
        bytes.extend_from_slice(&COMMITMENT_VERSION.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(self.commitments.len())
                .expect("participant bound is 16")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.policy_id.0);
        bytes.extend_from_slice(&self.attempt_id.0);
        for commitment in &self.commitments {
            bytes.extend_from_slice(&commitment.participant_id.0.to_le_bytes());
            bytes.extend_from_slice(&commitment.hiding);
            bytes.extend_from_slice(&commitment.binding);
        }
        bytes
    }

    /// Digest bound into the round-two participant agreement.
    #[must_use]
    pub fn commitment_id(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(COMMITMENT_ID_DOMAIN);
        hasher.update(&self.encode());
        *hasher.finalize().as_bytes()
    }

    /// Exact attempt owning every commitment.
    #[must_use]
    pub const fn attempt_id(&self) -> MultisigAttemptId {
        self.attempt_id
    }

    /// Exact-threshold sorted commitment list.
    #[must_use]
    pub fn commitments(&self) -> &[MultisigNonceCommitment] {
        &self.commitments
    }
}

/// Digest of every transaction and FROST package fact approved in round two.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MultisigAgreementId([u8; 32]);

impl MultisigAgreementId {
    /// Restores agreement bytes independently observed by a trusted adapter.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exact agreement digest bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for MultisigAgreementId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MultisigAgreementId(REDACTED)")
    }
}

/// Complete action-specific agreement checked before a signature share exists.
#[derive(Clone, Eq, PartialEq)]
pub struct MultisigSigningAgreement {
    action_index: u8,
    action_count: u8,
    policy_id: MultisigPolicyId,
    attempt_id: MultisigAttemptId,
    transcript_id: SigningTranscriptId,
    public_inputs: PublicInputDigest,
    authorization_digest: SpendAuthorizationDigest,
    randomized_key: [u8; 32],
    randomizer_commitment: [u8; 32],
    commitment_id: [u8; 32],
    selected: Vec<MultisigParticipantId>,
}

impl fmt::Debug for MultisigSigningAgreement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultisigSigningAgreement")
            .field("action_index", &self.action_index)
            .field("action_count", &self.action_count)
            .field("selected_count", &self.selected.len())
            .field("cryptographic_facts", &"REDACTED")
            .finish()
    }
}

impl MultisigSigningAgreement {
    /// Builds the exact round-two agreement and verifies proof-key randomization.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: &MultisigPolicy,
        commitments: &MultisigCommitmentSet,
        transcript_id: SigningTranscriptId,
        public_inputs: PublicInputDigest,
        action_index: usize,
        action_count: usize,
        prepared: &PreparedSpendAuthorization,
    ) -> Result<Self, MultisigError> {
        if commitments.policy_id != policy.policy_id()
            || !matches!(action_count, 2 | 4 | 8 | 16)
            || action_index >= action_count
            || !prepared.matches_group_validating_key(policy.group_validating_key)
        {
            return Err(MultisigError::InvalidAgreement);
        }
        let action_index =
            u8::try_from(action_index).map_err(|_| MultisigError::InvalidAgreement)?;
        let action_count =
            u8::try_from(action_count).map_err(|_| MultisigError::InvalidAgreement)?;
        let authorization_digest =
            SpendAuthorizationDigest::derive(policy.network_id, *public_inputs.as_bytes())
                .map_err(|_| MultisigError::InvalidAgreement)?;
        let randomizer = prepared.randomizer();
        let mut randomizer_hasher = Hasher::new_derive_key(RANDOMIZER_COMMITMENT_DOMAIN);
        randomizer_hasher.update(&policy.policy_id().0);
        randomizer_hasher.update(&commitments.attempt_id.0);
        randomizer_hasher.update(&transcript_id.to_bytes());
        randomizer_hasher.update(public_inputs.as_bytes());
        randomizer_hasher.update(&[action_index, action_count]);
        randomizer_hasher.update(randomizer.as_ref());
        let selected = commitments
            .commitments
            .iter()
            .map(|commitment| commitment.participant_id)
            .collect();
        Ok(Self {
            action_index,
            action_count,
            policy_id: policy.policy_id(),
            attempt_id: commitments.attempt_id,
            transcript_id,
            public_inputs,
            authorization_digest,
            randomized_key: prepared.randomized_verification_key(),
            randomizer_commitment: *randomizer_hasher.finalize().as_bytes(),
            commitment_id: commitments.commitment_id(),
            selected,
        })
    }

    /// Parses and independently reconstructs the canonical agreement.
    pub fn decode(
        bytes: &[u8],
        policy: &MultisigPolicy,
        commitments: &MultisigCommitmentSet,
        prepared: &PreparedSpendAuthorization,
    ) -> Result<Self, MultisigError> {
        if bytes.len() < AGREEMENT_HEADER_BYTES
            || bytes.len() > MULTISIG_SIGNING_AGREEMENT_MAX_BYTES
            || bytes[..4] != AGREEMENT_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| MultisigError::InvalidAgreement)?,
            ) != AGREEMENT_VERSION
            || bytes[9] != 0
        {
            return Err(MultisigError::InvalidAgreement);
        }
        let selected_count = usize::from(bytes[8]);
        let expected_length = AGREEMENT_HEADER_BYTES
            .checked_add(
                selected_count
                    .checked_mul(2)
                    .ok_or(MultisigError::InvalidAgreement)?,
            )
            .ok_or(MultisigError::InvalidAgreement)?;
        if bytes.len() != expected_length {
            return Err(MultisigError::InvalidAgreement);
        }
        let transcript_id = SigningTranscriptId::from_bytes(
            bytes[74..106]
                .try_into()
                .map_err(|_| MultisigError::InvalidAgreement)?,
        );
        let public_inputs = PublicInputDigest::new(
            bytes[106..138]
                .try_into()
                .map_err(|_| MultisigError::InvalidAgreement)?,
        );
        let reconstructed = Self::new(
            policy,
            commitments,
            transcript_id,
            public_inputs,
            usize::from(bytes[6]),
            usize::from(bytes[7]),
            prepared,
        )?;
        let encoded = reconstructed.encode();
        if !bool::from(encoded.as_slice().ct_eq(bytes)) {
            return Err(MultisigError::InvalidAgreement);
        }
        Ok(reconstructed)
    }

    /// Canonical bounded agreement encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(AGREEMENT_HEADER_BYTES + self.selected.len() * 2);
        bytes.extend_from_slice(&AGREEMENT_MAGIC);
        bytes.extend_from_slice(&AGREEMENT_VERSION.to_le_bytes());
        bytes.push(self.action_index);
        bytes.push(self.action_count);
        bytes.push(u8::try_from(self.selected.len()).expect("participant bound is 16"));
        bytes.push(0);
        bytes.extend_from_slice(&self.policy_id.0);
        bytes.extend_from_slice(&self.attempt_id.0);
        bytes.extend_from_slice(&self.transcript_id.to_bytes());
        bytes.extend_from_slice(self.public_inputs.as_bytes());
        bytes.extend_from_slice(self.authorization_digest.as_bytes());
        bytes.extend_from_slice(&self.randomized_key);
        bytes.extend_from_slice(&self.randomizer_commitment);
        bytes.extend_from_slice(&self.commitment_id);
        for participant in &self.selected {
            bytes.extend_from_slice(&participant.0.to_le_bytes());
        }
        bytes
    }

    /// Domain-separated identity that every selected signer must approve.
    #[must_use]
    pub fn agreement_id(&self) -> MultisigAgreementId {
        let mut hasher = Hasher::new_derive_key(AGREEMENT_ID_DOMAIN);
        hasher.update(&self.encode());
        MultisigAgreementId(*hasher.finalize().as_bytes())
    }

    /// Requests independent confirmation from one selected participant.
    pub fn confirm<C: TrustedMultisigAgreement>(
        &self,
        participant_id: MultisigParticipantId,
        confirmation: &mut C,
    ) -> Result<ConfirmedMultisigAgreement, MultisigError> {
        if self.selected.binary_search(&participant_id).is_err() {
            return Err(MultisigError::ParticipantNotSelected);
        }
        let facts = MultisigAgreementFacts {
            agreement_id: self.agreement_id(),
            policy_id: self.policy_id,
            attempt_id: self.attempt_id,
            transcript_id: self.transcript_id,
            public_inputs: self.public_inputs,
            authorization_digest: self.authorization_digest,
            action_index: self.action_index,
            action_count: self.action_count,
            randomized_key: self.randomized_key,
            randomizer_commitment: self.randomizer_commitment,
            commitment_id: self.commitment_id,
            selected: self.selected.clone(),
        };
        let observed = confirmation
            .confirm_multisig_agreement(&facts)
            .map_err(|_| MultisigError::ConfirmationFailed)?;
        if !bool::from(observed.to_bytes().ct_eq(&facts.agreement_id.to_bytes())) {
            return Err(MultisigError::ConfirmationFailed);
        }
        Ok(ConfirmedMultisigAgreement {
            agreement_id: facts.agreement_id,
            attempt_id: facts.attempt_id,
            participant_id,
        })
    }

    /// Action index in the padded transfer.
    #[must_use]
    pub const fn action_index(&self) -> usize {
        self.action_index as usize
    }

    /// Complete padded action count.
    #[must_use]
    pub const fn action_count(&self) -> usize {
        self.action_count as usize
    }

    /// Bound transfer signer transcript.
    #[must_use]
    pub const fn transcript_id(&self) -> SigningTranscriptId {
        self.transcript_id
    }

    /// Exact public-effects digest.
    #[must_use]
    pub const fn public_inputs_digest(&self) -> PublicInputDigest {
        self.public_inputs
    }

    /// Exact message signed by re-randomized FROST.
    #[must_use]
    pub const fn authorization_digest(&self) -> SpendAuthorizationDigest {
        self.authorization_digest
    }

    /// Action key already bound inside the transfer proof.
    #[must_use]
    pub const fn randomized_validating_key(&self) -> [u8; 32] {
        self.randomized_key
    }

    /// Exact selected participant set; it always has threshold size.
    #[must_use]
    pub fn selected_participants(&self) -> &[MultisigParticipantId] {
        &self.selected
    }
}

/// Public facts shown by one selected signer before producing a share.
#[derive(Clone, Eq, PartialEq)]
pub struct MultisigAgreementFacts {
    agreement_id: MultisigAgreementId,
    policy_id: MultisigPolicyId,
    attempt_id: MultisigAttemptId,
    transcript_id: SigningTranscriptId,
    public_inputs: PublicInputDigest,
    authorization_digest: SpendAuthorizationDigest,
    action_index: u8,
    action_count: u8,
    randomized_key: [u8; 32],
    randomizer_commitment: [u8; 32],
    commitment_id: [u8; 32],
    selected: Vec<MultisigParticipantId>,
}

impl fmt::Debug for MultisigAgreementFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultisigAgreementFacts")
            .field("action_index", &self.action_index)
            .field("action_count", &self.action_count)
            .field("selected_count", &self.selected.len())
            .field("cryptographic_facts", &"REDACTED")
            .finish()
    }
}

impl MultisigAgreementFacts {
    /// Complete agreement identity to compare independently.
    #[must_use]
    pub const fn agreement_id(&self) -> MultisigAgreementId {
        self.agreement_id
    }

    /// Immutable roster/policy identity.
    #[must_use]
    pub const fn policy_id(&self) -> MultisigPolicyId {
        self.policy_id
    }

    /// Fresh action-specific signing attempt.
    #[must_use]
    pub const fn attempt_id(&self) -> MultisigAttemptId {
        self.attempt_id
    }

    /// Bound transfer transcript.
    #[must_use]
    pub const fn transcript_id(&self) -> SigningTranscriptId {
        self.transcript_id
    }

    /// Exact transaction-effects digest.
    #[must_use]
    pub const fn public_inputs_digest(&self) -> PublicInputDigest {
        self.public_inputs
    }

    /// Exact RedPallas message.
    #[must_use]
    pub const fn authorization_digest(&self) -> SpendAuthorizationDigest {
        self.authorization_digest
    }

    /// Action position and padded action count.
    #[must_use]
    pub const fn action_position(&self) -> (usize, usize) {
        (self.action_index as usize, self.action_count as usize)
    }

    /// Proof-bound randomized action key.
    #[must_use]
    pub const fn randomized_validating_key(&self) -> [u8; 32] {
        self.randomized_key
    }

    /// Commitment to the confidential proof/FROST key randomizer.
    #[must_use]
    pub const fn randomizer_commitment(&self) -> [u8; 32] {
        self.randomizer_commitment
    }

    /// Digest of the exact round-one commitment set.
    #[must_use]
    pub const fn commitment_id(&self) -> [u8; 32] {
        self.commitment_id
    }

    /// Exact threshold-sized selected participant set.
    #[must_use]
    pub fn selected_participants(&self) -> &[MultisigParticipantId] {
        &self.selected
    }
}

/// Trusted local confirmation required before a FROST adapter may sign.
pub trait TrustedMultisigAgreement {
    /// Shows/checks the exact agreement and returns the independently approved ID.
    fn confirm_multisig_agreement(
        &mut self,
        facts: &MultisigAgreementFacts,
    ) -> Result<MultisigAgreementId, SignerConfirmationError>;
}

/// One selected participant's non-transferable approval token.
pub struct ConfirmedMultisigAgreement {
    agreement_id: MultisigAgreementId,
    attempt_id: MultisigAttemptId,
    participant_id: MultisigParticipantId,
}

impl fmt::Debug for ConfirmedMultisigAgreement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmedMultisigAgreement(REDACTED)")
    }
}

impl ConfirmedMultisigAgreement {
    /// Participant whose trusted surface approved the agreement.
    #[must_use]
    pub const fn participant_id(&self) -> MultisigParticipantId {
        self.participant_id
    }

    /// Whether this one-shot token belongs to the supplied agreement.
    #[must_use]
    pub fn matches(&self, agreement: &MultisigSigningAgreement) -> bool {
        self.attempt_id == agreement.attempt_id
            && bool::from(
                self.agreement_id
                    .to_bytes()
                    .ct_eq(&agreement.agreement_id().to_bytes()),
            )
    }
}

/// Participant-owned two-round adapter with durable nonce lifecycle.
///
/// `reserve_nonces` MUST durably reserve a fresh secret hiding/binding pair for
/// the exact policy, attempt and action before exposing its commitment. It MUST
/// reject reuse after restart. `sign_share` MUST require the matching confirmed
/// token, independently reconstruct the complete agreement and proof
/// randomizer, and atomically burn the nonce pair before returning a share.
/// `abort` MUST also burn any reserved nonce. Any timeout, missing selected
/// participant, changed package, invalid share, storage uncertainty, or peer
/// revocation aborts the whole exact-threshold attempt; retry uses a fresh
/// attempt ID and fresh nonces for every participant.
pub trait MultisigParticipantRound {
    /// Concrete reviewed FROST adapter error.
    type Error: std::error::Error;
    /// Concrete canonical FROST signature-share type.
    type SignatureShare;

    /// Durably reserves one nonce pair and returns its public commitments.
    fn reserve_nonces(
        &mut self,
        policy: &MultisigPolicy,
        attempt_id: MultisigAttemptId,
        transcript_id: SigningTranscriptId,
        action_index: usize,
        action_count: usize,
    ) -> Result<MultisigNonceCommitment, Self::Error>;

    /// Consumes a confirmed agreement and burns its nonce before releasing a share.
    fn sign_share(
        &mut self,
        policy: &MultisigPolicy,
        commitments: &MultisigCommitmentSet,
        agreement: &MultisigSigningAgreement,
        confirmation: ConfirmedMultisigAgreement,
        prepared: &PreparedSpendAuthorization,
    ) -> Result<Self::SignatureShare, Self::Error>;

    /// Irreversibly burns any nonce reserved for the failed attempt.
    fn abort(&mut self, attempt_id: MultisigAttemptId) -> Result<(), Self::Error>;
}

/// Canonical multisig profile failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultisigError {
    /// Roster, threshold, network or group key is invalid.
    InvalidPolicy,
    /// Participant identifier, peer binding or verifying share is invalid.
    InvalidParticipant,
    /// Round-one commitment set is invalid or not exactly threshold-sized.
    InvalidCommitment,
    /// Round-two agreement differs from the transaction/proof/package facts.
    InvalidAgreement,
    /// The requested participant is not in the frozen signing subset.
    ParticipantNotSelected,
    /// Trusted confirmation failed or approved a different agreement.
    ConfirmationFailed,
    /// A fresh non-zero attempt identifier could not be generated.
    EntropyUnavailable,
}

impl fmt::Display for MultisigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPolicy => "invalid multisig policy",
            Self::InvalidParticipant => "invalid multisig participant",
            Self::InvalidCommitment => "invalid multisig commitment set",
            Self::InvalidAgreement => "invalid multisig signing agreement",
            Self::ParticipantNotSelected => "multisig participant is not selected",
            Self::ConfirmationFailed => "multisig agreement confirmation failed",
            Self::EntropyUnavailable => "multisig attempt entropy is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MultisigError {}
