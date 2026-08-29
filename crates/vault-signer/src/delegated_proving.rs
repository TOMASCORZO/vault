//! Authorization and disclosure contracts for delegated transfer proving.
//!
//! Local proving remains the default. This module deliberately implements no
//! prover network, durable store, or permissive proof verifier. It freezes the
//! exact per-job approval, bounded request/response envelopes, and fail-closed
//! lifecycle that future reviewed adapters must implement.

use core::fmt;

use blake3::Hasher;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use vault_protocol::{
    ALLOWED_TRANSFER_V2_ACTION_COUNTS, MAX_PROOF_BYTES, PublicInputDigest,
    TRANSFER_V2_MAX_EFFECT_BYTES, TransferV2Effects,
};
use zeroize::Zeroizing;

use crate::SignerConfirmationError;

const POLICY_MAGIC: [u8; 4] = *b"VDPP";
const POLICY_VERSION: u16 = 1;
const AUTHORIZATION_MAGIC: [u8; 4] = *b"VDPA";
const AUTHORIZATION_VERSION: u16 = 1;
const REQUEST_MAGIC: [u8; 4] = *b"VDPR";
const REQUEST_VERSION: u16 = 1;
const RESPONSE_MAGIC: [u8; 4] = *b"VDPS";
const RESPONSE_VERSION: u16 = 1;
const DELEGATED_WITNESS_MAGIC: [u8; 4] = *b"VDPW";
const DELEGATED_WITNESS_VERSION: u16 = 1;
const REQUEST_HEADER_BYTES: usize = 4 + 2 + 1 + 1 + 4 + 4;
const RESPONSE_HEADER_BYTES: usize = 4 + 2 + 1 + 1 + 4 * 32 + 4;
const DELEGATED_WITNESS_BINDING_BYTES: usize = 4 + 2 + 1 + 1 + 3 * 32;

const POLICY_ID_DOMAIN: &str = "vault.signer.delegated-proving.policy.v1";
const PROVER_ID_DOMAIN: &str = "vault.signer.delegated-proving.prover-id.v1";
const PROVER_FINGERPRINT_DOMAIN: &str = "vault.signer.delegated-proving.fingerprint.v1";
const WITNESS_COMMITMENT_DOMAIN: &str = "vault.signer.delegated-proving.witness.v1";
const AUTHORIZATION_ID_DOMAIN: &str = "vault.signer.delegated-proving.authorization.v1";
const REVOCATION_ID_DOMAIN: &str = "vault.signer.delegated-proving.revocation.v1";

/// Fixed canonical delegated-proving policy length.
pub const DELEGATED_PROVING_POLICY_BYTES: usize = 148;
/// Fixed canonical one-job authorization length.
pub const DELEGATED_PROVING_AUTHORIZATION_BYTES: usize = 184;
/// Absolute pre-allocation bound for the canonical VDPW v1 private witness.
pub const DELEGATED_PROVING_WITNESS_MAX_BYTES: usize = 60_286;
/// Absolute canonical request bound before any allocation.
pub const DELEGATED_PROVING_REQUEST_MAX_BYTES: usize = REQUEST_HEADER_BYTES
    + DELEGATED_PROVING_POLICY_BYTES
    + DELEGATED_PROVING_AUTHORIZATION_BYTES
    + TRANSFER_V2_MAX_EFFECT_BYTES
    + DELEGATED_PROVING_WITNESS_MAX_BYTES;
/// Absolute canonical response bound before any allocation.
pub const DELEGATED_PROVING_RESPONSE_MAX_BYTES: usize = RESPONSE_HEADER_BYTES + MAX_PROOF_BYTES;

/// The only disclosure supported by the current monolithic transfer circuit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DelegatedProvingDisclosure {
    /// Complete transaction witness plus the account full-viewing capability.
    CompleteTransferWitnessWithFullViewingKeyV1 = 1,
}

impl DelegatedProvingDisclosure {
    fn from_byte(value: u8) -> Result<Self, DelegatedProvingError> {
        match value {
            1 => Ok(Self::CompleteTransferWitnessWithFullViewingKeyV1),
            _ => Err(DelegatedProvingError::InvalidPolicy),
        }
    }

    /// Whether disclosure includes complete private transaction relationships.
    #[must_use]
    pub const fn reveals_complete_transaction_witness(self) -> bool {
        true
    }

    /// Whether disclosure includes the durable account full-viewing capability.
    #[must_use]
    pub const fn reveals_full_viewing_capability(self) -> bool {
        true
    }

    /// Whether this profile ever intentionally discloses spending authority.
    #[must_use]
    pub const fn reveals_spending_authority(self) -> bool {
        false
    }

    /// Whether revocation can erase knowledge already received by the prover.
    #[must_use]
    pub const fn remotely_erasable(self) -> bool {
        false
    }
}

/// Stable identity derived from a dedicated authenticated prover transport key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DelegatedProverId([u8; 32]);

impl DelegatedProverId {
    /// Exact identity digest bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for DelegatedProverId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DelegatedProverId(REDACTED)")
    }
}

/// Human-comparable fingerprint for one exact prover policy identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DelegatedProverFingerprint([u8; 16]);

impl DelegatedProverFingerprint {
    /// Exact 128-bit display bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for DelegatedProverFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DelegatedProverFingerprint(REDACTED)")
    }
}

/// Digest of one immutable delegated-proving policy.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DelegatedProvingPolicyId([u8; 32]);

impl DelegatedProvingPolicyId {
    /// Restores exact policy-ID bytes for trusted-display comparison.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exact policy digest bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for DelegatedProvingPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DelegatedProvingPolicyId(REDACTED)")
    }
}

/// Immutable exact-suite policy for one dedicated prover endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct DelegatedProvingPolicy {
    disclosure: DelegatedProvingDisclosure,
    action_count: u8,
    network_id: [u8; 32],
    circuit_id: [u8; 32],
    proof_suite_id: [u8; 32],
    prover_transport_key: [u8; 32],
    maximum_witness_bytes: u32,
    expected_proof_bytes: u32,
}

impl fmt::Debug for DelegatedProvingPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegatedProvingPolicy")
            .field("disclosure", &self.disclosure)
            .field("action_count", &self.action_count)
            .field("maximum_witness_bytes", &self.maximum_witness_bytes)
            .field("expected_proof_bytes", &self.expected_proof_bytes)
            .field("domains_and_identity", &"REDACTED")
            .finish()
    }
}

impl DelegatedProvingPolicy {
    /// Creates one exact network/circuit/suite/endpoint policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: [u8; 32],
        circuit_id: [u8; 32],
        proof_suite_id: [u8; 32],
        action_count: usize,
        prover_transport_key: [u8; 32],
        maximum_witness_bytes: usize,
        expected_proof_bytes: usize,
    ) -> Result<Self, DelegatedProvingError> {
        if network_id == [0; 32]
            || circuit_id == [0; 32]
            || proof_suite_id == [0; 32]
            || prover_transport_key == [0; 32]
            || !ALLOWED_TRANSFER_V2_ACTION_COUNTS.contains(&action_count)
            || maximum_witness_bytes == 0
            || maximum_witness_bytes > DELEGATED_PROVING_WITNESS_MAX_BYTES
            || expected_proof_bytes == 0
            || expected_proof_bytes > MAX_PROOF_BYTES
        {
            return Err(DelegatedProvingError::InvalidPolicy);
        }
        Ok(Self {
            disclosure: DelegatedProvingDisclosure::CompleteTransferWitnessWithFullViewingKeyV1,
            action_count: u8::try_from(action_count)
                .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
            network_id,
            circuit_id,
            proof_suite_id,
            prover_transport_key,
            maximum_witness_bytes: u32::try_from(maximum_witness_bytes)
                .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
            expected_proof_bytes: u32::try_from(expected_proof_bytes)
                .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
        })
    }

    /// Parses and revalidates the fixed canonical policy.
    pub fn decode(bytes: &[u8]) -> Result<Self, DelegatedProvingError> {
        if bytes.len() != DELEGATED_PROVING_POLICY_BYTES
            || bytes[..4] != POLICY_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
            ) != POLICY_VERSION
            || bytes[144..148] != [0; 4]
        {
            return Err(DelegatedProvingError::InvalidPolicy);
        }
        let disclosure = DelegatedProvingDisclosure::from_byte(bytes[6])?;
        if disclosure != DelegatedProvingDisclosure::CompleteTransferWitnessWithFullViewingKeyV1 {
            return Err(DelegatedProvingError::InvalidPolicy);
        }
        let policy = Self::new(
            bytes[8..40]
                .try_into()
                .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
            bytes[40..72]
                .try_into()
                .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
            bytes[72..104]
                .try_into()
                .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
            usize::from(bytes[7]),
            bytes[104..136]
                .try_into()
                .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
            usize::try_from(u32::from_le_bytes(
                bytes[136..140]
                    .try_into()
                    .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
            ))
            .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
            usize::try_from(u32::from_le_bytes(
                bytes[140..144]
                    .try_into()
                    .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
            ))
            .map_err(|_| DelegatedProvingError::InvalidPolicy)?,
        )?;
        if !bool::from(policy.encode().as_slice().ct_eq(bytes)) {
            return Err(DelegatedProvingError::InvalidPolicy);
        }
        Ok(policy)
    }

    /// Fixed 148-byte canonical policy encoding.
    #[must_use]
    pub fn encode(&self) -> [u8; DELEGATED_PROVING_POLICY_BYTES] {
        let mut bytes = [0; DELEGATED_PROVING_POLICY_BYTES];
        bytes[..4].copy_from_slice(&POLICY_MAGIC);
        bytes[4..6].copy_from_slice(&POLICY_VERSION.to_le_bytes());
        bytes[6] = self.disclosure as u8;
        bytes[7] = self.action_count;
        bytes[8..40].copy_from_slice(&self.network_id);
        bytes[40..72].copy_from_slice(&self.circuit_id);
        bytes[72..104].copy_from_slice(&self.proof_suite_id);
        bytes[104..136].copy_from_slice(&self.prover_transport_key);
        bytes[136..140].copy_from_slice(&self.maximum_witness_bytes.to_le_bytes());
        bytes[140..144].copy_from_slice(&self.expected_proof_bytes.to_le_bytes());
        bytes
    }

    /// Domain-separated identity of the complete immutable policy.
    #[must_use]
    pub fn policy_id(&self) -> DelegatedProvingPolicyId {
        let mut hasher = Hasher::new_derive_key(POLICY_ID_DOMAIN);
        hasher.update(&self.encode());
        DelegatedProvingPolicyId(*hasher.finalize().as_bytes())
    }

    /// Identity derived from the dedicated prover transport key.
    #[must_use]
    pub fn prover_id(&self) -> DelegatedProverId {
        let mut hasher = Hasher::new_derive_key(PROVER_ID_DOMAIN);
        hasher.update(&self.prover_transport_key);
        DelegatedProverId(*hasher.finalize().as_bytes())
    }

    /// Fingerprint shown during per-job approval and permanent revocation.
    #[must_use]
    pub fn prover_fingerprint(&self) -> DelegatedProverFingerprint {
        let mut hasher = Hasher::new_derive_key(PROVER_FINGERPRINT_DOMAIN);
        hasher.update(&self.encode());
        let mut fingerprint = [0; 16];
        fingerprint.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        DelegatedProverFingerprint(fingerprint)
    }

    /// Fixed disclosure profile and its irreversible privacy consequence.
    #[must_use]
    pub const fn disclosure(&self) -> DelegatedProvingDisclosure {
        self.disclosure
    }

    /// Exact padded Action bucket.
    #[must_use]
    pub const fn action_count(&self) -> usize {
        self.action_count as usize
    }

    /// Exact network domain.
    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Exact transfer circuit ID.
    #[must_use]
    pub const fn circuit_id(&self) -> [u8; 32] {
        self.circuit_id
    }

    /// Exact selected Halo2 suite/VK identity.
    #[must_use]
    pub const fn proof_suite_id(&self) -> [u8; 32] {
        self.proof_suite_id
    }

    /// Dedicated authenticated transport public key.
    #[must_use]
    pub const fn prover_transport_key(&self) -> [u8; 32] {
        self.prover_transport_key
    }

    /// Maximum canonical VDPW witness-package bytes.
    #[must_use]
    pub const fn maximum_witness_bytes(&self) -> usize {
        self.maximum_witness_bytes as usize
    }

    /// Exact canonical proof length for this suite.
    #[must_use]
    pub const fn expected_proof_bytes(&self) -> usize {
        self.expected_proof_bytes as usize
    }

    fn matches_effects(&self, effects: &TransferV2Effects) -> bool {
        effects.chain_id().as_bytes() == &self.network_id
            && effects.circuit_id().as_bytes() == &self.circuit_id
            && effects.actions().len() == usize::from(self.action_count)
    }
}

/// Commitment to the complete canonical VDPW witness-package encoding.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DelegatedWitnessCommitment([u8; 32]);

impl DelegatedWitnessCommitment {
    /// Exact commitment bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    fn from_bytes(bytes: [u8; 32]) -> Result<Self, DelegatedProvingError> {
        if bytes == [0; 32] {
            return Err(DelegatedProvingError::InvalidWitnessPackage);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for DelegatedWitnessCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DelegatedWitnessCommitment(REDACTED)")
    }
}

/// Bounded zeroizing container for the A3-6 canonical witness package.
pub struct DelegatedWitnessPackage {
    bytes: Zeroizing<Vec<u8>>,
    commitment: DelegatedWitnessCommitment,
}

impl fmt::Debug for DelegatedWitnessPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegatedWitnessPackage")
            .field("bytes", &self.bytes.len())
            .field("private_witness", &"REDACTED")
            .finish()
    }
}

impl DelegatedWitnessPackage {
    /// Wraps canonical witness bytes for authorization and request binding.
    pub fn new(bytes: Vec<u8>) -> Result<Self, DelegatedProvingError> {
        if bytes.is_empty() || bytes.len() > DELEGATED_PROVING_WITNESS_MAX_BYTES {
            return Err(DelegatedProvingError::InvalidWitnessPackage);
        }
        let mut hasher = Hasher::new_derive_key(WITNESS_COMMITMENT_DOMAIN);
        hasher.update(&bytes);
        let commitment = DelegatedWitnessCommitment::from_bytes(*hasher.finalize().as_bytes())?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            commitment,
        })
    }

    /// Exact package byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the package is empty. Valid packages are never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Commitment bound into the one-job authorization.
    #[must_use]
    pub const fn commitment(&self) -> DelegatedWitnessCommitment {
        self.commitment
    }

    /// Consumes the redacted wrapper for a reviewed confidential transport.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

/// Fresh non-zero identifier for one disclosure/proving attempt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DelegatedProvingJobId([u8; 32]);

impl DelegatedProvingJobId {
    /// Generates a fresh job ID from a CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, DelegatedProvingError> {
        for _ in 0..=u16::MAX {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            if bytes != [0; 32] {
                return Ok(Self(bytes));
            }
        }
        Err(DelegatedProvingError::EntropyUnavailable)
    }

    /// Restores a previously persisted non-zero job ID.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, DelegatedProvingError> {
        if bytes == [0; 32] {
            return Err(DelegatedProvingError::InvalidAuthorization);
        }
        Ok(Self(bytes))
    }

    /// Exact job ID bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for DelegatedProvingJobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DelegatedProvingJobId(REDACTED)")
    }
}

/// Fresh authenticated-channel binding dedicated to one proving job.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DelegatedProverChannelBinding([u8; 32]);

impl DelegatedProverChannelBinding {
    /// Accepts a non-zero binding from the authenticated confidential channel.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, DelegatedProvingError> {
        if bytes == [0; 32] {
            return Err(DelegatedProvingError::InvalidAuthorization);
        }
        Ok(Self(bytes))
    }

    /// Exact channel-binding bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for DelegatedProverChannelBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DelegatedProverChannelBinding(REDACTED)")
    }
}

/// Digest of one complete per-job authorization.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DelegatedProvingAuthorizationId([u8; 32]);

impl DelegatedProvingAuthorizationId {
    /// Restores independently observed authorization bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exact authorization digest bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for DelegatedProvingAuthorizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DelegatedProvingAuthorizationId(REDACTED)")
    }
}

/// Complete one-job authorization reconstructed before witness disclosure.
#[derive(Clone, Eq, PartialEq)]
pub struct DelegatedProvingAuthorization {
    action_count: u8,
    disclosure: DelegatedProvingDisclosure,
    authorization_counter: u64,
    policy_id: DelegatedProvingPolicyId,
    job_id: DelegatedProvingJobId,
    channel_binding: DelegatedProverChannelBinding,
    effects_digest: PublicInputDigest,
    witness_commitment: DelegatedWitnessCommitment,
    witness_bytes: u32,
    proof_bytes: u32,
}

impl fmt::Debug for DelegatedProvingAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegatedProvingAuthorization")
            .field("action_count", &self.action_count)
            .field("authorization_counter", &self.authorization_counter)
            .field("witness_bytes", &self.witness_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field("private_job_facts", &"REDACTED")
            .finish()
    }
}

impl DelegatedProvingAuthorization {
    /// Binds one exact package and transfer to a fresh authenticated channel.
    pub fn new(
        policy: &DelegatedProvingPolicy,
        job_id: DelegatedProvingJobId,
        authorization_counter: u64,
        channel_binding: DelegatedProverChannelBinding,
        effects: &TransferV2Effects,
        witness: &DelegatedWitnessPackage,
    ) -> Result<Self, DelegatedProvingError> {
        Self::from_parts(
            policy,
            job_id,
            authorization_counter,
            channel_binding,
            effects,
            policy.disclosure,
            witness.commitment,
            witness.len(),
            policy.expected_proof_bytes(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        policy: &DelegatedProvingPolicy,
        job_id: DelegatedProvingJobId,
        authorization_counter: u64,
        channel_binding: DelegatedProverChannelBinding,
        effects: &TransferV2Effects,
        disclosure: DelegatedProvingDisclosure,
        witness_commitment: DelegatedWitnessCommitment,
        witness_bytes: usize,
        proof_bytes: usize,
    ) -> Result<Self, DelegatedProvingError> {
        if authorization_counter == 0
            || !policy.matches_effects(effects)
            || disclosure != policy.disclosure
            || witness_bytes == 0
            || witness_bytes > policy.maximum_witness_bytes()
            || proof_bytes != policy.expected_proof_bytes()
        {
            return Err(DelegatedProvingError::InvalidAuthorization);
        }
        Ok(Self {
            action_count: policy.action_count,
            disclosure,
            authorization_counter,
            policy_id: policy.policy_id(),
            job_id,
            channel_binding,
            effects_digest: effects.public_inputs_digest(),
            witness_commitment,
            witness_bytes: u32::try_from(witness_bytes)
                .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
            proof_bytes: u32::try_from(proof_bytes)
                .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
        })
    }

    /// Parses and reconstructs an authorization against exact local effects.
    pub fn decode(
        bytes: &[u8],
        policy: &DelegatedProvingPolicy,
        effects: &TransferV2Effects,
    ) -> Result<Self, DelegatedProvingError> {
        if bytes.len() != DELEGATED_PROVING_AUTHORIZATION_BYTES
            || bytes[..4] != AUTHORIZATION_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
            ) != AUTHORIZATION_VERSION
            || bytes[16..48] != policy.policy_id().0
        {
            return Err(DelegatedProvingError::InvalidAuthorization);
        }
        let authorization = Self::from_parts(
            policy,
            DelegatedProvingJobId::from_bytes(
                bytes[48..80]
                    .try_into()
                    .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
            )?,
            u64::from_le_bytes(
                bytes[8..16]
                    .try_into()
                    .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
            ),
            DelegatedProverChannelBinding::from_bytes(
                bytes[80..112]
                    .try_into()
                    .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
            )?,
            effects,
            DelegatedProvingDisclosure::from_byte(bytes[7])
                .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
            DelegatedWitnessCommitment::from_bytes(
                bytes[144..176]
                    .try_into()
                    .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
            )?,
            usize::try_from(u32::from_le_bytes(
                bytes[176..180]
                    .try_into()
                    .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
            ))
            .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
            usize::try_from(u32::from_le_bytes(
                bytes[180..184]
                    .try_into()
                    .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
            ))
            .map_err(|_| DelegatedProvingError::InvalidAuthorization)?,
        )?;
        if bytes[6] != authorization.action_count
            || bytes[112..144] != authorization.effects_digest.as_bytes()[..]
            || !bool::from(authorization.encode().as_slice().ct_eq(bytes))
        {
            return Err(DelegatedProvingError::InvalidAuthorization);
        }
        Ok(authorization)
    }

    /// Fixed 184-byte canonical one-job authorization.
    #[must_use]
    pub fn encode(&self) -> [u8; DELEGATED_PROVING_AUTHORIZATION_BYTES] {
        let mut bytes = [0; DELEGATED_PROVING_AUTHORIZATION_BYTES];
        bytes[..4].copy_from_slice(&AUTHORIZATION_MAGIC);
        bytes[4..6].copy_from_slice(&AUTHORIZATION_VERSION.to_le_bytes());
        bytes[6] = self.action_count;
        bytes[7] = self.disclosure as u8;
        bytes[8..16].copy_from_slice(&self.authorization_counter.to_le_bytes());
        bytes[16..48].copy_from_slice(&self.policy_id.0);
        bytes[48..80].copy_from_slice(&self.job_id.0);
        bytes[80..112].copy_from_slice(&self.channel_binding.0);
        bytes[112..144].copy_from_slice(self.effects_digest.as_bytes());
        bytes[144..176].copy_from_slice(&self.witness_commitment.0);
        bytes[176..180].copy_from_slice(&self.witness_bytes.to_le_bytes());
        bytes[180..184].copy_from_slice(&self.proof_bytes.to_le_bytes());
        bytes
    }

    /// Identity of all policy, channel, effects and disclosure facts.
    #[must_use]
    pub fn authorization_id(&self) -> DelegatedProvingAuthorizationId {
        let mut hasher = Hasher::new_derive_key(AUTHORIZATION_ID_DOMAIN);
        hasher.update(&self.encode());
        DelegatedProvingAuthorizationId(*hasher.finalize().as_bytes())
    }

    /// Requests explicit trusted approval of the irreversible disclosure.
    pub fn confirm<C: TrustedDelegatedProvingAuthorization>(
        &self,
        policy: &DelegatedProvingPolicy,
        confirmation: &mut C,
    ) -> Result<ConfirmedDelegatedProvingAuthorization, DelegatedProvingError> {
        if self.policy_id != policy.policy_id() {
            return Err(DelegatedProvingError::InvalidAuthorization);
        }
        let facts = DelegatedProvingAuthorizationFacts {
            authorization_id: self.authorization_id(),
            policy_id: self.policy_id,
            prover_id: policy.prover_id(),
            prover_fingerprint: policy.prover_fingerprint(),
            disclosure: self.disclosure,
            network_id: policy.network_id,
            circuit_id: policy.circuit_id,
            proof_suite_id: policy.proof_suite_id,
            action_count: self.action_count,
            authorization_counter: self.authorization_counter,
            job_id: self.job_id,
            channel_binding: self.channel_binding,
            effects_digest: self.effects_digest,
            witness_commitment: self.witness_commitment,
            witness_bytes: self.witness_bytes,
            proof_bytes: self.proof_bytes,
        };
        let observed = confirmation
            .confirm_delegated_proving(&facts)
            .map_err(|_| DelegatedProvingError::ConfirmationFailed)?;
        if !bool::from(
            observed
                .to_bytes()
                .ct_eq(&facts.authorization_id.to_bytes()),
        ) {
            return Err(DelegatedProvingError::ConfirmationFailed);
        }
        Ok(ConfirmedDelegatedProvingAuthorization {
            authorization_id: facts.authorization_id,
            policy_id: facts.policy_id,
            job_id: facts.job_id,
            authorization_counter: facts.authorization_counter,
        })
    }

    /// Verifies a returned proof locally against exact typed effects.
    pub fn verify_result<V: DelegatedTransferProofVerifier>(
        &self,
        policy: &DelegatedProvingPolicy,
        effects: &TransferV2Effects,
        proof: Vec<u8>,
        verifier: &mut V,
    ) -> Result<VerifiedDelegatedTransferProof, DelegatedProvingError> {
        if self.policy_id != policy.policy_id()
            || !policy.matches_effects(effects)
            || self.action_count() != effects.actions().len()
            || self.effects_digest != effects.public_inputs_digest()
            || proof.len() != self.proof_bytes()
            || proof.len() != policy.expected_proof_bytes()
        {
            return Err(DelegatedProvingError::ProofRejected);
        }
        verifier
            .verify_delegated_transfer(policy.proof_suite_id, effects, &proof)
            .map_err(|_| DelegatedProvingError::ProofRejected)?;
        Ok(VerifiedDelegatedTransferProof {
            authorization_id: self.authorization_id(),
            effects_digest: self.effects_digest,
            proof,
        })
    }

    /// Whether exact package bytes match the authorized disclosure.
    #[must_use]
    pub fn matches_witness_package(&self, package: &DelegatedWitnessPackage) -> bool {
        package.len() == self.witness_bytes()
            && bool::from(
                package
                    .commitment()
                    .to_bytes()
                    .ct_eq(&self.witness_commitment.to_bytes()),
            )
    }

    /// Immutable policy identity.
    #[must_use]
    pub const fn policy_id(&self) -> DelegatedProvingPolicyId {
        self.policy_id
    }

    /// Fresh job identity.
    #[must_use]
    pub const fn job_id(&self) -> DelegatedProvingJobId {
        self.job_id
    }

    /// Durable monotonic job counter.
    #[must_use]
    pub const fn authorization_counter(&self) -> u64 {
        self.authorization_counter
    }

    /// Authenticated one-job channel binding.
    #[must_use]
    pub const fn channel_binding(&self) -> DelegatedProverChannelBinding {
        self.channel_binding
    }

    /// Exact canonical public-effects digest.
    #[must_use]
    pub const fn effects_digest(&self) -> PublicInputDigest {
        self.effects_digest
    }

    /// Exact witness-package commitment.
    #[must_use]
    pub const fn witness_commitment(&self) -> DelegatedWitnessCommitment {
        self.witness_commitment
    }

    /// Exact witness-package byte length.
    #[must_use]
    pub const fn witness_bytes(&self) -> usize {
        self.witness_bytes as usize
    }

    /// Exact expected proof byte length.
    #[must_use]
    pub const fn proof_bytes(&self) -> usize {
        self.proof_bytes as usize
    }

    /// Exact padded Action bucket.
    #[must_use]
    pub const fn action_count(&self) -> usize {
        self.action_count as usize
    }

    /// Exact irreversible disclosure profile.
    #[must_use]
    pub const fn disclosure(&self) -> DelegatedProvingDisclosure {
        self.disclosure
    }
}

/// Facts independently displayed before a private witness may leave the wallet.
#[derive(Clone, Eq, PartialEq)]
pub struct DelegatedProvingAuthorizationFacts {
    authorization_id: DelegatedProvingAuthorizationId,
    policy_id: DelegatedProvingPolicyId,
    prover_id: DelegatedProverId,
    prover_fingerprint: DelegatedProverFingerprint,
    disclosure: DelegatedProvingDisclosure,
    network_id: [u8; 32],
    circuit_id: [u8; 32],
    proof_suite_id: [u8; 32],
    action_count: u8,
    authorization_counter: u64,
    job_id: DelegatedProvingJobId,
    channel_binding: DelegatedProverChannelBinding,
    effects_digest: PublicInputDigest,
    witness_commitment: DelegatedWitnessCommitment,
    witness_bytes: u32,
    proof_bytes: u32,
}

impl fmt::Debug for DelegatedProvingAuthorizationFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegatedProvingAuthorizationFacts")
            .field("disclosure", &self.disclosure)
            .field("action_count", &self.action_count)
            .field("authorization_counter", &self.authorization_counter)
            .field("witness_bytes", &self.witness_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field("private_job_facts", &"REDACTED")
            .finish()
    }
}

impl DelegatedProvingAuthorizationFacts {
    /// Complete authorization identity.
    #[must_use]
    pub const fn authorization_id(&self) -> DelegatedProvingAuthorizationId {
        self.authorization_id
    }

    /// Immutable policy identity.
    #[must_use]
    pub const fn policy_id(&self) -> DelegatedProvingPolicyId {
        self.policy_id
    }

    /// Dedicated authenticated prover identity.
    #[must_use]
    pub const fn prover_id(&self) -> DelegatedProverId {
        self.prover_id
    }

    /// Human-comparable exact endpoint fingerprint.
    #[must_use]
    pub const fn prover_fingerprint(&self) -> DelegatedProverFingerprint {
        self.prover_fingerprint
    }

    /// Irreversible witness-disclosure class.
    #[must_use]
    pub const fn disclosure(&self) -> DelegatedProvingDisclosure {
        self.disclosure
    }

    /// Network, circuit and suite domains.
    #[must_use]
    pub const fn proof_domains(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (self.network_id, self.circuit_id, self.proof_suite_id)
    }

    /// Exact padded action count.
    #[must_use]
    pub const fn action_count(&self) -> usize {
        self.action_count as usize
    }

    /// Durable counter and fresh job ID.
    #[must_use]
    pub const fn job(&self) -> (u64, DelegatedProvingJobId) {
        (self.authorization_counter, self.job_id)
    }

    /// Authenticated one-job channel binding.
    #[must_use]
    pub const fn channel_binding(&self) -> DelegatedProverChannelBinding {
        self.channel_binding
    }

    /// Exact effects and witness commitments.
    #[must_use]
    pub const fn commitments(&self) -> (PublicInputDigest, DelegatedWitnessCommitment) {
        (self.effects_digest, self.witness_commitment)
    }

    /// Exact witness and proof byte lengths.
    #[must_use]
    pub const fn byte_lengths(&self) -> (usize, usize) {
        (self.witness_bytes as usize, self.proof_bytes as usize)
    }
}

/// Trusted per-job disclosure approval; the crate provides no default.
pub trait TrustedDelegatedProvingAuthorization {
    /// Displays/verifies every fact and returns the independently approved ID.
    fn confirm_delegated_proving(
        &mut self,
        facts: &DelegatedProvingAuthorizationFacts,
    ) -> Result<DelegatedProvingAuthorizationId, SignerConfirmationError>;
}

/// Non-serializable approval token for one exact job disclosure.
pub struct ConfirmedDelegatedProvingAuthorization {
    authorization_id: DelegatedProvingAuthorizationId,
    policy_id: DelegatedProvingPolicyId,
    job_id: DelegatedProvingJobId,
    authorization_counter: u64,
}

impl fmt::Debug for ConfirmedDelegatedProvingAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmedDelegatedProvingAuthorization(REDACTED)")
    }
}

impl ConfirmedDelegatedProvingAuthorization {
    /// Whether this token approves the exact supplied policy/job authorization.
    #[must_use]
    pub fn matches(
        &self,
        policy: &DelegatedProvingPolicy,
        authorization: &DelegatedProvingAuthorization,
    ) -> bool {
        self.policy_id == policy.policy_id()
            && self.job_id == authorization.job_id
            && self.authorization_counter == authorization.authorization_counter
            && bool::from(
                self.authorization_id
                    .to_bytes()
                    .ct_eq(&authorization.authorization_id().to_bytes()),
            )
    }
}

/// Local selected-suite verifier used before a remote result can leave A3.
pub trait DelegatedTransferProofVerifier {
    /// Concrete selected-verifier failure.
    type Error: std::error::Error;

    /// Verifies exact proof bytes against independently reconstructed effects.
    fn verify_delegated_transfer(
        &mut self,
        proof_suite_id: [u8; 32],
        effects: &TransferV2Effects,
        proof: &[u8],
    ) -> Result<(), Self::Error>;
}

/// Non-cloneable result of exact local verification of a delegated proof.
pub struct VerifiedDelegatedTransferProof {
    authorization_id: DelegatedProvingAuthorizationId,
    effects_digest: PublicInputDigest,
    proof: Vec<u8>,
}

impl fmt::Debug for VerifiedDelegatedTransferProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDelegatedTransferProof")
            .field("proof_bytes", &self.proof.len())
            .field("binding", &"REDACTED")
            .finish()
    }
}

impl VerifiedDelegatedTransferProof {
    /// Job authorization whose exact effects and proof were verified.
    #[must_use]
    pub const fn authorization_id(&self) -> DelegatedProvingAuthorizationId {
        self.authorization_id
    }

    /// Exact effects digest used by the local verifier.
    #[must_use]
    pub const fn effects_digest(&self) -> PublicInputDigest {
        self.effects_digest
    }

    /// Consumes the verified wrapper after durable job closure.
    #[must_use]
    pub fn into_proof(self) -> Vec<u8> {
        self.proof
    }
}

/// Self-contained, bounded request for one already-authorized proving job.
///
/// This envelope is not a transport and provides no confidentiality by itself.
/// Its bytes may leave the wallet only through the separately authorized job
/// lifecycle and a reviewed authenticated confidential channel.
pub struct DelegatedProvingRequest {
    policy: DelegatedProvingPolicy,
    authorization: DelegatedProvingAuthorization,
    effects: TransferV2Effects,
    witness: DelegatedWitnessPackage,
}

impl fmt::Debug for DelegatedProvingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegatedProvingRequest")
            .field("action_count", &self.policy.action_count())
            .field("encoded_bytes", &self.encoded_len())
            .field("private_request", &"REDACTED")
            .finish()
    }
}

impl DelegatedProvingRequest {
    /// Binds exact policy, authorization, effects and canonical VDPW bytes.
    pub fn new(
        policy: DelegatedProvingPolicy,
        authorization: DelegatedProvingAuthorization,
        effects: TransferV2Effects,
        witness: DelegatedWitnessPackage,
    ) -> Result<Self, DelegatedProvingError> {
        if authorization.policy_id() != policy.policy_id()
            || authorization.action_count() != policy.action_count()
            || authorization.disclosure() != policy.disclosure()
            || authorization.effects_digest() != effects.public_inputs_digest()
            || !policy.matches_effects(&effects)
            || !authorization.matches_witness_package(&witness)
            || !delegated_witness_binding_matches(&witness.bytes, &policy, &effects)
        {
            return Err(DelegatedProvingError::InvalidRequest);
        }
        Ok(Self {
            policy,
            authorization,
            effects,
            witness,
        })
    }

    /// Strictly parses a self-contained request before any unbounded allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, DelegatedProvingError> {
        if bytes.len() > DELEGATED_PROVING_REQUEST_MAX_BYTES {
            return Err(DelegatedProvingError::InvalidRequest);
        }
        let mut reader = DelegatedReader::new(bytes, DelegatedProvingError::InvalidRequest);
        if reader.take::<4>()? != REQUEST_MAGIC
            || u16::from_le_bytes(reader.take()?) != REQUEST_VERSION
        {
            return Err(DelegatedProvingError::InvalidRequest);
        }
        let action_count = reader.take::<1>()?[0];
        let disclosure = reader.take::<1>()?[0];
        let effects_bytes = usize::try_from(u32::from_le_bytes(reader.take()?))
            .map_err(|_| DelegatedProvingError::InvalidRequest)?;
        let witness_bytes = usize::try_from(u32::from_le_bytes(reader.take()?))
            .map_err(|_| DelegatedProvingError::InvalidRequest)?;
        if effects_bytes == 0
            || effects_bytes > TRANSFER_V2_MAX_EFFECT_BYTES
            || witness_bytes == 0
            || witness_bytes > DELEGATED_PROVING_WITNESS_MAX_BYTES
        {
            return Err(DelegatedProvingError::InvalidRequest);
        }
        let policy =
            DelegatedProvingPolicy::decode(reader.take_slice(DELEGATED_PROVING_POLICY_BYTES)?)
                .map_err(|_| DelegatedProvingError::InvalidRequest)?;
        let authorization_bytes = reader
            .take_slice(DELEGATED_PROVING_AUTHORIZATION_BYTES)?
            .to_vec();
        let effects = TransferV2Effects::decode_canonical(reader.take_slice(effects_bytes)?)
            .map_err(|_| DelegatedProvingError::InvalidRequest)?;
        let witness = DelegatedWitnessPackage::new(reader.take_slice(witness_bytes)?.to_vec())
            .map_err(|_| DelegatedProvingError::InvalidRequest)?;
        if !reader.is_empty() {
            return Err(DelegatedProvingError::InvalidRequest);
        }
        let authorization =
            DelegatedProvingAuthorization::decode(&authorization_bytes, &policy, &effects)
                .map_err(|_| DelegatedProvingError::InvalidRequest)?;
        let request = Self::new(policy, authorization, effects, witness)?;
        if action_count != u8::try_from(request.policy.action_count()).unwrap_or(0)
            || disclosure != request.policy.disclosure() as u8
            || !bool::from(request.encode().as_slice().ct_eq(bytes))
        {
            return Err(DelegatedProvingError::InvalidRequest);
        }
        Ok(request)
    }

    /// Canonical request bytes. The allocation is zeroized when dropped.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let effects = self.effects.encode_canonical();
        let mut bytes = Zeroizing::new(Vec::with_capacity(self.encoded_len()));
        bytes.extend_from_slice(&REQUEST_MAGIC);
        bytes.extend_from_slice(&REQUEST_VERSION.to_le_bytes());
        bytes.push(u8::try_from(self.policy.action_count()).expect("valid Action bucket fits u8"));
        bytes.push(self.policy.disclosure() as u8);
        bytes.extend_from_slice(
            &u32::try_from(effects.len())
                .expect("bounded effects length fits u32")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.witness.len())
                .expect("bounded witness length fits u32")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.policy.encode());
        bytes.extend_from_slice(&self.authorization.encode());
        bytes.extend_from_slice(&effects);
        bytes.extend_from_slice(&self.witness.bytes);
        debug_assert_eq!(bytes.len(), self.encoded_len());
        bytes
    }

    /// Exact request byte length before transport encryption.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        REQUEST_HEADER_BYTES
            + DELEGATED_PROVING_POLICY_BYTES
            + DELEGATED_PROVING_AUTHORIZATION_BYTES
            + self.effects.encode_canonical().len()
            + self.witness.len()
    }

    /// Immutable policy reconstructed from the envelope.
    #[must_use]
    pub const fn policy(&self) -> &DelegatedProvingPolicy {
        &self.policy
    }

    /// One-job authorization reconstructed from the envelope.
    #[must_use]
    pub const fn authorization(&self) -> &DelegatedProvingAuthorization {
        &self.authorization
    }

    /// Independently typed public effects reconstructed from the envelope.
    #[must_use]
    pub const fn effects(&self) -> &TransferV2Effects {
        &self.effects
    }

    /// Consumes the request into typed context and zeroizing witness bytes.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        DelegatedProvingPolicy,
        DelegatedProvingAuthorization,
        TransferV2Effects,
        Zeroizing<Vec<u8>>,
    ) {
        (
            self.policy,
            self.authorization,
            self.effects,
            self.witness.into_bytes(),
        )
    }
}

/// Bounded proof response bound to one exact delegated-proving job.
pub struct DelegatedProvingResponse {
    action_count: u8,
    disclosure: DelegatedProvingDisclosure,
    authorization_id: DelegatedProvingAuthorizationId,
    policy_id: DelegatedProvingPolicyId,
    job_id: DelegatedProvingJobId,
    effects_digest: PublicInputDigest,
    proof: Vec<u8>,
}

impl fmt::Debug for DelegatedProvingResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegatedProvingResponse")
            .field("action_count", &self.action_count)
            .field("proof_bytes", &self.proof.len())
            .field("job_binding", &"REDACTED")
            .finish()
    }
}

impl DelegatedProvingResponse {
    /// Binds untrusted returned proof bytes to exact local job context.
    pub fn new(
        policy: &DelegatedProvingPolicy,
        authorization: &DelegatedProvingAuthorization,
        effects: &TransferV2Effects,
        proof: Vec<u8>,
    ) -> Result<Self, DelegatedProvingError> {
        if authorization.policy_id() != policy.policy_id()
            || authorization.action_count() != policy.action_count()
            || authorization.disclosure() != policy.disclosure()
            || authorization.effects_digest() != effects.public_inputs_digest()
            || !policy.matches_effects(effects)
            || proof.len() != authorization.proof_bytes()
            || proof.len() != policy.expected_proof_bytes()
        {
            return Err(DelegatedProvingError::InvalidResponse);
        }
        Ok(Self {
            action_count: u8::try_from(policy.action_count())
                .map_err(|_| DelegatedProvingError::InvalidResponse)?,
            disclosure: policy.disclosure(),
            authorization_id: authorization.authorization_id(),
            policy_id: policy.policy_id(),
            job_id: authorization.job_id(),
            effects_digest: effects.public_inputs_digest(),
            proof,
        })
    }

    /// Parses only in the exact locally expected policy/job/effects context.
    pub fn decode(
        bytes: &[u8],
        policy: &DelegatedProvingPolicy,
        authorization: &DelegatedProvingAuthorization,
        effects: &TransferV2Effects,
    ) -> Result<Self, DelegatedProvingError> {
        if bytes.len() > DELEGATED_PROVING_RESPONSE_MAX_BYTES {
            return Err(DelegatedProvingError::InvalidResponse);
        }
        let mut reader = DelegatedReader::new(bytes, DelegatedProvingError::InvalidResponse);
        if reader.take::<4>()? != RESPONSE_MAGIC
            || u16::from_le_bytes(reader.take()?) != RESPONSE_VERSION
            || reader.take::<1>()?[0] != u8::try_from(policy.action_count()).unwrap_or(0)
            || reader.take::<1>()?[0] != policy.disclosure() as u8
            || reader.take::<32>()? != authorization.authorization_id().to_bytes()
            || reader.take::<32>()? != policy.policy_id().to_bytes()
            || reader.take::<32>()? != authorization.job_id().to_bytes()
            || reader.take::<32>()? != effects.public_inputs_digest().into_bytes()
        {
            return Err(DelegatedProvingError::InvalidResponse);
        }
        let proof_bytes = usize::try_from(u32::from_le_bytes(reader.take()?))
            .map_err(|_| DelegatedProvingError::InvalidResponse)?;
        if proof_bytes != policy.expected_proof_bytes()
            || proof_bytes != authorization.proof_bytes()
            || proof_bytes > MAX_PROOF_BYTES
        {
            return Err(DelegatedProvingError::InvalidResponse);
        }
        let response = Self::new(
            policy,
            authorization,
            effects,
            reader.take_slice(proof_bytes)?.to_vec(),
        )?;
        if !reader.is_empty() || !bool::from(response.encode().as_slice().ct_eq(bytes)) {
            return Err(DelegatedProvingError::InvalidResponse);
        }
        Ok(response)
    }

    /// Canonical response bytes. Proof bytes remain untrusted until `verify`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RESPONSE_HEADER_BYTES + self.proof.len());
        bytes.extend_from_slice(&RESPONSE_MAGIC);
        bytes.extend_from_slice(&RESPONSE_VERSION.to_le_bytes());
        bytes.push(self.action_count);
        bytes.push(self.disclosure as u8);
        bytes.extend_from_slice(&self.authorization_id.to_bytes());
        bytes.extend_from_slice(&self.policy_id.to_bytes());
        bytes.extend_from_slice(&self.job_id.to_bytes());
        bytes.extend_from_slice(self.effects_digest.as_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.proof.len())
                .expect("bounded proof length fits u32")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.proof);
        bytes
    }

    /// Runs the mandatory selected-suite verifier against independent effects.
    pub fn verify<V: DelegatedTransferProofVerifier>(
        self,
        policy: &DelegatedProvingPolicy,
        authorization: &DelegatedProvingAuthorization,
        effects: &TransferV2Effects,
        verifier: &mut V,
    ) -> Result<VerifiedDelegatedTransferProof, DelegatedProvingError> {
        if self.authorization_id != authorization.authorization_id()
            || self.policy_id != policy.policy_id()
            || self.job_id != authorization.job_id()
            || self.effects_digest != effects.public_inputs_digest()
            || self.action_count as usize != policy.action_count()
            || self.disclosure != policy.disclosure()
        {
            return Err(DelegatedProvingError::ProofRejected);
        }
        authorization.verify_result(policy, effects, self.proof, verifier)
    }

    /// Exact untrusted proof length.
    #[must_use]
    pub fn proof_bytes(&self) -> usize {
        self.proof.len()
    }
}

fn delegated_witness_binding_matches(
    bytes: &[u8],
    policy: &DelegatedProvingPolicy,
    effects: &TransferV2Effects,
) -> bool {
    bytes.len() >= DELEGATED_WITNESS_BINDING_BYTES
        && bytes[..4] == DELEGATED_WITNESS_MAGIC
        && bytes[4..6] == DELEGATED_WITNESS_VERSION.to_le_bytes()
        && bytes[6] == policy.disclosure() as u8
        && usize::from(bytes[7]) == policy.action_count()
        && bytes[8..40] == policy.network_id()
        && bytes[40..72] == policy.circuit_id()
        && bytes[72..104] == effects.public_inputs_digest().as_bytes()[..]
}

struct DelegatedReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    error: DelegatedProvingError,
}

impl<'a> DelegatedReader<'a> {
    const fn new(bytes: &'a [u8], error: DelegatedProvingError) -> Self {
        Self {
            bytes,
            offset: 0,
            error,
        }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], DelegatedProvingError> {
        self.take_slice(N)?.try_into().map_err(|_| self.error)
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], DelegatedProvingError> {
        let end = self.offset.checked_add(length).ok_or(self.error)?;
        let value = self.bytes.get(self.offset..end).ok_or(self.error)?;
        self.offset = end;
        Ok(value)
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Digest of an exact permanent policy-revocation decision.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DelegatedProverRevocationId([u8; 32]);

impl DelegatedProverRevocationId {
    /// Restores independently approved revocation bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exact revocation digest bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for DelegatedProverRevocationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DelegatedProverRevocationId(REDACTED)")
    }
}

/// Facts shown before a prover policy is permanently tombstoned.
#[derive(Clone, Eq, PartialEq)]
pub struct DelegatedProverRevocationFacts {
    revocation_id: DelegatedProverRevocationId,
    policy_id: DelegatedProvingPolicyId,
    prover_id: DelegatedProverId,
    prover_fingerprint: DelegatedProverFingerprint,
    disclosure: DelegatedProvingDisclosure,
    state_generation: u64,
    active_authorization: Option<DelegatedProvingAuthorizationId>,
}

impl fmt::Debug for DelegatedProverRevocationFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegatedProverRevocationFacts")
            .field("state_generation", &self.state_generation)
            .field("has_active_job", &self.active_authorization.is_some())
            .field("identity", &"REDACTED")
            .finish()
    }
}

impl DelegatedProverRevocationFacts {
    /// Exact decision ID.
    #[must_use]
    pub const fn revocation_id(&self) -> DelegatedProverRevocationId {
        self.revocation_id
    }

    /// Policy and dedicated prover identities.
    #[must_use]
    pub const fn identities(&self) -> (DelegatedProvingPolicyId, DelegatedProverId) {
        (self.policy_id, self.prover_id)
    }

    /// Human-comparable endpoint fingerprint.
    #[must_use]
    pub const fn prover_fingerprint(&self) -> DelegatedProverFingerprint {
        self.prover_fingerprint
    }

    /// Disclosure whose remote knowledge cannot be erased by revocation.
    #[must_use]
    pub const fn disclosure(&self) -> DelegatedProvingDisclosure {
        self.disclosure
    }

    /// Rollback-protected state generation being revoked.
    #[must_use]
    pub const fn state_generation(&self) -> u64 {
        self.state_generation
    }

    /// Active job that must be closed and rejected, if any.
    #[must_use]
    pub const fn active_authorization(&self) -> Option<DelegatedProvingAuthorizationId> {
        self.active_authorization
    }
}

/// Trusted permanent-revocation approval; the crate provides no default.
pub trait TrustedDelegatedProverRevocation {
    /// Displays/verifies exact policy/job state and returns the approved ID.
    fn confirm_delegated_prover_revocation(
        &mut self,
        facts: &DelegatedProverRevocationFacts,
    ) -> Result<DelegatedProverRevocationId, SignerConfirmationError>;
}

/// Non-serializable token consumed by a durable policy lifecycle adapter.
pub struct ConfirmedDelegatedProverRevocation {
    revocation_id: DelegatedProverRevocationId,
    policy_id: DelegatedProvingPolicyId,
    state_generation: u64,
    active_authorization: Option<DelegatedProvingAuthorizationId>,
}

impl fmt::Debug for ConfirmedDelegatedProverRevocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmedDelegatedProverRevocation(REDACTED)")
    }
}

impl DelegatedProvingPolicy {
    /// Requests trusted approval before permanently revoking this policy.
    pub fn confirm_revocation<C: TrustedDelegatedProverRevocation>(
        &self,
        state_generation: u64,
        active: Option<&DelegatedProvingAuthorization>,
        confirmation: &mut C,
    ) -> Result<ConfirmedDelegatedProverRevocation, DelegatedProvingError> {
        if state_generation == 0
            || active.is_some_and(|authorization| authorization.policy_id != self.policy_id())
        {
            return Err(DelegatedProvingError::InvalidRevocation);
        }
        let active_authorization = active.map(DelegatedProvingAuthorization::authorization_id);
        let mut hasher = Hasher::new_derive_key(REVOCATION_ID_DOMAIN);
        hasher.update(&self.policy_id().0);
        hasher.update(&state_generation.to_le_bytes());
        hasher.update(
            &active_authorization
                .map(DelegatedProvingAuthorizationId::to_bytes)
                .unwrap_or([0; 32]),
        );
        let revocation_id = DelegatedProverRevocationId(*hasher.finalize().as_bytes());
        let facts = DelegatedProverRevocationFacts {
            revocation_id,
            policy_id: self.policy_id(),
            prover_id: self.prover_id(),
            prover_fingerprint: self.prover_fingerprint(),
            disclosure: self.disclosure,
            state_generation,
            active_authorization,
        };
        let observed = confirmation
            .confirm_delegated_prover_revocation(&facts)
            .map_err(|_| DelegatedProvingError::ConfirmationFailed)?;
        if !bool::from(observed.to_bytes().ct_eq(&revocation_id.to_bytes())) {
            return Err(DelegatedProvingError::ConfirmationFailed);
        }
        Ok(ConfirmedDelegatedProverRevocation {
            revocation_id,
            policy_id: self.policy_id(),
            state_generation,
            active_authorization,
        })
    }
}

impl ConfirmedDelegatedProverRevocation {
    /// Whether this token covers the exact policy generation and active job.
    #[must_use]
    pub fn matches(
        &self,
        policy: &DelegatedProvingPolicy,
        state_generation: u64,
        active: Option<&DelegatedProvingAuthorization>,
    ) -> bool {
        let active_authorization = active.map(DelegatedProvingAuthorization::authorization_id);
        self.policy_id == policy.policy_id()
            && self.state_generation == state_generation
            && self.active_authorization == active_authorization
            && {
                let mut hasher = Hasher::new_derive_key(REVOCATION_ID_DOMAIN);
                hasher.update(&policy.policy_id().0);
                hasher.update(&state_generation.to_le_bytes());
                hasher.update(
                    &active_authorization
                        .map(DelegatedProvingAuthorizationId::to_bytes)
                        .unwrap_or([0; 32]),
                );
                bool::from(
                    self.revocation_id
                        .to_bytes()
                        .ct_eq(hasher.finalize().as_bytes()),
                )
            }
    }
}

/// Platform adapter contract for the rollback-resistant one-job lifecycle.
///
/// An implementation MUST permit at most one active job per policy and retain
/// a monotonic authorization counter plus permanent policy tombstone across
/// restart and host-controlled rollback. `reserve_authorization` persists the
/// exact authorization before it leaves the wallet. `disclose_witness` checks
/// the dedicated authenticated endpoint/channel and matching confirmation,
/// then persists phase `disclosed` before sending any package byte.
/// `complete` accepts only a [`VerifiedDelegatedTransferProof`] and closes the
/// job before returning it. `abort` closes the channel and irreversibly closes
/// the job. `revoke_policy` closes the channel before atomically persisting the
/// permanent tombstone. Any uncertain transition poisons the open adapter.
pub trait DelegatedProvingJobLifecycle {
    /// Concrete protected storage/transport failure.
    type Error: std::error::Error;

    /// Durably reserves one exact approved authorization.
    fn reserve_authorization(
        &mut self,
        policy: &DelegatedProvingPolicy,
        authorization: &DelegatedProvingAuthorization,
    ) -> Result<(), Self::Error>;

    /// Commits disclosure before sending the exact matching witness package.
    fn disclose_witness(
        &mut self,
        policy: &DelegatedProvingPolicy,
        authorization: &DelegatedProvingAuthorization,
        confirmation: ConfirmedDelegatedProvingAuthorization,
        witness: DelegatedWitnessPackage,
    ) -> Result<(), Self::Error>;

    /// Closes the job durably before returning its locally verified proof.
    fn complete(
        &mut self,
        policy: &DelegatedProvingPolicy,
        authorization: &DelegatedProvingAuthorization,
        proof: VerifiedDelegatedTransferProof,
    ) -> Result<VerifiedDelegatedTransferProof, Self::Error>;

    /// Closes one failed or cancelled job and its authenticated channel.
    fn abort(
        &mut self,
        policy: &DelegatedProvingPolicy,
        authorization: &DelegatedProvingAuthorization,
    ) -> Result<(), Self::Error>;

    /// Permanently tombstones a policy after closing any active channel/job.
    fn revoke_policy(
        &mut self,
        policy: &DelegatedProvingPolicy,
        confirmation: ConfirmedDelegatedProverRevocation,
    ) -> Result<(), Self::Error>;
}

/// Delegated-proving contract failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegatedProvingError {
    /// Policy domains, endpoint, bucket or resource limits are invalid.
    InvalidPolicy,
    /// Witness package is empty, oversized or has a reserved commitment.
    InvalidWitnessPackage,
    /// Job, channel, counter, effects or package binding is invalid.
    InvalidAuthorization,
    /// A request is malformed, oversized, non-canonical or context-inconsistent.
    InvalidRequest,
    /// A response is malformed, oversized, non-canonical or context-inconsistent.
    InvalidResponse,
    /// Trusted approval rejected or returned different decision bytes.
    ConfirmationFailed,
    /// Proof length, effects binding, suite or local verification failed.
    ProofRejected,
    /// Permanent revocation facts are invalid or belong to another policy.
    InvalidRevocation,
    /// A fresh non-zero job identifier could not be generated.
    EntropyUnavailable,
}

impl fmt::Display for DelegatedProvingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPolicy => "invalid delegated-proving policy",
            Self::InvalidWitnessPackage => "invalid delegated-proving witness package",
            Self::InvalidAuthorization => "invalid delegated-proving authorization",
            Self::InvalidRequest => "invalid delegated-proving request",
            Self::InvalidResponse => "invalid delegated-proving response",
            Self::ConfirmationFailed => "delegated-proving confirmation failed",
            Self::ProofRejected => "delegated proof was rejected",
            Self::InvalidRevocation => "invalid delegated-prover revocation",
            Self::EntropyUnavailable => "delegated-proving job entropy is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DelegatedProvingError {}
