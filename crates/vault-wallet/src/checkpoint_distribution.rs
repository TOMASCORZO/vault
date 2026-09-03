//! Threshold-authenticated distribution for wallet birthday checkpoints.
//!
//! Publisher signatures authenticate the distributed frontier, but never prove
//! consensus finality. Acceptance additionally requires an independently
//! verified [`FinalizedCompactBlockHeader`] with exactly matching fields.

use core::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use vault_privacy::{NoteCommitmentTree, NoteTreeRoot, NoteTreeSnapshot};
use vault_protocol::{ChainId, FinalizedCompactBlockHeader};

use crate::WalletBirthdayCheckpoint;

const CHECKPOINT_MAGIC: [u8; 8] = *b"VCKPT001";
const TARGET_MAGIC: [u8; 8] = *b"VTARG001";
const POLICY_BOOTSTRAP_MAGIC: [u8; 8] = *b"VBOOT001";
const POLICY_UPDATE_MAGIC: [u8; 8] = *b"VPOLY001";
const CHECKPOINT_PUBLISHER_ID_DOMAIN: &str = "vault.wallet.checkpoint-publisher-id-v1.2026-09-02";
const CHECKPOINT_POLICY_ID_DOMAIN: &str = "vault.wallet.checkpoint-policy-id-v1.2026-09-02";
const MAX_FRONTIER_OMMERS: usize = 32;
const FIXED_SIGNING_BYTES: usize = 8 + 32 + 8 + 32 + 8 + 32 + 1 + 32 + 1;
const TARGET_SIGNING_BYTES: usize = 8 + 32 + 8 + 32 + 8 + 32;
const POLICY_BOOTSTRAP_FIXED_SIGNING_BYTES: usize = 8 + 32 + 8 + 1 + 1 + 32 + 32;
const POLICY_UPDATE_FIXED_SIGNING_BYTES: usize = 8 + 32 + 8 + 32 + 8 + 1 + 1;
const SIGNATURE_RECORD_BYTES: usize = 32 + 64;
const MAX_CHECKPOINT_DISTRIBUTION_BYTES: usize = FIXED_SIGNING_BYTES
    + MAX_FRONTIER_OMMERS * 32
    + 1
    + MAX_CHECKPOINT_PUBLISHERS * SIGNATURE_RECORD_BYTES;

/// Maximum independent publisher keys in one checkpoint trust policy.
pub const MAX_CHECKPOINT_PUBLISHERS: usize = 8;
/// Maximum encoded bytes in one proof-of-possession bootstrap package.
pub const MAX_CHECKPOINT_POLICY_BOOTSTRAP_BYTES: usize = POLICY_BOOTSTRAP_FIXED_SIGNING_BYTES
    + MAX_CHECKPOINT_PUBLISHERS * 32
    + 1
    + MAX_CHECKPOINT_PUBLISHERS * SIGNATURE_RECORD_BYTES;
/// Maximum encoded bytes in one authenticated publisher-policy update.
pub const MAX_CHECKPOINT_POLICY_UPDATE_BYTES: usize = POLICY_UPDATE_FIXED_SIGNING_BYTES
    + MAX_CHECKPOINT_PUBLISHERS * 32
    + 1
    + MAX_CHECKPOINT_PUBLISHERS * SIGNATURE_RECORD_BYTES;

/// Fail-closed checkpoint distribution validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointDistributionError {
    /// Framing, counts, canonical fields, or frontier data are invalid.
    InvalidEncoding,
    /// The package or policy belongs to another network.
    WrongNetwork,
    /// Publisher keys or the required threshold are invalid.
    InvalidPolicy,
    /// The bootstrap artifact does not match its separately pinned policy ID.
    BootstrapMismatch,
    /// An update does not descend from the exact active publisher policy.
    PolicyPredecessorMismatch,
    /// Publisher records are unknown, duplicated, unsorted, or fail signature verification.
    AuthenticationFailed,
    /// The package does not match the independently finalized header.
    FinalizedHeaderMismatch,
}

impl fmt::Display for CheckpointDistributionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEncoding => "checkpoint distribution encoding is invalid",
            Self::WrongNetwork => "checkpoint distribution belongs to another network",
            Self::InvalidPolicy => "checkpoint publisher policy is invalid",
            Self::BootstrapMismatch => "checkpoint bootstrap does not match its pinned policy ID",
            Self::PolicyPredecessorMismatch => {
                "checkpoint publisher policy predecessor does not match"
            }
            Self::AuthenticationFailed => "checkpoint publisher authentication failed",
            Self::FinalizedHeaderMismatch => {
                "checkpoint does not match the independently finalized header"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CheckpointDistributionError {}

#[derive(Clone)]
struct TrustedPublisher {
    id: [u8; 32],
    key: VerifyingKey,
}

/// Separately configured publisher keys and threshold for one Vault network.
#[derive(Clone)]
pub struct CheckpointTrustPolicy {
    chain_id: ChainId,
    generation: u64,
    threshold: usize,
    publishers: Vec<TrustedPublisher>,
}

impl fmt::Debug for CheckpointTrustPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointTrustPolicy")
            .field("chain_id", &self.chain_id)
            .field("generation", &self.generation)
            .field("threshold", &self.threshold)
            .field("publisher_count", &self.publishers.len())
            .finish()
    }
}

impl CheckpointTrustPolicy {
    /// Validates and pins an unordered set of independent Ed25519 publisher keys.
    pub fn new(
        chain_id: ChainId,
        threshold: usize,
        publisher_keys: Vec<[u8; 32]>,
    ) -> Result<Self, CheckpointDistributionError> {
        Self::new_at_generation(chain_id, 1, threshold, publisher_keys)
    }

    /// Replaces the complete publisher set at a strictly newer policy generation.
    /// Keys omitted from the successor are revoked for all later verification.
    pub fn rotated(
        &self,
        next_generation: u64,
        threshold: usize,
        publisher_keys: Vec<[u8; 32]>,
    ) -> Result<Self, CheckpointDistributionError> {
        if next_generation <= self.generation {
            return Err(CheckpointDistributionError::InvalidPolicy);
        }
        Self::new_at_generation(self.chain_id, next_generation, threshold, publisher_keys)
    }

    /// Monotonic policy generation that platform storage must protect from rollback.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Network on which this policy can authenticate checkpoint distribution.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Stable commitment to the complete canonical policy state.
    #[must_use]
    pub fn policy_id(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_POLICY_ID_DOMAIN);
        hasher.update(self.chain_id.as_bytes());
        hasher.update(&self.generation.to_be_bytes());
        hasher.update(&[u8::try_from(self.threshold).expect("publisher threshold fits u8")]);
        hasher.update(&[u8::try_from(self.publishers.len()).expect("publisher count fits u8")]);
        for publisher in &self.publishers {
            hasher.update(publisher.key.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    fn new_at_generation(
        chain_id: ChainId,
        generation: u64,
        threshold: usize,
        publisher_keys: Vec<[u8; 32]>,
    ) -> Result<Self, CheckpointDistributionError> {
        if chain_id.is_zero()
            || generation == 0
            || publisher_keys.is_empty()
            || publisher_keys.len() > MAX_CHECKPOINT_PUBLISHERS
            || threshold == 0
            || threshold > publisher_keys.len()
        {
            return Err(CheckpointDistributionError::InvalidPolicy);
        }
        let mut publishers = publisher_keys
            .into_iter()
            .map(|bytes| {
                let key = VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| CheckpointDistributionError::InvalidPolicy)?;
                if key.is_weak() {
                    return Err(CheckpointDistributionError::InvalidPolicy);
                }
                Ok(TrustedPublisher {
                    id: checkpoint_publisher_id(bytes),
                    key,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        publishers.sort_unstable_by_key(|publisher| publisher.id);
        if publishers.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(CheckpointDistributionError::InvalidPolicy);
        }
        Ok(Self {
            chain_id,
            generation,
            threshold,
            publishers,
        })
    }
}

/// Canonical generation-1 policy awaiting proof of possession from every key.
pub struct CheckpointPolicyBootstrapDraft {
    signing_bytes: Vec<u8>,
    publisher_count: usize,
}

impl fmt::Debug for CheckpointPolicyBootstrapDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointPolicyBootstrapDraft")
            .field("signing_bytes", &self.signing_bytes.len())
            .field("publisher_count", &self.publisher_count)
            .finish()
    }
}

impl CheckpointPolicyBootstrapDraft {
    /// Builds a generation-1 artifact from the complete publisher set.
    ///
    /// `ceremony_nonce` must be sampled independently for this ceremony. The
    /// resulting policy ID must still be pinned through a trusted release or
    /// operator-confirmation channel; signatures cannot make a root trust
    /// decision self-authenticating.
    pub fn new(
        chain_id: ChainId,
        threshold: usize,
        publisher_keys: Vec<[u8; 32]>,
        ceremony_nonce: [u8; 32],
    ) -> Result<Self, CheckpointDistributionError> {
        if ceremony_nonce == [0; 32] {
            return Err(CheckpointDistributionError::InvalidPolicy);
        }
        let policy = CheckpointTrustPolicy::new(chain_id, threshold, publisher_keys)?;
        let mut bytes =
            Vec::with_capacity(POLICY_BOOTSTRAP_FIXED_SIGNING_BYTES + policy.publishers.len() * 32);
        bytes.extend_from_slice(&POLICY_BOOTSTRAP_MAGIC);
        bytes.extend_from_slice(policy.chain_id.as_bytes());
        bytes.extend_from_slice(&policy.generation.to_be_bytes());
        bytes.push(
            u8::try_from(policy.threshold)
                .map_err(|_| CheckpointDistributionError::InvalidPolicy)?,
        );
        bytes.push(
            u8::try_from(policy.publishers.len())
                .map_err(|_| CheckpointDistributionError::InvalidPolicy)?,
        );
        for publisher in &policy.publishers {
            bytes.extend_from_slice(publisher.key.as_bytes());
        }
        bytes.extend_from_slice(&ceremony_nonce);
        bytes.extend_from_slice(&policy.policy_id());
        Ok(Self {
            signing_bytes: bytes,
            publisher_count: policy.publishers.len(),
        })
    }

    /// Exact ceremony-bound bytes every configured publisher must sign.
    #[must_use]
    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }

    /// Appends one proof-of-possession signature from every publisher.
    pub fn assemble(
        self,
        signatures: Vec<CheckpointPublisherSignature>,
    ) -> Result<Vec<u8>, CheckpointDistributionError> {
        if signatures.len() != self.publisher_count {
            return Err(CheckpointDistributionError::AuthenticationFailed);
        }
        assemble_signed_package(self.signing_bytes, signatures)
    }
}

/// Validated successor-policy bytes awaiting signatures from the active policy.
pub struct CheckpointPolicyUpdateDraft {
    signing_bytes: Vec<u8>,
}

impl fmt::Debug for CheckpointPolicyUpdateDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointPolicyUpdateDraft")
            .field("signing_bytes", &self.signing_bytes.len())
            .finish()
    }
}

impl CheckpointPolicyUpdateDraft {
    /// Canonically encodes a complete successor policy bound to its predecessor.
    pub fn new(
        current: &CheckpointTrustPolicy,
        next_generation: u64,
        threshold: usize,
        publisher_keys: Vec<[u8; 32]>,
    ) -> Result<Self, CheckpointDistributionError> {
        let successor = current.rotated(next_generation, threshold, publisher_keys)?;
        let mut bytes =
            Vec::with_capacity(POLICY_UPDATE_FIXED_SIGNING_BYTES + successor.publishers.len() * 32);
        bytes.extend_from_slice(&POLICY_UPDATE_MAGIC);
        bytes.extend_from_slice(current.chain_id.as_bytes());
        bytes.extend_from_slice(&current.generation.to_be_bytes());
        bytes.extend_from_slice(&current.policy_id());
        bytes.extend_from_slice(&successor.generation.to_be_bytes());
        bytes.push(
            u8::try_from(successor.threshold)
                .map_err(|_| CheckpointDistributionError::InvalidPolicy)?,
        );
        bytes.push(
            u8::try_from(successor.publishers.len())
                .map_err(|_| CheckpointDistributionError::InvalidPolicy)?,
        );
        for publisher in &successor.publishers {
            bytes.extend_from_slice(publisher.key.as_bytes());
        }
        Ok(Self {
            signing_bytes: bytes,
        })
    }

    /// Exact predecessor-bound bytes each current publisher must sign.
    #[must_use]
    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }

    /// Canonically orders and appends current-publisher signatures.
    pub fn assemble(
        self,
        signatures: Vec<CheckpointPublisherSignature>,
    ) -> Result<Vec<u8>, CheckpointDistributionError> {
        assemble_signed_package(self.signing_bytes, signatures)
    }
}

/// Stable identifier for one separately pinned checkpoint publisher key.
#[must_use]
pub fn checkpoint_publisher_id(verifying_key: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_PUBLISHER_ID_DOMAIN);
    hasher.update(&verifying_key);
    *hasher.finalize().as_bytes()
}

/// One externally produced signature over exact checkpoint signing bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointPublisherSignature {
    publisher_id: [u8; 32],
    signature: [u8; 64],
}

impl CheckpointPublisherSignature {
    /// Associates a canonical signature with its separately trusted publisher.
    #[must_use]
    pub const fn new(publisher_id: [u8; 32], signature: [u8; 64]) -> Self {
        Self {
            publisher_id,
            signature,
        }
    }
}

/// Validated unsigned checkpoint bytes awaiting independent publisher signatures.
pub struct CheckpointDistributionDraft {
    signing_bytes: Vec<u8>,
}

impl fmt::Debug for CheckpointDistributionDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointDistributionDraft")
            .field("signing_bytes", &self.signing_bytes.len())
            .finish()
    }
}

impl CheckpointDistributionDraft {
    /// Builds the canonical bytes only when the frontier matches the asserted header.
    pub fn new(
        header: &FinalizedCompactBlockHeader,
        snapshot: &NoteTreeSnapshot,
    ) -> Result<Self, CheckpointDistributionError> {
        WalletBirthdayCheckpoint::from_finalized_header(header, snapshot)
            .map_err(|_| CheckpointDistributionError::FinalizedHeaderMismatch)?;
        if snapshot.ommers().len() > MAX_FRONTIER_OMMERS {
            return Err(CheckpointDistributionError::InvalidEncoding);
        }
        let mut bytes = Vec::with_capacity(FIXED_SIGNING_BYTES + snapshot.ommers().len() * 32);
        bytes.extend_from_slice(&CHECKPOINT_MAGIC);
        bytes.extend_from_slice(header.chain_id().as_bytes());
        bytes.extend_from_slice(&header.height().to_be_bytes());
        bytes.extend_from_slice(&header.block_hash());
        bytes.extend_from_slice(&header.post_tree_size().to_be_bytes());
        bytes.extend_from_slice(&header.post_tree_root().to_bytes());
        if let Some(leaf) = snapshot.leaf() {
            bytes.push(1);
            bytes.extend_from_slice(&leaf);
        } else {
            bytes.push(0);
            bytes.extend_from_slice(&[0; 32]);
        }
        bytes.push(
            u8::try_from(snapshot.ommers().len())
                .map_err(|_| CheckpointDistributionError::InvalidEncoding)?,
        );
        for ommer in snapshot.ommers() {
            bytes.extend_from_slice(ommer);
        }
        Ok(Self {
            signing_bytes: bytes,
        })
    }

    /// Exact domain/version-bound bytes each publisher must sign.
    #[must_use]
    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }

    /// Canonically orders and appends bounded publisher signature records.
    pub fn assemble(
        self,
        signatures: Vec<CheckpointPublisherSignature>,
    ) -> Result<Vec<u8>, CheckpointDistributionError> {
        assemble_signed_package(self.signing_bytes, signatures)
    }
}

/// Validated unsigned recovery-target bytes awaiting publisher signatures.
pub struct RecoveryTargetDistributionDraft {
    signing_bytes: Vec<u8>,
}

impl fmt::Debug for RecoveryTargetDistributionDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryTargetDistributionDraft")
            .field("signing_bytes", &self.signing_bytes.len())
            .finish()
    }
}

impl RecoveryTargetDistributionDraft {
    /// Encodes the exact target boundary asserted by a finalized header.
    pub fn new(header: &FinalizedCompactBlockHeader) -> Self {
        let mut bytes = Vec::with_capacity(TARGET_SIGNING_BYTES);
        bytes.extend_from_slice(&TARGET_MAGIC);
        bytes.extend_from_slice(header.chain_id().as_bytes());
        bytes.extend_from_slice(&header.height().to_be_bytes());
        bytes.extend_from_slice(&header.block_hash());
        bytes.extend_from_slice(&header.post_tree_size().to_be_bytes());
        bytes.extend_from_slice(&header.post_tree_root().to_bytes());
        Self {
            signing_bytes: bytes,
        }
    }

    /// Exact domain/version-bound bytes each publisher must sign.
    #[must_use]
    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }

    /// Canonically orders and appends bounded publisher signature records.
    pub fn assemble(
        self,
        signatures: Vec<CheckpointPublisherSignature>,
    ) -> Result<Vec<u8>, CheckpointDistributionError> {
        assemble_signed_package(self.signing_bytes, signatures)
    }
}

/// Recovery target authenticated by publishers and matched to independent finality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedRecoveryTarget {
    header: FinalizedCompactBlockHeader,
}

impl AuthenticatedRecoveryTarget {
    /// Exact finalized target height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.header.height()
    }

    pub(crate) const fn finalized_header(&self) -> &FinalizedCompactBlockHeader {
        &self.header
    }
}

fn assemble_signed_package(
    mut signing_bytes: Vec<u8>,
    mut signatures: Vec<CheckpointPublisherSignature>,
) -> Result<Vec<u8>, CheckpointDistributionError> {
    if signatures.is_empty() || signatures.len() > MAX_CHECKPOINT_PUBLISHERS {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    signatures.sort_unstable_by_key(|signature| signature.publisher_id);
    if signatures
        .windows(2)
        .any(|pair| pair[0].publisher_id == pair[1].publisher_id)
    {
        return Err(CheckpointDistributionError::AuthenticationFailed);
    }
    signing_bytes.push(
        u8::try_from(signatures.len()).map_err(|_| CheckpointDistributionError::InvalidEncoding)?,
    );
    for signature in signatures {
        signing_bytes.extend_from_slice(&signature.publisher_id);
        signing_bytes.extend_from_slice(&signature.signature);
    }
    Ok(signing_bytes)
}

/// Verifies a generation-1 bootstrap against a separately pinned policy ID.
///
/// Every configured publisher must prove possession of its private key. This
/// does not authenticate publisher identity: callers must obtain
/// `expected_policy_id` through the approved release/bootstrap ceremony.
pub fn verify_checkpoint_policy_bootstrap(
    package: &[u8],
    expected_chain_id: ChainId,
    expected_policy_id: [u8; 32],
) -> Result<CheckpointTrustPolicy, CheckpointDistributionError> {
    let minimum_bytes = POLICY_BOOTSTRAP_FIXED_SIGNING_BYTES + 32 + 1 + SIGNATURE_RECORD_BYTES;
    if package.len() < minimum_bytes || package.len() > MAX_CHECKPOINT_POLICY_BOOTSTRAP_BYTES {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    let mut reader = Reader::new(package);
    if reader.take::<8>()? != POLICY_BOOTSTRAP_MAGIC {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    let chain_id = ChainId::new(reader.take()?);
    if chain_id != expected_chain_id {
        return Err(CheckpointDistributionError::WrongNetwork);
    }
    let generation = u64::from_be_bytes(reader.take()?);
    let threshold = usize::from(reader.take::<1>()?[0]);
    let publisher_count = usize::from(reader.take::<1>()?[0]);
    if generation != 1 || publisher_count == 0 || publisher_count > MAX_CHECKPOINT_PUBLISHERS {
        return Err(CheckpointDistributionError::InvalidPolicy);
    }
    let mut publisher_keys = Vec::with_capacity(publisher_count);
    let mut previous_id = None;
    for _ in 0..publisher_count {
        let key = reader.take::<32>()?;
        let publisher_id = checkpoint_publisher_id(key);
        if previous_id.is_some_and(|previous| previous >= publisher_id) {
            return Err(CheckpointDistributionError::InvalidEncoding);
        }
        previous_id = Some(publisher_id);
        publisher_keys.push(key);
    }
    if reader.take::<32>()? == [0; 32] {
        return Err(CheckpointDistributionError::InvalidPolicy);
    }
    let encoded_policy_id = reader.take::<32>()?;
    let signing_end = reader.position();

    let policy = CheckpointTrustPolicy::new(chain_id, threshold, publisher_keys.clone())?;
    if encoded_policy_id != policy.policy_id() || encoded_policy_id != expected_policy_id {
        return Err(CheckpointDistributionError::BootstrapMismatch);
    }
    let proof_policy = CheckpointTrustPolicy::new(chain_id, publisher_count, publisher_keys)?;
    verify_signature_records(package, signing_end, &mut reader, &proof_policy)?;
    Ok(policy)
}

/// Authenticates and reconstructs a complete successor publisher policy.
///
/// The signatures are verified with the exact active predecessor policy. The
/// returned policy cannot be used as evidence of consensus finality; it only
/// controls authentication of checkpoint distribution.
pub fn verify_checkpoint_policy_update(
    package: &[u8],
    current: &CheckpointTrustPolicy,
) -> Result<CheckpointTrustPolicy, CheckpointDistributionError> {
    let minimum_bytes = POLICY_UPDATE_FIXED_SIGNING_BYTES + 32 + 1 + SIGNATURE_RECORD_BYTES;
    if package.len() < minimum_bytes || package.len() > MAX_CHECKPOINT_POLICY_UPDATE_BYTES {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    let mut reader = Reader::new(package);
    if reader.take::<8>()? != POLICY_UPDATE_MAGIC {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    let chain_id = ChainId::new(reader.take()?);
    let predecessor_generation = u64::from_be_bytes(reader.take()?);
    let predecessor_id = reader.take::<32>()?;
    if chain_id != current.chain_id {
        return Err(CheckpointDistributionError::WrongNetwork);
    }
    if predecessor_generation != current.generation || predecessor_id != current.policy_id() {
        return Err(CheckpointDistributionError::PolicyPredecessorMismatch);
    }

    let next_generation = u64::from_be_bytes(reader.take()?);
    let threshold = usize::from(reader.take::<1>()?[0]);
    let publisher_count = usize::from(reader.take::<1>()?[0]);
    if publisher_count == 0 || publisher_count > MAX_CHECKPOINT_PUBLISHERS {
        return Err(CheckpointDistributionError::InvalidPolicy);
    }
    let mut publisher_keys = Vec::with_capacity(publisher_count);
    let mut previous_id = None;
    for _ in 0..publisher_count {
        let key = reader.take::<32>()?;
        let publisher_id = checkpoint_publisher_id(key);
        if previous_id.is_some_and(|previous| previous >= publisher_id) {
            return Err(CheckpointDistributionError::InvalidEncoding);
        }
        previous_id = Some(publisher_id);
        publisher_keys.push(key);
    }
    let signing_end = reader.position();
    verify_signature_records(package, signing_end, &mut reader, current)?;
    current.rotated(next_generation, threshold, publisher_keys)
}

/// Verifies publisher threshold and exact correspondence with consensus-finalized state.
pub fn verify_birthday_checkpoint_distribution(
    package: &[u8],
    policy: &CheckpointTrustPolicy,
    finalized_header: &FinalizedCompactBlockHeader,
) -> Result<WalletBirthdayCheckpoint, CheckpointDistributionError> {
    if package.len() < FIXED_SIGNING_BYTES + 1 + SIGNATURE_RECORD_BYTES
        || package.len() > MAX_CHECKPOINT_DISTRIBUTION_BYTES
    {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    let mut reader = Reader::new(package);
    if reader.take::<8>()? != CHECKPOINT_MAGIC {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    let chain_id = ChainId::new(reader.take()?);
    if chain_id != policy.chain_id {
        return Err(CheckpointDistributionError::WrongNetwork);
    }
    let height = u64::from_be_bytes(reader.take()?);
    let block_hash = reader.take()?;
    let tree_size = u64::from_be_bytes(reader.take()?);
    let tree_root = NoteTreeRoot::from_bytes(reader.take()?)
        .map_err(|_| CheckpointDistributionError::InvalidEncoding)?;
    let leaf_present = reader.take::<1>()?[0];
    let leaf_bytes = reader.take::<32>()?;
    let leaf = match leaf_present {
        0 if leaf_bytes == [0; 32] => None,
        1 => Some(leaf_bytes),
        _ => return Err(CheckpointDistributionError::InvalidEncoding),
    };
    let ommer_count = usize::from(reader.take::<1>()?[0]);
    if ommer_count > MAX_FRONTIER_OMMERS {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    let mut ommers = Vec::with_capacity(ommer_count);
    for _ in 0..ommer_count {
        ommers.push(reader.take()?);
    }
    let signing_end = reader.position();
    verify_signature_records(package, signing_end, &mut reader, policy)?;

    let snapshot = NoteTreeSnapshot::from_parts(tree_size, leaf, ommers);
    let tree = NoteCommitmentTree::restore(&snapshot)
        .map_err(|_| CheckpointDistributionError::InvalidEncoding)?;
    if tree.size() != tree_size || tree.typed_root() != tree_root {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    if finalized_header.chain_id() != chain_id
        || finalized_header.height() != height
        || finalized_header.block_hash() != block_hash
        || finalized_header.post_tree_size() != tree_size
        || finalized_header.post_tree_root() != tree_root
    {
        return Err(CheckpointDistributionError::FinalizedHeaderMismatch);
    }
    WalletBirthdayCheckpoint::from_finalized_header(finalized_header, &snapshot)
        .map_err(|_| CheckpointDistributionError::FinalizedHeaderMismatch)
}

/// Verifies a distributed recovery target against both publishers and finality.
pub fn verify_recovery_target_distribution(
    package: &[u8],
    policy: &CheckpointTrustPolicy,
    finalized_header: &FinalizedCompactBlockHeader,
) -> Result<AuthenticatedRecoveryTarget, CheckpointDistributionError> {
    let maximum_bytes =
        TARGET_SIGNING_BYTES + 1 + MAX_CHECKPOINT_PUBLISHERS * SIGNATURE_RECORD_BYTES;
    if package.len() < TARGET_SIGNING_BYTES + 1 + SIGNATURE_RECORD_BYTES
        || package.len() > maximum_bytes
    {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    let mut reader = Reader::new(package);
    if reader.take::<8>()? != TARGET_MAGIC {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    let chain_id = ChainId::new(reader.take()?);
    if chain_id != policy.chain_id {
        return Err(CheckpointDistributionError::WrongNetwork);
    }
    let height = u64::from_be_bytes(reader.take()?);
    let block_hash = reader.take()?;
    let tree_size = u64::from_be_bytes(reader.take()?);
    let tree_root = NoteTreeRoot::from_bytes(reader.take()?)
        .map_err(|_| CheckpointDistributionError::InvalidEncoding)?;
    let signing_end = reader.position();
    debug_assert_eq!(signing_end, TARGET_SIGNING_BYTES);
    verify_signature_records(package, signing_end, &mut reader, policy)?;

    if finalized_header.chain_id() != chain_id
        || finalized_header.height() != height
        || finalized_header.block_hash() != block_hash
        || finalized_header.post_tree_size() != tree_size
        || finalized_header.post_tree_root() != tree_root
    {
        return Err(CheckpointDistributionError::FinalizedHeaderMismatch);
    }
    Ok(AuthenticatedRecoveryTarget {
        header: *finalized_header,
    })
}

fn verify_signature_records(
    package: &[u8],
    signing_end: usize,
    reader: &mut Reader<'_>,
    policy: &CheckpointTrustPolicy,
) -> Result<(), CheckpointDistributionError> {
    let signature_count = usize::from(reader.take::<1>()?[0]);
    if signature_count == 0
        || signature_count > MAX_CHECKPOINT_PUBLISHERS
        || signature_count < policy.threshold
        || reader.remaining() != signature_count * SIGNATURE_RECORD_BYTES
    {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }

    let mut previous_id = None;
    for _ in 0..signature_count {
        let publisher_id = reader.take::<32>()?;
        if previous_id.is_some_and(|previous| previous >= publisher_id) {
            return Err(CheckpointDistributionError::AuthenticationFailed);
        }
        previous_id = Some(publisher_id);
        let signature_bytes = reader.take::<64>()?;
        let publisher = policy
            .publishers
            .iter()
            .find(|publisher| publisher.id == publisher_id)
            .ok_or(CheckpointDistributionError::AuthenticationFailed)?;
        let signature = Signature::from_bytes(&signature_bytes);
        publisher
            .key
            .verify_strict(&package[..signing_end], &signature)
            .map_err(|_| CheckpointDistributionError::AuthenticationFailed)?;
    }
    if reader.remaining() != 0 {
        return Err(CheckpointDistributionError::InvalidEncoding);
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], CheckpointDistributionError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(CheckpointDistributionError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CheckpointDistributionError::InvalidEncoding)?
            .try_into()
            .map_err(|_| CheckpointDistributionError::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }

    const fn position(&self) -> usize {
        self.offset
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use vault_privacy::NoteCommitmentTree;
    use vault_protocol::CompactBlockCommitment;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{WalletRecoveryAccounts, WalletRecoveryPlan, WalletSeedMaterial};

    const NETWORK: [u8; 32] = [0x71; 32];

    fn header_at(height: u64, block_hash: [u8; 32]) -> FinalizedCompactBlockHeader {
        let empty_root = NoteCommitmentTree::new().typed_root();
        FinalizedCompactBlockHeader::from_verified_consensus(
            ChainId::new(NETWORK),
            height,
            block_hash,
            [0x73; 32],
            0,
            empty_root,
            0,
            empty_root,
            CompactBlockCommitment::from_bytes([0x74; 32]).unwrap(),
        )
        .unwrap()
    }

    fn header(block_hash: [u8; 32]) -> FinalizedCompactBlockHeader {
        header_at(100, block_hash)
    }

    fn signatures(
        signing_bytes: &[u8],
        signing_keys: &[SigningKey],
    ) -> Vec<CheckpointPublisherSignature> {
        signing_keys
            .iter()
            .map(|key| {
                CheckpointPublisherSignature::new(
                    checkpoint_publisher_id(key.verifying_key().to_bytes()),
                    key.sign(signing_bytes).to_bytes(),
                )
            })
            .collect()
    }

    fn signed_package(
        header: &FinalizedCompactBlockHeader,
        signing_keys: &[SigningKey],
    ) -> Vec<u8> {
        let draft = CheckpointDistributionDraft::new(header, &NoteCommitmentTree::new().snapshot())
            .unwrap();
        let signed = signatures(draft.signing_bytes(), signing_keys);
        draft.assemble(signed).unwrap()
    }

    #[test]
    fn bootstrap_requires_every_key_and_the_separately_pinned_policy_id() {
        const EXPECTED_BOOTSTRAP_HASH: [u8; 32] = [
            0xf6, 0xbc, 0x8a, 0x6b, 0x6e, 0x70, 0x6d, 0x19, 0xae, 0x2b, 0x81, 0x0d, 0xc5, 0xef,
            0xd8, 0xb6, 0x97, 0x9a, 0x87, 0xea, 0x66, 0x60, 0xba, 0xfc, 0x05, 0x81, 0x74, 0xfd,
            0x53, 0x30, 0xd3, 0x17,
        ];
        let keys = [
            SigningKey::from_bytes(&[71; 32]),
            SigningKey::from_bytes(&[72; 32]),
            SigningKey::from_bytes(&[73; 32]),
        ];
        let publisher_keys = keys
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect::<Vec<_>>();
        let policy =
            CheckpointTrustPolicy::new(ChainId::new(NETWORK), 2, publisher_keys.clone()).unwrap();
        let draft = CheckpointPolicyBootstrapDraft::new(
            ChainId::new(NETWORK),
            2,
            publisher_keys.clone(),
            [0xB1; 32],
        )
        .unwrap();
        let all_signatures = signatures(draft.signing_bytes(), &keys);
        let package = draft.assemble(all_signatures).unwrap();

        assert_eq!(package.len(), 499);
        assert_eq!(blake3::hash(&package).as_bytes(), &EXPECTED_BOOTSTRAP_HASH);
        let verified =
            verify_checkpoint_policy_bootstrap(&package, ChainId::new(NETWORK), policy.policy_id())
                .unwrap();
        assert_eq!(verified.chain_id(), policy.chain_id());
        assert_eq!(verified.generation(), 1);
        assert_eq!(verified.policy_id(), policy.policy_id());

        let incomplete = CheckpointPolicyBootstrapDraft::new(
            ChainId::new(NETWORK),
            2,
            publisher_keys,
            [0xB1; 32],
        )
        .unwrap();
        let incomplete_signatures = signatures(incomplete.signing_bytes(), &keys[..2]);
        assert_eq!(
            incomplete.assemble(incomplete_signatures).unwrap_err(),
            CheckpointDistributionError::AuthenticationFailed
        );
        assert_eq!(
            verify_checkpoint_policy_bootstrap(&package, ChainId::new(NETWORK), [0xFF; 32])
                .unwrap_err(),
            CheckpointDistributionError::BootstrapMismatch
        );
        assert_eq!(
            verify_checkpoint_policy_bootstrap(
                &package,
                ChainId::new([0xFF; 32]),
                policy.policy_id()
            )
            .unwrap_err(),
            CheckpointDistributionError::WrongNetwork
        );
        assert!(
            CheckpointPolicyBootstrapDraft::new(
                ChainId::new(NETWORK),
                2,
                keys.iter()
                    .map(|key| key.verifying_key().to_bytes())
                    .collect(),
                [0; 32],
            )
            .is_err()
        );

        for index in 0..package.len() {
            let mut mutated = package.clone();
            mutated[index] ^= 1;
            assert!(
                verify_checkpoint_policy_bootstrap(
                    &mutated,
                    ChainId::new(NETWORK),
                    policy.policy_id()
                )
                .is_err(),
                "bootstrap mutation at byte {index} was accepted"
            );
        }
        for length in 0..package.len() {
            assert!(
                verify_checkpoint_policy_bootstrap(
                    &package[..length],
                    ChainId::new(NETWORK),
                    policy.policy_id()
                )
                .is_err()
            );
        }
        let mut trailing = package;
        trailing.push(0);
        assert!(
            verify_checkpoint_policy_bootstrap(
                &trailing,
                ChainId::new(NETWORK),
                policy.policy_id()
            )
            .is_err()
        );
    }

    #[test]
    fn threshold_package_matches_finalized_header_and_rejects_every_mutation() {
        const EXPECTED_PACKAGE_HASH: [u8; 32] = [
            0xed, 0x55, 0x9e, 0xbb, 0xce, 0x82, 0x26, 0x3c, 0x23, 0xf7, 0xb2, 0xe2, 0x84, 0xd3,
            0x7d, 0x1c, 0x86, 0xbb, 0xf1, 0xd1, 0x22, 0xde, 0xc8, 0xcc, 0x2f, 0xac, 0x72, 0xae,
            0xfc, 0xae, 0x0a, 0x22,
        ];
        let keys = [
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
            SigningKey::from_bytes(&[3; 32]),
        ];
        let policy = CheckpointTrustPolicy::new(
            ChainId::new(NETWORK),
            2,
            keys.iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
        )
        .unwrap();
        let finalized_header = header([0x72; 32]);
        let package = signed_package(&finalized_header, &keys[..2]);
        assert_eq!(package.len(), 347);
        assert_eq!(blake3::hash(&package).as_bytes(), &EXPECTED_PACKAGE_HASH);
        let checkpoint =
            verify_birthday_checkpoint_distribution(&package, &policy, &finalized_header).unwrap();
        assert_eq!(checkpoint.checkpoint_height(), 100);
        assert_eq!(checkpoint.first_scan_height(), 101);

        for index in 0..package.len() {
            let mut mutated = package.clone();
            mutated[index] ^= 1;
            assert!(
                verify_birthday_checkpoint_distribution(&mutated, &policy, &finalized_header)
                    .is_err(),
                "mutation at byte {index} was accepted"
            );
        }
        for length in 0..package.len() {
            assert!(
                verify_birthday_checkpoint_distribution(
                    &package[..length],
                    &policy,
                    &finalized_header
                )
                .is_err()
            );
        }
        let mut trailing = package.clone();
        trailing.push(0);
        assert!(
            verify_birthday_checkpoint_distribution(&trailing, &policy, &finalized_header).is_err()
        );
    }

    #[test]
    fn publisher_threshold_and_independent_finality_are_both_required() {
        let keys = [
            SigningKey::from_bytes(&[4; 32]),
            SigningKey::from_bytes(&[5; 32]),
            SigningKey::from_bytes(&[6; 32]),
        ];
        let policy = CheckpointTrustPolicy::new(
            ChainId::new(NETWORK),
            2,
            keys.iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
        )
        .unwrap();
        let finalized_header = header([0x75; 32]);
        let one_signature = signed_package(&finalized_header, &keys[..1]);
        assert!(
            verify_birthday_checkpoint_distribution(&one_signature, &policy, &finalized_header)
                .is_err()
        );

        let package = signed_package(&finalized_header, &keys[..2]);
        assert_eq!(
            verify_birthday_checkpoint_distribution(&package, &policy, &header([0x76; 32]))
                .unwrap_err(),
            CheckpointDistributionError::FinalizedHeaderMismatch
        );
    }

    #[test]
    fn invalid_publisher_policies_and_duplicate_records_fail_closed() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = key.verifying_key().to_bytes();
        assert!(CheckpointTrustPolicy::new(ChainId::new(NETWORK), 0, vec![public]).is_err());
        assert!(
            CheckpointTrustPolicy::new(ChainId::new(NETWORK), 1, vec![public, public]).is_err()
        );
        assert!(CheckpointTrustPolicy::new(ChainId::new([0; 32]), 1, vec![public]).is_err());

        let finalized_header = header([0x77; 32]);
        let draft = CheckpointDistributionDraft::new(
            &finalized_header,
            &NoteCommitmentTree::new().snapshot(),
        )
        .unwrap();
        let signature = CheckpointPublisherSignature::new(
            checkpoint_publisher_id(public),
            key.sign(draft.signing_bytes()).to_bytes(),
        );
        assert_eq!(
            draft.assemble(vec![signature, signature]).unwrap_err(),
            CheckpointDistributionError::AuthenticationFailed
        );
    }

    #[test]
    fn target_distribution_is_distinct_and_requires_the_exact_finalized_target() {
        let keys = [
            SigningKey::from_bytes(&[8; 32]),
            SigningKey::from_bytes(&[9; 32]),
            SigningKey::from_bytes(&[10; 32]),
        ];
        let policy = CheckpointTrustPolicy::new(
            ChainId::new(NETWORK),
            2,
            keys.iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
        )
        .unwrap();
        let finalized_target = header_at(200, [0x81; 32]);
        let draft = RecoveryTargetDistributionDraft::new(&finalized_target);
        let signed = signatures(draft.signing_bytes(), &keys[..2]);
        let package = draft.assemble(signed).unwrap();
        assert_eq!(package.len(), 313);
        let authenticated =
            verify_recovery_target_distribution(&package, &policy, &finalized_target).unwrap();
        assert_eq!(authenticated.height(), 200);

        let birthday_header = header_at(100, [0x80; 32]);
        let birthday_package = signed_package(&birthday_header, &keys[..2]);
        let birthday =
            verify_birthday_checkpoint_distribution(&birthday_package, &policy, &birthday_header)
                .unwrap();
        let seed = WalletSeedMaterial::from_custodian_entropy(Zeroizing::new([0x91; 32])).unwrap();
        let accounts = WalletRecoveryAccounts::derive(&seed, ChainId::new(NETWORK), 3).unwrap();
        let plan = WalletRecoveryPlan::new_with_authenticated_target(
            birthday,
            &authenticated,
            &accounts,
            2,
        )
        .unwrap();
        assert_eq!(plan.target_height(), 200);

        for index in 0..package.len() {
            let mut mutated = package.clone();
            mutated[index] ^= 1;
            assert!(
                verify_recovery_target_distribution(&mutated, &policy, &finalized_target).is_err(),
                "target mutation at byte {index} was accepted"
            );
        }
        assert_eq!(
            verify_recovery_target_distribution(&package, &policy, &header_at(200, [0x82; 32]))
                .unwrap_err(),
            CheckpointDistributionError::FinalizedHeaderMismatch
        );
    }

    #[test]
    fn successor_policy_revokes_removed_publishers_and_rejects_rollback() {
        let old_only = SigningKey::from_bytes(&[11; 32]);
        let retained = SigningKey::from_bytes(&[12; 32]);
        let added = SigningKey::from_bytes(&[13; 32]);
        let old_policy = CheckpointTrustPolicy::new(
            ChainId::new(NETWORK),
            2,
            vec![
                old_only.verifying_key().to_bytes(),
                retained.verifying_key().to_bytes(),
            ],
        )
        .unwrap();
        let new_policy = old_policy
            .rotated(
                2,
                2,
                vec![
                    retained.verifying_key().to_bytes(),
                    added.verifying_key().to_bytes(),
                ],
            )
            .unwrap();
        assert_eq!(new_policy.generation(), 2);
        assert!(
            old_policy
                .rotated(
                    1,
                    2,
                    vec![
                        retained.verifying_key().to_bytes(),
                        added.verifying_key().to_bytes(),
                    ],
                )
                .is_err()
        );

        let finalized_target = header_at(300, [0x83; 32]);
        let old_draft = RecoveryTargetDistributionDraft::new(&finalized_target);
        let old_signatures = signatures(old_draft.signing_bytes(), &[old_only, retained.clone()]);
        let old_package = old_draft.assemble(old_signatures).unwrap();
        assert!(
            verify_recovery_target_distribution(&old_package, &new_policy, &finalized_target)
                .is_err()
        );

        let new_draft = RecoveryTargetDistributionDraft::new(&finalized_target);
        let new_signatures = signatures(new_draft.signing_bytes(), &[retained, added]);
        let new_package = new_draft.assemble(new_signatures).unwrap();
        verify_recovery_target_distribution(&new_package, &new_policy, &finalized_target).unwrap();
    }

    #[test]
    fn authenticated_policy_update_binds_exact_predecessor_and_every_byte() {
        const EXPECTED_UPDATE_HASH: [u8; 32] = [
            0x68, 0x75, 0x55, 0xc0, 0x94, 0x69, 0xa2, 0x35, 0xa1, 0xb4, 0x8f, 0x08, 0x29, 0x3b,
            0xf3, 0x18, 0xe3, 0x9c, 0xb5, 0x68, 0x73, 0x39, 0x98, 0xd8, 0xe4, 0x59, 0x98, 0x37,
            0xb3, 0x32, 0xa6, 0x66,
        ];
        let old_keys = [
            SigningKey::from_bytes(&[21; 32]),
            SigningKey::from_bytes(&[22; 32]),
            SigningKey::from_bytes(&[23; 32]),
        ];
        let current = CheckpointTrustPolicy::new(
            ChainId::new(NETWORK),
            2,
            old_keys
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
        )
        .unwrap();
        let next_keys = [
            SigningKey::from_bytes(&[22; 32]),
            SigningKey::from_bytes(&[24; 32]),
            SigningKey::from_bytes(&[25; 32]),
        ];
        let draft = CheckpointPolicyUpdateDraft::new(
            &current,
            2,
            2,
            next_keys
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
        )
        .unwrap();
        let signed = signatures(draft.signing_bytes(), &old_keys[..2]);
        let package = draft.assemble(signed).unwrap();
        assert_eq!(package.len(), 379);
        assert_eq!(blake3::hash(&package).as_bytes(), &EXPECTED_UPDATE_HASH);
        let successor = verify_checkpoint_policy_update(&package, &current).unwrap();
        assert_eq!(successor.generation(), 2);
        assert_ne!(successor.policy_id(), current.policy_id());

        let wrong_predecessor = CheckpointTrustPolicy::new(
            ChainId::new(NETWORK),
            2,
            vec![
                old_keys[0].verifying_key().to_bytes(),
                old_keys[2].verifying_key().to_bytes(),
            ],
        )
        .unwrap();
        assert_eq!(
            verify_checkpoint_policy_update(&package, &wrong_predecessor).unwrap_err(),
            CheckpointDistributionError::PolicyPredecessorMismatch
        );

        for index in 0..package.len() {
            let mut mutated = package.clone();
            mutated[index] ^= 1;
            assert!(
                verify_checkpoint_policy_update(&mutated, &current).is_err(),
                "policy mutation at byte {index} was accepted"
            );
        }
        for length in 0..package.len() {
            assert!(verify_checkpoint_policy_update(&package[..length], &current).is_err());
        }
        let mut trailing = package;
        trailing.push(0);
        assert!(verify_checkpoint_policy_update(&trailing, &current).is_err());
    }
}
