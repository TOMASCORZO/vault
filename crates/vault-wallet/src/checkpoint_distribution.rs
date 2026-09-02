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
const CHECKPOINT_PUBLISHER_ID_DOMAIN: &str = "vault.wallet.checkpoint-publisher-id-v1.2026-09-02";
const MAX_FRONTIER_OMMERS: usize = 32;
const FIXED_SIGNING_BYTES: usize = 8 + 32 + 8 + 32 + 8 + 32 + 1 + 32 + 1;
const SIGNATURE_RECORD_BYTES: usize = 32 + 64;
const MAX_CHECKPOINT_DISTRIBUTION_BYTES: usize = FIXED_SIGNING_BYTES
    + MAX_FRONTIER_OMMERS * 32
    + 1
    + MAX_CHECKPOINT_PUBLISHERS * SIGNATURE_RECORD_BYTES;

/// Maximum independent publisher keys in one checkpoint trust policy.
pub const MAX_CHECKPOINT_PUBLISHERS: usize = 8;

/// Fail-closed checkpoint distribution validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointDistributionError {
    /// Framing, counts, canonical fields, or frontier data are invalid.
    InvalidEncoding,
    /// The package or policy belongs to another network.
    WrongNetwork,
    /// Publisher keys or the required threshold are invalid.
    InvalidPolicy,
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
            Self::AuthenticationFailed => "checkpoint publisher authentication failed",
            Self::FinalizedHeaderMismatch => {
                "checkpoint does not match the independently finalized header"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CheckpointDistributionError {}

struct TrustedPublisher {
    id: [u8; 32],
    key: VerifyingKey,
}

/// Separately configured publisher keys and threshold for one Vault network.
pub struct CheckpointTrustPolicy {
    chain_id: ChainId,
    threshold: usize,
    publishers: Vec<TrustedPublisher>,
}

impl fmt::Debug for CheckpointTrustPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointTrustPolicy")
            .field("chain_id", &self.chain_id)
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
        if chain_id.is_zero()
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
            threshold,
            publishers,
        })
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
        let mut package = self.signing_bytes;
        package.push(
            u8::try_from(signatures.len())
                .map_err(|_| CheckpointDistributionError::InvalidEncoding)?,
        );
        for signature in signatures {
            package.extend_from_slice(&signature.publisher_id);
            package.extend_from_slice(&signature.signature);
        }
        Ok(package)
    }
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

    use super::*;

    const NETWORK: [u8; 32] = [0x71; 32];

    fn header(block_hash: [u8; 32]) -> FinalizedCompactBlockHeader {
        let empty_root = NoteCommitmentTree::new().typed_root();
        FinalizedCompactBlockHeader::from_verified_consensus(
            ChainId::new(NETWORK),
            100,
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

    fn signed_package(
        header: &FinalizedCompactBlockHeader,
        signing_keys: &[SigningKey],
    ) -> Vec<u8> {
        let draft = CheckpointDistributionDraft::new(header, &NoteCommitmentTree::new().snapshot())
            .unwrap();
        let signatures = signing_keys
            .iter()
            .map(|key| {
                CheckpointPublisherSignature::new(
                    checkpoint_publisher_id(key.verifying_key().to_bytes()),
                    key.sign(draft.signing_bytes()).to_bytes(),
                )
            })
            .collect();
        draft.assemble(signatures).unwrap()
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
}
