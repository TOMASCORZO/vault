use std::{
    collections::HashMap,
    fmt,
    io::{self, Read, Write},
};

use pasta_curves::{
    group::{Group, GroupEncoding},
    pallas,
};

#[cfg(test)]
use super::DECRYPTION_SHARE_DOMAIN;
use super::{
    AggregatedBurnCiphertext, BURN_ENCRYPTION_SCHEME_ID, BurnCiphertext, BurnDecryptionShare,
    BurnEncryptionError, EpochBurnPublicKey, RecoveredBurnMessage, burn_message_generator,
    parse_ciphertext_point, recover_aggregate_message,
};

const AGGREGATE_ID_DOMAIN: &str = "vault.burn.pallas-threshold-elgamal-v1.aggregate.v1";
#[cfg(test)]
const AGGREGATION_POLICY_ID_DOMAIN: &str = "vault.burn.aggregate-policy.v1";
const RECOVERY_CACHE_DIGEST_DOMAIN: &str = "vault.burn.bsgs-recovery-cache.v1";
const RECOVERY_CACHE_MAGIC: [u8; 4] = *b"VBRC";
const RECOVERY_CACHE_TRAILER_MAGIC: [u8; 4] = *b"VBRE";
const RECOVERY_CACHE_VERSION: u16 = 1;
const RECOVERY_CACHE_HEADER_BYTES: usize = 104;
const RECOVERY_CACHE_RECORD_BYTES: usize = 32;
const RECOVERY_CACHE_TRAILER_BYTES: usize = 4 + 32;

/// Minimum number of distinct transfer effects required before aggregate
/// decryption shares may be produced.
pub const MIN_BURN_AGGREGATE_CONTRIBUTIONS: usize = 128;
/// Minimum number of public settlement windows spanned by an openable aggregate.
pub const MIN_BURN_AGGREGATE_WINDOWS: u64 = 16;
/// Defensive memory and state bound for one aggregate.
pub const MAX_BURN_AGGREGATE_CONTRIBUTIONS: usize = 65_536;
/// Maximum possible epoch burn under the frozen 21 million VLT supply cap.
pub const MAX_EPOCH_BURN_ATOMIC: u64 = 21_000_000 * 1_000_000_000;
/// Frozen identity of the H1-C4 aggregate formation and opening policy.
pub const BURN_AGGREGATION_POLICY_ID: [u8; 32] = [
    0x70, 0xbc, 0x5d, 0x1f, 0x3f, 0x22, 0xbd, 0xa5, 0xc0, 0xc6, 0xc2, 0xe5, 0x58, 0xd5, 0x54, 0xe3,
    0x18, 0x7d, 0xd1, 0x44, 0xe2, 0xbb, 0x10, 0x51, 0x69, 0x9d, 0x57, 0x23, 0xd5, 0x42, 0xa6, 0xe3,
];

/// Exact identity later activation must use for this aggregate policy.
#[must_use]
pub const fn burn_aggregation_policy_id() -> [u8; 32] {
    BURN_AGGREGATION_POLICY_ID
}

/// Canonical recovery-cache construction or loading failure.
#[derive(Debug)]
pub enum BurnRecoveryCacheError {
    /// The selected recovery bound or its in-memory table is invalid.
    Recovery(BurnEncryptionError),
    /// The cache stream could not be read or written.
    Io(io::Error),
    /// Header, record count, trailer, or exact stream length is invalid.
    InvalidFormat,
    /// The cache does not match its embedded and caller-trusted digest.
    DigestMismatch,
}

impl fmt::Display for BurnRecoveryCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recovery(error) => write!(formatter, "burn recovery cache: {error}"),
            Self::Io(error) => write!(formatter, "burn recovery cache I/O failed: {error}"),
            Self::InvalidFormat => formatter.write_str("invalid burn recovery cache format"),
            Self::DigestMismatch => formatter.write_str("burn recovery cache digest mismatch"),
        }
    }
}

impl std::error::Error for BurnRecoveryCacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Recovery(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::InvalidFormat | Self::DigestMismatch => None,
        }
    }
}

impl From<BurnEncryptionError> for BurnRecoveryCacheError {
    fn from(error: BurnEncryptionError) -> Self {
        Self::Recovery(error)
    }
}

impl From<io::Error> for BurnRecoveryCacheError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// One finalized transfer effect admitted to an epoch burn aggregate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BurnAggregateContribution {
    effect_id: [u8; 32],
    settlement_window: u64,
    epoch: u64,
    key_id: [u8; 32],
    ciphertext: BurnCiphertext,
}

impl BurnAggregateContribution {
    /// Binds a validated transfer effect and ciphertext to the exact epoch key.
    pub fn new(
        effect_id: [u8; 32],
        settlement_window: u64,
        epoch_key: &EpochBurnPublicKey,
        ciphertext: BurnCiphertext,
    ) -> Result<Self, BurnEncryptionError> {
        if effect_id == [0; 32] {
            return Err(BurnEncryptionError::InvalidAggregateContribution);
        }
        Ok(Self {
            effect_id,
            settlement_window,
            epoch: epoch_key.epoch(),
            key_id: epoch_key.key_id(),
            ciphertext,
        })
    }

    /// Canonical transaction-effects identity used for ordering and deduplication.
    #[must_use]
    pub const fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// Public settlement-window identifier supplied by the later consensus layer.
    #[must_use]
    pub const fn settlement_window(&self) -> u64 {
        self.settlement_window
    }

    /// Epoch key identity inherited from the validated transfer effect.
    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    /// Exact validated burn ciphertext.
    #[must_use]
    pub const fn ciphertext(&self) -> BurnCiphertext {
        self.ciphertext
    }
}

/// Outcome of closing one public settlement window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BurnAggregateReadiness {
    /// Privacy floors are not met; retain the same key and aggregate unchanged.
    CarryForward,
    /// The aggregate is now eligible for threshold decryption shares.
    Ready,
}

/// Canonically ordered burn aggregate that cannot be decrypted directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochBurnAggregate {
    epoch: u64,
    key_id: [u8; 32],
    first_window: u64,
    closed_through: Option<u64>,
    ready: bool,
    contributions: Vec<BurnAggregateContribution>,
}

impl EpochBurnAggregate {
    /// Starts an empty aggregate under one exact epoch key.
    #[must_use]
    pub fn new(epoch_key: &EpochBurnPublicKey, first_window: u64) -> Self {
        Self {
            epoch: epoch_key.epoch(),
            key_id: epoch_key.key_id(),
            first_window,
            closed_through: None,
            ready: false,
            contributions: Vec::new(),
        }
    }

    /// Atomically appends contributions, sorts by effects ID, and rejects any
    /// duplicate, stale window, wrong key, or capacity overflow.
    pub fn append(
        &mut self,
        contributions: &[BurnAggregateContribution],
    ) -> Result<(), BurnEncryptionError> {
        if self.ready || contributions.is_empty() {
            return Err(BurnEncryptionError::InvalidAggregateContribution);
        }
        let Some(total) = self.contributions.len().checked_add(contributions.len()) else {
            return Err(BurnEncryptionError::AggregateCapacityExceeded);
        };
        if total > MAX_BURN_AGGREGATE_CONTRIBUTIONS {
            return Err(BurnEncryptionError::AggregateCapacityExceeded);
        }

        if contributions.iter().any(|contribution| {
            contribution.effect_id == [0; 32]
                || contribution.epoch != self.epoch
                || contribution.key_id != self.key_id
                || contribution.settlement_window < self.first_window
                || self
                    .closed_through
                    .is_some_and(|closed| contribution.settlement_window <= closed)
        }) {
            return Err(BurnEncryptionError::InvalidAggregateContribution);
        }

        let mut combined = self.contributions.clone();
        combined.extend_from_slice(contributions);
        combined.sort_unstable_by_key(BurnAggregateContribution::effect_id);
        if combined
            .windows(2)
            .any(|pair| pair[0].effect_id == pair[1].effect_id)
        {
            return Err(BurnEncryptionError::InvalidAggregateContribution);
        }
        self.contributions = combined;
        Ok(())
    }

    /// Closes a monotonically increasing public window. Reaching a timeout
    /// never overrides either privacy floor: a low-volume aggregate is carried
    /// forward under the same key and remains impossible to open through this
    /// API.
    pub fn close_through(
        &mut self,
        settlement_window: u64,
    ) -> Result<BurnAggregateReadiness, BurnEncryptionError> {
        if self.ready
            || settlement_window < self.first_window
            || self
                .closed_through
                .is_some_and(|closed| settlement_window <= closed)
            || self
                .contributions
                .iter()
                .any(|contribution| contribution.settlement_window > settlement_window)
        {
            return Err(BurnEncryptionError::InvalidSettlementWindow);
        }

        self.closed_through = Some(settlement_window);
        let window_span = u128::from(settlement_window) - u128::from(self.first_window) + 1;
        self.ready = self.contributions.len() >= MIN_BURN_AGGREGATE_CONTRIBUTIONS
            && window_span >= u128::from(MIN_BURN_AGGREGATE_WINDOWS);
        Ok(if self.ready {
            BurnAggregateReadiness::Ready
        } else {
            BurnAggregateReadiness::CarryForward
        })
    }

    /// Converts only a policy-eligible aggregate into the type accepted by
    /// decryption-share and recovery APIs.
    pub fn into_openable(self) -> Result<OpenableBurnAggregate, BurnEncryptionError> {
        if !self.ready {
            return Err(BurnEncryptionError::AggregateNotOpenable);
        }
        OpenableBurnAggregate::from_closed(self)
    }

    /// Number of unique finalized transfer effects accumulated so far.
    #[must_use]
    pub fn contribution_count(&self) -> usize {
        self.contributions.len()
    }

    /// Most recent closed settlement window, if any.
    #[must_use]
    pub const fn closed_through(&self) -> Option<u64> {
        self.closed_through
    }
}

/// Aggregate that passed both public privacy floors and may receive shares.
#[derive(Clone, Eq, PartialEq)]
pub struct OpenableBurnAggregate {
    epoch: u64,
    key_id: [u8; 32],
    first_window: u64,
    closed_through: u64,
    aggregate_id: [u8; 32],
    ciphertext: AggregatedBurnCiphertext,
    contributions: Vec<BurnAggregateContribution>,
}

impl fmt::Debug for OpenableBurnAggregate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenableBurnAggregate")
            .field("epoch", &self.epoch)
            .field("first_window", &self.first_window)
            .field("closed_through", &self.closed_through)
            .field("contributions", &self.contributions.len())
            .finish_non_exhaustive()
    }
}

impl OpenableBurnAggregate {
    fn from_closed(aggregate: EpochBurnAggregate) -> Result<Self, BurnEncryptionError> {
        let closed_through = aggregate
            .closed_through
            .ok_or(BurnEncryptionError::AggregateNotOpenable)?;
        let ciphertexts = aggregate
            .contributions
            .iter()
            .map(BurnAggregateContribution::ciphertext)
            .collect::<Vec<_>>();
        let ciphertext = AggregatedBurnCiphertext::aggregate(&ciphertexts)?;
        let aggregate_id = derive_aggregate_id(
            aggregate.epoch,
            aggregate.key_id,
            aggregate.first_window,
            closed_through,
            &aggregate.contributions,
            ciphertext,
        );
        Ok(Self {
            epoch: aggregate.epoch,
            key_id: aggregate.key_id,
            first_window: aggregate.first_window,
            closed_through,
            aggregate_id,
            ciphertext,
            contributions: aggregate.contributions,
        })
    }

    /// Epoch whose DKG key encrypts every contribution.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Exact DKG descriptor identity shared by every contribution.
    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    /// Domain-separated identity of membership, windows, and ciphertext sum.
    #[must_use]
    pub const fn aggregate_id(&self) -> [u8; 32] {
        self.aggregate_id
    }

    /// Number of unique effects protected by this aggregate.
    #[must_use]
    pub fn contribution_count(&self) -> usize {
        self.contributions.len()
    }

    /// Canonical contribution order used by the aggregate identity.
    #[must_use]
    pub fn contributions(&self) -> &[BurnAggregateContribution] {
        &self.contributions
    }

    /// Exact homomorphic ciphertext sum.
    #[must_use]
    pub const fn ciphertext_bytes(&self) -> [u8; 64] {
        self.ciphertext.to_bytes()
    }

    pub(crate) const fn ciphertext(&self) -> AggregatedBurnCiphertext {
        self.ciphertext
    }
}

/// Deterministic baby-step/giant-step table for an explicit inclusive bound.
///
/// Construction uses `ceil(sqrt(maximum + 1))` stored points and recovery uses
/// at most the same number of giant steps. H1-A1 must benchmark and approve the
/// full [`MAX_EPOCH_BURN_ATOMIC`] table before activation.
pub struct BoundedBurnRecovery {
    maximum: u64,
    step_size: u64,
    baby_steps: HashMap<[u8; 32], u64>,
    giant_stride: pallas::Point,
}

impl fmt::Debug for BoundedBurnRecovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedBurnRecovery")
            .field("maximum", &self.maximum)
            .field("step_size", &self.step_size)
            .finish_non_exhaustive()
    }
}

impl BoundedBurnRecovery {
    /// Precomputes the deterministic recovery table for `0..=maximum`.
    pub fn new(maximum: u64) -> Result<Self, BurnEncryptionError> {
        let (step_size, mut baby_steps) = empty_recovery_table(maximum)?;

        let generator = burn_message_generator();
        let mut point = pallas::Point::identity();
        for index in 0..step_size {
            baby_steps.insert(point.to_bytes(), index);
            point += generator;
        }
        Ok(Self {
            maximum,
            step_size,
            baby_steps,
            giant_stride: generator * pallas::Scalar::from(step_size),
        })
    }

    /// Builds the exact in-memory table while writing its canonical cache.
    ///
    /// Cache records are compressed baby-step points in increasing implicit
    /// index order. The returned digest must be retained in trusted activation
    /// configuration and supplied to [`Self::from_canonical_cache`]. A partial
    /// stream after any error must be discarded by the caller.
    pub fn build_with_canonical_cache<W: Write>(
        maximum: u64,
        mut writer: W,
    ) -> Result<(Self, [u8; 32]), BurnRecoveryCacheError> {
        let (step_size, mut baby_steps) = empty_recovery_table(maximum)?;
        let header = recovery_cache_header(maximum, step_size);
        let mut hasher = blake3::Hasher::new_derive_key(RECOVERY_CACHE_DIGEST_DOMAIN);
        writer.write_all(&header)?;
        hasher.update(&header);

        let generator = burn_message_generator();
        let mut point = pallas::Point::identity();
        for index in 0..step_size {
            let point_bytes = point.to_bytes();
            writer.write_all(&point_bytes)?;
            hasher.update(&point_bytes);
            if baby_steps.insert(point_bytes, index).is_some() {
                return Err(BurnRecoveryCacheError::InvalidFormat);
            }
            point += generator;
        }
        let digest = *hasher.finalize().as_bytes();
        writer.write_all(&RECOVERY_CACHE_TRAILER_MAGIC)?;
        writer.write_all(&digest)?;

        Ok((
            Self {
                maximum,
                step_size,
                baby_steps,
                giant_stride: generator * pallas::Scalar::from(step_size),
            },
            digest,
        ))
    }

    /// Reconstructs the in-memory table from one exact trusted cache artifact.
    ///
    /// The expected digest is deliberately supplied out of band: an embedded
    /// digest alone would detect accidental corruption but would not
    /// authenticate a maliciously replaced cache. No proof or recovery is
    /// accepted from a cache whose complete header and payload differ.
    pub fn from_canonical_cache<R: Read>(
        maximum: u64,
        expected_digest: [u8; 32],
        mut reader: R,
    ) -> Result<Self, BurnRecoveryCacheError> {
        if expected_digest == [0; 32] {
            return Err(BurnRecoveryCacheError::DigestMismatch);
        }
        let (step_size, mut baby_steps) = empty_recovery_table(maximum)?;
        let expected_header = recovery_cache_header(maximum, step_size);
        let mut header = [0_u8; RECOVERY_CACHE_HEADER_BYTES];
        reader.read_exact(&mut header)?;
        if header != expected_header {
            return Err(BurnRecoveryCacheError::InvalidFormat);
        }

        let mut hasher = blake3::Hasher::new_derive_key(RECOVERY_CACHE_DIGEST_DOMAIN);
        hasher.update(&header);
        for index in 0..step_size {
            let mut point_bytes = [0_u8; RECOVERY_CACHE_RECORD_BYTES];
            reader.read_exact(&mut point_bytes)?;
            hasher.update(&point_bytes);
            if baby_steps.insert(point_bytes, index).is_some() {
                return Err(BurnRecoveryCacheError::InvalidFormat);
            }
        }

        let mut trailer_magic = [0_u8; 4];
        let mut embedded_digest = [0_u8; 32];
        reader.read_exact(&mut trailer_magic)?;
        reader.read_exact(&mut embedded_digest)?;
        let computed_digest = *hasher.finalize().as_bytes();
        if trailer_magic != RECOVERY_CACHE_TRAILER_MAGIC
            || embedded_digest != computed_digest
            || expected_digest != computed_digest
        {
            return Err(BurnRecoveryCacheError::DigestMismatch);
        }
        let mut trailing = [0_u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(BurnRecoveryCacheError::InvalidFormat);
        }

        let generator = burn_message_generator();
        Ok(Self {
            maximum,
            step_size,
            baby_steps,
            giant_stride: generator * pallas::Scalar::from(step_size),
        })
    }

    /// Exact canonical cache length for this bounded table.
    pub fn canonical_cache_len(&self) -> Result<u64, BurnRecoveryCacheError> {
        recovery_cache_len(self.step_size)
    }

    /// Inclusive integer bound covered by this exact table.
    #[must_use]
    pub const fn maximum(&self) -> u64 {
        self.maximum
    }

    /// Exact number of stored baby steps and maximum giant steps.
    #[must_use]
    pub const fn step_size(&self) -> u64 {
        self.step_size
    }

    /// Recovers a deterministic known message for isolated resource tooling.
    ///
    /// This entry point is available only with the non-default
    /// `reference-oracle` feature. It does not accept ciphertexts, shares, or
    /// aggregates and cannot enter the production decryption boundary.
    #[cfg(feature = "reference-oracle")]
    #[doc(hidden)]
    pub fn recover_known_amount_for_benchmark(
        &self,
        amount: u64,
    ) -> Result<u64, BurnEncryptionError> {
        if amount > self.maximum {
            return Err(BurnEncryptionError::AggregateBurnOutOfRange);
        }
        let message = RecoveredBurnMessage(
            (burn_message_generator() * pallas::Scalar::from(amount)).to_bytes(),
        );
        self.recover(message)
    }

    pub(crate) fn recover(
        &self,
        message: RecoveredBurnMessage,
    ) -> Result<u64, BurnEncryptionError> {
        let mut giant = parse_ciphertext_point(&message.to_bytes())?;
        for giant_index in 0..self.step_size {
            if let Some(baby_index) = self.baby_steps.get(&giant.to_bytes()) {
                let candidate =
                    u128::from(giant_index) * u128::from(self.step_size) + u128::from(*baby_index);
                if candidate <= u128::from(self.maximum) {
                    let candidate = u64::try_from(candidate)
                        .map_err(|_| BurnEncryptionError::AggregateBurnOutOfRange)?;
                    if message.matches_amount(candidate) {
                        return Ok(candidate);
                    }
                }
            }
            giant -= self.giant_stride;
        }
        Err(BurnEncryptionError::AggregateBurnOutOfRange)
    }
}

fn empty_recovery_table(
    maximum: u64,
) -> Result<(u64, HashMap<[u8; 32], u64>), BurnEncryptionError> {
    if maximum > MAX_EPOCH_BURN_ATOMIC {
        return Err(BurnEncryptionError::RecoveryBoundOutOfRange);
    }
    let search_size = maximum
        .checked_add(1)
        .ok_or(BurnEncryptionError::RecoveryBoundOutOfRange)?;
    let step_size = ceil_sqrt(search_size);
    let capacity = usize::try_from(step_size)
        .map_err(|_| BurnEncryptionError::RecoveryResourcesUnavailable)?;
    let mut baby_steps = HashMap::new();
    baby_steps
        .try_reserve(capacity)
        .map_err(|_| BurnEncryptionError::RecoveryResourcesUnavailable)?;
    Ok((step_size, baby_steps))
}

fn recovery_cache_header(maximum: u64, step_size: u64) -> [u8; RECOVERY_CACHE_HEADER_BYTES] {
    let mut header = [0_u8; RECOVERY_CACHE_HEADER_BYTES];
    header[0..4].copy_from_slice(&RECOVERY_CACHE_MAGIC);
    header[4..6].copy_from_slice(&RECOVERY_CACHE_VERSION.to_le_bytes());
    header[6..8].copy_from_slice(
        &u16::try_from(RECOVERY_CACHE_HEADER_BYTES)
            .expect("fixed cache header length fits u16")
            .to_le_bytes(),
    );
    header[8..40].copy_from_slice(&BURN_ENCRYPTION_SCHEME_ID);
    header[40..72].copy_from_slice(&BURN_AGGREGATION_POLICY_ID);
    header[72..80].copy_from_slice(&maximum.to_le_bytes());
    header[80..88].copy_from_slice(&step_size.to_le_bytes());
    header[88..96].copy_from_slice(&step_size.to_le_bytes());
    header[96..98].copy_from_slice(
        &u16::try_from(RECOVERY_CACHE_RECORD_BYTES)
            .expect("fixed cache record length fits u16")
            .to_le_bytes(),
    );
    header
}

fn recovery_cache_len(step_size: u64) -> Result<u64, BurnRecoveryCacheError> {
    let payload = step_size
        .checked_mul(u64::try_from(RECOVERY_CACHE_RECORD_BYTES).unwrap())
        .ok_or(BurnRecoveryCacheError::InvalidFormat)?;
    u64::try_from(RECOVERY_CACHE_HEADER_BYTES)
        .unwrap()
        .checked_add(payload)
        .and_then(|length| length.checked_add(u64::try_from(RECOVERY_CACHE_TRAILER_BYTES).unwrap()))
        .ok_or(BurnRecoveryCacheError::InvalidFormat)
}

/// Verifies threshold shares for one policy-eligible aggregate and recovers its
/// exact burn within the supplied explicit bound.
pub fn recover_aggregate_burn(
    epoch_key: &EpochBurnPublicKey,
    aggregate: &OpenableBurnAggregate,
    shares: &[BurnDecryptionShare],
    recovery: &BoundedBurnRecovery,
) -> Result<u64, BurnEncryptionError> {
    let selected = select_valid_decryption_shares(epoch_key, aggregate, shares)?;
    let message = recover_aggregate_message(epoch_key, aggregate, &selected)?;
    recovery.recover(message)
}

fn select_valid_decryption_shares(
    epoch_key: &EpochBurnPublicKey,
    aggregate: &OpenableBurnAggregate,
    shares: &[BurnDecryptionShare],
) -> Result<Vec<BurnDecryptionShare>, BurnEncryptionError> {
    let mut valid = shares
        .iter()
        .copied()
        .filter(|share| share.verify(epoch_key, aggregate))
        .collect::<Vec<_>>();
    valid.sort_unstable_by(|left, right| {
        (left.participant, left.share, left.challenge, left.response).cmp(&(
            right.participant,
            right.share,
            right.challenge,
            right.response,
        ))
    });
    valid.dedup_by_key(|share| share.participant);
    if valid.len() < usize::from(epoch_key.threshold()) {
        return Err(BurnEncryptionError::InvalidDecryptionShareSet);
    }
    valid.truncate(usize::from(epoch_key.threshold()));
    Ok(valid)
}

fn derive_aggregate_id(
    epoch: u64,
    key_id: [u8; 32],
    first_window: u64,
    closed_through: u64,
    contributions: &[BurnAggregateContribution],
    ciphertext: AggregatedBurnCiphertext,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(AGGREGATE_ID_DOMAIN);
    hasher.update(&BURN_ENCRYPTION_SCHEME_ID);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&key_id);
    hasher.update(&first_window.to_le_bytes());
    hasher.update(&closed_through.to_le_bytes());
    hasher.update(&(contributions.len() as u64).to_le_bytes());
    for contribution in contributions {
        hasher.update(&contribution.effect_id);
        hasher.update(&contribution.settlement_window.to_le_bytes());
        hasher.update(&contribution.ciphertext.to_bytes());
    }
    hasher.update(&ciphertext.to_bytes());
    *hasher.finalize().as_bytes()
}

fn ceil_sqrt(value: u64) -> u64 {
    let mut low = 0_u64;
    let mut high = 1_u64 << 32;
    while low < high {
        let middle = low + (high - low) / 2;
        if u128::from(middle) * u128::from(middle) >= u128::from(value) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

#[cfg(test)]
fn derive_aggregation_policy_id() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(AGGREGATION_POLICY_ID_DOMAIN);
    hasher.update(&BURN_ENCRYPTION_SCHEME_ID);
    hasher.update(&(MIN_BURN_AGGREGATE_CONTRIBUTIONS as u64).to_le_bytes());
    hasher.update(&MIN_BURN_AGGREGATE_WINDOWS.to_le_bytes());
    hasher.update(&(MAX_BURN_AGGREGATE_CONTRIBUTIONS as u64).to_le_bytes());
    hasher.update(&MAX_EPOCH_BURN_ATOMIC.to_le_bytes());
    hasher.update(AGGREGATE_ID_DOMAIN.as_bytes());
    hasher.update(DECRYPTION_SHARE_DOMAIN.as_bytes());
    hasher.update(
        b"effect-id-lexicographic;strict-unique;same-epoch-key;close-first-eligible;low-volume-carry-forward;same-key;never-individual-decrypt",
    );
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_bounds_have_exact_square_root_resources() {
        assert_eq!(ceil_sqrt(1), 1);
        assert_eq!(ceil_sqrt(2), 2);
        assert_eq!(ceil_sqrt(4), 2);
        assert_eq!(ceil_sqrt(5), 3);
        assert_eq!(ceil_sqrt(MAX_EPOCH_BURN_ATOMIC + 1), 144_913_768);
        assert_eq!(recovery_cache_len(144_913_768).unwrap(), 4_637_240_716);
        assert_eq!(derive_aggregation_policy_id(), BURN_AGGREGATION_POLICY_ID);
    }

    #[test]
    fn canonical_recovery_cache_is_reproducible_bound_and_fail_closed() {
        let mut first_bytes = Vec::new();
        let (first, digest) =
            BoundedBurnRecovery::build_with_canonical_cache(255, &mut first_bytes).unwrap();
        assert_eq!(first.step_size(), 16);
        assert_eq!(first.canonical_cache_len().unwrap(), 652);
        assert_eq!(u64::try_from(first_bytes.len()).unwrap(), 652);

        let mut second_bytes = Vec::new();
        let (_, second_digest) =
            BoundedBurnRecovery::build_with_canonical_cache(255, &mut second_bytes).unwrap();
        assert_eq!(second_bytes, first_bytes);
        assert_eq!(second_digest, digest);

        let loaded =
            BoundedBurnRecovery::from_canonical_cache(255, digest, first_bytes.as_slice()).unwrap();
        for amount in [0, 1, 15, 16, 254, 255] {
            let message = RecoveredBurnMessage(
                (burn_message_generator() * pallas::Scalar::from(amount)).to_bytes(),
            );
            assert_eq!(loaded.recover(message), Ok(amount));
        }

        assert!(matches!(
            BoundedBurnRecovery::from_canonical_cache(255, [0; 32], first_bytes.as_slice()),
            Err(BurnRecoveryCacheError::DigestMismatch)
        ));
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        assert!(matches!(
            BoundedBurnRecovery::from_canonical_cache(255, wrong_digest, first_bytes.as_slice()),
            Err(BurnRecoveryCacheError::DigestMismatch)
        ));
        assert!(matches!(
            BoundedBurnRecovery::from_canonical_cache(256, digest, first_bytes.as_slice()),
            Err(BurnRecoveryCacheError::InvalidFormat)
        ));

        let mut corrupted_header = first_bytes.clone();
        corrupted_header[8] ^= 1;
        assert!(matches!(
            BoundedBurnRecovery::from_canonical_cache(255, digest, corrupted_header.as_slice()),
            Err(BurnRecoveryCacheError::InvalidFormat)
        ));
        let mut corrupted_payload = first_bytes.clone();
        corrupted_payload[RECOVERY_CACHE_HEADER_BYTES] ^= 1;
        assert!(matches!(
            BoundedBurnRecovery::from_canonical_cache(255, digest, corrupted_payload.as_slice()),
            Err(BurnRecoveryCacheError::DigestMismatch)
        ));
        let mut corrupted_trailer = first_bytes.clone();
        let final_byte = corrupted_trailer.len() - 1;
        corrupted_trailer[final_byte] ^= 1;
        assert!(matches!(
            BoundedBurnRecovery::from_canonical_cache(255, digest, corrupted_trailer.as_slice()),
            Err(BurnRecoveryCacheError::DigestMismatch)
        ));
        let mut extended = first_bytes.clone();
        extended.push(0);
        assert!(matches!(
            BoundedBurnRecovery::from_canonical_cache(255, digest, extended.as_slice()),
            Err(BurnRecoveryCacheError::InvalidFormat)
        ));
        assert!(matches!(
            BoundedBurnRecovery::from_canonical_cache(
                255,
                digest,
                &first_bytes[..first_bytes.len() - 1]
            ),
            Err(BurnRecoveryCacheError::Io(error))
                if error.kind() == io::ErrorKind::UnexpectedEof
        ));
    }
}
