//! Bounded, restart-safe orchestration for deterministic seed recovery.
//!
//! This module authenticates hostile compact-block bytes against headers that
//! an external consensus adapter has already verified as finalized. The trait
//! boundary does not turn an RPC response into finality; production adapters
//! must be backed by a validating full node or reviewed light client.

use core::fmt;

use vault_protocol::{
    CompactBlock, CompactBlockError, FinalizedCompactBlockHeader, MAX_COMPACT_BLOCK_BYTES,
};

use crate::{
    EncryptedWalletDb, FinalizedWalletStore, ScanCommitError, WalletDbError,
    WalletRecoveryAccounts, WalletRecoveryStatus, WalletScanError, scan_and_commit,
};

/// Maximum finalized blocks committed by one coordinator invocation.
///
/// Each block remains its own durable transaction, so interruption after any
/// confirmed commit can resume at the next height. Callers should choose a
/// smaller scheduling quantum when they need responsive cancellation.
pub const MAX_RECOVERY_BLOCKS_PER_ADVANCE: usize = 4_096;

/// Consensus-finalized header and untrusted compact-block retrieval boundary.
///
/// `finalized_header` MUST return a header only after consensus validation and
/// finality verification by a full-node or light-client adapter. Agreement
/// between ordinary RPC providers is not sufficient. Compact bytes remain
/// hostile and are independently decoded and authenticated by the coordinator.
pub trait FinalizedRecoverySource {
    /// Transport, availability, or consensus-adapter failure.
    type Error: std::error::Error;

    /// Returns the independently verified finalized header at `height`.
    fn finalized_header(&mut self, height: u64)
    -> Result<FinalizedCompactBlockHeader, Self::Error>;

    /// Returns canonical compact bytes for the exact verified header.
    ///
    /// Implementations MUST enforce `maximum_bytes` while reading the response,
    /// before allocating or buffering beyond that limit. The coordinator checks
    /// the returned length again and never trusts provider-side enforcement.
    fn compact_block_bytes(
        &mut self,
        header: &FinalizedCompactBlockHeader,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Classified coordinator failure. Inner source errors remain available to a
/// caller but default diagnostics never render their potentially sensitive text.
pub enum WalletRecoveryCoordinatorFailure<SourceError> {
    /// Requested work quantum was zero or exceeded its production bound.
    InvalidBlockLimit,
    /// The database is a normal genesis wallet, not a seed-recovery database.
    NotSeedRecovery,
    /// Derived accounts do not match the exact encrypted recovery plan.
    AccountSetMismatch,
    /// Header or compact bytes could not be retrieved.
    Source(SourceError),
    /// The asserted finalized header did not extend the requested wallet chain.
    HeaderMismatch,
    /// Compact bytes were malformed, oversized, or did not match the header.
    CompactBlock(CompactBlockError),
    /// Authenticated block scanning failed before storage mutation.
    Scan(WalletScanError),
    /// Durable status loading or the atomic store commit failed.
    Store(WalletDbError),
}

impl<SourceError> fmt::Debug for WalletRecoveryCoordinatorFailure<SourceError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::InvalidBlockLimit => "InvalidBlockLimit",
            Self::NotSeedRecovery => "NotSeedRecovery",
            Self::AccountSetMismatch => "AccountSetMismatch",
            Self::Source(_) => "Source(REDACTED)",
            Self::HeaderMismatch => "HeaderMismatch",
            Self::CompactBlock(_) => "CompactBlock(REDACTED)",
            Self::Scan(_) => "Scan(REDACTED)",
            Self::Store(_) => "Store(REDACTED)",
        };
        formatter.write_str(name)
    }
}

/// Failure plus the number of earlier blocks durably committed by this call.
///
/// The failing block is not included. A `Store(Poisoned)` failure can represent
/// uncertain durability for that final block and requires reopening/validation.
pub struct WalletRecoveryCoordinatorError<SourceError> {
    committed_blocks: usize,
    failure: WalletRecoveryCoordinatorFailure<SourceError>,
}

impl<SourceError> WalletRecoveryCoordinatorError<SourceError> {
    fn new(
        committed_blocks: usize,
        failure: WalletRecoveryCoordinatorFailure<SourceError>,
    ) -> Self {
        Self {
            committed_blocks,
            failure,
        }
    }

    /// Earlier blocks whose commits returned definite success.
    #[must_use]
    pub const fn committed_blocks(&self) -> usize {
        self.committed_blocks
    }

    /// Classified failure with the original typed source/store cause.
    #[must_use]
    pub const fn failure(&self) -> &WalletRecoveryCoordinatorFailure<SourceError> {
        &self.failure
    }
}

impl<SourceError> fmt::Debug for WalletRecoveryCoordinatorError<SourceError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletRecoveryCoordinatorError")
            .field("progress", &"REDACTED")
            .field("failure", &self.failure)
            .finish()
    }
}

impl<SourceError> fmt::Display for WalletRecoveryCoordinatorError<SourceError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("wallet recovery coordinator failed")
    }
}

impl<SourceError: std::error::Error + 'static> std::error::Error
    for WalletRecoveryCoordinatorError<SourceError>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.failure {
            WalletRecoveryCoordinatorFailure::Source(error) => Some(error),
            WalletRecoveryCoordinatorFailure::CompactBlock(error) => Some(error),
            WalletRecoveryCoordinatorFailure::Scan(error) => Some(error),
            WalletRecoveryCoordinatorFailure::Store(error) => Some(error),
            WalletRecoveryCoordinatorFailure::InvalidBlockLimit
            | WalletRecoveryCoordinatorFailure::NotSeedRecovery
            | WalletRecoveryCoordinatorFailure::AccountSetMismatch
            | WalletRecoveryCoordinatorFailure::HeaderMismatch => None,
        }
    }
}

/// Bounded successful advancement result.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WalletRecoveryAdvance {
    committed_blocks: usize,
    last_height: u64,
    status: WalletRecoveryStatus,
}

impl fmt::Debug for WalletRecoveryAdvance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletRecoveryAdvance")
            .field("progress", &"REDACTED")
            .field("wallet_state", &"REDACTED")
            .finish()
    }
}

impl WalletRecoveryAdvance {
    /// Blocks durably committed by this invocation.
    #[must_use]
    pub const fn committed_blocks(self) -> usize {
        self.committed_blocks
    }

    /// Last authenticated finalized height in the database.
    #[must_use]
    pub const fn last_height(self) -> u64 {
        self.last_height
    }

    /// Authenticated recovery phase after the bounded run.
    #[must_use]
    pub const fn status(self) -> WalletRecoveryStatus {
        self.status
    }
}

/// Advances deterministic recovery through at most `maximum_blocks` finalized
/// compact blocks.
///
/// Every height is fetched, decoded, header-authenticated, independently tree
/// replayed, scanned against the exact planned accounts, and committed before
/// the next height is requested. Complete and range-exhausted states are
/// idempotent no-ops. Ordinary genesis wallets are rejected.
pub fn advance_seed_recovery<Source: FinalizedRecoverySource>(
    database: &mut EncryptedWalletDb,
    source: &mut Source,
    accounts: &WalletRecoveryAccounts,
    maximum_blocks: usize,
) -> Result<WalletRecoveryAdvance, WalletRecoveryCoordinatorError<Source::Error>> {
    if maximum_blocks == 0 || maximum_blocks > MAX_RECOVERY_BLOCKS_PER_ADVANCE {
        return Err(WalletRecoveryCoordinatorError::new(
            0,
            WalletRecoveryCoordinatorFailure::InvalidBlockLimit,
        ));
    }

    let mut status = database.recovery_status().map_err(|error| {
        WalletRecoveryCoordinatorError::new(0, WalletRecoveryCoordinatorFailure::Store(error))
    })?;
    match status {
        WalletRecoveryStatus::NotRequired => {
            return Err(WalletRecoveryCoordinatorError::new(
                0,
                WalletRecoveryCoordinatorFailure::NotSeedRecovery,
            ));
        }
        WalletRecoveryStatus::Complete { .. }
        | WalletRecoveryStatus::RequiresLargerAccountRange { .. } => {
            let tip = database.load_tip().map_err(|error| {
                WalletRecoveryCoordinatorError::new(
                    0,
                    WalletRecoveryCoordinatorFailure::Store(error),
                )
            })?;
            return Ok(WalletRecoveryAdvance {
                committed_blocks: 0,
                last_height: tip.height(),
                status,
            });
        }
        WalletRecoveryStatus::InProgress { .. } => {}
    }

    if !database
        .recovery_account_set_matches(accounts.commitment)
        .map_err(|error| {
            WalletRecoveryCoordinatorError::new(0, WalletRecoveryCoordinatorFailure::Store(error))
        })?
    {
        return Err(WalletRecoveryCoordinatorError::new(
            0,
            WalletRecoveryCoordinatorFailure::AccountSetMismatch,
        ));
    }

    let mut committed_blocks = 0usize;
    while committed_blocks < maximum_blocks {
        let (scanned_height, target_height) = match status {
            WalletRecoveryStatus::InProgress {
                scanned_height,
                target_height,
                ..
            } => (scanned_height, target_height),
            WalletRecoveryStatus::Complete { .. }
            | WalletRecoveryStatus::RequiresLargerAccountRange { .. } => break,
            WalletRecoveryStatus::NotRequired => {
                return Err(WalletRecoveryCoordinatorError::new(
                    committed_blocks,
                    WalletRecoveryCoordinatorFailure::Store(WalletDbError::CorruptState),
                ));
            }
        };
        if scanned_height >= target_height {
            return Err(WalletRecoveryCoordinatorError::new(
                committed_blocks,
                WalletRecoveryCoordinatorFailure::Store(WalletDbError::CorruptState),
            ));
        }
        let next_height = scanned_height.checked_add(1).ok_or_else(|| {
            WalletRecoveryCoordinatorError::new(
                committed_blocks,
                WalletRecoveryCoordinatorFailure::Store(WalletDbError::CorruptState),
            )
        })?;
        let tip = database.load_tip().map_err(|error| {
            WalletRecoveryCoordinatorError::new(
                committed_blocks,
                WalletRecoveryCoordinatorFailure::Store(error),
            )
        })?;
        if tip.height() != scanned_height || accounts.chain_id() != tip.chain_id() {
            return Err(WalletRecoveryCoordinatorError::new(
                committed_blocks,
                WalletRecoveryCoordinatorFailure::AccountSetMismatch,
            ));
        }

        let header = source.finalized_header(next_height).map_err(|error| {
            WalletRecoveryCoordinatorError::new(
                committed_blocks,
                WalletRecoveryCoordinatorFailure::Source(error),
            )
        })?;
        if header.height() != next_height || header.chain_id() != tip.chain_id() {
            return Err(WalletRecoveryCoordinatorError::new(
                committed_blocks,
                WalletRecoveryCoordinatorFailure::HeaderMismatch,
            ));
        }
        let bytes = source
            .compact_block_bytes(&header, MAX_COMPACT_BLOCK_BYTES)
            .map_err(|error| {
                WalletRecoveryCoordinatorError::new(
                    committed_blocks,
                    WalletRecoveryCoordinatorFailure::Source(error),
                )
            })?;
        let compact = CompactBlock::decode(&bytes).map_err(|error| {
            WalletRecoveryCoordinatorError::new(
                committed_blocks,
                WalletRecoveryCoordinatorFailure::CompactBlock(error),
            )
        })?;
        let authenticated = compact.authenticate(header).map_err(|error| {
            WalletRecoveryCoordinatorError::new(
                committed_blocks,
                WalletRecoveryCoordinatorFailure::CompactBlock(error),
            )
        })?;
        let scan_accounts = accounts.scan_accounts();
        scan_and_commit(database, &authenticated, &scan_accounts).map_err(|error| {
            let failure = match error {
                ScanCommitError::Scan(error) => WalletRecoveryCoordinatorFailure::Scan(error),
                ScanCommitError::Store(error) => WalletRecoveryCoordinatorFailure::Store(error),
            };
            WalletRecoveryCoordinatorError::new(committed_blocks, failure)
        })?;
        committed_blocks += 1;
        status = database.recovery_status().map_err(|error| {
            WalletRecoveryCoordinatorError::new(
                committed_blocks,
                WalletRecoveryCoordinatorFailure::Store(error),
            )
        })?;
    }

    let tip = database.load_tip().map_err(|error| {
        WalletRecoveryCoordinatorError::new(
            committed_blocks,
            WalletRecoveryCoordinatorFailure::Store(error),
        )
    })?;
    Ok(WalletRecoveryAdvance {
        committed_blocks,
        last_height: tip.height(),
        status,
    })
}
