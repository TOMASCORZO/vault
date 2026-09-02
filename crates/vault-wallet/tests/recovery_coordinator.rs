#![cfg(unix)]

use std::{collections::BTreeMap, fmt, fs, path::PathBuf};

use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use tempfile::TempDir;
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NoteCommitmentTree, PreparedNoteOutput,
    VaultFullViewingKey, VaultSpendingKey,
};
use vault_protocol::{
    ChainId, CompactBlock, CompactBlockAction, CompactBlockTransaction,
    FinalizedCompactBlockHeader, MAX_COMPACT_BLOCK_BYTES, TransactionId,
};
use vault_wallet::{
    EncryptedWalletDb, FinalizedRecoverySource, FinalizedWalletStore,
    MAX_RECOVERY_BLOCKS_PER_ADVANCE, WalletBirthdayCheckpoint, WalletDatabaseConfig,
    WalletRecoveryAccounts, WalletRecoveryCoordinatorFailure, WalletRecoveryPlan,
    WalletRecoveryStatus, WalletScanError, WalletScanTip, WalletSeedMaterial,
    advance_seed_recovery, scan_finalized_block,
};
use zeroize::Zeroizing;

const NETWORK: [u8; 32] = [0x91; 32];
const GENESIS_HASH: [u8; 32] = [0x92; 32];
const WALLET_ID: [u8; 32] = [0x93; 32];
const ROOT_KEY: [u8; 32] = [0x94; 32];
const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;

fn nullifier(byte: u8) -> ActionNullifier {
    ActionNullifier::from_bytes([byte; 32]).unwrap()
}

fn wallet(seed: u8) -> VaultFullViewingKey {
    VaultSpendingKey::derive(&[seed; 32], NETWORK, 0)
        .unwrap()
        .full_viewing_key()
}

fn recovery_seed(byte: u8) -> WalletSeedMaterial {
    WalletSeedMaterial::from_custodian_entropy(Zeroizing::new([byte; 32])).unwrap()
}

fn action(
    owner: &VaultFullViewingKey,
    action_nullifier: ActionNullifier,
    byte: u8,
    rng: &mut ChaCha20Rng,
) -> CompactBlockAction {
    let output = PreparedNoteOutput::create(
        owner,
        KeyScope::External,
        owner.address_at(u32::from(byte), KeyScope::External),
        1_000 + u64::from(byte),
        MAXIMUM_VALUE,
        action_nullifier,
        [byte; MEMO_BYTES],
        rng,
    )
    .unwrap();
    CompactBlockAction::new(action_nullifier, output.encrypted_note().clone())
}

fn block_and_header(
    tip: &WalletScanTip,
    block_hash: [u8; 32],
    transaction_id: [u8; 32],
    mut actions: Vec<CompactBlockAction>,
) -> (CompactBlock, FinalizedCompactBlockHeader) {
    actions.sort_by_key(CompactBlockAction::nullifier);
    let mut post_tree = NoteCommitmentTree::restore(&tip.tree_snapshot()).unwrap();
    for action in &actions {
        post_tree.append(action.output().note_commitment()).unwrap();
    }
    let transaction =
        CompactBlockTransaction::new(TransactionId::new(transaction_id), actions).unwrap();
    let block = CompactBlock::new(
        tip.chain_id(),
        tip.height() + 1,
        block_hash,
        tip.block_hash(),
        tip.tree_size(),
        tip.tree_root(),
        post_tree.size(),
        post_tree.typed_root(),
        vec![transaction],
    )
    .unwrap();
    let header = FinalizedCompactBlockHeader::from_verified_consensus(
        block.chain_id(),
        block.height(),
        block.block_hash(),
        block.parent_hash(),
        block.pre_tree_size(),
        block.pre_tree_root(),
        block.post_tree_size(),
        block.post_tree_root(),
        block.commitment(),
    )
    .unwrap();
    (block, header)
}

fn initial_tip() -> WalletScanTip {
    WalletScanTip::from_verified_checkpoint(
        ChainId::new(NETWORK),
        0,
        GENESIS_HASH,
        &NoteCommitmentTree::new().snapshot(),
    )
    .unwrap()
}

fn config() -> WalletDatabaseConfig {
    WalletDatabaseConfig::new(WALLET_ID, MAXIMUM_VALUE, 100).unwrap()
}

struct RecoveryFixture {
    _temp: TempDir,
    path: PathBuf,
    database: EncryptedWalletDb,
    accounts: WalletRecoveryAccounts,
    second_block: CompactBlock,
    second_header: FinalizedCompactBlockHeader,
    target_block: CompactBlock,
    target_header: FinalizedCompactBlockHeader,
    spend_nullifier: ActionNullifier,
}

fn fixture() -> RecoveryFixture {
    let temp = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .join("coordinator.sqlite3");
    let accounts =
        WalletRecoveryAccounts::derive(&recovery_seed(0xA1), ChainId::new(NETWORK), 3).unwrap();
    let owner = accounts.full_viewing_key(0).unwrap();
    let unrelated = wallet(0xA2);
    let mut rng = ChaCha20Rng::from_seed([0xA3; 32]);
    let genesis_tip = initial_tip();
    let (history_block, history_header) = block_and_header(
        &genesis_tip,
        [0xA4; 32],
        [0xA5; 32],
        vec![
            action(&unrelated, nullifier(1), 1, &mut rng),
            action(&unrelated, nullifier(2), 2, &mut rng),
        ],
    );
    let history_authenticated = history_block.clone().authenticate(history_header).unwrap();
    let history_tip = scan_finalized_block(&genesis_tip, &history_authenticated, &[])
        .unwrap()
        .next_tip()
        .clone();
    let checkpoint = WalletBirthdayCheckpoint::from_finalized_header(
        &history_header,
        &history_tip.tree_snapshot(),
    )
    .unwrap();

    let (second_block, second_header) = block_and_header(
        &history_tip,
        [0xA6; 32],
        [0xA7; 32],
        vec![
            action(owner, nullifier(3), 3, &mut rng),
            action(&unrelated, nullifier(4), 4, &mut rng),
        ],
    );
    let second_authenticated = second_block.clone().authenticate(second_header).unwrap();
    let second_update = scan_finalized_block(
        &history_tip,
        &second_authenticated,
        &accounts.scan_accounts(),
    )
    .unwrap();
    let spend_nullifier = second_update.detected_notes()[0].spend_nullifier();
    let second_tip = second_update.next_tip().clone();

    let (target_block, target_header) = block_and_header(
        &second_tip,
        [0xA8; 32],
        [0xA9; 32],
        vec![
            action(&unrelated, nullifier(5), 5, &mut rng),
            action(&unrelated, nullifier(6), 6, &mut rng),
        ],
    );
    let plan = WalletRecoveryPlan::new(checkpoint, &target_header, &accounts, 2).unwrap();
    let database =
        EncryptedWalletDb::create_from_recovery_plan(&path, &ROOT_KEY, config(), plan).unwrap();
    RecoveryFixture {
        _temp: temp,
        path,
        database,
        accounts,
        second_block,
        second_header,
        target_block,
        target_header,
        spend_nullifier,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScriptedSourceError;

impl fmt::Display for ScriptedSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SENSITIVE SOURCE DETAIL")
    }
}

impl std::error::Error for ScriptedSourceError {}

struct SourceEntry {
    header: FinalizedCompactBlockHeader,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct ScriptedSource {
    entries: BTreeMap<u64, SourceEntry>,
    fail_header_at: Option<u64>,
    fail_bytes_at: Option<u64>,
    header_requests: Vec<u64>,
    byte_requests: Vec<(u64, usize)>,
}

impl ScriptedSource {
    fn with_entry(mut self, header: FinalizedCompactBlockHeader, block: &CompactBlock) -> Self {
        self.entries.insert(
            header.height(),
            SourceEntry {
                header,
                bytes: block.encode(),
            },
        );
        self
    }
}

impl FinalizedRecoverySource for ScriptedSource {
    type Error = ScriptedSourceError;

    fn finalized_header(
        &mut self,
        height: u64,
    ) -> Result<FinalizedCompactBlockHeader, Self::Error> {
        self.header_requests.push(height);
        if self.fail_header_at == Some(height) {
            return Err(ScriptedSourceError);
        }
        self.entries
            .get(&height)
            .map(|entry| entry.header)
            .ok_or(ScriptedSourceError)
    }

    fn compact_block_bytes(
        &mut self,
        header: &FinalizedCompactBlockHeader,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        self.byte_requests.push((header.height(), maximum_bytes));
        if self.fail_bytes_at == Some(header.height()) {
            return Err(ScriptedSourceError);
        }
        self.entries
            .get(&header.height())
            .map(|entry| entry.bytes.clone())
            .ok_or(ScriptedSourceError)
    }
}

#[test]
fn coordinator_commits_a_bounded_prefix_then_reopens_and_resumes_exactly() {
    let RecoveryFixture {
        _temp,
        path,
        mut database,
        accounts,
        second_block,
        second_header,
        target_block,
        target_header,
        spend_nullifier,
    } = fixture();
    let mut interrupted = ScriptedSource::default()
        .with_entry(second_header, &second_block)
        .with_entry(target_header, &target_block);
    interrupted.fail_header_at = Some(3);
    let error = advance_seed_recovery(&mut database, &mut interrupted, &accounts, 2).unwrap_err();
    assert_eq!(error.committed_blocks(), 1);
    assert!(matches!(
        error.failure(),
        WalletRecoveryCoordinatorFailure::Source(ScriptedSourceError)
    ));
    assert!(!format!("{error:?}").contains("SENSITIVE SOURCE DETAIL"));
    assert!(!format!("{error:?}").contains("committed_blocks"));
    assert_eq!(interrupted.header_requests, vec![2, 3]);
    assert_eq!(
        interrupted.byte_requests,
        vec![(2, MAX_COMPACT_BLOCK_BYTES)]
    );
    assert_eq!(database.load_tip().unwrap().height(), 2);
    assert!(matches!(
        database.recovery_status().unwrap(),
        WalletRecoveryStatus::InProgress {
            scanned_height: 2,
            ..
        }
    ));

    drop(database);
    let mut database =
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 2).unwrap();
    let mut resumed = ScriptedSource::default().with_entry(target_header, &target_block);
    let advanced = advance_seed_recovery(&mut database, &mut resumed, &accounts, 1).unwrap();
    assert_eq!(advanced.committed_blocks(), 1);
    assert_eq!(advanced.last_height(), 3);
    assert_eq!(
        advanced.status(),
        WalletRecoveryStatus::Complete {
            target_height: 3,
            account_count: 3,
            highest_used_account: Some(0),
        }
    );
    assert!(database.witness_for_spend(spend_nullifier).is_ok());

    let mut empty = ScriptedSource::default();
    let no_op = advance_seed_recovery(&mut database, &mut empty, &accounts, 1).unwrap();
    assert_eq!(no_op.committed_blocks(), 0);
    assert_eq!(no_op.last_height(), 3);
    assert!(empty.header_requests.is_empty());
    drop(database);
    drop(_temp);
}

#[test]
fn coordinator_rejects_limits_wrong_accounts_headers_and_compact_bytes_before_mutation() {
    let mut fixture = fixture();
    let starting_tip = fixture.database.load_tip().unwrap();
    let mut empty = ScriptedSource::default();
    for invalid_limit in [0, MAX_RECOVERY_BLOCKS_PER_ADVANCE + 1] {
        let error = advance_seed_recovery(
            &mut fixture.database,
            &mut empty,
            &fixture.accounts,
            invalid_limit,
        )
        .unwrap_err();
        assert_eq!(error.committed_blocks(), 0);
        assert!(matches!(
            error.failure(),
            WalletRecoveryCoordinatorFailure::InvalidBlockLimit
        ));
    }
    assert!(empty.header_requests.is_empty());

    let wrong_accounts =
        WalletRecoveryAccounts::derive(&recovery_seed(0xB1), ChainId::new(NETWORK), 3).unwrap();
    let error =
        advance_seed_recovery(&mut fixture.database, &mut empty, &wrong_accounts, 1).unwrap_err();
    assert!(matches!(
        error.failure(),
        WalletRecoveryCoordinatorFailure::AccountSetMismatch
    ));
    assert!(empty.header_requests.is_empty());

    let mut wrong_header = ScriptedSource::default();
    wrong_header.entries.insert(
        2,
        SourceEntry {
            header: fixture.target_header,
            bytes: fixture.second_block.encode(),
        },
    );
    let error = advance_seed_recovery(
        &mut fixture.database,
        &mut wrong_header,
        &fixture.accounts,
        1,
    )
    .unwrap_err();
    assert!(matches!(
        error.failure(),
        WalletRecoveryCoordinatorFailure::HeaderMismatch
    ));
    assert!(wrong_header.byte_requests.is_empty());
    assert_eq!(fixture.database.load_tip().unwrap(), starting_tip);

    let mut tampered = fixture.second_block.encode();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut bad_bytes = ScriptedSource::default();
    bad_bytes.entries.insert(
        2,
        SourceEntry {
            header: fixture.second_header,
            bytes: tampered,
        },
    );
    let error = advance_seed_recovery(&mut fixture.database, &mut bad_bytes, &fixture.accounts, 1)
        .unwrap_err();
    assert!(matches!(
        error.failure(),
        WalletRecoveryCoordinatorFailure::CompactBlock(_)
    ));
    assert_eq!(bad_bytes.byte_requests, vec![(2, MAX_COMPACT_BLOCK_BYTES)]);
    assert_eq!(fixture.database.load_tip().unwrap(), starting_tip);

    let false_parent_tip = WalletScanTip::from_verified_checkpoint(
        starting_tip.chain_id(),
        starting_tip.height(),
        [0xC1; 32],
        &starting_tip.tree_snapshot(),
    )
    .unwrap();
    let mut rng = ChaCha20Rng::from_seed([0xC2; 32]);
    let owner = fixture.accounts.full_viewing_key(0).unwrap();
    let (orphan_block, orphan_header) = block_and_header(
        &false_parent_tip,
        [0xC3; 32],
        [0xC4; 32],
        vec![
            action(owner, nullifier(21), 21, &mut rng),
            action(owner, nullifier(22), 22, &mut rng),
        ],
    );
    let mut orphaned = ScriptedSource::default().with_entry(orphan_header, &orphan_block);
    let error = advance_seed_recovery(&mut fixture.database, &mut orphaned, &fixture.accounts, 1)
        .unwrap_err();
    assert!(matches!(
        error.failure(),
        WalletRecoveryCoordinatorFailure::Scan(WalletScanError::ParentMismatch)
    ));
    assert_eq!(fixture.database.load_tip().unwrap(), starting_tip);

    let mut unavailable = ScriptedSource {
        fail_header_at: Some(2),
        ..ScriptedSource::default()
    };
    let error = advance_seed_recovery(
        &mut fixture.database,
        &mut unavailable,
        &fixture.accounts,
        1,
    )
    .unwrap_err();
    assert!(matches!(
        error.failure(),
        WalletRecoveryCoordinatorFailure::Source(_)
    ));
    assert_eq!(fixture.database.load_tip().unwrap(), starting_tip);

    let genesis_path = fs::canonicalize(fixture._temp.path())
        .unwrap()
        .join("genesis.sqlite3");
    let mut genesis =
        EncryptedWalletDb::create(&genesis_path, &ROOT_KEY, config(), initial_tip()).unwrap();
    let error = advance_seed_recovery(&mut genesis, &mut empty, &fixture.accounts, 1).unwrap_err();
    assert!(matches!(
        error.failure(),
        WalletRecoveryCoordinatorFailure::NotSeedRecovery
    ));
    assert!(empty.header_requests.is_empty());
}
