#![cfg(unix)]

use std::{fs, path::Path};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use rusqlite::{Connection, params};
use tempfile::TempDir;
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NoteCommitmentTree, PreparedNoteOutput,
    VaultFullViewingKey, VaultSpendingKey,
};
use vault_protocol::{
    AuthenticatedCompactBlock, ChainId, CompactBlock, CompactBlockAction, CompactBlockTransaction,
    FinalizedCompactBlockHeader, TransactionId,
};
use vault_wallet::{
    EncryptedWalletDb, FinalizedWalletStore, WalletAccountId, WalletDatabaseConfig, WalletDbError,
    WalletScanAccount, WalletScanTip, scan_finalized_block,
};
use zeroize::Zeroizing;

#[cfg(unix)]
use vault_wallet::{
    WalletBirthdayCheckpoint, WalletRecoveryAccounts, WalletRecoveryError, WalletRecoveryPlan,
    WalletRecoveryStatus, WalletScanError, WalletSeedMaterial,
};

const NETWORK: [u8; 32] = [0x41; 32];
const GENESIS_HASH: [u8; 32] = [0x51; 32];
const FIRST_BLOCK_HASH: [u8; 32] = [0x52; 32];
const SECOND_BLOCK_HASH: [u8; 32] = [0x53; 32];
const WALLET_ID: [u8; 32] = [0x81; 32];
const ACCOUNT_ID: [u8; 32] = [0x82; 32];
const ROOT_KEY: [u8; 32] = [0x91; 32];
const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;

fn nullifier(byte: u8) -> ActionNullifier {
    ActionNullifier::from_bytes([byte; 32]).unwrap()
}

fn wallet(seed: u8) -> VaultFullViewingKey {
    VaultSpendingKey::derive(&[seed; 32], NETWORK, 0)
        .unwrap()
        .full_viewing_key()
}

#[cfg(unix)]
fn recovery_seed(byte: u8) -> WalletSeedMaterial {
    WalletSeedMaterial::from_custodian_entropy(Zeroizing::new([byte; 32])).unwrap()
}

fn action(
    owner: &VaultFullViewingKey,
    scope: KeyScope,
    action_nullifier: ActionNullifier,
    byte: u8,
    value: u64,
    rng: &mut ChaCha20Rng,
) -> CompactBlockAction {
    let output = PreparedNoteOutput::create(
        owner,
        scope,
        owner.address_at(u32::from(byte), scope),
        value,
        MAXIMUM_VALUE,
        action_nullifier,
        [byte; MEMO_BYTES],
        rng,
    )
    .unwrap();
    CompactBlockAction::new(action_nullifier, output.encrypted_note().clone())
}

fn block_extending(
    tip: &WalletScanTip,
    block_hash: [u8; 32],
    transaction_id: [u8; 32],
    actions: Vec<CompactBlockAction>,
) -> AuthenticatedCompactBlock {
    block_and_header_extending(tip, block_hash, transaction_id, actions).0
}

fn block_and_header_extending(
    tip: &WalletScanTip,
    block_hash: [u8; 32],
    transaction_id: [u8; 32],
    mut actions: Vec<CompactBlockAction>,
) -> (AuthenticatedCompactBlock, FinalizedCompactBlockHeader) {
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
    (block.authenticate(header).unwrap(), header)
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

fn database_path(temp: &TempDir) -> std::path::PathBuf {
    fs::canonicalize(temp.path())
        .unwrap()
        .join("wallet.sqlite3")
}

fn config() -> WalletDatabaseConfig {
    WalletDatabaseConfig::new(WALLET_ID, MAXIMUM_VALUE, 100).unwrap()
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn first_block(owner: &VaultFullViewingKey, tip: &WalletScanTip) -> AuthenticatedCompactBlock {
    let unrelated = wallet(0xB2);
    let mut rng = ChaCha20Rng::from_seed([0xA1; 32]);
    block_extending(
        tip,
        FIRST_BLOCK_HASH,
        [0x61; 32],
        vec![
            action(owner, KeyScope::External, nullifier(1), 1, 1_001, &mut rng),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(2),
                2,
                2_002,
                &mut rng,
            ),
            action(owner, KeyScope::Internal, nullifier(3), 3, 3_003, &mut rng),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(4),
                4,
                4_004,
                &mut rng,
            ),
        ],
    )
}

fn open_database(path: &Path) -> EncryptedWalletDb {
    EncryptedWalletDb::open(path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 0).unwrap()
}

#[test]
fn encrypted_database_commits_reopens_witnesses_and_marks_a_later_spend() {
    let temp = tempfile::tempdir().unwrap();
    let path = database_path(&temp);
    let owner = wallet(0xB1);
    let tip = initial_tip();
    let mut database = EncryptedWalletDb::create(&path, &ROOT_KEY, config(), tip.clone()).unwrap();
    assert_eq!(database.load_tip().unwrap(), tip);
    assert_eq!(format!("{database:?}"), "EncryptedWalletDb(REDACTED)");

    assert_eq!(
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 0).unwrap_err(),
        WalletDbError::Locked
    );

    let account = WalletScanAccount::new(WalletAccountId::from_bytes(ACCOUNT_ID).unwrap(), &owner);
    let block = first_block(&owner, &tip);
    let update = scan_finalized_block(&tip, &block, &[account]).unwrap();
    assert_eq!(update.detected_notes().len(), 2);
    let external_nullifier = update.detected_notes()[0].spend_nullifier();
    let internal_nullifier = update.detected_notes()[1].spend_nullifier();
    database.commit_finalized_block(update).unwrap();

    let persisted_tip = database.load_tip().unwrap();
    assert_eq!(persisted_tip.height(), 1);
    let external_witness = database.witness_for_spend(external_nullifier).unwrap();
    assert_eq!(external_witness.key_scope(), KeyScope::External);
    assert_eq!(external_witness.account_id().to_bytes(), ACCOUNT_ID);
    assert_eq!(external_witness.decrypted().note().value(), 1_001);
    assert!(external_witness.membership_path().verify(
        external_witness.decrypted().note().commitment().unwrap(),
        external_witness.anchor()
    ));
    let internal_witness = database.witness_for_spend(internal_nullifier).unwrap();
    assert_eq!(internal_witness.key_scope(), KeyScope::Internal);
    assert_eq!(internal_witness.decrypted().note().value(), 3_003);
    assert_eq!(
        format!("{internal_witness:?}"),
        "WalletSpendWitness(REDACTED)"
    );

    drop(database);
    let database_bytes = fs::read(&path).unwrap();
    assert!(!database_bytes.windows(64).any(|window| window == [1; 64]));
    assert!(!database_bytes.windows(64).any(|window| window == [3; 64]));
    assert!(
        !database_bytes
            .windows(32)
            .any(|window| window == external_nullifier.to_bytes())
    );
    assert!(!path.with_file_name("wallet.sqlite3-journal").exists());
    assert_eq!(
        EncryptedWalletDb::open(&path, &[0x92; 32], ChainId::new(NETWORK), WALLET_ID, 0,)
            .unwrap_err(),
        WalletDbError::AuthenticationFailed
    );
    assert_eq!(
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 2,)
            .unwrap_err(),
        WalletDbError::RollbackDetected
    );
    let mut database = open_database(&path);
    assert_eq!(
        database
            .witness_for_spend(external_nullifier)
            .unwrap()
            .checkpoint_height(),
        1
    );

    let unrelated = wallet(0xB3);
    let mut rng = ChaCha20Rng::from_seed([0xA2; 32]);
    let second_block = block_extending(
        &persisted_tip,
        SECOND_BLOCK_HASH,
        [0x62; 32],
        vec![
            action(
                &unrelated,
                KeyScope::External,
                external_nullifier,
                5,
                5_005,
                &mut rng,
            ),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(6),
                6,
                6_006,
                &mut rng,
            ),
        ],
    );
    let account = WalletScanAccount::new(WalletAccountId::from_bytes(ACCOUNT_ID).unwrap(), &owner);
    let second_update = scan_finalized_block(&persisted_tip, &second_block, &[account]).unwrap();
    database.commit_finalized_block(second_update).unwrap();
    assert_eq!(database.load_tip().unwrap().height(), 2);
    assert_eq!(
        database.witness_for_spend(external_nullifier).unwrap_err(),
        WalletDbError::NoteAlreadySpent
    );
    assert!(database.witness_for_spend(internal_nullifier).is_ok());
    drop(database);
    let database =
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 2).unwrap();
    assert_eq!(database.load_tip().unwrap().height(), 2);
    assert_eq!(
        database.witness_for_spend(external_nullifier).unwrap_err(),
        WalletDbError::NoteAlreadySpent
    );
    assert!(database.witness_for_spend(internal_nullifier).is_ok());
}

#[test]
fn stale_update_rolls_back_without_poisoning_or_advancing_the_tip() {
    let temp = tempfile::tempdir().unwrap();
    let path = database_path(&temp);
    let owner = wallet(0xC1);
    let tip = initial_tip();
    let mut database = EncryptedWalletDb::create(&path, &ROOT_KEY, config(), tip.clone()).unwrap();
    let block = first_block(&owner, &tip);
    let first_account =
        WalletScanAccount::new(WalletAccountId::from_bytes(ACCOUNT_ID).unwrap(), &owner);
    let first = scan_finalized_block(&tip, &block, &[first_account]).unwrap();
    let second_account =
        WalletScanAccount::new(WalletAccountId::from_bytes(ACCOUNT_ID).unwrap(), &owner);
    let stale = scan_finalized_block(&tip, &block, &[second_account]).unwrap();
    database.commit_finalized_block(first).unwrap();
    assert_eq!(
        database.commit_finalized_block(stale).unwrap_err(),
        WalletDbError::TipMismatch
    );
    assert_eq!(database.load_tip().unwrap().height(), 1);
}

#[test]
fn wrong_scope_missing_file_and_authenticated_tip_tampering_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let path = database_path(&temp);
    assert_eq!(
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 0).unwrap_err(),
        WalletDbError::Missing
    );
    let database = EncryptedWalletDb::create(&path, &ROOT_KEY, config(), initial_tip()).unwrap();
    drop(database);
    assert_eq!(
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new([0x42; 32]), WALLET_ID, 0,)
            .unwrap_err(),
        WalletDbError::ScopeMismatch
    );
    assert_eq!(
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), [0x83; 32], 0,)
            .unwrap_err(),
        WalletDbError::ScopeMismatch
    );

    let connection = Connection::open(&path).unwrap();
    let mut payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM wallet_tip WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let last = payload.len() - 1;
    payload[last] ^= 0x01;
    connection
        .execute(
            "UPDATE wallet_tip SET payload = ?1 WHERE singleton = 1",
            params![payload],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 0).unwrap_err(),
        WalletDbError::AuthenticationFailed
    );
}

#[test]
fn deleting_an_owned_note_row_is_detected_against_shardtree_marks_on_open() {
    let temp = tempfile::tempdir().unwrap();
    let path = database_path(&temp);
    let owner = wallet(0xD1);
    let tip = initial_tip();
    let mut database = EncryptedWalletDb::create(&path, &ROOT_KEY, config(), tip.clone()).unwrap();
    let block = first_block(&owner, &tip);
    let account = WalletScanAccount::new(WalletAccountId::from_bytes(ACCOUNT_ID).unwrap(), &owner);
    let update = scan_finalized_block(&tip, &block, &[account]).unwrap();
    database.commit_finalized_block(update).unwrap();
    drop(database);

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .execute(
                "DELETE FROM wallet_notes WHERE nullifier_tag = (
                    SELECT nullifier_tag FROM wallet_notes LIMIT 1
                 )",
                [],
            )
            .unwrap(),
        1
    );
    drop(connection);
    assert_eq!(
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 1).unwrap_err(),
        WalletDbError::CorruptState
    );
}

#[cfg(unix)]
#[test]
fn verified_birthday_frontier_recovers_future_notes_and_persists_its_origin() {
    let temp = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(temp.path()).unwrap();
    let path = database_path(&temp);
    let recovery_accounts =
        WalletRecoveryAccounts::derive(&recovery_seed(0xD2), ChainId::new(NETWORK), 3).unwrap();
    let owner = recovery_accounts.full_viewing_key(0).unwrap();
    let unrelated = wallet(0xD3);
    let genesis_tip = initial_tip();
    let mut rng = ChaCha20Rng::from_seed([0xD4; 32]);
    let (history_block, history_header) = block_and_header_extending(
        &genesis_tip,
        FIRST_BLOCK_HASH,
        [0xD5; 32],
        vec![
            action(
                &unrelated,
                KeyScope::External,
                nullifier(21),
                21,
                21_021,
                &mut rng,
            ),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(22),
                22,
                22_022,
                &mut rng,
            ),
        ],
    );
    let history_update = scan_finalized_block(&genesis_tip, &history_block, &[]).unwrap();
    let history_tip = history_update.next_tip().clone();
    let checkpoint = WalletBirthdayCheckpoint::from_finalized_header(
        &history_header,
        &history_tip.tree_snapshot(),
    )
    .unwrap();
    assert_eq!(
        format!("{checkpoint:?}"),
        "WalletBirthdayCheckpoint(REDACTED)"
    );
    assert_eq!(checkpoint.checkpoint_height(), 1);
    assert_eq!(checkpoint.first_scan_height(), 2);
    assert_eq!(checkpoint.block_hash(), FIRST_BLOCK_HASH);
    assert_eq!(
        WalletBirthdayCheckpoint::from_finalized_header(
            &history_header,
            &genesis_tip.tree_snapshot(),
        )
        .unwrap_err(),
        WalletScanError::InvalidCheckpoint
    );

    let ordinary_path = directory.join("ordinary-nonempty.sqlite3");
    assert_eq!(
        EncryptedWalletDb::create(&ordinary_path, &ROOT_KEY, config(), history_tip.clone(),)
            .unwrap_err(),
        WalletDbError::NonEmptyInitializationUnsupported
    );
    assert!(!ordinary_path.exists());
    let non_genesis_empty = WalletScanTip::from_verified_checkpoint(
        ChainId::new(NETWORK),
        1,
        [0xD6; 32],
        &NoteCommitmentTree::new().snapshot(),
    )
    .unwrap();
    let ordinary_empty_path = directory.join("ordinary-height-one.sqlite3");
    assert_eq!(
        EncryptedWalletDb::create(&ordinary_empty_path, &ROOT_KEY, config(), non_genesis_empty,)
            .unwrap_err(),
        WalletDbError::NonEmptyInitializationUnsupported
    );
    assert!(!ordinary_empty_path.exists());

    let payment_block = block_extending(
        &history_tip,
        SECOND_BLOCK_HASH,
        [0xD7; 32],
        vec![
            action(
                owner,
                KeyScope::External,
                nullifier(23),
                23,
                23_023,
                &mut rng,
            ),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(24),
                24,
                24_024,
                &mut rng,
            ),
        ],
    );
    let payment_preview = scan_finalized_block(
        &history_tip,
        &payment_block,
        &recovery_accounts.scan_accounts(),
    )
    .unwrap();
    let payment_tip = payment_preview.next_tip().clone();
    let (later_block, later_header) = block_and_header_extending(
        &payment_tip,
        [0xD8; 32],
        [0xD9; 32],
        vec![
            action(
                &unrelated,
                KeyScope::External,
                nullifier(25),
                25,
                25_025,
                &mut rng,
            ),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(26),
                26,
                26_026,
                &mut rng,
            ),
        ],
    );
    assert_eq!(
        WalletRecoveryPlan::new(checkpoint.clone(), &later_header, &recovery_accounts, 0,)
            .unwrap_err(),
        WalletRecoveryError::InvalidGapLimit
    );
    assert_eq!(
        WalletRecoveryPlan::new(checkpoint.clone(), &history_header, &recovery_accounts, 2,)
            .unwrap_err(),
        WalletRecoveryError::InvalidTarget
    );
    let wrong_network_accounts =
        WalletRecoveryAccounts::derive(&recovery_seed(0xD2), ChainId::new([0x42; 32]), 3).unwrap();
    assert_eq!(
        WalletRecoveryPlan::new(
            checkpoint.clone(),
            &later_header,
            &wrong_network_accounts,
            2,
        )
        .unwrap_err(),
        WalletRecoveryError::WrongNetwork
    );
    let plan =
        WalletRecoveryPlan::new(checkpoint.clone(), &later_header, &recovery_accounts, 2).unwrap();
    assert_eq!(format!("{plan:?}"), "WalletRecoveryPlan(REDACTED)");
    assert_eq!(plan.target_height(), 3);
    assert_eq!(plan.account_count(), 3);
    assert_eq!(plan.gap_limit(), 2);

    let mut database =
        EncryptedWalletDb::create_from_recovery_plan(&path, &ROOT_KEY, config(), plan).unwrap();
    assert_eq!(database.load_tip().unwrap(), history_tip);
    assert_eq!(
        database.birthday_checkpoint().unwrap(),
        Some(checkpoint.clone())
    );
    assert_eq!(
        database.recovery_status().unwrap(),
        WalletRecoveryStatus::InProgress {
            birthday_height: 1,
            scanned_height: 1,
            target_height: 3,
            account_count: 3,
            gap_limit: 2,
        }
    );
    let initial_recovery_payload: Vec<u8> = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT payload FROM wallet_recovery WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();

    let wrong_accounts =
        WalletRecoveryAccounts::derive(&recovery_seed(0xDE), ChainId::new(NETWORK), 3).unwrap();
    let wrong_update = scan_finalized_block(
        &history_tip,
        &payment_block,
        &wrong_accounts.scan_accounts(),
    )
    .unwrap();
    assert_eq!(
        database.commit_finalized_block(wrong_update).unwrap_err(),
        WalletDbError::RecoveryAccountMismatch
    );
    assert_eq!(database.load_tip().unwrap(), history_tip);

    let payment_update = scan_finalized_block(
        &history_tip,
        &payment_block,
        &recovery_accounts.scan_accounts(),
    )
    .unwrap();
    assert_eq!(payment_update.detected_notes().len(), 1);
    assert_eq!(payment_update.detected_notes()[0].position(), 2);
    let spend_nullifier = payment_update.detected_notes()[0].spend_nullifier();
    database.commit_finalized_block(payment_update).unwrap();
    let payment_tip = database.load_tip().unwrap();
    assert_eq!(
        database.witness_for_spend(spend_nullifier).unwrap_err(),
        WalletDbError::RecoveryIncomplete
    );
    let partial_backup = directory.join("partial-recovery.vwb");
    let partial_restored_path = directory.join("partial-recovery.sqlite3");
    database.export_backup(&partial_backup, &ROOT_KEY).unwrap();
    let partial_restored = EncryptedWalletDb::restore_backup(
        &partial_backup,
        &partial_restored_path,
        &ROOT_KEY,
        ChainId::new(NETWORK),
        WALLET_ID,
        2,
    )
    .unwrap();
    assert_eq!(
        partial_restored.recovery_status().unwrap(),
        WalletRecoveryStatus::InProgress {
            birthday_height: 1,
            scanned_height: 2,
            target_height: 3,
            account_count: 3,
            gap_limit: 2,
        }
    );
    assert_eq!(
        partial_restored
            .witness_for_spend(spend_nullifier)
            .unwrap_err(),
        WalletDbError::RecoveryIncomplete
    );
    drop(partial_restored);
    let connection = Connection::open(&partial_restored_path).unwrap();
    connection
        .execute(
            "UPDATE wallet_recovery SET payload = ?1 WHERE singleton = 1",
            params![initial_recovery_payload],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        EncryptedWalletDb::open(
            &partial_restored_path,
            &ROOT_KEY,
            ChainId::new(NETWORK),
            WALLET_ID,
            0,
        )
        .unwrap_err(),
        WalletDbError::CorruptState
    );
    drop(database);
    let mut database =
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 2).unwrap();
    assert_eq!(
        database.recovery_status().unwrap(),
        WalletRecoveryStatus::InProgress {
            birthday_height: 1,
            scanned_height: 2,
            target_height: 3,
            account_count: 3,
            gap_limit: 2,
        }
    );
    let later_update = scan_finalized_block(
        &payment_tip,
        &later_block,
        &recovery_accounts.scan_accounts(),
    )
    .unwrap();
    database.commit_finalized_block(later_update).unwrap();
    assert_eq!(
        database.recovery_status().unwrap(),
        WalletRecoveryStatus::Complete {
            target_height: 3,
            account_count: 3,
            highest_used_account: Some(0),
        }
    );
    let first_witness = database.witness_for_spend(spend_nullifier).unwrap();
    assert!(first_witness.membership_path().verify(
        first_witness.decrypted().note().commitment().unwrap(),
        first_witness.anchor()
    ));

    let live_tip = database.load_tip().unwrap();
    let live_block = block_extending(
        &live_tip,
        [0xDA; 32],
        [0xDB; 32],
        vec![
            action(
                &unrelated,
                KeyScope::External,
                nullifier(27),
                27,
                27_027,
                &mut rng,
            ),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(28),
                28,
                28_028,
                &mut rng,
            ),
        ],
    );
    let live_update =
        scan_finalized_block(&live_tip, &live_block, &recovery_accounts.scan_accounts()).unwrap();
    database.commit_finalized_block(live_update).unwrap();
    let current_witness = database.witness_for_spend(spend_nullifier).unwrap();
    assert_ne!(current_witness.anchor(), first_witness.anchor());
    assert!(current_witness.membership_path().verify(
        current_witness.decrypted().note().commitment().unwrap(),
        current_witness.anchor()
    ));
    drop(database);

    let database =
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 4).unwrap();
    assert_eq!(database.birthday_checkpoint().unwrap(), Some(checkpoint));
    assert!(matches!(
        database.recovery_status().unwrap(),
        WalletRecoveryStatus::Complete { .. }
    ));
    assert!(database.witness_for_spend(spend_nullifier).is_ok());
    let birthday_backup = directory.join("birthday.vwb");
    let birthday_restored_path = directory.join("birthday-restored.sqlite3");
    database.export_backup(&birthday_backup, &ROOT_KEY).unwrap();
    let birthday_restored = EncryptedWalletDb::restore_backup(
        &birthday_backup,
        &birthday_restored_path,
        &ROOT_KEY,
        ChainId::new(NETWORK),
        WALLET_ID,
        4,
    )
    .unwrap();
    assert_eq!(
        birthday_restored.birthday_checkpoint().unwrap(),
        database.birthday_checkpoint().unwrap()
    );
    assert_eq!(
        birthday_restored.recovery_status().unwrap(),
        database.recovery_status().unwrap()
    );
    assert!(birthday_restored.witness_for_spend(spend_nullifier).is_ok());
    drop(birthday_restored);
    drop(database);

    let connection = Connection::open(&birthday_restored_path).unwrap();
    let mut recovery_payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM wallet_recovery WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let last = recovery_payload.len() - 1;
    recovery_payload[last] ^= 1;
    connection
        .execute(
            "UPDATE wallet_recovery SET payload = ?1 WHERE singleton = 1",
            params![recovery_payload],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        EncryptedWalletDb::open(
            &birthday_restored_path,
            &ROOT_KEY,
            ChainId::new(NETWORK),
            WALLET_ID,
            0,
        )
        .unwrap_err(),
        WalletDbError::AuthenticationFailed
    );

    let connection = Connection::open(&path).unwrap();
    let mut payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM wallet_origin WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let last = payload.len() - 1;
    payload[last] ^= 1;
    connection
        .execute(
            "UPDATE wallet_origin SET payload = ?1 WHERE singleton = 1",
            params![payload],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        EncryptedWalletDb::open(&path, &ROOT_KEY, ChainId::new(NETWORK), WALLET_ID, 0).unwrap_err(),
        WalletDbError::AuthenticationFailed
    );
}

#[cfg(unix)]
#[test]
fn recovery_target_and_trailing_account_gap_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let path = database_path(&temp);
    let accounts =
        WalletRecoveryAccounts::derive(&recovery_seed(0xE1), ChainId::new(NETWORK), 2).unwrap();
    let owner = accounts.full_viewing_key(1).unwrap();
    let unrelated = wallet(0xE2);
    let genesis_tip = initial_tip();
    let mut rng = ChaCha20Rng::from_seed([0xE3; 32]);
    let (history_block, history_header) = block_and_header_extending(
        &genesis_tip,
        [0xE4; 32],
        [0xE5; 32],
        vec![
            action(
                &unrelated,
                KeyScope::External,
                nullifier(51),
                51,
                51_051,
                &mut rng,
            ),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(52),
                52,
                52_052,
                &mut rng,
            ),
        ],
    );
    let history_tip = scan_finalized_block(&genesis_tip, &history_block, &[])
        .unwrap()
        .next_tip()
        .clone();
    let checkpoint = WalletBirthdayCheckpoint::from_finalized_header(
        &history_header,
        &history_tip.tree_snapshot(),
    )
    .unwrap();
    let (target_block, target_header) = block_and_header_extending(
        &history_tip,
        [0xE6; 32],
        [0xE7; 32],
        vec![
            action(
                owner,
                KeyScope::External,
                nullifier(53),
                53,
                53_053,
                &mut rng,
            ),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(54),
                54,
                54_054,
                &mut rng,
            ),
        ],
    );
    let alternate_target = block_extending(
        &history_tip,
        [0xE8; 32],
        [0xE9; 32],
        vec![
            action(
                &unrelated,
                KeyScope::External,
                nullifier(55),
                55,
                55_055,
                &mut rng,
            ),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(56),
                56,
                56_056,
                &mut rng,
            ),
        ],
    );
    let plan = WalletRecoveryPlan::new(checkpoint, &target_header, &accounts, 1).unwrap();
    let mut database =
        EncryptedWalletDb::create_from_recovery_plan(&path, &ROOT_KEY, config(), plan).unwrap();

    let alternate_update =
        scan_finalized_block(&history_tip, &alternate_target, &accounts.scan_accounts()).unwrap();
    assert_eq!(
        database
            .commit_finalized_block(alternate_update)
            .unwrap_err(),
        WalletDbError::RecoveryTargetMismatch
    );
    assert_eq!(database.load_tip().unwrap(), history_tip);

    let target_update =
        scan_finalized_block(&history_tip, &target_block, &accounts.scan_accounts()).unwrap();
    let spend_nullifier = target_update.detected_notes()[0].spend_nullifier();
    database.commit_finalized_block(target_update).unwrap();
    assert_eq!(
        database.recovery_status().unwrap(),
        WalletRecoveryStatus::RequiresLargerAccountRange {
            target_height: 2,
            account_count: 2,
            highest_used_account: 1,
            gap_limit: 1,
        }
    );
    assert_eq!(
        database.witness_for_spend(spend_nullifier).unwrap_err(),
        WalletDbError::RecoveryIncomplete
    );

    let exhausted_tip = database.load_tip().unwrap();
    let future_block = block_extending(
        &exhausted_tip,
        [0xEA; 32],
        [0xEB; 32],
        vec![
            action(
                &unrelated,
                KeyScope::External,
                nullifier(57),
                57,
                57_057,
                &mut rng,
            ),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(58),
                58,
                58_058,
                &mut rng,
            ),
        ],
    );
    let future_update =
        scan_finalized_block(&exhausted_tip, &future_block, &accounts.scan_accounts()).unwrap();
    assert_eq!(
        database.commit_finalized_block(future_update).unwrap_err(),
        WalletDbError::RecoveryAccountRangeExhausted
    );
    assert_eq!(database.load_tip().unwrap(), exhausted_tip);
}

#[cfg(unix)]
#[test]
fn authenticated_backup_restores_a_nonempty_spendable_wallet_without_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(temp.path()).unwrap();
    let source_path = database_path(&temp);
    let backup_path = directory.join("wallet.vwb");
    let restored_path = directory.join("restored.sqlite3");
    let owner = wallet(0xE1);
    let tip = initial_tip();
    let mut source =
        EncryptedWalletDb::create(&source_path, &ROOT_KEY, config(), tip.clone()).unwrap();
    let account = WalletScanAccount::new(WalletAccountId::from_bytes(ACCOUNT_ID).unwrap(), &owner);
    let first = scan_finalized_block(&tip, &first_block(&owner, &tip), &[account]).unwrap();
    let external_nullifier = first.detected_notes()[0].spend_nullifier();
    let internal_nullifier = first.detected_notes()[1].spend_nullifier();
    source.commit_finalized_block(first).unwrap();

    let source_external = source.witness_for_spend(external_nullifier).unwrap();
    let summary = source.export_backup(&backup_path, &ROOT_KEY).unwrap();
    assert_eq!(summary.finalized_height(), 1);
    assert_eq!(format!("{summary:?}"), "WalletBackupSummary(REDACTED)");
    assert!(summary.snapshot_bytes() > 0);
    assert_eq!(
        summary.backup_bytes(),
        fs::metadata(&backup_path).unwrap().len()
    );
    assert_eq!(summary.backup_bytes(), 1_049_104);
    assert_eq!(fs::metadata(&backup_path).unwrap().mode() & 0o777, 0o600);

    let backup_bytes = fs::read(&backup_path).unwrap();
    assert_eq!(&backup_bytes[..4], b"VWB1");
    let public_prefix = &backup_bytes[..64];
    assert!(!public_prefix.windows(32).any(|window| window == NETWORK));
    assert!(!public_prefix.windows(32).any(|window| window == WALLET_ID));
    assert!(
        !public_prefix
            .windows(32)
            .any(|window| window == FIRST_BLOCK_HASH)
    );
    assert!(
        !backup_bytes
            .windows(16)
            .any(|window| window == b"SQLite format 3\0")
    );
    assert!(
        !backup_bytes
            .windows(32)
            .any(|window| window == external_nullifier.to_bytes())
    );
    assert_eq!(
        source.export_backup(&backup_path, &ROOT_KEY).unwrap_err(),
        WalletDbError::AlreadyExists
    );
    assert_eq!(fs::read(&backup_path).unwrap(), backup_bytes);
    let unreadable_path = directory.join("wrong-root.vwb");
    assert_eq!(
        source
            .export_backup(&unreadable_path, &[0x92; 32])
            .unwrap_err(),
        WalletDbError::AuthenticationFailed
    );
    assert!(!unreadable_path.exists());

    let mut restored = EncryptedWalletDb::restore_backup(
        &backup_path,
        &restored_path,
        &ROOT_KEY,
        ChainId::new(NETWORK),
        WALLET_ID,
        1,
    )
    .unwrap();
    assert_eq!(restored.load_tip().unwrap().height(), 1);
    let restored_external = restored.witness_for_spend(external_nullifier).unwrap();
    assert_eq!(restored_external.anchor(), source_external.anchor());
    assert_eq!(
        restored_external.decrypted().note().value(),
        source_external.decrypted().note().value()
    );
    assert!(restored_external.membership_path().verify(
        restored_external.decrypted().note().commitment().unwrap(),
        restored_external.anchor()
    ));
    assert!(restored.witness_for_spend(internal_nullifier).is_ok());
    assert_eq!(fs::metadata(&restored_path).unwrap().mode() & 0o777, 0o600);

    let persisted_tip = restored.load_tip().unwrap();
    let unrelated = wallet(0xE2);
    let mut rng = ChaCha20Rng::from_seed([0xE3; 32]);
    let second = block_extending(
        &persisted_tip,
        SECOND_BLOCK_HASH,
        [0xE4; 32],
        vec![
            action(
                &unrelated,
                KeyScope::External,
                external_nullifier,
                9,
                9_009,
                &mut rng,
            ),
            action(
                &unrelated,
                KeyScope::External,
                nullifier(10),
                10,
                10_010,
                &mut rng,
            ),
        ],
    );
    let account = WalletScanAccount::new(WalletAccountId::from_bytes(ACCOUNT_ID).unwrap(), &owner);
    let update = scan_finalized_block(&persisted_tip, &second, &[account]).unwrap();
    restored.commit_finalized_block(update).unwrap();
    assert_eq!(
        restored.witness_for_spend(external_nullifier).unwrap_err(),
        WalletDbError::NoteAlreadySpent
    );
    assert!(restored.witness_for_spend(internal_nullifier).is_ok());
    drop(restored);
    let reopened = EncryptedWalletDb::open(
        &restored_path,
        &ROOT_KEY,
        ChainId::new(NETWORK),
        WALLET_ID,
        2,
    )
    .unwrap();
    assert_eq!(reopened.load_tip().unwrap().height(), 2);
}

#[cfg(unix)]
#[test]
fn backup_restore_rejects_mixups_rollback_corruption_truncation_and_splicing() {
    let temp = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(temp.path()).unwrap();
    let source_path = database_path(&temp);
    let backup_path = directory.join("wallet.vwb");
    let second_backup_path = directory.join("wallet-second.vwb");
    let owner = wallet(0xF1);
    let tip = initial_tip();
    let mut source =
        EncryptedWalletDb::create(&source_path, &ROOT_KEY, config(), tip.clone()).unwrap();
    let account = WalletScanAccount::new(WalletAccountId::from_bytes(ACCOUNT_ID).unwrap(), &owner);
    let update = scan_finalized_block(&tip, &first_block(&owner, &tip), &[account]).unwrap();
    source.commit_finalized_block(update).unwrap();
    source.export_backup(&backup_path, &ROOT_KEY).unwrap();
    source
        .export_backup(&second_backup_path, &ROOT_KEY)
        .unwrap();
    let original = fs::read(&backup_path).unwrap();
    let second = fs::read(&second_backup_path).unwrap();
    assert_eq!(original.len(), second.len());

    let wrong_root_destination = directory.join("wrong-root.sqlite3");
    assert_eq!(
        EncryptedWalletDb::restore_backup(
            &backup_path,
            &wrong_root_destination,
            &[0x92; 32],
            ChainId::new(NETWORK),
            WALLET_ID,
            0,
        )
        .unwrap_err(),
        WalletDbError::AuthenticationFailed
    );
    assert!(!wrong_root_destination.exists());

    let wrong_scope_destination = directory.join("wrong-scope.sqlite3");
    assert_eq!(
        EncryptedWalletDb::restore_backup(
            &backup_path,
            &wrong_scope_destination,
            &ROOT_KEY,
            ChainId::new([0x42; 32]),
            WALLET_ID,
            0,
        )
        .unwrap_err(),
        WalletDbError::ScopeMismatch
    );
    assert!(!wrong_scope_destination.exists());

    let rollback_destination = directory.join("rollback.sqlite3");
    assert_eq!(
        EncryptedWalletDb::restore_backup(
            &backup_path,
            &rollback_destination,
            &ROOT_KEY,
            ChainId::new(NETWORK),
            WALLET_ID,
            2,
        )
        .unwrap_err(),
        WalletDbError::RollbackDetected
    );
    assert!(!rollback_destination.exists());

    let existing_destination = directory.join("existing.sqlite3");
    write_private(&existing_destination, b"do-not-overwrite");
    assert_eq!(
        EncryptedWalletDb::restore_backup(
            &backup_path,
            &existing_destination,
            &ROOT_KEY,
            ChainId::new(NETWORK),
            WALLET_ID,
            0,
        )
        .unwrap_err(),
        WalletDbError::AlreadyExists
    );
    assert_eq!(
        fs::read(&existing_destination).unwrap(),
        b"do-not-overwrite"
    );

    let cases: [(&str, Vec<u8>, WalletDbError); 7] = [
        ("empty", Vec::new(), WalletDbError::InvalidBackup),
        (
            "short-header",
            original[..271].to_vec(),
            WalletDbError::InvalidBackup,
        ),
        (
            "truncated",
            original[..original.len() - 1].to_vec(),
            WalletDbError::InvalidBackup,
        ),
        (
            "appended",
            [original.as_slice(), &[0]].concat(),
            WalletDbError::InvalidBackup,
        ),
        (
            "bad-magic",
            {
                let mut bytes = original.clone();
                bytes[0] ^= 1;
                bytes
            },
            WalletDbError::InvalidBackup,
        ),
        (
            "bad-manifest",
            {
                let mut bytes = original.clone();
                bytes[64] ^= 1;
                bytes
            },
            WalletDbError::AuthenticationFailed,
        ),
        (
            "bad-padding",
            {
                let mut bytes = original.clone();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                bytes
            },
            WalletDbError::AuthenticationFailed,
        ),
    ];
    for (name, bytes, expected) in cases {
        let corrupted_path = directory.join(format!("{name}.vwb"));
        let destination = directory.join(format!("{name}.sqlite3"));
        write_private(&corrupted_path, &bytes);
        assert_eq!(
            EncryptedWalletDb::restore_backup(
                &corrupted_path,
                &destination,
                &ROOT_KEY,
                ChainId::new(NETWORK),
                WALLET_ID,
                0,
            )
            .unwrap_err(),
            expected,
            "case {name}"
        );
        assert!(!destination.exists(), "case {name}");
    }

    let mut first_chunk_corruption = original.clone();
    first_chunk_corruption[272] ^= 1;
    let first_chunk_path = directory.join("first-chunk.vwb");
    let first_chunk_destination = directory.join("first-chunk.sqlite3");
    write_private(&first_chunk_path, &first_chunk_corruption);
    assert_eq!(
        EncryptedWalletDb::restore_backup(
            &first_chunk_path,
            &first_chunk_destination,
            &ROOT_KEY,
            ChainId::new(NETWORK),
            WALLET_ID,
            0,
        )
        .unwrap_err(),
        WalletDbError::AuthenticationFailed
    );
    assert!(!first_chunk_destination.exists());

    let mut spliced = original.clone();
    spliced[272..272 + 65_552].copy_from_slice(&second[272..272 + 65_552]);
    let spliced_path = directory.join("spliced.vwb");
    let spliced_destination = directory.join("spliced.sqlite3");
    write_private(&spliced_path, &spliced);
    assert_eq!(
        EncryptedWalletDb::restore_backup(
            &spliced_path,
            &spliced_destination,
            &ROOT_KEY,
            ChainId::new(NETWORK),
            WALLET_ID,
            0,
        )
        .unwrap_err(),
        WalletDbError::AuthenticationFailed
    );
    assert!(!spliced_destination.exists());

    let permissive_path = directory.join("permissive.vwb");
    fs::copy(&backup_path, &permissive_path).unwrap();
    fs::set_permissions(&permissive_path, fs::Permissions::from_mode(0o644)).unwrap();
    let permissive_destination = directory.join("permissive.sqlite3");
    assert_eq!(
        EncryptedWalletDb::restore_backup(
            &permissive_path,
            &permissive_destination,
            &ROOT_KEY,
            ChainId::new(NETWORK),
            WALLET_ID,
            0,
        )
        .unwrap_err(),
        WalletDbError::UnsafeFile
    );
    assert!(!permissive_destination.exists());

    let symlink_path = directory.join("symlink.vwb");
    symlink(&backup_path, &symlink_path).unwrap();
    let symlink_destination = directory.join("symlink.sqlite3");
    assert_eq!(
        EncryptedWalletDb::restore_backup(
            &symlink_path,
            &symlink_destination,
            &ROOT_KEY,
            ChainId::new(NETWORK),
            WALLET_ID,
            0,
        )
        .unwrap_err(),
        WalletDbError::UnsafeFile
    );
    assert!(!symlink_destination.exists());

    let hardlink_path = directory.join("hardlink.vwb");
    fs::hard_link(&second_backup_path, &hardlink_path).unwrap();
    let hardlink_destination = directory.join("hardlink.sqlite3");
    assert_eq!(
        EncryptedWalletDb::restore_backup(
            &hardlink_path,
            &hardlink_destination,
            &ROOT_KEY,
            ChainId::new(NETWORK),
            WALLET_ID,
            0,
        )
        .unwrap_err(),
        WalletDbError::UnsafeFile
    );
    assert!(!hardlink_destination.exists());
}
