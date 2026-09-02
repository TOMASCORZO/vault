use std::fmt;

use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NoteCommitmentTree, NoteTreeSnapshot,
    PreparedNoteOutput, VaultFullViewingKey, VaultSpendingKey,
};
use vault_protocol::{
    ChainId, CompactBlock, CompactBlockAction, CompactBlockTransaction,
    FinalizedCompactBlockHeader, TransactionId,
};
use vault_wallet::{
    FinalizedWalletStore, MAX_SCAN_ACCOUNTS, ScanCommitError, ScannedBlockUpdate, WalletAccountId,
    WalletRecoveryAccounts, WalletRecoveryError, WalletScanAccount, WalletScanError, WalletScanTip,
    WalletSeedMaterial, scan_and_commit, scan_finalized_block,
};
use zeroize::Zeroizing;

const NETWORK: [u8; 32] = [0x31; 32];
const GENESIS_HASH: [u8; 32] = [0x60; 32];
const BLOCK_HASH: [u8; 32] = [0x61; 32];
const SECOND_BLOCK_HASH: [u8; 32] = [0x62; 32];
const FIRST_ACCOUNT_ID: [u8; 32] = [0xD1; 32];
const SECOND_ACCOUNT_ID: [u8; 32] = [0xD2; 32];
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

fn action_with_nullifier(
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

fn action(
    owner: &VaultFullViewingKey,
    scope: KeyScope,
    byte: u8,
    value: u64,
    rng: &mut ChaCha20Rng,
) -> CompactBlockAction {
    action_with_nullifier(owner, scope, nullifier(byte), byte, value, rng)
}

struct Fixture {
    tip: WalletScanTip,
    block: vault_protocol::AuthenticatedCompactBlock,
    first: VaultFullViewingKey,
    second: VaultFullViewingKey,
}

fn fixture() -> Fixture {
    let first = wallet(0xA1);
    let second = wallet(0xA2);
    let unrelated = wallet(0xA3);
    let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
    let actions = vec![
        action(&first, KeyScope::External, 1, 1_001, &mut rng),
        action(&second, KeyScope::External, 2, 2_002, &mut rng),
        action(&unrelated, KeyScope::External, 3, 3_003, &mut rng),
        action(&first, KeyScope::Internal, 4, 4_004, &mut rng),
    ];
    let transaction =
        CompactBlockTransaction::new(TransactionId::new([0x71; 32]), actions).unwrap();
    let pre_tree = NoteCommitmentTree::new();
    let mut post_tree = pre_tree.clone();
    for item in transaction.actions() {
        post_tree.append(item.output().note_commitment()).unwrap();
    }
    let block = CompactBlock::new(
        ChainId::new(NETWORK),
        1,
        BLOCK_HASH,
        GENESIS_HASH,
        0,
        pre_tree.typed_root(),
        4,
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
    let block = block.authenticate(header).unwrap();
    let tip = WalletScanTip::from_verified_checkpoint(
        ChainId::new(NETWORK),
        0,
        GENESIS_HASH,
        &pre_tree.snapshot(),
    )
    .unwrap();
    Fixture {
        tip,
        block,
        first,
        second,
    }
}

fn scan_accounts(fixture: &Fixture) -> [WalletScanAccount<'_>; 2] {
    [
        WalletScanAccount::new(
            WalletAccountId::from_bytes(FIRST_ACCOUNT_ID).unwrap(),
            &fixture.first,
        ),
        WalletScanAccount::new(
            WalletAccountId::from_bytes(SECOND_ACCOUNT_ID).unwrap(),
            &fixture.second,
        ),
    ]
}

fn block_extending(
    tip: &WalletScanTip,
    block_hash: [u8; 32],
    transaction_id: [u8; 32],
    mut actions: Vec<CompactBlockAction>,
) -> vault_protocol::AuthenticatedCompactBlock {
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
    block.authenticate(header).unwrap()
}

#[test]
fn complete_finalized_block_scan_finds_owned_notes_and_exact_positions() {
    let fixture = fixture();
    let accounts = scan_accounts(&fixture);
    let update = scan_finalized_block(&fixture.tip, &fixture.block, &accounts).unwrap();

    assert_eq!(update.expected_parent_height(), 0);
    assert_eq!(update.expected_parent_hash(), GENESIS_HASH);
    assert_eq!(update.expected_pre_tree_size(), 0);
    assert_eq!(update.next_tip().height(), 1);
    assert_eq!(update.next_tip().block_hash(), BLOCK_HASH);
    assert_eq!(update.next_tip().tree_size(), 4);
    assert_eq!(
        update.next_tip().tree_root(),
        fixture.block.block().post_tree_root()
    );
    assert_eq!(update.nullifiers().len(), 4);
    assert_eq!(update.note_commitments().len(), 4);
    assert_eq!(update.detected_notes().len(), 3);

    let positions = update
        .detected_notes()
        .iter()
        .map(|note| note.position())
        .collect::<Vec<_>>();
    assert_eq!(positions, vec![0, 1, 3]);
    assert_eq!(
        update.detected_notes()[0].account_id().to_bytes(),
        FIRST_ACCOUNT_ID
    );
    assert_eq!(
        update.detected_notes()[1].account_id().to_bytes(),
        SECOND_ACCOUNT_ID
    );
    assert_eq!(
        update.detected_notes()[2].account_id().to_bytes(),
        FIRST_ACCOUNT_ID
    );
    assert_eq!(update.detected_notes()[0].key_scope(), KeyScope::External);
    assert_eq!(update.detected_notes()[1].key_scope(), KeyScope::External);
    assert_eq!(update.detected_notes()[2].key_scope(), KeyScope::Internal);
    assert_eq!(update.detected_notes()[0].decrypted().note().value(), 1_001);
    assert_eq!(update.detected_notes()[1].decrypted().note().value(), 2_002);
    assert_eq!(update.detected_notes()[2].decrypted().note().value(), 4_004);
    assert_eq!(
        *update.detected_notes()[2].decrypted().memo(),
        [4; MEMO_BYTES]
    );
    for note in update.detected_notes() {
        assert_eq!(
            note.decrypted().note().commitment().unwrap(),
            note.output().note_commitment()
        );
    }
    assert_eq!(
        update.detected_notes()[0].spend_nullifier(),
        fixture
            .first
            .note_nullifier(update.detected_notes()[0].decrypted().note())
            .unwrap()
    );
    assert!(format!("{update:?}").contains("REDACTED"));
    assert_eq!(
        format!("{:?}", update.detected_notes()[0].account_id()),
        "WalletAccountId(REDACTED)"
    );
}

#[test]
fn derived_owned_nullifier_matches_a_later_public_spend_without_remote_query() {
    let fixture = fixture();
    let accounts = scan_accounts(&fixture);
    let first_update = scan_finalized_block(&fixture.tip, &fixture.block, &accounts).unwrap();
    let spent_nullifier = first_update.detected_notes()[0].spend_nullifier();
    let first_post_tip = first_update.next_tip().clone();

    let unrelated = wallet(0xA4);
    let mut rng = ChaCha20Rng::from_seed([0x92; 32]);
    let second_block = block_extending(
        &first_post_tip,
        SECOND_BLOCK_HASH,
        [0x72; 32],
        vec![
            action_with_nullifier(
                &unrelated,
                KeyScope::External,
                spent_nullifier,
                5,
                5_005,
                &mut rng,
            ),
            action(&unrelated, KeyScope::External, 6, 6_006, &mut rng),
        ],
    );
    let second_update = scan_finalized_block(&first_post_tip, &second_block, &accounts).unwrap();

    assert_eq!(second_update.next_tip().height(), 2);
    assert!(second_update.nullifiers().contains(&spent_nullifier));
    assert!(second_update.detected_notes().is_empty());
}

#[test]
fn network_height_parent_and_pre_tree_mismatches_fail_before_decryption() {
    let fixture = fixture();
    let wrong_network = WalletScanTip::from_verified_checkpoint(
        ChainId::new([0x32; 32]),
        0,
        GENESIS_HASH,
        &NoteCommitmentTree::new().snapshot(),
    )
    .unwrap();
    assert_eq!(
        scan_finalized_block(&wrong_network, &fixture.block, &[]).unwrap_err(),
        WalletScanError::WrongNetwork
    );
    let wrong_height = WalletScanTip::from_verified_checkpoint(
        ChainId::new(NETWORK),
        8,
        GENESIS_HASH,
        &NoteCommitmentTree::new().snapshot(),
    )
    .unwrap();
    assert_eq!(
        scan_finalized_block(&wrong_height, &fixture.block, &[]).unwrap_err(),
        WalletScanError::HeightDiscontinuity
    );
    let wrong_parent = WalletScanTip::from_verified_checkpoint(
        ChainId::new(NETWORK),
        0,
        [0x62; 32],
        &NoteCommitmentTree::new().snapshot(),
    )
    .unwrap();
    assert_eq!(
        scan_finalized_block(&wrong_parent, &fixture.block, &[]).unwrap_err(),
        WalletScanError::ParentMismatch
    );

    let mut nonempty_tree = NoteCommitmentTree::new();
    nonempty_tree
        .append(
            fixture.block.block().transactions()[0].actions()[0]
                .output()
                .note_commitment(),
        )
        .unwrap();
    let wrong_tree = WalletScanTip::from_verified_checkpoint(
        ChainId::new(NETWORK),
        0,
        GENESIS_HASH,
        &nonempty_tree.snapshot(),
    )
    .unwrap();
    assert_eq!(
        scan_finalized_block(&wrong_tree, &fixture.block, &[]).unwrap_err(),
        WalletScanError::ParentMismatch
    );

    assert_eq!(
        WalletScanTip::from_verified_checkpoint(
            ChainId::new([0; 32]),
            0,
            GENESIS_HASH,
            &NoteCommitmentTree::new().snapshot(),
        )
        .unwrap_err(),
        WalletScanError::InvalidCheckpoint
    );
    let invalid_snapshot = NoteTreeSnapshot::from_parts(1, None, vec![]);
    assert_eq!(
        WalletScanTip::from_verified_checkpoint(
            ChainId::new(NETWORK),
            0,
            GENESIS_HASH,
            &invalid_snapshot,
        )
        .unwrap_err(),
        WalletScanError::InvalidCheckpoint
    );
}

#[test]
fn scan_accounts_are_bounded_unique_and_include_both_scopes() {
    assert_eq!(
        WalletAccountId::from_bytes([0; 32]).unwrap_err(),
        WalletScanError::InvalidAccountId
    );

    let fixture = fixture();
    let duplicate_id = WalletAccountId::from_bytes(FIRST_ACCOUNT_ID).unwrap();
    let duplicate_ids = [
        WalletScanAccount::new(duplicate_id, &fixture.first),
        WalletScanAccount::new(duplicate_id, &fixture.second),
    ];
    assert_eq!(
        scan_finalized_block(&fixture.tip, &fixture.block, &duplicate_ids).unwrap_err(),
        WalletScanError::DuplicateScanAccountId
    );

    let duplicate_capabilities = [
        WalletScanAccount::new(
            WalletAccountId::from_bytes(FIRST_ACCOUNT_ID).unwrap(),
            &fixture.first,
        ),
        WalletScanAccount::new(
            WalletAccountId::from_bytes(SECOND_ACCOUNT_ID).unwrap(),
            &fixture.first,
        ),
    ];
    assert_eq!(
        scan_finalized_block(&fixture.tip, &fixture.block, &duplicate_capabilities).unwrap_err(),
        WalletScanError::DuplicateScanCapability
    );

    let full_viewing_keys = (0..=MAX_SCAN_ACCOUNTS)
        .map(|index| {
            VaultSpendingKey::derive(&[0xB0; 32], NETWORK, u32::try_from(index).unwrap())
                .unwrap()
                .full_viewing_key()
        })
        .collect::<Vec<_>>();
    let too_many = full_viewing_keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let mut id = [0; 32];
            id[0] = u8::try_from(index + 1).unwrap();
            WalletScanAccount::new(WalletAccountId::from_bytes(id).unwrap(), key)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        scan_finalized_block(&fixture.tip, &fixture.block, &too_many).unwrap_err(),
        WalletScanError::TooManyScanAccounts
    );
}

#[test]
fn deterministic_seed_accounts_cross_primitive_batches_without_retaining_spending_keys() {
    let seed = recovery_seed(0xC7);
    let accounts = WalletRecoveryAccounts::derive(&seed, ChainId::new(NETWORK), 20).unwrap();
    let repeated = WalletRecoveryAccounts::derive(&seed, ChainId::new(NETWORK), 20).unwrap();
    assert_eq!(format!("{accounts:?}"), "WalletRecoveryAccounts(REDACTED)");
    assert_eq!(accounts.account_count(), 20);
    for index in 0..20 {
        assert_eq!(accounts.account_id(index), repeated.account_id(index));
        assert_eq!(
            accounts.full_viewing_key(index).unwrap().export().as_ref(),
            repeated.full_viewing_key(index).unwrap().export().as_ref()
        );
    }
    let other_network =
        WalletRecoveryAccounts::derive(&seed, ChainId::new([0x32; 32]), 20).unwrap();
    assert_ne!(accounts.account_id(17), other_network.account_id(17));
    assert_eq!(
        WalletRecoveryAccounts::derive(&seed, ChainId::new(NETWORK), 0).unwrap_err(),
        WalletRecoveryError::InvalidAccountCount
    );
    assert_eq!(
        WalletRecoveryAccounts::derive(&seed, ChainId::new(NETWORK), MAX_SCAN_ACCOUNTS + 1,)
            .unwrap_err(),
        WalletRecoveryError::InvalidAccountCount
    );

    let tip = WalletScanTip::from_verified_checkpoint(
        ChainId::new(NETWORK),
        0,
        GENESIS_HASH,
        &NoteCommitmentTree::new().snapshot(),
    )
    .unwrap();
    let unrelated = wallet(0xC8);
    let mut rng = ChaCha20Rng::from_seed([0xC9; 32]);
    let block = block_extending(
        &tip,
        [0xCA; 32],
        [0xCB; 32],
        vec![
            action_with_nullifier(
                accounts.full_viewing_key(17).unwrap(),
                KeyScope::External,
                nullifier(41),
                41,
                41_041,
                &mut rng,
            ),
            action_with_nullifier(
                &unrelated,
                KeyScope::External,
                nullifier(42),
                42,
                42_042,
                &mut rng,
            ),
        ],
    );
    let update = scan_finalized_block(&tip, &block, &accounts.scan_accounts()).unwrap();
    assert_eq!(update.detected_notes().len(), 1);
    assert_eq!(
        update.detected_notes()[0].account_id(),
        accounts.account_id(17).unwrap()
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TestStoreError;

impl fmt::Display for TestStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("test store failure")
    }
}

impl std::error::Error for TestStoreError {}

struct RecordingStore {
    tip: WalletScanTip,
    fail_commit: bool,
    committed_actions: usize,
    committed_notes: usize,
}

impl FinalizedWalletStore for RecordingStore {
    type Error = TestStoreError;

    fn load_tip(&self) -> Result<WalletScanTip, Self::Error> {
        Ok(self.tip.clone())
    }

    fn commit_finalized_block(&mut self, update: ScannedBlockUpdate) -> Result<(), Self::Error> {
        if self.fail_commit {
            return Err(TestStoreError);
        }
        assert_eq!(self.tip.height(), update.expected_parent_height());
        assert_eq!(self.tip.block_hash(), update.expected_parent_hash());
        assert_eq!(self.tip.tree_size(), update.expected_pre_tree_size());
        assert_eq!(self.tip.tree_root(), update.expected_pre_tree_root());
        self.committed_actions = update.nullifiers().len();
        self.committed_notes = update.detected_notes().len();
        self.tip = update.next_tip().clone();
        Ok(())
    }
}

#[test]
fn store_commit_failure_does_not_report_or_advance_success() {
    let fixture = fixture();
    let accounts = scan_accounts(&fixture);
    let mut store = RecordingStore {
        tip: fixture.tip.clone(),
        fail_commit: true,
        committed_actions: 0,
        committed_notes: 0,
    };
    assert!(matches!(
        scan_and_commit(&mut store, &fixture.block, &accounts),
        Err(ScanCommitError::Store(TestStoreError))
    ));
    assert_eq!(store.tip, fixture.tip);
    assert_eq!(store.committed_actions, 0);
    assert_eq!(store.committed_notes, 0);

    store.fail_commit = false;
    let summary = scan_and_commit(&mut store, &fixture.block, &accounts).unwrap();
    assert_eq!(summary.height(), 1);
    assert_eq!(summary.action_count(), 4);
    assert_eq!(store.tip.height(), 1);
    assert_eq!(store.committed_actions, 4);
    assert_eq!(store.committed_notes, 3);
}
