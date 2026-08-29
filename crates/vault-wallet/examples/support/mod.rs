//! Shared deterministic fixtures for opt-in H1-A2 acceptance harnesses.
//!
//! The constants in this module are public fixture material. They must never
//! be reused for a live wallet or with real funds.

use std::path::Path;

use blake3::Hasher;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NoteCommitmentTree, PreparedNoteOutput,
    VaultFullViewingKey, VaultSpendingKey,
};
use vault_protocol::{
    ChainId, CompactBlock, CompactBlockAction, CompactBlockTransaction,
    FinalizedCompactBlockHeader, TransactionId,
};
use vault_wallet::{
    EncryptedWalletDb, ScannedBlockUpdate, WalletAccountId, WalletDatabaseConfig,
    WalletScanAccount, WalletScanTip, scan_finalized_block,
};

const CHAIN_ID: [u8; 32] = [0xA2; 32];
const GENESIS_HASH: [u8; 32] = [0xA3; 32];
const WALLET_ID: [u8; 32] = [0xA4; 32];
const ROOT_KEY: [u8; 32] = [0xA5; 32];
const ACCOUNT_ID: [u8; 32] = [0xA6; 32];
const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;

pub const MAX_BLOCKS: u64 = 1_000_000;

pub const fn chain_id() -> ChainId {
    ChainId::new(CHAIN_ID)
}

pub const fn wallet_id() -> [u8; 32] {
    WALLET_ID
}

pub const fn root_key() -> &'static [u8; 32] {
    &ROOT_KEY
}

pub fn initial_tip() -> WalletScanTip {
    WalletScanTip::from_verified_checkpoint(
        chain_id(),
        0,
        GENESIS_HASH,
        &NoteCommitmentTree::new().snapshot(),
    )
    .expect("fixed empty fixture checkpoint is valid")
}

pub fn create_database(path: &Path, max_checkpoints: usize) -> EncryptedWalletDb {
    let config = WalletDatabaseConfig::new(WALLET_ID, MAXIMUM_VALUE, max_checkpoints)
        .expect("bounded fixture database policy is valid");
    EncryptedWalletDb::create(path, &ROOT_KEY, config, initial_tip())
        .expect("fixture database creation succeeds")
}

pub struct SyntheticWalletFixture {
    scanner: VaultFullViewingKey,
    recipient: VaultFullViewingKey,
    owns_outputs: bool,
}

impl SyntheticWalletFixture {
    pub fn new(owns_outputs: bool) -> Self {
        let scanner = VaultSpendingKey::derive(&[0xB1; 32], CHAIN_ID, 0)
            .expect("fixed scanner key is valid")
            .full_viewing_key();
        let recipient_seed = if owns_outputs { [0xB1; 32] } else { [0xB2; 32] };
        Self {
            scanner,
            recipient: VaultSpendingKey::derive(&recipient_seed, CHAIN_ID, 0)
                .expect("fixed recipient key is valid")
                .full_viewing_key(),
            owns_outputs,
        }
    }

    pub fn next_update(
        &self,
        tip: &WalletScanTip,
        height: u64,
        actions_per_block: usize,
    ) -> ScannedBlockUpdate {
        let (block, header) = self.build_block(tip, height, actions_per_block);
        let authenticated = block
            .authenticate(header)
            .expect("fixture header authenticates its compact block");
        let account = WalletScanAccount::new(
            WalletAccountId::from_bytes(ACCOUNT_ID).expect("fixture account ID is valid"),
            &self.scanner,
        );
        let update = scan_finalized_block(tip, &authenticated, &[account])
            .expect("fixture compact block scans");
        assert_eq!(
            update.detected_notes().len(),
            if self.owns_outputs {
                actions_per_block
            } else {
                0
            }
        );
        update
    }

    fn build_block(
        &self,
        tip: &WalletScanTip,
        height: u64,
        actions_per_block: usize,
    ) -> (CompactBlock, FinalizedCompactBlockHeader) {
        let mut rng =
            ChaCha20Rng::from_seed(derived_bytes("vault.h1-a2.history.block-rng.v1", height));
        let mut actions = Vec::with_capacity(actions_per_block);
        for action_index in 0..actions_per_block {
            let ordinal = height
                .checked_mul(16)
                .and_then(|value| value.checked_add(action_index as u64))
                .expect("bounded history ordinal");
            let nullifier = action_nullifier(ordinal);
            let address_index = u32::try_from(ordinal).expect("bounded history address index");
            let output = PreparedNoteOutput::create(
                &self.recipient,
                KeyScope::External,
                self.recipient.address_at(address_index, KeyScope::External),
                ordinal.saturating_add(1),
                MAXIMUM_VALUE,
                nullifier,
                [u8::try_from(action_index).expect("bounded action index"); MEMO_BYTES],
                &mut rng,
            )
            .expect("fixed fixture output is valid");
            actions.push(CompactBlockAction::new(
                nullifier,
                output.encrypted_note().clone(),
            ));
        }
        actions.sort_by_key(CompactBlockAction::nullifier);
        let mut post_tree =
            NoteCommitmentTree::restore(&tip.tree_snapshot()).expect("validated tip tree restores");
        for action in &actions {
            post_tree
                .append(action.output().note_commitment())
                .expect("bounded fixture tree has capacity");
        }
        let transaction = CompactBlockTransaction::new(
            TransactionId::new(derived_bytes("vault.h1-a2.history.transaction.v1", height)),
            actions,
        )
        .expect("fixture transaction is canonical");
        let block_hash = derived_bytes("vault.h1-a2.history.block.v1", height);
        let block = CompactBlock::new(
            tip.chain_id(),
            height,
            block_hash,
            tip.block_hash(),
            tip.tree_size(),
            tip.tree_root(),
            post_tree.size(),
            post_tree.typed_root(),
            vec![transaction],
        )
        .expect("fixture block transition is valid");
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
        .expect("fixture finalized header is valid");
        (block, header)
    }
}

fn derived_bytes(context: &str, value: u64) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(context);
    hasher.update(&value.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn action_nullifier(value: u64) -> ActionNullifier {
    for counter in 0..=u8::MAX {
        let mut hasher = Hasher::new_derive_key("vault.h1-a2.history.nullifier.v1");
        hasher.update(&value.to_be_bytes());
        hasher.update(&[counter]);
        if let Ok(nullifier) = ActionNullifier::from_bytes(*hasher.finalize().as_bytes()) {
            return nullifier;
        }
    }
    panic!("bounded fixture nullifier rejection sampling exhausted")
}
