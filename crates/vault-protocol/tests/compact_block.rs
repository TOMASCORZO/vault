use proptest::prelude::*;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NoteCommitmentTree, PreparedNoteOutput, VaultSpendingKey,
};
use vault_protocol::{
    COMPACT_BLOCK_ACTION_BYTES, COMPACT_BLOCK_HEADER_BYTES, COMPACT_BLOCK_MAGIC,
    COMPACT_BLOCK_VERSION, ChainId, CompactBlock, CompactBlockAction, CompactBlockCommitment,
    CompactBlockError, CompactBlockTransaction, FinalizedCompactBlockHeader,
    MAX_COMPACT_BLOCK_ACTIONS, TransactionId,
};

const NETWORK: [u8; 32] = [0x31; 32];
const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;

fn nullifier(byte: u8) -> ActionNullifier {
    ActionNullifier::from_bytes([byte; 32]).unwrap()
}

fn compact_action(
    full_viewing_key: &vault_privacy::VaultFullViewingKey,
    byte: u8,
    rng: &mut ChaCha20Rng,
) -> CompactBlockAction {
    let action_nullifier = nullifier(byte);
    let output = PreparedNoteOutput::create(
        full_viewing_key,
        KeyScope::External,
        full_viewing_key.address_at(u32::from(byte), KeyScope::External),
        1_000 + u64::from(byte),
        MAXIMUM_VALUE,
        action_nullifier,
        [byte; MEMO_BYTES],
        rng,
    )
    .unwrap();
    CompactBlockAction::new(action_nullifier, output.encrypted_note().clone())
}

fn fixture_with_hash(block_hash: [u8; 32]) -> CompactBlock {
    let spending_key = VaultSpendingKey::derive(&[0xA5; 32], NETWORK, 0).unwrap();
    let full_viewing_key = spending_key.full_viewing_key();
    let mut rng = ChaCha20Rng::from_seed([0x81; 32]);
    let actions = vec![
        compact_action(&full_viewing_key, 1, &mut rng),
        compact_action(&full_viewing_key, 2, &mut rng),
    ];
    let transaction =
        CompactBlockTransaction::new(TransactionId::new([0x71; 32]), actions).unwrap();
    let pre_tree = NoteCommitmentTree::new();
    let mut post_tree = pre_tree.clone();
    for action in transaction.actions() {
        post_tree.append(action.output().note_commitment()).unwrap();
    }
    CompactBlock::new(
        ChainId::new(NETWORK),
        1,
        block_hash,
        [0x60; 32],
        pre_tree.size(),
        pre_tree.typed_root(),
        post_tree.size(),
        post_tree.typed_root(),
        vec![transaction],
    )
    .unwrap()
}

fn finalized_header(block: &CompactBlock) -> FinalizedCompactBlockHeader {
    FinalizedCompactBlockHeader::from_verified_consensus(
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
    .unwrap()
}

#[test]
fn canonical_codec_header_authentication_and_tree_replay_are_exact() {
    let block = fixture_with_hash([0x61; 32]);
    let encoded = block.encode();
    assert_eq!(&encoded[..4], &COMPACT_BLOCK_MAGIC);
    assert_eq!(
        u16::from_le_bytes(encoded[4..6].try_into().unwrap()),
        COMPACT_BLOCK_VERSION
    );
    assert_eq!(
        encoded.len(),
        COMPACT_BLOCK_HEADER_BYTES + 33 + COMPACT_BLOCK_ACTION_BYTES * 2
    );
    assert_eq!(block.encoded_len(), encoded.len());

    let decoded = CompactBlock::decode(&encoded).unwrap();
    assert_eq!(decoded.encode(), encoded);
    assert_eq!(decoded, block);
    let authenticated = decoded.authenticate(finalized_header(&block)).unwrap();
    let post_tree = authenticated
        .block()
        .verify_tree_transition(&NoteCommitmentTree::new())
        .unwrap();
    assert_eq!(post_tree.size(), 2);
    assert_eq!(post_tree.typed_root(), block.post_tree_root());

    let different_hash = fixture_with_hash([0x62; 32]);
    assert_eq!(block.commitment(), different_hash.commitment());
    assert_ne!(block.block_hash(), different_hash.block_hash());
    assert_eq!(
        different_hash
            .authenticate(finalized_header(&block))
            .unwrap_err(),
        CompactBlockError::HeaderMismatch
    );
}

#[test]
fn parser_rejects_noncanonical_counts_lengths_actions_and_duplicates() {
    let block = fixture_with_hash([0x61; 32]);
    let original = block.encode();

    for prefix_length in 0..original.len() {
        assert!(
            CompactBlock::decode(&original[..prefix_length]).is_err(),
            "truncated prefix {prefix_length} was accepted"
        );
    }
    let mut trailing = original.clone();
    trailing.push(0);
    assert_eq!(
        CompactBlock::decode(&trailing).unwrap_err(),
        CompactBlockError::InvalidEncoding
    );

    let mut wrong_magic = original.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        CompactBlock::decode(&wrong_magic).unwrap_err(),
        CompactBlockError::InvalidEncoding
    );
    let mut wrong_version = original.clone();
    wrong_version[4] ^= 1;
    assert_eq!(
        CompactBlock::decode(&wrong_version).unwrap_err(),
        CompactBlockError::UnsupportedVersion
    );
    let mut wrong_tx_count = original.clone();
    wrong_tx_count[190..194].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(
        CompactBlock::decode(&wrong_tx_count).unwrap_err(),
        CompactBlockError::InvalidEncoding
    );
    let mut oversized_actions = original.clone();
    oversized_actions[194..198].copy_from_slice(
        &u32::try_from(MAX_COMPACT_BLOCK_ACTIONS + 1)
            .unwrap()
            .to_le_bytes(),
    );
    assert_eq!(
        CompactBlock::decode(&oversized_actions).unwrap_err(),
        CompactBlockError::ResourceLimitExceeded
    );
    let mut invalid_bucket = original.clone();
    invalid_bucket[230] = 3;
    assert_eq!(
        CompactBlock::decode(&invalid_bucket).unwrap_err(),
        CompactBlockError::InvalidTransaction
    );

    let second_action = COMPACT_BLOCK_HEADER_BYTES + 33 + COMPACT_BLOCK_ACTION_BYTES;
    let first_action = COMPACT_BLOCK_HEADER_BYTES + 33;
    let mut duplicate_nullifier = original.clone();
    duplicate_nullifier[second_action..second_action + 32]
        .copy_from_slice(&original[first_action..first_action + 32]);
    assert_eq!(
        CompactBlock::decode(&duplicate_nullifier).unwrap_err(),
        CompactBlockError::InvalidTransaction
    );
    let mut duplicate_commitment = original.clone();
    duplicate_commitment[second_action + 32..second_action + 64]
        .copy_from_slice(&original[first_action + 32..first_action + 64]);
    assert_eq!(
        CompactBlock::decode(&duplicate_commitment).unwrap_err(),
        CompactBlockError::DuplicateNoteCommitment
    );
}

#[test]
fn ciphertext_or_tree_substitution_cannot_pass_both_header_and_tree_checks() {
    let block = fixture_with_hash([0x61; 32]);
    let header = finalized_header(&block);
    let mut ciphertext_mutation = block.encode();
    let ciphertext_offset = COMPACT_BLOCK_HEADER_BYTES + 33 + 32 + 32 + 32 + 32;
    ciphertext_mutation[ciphertext_offset] ^= 1;
    let mutated = CompactBlock::decode(&ciphertext_mutation).unwrap();
    assert_eq!(
        mutated.authenticate(header).unwrap_err(),
        CompactBlockError::HeaderMismatch
    );

    let wrong_root = CompactBlock::new(
        block.chain_id(),
        block.height(),
        block.block_hash(),
        block.parent_hash(),
        block.pre_tree_size(),
        block.pre_tree_root(),
        block.post_tree_size(),
        block.pre_tree_root(),
        block.transactions().to_vec(),
    )
    .unwrap();
    assert_eq!(
        wrong_root
            .verify_tree_transition(&NoteCommitmentTree::new())
            .unwrap_err(),
        CompactBlockError::InvalidTreeTransition
    );

    assert_eq!(
        CompactBlockCommitment::from_bytes([0; 32]).unwrap_err(),
        CompactBlockError::InvalidBlockIdentity
    );
}

proptest! {
    #[test]
    fn decoder_never_panics_on_bounded_untrusted_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..16_384)
    ) {
        let _ = CompactBlock::decode(&bytes);
    }
}
