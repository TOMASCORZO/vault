//! Deterministic private fixture shared by native tests and real proving.

use incrementalmerkletree::{Hashable, Level};
use orchard::{
    note::ExtractedNoteCommitment,
    tree::{MerkleHashOrchard, MerklePath},
};
use pasta_curves::{
    group::{Group, GroupEncoding},
    pallas,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_burn::{EpochBurnPublicKey, PreparedBurnCiphertext};
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NoteMembershipPath, NoteTreeRoot, OutputKind,
    PreparedBurnCommitment, PreparedNetValueCommitment, PreparedNoteOutput, PrivateNote,
    RandomizedSpendValidatingKey, VaultSpendingKey,
};
use vault_protocol::{
    ChainId, CircuitId, EncryptedBurnV2, GasParameters, TransferV2Action, TransferV2Effects,
};
use vault_zk_transfer_core::{
    BurnOpeningWitness, EpochKeyClaim, MAXIMUM_NATIVE_VALUE, REFERENCE_STATEMENT_VERSION,
    ReferenceActionWitness, TransferV2ReferenceClaim,
};

const NETWORK: [u8; 32] = [0x31; 32];
const CIRCUIT_ID: [u8; 32] = [0xc4; 32];
const GAS_UNITS: u64 = 25;
const FEE_PER_GAS: u64 = 1;
const EPOCH: u64 = 9;

/// One deterministic valid claim and its decoded public effects.
pub struct ReferenceFixture {
    /// Complete private claim sent only to the guest.
    pub claim: TransferV2ReferenceClaim,
    /// Canonical public effects used to check the receipt journal.
    pub effects: TransferV2Effects,
}

/// Builds a valid external-payment plus exact-receiver internal-change bundle.
#[must_use]
pub fn reference_fixture() -> ReferenceFixture {
    let spending_key = VaultSpendingKey::derive(&[0xa5; 32], NETWORK, 0)
        .expect("deterministic fixture spending key");
    let full_viewing_key = spending_key.full_viewing_key();
    let external_input = full_viewing_key.address_at(0, KeyScope::External);
    let internal_input = full_viewing_key.address_at(1, KeyScope::Internal);
    let external_recipient = VaultSpendingKey::derive(&[0xb6; 32], NETWORK, 0)
        .expect("deterministic recipient key")
        .full_viewing_key()
        .address_at(7, KeyScope::External);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);

    let inputs = [
        PrivateNote::create(
            external_input,
            5_050,
            MAXIMUM_NATIVE_VALUE,
            seed_nullifier(2),
            &mut rng,
        )
        .expect("valid external input"),
        PrivateNote::create(
            internal_input,
            1_000,
            MAXIMUM_NATIVE_VALUE,
            seed_nullifier(3),
            &mut rng,
        )
        .expect("valid internal input"),
    ];
    let commitments = inputs
        .iter()
        .map(|note| note.commitment().expect("valid input commitment"))
        .collect::<Vec<_>>()
        .try_into()
        .expect("two inputs");
    let (anchor, paths) = two_leaf_paths(commitments);
    let output_recipients = [external_recipient, internal_input];
    let output_values = [5_000, 1_000];
    let output_kinds = [OutputKind::ExternalPayment, OutputKind::InternalChange];
    let sender_scopes = [KeyScope::External, KeyScope::Internal];

    let full_viewing_key_bytes = full_viewing_key.export();
    let mut entries = Vec::with_capacity(2);
    for (index, (input, path)) in inputs.into_iter().zip(paths).enumerate() {
        let action_nullifier = full_viewing_key
            .note_nullifier(&input)
            .expect("valid action nullifier");
        let output = PreparedNoteOutput::create(
            &full_viewing_key,
            sender_scopes[index],
            output_recipients[index],
            output_values[index],
            MAXIMUM_NATIVE_VALUE,
            action_nullifier,
            [u8::try_from(index).expect("fixture index"); MEMO_BYTES],
            &mut rng,
        )
        .expect("valid output");
        let authorization = spending_key
            .prepare_spend_authorization(&mut rng)
            .expect("valid randomized authorization");
        let net_value =
            PreparedNetValueCommitment::create(input.value(), output_values[index], &mut rng)
                .expect("valid net commitment");
        let public_action = TransferV2Action::new(
            action_nullifier,
            RandomizedSpendValidatingKey::from_bytes(authorization.randomized_verification_key())
                .expect("valid randomized key"),
            net_value.commitment(),
            output.encrypted_note().clone(),
        );
        let packet = output
            .authorization_packet(NETWORK, output_kinds[index])
            .expect("valid reference packet")
            .encode();
        let input_note = input.encode_private();
        let witness = ReferenceActionWitness {
            full_viewing_key: full_viewing_key_bytes.to_vec(),
            input_note: input_note.to_vec(),
            membership_position: path.position(),
            membership_auth_path: path.auth_path().to_vec(),
            authorization_randomizer: *authorization.randomizer(),
            net_value_trapdoor: *net_value.trapdoor(),
            output_authorization_packet: packet.to_vec(),
        };
        entries.push((action_nullifier, public_action, witness));
    }
    entries.sort_by_key(|entry| entry.0);

    let coefficient_scalars = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
    let coefficient_commitments =
        coefficient_scalars.map(|value| (pallas::Point::generator() * value).to_bytes());
    let participants = vec![1, 2, 3];
    let epoch_key = EpochBurnPublicKey::from_parts(
        EPOCH,
        2,
        participants.clone(),
        coefficient_commitments.to_vec(),
    )
    .expect("valid epoch key");
    let burn_amount = 25;
    let burn_commitment =
        PreparedBurnCommitment::create(burn_amount, MAXIMUM_NATIVE_VALUE, &mut rng)
            .expect("valid burn commitment");
    let burn_ciphertext =
        PreparedBurnCiphertext::encrypt(burn_amount, MAXIMUM_NATIVE_VALUE, &epoch_key, &mut rng)
            .expect("valid burn ciphertext");
    let burn_payload = EncryptedBurnV2::from_threshold_ciphertext(
        &epoch_key,
        burn_commitment.commitment(),
        burn_ciphertext.ciphertext(),
    )
    .expect("valid public burn payload");

    let (public_actions, private_actions): (Vec<_>, Vec<_>) = entries
        .into_iter()
        .map(|(_, public, private)| (public, private))
        .unzip();
    let effects = TransferV2Effects::new(
        ChainId::new(NETWORK),
        CircuitId::new(CIRCUIT_ID),
        anchor,
        burn_payload,
        GasParameters {
            units: GAS_UNITS,
            fee_per_gas: FEE_PER_GAS,
        },
        public_actions,
    )
    .expect("valid canonical effects");
    let claim = TransferV2ReferenceClaim {
        statement_version: REFERENCE_STATEMENT_VERSION,
        effects: effects.encode_canonical(),
        actions: private_actions,
        epoch_key: EpochKeyClaim {
            epoch: EPOCH,
            threshold: 2,
            participants,
            coefficient_commitments: coefficient_commitments.to_vec(),
        },
        burn: BurnOpeningWitness {
            commitment_trapdoor: *burn_commitment.trapdoor(),
            encryption_randomness: *burn_ciphertext.randomness(),
        },
    };

    ReferenceFixture { claim, effects }
}

fn seed_nullifier(byte: u8) -> ActionNullifier {
    ActionNullifier::from_bytes([byte; 32]).expect("canonical deterministic rho")
}

fn two_leaf_paths(commitments: [[u8; 32]; 2]) -> (NoteTreeRoot, [NoteMembershipPath; 2]) {
    let commitments = commitments.map(|bytes| {
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&bytes))
            .expect("canonical note commitment")
    });
    let leaves = commitments.map(|cmx| MerkleHashOrchard::from_cmx(&cmx));
    let paths = [0_u32, 1_u32].map(|position| {
        let mut nodes = [MerkleHashOrchard::empty_leaf(); 32];
        nodes[0] = leaves[1 - position as usize];
        for level in 1_u8..32 {
            nodes[usize::from(level)] = MerkleHashOrchard::empty_root(Level::from(level));
        }
        let orchard_path = MerklePath::from_parts(position, nodes);
        let root = orchard_path.root(commitments[position as usize]);
        let path = NoteMembershipPath::from_parts(position, nodes.map(|node| node.to_bytes()))
            .expect("canonical membership path");
        (root, path)
    });
    assert_eq!(paths[0].0, paths[1].0);
    (
        NoteTreeRoot::from_bytes(paths[0].0.to_bytes()).expect("canonical common anchor"),
        [paths[0].1.clone(), paths[1].1.clone()],
    )
}
