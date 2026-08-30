//! Complete transfer-v2 statement for the isolated RISC Zero reference backend.
//!
//! The guest reconstructs every private Action opening with the production
//! Ironwood/Orchard primitives, checks the exact public effects encoding, and
//! binds the same hidden burn to conservation, its value commitment, and the
//! threshold-ElGamal ciphertext. This module is evidence for C1; it does not
//! activate a consensus verifier.

use serde::{Deserialize, Serialize};
use vault_burn::{BURN_ENCRYPTION_SCHEME_ID, BurnCiphertext, EpochBurnPublicKey};
use vault_privacy::{
    CanonicalValueCommitment, NOTE_TREE_DEPTH, NoteMembershipPath, OutputAuthorizationPacket,
    OutputKind, PrivateNote, VaultFullViewingKey,
};
use vault_protocol::TransferV2Effects;

/// Maximum supply expressed in atomic VLT units.
pub const MAXIMUM_VLT_ATOMIC: u64 = 21_000_000 * 1_000_000_000;

/// Private opening for one canonical transfer-v2 action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferV2ActionWitness {
    /// Exact Orchard full-viewing-key encoding for the consumed note owner.
    pub full_viewing_key: Vec<u8>,
    /// Exact `PrivateNote::encode_private()` bytes for the consumed note.
    pub input_note: Vec<u8>,
    /// Zero-based position selected by the Merkle authentication path.
    pub membership_position: u32,
    /// Depth-32 Orchard authentication path, from leaf to root.
    pub membership_auth_path: Vec<[u8; 32]>,
    /// Exact private signer packet that reconstructs the public encrypted output.
    pub output_authorization_packet: Vec<u8>,
    /// Non-zero Action randomizer `alpha` opening the public randomized key.
    pub authorization_randomizer: [u8; 32],
    /// Orchard trapdoor opening the public commitment to `input - output`.
    pub net_value_commitment_trapdoor: [u8; 32],
}

/// Public DKG result and private openings for the exact mandatory burn.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferV2BurnWitness {
    /// Epoch selected by the canonical effects.
    pub epoch: u64,
    /// Threshold of the reviewed DKG result.
    pub threshold: u16,
    /// Canonically sorted non-zero DKG participant identifiers.
    pub participants: Vec<u16>,
    /// Feldman coefficient commitments for the epoch polynomial.
    pub coefficient_commitments: Vec<[u8; 32]>,
    /// Circuit-compatible opening of the public burn value commitment.
    pub commitment_trapdoor: [u8; 32],
    /// Circuit-compatible threshold-ElGamal encryption randomness.
    pub encryption_randomness: [u8; 32],
}

/// Exact public effects plus every private opening consumed by the guest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferV2ReferenceClaim {
    /// Exact `TransferV2Effects::encode_canonical()` bytes.
    pub canonical_effects: Vec<u8>,
    /// One private witness for each public padded action.
    pub actions: Vec<TransferV2ActionWitness>,
    /// Epoch-key material and private openings for the hidden burn.
    pub burn: TransferV2BurnWitness,
}

/// Minimal public result committed to the RISC Zero journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferV2ReferenceJournal {
    /// Digest recomputed by the typed canonical transfer-v2 codec.
    pub public_inputs_digest: [u8; 32],
    /// Public padded action bucket.
    pub action_count: u16,
    /// Public gas fee recomputed with checked arithmetic.
    pub gas_fee: u128,
}

/// Deterministic rejection reasons shared by native tests and the zkVM guest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferV2ReferenceError {
    /// Public effects failed the exact consensus-facing transfer-v2 codec.
    InvalidEffectsEncoding,
    /// The private witness count differs from the public padded bucket.
    ActionCountMismatch,
    /// The DKG result is malformed or differs from the public epoch/key ID.
    InvalidEpochKey,
    /// A full viewing key has a wrong length or invalid canonical encoding.
    InvalidFullViewingKey,
    /// A private input note has a wrong length or invalid canonical encoding.
    InvalidInputNote,
    /// A Merkle path has the wrong depth or a non-canonical node.
    InvalidMembershipPath,
    /// The supplied viewing key does not own the consumed note receiver.
    OwnershipFailure,
    /// A non-zero input note is not a member of the public anchor.
    MembershipFailure,
    /// The public nullifier is not derived from the owned input note.
    NullifierMismatch,
    /// The public randomized validating key is not `ak + alpha`.
    AuthorizationMismatch,
    /// The public net-value commitment does not open to input minus output.
    NetValueCommitmentMismatch,
    /// The private packet does not reconstruct the exact public encrypted output.
    OutputOpeningMismatch,
    /// Output payment/change/dummy classification is not receiver-derived.
    OutputClassificationMismatch,
    /// One private amount exceeds the fixed VLT supply bound.
    AmountOutOfRange,
    /// A checked sum, multiplication, or narrowing conversion failed.
    ArithmeticOverflow,
    /// Hidden inputs do not fund outputs, exact burn, and public gas.
    ConservationFailure,
    /// The public burn commitment does not open to the exact derived burn.
    BurnCommitmentMismatch,
    /// The public burn ciphertext does not encrypt the exact derived burn.
    BurnCiphertextMismatch,
}

impl TransferV2ReferenceClaim {
    /// Executes the complete bounded transfer-v2 reference statement.
    pub fn validate(&self) -> Result<TransferV2ReferenceJournal, TransferV2ReferenceError> {
        let effects = TransferV2Effects::decode_canonical(&self.canonical_effects)
            .map_err(|_| TransferV2ReferenceError::InvalidEffectsEncoding)?;
        if self.actions.len() != effects.actions().len() {
            return Err(TransferV2ReferenceError::ActionCountMismatch);
        }

        let epoch_key = EpochBurnPublicKey::from_parts(
            self.burn.epoch,
            self.burn.threshold,
            self.burn.participants.clone(),
            self.burn.coefficient_commitments.clone(),
        )
        .map_err(|_| TransferV2ReferenceError::InvalidEpochKey)?;
        if effects.burn().scheme_id() != BURN_ENCRYPTION_SCHEME_ID
            || effects.burn().epoch() != epoch_key.epoch()
            || effects.burn().key_id() != epoch_key.key_id()
        {
            return Err(TransferV2ReferenceError::InvalidEpochKey);
        }

        let mut input_sum = 0_u128;
        let mut output_sum = 0_u128;
        let mut taxable_sum = 0_u128;
        for (witness, action) in self.actions.iter().zip(effects.actions()) {
            let full_viewing_key = VaultFullViewingKey::from_bytes(exact_array(
                &witness.full_viewing_key,
                TransferV2ReferenceError::InvalidFullViewingKey,
            )?)
            .map_err(|_| TransferV2ReferenceError::InvalidFullViewingKey)?;
            let input_note = PrivateNote::decode_private(
                exact_array(
                    &witness.input_note,
                    TransferV2ReferenceError::InvalidInputNote,
                )?,
                MAXIMUM_VLT_ATOMIC,
            )
            .map_err(|_| TransferV2ReferenceError::InvalidInputNote)?;
            if !full_viewing_key.owns_address(input_note.recipient()) {
                return Err(TransferV2ReferenceError::OwnershipFailure);
            }

            let auth_path: [[u8; 32]; NOTE_TREE_DEPTH as usize] = witness
                .membership_auth_path
                .clone()
                .try_into()
                .map_err(|_| TransferV2ReferenceError::InvalidMembershipPath)?;
            let membership = NoteMembershipPath::from_parts(witness.membership_position, auth_path)
                .map_err(|_| TransferV2ReferenceError::InvalidMembershipPath)?;
            let input_commitment = input_note
                .commitment()
                .map_err(|_| TransferV2ReferenceError::InvalidInputNote)?;
            if input_note.value() != 0
                && !membership.verify(input_commitment, effects.anchor().to_bytes())
            {
                return Err(TransferV2ReferenceError::MembershipFailure);
            }

            if full_viewing_key
                .note_nullifier(&input_note)
                .map_err(|_| TransferV2ReferenceError::NullifierMismatch)?
                != action.nullifier()
            {
                return Err(TransferV2ReferenceError::NullifierMismatch);
            }
            if full_viewing_key
                .randomized_spend_validating_key(witness.authorization_randomizer)
                .map_err(|_| TransferV2ReferenceError::AuthorizationMismatch)?
                != action.randomized_verification_key()
            {
                return Err(TransferV2ReferenceError::AuthorizationMismatch);
            }

            let packet = OutputAuthorizationPacket::decode(&witness.output_authorization_packet)
                .map_err(|_| TransferV2ReferenceError::OutputOpeningMismatch)?;
            let verified_output = packet
                .verify_reference(&full_viewing_key, action.output(), MAXIMUM_VLT_ATOMIC)
                .map_err(|_| TransferV2ReferenceError::OutputOpeningMismatch)?;
            if verified_output.network_id() != *effects.chain_id().as_bytes()
                || !verified_output.matches_action(action.nullifier(), action.output())
            {
                return Err(TransferV2ReferenceError::OutputOpeningMismatch);
            }

            let input_value = input_note.value();
            let output_value = verified_output.value();
            if input_value > MAXIMUM_VLT_ATOMIC || output_value > MAXIMUM_VLT_ATOMIC {
                return Err(TransferV2ReferenceError::AmountOutOfRange);
            }
            let expected_net = CanonicalValueCommitment::derive_net_opening(
                input_value,
                output_value,
                witness.net_value_commitment_trapdoor,
            )
            .map_err(|_| TransferV2ReferenceError::NetValueCommitmentMismatch)?;
            if expected_net != action.net_value_commitment() {
                return Err(TransferV2ReferenceError::NetValueCommitmentMismatch);
            }

            let same_receiver = input_note.recipient() == verified_output.recipient();
            let expected_kind = if input_value == 0 && output_value == 0 && same_receiver {
                OutputKind::Dummy
            } else if output_value != 0 && same_receiver {
                OutputKind::InternalChange
            } else if output_value != 0 {
                OutputKind::ExternalPayment
            } else {
                return Err(TransferV2ReferenceError::OutputClassificationMismatch);
            };
            if verified_output.kind() != expected_kind {
                return Err(TransferV2ReferenceError::OutputClassificationMismatch);
            }

            input_sum = input_sum
                .checked_add(u128::from(input_value))
                .ok_or(TransferV2ReferenceError::ArithmeticOverflow)?;
            output_sum = output_sum
                .checked_add(u128::from(output_value))
                .ok_or(TransferV2ReferenceError::ArithmeticOverflow)?;
            if expected_kind == OutputKind::ExternalPayment {
                taxable_sum = taxable_sum
                    .checked_add(u128::from(output_value))
                    .ok_or(TransferV2ReferenceError::ArithmeticOverflow)?;
            }
        }

        let burn = burn_for(taxable_sum);
        let burn_u64 =
            u64::try_from(burn).map_err(|_| TransferV2ReferenceError::ArithmeticOverflow)?;
        let gas_fee = u128::from(effects.gas().units)
            .checked_mul(u128::from(effects.gas().fee_per_gas))
            .ok_or(TransferV2ReferenceError::ArithmeticOverflow)?;
        let required = output_sum
            .checked_add(burn)
            .and_then(|value| value.checked_add(gas_fee))
            .ok_or(TransferV2ReferenceError::ArithmeticOverflow)?;
        if input_sum != required {
            return Err(TransferV2ReferenceError::ConservationFailure);
        }

        let burn_commitment = CanonicalValueCommitment::derive_burn_opening(
            burn_u64,
            MAXIMUM_VLT_ATOMIC,
            self.burn.commitment_trapdoor,
        )
        .map_err(|_| TransferV2ReferenceError::BurnCommitmentMismatch)?;
        if burn_commitment != effects.burn().commitment() {
            return Err(TransferV2ReferenceError::BurnCommitmentMismatch);
        }
        let burn_ciphertext = BurnCiphertext::derive_opening(
            burn_u64,
            MAXIMUM_VLT_ATOMIC,
            &epoch_key,
            self.burn.encryption_randomness,
        )
        .map_err(|_| TransferV2ReferenceError::BurnCiphertextMismatch)?;
        if burn_ciphertext.to_bytes() != *effects.burn().ciphertext() {
            return Err(TransferV2ReferenceError::BurnCiphertextMismatch);
        }

        Ok(TransferV2ReferenceJournal {
            public_inputs_digest: *effects.public_inputs_digest().as_bytes(),
            action_count: u16::try_from(effects.actions().len())
                .map_err(|_| TransferV2ReferenceError::ActionCountMismatch)?,
            gas_fee,
        })
    }
}

/// Exact 0.5% burn rounded upward to one atomic unit.
#[must_use]
pub const fn burn_for(taxable_amount: u128) -> u128 {
    let quotient = taxable_amount / 200;
    let remainder = taxable_amount % 200;
    quotient + if remainder == 0 { 0 } else { 1 }
}

fn exact_array<const N: usize>(
    bytes: &[u8],
    error: TransferV2ReferenceError,
) -> Result<[u8; N], TransferV2ReferenceError> {
    bytes.try_into().map_err(|_| error)
}

#[cfg(test)]
mod tests {
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
        ActionNullifier, KeyScope, MEMO_BYTES, NoteTreeRoot, OutputKind, PreparedBurnCommitment,
        PreparedNetValueCommitment, PreparedNoteOutput, PrivateNote, RandomizedSpendValidatingKey,
        VaultSpendingKey,
    };
    use vault_protocol::{
        ChainId, CircuitId, EncryptedBurnV2, GasParameters, TransferV2Action, TransferV2Effects,
    };

    use super::*;

    const NETWORK: [u8; 32] = [0x31; 32];

    fn nullifier(byte: u8) -> ActionNullifier {
        ActionNullifier::from_bytes([byte; 32]).unwrap()
    }

    fn two_leaf_paths(commitments: [[u8; 32]; 2]) -> (NoteTreeRoot, [NoteMembershipPath; 2]) {
        let commitments = commitments.map(|bytes| {
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&bytes))
                .unwrap()
        });
        let leaves = commitments.map(|cmx| MerkleHashOrchard::from_cmx(&cmx));
        let paths = [0_u32, 1_u32].map(|position| {
            let mut nodes = [MerkleHashOrchard::empty_leaf(); NOTE_TREE_DEPTH as usize];
            nodes[0] = leaves[1 - position as usize];
            for level in 1_u8..NOTE_TREE_DEPTH {
                nodes[usize::from(level)] = MerkleHashOrchard::empty_root(Level::from(level));
            }
            let path = MerklePath::from_parts(position, nodes);
            let root = path.root(commitments[position as usize]);
            (
                root,
                NoteMembershipPath::from_parts(position, nodes.map(|node| node.to_bytes()))
                    .unwrap(),
            )
        });
        assert_eq!(paths[0].0, paths[1].0);
        (
            NoteTreeRoot::from_bytes(paths[0].0.to_bytes()).unwrap(),
            [paths[0].1.clone(), paths[1].1.clone()],
        )
    }

    fn claim_with_values(
        input_values: [u64; 2],
        output_values: [u64; 2],
        encoded_burn: u64,
    ) -> TransferV2ReferenceClaim {
        let spending_key = VaultSpendingKey::derive(&[0xA5; 32], NETWORK, 0).unwrap();
        let full_viewing_key = spending_key.full_viewing_key();
        let input_address = full_viewing_key.address_at(0, KeyScope::Internal);
        let external_address = VaultSpendingKey::derive(&[0xB6; 32], NETWORK, 0)
            .unwrap()
            .full_viewing_key()
            .address_at(0, KeyScope::External);
        let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
        let inputs = [
            PrivateNote::create(
                input_address,
                input_values[0],
                MAXIMUM_VLT_ATOMIC,
                nullifier(2),
                &mut rng,
            )
            .unwrap(),
            PrivateNote::create(
                input_address,
                input_values[1],
                MAXIMUM_VLT_ATOMIC,
                nullifier(3),
                &mut rng,
            )
            .unwrap(),
        ];
        let (anchor, paths) = two_leaf_paths([
            inputs[0].commitment().unwrap(),
            inputs[1].commitment().unwrap(),
        ]);

        let recipients = [external_address, input_address];
        let kinds = [OutputKind::ExternalPayment, OutputKind::InternalChange];
        let mut prepared = Vec::new();
        for index in 0..2 {
            let action_nullifier = full_viewing_key.note_nullifier(&inputs[index]).unwrap();
            let output = PreparedNoteOutput::create(
                &full_viewing_key,
                KeyScope::External,
                recipients[index],
                output_values[index],
                MAXIMUM_VLT_ATOMIC,
                action_nullifier,
                [index as u8; MEMO_BYTES],
                &mut rng,
            )
            .unwrap();
            let authorization = spending_key.prepare_spend_authorization(&mut rng).unwrap();
            let net = PreparedNetValueCommitment::create(
                inputs[index].value(),
                output_values[index],
                &mut rng,
            )
            .unwrap();
            let packet = output.authorization_packet(NETWORK, kinds[index]).unwrap();
            let witness = TransferV2ActionWitness {
                full_viewing_key: full_viewing_key.export().to_vec(),
                input_note: inputs[index].encode_private().to_vec(),
                membership_position: paths[index].position(),
                membership_auth_path: paths[index].auth_path().to_vec(),
                output_authorization_packet: packet.encode().to_vec(),
                authorization_randomizer: *authorization.randomizer(),
                net_value_commitment_trapdoor: *net.trapdoor(),
            };
            let public = TransferV2Action::new(
                action_nullifier,
                RandomizedSpendValidatingKey::from_bytes(
                    authorization.randomized_verification_key(),
                )
                .unwrap(),
                net.commitment(),
                output.encrypted_note().clone(),
            );
            prepared.push((action_nullifier, witness, public));
        }
        prepared.sort_by_key(|(action_nullifier, _, _)| *action_nullifier);
        let (actions, public_actions): (Vec<_>, Vec<_>) = prepared
            .into_iter()
            .map(|(_, witness, public)| (witness, public))
            .unzip();

        let coefficients = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
        let commitments = coefficients
            .map(|value| (pallas::Point::generator() * value).to_bytes())
            .to_vec();
        let epoch_key =
            EpochBurnPublicKey::from_parts(9, 2, vec![1, 2, 3], commitments.clone()).unwrap();
        let burn_commitment =
            PreparedBurnCommitment::create(encoded_burn, MAXIMUM_VLT_ATOMIC, &mut rng).unwrap();
        let burn_ciphertext =
            PreparedBurnCiphertext::encrypt(encoded_burn, MAXIMUM_VLT_ATOMIC, &epoch_key, &mut rng)
                .unwrap();
        let effects = TransferV2Effects::new(
            ChainId::new(NETWORK),
            CircuitId::new([0x44; 32]),
            anchor,
            EncryptedBurnV2::from_threshold_ciphertext(
                &epoch_key,
                burn_commitment.commitment(),
                burn_ciphertext.ciphertext(),
            )
            .unwrap(),
            GasParameters {
                units: 2,
                fee_per_gas: 13,
            },
            public_actions,
        )
        .unwrap();

        TransferV2ReferenceClaim {
            canonical_effects: effects.encode_canonical(),
            actions,
            burn: TransferV2BurnWitness {
                epoch: epoch_key.epoch(),
                threshold: epoch_key.threshold(),
                participants: epoch_key.participants().to_vec(),
                coefficient_commitments: commitments,
                commitment_trapdoor: *burn_commitment.trapdoor(),
                encryption_randomness: *burn_ciphertext.randomness(),
            },
        }
    }

    fn valid_claim() -> TransferV2ReferenceClaim {
        claim_with_values([5_051, 1_000], [5_000, 1_000], 25)
    }

    #[test]
    fn validates_all_transfer_v2_relations() {
        let claim = valid_claim();
        let effects = TransferV2Effects::decode_canonical(&claim.canonical_effects).unwrap();
        let journal = claim.validate().unwrap();
        assert_eq!(
            journal.public_inputs_digest,
            *effects.public_inputs_digest().as_bytes()
        );
        assert_eq!(journal.action_count, 2);
        assert_eq!(journal.gas_fee, 26);
    }

    #[test]
    fn rejects_membership_nullifier_and_authorization_tampering() {
        let mut claim = valid_claim();
        claim.actions[0].membership_auth_path[0][0] ^= 1;
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::MembershipFailure)
        );

        let mut claim = valid_claim();
        claim.actions[0].authorization_randomizer[0] ^= 1;
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::AuthorizationMismatch)
        );

        let mut claim = valid_claim();
        claim.canonical_effects[287] ^= 1;
        assert!(matches!(
            claim.validate(),
            Err(TransferV2ReferenceError::InvalidEffectsEncoding)
                | Err(TransferV2ReferenceError::NullifierMismatch)
        ));

        let other_owner = VaultSpendingKey::derive(&[0xC7; 32], NETWORK, 0)
            .unwrap()
            .full_viewing_key();
        let mut claim = valid_claim();
        claim.actions[0].full_viewing_key = other_owner.export().to_vec();
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::OwnershipFailure)
        );
    }

    #[test]
    fn rejects_note_output_net_and_classification_tampering() {
        let mut claim = valid_claim();
        claim.actions[0].input_note[43] ^= 1;
        assert!(matches!(
            claim.validate(),
            Err(TransferV2ReferenceError::MembershipFailure)
                | Err(TransferV2ReferenceError::NetValueCommitmentMismatch)
        ));

        let mut claim = valid_claim();
        claim.actions[0].net_value_commitment_trapdoor[0] ^= 1;
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::NetValueCommitmentMismatch)
        );

        let mut claim = valid_claim();
        let last = claim.actions[0].output_authorization_packet.len() - 1;
        claim.actions[0].output_authorization_packet[last] ^= 1;
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::OutputOpeningMismatch)
        );

        let mut claim = valid_claim();
        let change = claim
            .actions
            .iter_mut()
            .find(|action| {
                action.output_authorization_packet[39] == OutputKind::InternalChange as u8
            })
            .unwrap();
        change.output_authorization_packet[39] = OutputKind::ExternalPayment as u8;
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::OutputClassificationMismatch)
        );
    }

    #[test]
    fn rejects_conservation_and_ceil_burn_divergence() {
        let claim = claim_with_values([5_050, 1_000], [5_000, 1_000], 25);
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::ConservationFailure)
        );

        // 5_001 taxable atoms require ceil(5_001 / 200) = 26. All value
        // commitments and conservation use that amount, while the encoded burn
        // is intentionally opened to 25 so the exact binding must reject it.
        let claim = claim_with_values([5_053, 1_000], [5_001, 1_000], 25);
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::BurnCommitmentMismatch)
        );
    }

    #[test]
    fn rejects_burn_opening_and_epoch_tampering() {
        let mut claim = valid_claim();
        claim.burn.commitment_trapdoor[0] ^= 1;
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::BurnCommitmentMismatch)
        );

        let mut claim = valid_claim();
        claim.burn.encryption_randomness[0] ^= 1;
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::BurnCiphertextMismatch)
        );

        let mut claim = valid_claim();
        claim.burn.epoch += 1;
        assert_eq!(
            claim.validate(),
            Err(TransferV2ReferenceError::InvalidEpochKey)
        );
    }
}
