use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_privacy::{PreparedSpendAuthorization, VaultSpendingKey};
use vault_protocol::PublicInputDigest;
use vault_signer::{
    MULTISIG_COMMITMENT_SET_MAX_BYTES, MULTISIG_POLICY_MAX_BYTES,
    MULTISIG_SIGNING_AGREEMENT_MAX_BYTES, MultisigAgreementFacts, MultisigAgreementId,
    MultisigAttemptId, MultisigCommitmentSet, MultisigError, MultisigNonceCommitment,
    MultisigParticipant, MultisigParticipantId, MultisigPolicy, MultisigSigningAgreement,
    PairedPeerId, SignerConfirmationError, SigningTranscriptId, TrustedMultisigAgreement,
};

const NETWORK: [u8; 32] = [0x31; 32];

fn spending_key(seed: u8, account: u32) -> VaultSpendingKey {
    VaultSpendingKey::derive(&[seed; 32], NETWORK, account).unwrap()
}

fn point(seed: u8, account: u32) -> [u8; 32] {
    spending_key(seed, account)
        .full_viewing_key()
        .spend_validating_key()
}

fn participant(id: u16, seed: u8) -> MultisigParticipant {
    MultisigParticipant::new(
        MultisigParticipantId::new(id).unwrap(),
        PairedPeerId::from_bytes([seed; 32]).unwrap(),
        point(seed, u32::from(id)),
    )
    .unwrap()
}

fn policy() -> (VaultSpendingKey, MultisigPolicy) {
    let group = spending_key(0x51, 0);
    let policy = MultisigPolicy::new(
        NETWORK,
        2,
        &group.full_viewing_key(),
        vec![
            participant(1, 0x61),
            participant(2, 0x62),
            participant(3, 0x63),
        ],
    )
    .unwrap();
    (group, policy)
}

fn agreement_fixture() -> (
    MultisigPolicy,
    MultisigCommitmentSet,
    PreparedSpendAuthorization,
    MultisigSigningAgreement,
) {
    let (group, policy) = policy();
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let attempt = MultisigAttemptId::generate(&mut rng).unwrap();
    let commitments = MultisigCommitmentSet::new(
        &policy,
        attempt,
        vec![
            MultisigNonceCommitment::new(
                MultisigParticipantId::new(1).unwrap(),
                point(0x81, 1),
                point(0x82, 1),
            )
            .unwrap(),
            MultisigNonceCommitment::new(
                MultisigParticipantId::new(3).unwrap(),
                point(0x83, 3),
                point(0x84, 3),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let prepared = group.prepare_spend_authorization(&mut rng).unwrap();
    let agreement = MultisigSigningAgreement::new(
        &policy,
        &commitments,
        SigningTranscriptId::from_bytes([0x91; 32]),
        PublicInputDigest::new([0x92; 32]),
        0,
        2,
        &prepared,
    )
    .unwrap();
    (policy, commitments, prepared, agreement)
}

#[test]
fn policy_codec_binds_sorted_unique_roster_threshold_network_and_group_key() {
    let (_, policy) = policy();
    let encoded = policy.encode();
    assert!(encoded.len() <= MULTISIG_POLICY_MAX_BYTES);
    assert_eq!(MultisigPolicy::decode(&encoded).unwrap(), policy);
    assert_eq!(policy.participants().len(), 3);
    assert_eq!(policy.threshold(), 2);
    assert_eq!(policy.network_id(), NETWORK);
    assert!(format!("{policy:?}").contains("REDACTED"));

    for offset in [0, 4, 6, 7, 8, 40, 72, 74, 106] {
        let mut malformed = encoded.clone();
        match offset {
            6 => malformed[offset] = 1,
            7 => malformed[offset] = 17,
            8 => malformed[offset..offset + 32].fill(0),
            40 => malformed[offset..offset + 32].fill(0),
            72 => malformed[offset..offset + 2].fill(0),
            74 => malformed[offset..offset + 32].fill(0),
            106 => malformed[offset..offset + 32].fill(0),
            _ => malformed[offset] ^= 1,
        }
        assert!(
            MultisigPolicy::decode(&malformed).is_err(),
            "malformed policy at offset {offset} was accepted"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(MultisigPolicy::decode(&trailing).is_err());
    assert!(MultisigPolicy::decode(&encoded[..encoded.len() - 1]).is_err());

    let group = spending_key(0x51, 0);
    assert!(matches!(
        MultisigPolicy::new(
            NETWORK,
            2,
            &group.full_viewing_key(),
            vec![participant(2, 0x62), participant(1, 0x61)],
        ),
        Err(MultisigError::InvalidPolicy)
    ));
    assert!(matches!(
        MultisigPolicy::new(
            NETWORK,
            2,
            &group.full_viewing_key(),
            vec![participant(1, 0x61), participant(2, 0x61)],
        ),
        Err(MultisigError::InvalidPolicy)
    ));
}

#[test]
fn commitment_set_is_exactly_threshold_sorted_and_attempt_bound() {
    let (_, policy) = policy();
    let mut rng = ChaCha20Rng::from_seed([0x72; 32]);
    let attempt = MultisigAttemptId::generate(&mut rng).unwrap();
    let first = MultisigNonceCommitment::new(
        MultisigParticipantId::new(1).unwrap(),
        point(0x81, 1),
        point(0x82, 1),
    )
    .unwrap();
    let second = MultisigNonceCommitment::new(
        MultisigParticipantId::new(2).unwrap(),
        point(0x83, 2),
        point(0x84, 2),
    )
    .unwrap();
    let set = MultisigCommitmentSet::new(&policy, attempt, vec![first, second]).unwrap();
    let encoded = set.encode();
    assert!(encoded.len() <= MULTISIG_COMMITMENT_SET_MAX_BYTES);
    assert_eq!(
        MultisigCommitmentSet::decode(&encoded, &policy).unwrap(),
        set
    );
    assert!(format!("{set:?}").contains("REDACTED"));

    assert!(matches!(
        MultisigCommitmentSet::new(&policy, attempt, vec![first]),
        Err(MultisigError::InvalidCommitment)
    ));
    assert!(matches!(
        MultisigCommitmentSet::new(&policy, attempt, vec![second, first]),
        Err(MultisigError::InvalidCommitment)
    ));
    let repeated_point = MultisigNonceCommitment::new(
        MultisigParticipantId::new(2).unwrap(),
        first.hiding(),
        point(0x85, 2),
    )
    .unwrap();
    assert!(matches!(
        MultisigCommitmentSet::new(&policy, attempt, vec![first, repeated_point]),
        Err(MultisigError::InvalidCommitment)
    ));
    assert!(
        MultisigNonceCommitment::new(
            MultisigParticipantId::new(1).unwrap(),
            point(0x81, 1),
            point(0x81, 1),
        )
        .is_err()
    );

    for offset in [0, 4, 6, 8, 40, 72, 74, 106] {
        let mut malformed = encoded.clone();
        match offset {
            40 => malformed[offset..offset + 32].fill(0),
            72 => malformed[offset..offset + 2].fill(0),
            74 | 106 => malformed[offset..offset + 32].fill(0),
            _ => malformed[offset] ^= 1,
        }
        assert!(
            MultisigCommitmentSet::decode(&malformed, &policy).is_err(),
            "malformed commitment set at offset {offset} was accepted"
        );
    }
}

#[test]
fn agreement_binds_transaction_action_randomizer_and_every_round_one_fact() {
    let (policy, commitments, prepared, agreement) = agreement_fixture();
    let encoded = agreement.encode();
    assert!(encoded.len() <= MULTISIG_SIGNING_AGREEMENT_MAX_BYTES);
    assert_eq!(
        MultisigSigningAgreement::decode(&encoded, &policy, &commitments, &prepared).unwrap(),
        agreement
    );
    assert_eq!(agreement.action_index(), 0);
    assert_eq!(agreement.action_count(), 2);
    assert_eq!(agreement.selected_participants().len(), 2);
    assert!(format!("{agreement:?}").contains("REDACTED"));

    for offset in [0, 4, 6, 7, 8, 9, 10, 42, 74, 106, 138, 170, 202, 234, 266] {
        let mut malformed = encoded.clone();
        malformed[offset] ^= 1;
        assert!(
            MultisigSigningAgreement::decode(&malformed, &policy, &commitments, &prepared).is_err(),
            "malformed agreement at offset {offset} was accepted"
        );
    }

    let other = spending_key(0x52, 0);
    let mut rng = ChaCha20Rng::from_seed([0x73; 32]);
    let wrong_prepared = other.prepare_spend_authorization(&mut rng).unwrap();
    assert!(matches!(
        MultisigSigningAgreement::new(
            &policy,
            &commitments,
            SigningTranscriptId::from_bytes([0x91; 32]),
            PublicInputDigest::new([0x92; 32]),
            0,
            2,
            &wrong_prepared,
        ),
        Err(MultisigError::InvalidAgreement)
    ));
}

struct TestConfirmation {
    seen: Option<MultisigAgreementFacts>,
    wrong: bool,
}

impl TrustedMultisigAgreement for TestConfirmation {
    fn confirm_multisig_agreement(
        &mut self,
        facts: &MultisigAgreementFacts,
    ) -> Result<MultisigAgreementId, SignerConfirmationError> {
        self.seen = Some(facts.clone());
        if self.wrong {
            Ok(MultisigAgreementId::from_bytes([0xFF; 32]))
        } else {
            Ok(facts.agreement_id())
        }
    }
}

#[test]
fn every_selected_participant_must_confirm_the_same_exact_agreement() {
    let (_, _, _, agreement) = agreement_fixture();
    let selected = MultisigParticipantId::new(1).unwrap();
    let mut confirmation = TestConfirmation {
        seen: None,
        wrong: false,
    };
    let approved = agreement.confirm(selected, &mut confirmation).unwrap();
    assert!(approved.matches(&agreement));
    assert_eq!(approved.participant_id(), selected);
    let seen = confirmation.seen.unwrap();
    assert_eq!(seen.agreement_id(), agreement.agreement_id());
    assert_eq!(seen.transcript_id(), agreement.transcript_id());
    assert_eq!(seen.action_position(), (0, 2));
    assert_eq!(
        seen.selected_participants(),
        agreement.selected_participants()
    );
    assert!(format!("{seen:?}").contains("REDACTED"));

    let mut wrong = TestConfirmation {
        seen: None,
        wrong: true,
    };
    assert!(matches!(
        agreement.confirm(selected, &mut wrong),
        Err(MultisigError::ConfirmationFailed)
    ));
    assert!(matches!(
        agreement.confirm(MultisigParticipantId::new(2).unwrap(), &mut wrong),
        Err(MultisigError::ParticipantNotSelected)
    ));
}
