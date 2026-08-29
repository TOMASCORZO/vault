use std::{cell::RefCell, fmt, rc::Rc};

use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_signer::{
    DurableReplayGuard, ProtectedSignerKeys, RollbackProtectedReplayStore,
    SIGNER_PROTECTED_KEY_MATERIAL_BYTES, SIGNER_SECURE_REPLAY_STATE_BYTES, SessionChallenge,
    SessionError, SignerPairingRole, SignerProtectedKeyMaterial, SignerProtectedKeyStore,
    SignerProtectedKeyStoreError, SignerSecureReplayError, SignerSecureReplayState,
    SignerSecureReplayStore,
};

const NETWORK: [u8; 32] = [0x31; 32];
const CHANNEL: [u8; 32] = [0x77; 32];

#[derive(Clone, Copy, Debug)]
struct TestStoreError;

impl fmt::Display for TestStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("test store failure")
    }
}

impl std::error::Error for TestStoreError {}

#[derive(Clone, Default)]
struct TestProtectedKeyStore(Rc<RefCell<Option<[u8; SIGNER_PROTECTED_KEY_MATERIAL_BYTES]>>>);

impl SignerProtectedKeyStore for TestProtectedKeyStore {
    type Error = TestStoreError;

    fn create(&mut self, material: &SignerProtectedKeyMaterial) -> Result<bool, Self::Error> {
        let mut slot = self.0.borrow_mut();
        if slot.is_some() {
            return Ok(false);
        }
        // Test-only memory adapter. Production adapters must meet the stronger
        // platform contract documented by SignerProtectedKeyStore.
        *slot = Some(*material.to_bytes());
        Ok(true)
    }

    fn load(&mut self) -> Result<Option<SignerProtectedKeyMaterial>, Self::Error> {
        let Some(mut bytes) = self.0.borrow().as_ref().copied() else {
            return Ok(None);
        };
        SignerProtectedKeyMaterial::from_bytes(&mut bytes)
            .map(Some)
            .map_err(|_| TestStoreError)
    }
}

#[derive(Clone, Default)]
struct TestReplayStore(Rc<RefCell<TestReplayStoreState>>);

#[derive(Default)]
struct TestReplayStoreState {
    value: Option<SignerSecureReplayState>,
    reject_next_compare: bool,
    fail_next_compare_after_write: bool,
}

impl SignerSecureReplayStore for TestReplayStore {
    type Error = TestStoreError;

    fn load(&mut self) -> Result<Option<SignerSecureReplayState>, Self::Error> {
        Ok(self.0.borrow().value)
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<&SignerSecureReplayState>,
        replacement: &SignerSecureReplayState,
    ) -> Result<bool, Self::Error> {
        let mut slot = self.0.borrow_mut();
        if slot.reject_next_compare {
            slot.reject_next_compare = false;
            return Ok(false);
        }
        if slot.value.as_ref() != expected {
            return Ok(false);
        }
        slot.value = Some(*replacement);
        if slot.fail_next_compare_after_write {
            slot.fail_next_compare_after_write = false;
            return Err(TestStoreError);
        }
        Ok(true)
    }
}

fn material(seed: u8) -> SignerProtectedKeyMaterial {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    SignerProtectedKeyMaterial::generate(NETWORK, SignerPairingRole::Signer, &mut rng).unwrap()
}

#[test]
fn protected_key_record_is_canonical_scoped_and_redacted() {
    let original = material(0x51);
    let encoded = original.to_bytes();
    assert_eq!(encoded.len(), SIGNER_PROTECTED_KEY_MATERIAL_BYTES);

    let mut restored_bytes = *encoded;
    let restored = SignerProtectedKeyMaterial::from_bytes(&mut restored_bytes).unwrap();
    assert_eq!(restored_bytes, [0; SIGNER_PROTECTED_KEY_MATERIAL_BYTES]);
    assert_eq!(restored.to_bytes().as_ref(), encoded.as_ref());
    assert_eq!(restored.network_id(), NETWORK);
    assert_eq!(restored.role(), SignerPairingRole::Signer);
    assert_eq!(
        restored.transport().public_key(),
        original.transport().public_key()
    );
    assert!(restored.registry_scope().is_ok());
    assert_eq!(
        format!("{restored:?}"),
        "SignerProtectedKeyMaterial(REDACTED)"
    );

    for offset in [0, 4, 6, 7, 8, 40, 72, 104] {
        let mut malformed = *encoded;
        if offset == 6 {
            malformed[offset] = 2;
        } else if matches!(offset, 8 | 40 | 72 | 104) {
            malformed[offset..offset + 32].fill(0);
        } else {
            malformed[offset] ^= 1;
        }
        assert!(
            SignerProtectedKeyMaterial::from_bytes(&mut malformed).is_err(),
            "malformed protected material at offset {offset} was accepted"
        );
    }
}

#[test]
fn protected_key_enrollment_is_no_clobber_and_missing_open_fails() {
    assert!(matches!(
        ProtectedSignerKeys::open(TestProtectedKeyStore::default()).unwrap_err(),
        SignerProtectedKeyStoreError::NotEnrolled
    ));

    let store = TestProtectedKeyStore::default();
    let observer = store.clone();
    let enrolled = ProtectedSignerKeys::enroll(material(0x52), store).unwrap();
    let expected_public = enrolled.material().transport().public_key();
    assert!(format!("{enrolled:?}").contains("REDACTED"));
    drop(enrolled);

    assert!(matches!(
        ProtectedSignerKeys::enroll(material(0x53), observer.clone()).unwrap_err(),
        SignerProtectedKeyStoreError::AlreadyEnrolled
    ));
    let reopened = ProtectedSignerKeys::open(observer).unwrap();
    assert_eq!(
        reopened.material().transport().public_key(),
        expected_public
    );
}

#[test]
fn secure_replay_state_round_trips_and_rejects_noncanonical_records() {
    let store = TestReplayStore::default();
    let protected = RollbackProtectedReplayStore::enroll(store).unwrap();
    let initial = protected.state();
    let encoded = initial.to_bytes();
    assert_eq!(encoded.len(), SIGNER_SECURE_REPLAY_STATE_BYTES);
    assert_eq!(
        SignerSecureReplayState::from_bytes(&encoded).unwrap(),
        initial
    );
    assert_eq!(format!("{initial:?}"), "SignerSecureReplayState(REDACTED)");

    for offset in [0, 4, 6, 7, 8, 24, 32] {
        let mut malformed = encoded;
        match offset {
            6 => malformed[offset] = 2,
            8 => malformed[offset..offset + 8].fill(0),
            24 => malformed[offset] = 1,
            32 => malformed[offset] = 1,
            _ => malformed[offset] ^= 1,
        }
        assert!(
            SignerSecureReplayState::from_bytes(&malformed).is_err(),
            "malformed secure replay state at offset {offset} was accepted"
        );
    }
}

#[test]
fn secure_replay_transitions_survive_reopen_and_consume_exactly_once() {
    let store = TestReplayStore::default();
    let observer = store.clone();
    let mut protected = RollbackProtectedReplayStore::enroll(store).unwrap();
    assert_eq!(protected.state().generation(), 1);

    let mut rng = ChaCha20Rng::from_seed([0x61; 32]);
    let challenge = protected
        .issue_challenge(NETWORK, CHANNEL, &mut rng)
        .unwrap();
    assert_eq!(challenge.counter(), 1);
    assert_eq!(protected.state().generation(), 2);
    assert!(protected.state().has_pending());
    drop(protected);

    let mut reopened = RollbackProtectedReplayStore::open(observer.clone()).unwrap();
    reopened.consume_challenge(&challenge).unwrap();
    assert_eq!(reopened.state().generation(), 3);
    assert_eq!(reopened.state().highest_issued(), 1);
    assert_eq!(reopened.state().highest_consumed(), 1);
    assert!(!reopened.state().has_pending());
    assert!(matches!(
        reopened.consume_challenge(&challenge),
        Err(SignerSecureReplayError::ReplayDetected)
    ));
    drop(reopened);

    let mut reopened = RollbackProtectedReplayStore::open(observer).unwrap();
    let next = reopened
        .issue_challenge(NETWORK, CHANNEL, &mut rng)
        .unwrap();
    assert_eq!(next.counter(), 2);
    assert_eq!(reopened.state().generation(), 4);
}

#[test]
fn secure_replay_binds_every_challenge_field_and_invalidates_abandoned_work() {
    let mut protected = RollbackProtectedReplayStore::enroll(TestReplayStore::default()).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x62; 32]);
    let abandoned = protected
        .issue_challenge(NETWORK, CHANNEL, &mut rng)
        .unwrap();
    let current = protected
        .issue_challenge(NETWORK, CHANNEL, &mut rng)
        .unwrap();
    assert!(matches!(
        protected.consume_challenge(&abandoned),
        Err(SignerSecureReplayError::ReplayDetected)
    ));

    let bytes = current.encode();
    for offset in [6, 38, 70, 103] {
        let mut modified = bytes.to_vec();
        modified[offset] ^= 1;
        let modified = SessionChallenge::decode(&modified).unwrap();
        assert!(matches!(
            protected.consume_challenge(&modified),
            Err(SignerSecureReplayError::ReplayDetected)
        ));
    }
    DurableReplayGuard::consume(&mut protected, &current).unwrap();
    assert_eq!(
        DurableReplayGuard::consume(&mut protected, &current),
        Err(SessionError::ReplayDetected)
    );
}

#[test]
fn uncertain_or_concurrent_secure_transition_poisons_the_handle() {
    let store = TestReplayStore::default();
    let observer = store.clone();
    let mut protected = RollbackProtectedReplayStore::enroll(store).unwrap();
    observer.0.borrow_mut().reject_next_compare = true;
    let mut rng = ChaCha20Rng::from_seed([0x63; 32]);
    assert!(matches!(
        protected.issue_challenge(NETWORK, CHANNEL, &mut rng),
        Err(SignerSecureReplayError::ConcurrentModification)
    ));
    assert!(matches!(
        protected.issue_challenge(NETWORK, CHANNEL, &mut rng),
        Err(SignerSecureReplayError::Poisoned)
    ));

    let mut reopened = RollbackProtectedReplayStore::open(observer.clone()).unwrap();
    observer.0.borrow_mut().fail_next_compare_after_write = true;
    assert!(matches!(
        reopened.issue_challenge(NETWORK, CHANNEL, &mut rng),
        Err(SignerSecureReplayError::SecureStore(_))
    ));
    assert!(matches!(
        reopened.issue_challenge(NETWORK, CHANNEL, &mut rng),
        Err(SignerSecureReplayError::Poisoned)
    ));
    drop(reopened);

    let persisted = RollbackProtectedReplayStore::open(observer).unwrap();
    assert_eq!(persisted.state().highest_issued(), 1);
    assert!(persisted.state().has_pending());
}
