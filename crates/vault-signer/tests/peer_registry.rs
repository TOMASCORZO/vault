use std::{fs, path::Path};

use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use tempfile::tempdir;
use vault_signer::{
    ENCRYPTED_PEER_REGISTRY_BYTES, EncryptedPeerRegistry, MAX_ACTIVE_PAIRED_SIGNERS,
    PairedPeerState, PairedSignerRecord, PairingConfirmationFacts, PairingFingerprint,
    PeerLifecycleAction, PeerLifecycleConfirmationFacts, PeerRegistryError, PeerRegistryId,
    PeerRegistryScope, PeerRegistryStorageKey, SignerConfirmationError, SignerHandshake,
    SignerPairingHandshake, SignerPairingRole, SignerTransportError, SignerTransportKeyPair,
    SignerTransportMessageKind, TrustedPairingConfirmation, TrustedPeerConfirmation,
    UnconfirmedSignerPairing,
};

const NETWORK: [u8; 32] = [0x31; 32];

#[derive(Default)]
struct RecordingPeerConfirmation {
    facts: Vec<PeerLifecycleConfirmationFacts>,
    reject: bool,
}

impl TrustedPeerConfirmation for RecordingPeerConfirmation {
    fn confirm_peer_lifecycle(
        &mut self,
        facts: &PeerLifecycleConfirmationFacts,
    ) -> Result<(), SignerConfirmationError> {
        self.facts.push(*facts);
        if self.reject {
            Err(SignerConfirmationError::Rejected)
        } else {
            Ok(())
        }
    }
}

struct TestPairingConfirmation(PairingFingerprint);

impl TrustedPairingConfirmation for TestPairingConfirmation {
    fn confirm_pairing(
        &mut self,
        _facts: &PairingConfirmationFacts,
    ) -> Result<PairingFingerprint, SignerConfirmationError> {
        Ok(self.0)
    }
}

fn registry_id() -> PeerRegistryId {
    PeerRegistryId::from_bytes([0x61; 32]).unwrap()
}

fn completed_pairing(
    coordinator_key: &SignerTransportKeyPair,
    signer_key: &SignerTransportKeyPair,
    network: [u8; 32],
) -> (UnconfirmedSignerPairing, UnconfirmedSignerPairing) {
    let mut coordinator = SignerPairingHandshake::coordinator(coordinator_key, network).unwrap();
    let mut signer = SignerPairingHandshake::signer(signer_key, network).unwrap();
    let first = coordinator.write_message().unwrap();
    signer.read_message(&first).unwrap();
    let second = signer.write_message().unwrap();
    coordinator.read_message(&second).unwrap();
    let third = coordinator.write_message().unwrap();
    signer.read_message(&third).unwrap();
    (coordinator.finish().unwrap(), signer.finish().unwrap())
}

fn confirmed_pairing(
    coordinator_key: &SignerTransportKeyPair,
    signer_key: &SignerTransportKeyPair,
    network: [u8; 32],
) -> (PairedSignerRecord, PairedSignerRecord) {
    let (coordinator, signer) = completed_pairing(coordinator_key, signer_key, network);
    let fingerprint = coordinator.fingerprint();
    assert_eq!(fingerprint, signer.fingerprint());
    (
        coordinator
            .confirm(&mut TestPairingConfirmation(fingerprint))
            .unwrap(),
        signer
            .confirm(&mut TestPairingConfirmation(fingerprint))
            .unwrap(),
    )
}

fn registered_handshake<R: rand_core::RngCore + rand_core::CryptoRng>(
    path: &Path,
    record: PairedSignerRecord,
    local: &SignerTransportKeyPair,
    rng: &mut R,
) -> SignerHandshake {
    let storage_key = PeerRegistryStorageKey::generate(rng).unwrap();
    let scope = PeerRegistryScope::new(
        record.network_id(),
        record.role(),
        local,
        PeerRegistryId::generate(rng).unwrap(),
    )
    .unwrap();
    let mut registry = EncryptedPeerRegistry::create(path, &storage_key, scope, rng).unwrap();
    let id = registry.add_confirmed(record, rng).unwrap();
    registry.open_handshake(id, local).unwrap()
}

#[test]
fn registry_encrypts_fixed_size_state_and_reopens_exactly() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("peers.vpse");
    let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
    let local = SignerTransportKeyPair::generate(&mut rng);
    let remote = SignerTransportKeyPair::generate(&mut rng);
    let key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let scope = PeerRegistryScope::new(
        NETWORK,
        SignerPairingRole::Coordinator,
        &local,
        registry_id(),
    )
    .unwrap();
    let (record, _) = confirmed_pairing(&local, &remote, NETWORK);
    let record_bytes = record.encode();
    let fingerprint_code = record.fingerprint().human_code();
    let peer_id;

    {
        let mut registry = EncryptedPeerRegistry::create(&path, &key, scope, &mut rng).unwrap();
        assert_eq!(registry.generation(), 1);
        assert!(registry.peers().is_empty());
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            ENCRYPTED_PEER_REGISTRY_BYTES as u64
        );
        peer_id = registry.add_confirmed(record, &mut rng).unwrap();
        assert_eq!(registry.generation(), 2);
        assert_eq!(registry.peers()[0].state(), PairedPeerState::Active);

        let encrypted = fs::read(&path).unwrap();
        assert_eq!(encrypted.len(), ENCRYPTED_PEER_REGISTRY_BYTES);
        assert!(
            !encrypted
                .windows(record_bytes.len())
                .any(|window| window == record_bytes)
        );
        assert!(
            !encrypted
                .windows(fingerprint_code.len())
                .any(|window| window == fingerprint_code.as_bytes())
        );
    }

    let registry = EncryptedPeerRegistry::open(&path, &key, scope).unwrap();
    assert_eq!(registry.generation(), 2);
    assert_eq!(registry.peers().len(), 1);
    assert_eq!(registry.peers()[0].id(), peer_id);
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        ENCRYPTED_PEER_REGISTRY_BYTES as u64
    );
    assert!(format!("{registry:?}").contains("REDACTED"));
    assert!(format!("{key:?}").contains("REDACTED"));
}

#[test]
fn only_active_registry_entries_can_open_the_paired_kk_channel() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("peers.vpse");
    let mut rng = ChaCha20Rng::from_seed([0x92; 32]);
    let coordinator_key = SignerTransportKeyPair::generate(&mut rng);
    let signer_key = SignerTransportKeyPair::generate(&mut rng);
    let storage_key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let scope = PeerRegistryScope::new(
        NETWORK,
        SignerPairingRole::Coordinator,
        &coordinator_key,
        registry_id(),
    )
    .unwrap();
    let (coordinator_record, signer_record) =
        confirmed_pairing(&coordinator_key, &signer_key, NETWORK);
    let fingerprint = coordinator_record.fingerprint();
    let mut registry = EncryptedPeerRegistry::create(&path, &storage_key, scope, &mut rng).unwrap();
    let peer_id = registry
        .add_confirmed(coordinator_record.clone(), &mut rng)
        .unwrap();

    let mut coordinator = registry.open_handshake(peer_id, &coordinator_key).unwrap();
    let mut signer = registered_handshake(
        &directory.path().join("signer-peers.vpse"),
        signer_record,
        &signer_key,
        &mut rng,
    );
    let first = coordinator.write_message().unwrap();
    signer.read_message(&first).unwrap();
    let second = signer.write_message().unwrap();
    coordinator.read_message(&second).unwrap();
    let mut coordinator = coordinator.into_transport().unwrap();
    let mut signer = signer.into_transport().unwrap();
    let encrypted = coordinator
        .write_message(SignerTransportMessageKind::Challenge, b"active")
        .unwrap();
    assert_eq!(signer.read_message(&encrypted).unwrap().payload, b"active");

    let mut rejected = RecordingPeerConfirmation {
        reject: true,
        ..Default::default()
    };
    assert_eq!(
        registry.revoke_confirmed(peer_id, &mut rejected, &mut rng),
        Err(PeerRegistryError::ConfirmationFailed)
    );
    assert_eq!(registry.generation(), 2);
    let still_active = coordinator
        .write_message(SignerTransportMessageKind::Abort, b"still-active")
        .unwrap();
    assert_eq!(
        signer.read_message(&still_active).unwrap().payload,
        b"still-active"
    );

    let mut confirmed = RecordingPeerConfirmation::default();
    registry
        .revoke_confirmed(peer_id, &mut confirmed, &mut rng)
        .unwrap();
    assert_eq!(confirmed.facts.len(), 1);
    assert_eq!(confirmed.facts[0].action(), PeerLifecycleAction::Revoke);
    assert_eq!(confirmed.facts[0].network_id(), NETWORK);
    assert_eq!(
        confirmed.facts[0].local_role(),
        SignerPairingRole::Coordinator
    );
    assert_eq!(confirmed.facts[0].peer_id(), peer_id);
    assert_eq!(confirmed.facts[0].current_fingerprint(), fingerprint);
    assert_eq!(confirmed.facts[0].replacement_fingerprint(), None);
    assert_eq!(confirmed.facts[0].current_generation(), 2);
    assert_eq!(registry.generation(), 3);
    assert_eq!(registry.peers()[0].state(), PairedPeerState::Revoked);
    assert_eq!(
        coordinator
            .write_message(SignerTransportMessageKind::Abort, b"revoked")
            .unwrap_err(),
        SignerTransportError::Closed
    );
    assert_eq!(
        registry
            .open_handshake(peer_id, &coordinator_key)
            .unwrap_err(),
        PeerRegistryError::PeerRevoked
    );
    assert_eq!(
        registry.revoke_confirmed(peer_id, &mut confirmed, &mut rng),
        Err(PeerRegistryError::PeerRevoked)
    );
    assert_eq!(
        registry.add_confirmed(coordinator_record, &mut rng),
        Err(PeerRegistryError::PeerAlreadyKnown)
    );

    let (same_static_new_transcript, _) = confirmed_pairing(&coordinator_key, &signer_key, NETWORK);
    assert_ne!(same_static_new_transcript.fingerprint(), fingerprint);
    assert_eq!(
        registry.add_confirmed(same_static_new_transcript, &mut rng),
        Err(PeerRegistryError::PeerAlreadyKnown)
    );
}

#[test]
fn rotation_tombstones_old_peer_and_installs_fresh_identity_atomically() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("peers.vpse");
    let mut rng = ChaCha20Rng::from_seed([0x93; 32]);
    let coordinator_key = SignerTransportKeyPair::generate(&mut rng);
    let first_signer_key = SignerTransportKeyPair::generate(&mut rng);
    let second_signer_key = SignerTransportKeyPair::generate(&mut rng);
    let storage_key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let scope = PeerRegistryScope::new(
        NETWORK,
        SignerPairingRole::Coordinator,
        &coordinator_key,
        registry_id(),
    )
    .unwrap();
    let (first_record, first_signer_record) =
        confirmed_pairing(&coordinator_key, &first_signer_key, NETWORK);
    let (replacement, replacement_signer_record) =
        confirmed_pairing(&coordinator_key, &second_signer_key, NETWORK);
    let mut registry = EncryptedPeerRegistry::create(&path, &storage_key, scope, &mut rng).unwrap();
    let first_id = registry.add_confirmed(first_record, &mut rng).unwrap();
    let mut old_coordinator = registry.open_handshake(first_id, &coordinator_key).unwrap();
    let mut old_signer = registered_handshake(
        &directory.path().join("first-signer-peers.vpse"),
        first_signer_record,
        &first_signer_key,
        &mut rng,
    );
    let first = old_coordinator.write_message().unwrap();
    old_signer.read_message(&first).unwrap();
    let second = old_signer.write_message().unwrap();
    old_coordinator.read_message(&second).unwrap();
    let mut old_coordinator = old_coordinator.into_transport().unwrap();
    let _old_signer = old_signer.into_transport().unwrap();
    let mut confirmation = RecordingPeerConfirmation::default();
    let replacement_id = registry
        .rotate_confirmed(first_id, replacement, &mut confirmation, &mut rng)
        .unwrap();

    assert_eq!(confirmation.facts.len(), 1);
    assert_eq!(confirmation.facts[0].action(), PeerLifecycleAction::Rotate);
    assert_eq!(confirmation.facts[0].peer_id(), first_id);
    assert_eq!(confirmation.facts[0].current_generation(), 2);
    assert_eq!(
        confirmation.facts[0].replacement_fingerprint(),
        Some(replacement_signer_record.fingerprint())
    );

    assert_eq!(
        old_coordinator
            .write_message(SignerTransportMessageKind::Abort, b"rotated")
            .unwrap_err(),
        SignerTransportError::Closed
    );

    assert_eq!(registry.generation(), 3);
    let old = registry
        .peers()
        .into_iter()
        .find(|peer| peer.id() == first_id)
        .unwrap();
    let new = registry
        .peers()
        .into_iter()
        .find(|peer| peer.id() == replacement_id)
        .unwrap();
    assert_eq!(old.state(), PairedPeerState::Revoked);
    assert_eq!(old.revoked_generation(), Some(3));
    assert_eq!(new.state(), PairedPeerState::Active);
    assert_eq!(new.created_generation(), 3);
    assert_eq!(
        registry
            .open_handshake(first_id, &coordinator_key)
            .unwrap_err(),
        PeerRegistryError::PeerRevoked
    );

    let mut coordinator = registry
        .open_handshake(replacement_id, &coordinator_key)
        .unwrap();
    let mut signer = registered_handshake(
        &directory.path().join("replacement-signer-peers.vpse"),
        replacement_signer_record,
        &second_signer_key,
        &mut rng,
    );
    let first = coordinator.write_message().unwrap();
    signer.read_message(&first).unwrap();
    let second = signer.write_message().unwrap();
    coordinator.read_message(&second).unwrap();
    assert!(coordinator.into_transport().is_ok());
    assert!(signer.into_transport().is_ok());

    drop(registry);
    let registry = EncryptedPeerRegistry::open(&path, &storage_key, scope).unwrap();
    assert_eq!(registry.generation(), 3);
    assert_eq!(registry.peers().len(), 2);
}

#[test]
fn wrong_key_scope_tampering_and_noncanonical_lengths_fail_closed() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("peers.vpse");
    let mut rng = ChaCha20Rng::from_seed([0x94; 32]);
    let local = SignerTransportKeyPair::generate(&mut rng);
    let key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let wrong_key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let scope = PeerRegistryScope::new(
        NETWORK,
        SignerPairingRole::Coordinator,
        &local,
        registry_id(),
    )
    .unwrap();
    drop(EncryptedPeerRegistry::create(&path, &key, scope, &mut rng).unwrap());
    let original = fs::read(&path).unwrap();

    assert_eq!(
        EncryptedPeerRegistry::open(&path, &wrong_key, scope).unwrap_err(),
        PeerRegistryError::AuthenticationFailed
    );
    let wrong_scope = PeerRegistryScope::new(
        [0x32; 32],
        SignerPairingRole::Coordinator,
        &local,
        registry_id(),
    )
    .unwrap();
    assert_eq!(
        EncryptedPeerRegistry::open(&path, &key, wrong_scope).unwrap_err(),
        PeerRegistryError::AuthenticationFailed
    );
    let wrong_slot = PeerRegistryScope::new(
        NETWORK,
        SignerPairingRole::Coordinator,
        &local,
        PeerRegistryId::from_bytes([0x62; 32]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        EncryptedPeerRegistry::open(&path, &key, wrong_slot).unwrap_err(),
        PeerRegistryError::AuthenticationFailed
    );

    for offset in [0, 4, 6, 7, 32] {
        let mut modified = original.clone();
        modified[offset] ^= 1;
        fs::write(&path, &modified).unwrap();
        assert_eq!(
            EncryptedPeerRegistry::open(&path, &key, scope).unwrap_err(),
            PeerRegistryError::InvalidStore,
            "canonical header mutation at {offset} was accepted"
        );
    }
    for offset in [8, 36, original.len() - 1] {
        let mut modified = original.clone();
        modified[offset] ^= 1;
        fs::write(&path, &modified).unwrap();
        assert_eq!(
            EncryptedPeerRegistry::open(&path, &key, scope).unwrap_err(),
            PeerRegistryError::AuthenticationFailed,
            "authenticated mutation at {offset} was accepted"
        );
    }

    fs::write(&path, &original[..original.len() - 1]).unwrap();
    assert_eq!(
        EncryptedPeerRegistry::open(&path, &key, scope).unwrap_err(),
        PeerRegistryError::InvalidStore
    );
    let mut oversized = original;
    oversized.push(0);
    fs::write(&path, oversized).unwrap();
    assert_eq!(
        EncryptedPeerRegistry::open(&path, &key, scope).unwrap_err(),
        PeerRegistryError::InvalidStore
    );
}

#[test]
fn duplicate_owner_scope_capacity_locking_and_io_failure_are_enforced() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("peers.vpse");
    let mut rng = ChaCha20Rng::from_seed([0x95; 32]);
    let local = SignerTransportKeyPair::generate(&mut rng);
    let other_local = SignerTransportKeyPair::generate(&mut rng);
    let key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let scope = PeerRegistryScope::new(
        NETWORK,
        SignerPairingRole::Coordinator,
        &local,
        registry_id(),
    )
    .unwrap();
    assert_eq!(
        EncryptedPeerRegistry::open(&path, &key, scope).unwrap_err(),
        PeerRegistryError::StoreMissing
    );
    let mut registry = EncryptedPeerRegistry::create(&path, &key, scope, &mut rng).unwrap();
    assert_eq!(
        EncryptedPeerRegistry::open(&path, &key, scope).unwrap_err(),
        PeerRegistryError::LockContended
    );

    let wrong_remote = SignerTransportKeyPair::generate(&mut rng);
    let (wrong_local_record, _) = confirmed_pairing(&other_local, &wrong_remote, NETWORK);
    assert_eq!(
        registry.add_confirmed(wrong_local_record, &mut rng),
        Err(PeerRegistryError::InvalidScope)
    );

    for _ in 0..MAX_ACTIVE_PAIRED_SIGNERS {
        let remote = SignerTransportKeyPair::generate(&mut rng);
        let (record, _) = confirmed_pairing(&local, &remote, NETWORK);
        registry.add_confirmed(record, &mut rng).unwrap();
    }
    let excess_remote = SignerTransportKeyPair::generate(&mut rng);
    let (excess, _) = confirmed_pairing(&local, &excess_remote, NETWORK);
    assert_eq!(
        registry.add_confirmed(excess, &mut rng),
        Err(PeerRegistryError::CapacityExceeded)
    );

    drop(registry);
    assert_eq!(
        EncryptedPeerRegistry::create(&path, &key, scope, &mut rng).unwrap_err(),
        PeerRegistryError::StoreAlreadyExists
    );
    let live_parent = directory.path().join("live");
    let moved_parent = directory.path().join("moved");
    fs::create_dir(&live_parent).unwrap();
    let failing_path = live_parent.join("peers.vpse");
    let mut failing = EncryptedPeerRegistry::create(&failing_path, &key, scope, &mut rng).unwrap();
    let established_remote = SignerTransportKeyPair::generate(&mut rng);
    let (established_record, established_remote_record) =
        confirmed_pairing(&local, &established_remote, NETWORK);
    let established_id = failing.add_confirmed(established_record, &mut rng).unwrap();
    let mut established_local = failing.open_handshake(established_id, &local).unwrap();
    let mut established_signer = registered_handshake(
        &directory.path().join("failing-remote-peers.vpse"),
        established_remote_record,
        &established_remote,
        &mut rng,
    );
    let first = established_local.write_message().unwrap();
    established_signer.read_message(&first).unwrap();
    let second = established_signer.write_message().unwrap();
    established_local.read_message(&second).unwrap();
    let mut established_local = established_local.into_transport().unwrap();
    let _established_signer = established_signer.into_transport().unwrap();

    let remote = SignerTransportKeyPair::generate(&mut rng);
    let (record, _) = confirmed_pairing(&local, &remote, NETWORK);
    fs::rename(&live_parent, &moved_parent).unwrap();
    assert_eq!(
        failing.add_confirmed(record, &mut rng),
        Err(PeerRegistryError::IoFailure)
    );
    assert_eq!(
        established_local
            .write_message(SignerTransportMessageKind::Abort, b"poisoned")
            .unwrap_err(),
        SignerTransportError::Closed
    );
    assert_eq!(
        failing
            .open_handshake(
                vault_signer::PairedPeerId::from_bytes([0x44; 32]).unwrap(),
                &local,
            )
            .unwrap_err(),
        PeerRegistryError::Poisoned
    );

    assert_eq!(
        PeerRegistryStorageKey::from_bytes([0; 32]).unwrap_err(),
        PeerRegistryError::InvalidStorageKey
    );
    assert_eq!(
        PeerRegistryId::from_bytes([0; 32]).unwrap_err(),
        PeerRegistryError::InvalidScope
    );
}
