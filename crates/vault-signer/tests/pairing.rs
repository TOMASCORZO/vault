use core::str::FromStr;

use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
#[cfg(unix)]
use tempfile::tempdir;
use vault_signer::{
    PairedSignerRecord, PairingFingerprint, SignerPairingError, SignerPairingHandshake,
    SignerTransportKeyPair,
};

#[cfg(unix)]
use vault_signer::{
    ENCRYPTED_PEER_REGISTRY_BYTES, EncryptedPeerRegistry, PAIRED_SIGNER_RECORD_BYTES,
    PeerRegistryError, PeerRegistryId, PeerRegistryScope, PeerRegistryStorageKey,
    SignerPairingRole, SignerTransportMessageKind,
};

const NETWORK: [u8; 32] = [0x31; 32];

fn completed_pairing(
    coordinator_key: &SignerTransportKeyPair,
    signer_key: &SignerTransportKeyPair,
) -> (
    vault_signer::UnconfirmedSignerPairing,
    vault_signer::UnconfirmedSignerPairing,
) {
    let mut coordinator = SignerPairingHandshake::coordinator(coordinator_key, NETWORK).unwrap();
    let mut signer = SignerPairingHandshake::signer(signer_key, NETWORK).unwrap();

    let first = coordinator.write_message().unwrap();
    signer.read_message(&first).unwrap();
    let second = signer.write_message().unwrap();
    coordinator.read_message(&second).unwrap();
    let third = coordinator.write_message().unwrap();
    signer.read_message(&third).unwrap();

    (coordinator.finish().unwrap(), signer.finish().unwrap())
}

#[test]
fn xx_pairing_requires_matching_out_of_band_confirmation() {
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let coordinator_key = SignerTransportKeyPair::generate(&mut rng);
    let signer_key = SignerTransportKeyPair::generate(&mut rng);
    let (coordinator, signer) = completed_pairing(&coordinator_key, &signer_key);

    assert_eq!(coordinator.fingerprint(), signer.fingerprint());
    let human_code = coordinator.fingerprint().human_code();
    assert_eq!(human_code.len(), 35);
    assert_eq!(
        PairingFingerprint::from_str(&human_code).unwrap(),
        signer.fingerprint()
    );
    assert_eq!(
        PairingFingerprint::from_str(&human_code.to_ascii_lowercase()).unwrap(),
        signer.fingerprint()
    );

    let mut wrong = signer.fingerprint().to_bytes();
    wrong[0] ^= 1;
    assert_eq!(
        coordinator.confirm(PairingFingerprint::from_bytes(wrong)),
        Err(SignerPairingError::ConfirmationFailed)
    );
}

#[test]
#[cfg(unix)]
fn confirmed_records_round_trip_and_open_the_paired_kk_channel() {
    let mut rng = ChaCha20Rng::from_seed([0x72; 32]);
    let coordinator_key = SignerTransportKeyPair::generate(&mut rng);
    let signer_key = SignerTransportKeyPair::generate(&mut rng);
    let (coordinator, signer) = completed_pairing(&coordinator_key, &signer_key);
    let fingerprint = coordinator.fingerprint();
    let coordinator_record = coordinator.confirm(fingerprint).unwrap();
    let signer_record = signer.confirm(fingerprint).unwrap();

    let coordinator_bytes = coordinator_record.encode();
    let signer_bytes = signer_record.encode();
    assert_eq!(coordinator_bytes.len(), PAIRED_SIGNER_RECORD_BYTES);
    assert_eq!(
        PairedSignerRecord::decode(&coordinator_bytes).unwrap(),
        coordinator_record
    );
    assert_eq!(
        PairedSignerRecord::decode(&signer_bytes).unwrap(),
        signer_record
    );
    assert_eq!(
        coordinator_record.remote_public_key(),
        signer_key.public_key()
    );
    assert_eq!(
        signer_record.remote_public_key(),
        coordinator_key.public_key()
    );

    let coordinator_directory = tempdir().unwrap();
    let signer_directory = tempdir().unwrap();
    let coordinator_storage_key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let signer_storage_key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let coordinator_scope = PeerRegistryScope::new(
        NETWORK,
        SignerPairingRole::Coordinator,
        &coordinator_key,
        PeerRegistryId::generate(&mut rng).unwrap(),
    )
    .unwrap();
    let signer_scope = PeerRegistryScope::new(
        NETWORK,
        SignerPairingRole::Signer,
        &signer_key,
        PeerRegistryId::generate(&mut rng).unwrap(),
    )
    .unwrap();
    let mut coordinator_registry = EncryptedPeerRegistry::create(
        coordinator_directory.path().join("peers.vpse"),
        &coordinator_storage_key,
        coordinator_scope,
        &mut rng,
    )
    .unwrap();
    let mut signer_registry = EncryptedPeerRegistry::create(
        signer_directory.path().join("peers.vpse"),
        &signer_storage_key,
        signer_scope,
        &mut rng,
    )
    .unwrap();
    let coordinator_id = coordinator_registry
        .add_confirmed(coordinator_record, &mut rng)
        .unwrap();
    let signer_id = signer_registry
        .add_confirmed(signer_record, &mut rng)
        .unwrap();
    assert_eq!(
        std::fs::metadata(coordinator_directory.path().join("peers.vpse"))
            .unwrap()
            .len(),
        ENCRYPTED_PEER_REGISTRY_BYTES as u64
    );
    let mut coordinator_handshake = coordinator_registry
        .open_handshake(coordinator_id, &coordinator_key)
        .unwrap();
    let mut signer_handshake = signer_registry
        .open_handshake(signer_id, &signer_key)
        .unwrap();
    let first = coordinator_handshake.write_message().unwrap();
    signer_handshake.read_message(&first).unwrap();
    let second = signer_handshake.write_message().unwrap();
    coordinator_handshake.read_message(&second).unwrap();
    let mut coordinator_transport = coordinator_handshake.into_transport().unwrap();
    let mut signer_transport = signer_handshake.into_transport().unwrap();
    assert_eq!(
        coordinator_transport.channel_binding(),
        signer_transport.channel_binding()
    );

    let ciphertext = signer_transport
        .write_message(SignerTransportMessageKind::Challenge, b"paired")
        .unwrap();
    let plaintext = coordinator_transport.read_message(&ciphertext).unwrap();
    assert_eq!(plaintext.payload, b"paired");
}

#[test]
#[cfg(unix)]
fn wrong_network_tampering_and_wrong_local_key_fail_closed() {
    let mut rng = ChaCha20Rng::from_seed([0x73; 32]);
    let coordinator_key = SignerTransportKeyPair::generate(&mut rng);
    let signer_key = SignerTransportKeyPair::generate(&mut rng);
    let unrelated_key = SignerTransportKeyPair::generate(&mut rng);

    let mut coordinator = SignerPairingHandshake::coordinator(&coordinator_key, NETWORK).unwrap();
    let mut wrong_network = SignerPairingHandshake::signer(&signer_key, [0x32; 32]).unwrap();
    let first = coordinator.write_message().unwrap();
    wrong_network.read_message(&first).unwrap();
    let second = wrong_network.write_message().unwrap();
    assert_eq!(
        coordinator.read_message(&second),
        Err(SignerPairingError::HandshakeFailed)
    );

    let mut coordinator = SignerPairingHandshake::coordinator(&coordinator_key, NETWORK).unwrap();
    let mut signer = SignerPairingHandshake::signer(&signer_key, NETWORK).unwrap();
    let first = coordinator.write_message().unwrap();
    signer.read_message(&first).unwrap();
    let mut second = signer.write_message().unwrap();
    let last = second.len() - 1;
    second[last] ^= 1;
    assert_eq!(
        coordinator.read_message(&second),
        Err(SignerPairingError::HandshakeFailed)
    );

    let (coordinator, signer) = completed_pairing(&coordinator_key, &signer_key);
    let fingerprint = coordinator.fingerprint();
    let coordinator_record = coordinator.confirm(fingerprint).unwrap();
    let _signer_record = signer.confirm(fingerprint).unwrap();
    let directory = tempdir().unwrap();
    let storage_key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let scope = PeerRegistryScope::new(
        NETWORK,
        SignerPairingRole::Coordinator,
        &coordinator_key,
        PeerRegistryId::generate(&mut rng).unwrap(),
    )
    .unwrap();
    let mut registry = EncryptedPeerRegistry::create(
        directory.path().join("peers.vpse"),
        &storage_key,
        scope,
        &mut rng,
    )
    .unwrap();
    let id = registry
        .add_confirmed(coordinator_record, &mut rng)
        .unwrap();
    assert_eq!(
        registry.open_handshake(id, &unrelated_key).unwrap_err(),
        PeerRegistryError::InvalidScope
    );
}

#[test]
fn paired_record_decoder_rejects_noncanonical_or_modified_state() {
    let mut rng = ChaCha20Rng::from_seed([0x74; 32]);
    let coordinator_key = SignerTransportKeyPair::generate(&mut rng);
    let signer_key = SignerTransportKeyPair::generate(&mut rng);
    let (coordinator, _) = completed_pairing(&coordinator_key, &signer_key);
    let fingerprint = coordinator.fingerprint();
    let record = coordinator.confirm(fingerprint).unwrap();
    let encoded = record.encode();

    assert_eq!(
        PairedSignerRecord::decode(&encoded[..encoded.len() - 1]),
        Err(SignerPairingError::InvalidRecord)
    );
    for index in [0, 4, 6, 7, 8, 40, 72, 104, 136] {
        let mut modified = encoded;
        modified[index] ^= 1;
        assert_eq!(
            PairedSignerRecord::decode(&modified),
            Err(SignerPairingError::InvalidRecord),
            "modified byte {index} was accepted"
        );
    }

    assert_eq!(
        PairingFingerprint::from_str("00000000-00000000-00000000-0000000Z"),
        Err(SignerPairingError::ConfirmationFailed)
    );
    assert!(format!("{record:?}").contains("REDACTED"));
}
