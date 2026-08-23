use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use tempfile::tempdir;
use vault_signer::{
    EncryptedPeerRegistry, PeerRegistryId, PeerRegistryScope, PeerRegistryStorageKey,
    SignerPairingHandshake, SignerPairingRole, SignerTransport, SignerTransportKeyPair,
};

pub fn paired_transport(seed: [u8; 32], network: [u8; 32]) -> (SignerTransport, SignerTransport) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let coordinator_key = SignerTransportKeyPair::generate(&mut rng);
    let signer_key = SignerTransportKeyPair::generate(&mut rng);
    let mut coordinator_pairing =
        SignerPairingHandshake::coordinator(&coordinator_key, network).unwrap();
    let mut signer_pairing = SignerPairingHandshake::signer(&signer_key, network).unwrap();
    let first = coordinator_pairing.write_message().unwrap();
    signer_pairing.read_message(&first).unwrap();
    let second = signer_pairing.write_message().unwrap();
    coordinator_pairing.read_message(&second).unwrap();
    let third = coordinator_pairing.write_message().unwrap();
    signer_pairing.read_message(&third).unwrap();
    let coordinator_pairing = coordinator_pairing.finish().unwrap();
    let signer_pairing = signer_pairing.finish().unwrap();
    let fingerprint = coordinator_pairing.fingerprint();
    assert_eq!(fingerprint, signer_pairing.fingerprint());
    let coordinator_record = coordinator_pairing.confirm(fingerprint).unwrap();
    let signer_record = signer_pairing.confirm(fingerprint).unwrap();

    let coordinator_directory = tempdir().unwrap();
    let signer_directory = tempdir().unwrap();
    let coordinator_storage_key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let signer_storage_key = PeerRegistryStorageKey::generate(&mut rng).unwrap();
    let coordinator_scope = PeerRegistryScope::new(
        network,
        SignerPairingRole::Coordinator,
        &coordinator_key,
        PeerRegistryId::generate(&mut rng).unwrap(),
    )
    .unwrap();
    let signer_scope = PeerRegistryScope::new(
        network,
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
    let mut coordinator = coordinator_registry
        .open_handshake(coordinator_id, &coordinator_key)
        .unwrap();
    let mut signer = signer_registry
        .open_handshake(signer_id, &signer_key)
        .unwrap();
    let first = coordinator.write_message().unwrap();
    signer.read_message(&first).unwrap();
    let second = signer.write_message().unwrap();
    coordinator.read_message(&second).unwrap();
    (
        coordinator.into_transport().unwrap(),
        signer.into_transport().unwrap(),
    )
}
