use std::{fs, path::Path};

use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use tempfile::tempdir;
use vault_signer::{
    CrashConsistentReplayStore, DurableReplayGuard, REPLAY_STORE_STATE_BYTES, ReplayStoreError,
    SessionChallenge, SessionError,
};

const NETWORK: [u8; 32] = [0x31; 32];
const CHANNEL: [u8; 32] = [0x77; 32];

fn state_path(directory: &Path) -> std::path::PathBuf {
    directory.join("signer-replay.vsrg")
}

#[test]
fn issued_challenge_survives_restart_and_is_consumed_exactly_once() {
    let directory = tempdir().unwrap();
    let path = state_path(directory.path());
    let encoded_challenge;
    {
        let mut store = CrashConsistentReplayStore::create(&path).unwrap();
        assert_eq!(store.highest_issued(), 0);
        assert_eq!(store.highest_consumed(), 0);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            REPLAY_STORE_STATE_BYTES as u64
        );
        let mut rng = ChaCha20Rng::from_seed([0x81; 32]);
        let challenge = store.issue_challenge(NETWORK, CHANNEL, &mut rng).unwrap();
        assert_eq!(challenge.counter(), 1);
        assert_eq!(store.highest_issued(), 1);
        assert_eq!(store.highest_consumed(), 0);
        assert_eq!(fs::read(&path).unwrap()[6], 1);
        encoded_challenge = challenge.encode().to_vec();
    }

    {
        let mut store = CrashConsistentReplayStore::open(&path).unwrap();
        let challenge = SessionChallenge::decode(&encoded_challenge).unwrap();
        assert_eq!(store.highest_issued(), 1);
        assert_eq!(store.highest_consumed(), 0);
        store.consume_challenge(&challenge).unwrap();
        assert_eq!(store.highest_consumed(), 1);
        assert_eq!(fs::read(&path).unwrap()[6], 0);
        assert_eq!(
            store.consume_challenge(&challenge),
            Err(ReplayStoreError::ReplayDetected)
        );
    }

    let mut store = CrashConsistentReplayStore::open(&path).unwrap();
    let challenge = SessionChallenge::decode(&encoded_challenge).unwrap();
    assert_eq!(store.highest_issued(), 1);
    assert_eq!(store.highest_consumed(), 1);
    assert_eq!(
        store.consume_challenge(&challenge),
        Err(ReplayStoreError::ReplayDetected)
    );
}

#[test]
fn abandoned_challenges_are_invalidated_by_a_new_durable_counter() {
    let directory = tempdir().unwrap();
    let path = state_path(directory.path());
    let mut store = CrashConsistentReplayStore::create(&path).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x82; 32]);
    let abandoned = store.issue_challenge(NETWORK, CHANNEL, &mut rng).unwrap();
    let current = store.issue_challenge(NETWORK, CHANNEL, &mut rng).unwrap();

    assert_eq!(abandoned.counter(), 1);
    assert_eq!(current.counter(), 2);
    assert_eq!(
        store.consume_challenge(&abandoned),
        Err(ReplayStoreError::ReplayDetected)
    );
    store.consume_challenge(&current).unwrap();
    assert_eq!(store.highest_issued(), 2);
    assert_eq!(store.highest_consumed(), 2);
}

#[test]
fn exact_network_channel_session_and_counter_are_all_replay_bound() {
    let directory = tempdir().unwrap();
    let path = state_path(directory.path());
    let mut store = CrashConsistentReplayStore::create(&path).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x83; 32]);
    let challenge = store.issue_challenge(NETWORK, CHANNEL, &mut rng).unwrap();
    let bytes = challenge.encode();

    for offset in [6, 38, 70, 103] {
        let mut modified = bytes.to_vec();
        modified[offset] ^= 1;
        let modified = SessionChallenge::decode(&modified).unwrap();
        assert_eq!(
            store.consume_challenge(&modified),
            Err(ReplayStoreError::ReplayDetected),
            "modified challenge offset {offset} was accepted"
        );
    }
    store.consume_challenge(&challenge).unwrap();
}

#[test]
fn exclusive_lock_prevents_concurrent_store_owners() {
    let directory = tempdir().unwrap();
    let path = state_path(directory.path());
    assert_eq!(
        CrashConsistentReplayStore::open(&path).unwrap_err(),
        ReplayStoreError::StateMissing
    );
    let first = CrashConsistentReplayStore::create(&path).unwrap();
    assert_eq!(
        CrashConsistentReplayStore::open(&path).unwrap_err(),
        ReplayStoreError::LockContended
    );
    drop(first);
    assert_eq!(
        CrashConsistentReplayStore::create(&path).unwrap_err(),
        ReplayStoreError::StateAlreadyExists
    );
    CrashConsistentReplayStore::open(&path).unwrap();
}

#[test]
fn malformed_truncated_and_symlinked_state_fail_closed() {
    let directory = tempdir().unwrap();
    let path = state_path(directory.path());
    drop(CrashConsistentReplayStore::create(&path).unwrap());

    let original = fs::read(&path).unwrap();
    let mut corrupt = original.clone();
    corrupt[42] ^= 1;
    fs::write(&path, &corrupt).unwrap();
    assert_eq!(
        CrashConsistentReplayStore::open(&path).unwrap_err(),
        ReplayStoreError::CorruptState
    );

    fs::write(&path, &original[..original.len() - 1]).unwrap();
    assert_eq!(
        CrashConsistentReplayStore::open(&path).unwrap_err(),
        ReplayStoreError::CorruptState
    );

    fs::write(&path, &original).unwrap();
    assert_eq!(
        CrashConsistentReplayStore::open("relative-state.vsrg").unwrap_err(),
        ReplayStoreError::InvalidPath
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let link = directory.path().join("linked-state.vsrg");
        symlink(&path, &link).unwrap();
        assert_eq!(
            CrashConsistentReplayStore::open(&link).unwrap_err(),
            ReplayStoreError::InvalidPath
        );

        let hard_link = directory.path().join("hard-linked-state.vsrg");
        fs::hard_link(&path, &hard_link).unwrap();
        assert_eq!(
            CrashConsistentReplayStore::open(&hard_link).unwrap_err(),
            ReplayStoreError::InvalidPath
        );

        let insecure_parent = directory.path().join("insecure");
        fs::create_dir(&insecure_parent).unwrap();
        fs::set_permissions(&insecure_parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            CrashConsistentReplayStore::open(state_path(&insecure_parent)).unwrap_err(),
            ReplayStoreError::InvalidPath
        );
    }
}

#[test]
fn persistence_failure_poisoning_and_trait_mapping_are_fail_closed() {
    let directory = tempdir().unwrap();
    let live_parent = directory.path().join("live");
    let moved_parent = directory.path().join("moved");
    fs::create_dir(&live_parent).unwrap();
    let path = state_path(&live_parent);
    let mut store = CrashConsistentReplayStore::create(&path).unwrap();
    fs::rename(&live_parent, &moved_parent).unwrap();

    let mut rng = ChaCha20Rng::from_seed([0x84; 32]);
    assert_eq!(
        store
            .issue_challenge(NETWORK, CHANNEL, &mut rng)
            .unwrap_err(),
        ReplayStoreError::IoFailure
    );
    assert_eq!(
        store
            .issue_challenge(NETWORK, CHANNEL, &mut rng)
            .unwrap_err(),
        ReplayStoreError::Poisoned
    );

    let challenge = SessionChallenge::generate(NETWORK, CHANNEL, 1, &mut rng).unwrap();
    assert_eq!(
        DurableReplayGuard::consume(&mut store, &challenge),
        Err(SessionError::ReplayStoreFailure)
    );
}

#[test]
fn unix_state_and_lock_files_are_owner_only() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let path = state_path(directory.path());
        let store = CrashConsistentReplayStore::create(&path).unwrap();
        let state_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let lock_mode = fs::metadata(path.with_file_name("signer-replay.vsrg.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(state_mode, 0o600);
        assert_eq!(lock_mode, 0o600);
        assert!(format!("{store:?}").contains("REDACTED"));
    }
}
