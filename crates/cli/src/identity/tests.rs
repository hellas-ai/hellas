use super::*;
use hellas_rpc::Signature;
use std::env;

#[test]
fn creates_and_reloads_one_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    let first = load_or_create(Some(&path)).unwrap();
    let persisted = fs::read(&path).unwrap();
    let stored = StoredIdentity::from_canonical_bytes(&persisted).unwrap();
    assert_eq!(stored.version, VERSION);
    assert_eq!(stored.canonical_bytes(), persisted);
    let second = load_or_create(Some(&path)).unwrap();

    assert_eq!(
        first.transport_key.to_bytes(),
        second.transport_key.to_bytes()
    );
    assert_eq!(
        first.producer_key.producer_id(),
        second.producer_key.producer_id()
    );
    assert_eq!(first.genesis, second.genesis);
    assert_eq!(first.enrollment, second.enrollment);
    assert_eq!(first.enrollment.genesis, first.genesis);
    assert_eq!(first.enrollment.platform, PlatformEnrollment::Absent);
    assert_eq!(first.genesis.statement.root_kind, RootKind::Software);
    assert_eq!(
        first.genesis.statement.transport_public_key,
        PublicKey::Ed25519(*first.transport_key.public().as_bytes())
    );
    assert_eq!(
        first.genesis.statement.producer_public_key,
        first.producer_key.public_key()
    );
    let other = load_or_create(Some(&dir.path().join("other"))).unwrap();
    assert_ne!(
        first.genesis.statement.installation_nonce,
        other.genesis.statement.installation_nonce
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn rejects_old_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    fs::write(&path, [0; 32]).unwrap();
    assert!(
        load_existing(Some(&path))
            .err()
            .unwrap()
            .to_string()
            .contains("unsupported encoding")
    );
}

#[test]
fn rejects_v2_json_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    fs::write(&path, br#"{"version":2}"#).unwrap();
    assert!(
        load_existing(Some(&path))
            .err()
            .unwrap()
            .to_string()
            .contains("unsupported encoding")
    );
}

#[test]
fn identity_canonical_decode_contract() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    load_or_create(Some(&path)).unwrap();
    let persisted = fs::read(&path).unwrap();
    let stored = StoredIdentity::from_canonical_bytes(&persisted).unwrap();
    assert_eq!(stored.canonical_bytes(), persisted);

    let mut trailing = persisted.clone();
    trailing.push(0);
    assert!(StoredIdentity::from_canonical_bytes(&trailing).is_err());

    let mut encoded_producer_key = vec![0x58, 0x20];
    encoded_producer_key.extend_from_slice(&stored.producer_key);
    let producer_key_start = persisted
        .windows(encoded_producer_key.len())
        .position(|window| window == encoded_producer_key)
        .unwrap();
    let mut wrong_length = persisted.clone();
    wrong_length[producer_key_start + 1] = 31;
    wrong_length.remove(producer_key_start + 33);
    assert!(StoredIdentity::from_canonical_bytes(&wrong_length).is_err());

    assert_eq!(persisted[0], 0x86);
    let mut noncanonical = vec![0x98, 0x06];
    noncanonical.extend_from_slice(&persisted[1..]);
    fs::write(&path, noncanonical).unwrap();
    assert!(load_existing(Some(&path)).is_err());
}

#[test]
fn rejects_tampered_root_signature() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    load_or_create(Some(&path)).unwrap();
    let mut stored = StoredIdentity::from_canonical_bytes(&fs::read(&path).unwrap()).unwrap();
    let RootProof::Software(Signature::Secp256k1(signature)) =
        &mut stored.enrollment.genesis.root_proof
    else {
        panic!("software identity has a software root proof");
    };
    signature[0] ^= 1;
    fs::write(&path, stored.canonical_bytes()).unwrap();
    assert!(load_existing(Some(&path)).is_err());
}

#[test]
fn creates_parent_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub/dir/identity");
    load_or_create(Some(&path)).unwrap();
    assert!(path.exists());
}

#[test]
fn default_path_uses_home() {
    let dir = tempfile::tempdir().unwrap();
    unsafe { env::set_var("HOME", dir.path()) };
    assert_eq!(default_path().unwrap(), dir.path().join(".hellas/identity"));
    #[cfg(feature = "evaluate")]
    assert_eq!(
        default_content_index_path().unwrap(),
        dir.path().join(".hellas/content-index.bin")
    );
    unsafe { env::remove_var("HOME") };
}

#[test]
fn concurrent_creation_converges() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                load_or_create(Some(&path))
                    .unwrap()
                    .transport_key
                    .to_bytes()
            })
        })
        .collect();
    let keys: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert!(keys.iter().all(|key| key == &keys[0]));
}

#[test]
fn assertion_counter_partial_temp_write_leaves_old_value_intact() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemAssertionCounterStore::new(dir.path());
    let public_key = [7; 33];
    store.advance(&public_key, 2).unwrap();

    let mut interrupted = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
    interrupted.write_all(&[0, 0]).unwrap();
    interrupted.flush().unwrap();
    let (interrupted, _) = interrupted.keep().unwrap();
    drop(interrupted);

    assert_eq!(
        fs::read(store.counter_path(&public_key)).unwrap(),
        2_u32.to_be_bytes()
    );
    assert_eq!(
        store.advance(&public_key, 1),
        Err(AttestationError::Counter)
    );
    store.advance(&public_key, 3).unwrap();
}

#[test]
fn assertion_counter_corruption_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemAssertionCounterStore::new(dir.path());
    let public_key = [8; 33];
    fs::write(store.counter_path(&public_key), [0, 1]).unwrap();

    assert_eq!(store.advance(&public_key, 3), Err(AttestationError::State));
}

#[test]
fn provider_trust_requires_complete_apple_policy_and_threads_assurance() {
    let expected = Some(hellas_rpc::ContentId::from_bytes([9; 32]));
    let producer = provider_trust(
        expected,
        hellas_rpc::Assurance::ProducerSigned,
        None,
        vec![],
    )
    .unwrap();
    assert_eq!(
        producer.required_assurance,
        hellas_rpc::Assurance::ProducerSigned
    );
    assert!(producer.apple_app_attest.is_none());

    assert!(
        provider_trust(
            expected,
            hellas_rpc::Assurance::AppleAppAttest,
            None,
            vec![[1; 32]],
        )
        .unwrap_err()
        .to_string()
        .contains("--apple-app-attest-app-id")
    );
    assert!(
        provider_trust(
            expected,
            hellas_rpc::Assurance::AppleAppAttest,
            Some("TEAM.example.app".to_owned()),
            vec![],
        )
        .unwrap_err()
        .to_string()
        .contains("--apple-app-attest-cdhashes")
    );
}
