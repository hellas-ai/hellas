use super::*;

fn fetch() -> Job {
    Job::fetch(20, FetchContract::http().unwrap(), "http".into(), "request".into(),
        br#"{"url":"https://example.test/path","method":"GET","tls":{"roots":{"mode":"web_pki"}},"max_response_bytes":4096}"#.to_vec(),
        Assurance::ProducerSigned).unwrap()
}

fn http_policy(max_encoded_prepared_input: u32, max_upload_bytes: u64) -> InvocationPolicy {
    use hellas_rpc::protocol::invocation::{
        Admission, Limits,
        fetch::{FetchAdmission, FetchLimits, FetchRoutePolicy},
    };
    InvocationPolicy {
        admissions: vec![Admission::Fetch {
            admission: FetchAdmission {
                contract: FetchContract::http().unwrap(),
                route: FetchRoutePolicy::open_fetch(false, vec![]),
                limits: FetchLimits {
                    max_request_body_bytes: 4096,
                    max_output_events: 64,
                    max_spool_bytes: 65536,
                    max_encoded_result_frame: 65536,
                    max_encoded_prepared_input,
                },
            },
        }],
        limits: Limits {
            max_upload_bytes,
            max_output_bytes: 65536,
            max_steps: 1,
            execution_timeout_ms: 60_000,
        },
    }
}

fn runner() -> PublicKey {
    ProducerSigningKey::from_secret_bytes([0x22; 32])
        .unwrap()
        .public_key()
}

#[test]
fn folder_round_trip_preserves_semantics_and_exact_signed_input() {
    let directory = tempfile::tempdir().unwrap();
    let job = fetch();
    let folder = directory.path().join("job");
    job.save(&folder).unwrap();
    let loaded = Job::load(&folder).unwrap();
    assert_eq!(loaded.canonical_bytes(), job.canonical_bytes());
    assert_eq!(loaded.digest(), job.digest());
    let key = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
    let nonce = job.purchase_nonce(Digest::from_bytes([9; 32]), 1);
    let policy = http_policy(65536, 65536);
    let direct = job.prepare(&key, nonce, runner(), &policy).unwrap();
    let from_folder = loaded.prepare(&key, nonce, runner(), &policy).unwrap();
    assert_eq!(
        direct.canonical_bytes().unwrap(),
        from_folder.canonical_bytes().unwrap()
    );
    let hellas_rpc::protocol::invocation::Admission::Fetch { admission } = &policy.admissions[0]
    else {
        unreachable!()
    };
    let request = fetch::validate_input(
        &from_folder,
        admission,
        policy.limits.max_output_bytes,
        &key.public_key(),
    )
    .unwrap();
    assert_eq!(request.retention, hellas_rpc::Retention::Ephemeral);
    assert_eq!(request.service, "http");
    assert_eq!(request.caller_key, key.public_key());
    assert_ne!(nonce, loaded.purchase_nonce(Digest::from_bytes([9; 32]), 2));
    assert_ne!(
        direct.canonical_bytes().unwrap(),
        loaded
            .prepare(
                &key,
                loaded.purchase_nonce(Digest::from_bytes([9; 32]), 2),
                runner(),
                &policy,
            )
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        "a new purchase changes the actual signed input"
    );
    assert_ne!(nonce, loaded.purchase_nonce(Digest::from_bytes([8; 32]), 1));
    job.save(&folder).unwrap();
}

#[test]
fn malformed_job_documents_and_missing_files_are_refused() {
    for change in [
        ("hellas.job.v1", "hellas.job.v2"),
        ("[payment]", "[payment]\nunknown = 1"),
        ("[application]", "[application]\nunknown = 1"),
        ("[fetch]", "[fetch]\nunknown = 1"),
        ("price = 20", "price = 0"),
        ("request.json", "missing.json"),
        ("request.json", "../request.json"),
        ("request.json", "/request.json"),
        ("hellas/fetch-0.0.2", "foreign/fetch"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        fetch().save(directory.path()).unwrap();
        let path = directory.path().join("job.toml");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(change.0),
            "missing mutation target {} in {text}",
            change.0
        );
        std::fs::write(path, text.replace(change.0, change.1)).unwrap();
        assert!(
            Job::load(directory.path()).is_err(),
            "accepted mutation {change:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn folder_paths_cannot_follow_a_symlink_outside_or_inside_the_folder() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fetch().save(directory.path()).unwrap();
    let payload = std::fs::read(directory.path().join("request.json")).unwrap();
    std::fs::write(outside.path().join("request.json"), &payload).unwrap();
    std::fs::remove_file(directory.path().join("request.json")).unwrap();
    symlink(
        outside.path().join("request.json"),
        directory.path().join("request.json"),
    )
    .unwrap();
    assert!(Job::load(directory.path()).is_err());
    std::fs::remove_file(directory.path().join("request.json")).unwrap();
    symlink(outside.path(), directory.path().join("link")).unwrap();
    let path = directory.path().join("job.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("request.json", "link/request.json");
    std::fs::write(path, text).unwrap();
    assert!(Job::load(directory.path()).is_err());
}

#[test]
fn compute_folder_round_trip_binds_environment_plan_and_price() {
    use hellas_channel::test_support::channel::{environment, plan, work_policy};
    let content = || {
        let mut content = EphemeralContent::default();
        content.insert(environment().canonical_bytes().unwrap());
        InvocationContent::Ephemeral(content)
    };
    let job = Job::compute(20, environment(), plan(), vec![], content()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    job.save(directory.path()).unwrap();
    let loaded = Job::load(directory.path()).unwrap();
    assert_eq!(job.canonical_bytes(), loaded.canonical_bytes());
    let key = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
    let prepared = loaded
        .prepare(&key, [7; 32], runner(), &work_policy())
        .unwrap();
    assert_eq!(prepared.request.nonce, [7; 32]);
    assert_eq!(
        prepared.manifest().unwrap(),
        environment().manifest().unwrap()
    );
    assert_eq!(prepared.request.runner_public_key, runner());
    assert_ne!(
        job.digest(),
        Job::compute(21, environment(), plan(), vec![], content())
            .unwrap()
            .digest()
    );
}

#[cfg(unix)]
#[test]
fn directory_reads_stay_with_the_selected_inode_after_its_name_is_replaced() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("job");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("input"), b"selected").unwrap();
    let held = hellas_private::ReadDirectory::open(&root).unwrap();
    std::fs::rename(&root, parent.path().join("moved")).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("input"), b"replacement").unwrap();
    assert_eq!(held.read(Path::new("input"), 32).unwrap(), b"selected");
}

#[test]
fn typed_job_price_must_round_trip_through_toml() {
    assert!(Job::from_input(u64::MAX, fetch().input().clone()).is_err());
    let job = Job::from_input(i64::MAX as u64, fetch().input().clone()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    job.save(directory.path()).unwrap();
    assert_eq!(Job::load(directory.path()).unwrap().digest(), job.digest());
}

#[test]
fn fetch_unsigned_preflight_checks_the_worst_nonce_encoded_byte_ceiling() {
    let job = fetch();
    let mut expected = crate::test_support::PaidFixture::new().policy;
    expected.payment_policy.fixed_price = job.price();
    let actual = job
        .prepare(
            &ProducerSigningKey::generate(),
            [255; 32],
            runner(),
            &http_policy(60_000, 65536),
        )
        .unwrap()
        .canonical_bytes()
        .unwrap()
        .len();
    for nonce in [0, 23, 24, 255] {
        let measured = job
            .prepare(
                &ProducerSigningKey::generate(),
                [nonce; 32],
                runner(),
                &http_policy(60_000, 65536),
            )
            .unwrap()
            .canonical_bytes()
            .unwrap()
            .len();
        assert!(measured <= actual, "nonce {nonce} encodes past the ceiling");
    }
    // The policy is part of the encoded input: measure with a limit that
    // encodes at the same width as the ceiling under test.
    assert!((256..60_000).contains(&actual));
    let actual_u32: u32 = actual.try_into().unwrap();
    expected.invocation_policy = http_policy(actual_u32, 65536);
    job.check_policy(&expected).unwrap();
    expected.invocation_policy = http_policy(actual_u32 - 1, 65536);
    assert!(job.check_policy(&expected).is_err());
}
