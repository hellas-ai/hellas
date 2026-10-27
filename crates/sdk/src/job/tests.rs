use super::*;

fn fetch() -> Job {
    Job::fetch(20, FetchContract::http().unwrap(), "http".into(), "request".into(),
        br#"{"url":"https://example.test/path","method":"GET","tls":{"roots":{"mode":"web_pki"}},"max_response_bytes":4096}"#.to_vec(),
        Assurance::ProducerSigned).unwrap()
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
    let direct = job.prepare(&key, nonce).unwrap();
    let from_folder = loaded.prepare(&key, nonce).unwrap();
    assert_eq!(direct.encode().unwrap(), from_folder.encode().unwrap());
    let PreparedWorkInput::Fetch(prepared) = from_folder else {
        panic!("Fetch input")
    };
    let parts = prepared.parts().unwrap();
    let request = hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript).unwrap();
    assert_eq!(request.retention, hellas_rpc::Retention::Ephemeral);
    assert_eq!(request.service, "http");
    assert_eq!(request.caller_key, key.public_key());
    assert_ne!(nonce, loaded.purchase_nonce(Digest::from_bytes([9; 32]), 2));
    assert_ne!(
        direct.encode().unwrap(),
        loaded
            .prepare(&key, loaded.purchase_nonce(Digest::from_bytes([9; 32]), 2))
            .unwrap()
            .encode()
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
fn causal_lm_folder_round_trip_binds_environment_tokens_and_generation_policy() {
    let environment = CausalLmEnvironment::new(
        hellas_rpc::ContentRef::new(hellas_rpc::ContentId::from_bytes([9; 32]), 1),
        "main",
        Vec::new(),
        Vec::new(),
        vec![4],
        3,
        128,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 128,
            prefill_chunk_tokens: 64,
        },
    )
    .unwrap();
    let job = Job::causal_lm(20, environment.clone(), vec![0, 1], 3, vec![2]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    job.save(directory.path()).unwrap();
    let loaded = Job::load(directory.path()).unwrap();
    assert_eq!(job.canonical_bytes(), loaded.canonical_bytes());
    let key = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
    let input = loaded.prepare(&key, [7; 32]).unwrap();
    let PreparedWorkInput::Evaluate(prepared) = input else {
        panic!("causal LM input")
    };
    let parts = prepared.parts().unwrap();
    assert_eq!(parts.evaluate_request.nonce, [7; 32]);
    assert_eq!(parts.manifest, environment.manifest());
    assert_eq!(parts.evaluate_request.runner_public_key, key.public_key());
    assert_eq!(
        parts.prompt_tokens,
        hellas_rpc::protocol::artifacts::TokenIds::from_u32s(vec![0, 1])
    );
    assert_ne!(
        job.digest(),
        Job::causal_lm(21, environment, vec![0, 1], 3, vec![2])
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
fn causal_lm_unsigned_preflight_enforces_generation_identity_and_input_limits() {
    use hellas_rpc::protocol::artifacts::{BoundTermId, Canonical as _, TextArtifact, TextPolicy};
    use hellas_work::model::{
        profile::WorkPolicy,
        work::{EvaluatePolicyV2, generation_policy_digest, identity_source_digest},
    };
    let environment = CausalLmEnvironment::new(
        hellas_rpc::ContentRef::new(hellas_rpc::ContentId::from_bytes([9; 32]), 1),
        "main",
        vec![],
        vec![],
        vec![4],
        3,
        128,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 128,
            prefill_chunk_tokens: 64,
        },
    )
    .unwrap();
    let job = Job::causal_lm(20, environment, vec![0, 1], 3, vec![2]).unwrap();
    let mut policy = crate::test_support::PaidFixture::new().policy;
    policy.payment_policy.fixed_price = 20;
    let allowed = EvaluatePolicyV2 {
        allowed_environment: job.manifest().content_id(),
        generation_policy_digest: generation_policy_digest(
            &TextPolicy::from_u32_stop_tokens(4, vec![2]).canonical_bytes(),
        )
        .unwrap(),
        identity_source_digest: identity_source_digest(
            &TextArtifact::identity(BoundTermId::from_digest(
                job.manifest().content_id().digest(),
            ))
            .canonical_bytes(),
        )
        .unwrap(),
        max_prompt_tokens: 2,
        max_new_tokens: 4,
        max_stop_token_ids: 1,
        max_spool_bytes: 65536,
        max_encoded_result_frame: 65536,
        max_encoded_prepared_input: 65536,
        max_upload_bytes: 65536,
    };
    policy.work_policy = WorkPolicy::Evaluate(allowed);
    job.check_policy(&policy).unwrap();
    for field in [
        "generation",
        "identity",
        "prompt",
        "new tokens",
        "stop count",
        "encoded bytes",
        "upload bytes",
    ] {
        let mut denied = allowed;
        match field {
            "generation" => denied.generation_policy_digest = Digest::from_bytes([1; 32]),
            "identity" => denied.identity_source_digest = Digest::from_bytes([1; 32]),
            "prompt" => denied.max_prompt_tokens = 1,
            "new tokens" => denied.max_new_tokens = 2,
            "stop count" => denied.max_stop_token_ids = 0,
            "encoded bytes" => denied.max_encoded_prepared_input = 1,
            "upload bytes" => denied.max_upload_bytes = 1,
            _ => unreachable!(),
        }
        policy.work_policy = WorkPolicy::Evaluate(denied);
        assert!(
            job.check_policy(&policy).is_err(),
            "unsigned preflight admitted {field}"
        );
    }
}

#[test]
fn fetch_unsigned_preflight_checks_the_worst_nonce_encoded_byte_ceiling() {
    use hellas_work::model::{
        fetch::{FetchRoutePolicy, fetch_route_commitment},
        profile::WorkPolicy,
    };
    let job = fetch();
    let mut expected = crate::test_support::PaidFixture::new().policy;
    expected.payment_policy.fixed_price = job.price();
    let WorkPolicy::Fetch { mut policy, .. } = expected.work_policy else {
        unreachable!()
    };
    let route = FetchRoutePolicy::OpenFetch {
        require_spki_pin: false,
        allowed_hosts: vec![],
    };
    policy.allowed_environment = job.manifest().content_id();
    policy.route_commitment = fetch_route_commitment(&route.canonical_body_bytes()).unwrap();
    let actual = job
        .prepare(&ProducerSigningKey::generate(), [255; 32])
        .unwrap()
        .encode()
        .unwrap()
        .len();
    for nonce in [0, 23, 24, 255] {
        let measured = job
            .prepare(&ProducerSigningKey::generate(), [nonce; 32])
            .unwrap()
            .encode()
            .unwrap()
            .len();
        assert_eq!(actual - measured, if nonce < 24 { 32 } else { 0 });
    }
    policy.max_encoded_prepared_input = actual.try_into().unwrap();
    expected.work_policy = WorkPolicy::Fetch {
        policy,
        route: route.clone(),
        contract: FetchContract::http().unwrap(),
    };
    job.check_policy(&expected).unwrap();
    policy.max_encoded_prepared_input -= 1;
    expected.work_policy = WorkPolicy::Fetch {
        policy,
        route,
        contract: FetchContract::http().unwrap(),
    };
    assert!(job.check_policy(&expected).is_err());
    let WorkPolicy::Fetch {
        mut policy,
        route,
        contract,
    } = expected.work_policy
    else {
        unreachable!()
    };
    policy.max_encoded_prepared_input = actual.try_into().unwrap();
    policy.max_upload_bytes = (actual - 1).try_into().unwrap();
    expected.work_policy = WorkPolicy::Fetch {
        policy,
        route,
        contract,
    };
    assert!(
        job.check_policy(&expected).is_err(),
        "uncached upload must fit before funding"
    );
}
