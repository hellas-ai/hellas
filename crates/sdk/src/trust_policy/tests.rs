use super::*;

fn counters(
    store: &TrustPolicyStore,
) -> Arc<dyn hellas_attestation::AssertionCounterStore + Send + Sync> {
    Arc::new(crate::FilesystemAssertionCounterStore::new(
        store.directory.join("existing-counters"),
    ))
}

fn policy() -> TrustPolicy {
    TrustPolicy {
        provider_genesis: ContentId::from_bytes([1; 32]),
        assurance: Assurance::ProducerSigned,
        environments: vec![ContentId::from_bytes([2; 32])],
        apple: None,
    }
}

#[test]
fn resolution_never_creates_or_learns_approval_and_checks_exact_execution_terms() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("trust");
    let store = TrustPolicyStore::new(&directory);
    let policy = policy();
    assert!(
        store
            .resolve("provider", policy.assurance, counters(&store))
            .is_err()
    );
    assert!(!directory.exists());
    let first = store
        .approve(
            "provider",
            0,
            policy.clone(),
            "reviewed enrollment and contract".into(),
        )
        .unwrap();
    assert_eq!(first.revision, 1);
    assert_eq!(first.previous, None);
    let trust = store
        .resolve_environment(
            "provider",
            policy.assurance,
            policy.environments[0],
            counters(&store),
        )
        .unwrap();
    assert_eq!(trust.expected_genesis, policy.provider_genesis);
    assert!(trust.apple_app_attest.is_none());
    assert!(
        store
            .resolve_environment(
                "provider",
                policy.assurance,
                ContentId::from_bytes([3; 32]),
                counters(&store)
            )
            .is_err()
    );
    assert!(
        store
            .resolve("provider", Assurance::AppleAppAttest, counters(&store),)
            .is_err()
    );
    assert_eq!(store.load("provider").unwrap().revision, 1);
    assert!(!directory.join("existing-counters").exists());
}

#[test]
fn replacement_is_revision_checked_and_audited_and_keeps_assertion_counters() {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustPolicyStore::new(directory.path());
    let mut initial = policy();
    initial.assurance = Assurance::AppleAppAttest;
    initial.apple = Some(AppleApproval {
        app_id: "TEAM.example.app".into(),
        cd_hashes: vec![[7; 32]],
    });
    store
        .approve("provider", 0, initial.clone(), "initial".into())
        .unwrap();
    let trust = store
        .resolve("provider", initial.assurance, counters(&store))
        .unwrap();
    trust
        .apple_app_attest
        .unwrap()
        .counter_store
        .advance(&[9; 33], 7)
        .unwrap();
    let mut replacement = initial.clone();
    replacement.apple.as_mut().unwrap().cd_hashes = vec![[8; 32]];
    let second = store
        .approve(
            "provider",
            1,
            replacement.clone(),
            "approved new build".into(),
        )
        .unwrap();
    assert_eq!(second.revision, 2);
    assert_eq!(second.previous, Some(initial.commitment().unwrap()));
    assert_eq!(second.reason, "approved new build");
    assert_eq!(store.load("provider").unwrap().policy, replacement);
    assert!(
        store
            .approve("provider", 1, initial.clone(), "stale edit".into())
            .is_err()
    );
    assert!(
        store
            .approve("provider", 0, initial, "recreate".into())
            .is_err()
    );
    let restarted = TrustPolicyStore::new(directory.path());
    let trust = restarted
        .resolve("provider", replacement.assurance, counters(&restarted))
        .unwrap();
    let counters = trust.apple_app_attest.unwrap().counter_store;
    assert!(counters.advance(&[9; 33], 7).is_err());
    counters.advance(&[9; 33], 8).unwrap();
    assert_eq!(restarted.load("provider").unwrap().revision, 2);
}

#[test]
fn approval_validation_bounds_pins_ids_and_audit_before_writing() {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustPolicyStore::new(directory.path());
    for id in [
        "",
        "../outside",
        "a/b",
        "/absolute",
        "UPPER",
        &"a".repeat(65),
    ] {
        assert!(store.approve(id, 0, policy(), "reviewed".into()).is_err());
    }
    let mut invalid_policies = vec![];
    let mut p = policy();
    p.environments.clear();
    invalid_policies.push(p);
    let mut p = policy();
    p.environments.push(p.environments[0]);
    invalid_policies.push(p);
    let mut p = policy();
    p.assurance = Assurance::AppleAppAttest;
    invalid_policies.push(p);
    for app_id in ["", "TEAM", ".app", "TEAM.", "TEAM.\napp", &"a".repeat(256)] {
        let mut p = policy();
        p.apple = Some(AppleApproval {
            app_id: app_id.into(),
            cd_hashes: vec![[7; 32]],
        });
        invalid_policies.push(p);
    }
    for cd_hashes in [vec![], vec![[7; 32]; 2], vec![[7; 32]; 33]] {
        let mut p = policy();
        p.apple = Some(AppleApproval {
            app_id: "TEAM.app".into(),
            cd_hashes,
        });
        invalid_policies.push(p);
    }
    for p in invalid_policies {
        assert!(store.approve("invalid", 0, p, "reviewed".into()).is_err());
    }
    for reason in ["".into(), " ".into(), "a".repeat(257)] {
        assert!(store.approve("invalid", 0, policy(), reason).is_err());
    }
    assert!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none()
    );
    let mut value = serde_json::to_value(policy()).unwrap();
    value["offer"] = serde_json::json!({});
    assert!(serde_json::from_value::<TrustPolicy>(value).is_err());
}

#[test]
fn corrupt_or_relocated_records_cannot_be_replaced_as_missing() {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustPolicyStore::new(directory.path());
    let path = store.path("provider", ".json").unwrap();
    store
        .approve("provider", 0, policy(), "reviewed".into())
        .unwrap();
    let original = std::fs::read(&path).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    value["id"] = "other".into();
    for bytes in [
        b"{".to_vec(),
        serde_json::to_vec(&value).unwrap(),
        vec![b' '; MAX_FILE + 1],
    ] {
        hellas_private::write_atomically(&path, ".test", &bytes).unwrap();
        assert!(store.load("provider").is_err());
        assert!(
            store
                .approve("provider", 0, policy(), "overwrite corruption".into())
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    let mut exhausted: ApprovalRecord = serde_json::from_slice(&original).unwrap();
    exhausted.revision = u64::MAX;
    exhausted.previous = Some(policy().commitment().unwrap());
    let bytes = serde_json::to_vec(&exhausted).unwrap();
    hellas_private::write_atomically(&path, ".test", &bytes).unwrap();
    assert!(
        store
            .approve("provider", u64::MAX, policy(), "overflow".into())
            .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn public_files_and_symlinks_are_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let store = TrustPolicyStore::new(directory.path());
    store
        .approve("provider", 0, policy(), "reviewed".into())
        .unwrap();
    let path = store.path("provider", ".json").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.load("provider").is_err());
    assert!(
        store
            .approve("provider", 1, policy(), "replace public".into())
            .is_err()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&path, store.path("linked", ".json").unwrap()).unwrap();
    assert!(store.load("linked").is_err());
    assert!(
        store
            .approve("linked", 0, policy(), "follow link".into())
            .is_err()
    );
    let lock = store.path("provider", ".lock").unwrap();
    std::fs::remove_file(&lock).unwrap();
    symlink(&path, lock).unwrap();
    assert!(
        store
            .approve("provider", 1, policy(), "linked lock".into())
            .is_err()
    );
}

#[test]
fn approval_child() {
    let Some(directory) = std::env::var_os("HELLAS_TRUST_TEST_DIRECTORY") else {
        return;
    };
    let store = TrustPolicyStore::new(directory);
    store
        .approve("provider", 1, policy(), "process replacement".into())
        .unwrap();
}

#[test]
fn concurrent_processes_cannot_overwrite_one_expected_revision() {
    use std::process::{Command, Stdio};
    let directory = tempfile::tempdir().unwrap();
    let store = TrustPolicyStore::new(directory.path());
    store
        .approve("provider", 0, policy(), "initial".into())
        .unwrap();
    let children: Vec<_> = (0..2)
        .map(|_| {
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "trust_policy::tests::approval_child"])
                .env("HELLAS_TRUST_TEST_DIRECTORY", directory.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    let successes = children
        .into_iter()
        .filter_map(|mut child| child.wait().unwrap().success().then_some(()))
        .count();
    assert_eq!(successes, 1);
    let latest = store.load("provider").unwrap();
    assert_eq!(latest.revision, 2);
    assert_eq!(latest.previous, Some(policy().commitment().unwrap()));
}
