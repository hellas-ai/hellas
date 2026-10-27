use hellas_rpc::{Assurance, ContentId};
use hellas_sdk::trust_policy::{TrustPolicy, TrustPolicyStore};
use std::process::Command;

#[test]
fn local_approval_cli_is_separate_from_identity_and_execution_and_preserves_revision() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("trust");
    let source = directory.path().join("policy.json");
    let policy = TrustPolicy {
        provider_genesis: ContentId::from_bytes([1; 32]),
        assurance: Assurance::ProducerSigned,
        environments: vec![ContentId::from_bytes([2; 32])],
        apple: None,
    };
    std::fs::write(&source, serde_json::to_vec(&policy).unwrap()).unwrap();
    let invoke = |revision: &str| {
        Command::new(env!("CARGO_BIN_EXE_hellas-cli"))
            .args(["trust", "--store"])
            .arg(&root)
            .args([
                "approve",
                "provider",
                "--expected-revision",
                revision,
                "--policy",
            ])
            .arg(&source)
            .args(["--reason", "independently reviewed provider"])
            .env("HOME", directory.path())
            .output()
            .unwrap()
    };
    let first = invoke("0");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(!directory.path().join(".hellas/identity").exists());
    let stored = TrustPolicyStore::new(&root);
    assert_eq!(stored.load("provider").unwrap().revision, 1);
    assert!(!invoke("0").status.success());
    assert!(invoke("1").status.success());
    let shown = Command::new(env!("CARGO_BIN_EXE_hellas-cli"))
        .args(["trust", "--store"])
        .arg(&root)
        .args(["show", "provider"])
        .env("HOME", directory.path())
        .output()
        .unwrap();
    assert!(shown.status.success());
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["revision"], 2);
    assert_eq!(shown["reason"], "independently reviewed provider");
    assert_eq!(
        stored
            .resolve(
                "provider",
                policy.assurance,
                std::sync::Arc::new(hellas_sdk::FilesystemAssertionCounterStore::new(
                    directory.path().join("counters")
                ))
            )
            .unwrap()
            .expected_genesis,
        policy.provider_genesis
    );
    let help = Command::new(env!("CARGO_BIN_EXE_hellas-cli"))
        .args(["transact", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("--trust-store") && help.contains("--trust-policy"));
    assert!(!help.contains("--provider-genesis") && !help.contains("--apple-app-id"));
}
