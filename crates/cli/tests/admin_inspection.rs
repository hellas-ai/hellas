use hellas_auth::authority::{AuthorityInspection, InspectionQuery};
use hellas_authority::{model::grant::grant_network, test_support::Node};
use std::process::Command;

#[tokio::test]
async fn offline_inspection_needs_no_identity_and_refuses_a_running_writer() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("node");
    let query = directory.path().join("query.json");
    std::fs::write(
        &query,
        serde_json::to_vec(&InspectionQuery::Credentials { after: None }).unwrap(),
    )
    .unwrap();
    let world = Node::bootstrap(&root)
        .with_network(grant_network())
        .build()
        .await;
    let expected = world.store.state().authority().revision();
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_hellas-cli"))
            .args(["admin", "inspect-offline", "--journal"])
            .arg(&root)
            .arg(&query)
            .output()
            .unwrap()
    };
    let locked = invoke();
    assert!(!locked.status.success());
    assert!(
        String::from_utf8_lossy(&locked.stderr).contains("another process holds the journal"),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    drop(world);
    let journal = hellas_channel::work_store::journal::Journal::path(&root, "grants");
    let sidecars_before = hellas_channel::test_support::all_files(&root);
    let before = std::fs::read(&journal).unwrap();
    let output = invoke();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let view: AuthorityInspection = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(view.revision, expected);
    assert_eq!(std::fs::read(journal).unwrap(), before);
    assert_eq!(
        hellas_channel::test_support::all_files(&root),
        sidecars_before
    );
}
