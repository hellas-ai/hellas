#![cfg(all(
    feature = "construction-audit",
    feature = "client",
    not(target_family = "wasm")
))]

#[tokio::test]
async fn connection_attempt_is_observable_even_when_no_client_can_be_created() {
    assert_eq!(hellas_chain::construction_audit::events(), 0);
    assert!(
        hellas_chain::client::RemoteLightClient::connect("invalid-url")
            .await
            .is_err()
    );
    assert_eq!(hellas_chain::construction_audit::events(), 1);
}

#[test]
fn subprocess_audit_sink_records_connection_attempts() {
    const CHILD: &str = "HELLAS_CHAIN_AUDIT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(
            runtime
                .block_on(hellas_chain::client::RemoteLightClient::connect(
                    "invalid-url"
                ))
                .is_err()
        );
        assert_eq!(hellas_chain::construction_audit::events(), 1);
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "subprocess_audit_sink_records_connection_attempts",
        ])
        .env(CHILD, "1")
        .env("HELLAS_CHAIN_CONSTRUCTION_AUDIT", &audit)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(audit).unwrap(), b"chain-client\n");
}
