use std::process::Command;

#[test]
fn faucet_refuses_a_local_chain_without_creating_a_device_identity() {
    let home = tempfile::tempdir().unwrap();
    let profile = home.path().join("chain.json");
    std::fs::write(
        &profile,
        serde_json::to_vec(&hellas_genesis::test_support::profile().to_file()).unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
        .arg("--home")
        .arg(home.path())
        .arg("--chain-config")
        .arg(profile)
        .arg("faucet")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("selected chain has no faucet accounts")
    );
    assert!(home.path().join("principal.key").exists());
    assert!(!home.path().join("identity").exists());
}
