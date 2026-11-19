#![cfg(feature = "validator")]

use std::process::Command;

#[test]
fn validator_outside_configured_genesis_is_rejected_before_state() {
    let home = tempfile::tempdir().unwrap();
    let profile = home.path().join("chain.json");
    std::fs::write(
        &profile,
        serde_json::to_vec(&hellas_genesis::test_support::profile().to_file()).unwrap(),
    )
    .unwrap();
    let generated = Command::new(env!("CARGO_BIN_EXE_hellas"))
        .args([
            "chain",
            "validator",
            "config",
            "-n",
            "1",
            "--seed",
            "719",
            "--network-id",
            "test-network",
        ])
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let config = home.path().join("validator.toml");
    std::fs::write(&config, generated.stdout).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
        .arg("--home")
        .arg(home.path())
        .arg("--chain-config")
        .arg(profile)
        .args(["chain", "validator", "run", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert!(!home.path().join("chains").exists());
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("validator identity is not in the genesis committee"),
        "{error}"
    );
}
