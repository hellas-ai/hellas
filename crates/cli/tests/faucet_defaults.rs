#![cfg(feature = "validator")]
use std::process::Command;

#[test]
fn embedded_devnet_trust_is_the_offline_seed_100_export_for_the_shipped_genesis() {
    let root = tempfile::tempdir().unwrap();
    let genesis = root.path().join("genesis.json");
    std::fs::write(&genesis, hellas_chain::genesis::HELLAS_DEVNET_1_JSON).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hellas-cli"))
        .args([
            "chain",
            "validator",
            "config",
            "--validators",
            "6",
            "--validator",
            "0",
            "--seed",
            "100",
            "--start-port",
            "32900",
            "--metrics-port",
            "9190",
            "--genesis",
        ])
        .arg(&genesis)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = root.path().join("validator.toml");
    std::fs::write(&config, output.stdout).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hellas-cli"))
        .args(["chain", "validator", "export-trust", "--config"])
        .arg(config)
        .arg("--genesis")
        .arg(genesis)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let generated: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let embedded: serde_json::Value =
        serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_1_TRUST_JSON).unwrap();
    assert_eq!(embedded, generated);
    assert_eq!(
        generated["genesis_sha256"],
        "4dd31668a5822fa8326245bd2ad58af1086f2f377a074e44be0345f1e5dfec17"
    );
}
