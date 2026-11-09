#![cfg(feature = "validator")]
use std::process::Command;

#[test]
fn embedded_devnet_trust_is_the_offline_seed_100_export_for_the_shipped_genesis() {
    let root = tempfile::tempdir().unwrap();
    let genesis = root.path().join("genesis.json");
    std::fs::write(&genesis, hellas_chain::genesis::HELLAS_DEVNET_3_JSON).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
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
    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
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
        serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_3_TRUST_JSON).unwrap();
    assert_eq!(embedded, generated);
    assert_eq!(
        generated["genesis_sha256"],
        "35b2444df762b668cc66df28e784348ff9019d1dc0ee16ec2bea3949b4828c75"
    );
}
