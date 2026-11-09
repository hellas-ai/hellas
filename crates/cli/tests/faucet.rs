use sha2::Digest as _;
use std::process::Command;

#[test]
fn faucet_refuses_a_chain_without_faucet_accounts_before_creating_an_identity() {
    let home = tempfile::tempdir().unwrap();
    let known = hellas_chain::genesis::ChainProfile::known(hellas_chain::genesis::Chain::Devnet);
    let mut trust = known.trust().clone();
    trust.network_id = "custom-faucet-test".into();
    let mut genesis: serde_json::Value =
        serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_3_JSON).unwrap();
    genesis["network_id"] = serde_json::json!("custom-faucet-test");
    let genesis_json = serde_json::to_string(&genesis).unwrap();
    trust.genesis_sha256 = hex::encode(sha2::Sha256::digest(genesis_json.as_bytes()));
    let path = home.path().join("chain.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "trust": trust,
            "validators": ["ws://127.0.0.1:9080"],
            "genesis_json": genesis_json,
        }))
        .unwrap(),
    )
    .unwrap();
    let app = home.path().join("app");
    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
        .env("HOME", home.path())
        .arg("--home")
        .arg(&app)
        .arg("--chain-config")
        .arg(&path)
        .arg("faucet")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("selected chain has no faucet accounts"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The faucet pays the principal; it needs no device identity.
    assert!(app.join("principal.key").is_file());
    assert!(!app.join("identity").exists());
}
