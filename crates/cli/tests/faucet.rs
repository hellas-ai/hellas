use hellas_chain::genesis::{Chain, ChainProfile, FaucetAccount, HELLAS_DEVNET_3_FAUCET_JSON};
use sha2::Digest as _;
use std::process::Command;

#[test]
fn faucet_flags_sign_as_the_announced_account() {
    let accounts: Vec<FaucetAccount> = serde_json::from_str(HELLAS_DEVNET_3_FAUCET_JSON).unwrap();
    for selection in [vec!["--faucet"], vec!["--faucet-account", "7"]] {
        let home = tempfile::tempdir().unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
            .env("HOME", home.path())
            .env("XDG_DATA_HOME", home.path().join("data"))
            .args(["contact", "--name", "Public devnet user"])
            .args(&selection)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let card = hellas_sdk::contact::Contact::decode(&String::from_utf8(output.stdout).unwrap())
            .unwrap()
            .card;
        let account = accounts
            .iter()
            .find(|account| {
                let secret: [u8; 32] = hex::decode(&account.secret_scalar)
                    .unwrap()
                    .try_into()
                    .unwrap();
                let passkey = hellas_kernel::SoftPasskey::from_secret_scalar(secret).unwrap();
                card.principal()
                    == hellas_auth::authority::PrincipalId::from_public_key(
                        hellas_auth::PublicKey::P256(passkey.party_key().to_bytes()),
                    )
                    .unwrap()
            })
            .expect("the contact assertion verifies as one published faucet principal");
        assert!(String::from_utf8_lossy(&output.stderr).contains(&format!(
            "devnet faucet account {}: {}",
            account.index, account.address
        )));
        if selection.len() == 2 {
            assert_eq!(account.index, 7);
        }
    }
}

#[test]
fn faucet_rejects_another_authenticated_chain_before_identity_side_effects() {
    let home = tempfile::tempdir().unwrap();
    let known = ChainProfile::known(Chain::Devnet);
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
    let identity = home.path().join("app").join("identity");
    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
        .env("HOME", home.path())
        .arg("--home")
        .arg(home.path().join("app"))
        .arg("--chain-config")
        .arg(&path)
        .arg("--faucet")
        .args(["contact", "--name", "Public devnet user"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("selected chain has no faucet accounts")
    );
    assert!(!identity.exists());
    assert!(!home.path().join("app").exists());
}
