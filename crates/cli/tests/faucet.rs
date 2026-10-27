use hellas_chain::genesis::{FaucetAccount, HELLAS_DEVNET_1_FAUCET_JSON};
use hellas_work::model::grant::records::decode_contact_card;
use std::process::Command;

#[test]
fn faucet_flags_sign_as_the_announced_account_without_creating_a_node() {
    let accounts: Vec<FaucetAccount> = serde_json::from_str(HELLAS_DEVNET_1_FAUCET_JSON).unwrap();
    for selection in [vec!["--faucet"], vec!["--faucet-account", "7"]] {
        let home = tempfile::tempdir().unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_hellas-cli"))
            .env("HOME", home.path())
            .env("XDG_DATA_HOME", home.path().join("data"))
            .args(["contact", "export", "--display-name", "Public devnet user"])
            .args(&selection)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let card = decode_contact_card(&output.stdout).unwrap();
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
        assert!(!home.path().join(".hellas").exists());
    }
}
