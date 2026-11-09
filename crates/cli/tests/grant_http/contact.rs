use super::*;

#[tokio::test]
async fn a_contact_is_one_string_naming_the_principal_and_this_device() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Cli::new(directory.path(), "provider", [0x51; 32]);
    let line = provider.contact().await;
    let contact = hellas_sdk::contact::Contact::decode(&line).unwrap();
    assert_eq!(contact.card.principal(), provider.principal());
    assert_eq!(contact.card.name(), "provider");
    let hellas_auth::authority::CredentialHolder::Node(holder) = provider.holder().await else {
        panic!()
    };
    assert_eq!(contact.holder, holder);

    // Without --passkey the home principal key is created once and reused.
    let home = directory.path().join("fresh");
    let contact = |name: &'static str| {
        let home = home.clone();
        async move {
            let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_hellas"))
                .arg("--home")
                .arg(&home)
                .args(["contact", "--name", name])
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            hellas_sdk::contact::Contact::decode(&String::from_utf8(output.stdout).unwrap())
                .unwrap()
        }
    };
    let first = contact("Friend").await;
    let again = contact("Friend again").await;
    assert!(home.join("principal.key").is_file());
    assert_eq!(first.card.principal(), again.card.principal());
    assert_eq!(first.holder, again.holder);
    assert_eq!(again.card.name(), "Friend again");
}
