use super::*;

#[tokio::test]
async fn contact_cards_introduce_the_passkey_principal() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Cli::new(directory.path(), "provider", [0x51; 32]);
    let friend = Cli::new(directory.path(), "friend", [0x52; 32]);
    let card = directory.path().join("card");
    let exported = provider
        .output(&[
            "contact",
            "export",
            "--display-name",
            "Provider",
            "--out",
            string(&card),
        ])
        .await;
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let fingerprint = provider.principal().fingerprint();
    assert!(
        String::from_utf8_lossy(&exported.stderr)
            .contains(&format!("Principal fingerprint: {fingerprint}"))
    );
    let imported: Value = serde_json::from_str(
        &friend
            .run(&["contact", "import", string(&card), "--name", "provider"])
            .await,
    )
    .unwrap();
    assert_eq!(imported["fingerprint"], fingerprint);
    assert_eq!(
        imported["principal"],
        hex::encode(provider.principal().as_bytes())
    );
    assert_eq!(imported["display_name"], "Provider");
    // The card is the friend's, saved under the importer's principal.
    let decoded = hellas_authority::model::grant::records::decode_contact_card(
        &std::fs::read(&card).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded.principal(), provider.principal());
    assert!(
        directory
            .path()
            .join("grants")
            .join(format!(
                "p256-{}",
                hex::encode(friend.principal().as_bytes())
            ))
            .join("contacts/provider")
            .exists()
    );
    // Another card cannot silently replace the alias.
    let other = directory.path().join("other");
    friend
        .run(&[
            "contact",
            "export",
            "--display-name",
            "Friend",
            "--out",
            string(&other),
        ])
        .await;
    assert!(
        !friend
            .output(&["contact", "import", string(&other), "--name", "provider"])
            .await
            .status
            .success()
    );
    // A tampered card is refused.
    let mut forged = std::fs::read(&card).unwrap();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    std::fs::write(&other, forged).unwrap();
    assert!(
        !friend
            .output(&["contact", "import", string(&other), "--name", "forged"])
            .await
            .status
            .success()
    );
}
