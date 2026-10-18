use super::*;
use hellas_work::model::grant::records::{decode_contact, principal_id};

#[tokio::test]
async fn contact_import_reports_the_exported_identity() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Cli::new(directory.path(), "provider");
    let friend = Cli::new(directory.path(), "friend");
    provider.run(&["--software-root", "identity", "init"]).await;
    friend.run(&["--software-root", "identity", "init"]).await;
    let contact = directory.path().join("contact");
    let exported = provider
        .output(&["contact", "export", "--out", string(&contact)])
        .await;
    let imported = friend
        .output(&["contact", "import", string(&contact), "--name", "provider"])
        .await;
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let enrollment = decode_contact(&std::fs::read(contact).unwrap()).unwrap();
    let fingerprint = format!(
        "Identity fingerprint: {}",
        principal_id(&enrollment).unwrap().fingerprint()
    );
    assert!(String::from_utf8_lossy(&exported.stderr).contains(&fingerprint));
    assert!(String::from_utf8_lossy(&imported.stderr).contains(&fingerprint));
}
