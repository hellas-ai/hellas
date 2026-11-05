use super::*;

fn token(expiry: u64) -> String {
    format!(
        "header.{}.signature",
        URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{expiry}}}"#))
    )
}
fn write(path: &Path, access: &str) {
    let value = serde_json::json!({"auth_mode":"chatgpt","tokens":{"access_token":access,"account_id":"acct-1","refresh_token":"DO_NOT_READ_OR_REFRESH"},"last_refresh":"2026-11-05T00:00:00Z"});
    hellas_private::write_atomically(path, "json", &serde_json::to_vec(&value).unwrap()).unwrap();
}

#[tokio::test]
async fn native_credentials_are_reread_without_writes_or_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.json");
    write(&path, &token(4102444800));
    let original = std::fs::read(&path).unwrap();
    let store = CodexAuthStore::new(Some(&path)).unwrap();
    assert_eq!(store.account_id().unwrap(), "acct-1");
    assert_eq!(
        *store.credentials().await.unwrap().access_token,
        token(4102444800)
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);
    write(&path, &token(4102444801)); // only the external Codex owner writes
    assert_eq!(
        *store.credentials().await.unwrap().access_token,
        token(4102444801)
    );
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "no lock/state/refresh sidecars"
    );
}

#[tokio::test]
async fn expired_malformed_and_legacy_credentials_fail_closed_without_modification() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.json");
    let store = CodexAuthStore::new(Some(&path)).unwrap();
    assert!(store.credentials().await.is_err());
    assert!(!path.exists());
    for access in [token(1), "opaque-token".into()] {
        write(&path, &access);
        let before = std::fs::read(&path).unwrap();
        let error = store.credentials().await.err().unwrap();
        assert!(matches!(error, CodexAuthError::Expired));
        assert!(error.to_string().contains("Codex CLI"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    let legacy = serde_json::json!({"version":1,"tokens":{"access_token":token(4102444800),"account_id":"acct-1","refresh_token":"legacy"}});
    hellas_private::write_atomically(&path, "json", &serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert!(matches!(
        store.credentials().await,
        Err(CodexAuthError::Invalid)
    ));
}
