use hellas_private::StoreLocation;
use std::fs;
mod control;
use super::*;

fn write_config(dir: &tempfile::TempDir, config: serde_json::Value) -> PathBuf {
    let path = dir.path().join("fetch-config.json");
    fs::write(&path, config.to_string()).unwrap();
    path
}

fn codex_route(capabilities: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "service": "codex",
        "method": "responses",
        "destination": {
            "type": "codex-responses"
        },
        "capabilities": capabilities,
    })
}

fn authenticated_codex_route(
    dir: &tempfile::TempDir,
    capabilities: serde_json::Value,
) -> serde_json::Value {
    let auth_path = dir.path().join("codex-auth.json");
    let auth = crate::commands::codex_auth::CodexAuthStore::new(&auth_path).unwrap();
    auth.save(&crate::commands::codex_auth::CodexAuthState::new(
        crate::commands::codex_auth::test_tokens_with_account_id(
            "test-access",
            "test-refresh",
            "test-account",
        ),
        None,
    ))
    .unwrap();
    codex_route(capabilities)
}

#[test]
fn load_fetch_config_parses_route_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        &dir,
        serde_json::json!({
            "routes": [authenticated_codex_route(&dir, serde_json::json!({
                "models": ["gpt-5.5-codex"],
                "max_output_tokens": 4096
            }))],
        }),
    );

    let location = StoreLocation::for_test(dir.path());
    let registry = load_fetch_config(&path, &location).unwrap();

    let capabilities = &registry
        .entry(&FetchRoute::new("codex", "responses"))
        .unwrap()
        .capabilities;
    assert_eq!(capabilities.max_output_units, Some(4096));
    assert!(
        capabilities
            .allowed_models
            .as_ref()
            .unwrap()
            .contains("gpt-5.5-codex")
    );
}

#[test]
fn load_fetch_config_rejects_duplicate_route() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        &dir,
        serde_json::json!({
            "routes": [
                authenticated_codex_route(&dir, serde_json::json!({})),
                authenticated_codex_route(&dir, serde_json::json!({})),
            ],
        }),
    );

    let location = StoreLocation::for_test(dir.path());
    let err = load_fetch_config(&path, &location).unwrap_err();

    assert!(err.to_string().contains("registered twice"));
}

#[test]
fn unknown_capabilities_are_rejected() {
    let value = serde_json::json!({"routes": [codex_route(serde_json::json!({"modles": []}))]});
    assert!(serde_json::from_value::<FetchConfigFile>(value).is_err());
}
