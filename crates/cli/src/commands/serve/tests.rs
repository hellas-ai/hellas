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
        // Keep this fixture independent of the process-global HOME.
        "destination": {
            "type": "codex-responses",
            "auth_path": "target/hellas-test-codex-auth.json"
        },
        "capabilities": capabilities,
    })
}

fn authenticated_codex_route(
    dir: &tempfile::TempDir,
    capabilities: serde_json::Value,
) -> serde_json::Value {
    let auth_path = dir.path().join("codex-auth.json");
    hellas_private::write_atomically(&auth_path, "json", &serde_json::to_vec(&serde_json::json!({"auth_mode":"chatgpt","tokens":{"access_token":"test-access","refresh_token":"unused","account_id":"test-account"}})).unwrap()).unwrap();
    let mut route = codex_route(capabilities);
    route["destination"]["auth_path"] = serde_json::json!(auth_path);
    route
}

#[test]
fn load_fetch_config_parses_route_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        &dir,
        serde_json::json!({
            "version":1,
            "routes": [authenticated_codex_route(&dir, serde_json::json!({
                "models": ["gpt-5.5-codex"],
                "max_output_tokens": 4096
            }))],
        }),
    );

    let registry = hellas_sdk::serve_config::ServeConfig::load(&path)
        .unwrap()
        .routes()
        .unwrap();

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
            "version":1,
            "routes": [
                authenticated_codex_route(&dir, serde_json::json!({})),
                authenticated_codex_route(&dir, serde_json::json!({})),
            ],
        }),
    );

    let err = hellas_sdk::serve_config::ServeConfig::load(&path).unwrap_err();

    assert!(format!("{err:#}").contains("duplicate"));
}

#[test]
fn load_fetch_config_rejects_operator_claimed_trusted_identity() {
    let dir = tempfile::tempdir().unwrap();
    let mut route = codex_route(serde_json::json!({}));
    route["adaptor"] = serde_json::json!("codex-0.0.1");
    let path = write_config(&dir, serde_json::json!({ "version":1, "routes": [route] }));
    let err = hellas_sdk::serve_config::ServeConfig::load(&path).unwrap_err();
    assert!(format!("{err:#}").contains("unknown field `adaptor`"));

    let mut route = codex_route(serde_json::json!({}));
    route["environment"] = serde_json::json!({
        "program": "01",
        "config": "02",
        "build": "03"
    });
    let path = write_config(&dir, serde_json::json!({ "version":1, "routes": [route] }));
    let err = hellas_sdk::serve_config::ServeConfig::load(&path).unwrap_err();
    assert!(format!("{err:#}").contains("unknown field `environment`"));
}

#[test]
fn load_fetch_config_rejects_operator_selected_destination() {
    let dir = tempfile::tempdir().unwrap();
    let mut route = codex_route(serde_json::json!({}));
    route["destination"]["base_url"] = serde_json::json!("https://example.invalid/codex");
    let path = write_config(&dir, serde_json::json!({ "version":1, "routes": [route] }));
    let error = hellas_sdk::serve_config::ServeConfig::load(&path).unwrap_err();

    assert!(format!("{error:#}").contains("unknown field `base_url`"));
}

#[test]
fn core_cli_rejects_moved_openai_hosting_and_operator_endpoints() {
    let codex: hellas_sdk::serve_config::Destination = serde_json::from_value(serde_json::json!({
        "type": "codex-responses",
        "auth_path": "target/codex-auth.json"
    }))
    .unwrap();
    assert!(matches!(
        codex,
        hellas_sdk::serve_config::Destination::CodexResponses { .. }
    ));

    for value in [
        serde_json::json!({"type":"openai-responses","api_key_env":"HELLAS_TEST_OPENAI_KEY"}),
        serde_json::json!({"type":"codex-responses","url":"https://example.invalid/v1/responses"}),
    ] {
        assert!(serde_json::from_value::<hellas_sdk::serve_config::Destination>(value).is_err());
    }
}

#[test]
fn obsolete_callers_and_unknown_capabilities_are_rejected() {
    for value in [
        serde_json::json!({"version":1,"routes": [], "callers": []}),
        serde_json::json!({"version":1,"routes": [codex_route(serde_json::json!({"modles": []}))]}),
    ] {
        assert!(serde_json::from_value::<hellas_sdk::serve_config::ServeConfig>(value).is_err());
    }
}
