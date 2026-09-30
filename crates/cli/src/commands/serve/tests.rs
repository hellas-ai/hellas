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
    let auth = crate::commands::codex_auth::CodexAuthStore::new(Some(&auth_path)).unwrap();
    auth.save(&crate::commands::codex_auth::CodexAuthState::new(
        crate::commands::codex_auth::test_tokens_with_account_id(
            "test-access",
            "test-refresh",
            "test-account",
        ),
        None,
    ))
    .unwrap();
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
            "routes": [authenticated_codex_route(&dir, serde_json::json!({
                "models": ["gpt-5.5-codex"],
                "max_output_tokens": 4096
            }))],
        }),
    );

    let registry = load_fetch_config(&path).unwrap();

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

    let err = load_fetch_config(&path).unwrap_err();

    assert!(err.to_string().contains("registered twice"));
}

#[test]
fn load_fetch_config_rejects_operator_claimed_trusted_identity() {
    let dir = tempfile::tempdir().unwrap();
    let mut route = codex_route(serde_json::json!({}));
    route["adaptor"] = serde_json::json!("codex-0.0.1");
    let path = write_config(&dir, serde_json::json!({ "routes": [route] }));
    let err = load_fetch_config(&path).unwrap_err();
    assert!(format!("{err:#}").contains("unknown field `adaptor`"));

    let mut route = codex_route(serde_json::json!({}));
    route["environment"] = serde_json::json!({
        "program": "01",
        "config": "02",
        "build": "03"
    });
    let path = write_config(&dir, serde_json::json!({ "routes": [route] }));
    let err = load_fetch_config(&path).unwrap_err();
    assert!(format!("{err:#}").contains("unknown field `environment`"));
}

#[test]
fn load_fetch_config_rejects_operator_selected_destination() {
    let dir = tempfile::tempdir().unwrap();
    let mut route = codex_route(serde_json::json!({}));
    route["destination"]["base_url"] = serde_json::json!("https://example.invalid/codex");
    let path = write_config(&dir, serde_json::json!({ "routes": [route] }));
    let error = load_fetch_config(&path).unwrap_err();

    assert!(format!("{error:#}").contains("unknown field `base_url`"));
}

#[test]
fn config_has_two_sealed_destination_variants_and_no_url_field() {
    let codex: FetchDestination = serde_json::from_value(serde_json::json!({
        "type": "codex-responses",
        "auth_path": "target/codex-auth.json"
    }))
    .unwrap();
    assert!(matches!(codex, FetchDestination::CodexResponses { .. }));

    let openai: FetchDestination = serde_json::from_value(serde_json::json!({
        "type": "openai-responses",
        "api_key_env": "HELLAS_TEST_OPENAI_KEY"
    }))
    .unwrap();
    assert!(matches!(
        openai,
        FetchDestination::OpenaiResponses { ref api_key_env }
            if api_key_env == "HELLAS_TEST_OPENAI_KEY"
    ));

    let error = serde_json::from_value::<FetchDestination>(serde_json::json!({
        "type": "openai-responses",
        "url": "https://example.invalid/v1/responses"
    }))
    .unwrap_err();
    assert!(error.to_string().contains("unknown field `url`"));
}

#[test]
fn obsolete_callers_and_unknown_capabilities_are_rejected() {
    for value in [
        serde_json::json!({"routes": [], "callers": []}),
        serde_json::json!({"routes": [codex_route(serde_json::json!({"modles": []}))]}),
    ] {
        assert!(serde_json::from_value::<FetchConfigFile>(value).is_err());
    }
}
