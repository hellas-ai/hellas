#![cfg(unix)]
use hellas_cloud::configuration::Configuration;
use serde_json::json;

#[test]
fn configuration_bounds_credentials_and_withholds_debug_contents() {
    let mut config = Configuration {
        fetch_config: json!({"routes": [], "callers": []}),
        env: [("UPSTREAM_API_KEY".into(), "test-private-value".into())].into(),
        files: Default::default(),
    };
    config.validate().unwrap();
    assert!(!format!("{config:?}").contains("test-private-value"));
    for name in [
        "",
        "1KEY",
        "BAD-NAME",
        "HOME",
        "PATH",
        "LD_PRELOAD",
        "HELLAS_REMOTE_OWNER",
    ] {
        config.env = [(name.into(), "test-private-value".into())].into();
        assert!(config.validate().is_err());
    }
    config.env = [("API_KEY".into(), "x".repeat(48 * 1024))].into();
    assert!(config.validate().is_err());
    config.env.clear();
    config.env.insert("API_KEY".into(), "invalid\0value".into());
    assert!(config.validate().is_err());
    config.env.clear();
    for name in [
        "../auth.json",
        "/auth.json",
        ".hidden",
        "files/auth.json",
        "",
    ] {
        config.files = [(name.into(), json!({"token":"fixture"}))].into();
        assert!(config.validate().is_err());
    }
    config.files.clear();
    config.fetch_config = json!({"routes": []});
    assert!(config.validate().is_err());
}
