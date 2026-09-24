#![cfg(unix)]

use hellas_cloud::{
    agent::validate_download,
    config::*,
    provider::{Cloud, CloudKind, Docker, Provider},
};

fn spec(provider: ProviderConfig) -> Spec {
    Spec {
        name: "test-worker".into(),
        image: format!("ghcr.io/hellas-ai/hellas@sha256:{}", "a".repeat(64)),
        provider,
        trust: Trust::Token,
        serve_args: vec![],
    }
}

#[test]
fn reject_mutable_images_unsupported_trust_and_identity_overrides() {
    let mut value = spec(ProviderConfig::Docker { gpus: false });
    value.validate().unwrap();
    value.image = "ghcr.io/hellas-ai/hellas:cuda".into();
    assert!(value.validate().is_err());
    value = spec(ProviderConfig::Docker { gpus: false });
    value.trust = Trust::MeasuredBoot;
    assert!(
        Docker { gpus: false }
            .plan(&value)
            .unwrap_err()
            .to_string()
            .contains("verifier")
    );
    value.trust = Trust::Token;
    for arg in [
        "--identity=/tmp/stolen",
        "--owner=other",
        "--assurance=apple-app-attest",
        "--software-root",
        "--help",
    ] {
        value.serve_args = vec![arg.into()];
        assert!(value.validate().is_err());
    }
}

#[test]
fn runpod_preserves_entrypoint_and_mounts_persistent_identity() {
    let spec = spec(ProviderConfig::Runpod {
        account: None,
        gpu_type: "NVIDIA A100 80GB PCIe".into(),
        disk_gb: 20,
        volume_gb: 80,
        container_registry_auth_id: Some("registry-credential-id".into()),
    });
    let provider = Cloud::new(CloudKind::Runpod).unwrap();
    let mut credentials = Credentials::generate();
    credentials.owner = Some(iroh::SecretKey::generate().public().to_string());
    let body = provider
        .create_body(&spec, credentials.env(&spec).unwrap())
        .unwrap();
    assert_eq!(body["imageName"], spec.image);
    assert_eq!(body["volumeMountPath"], "/var/lib/hellas");
    assert_eq!(body["containerRegistryAuthId"], "registry-credential-id");
    assert_eq!(body["env"]["HELLAS_REMOTE_TOKEN"], credentials.token);
    assert_eq!(
        body["env"]["HELLAS_REMOTE_OWNER"],
        credentials.owner.unwrap()
    );
    assert!(body.get("dockerEntrypoint").is_none());
    assert!(body.get("dockerStartCmd").is_none());
    let plan = provider.plan(&spec).unwrap().to_string();
    assert!(!plan.contains(&credentials.token));
    assert!(!plan.contains(&credentials.admin_secret));
}

#[test]
fn vast_uses_args_mode_and_encodes_bootstrap_without_shell_quoting() {
    let mut spec = spec(ProviderConfig::Vast {
        offer_id: 123,
        disk_gb: 50,
    });
    spec.serve_args = vec!["--execute-policy".into(), "only(ab*)".into()];
    let provider = Cloud::new(CloudKind::Vast).unwrap();
    let env = Credentials::generate().env(&spec).unwrap();
    let body = provider.create_body(&spec, env.clone()).unwrap();
    assert_eq!(body["runtype"], "args");
    assert_eq!(body["args"], serde_json::json!([]));
    assert!(body.get("onstart").is_none());
    assert!(!body["env"].as_str().unwrap().contains('('));
    let decoded: Vec<String> =
        serde_json::from_slice(&hex::decode(&env["HELLAS_REMOTE_ARGS"]).unwrap()).unwrap();
    assert_eq!(decoded, spec.serve_args);
}

#[test]
fn state_is_private_and_cannot_accidentally_reallocate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    let state = Deployment {
        spec: spec(ProviderConfig::Docker { gpus: false }),
        credentials: Credentials::generate(),
        resource_id: None,
        enrollment: None,
        destroyed: false,
    };
    save_state(&path, &state, true).unwrap();
    let lock = lock_state(&path).unwrap();
    assert!(lock_state(&path).is_err());
    drop(lock);
    assert!(lock_state(&path).is_ok());
    assert!(save_state(&path, &state, true).is_err());
    let read: Deployment = read_json(&path).unwrap();
    assert_eq!(read.credentials.token, state.credentials.token);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn download_urls_and_sizes_are_explicit() {
    let hash = "a".repeat(64);
    assert!(validate_download("https://example.com/object", &hash, 1).is_ok());
    for url in [
        "http://example.com/a",
        "file:///etc/passwd",
        "https://u:p@example.com/a",
        "https://example.com/a#b",
    ] {
        assert!(validate_download(url, &hash, 1).is_err());
    }
    assert!(validate_download("https://example.com/a", "../escape", 1).is_err());
    assert!(validate_download("https://example.com/a", &hash, 0).is_err());
}
