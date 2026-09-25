use super::*;

#[test]
fn cloud_commands_accept_an_existing_owner_identity() {
    let cli =
        Cli::try_parse_from(["hellas", "cloud", "runpod", "--account", "work", "list"]).unwrap();
    assert!(validate_identity_options(&cli.command, None, false).is_ok());
    assert!(validate_identity_options(&cli.command, Some(Path::new("identity")), false).is_ok());
    assert!(validate_identity_options(&cli.command, None, true).is_err());
    let Commands::Cloud(hellas_cloud::cloud::CloudArgs {
        provider: hellas_cloud::cloud::CloudCommand::Runpod(args),
        ..
    }) = cli.command
    else {
        panic!("expected cloud runpod");
    };
    assert_eq!(args.account.as_deref(), Some("work"));
    assert!(matches!(
        args.command,
        hellas_cloud::cloud::RunpodCommand::List
    ));
}

#[test]
fn management_commands_require_an_existing_identity_and_do_not_generate_one() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("identity");
    for args in [
        vec!["hellas", "machines", "list"],
        vec!["hellas", "control", "serve"],
    ] {
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(validate_identity_options(&cli.command, Some(&missing), false).is_ok());
        assert!(validate_identity_options(&cli.command, Some(&missing), true).is_err());
    }
    assert!(identity::load_existing(Some(&missing)).is_err());
    assert!(!missing.exists());
}

#[test]
fn fetch_machine_uses_an_existing_identity_and_rejects_conflicting_pins() {
    let args = [
        "hellas",
        "fetch",
        "--machine",
        "metal",
        "--service",
        "http",
        "--method",
        "request",
        "--execution-environment",
        TEST_PROVIDER,
        "--payload",
        "{}",
    ];
    assert!(Cli::try_parse_from(args.into_iter().chain(["--node-addr", "127.0.0.1:3000"])).is_ok());
    let cli = Cli::try_parse_from(args).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("identity");
    assert!(load_command_identity(&cli.command, Some(&missing)).is_err());
    assert!(!missing.exists());
    assert!(validate_identity_options(&cli.command, None, true).is_err());
    for extra in [vec!["--provider", TEST_PROVIDER], vec![TEST_PROVIDER]] {
        assert!(Cli::try_parse_from(args.into_iter().chain(extra)).is_err());
    }
}

#[cfg(feature = "gateway")]
#[test]
fn gateway_machine_accepts_the_fetch_backend_without_a_model() {
    let cli = Cli::try_parse_from([
        "hellas",
        "gateway",
        "--machine",
        "metal",
        "--responses-backend",
        "fetch",
        "--responses-fetch-execution-environment",
        "openai-responses",
    ])
    .unwrap();
    assert_eq!(cli.command.owned_machine(), Some("metal"));
}

#[cfg(feature = "gateway")]
#[test]
fn gateway_can_select_owned_machines_without_conflicting_route_pins() {
    let cli = parse_gateway(&["--machine", "gpu"]).unwrap();
    assert!(validate_identity_options(&cli.command, None, true).is_err());
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("identity");
    assert!(load_command_identity(&cli.command, Some(&missing)).is_err());
    assert!(!missing.exists());
    assert!(parse_gateway(&["--machine", "gpu", "--provider", TEST_PROVIDER]).is_err());
    assert!(parse_gateway(&["--machine", "gpu", "--node-id", TEST_PROVIDER]).is_err());
    #[cfg(feature = "node")]
    assert!(parse_gateway(&["--machine", "gpu", "--paid-work-config", "work.json"]).is_err());
}

/// Actual local companion + Hellas server, with two real stored Hellas identities.
#[cfg(feature = "node")]
#[tokio::test]
#[ignore = "set HELLAS_CLI and HELLAS_AGENT to freshly built executables"]
async fn owner_controls_admin_and_hellas_rpc_even_when_receipt_is_stolen() {
    use hellas_cloud::{
        config::Credentials,
        management::{Request, Service},
        wire::{self, Operation, Response},
    };
    use std::time::Duration;
    let cli = PathBuf::from(std::env::var("HELLAS_CLI").unwrap());
    let agent = PathBuf::from(std::env::var("HELLAS_AGENT").unwrap());
    let dir = tempfile::tempdir().unwrap();
    let owner_path = dir.path().join("owner");
    let owner = identity::load_or_create(Some(&owner_path)).unwrap();
    let stranger_path = dir.path().join("stranger");
    let stranger = identity::load_or_create(Some(&stranger_path)).unwrap();
    let service = Service::new(owner.transport_key.clone(), &dir.path().join("inventory")).unwrap();
    let admin_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let admin_addr = admin_socket.local_addr().unwrap();
    drop(admin_socket);
    let node_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let node_addr = node_socket.local_addr().unwrap();
    drop(node_socket);
    let bootstrap = dir.path().join("bootstrap.json");
    service
        .execute(Request::Prepare {
            name: "metal".into(),
            bootstrap_file: bootstrap.clone(),
            admin_addr: Some(admin_addr),
            serve_args: vec![
                "--port".into(),
                node_addr.port().to_string(),
                "--execute-policy".into(),
                "none".into(),
                "--output-cache".into(),
                "record".into(),
                "--store-dir".into(),
                dir.path().join("store").to_string_lossy().into_owned(),
            ],
        })
        .await
        .unwrap();
    let mut child = tokio::process::Command::new(&agent)
        .args([
            "--no-relay",
            "--bind",
            &admin_addr.to_string(),
            "--bootstrap",
        ])
        .arg(&bootstrap)
        .arg("--cli")
        .arg(&cli)
        .arg("--data")
        .arg(dir.path().join("worker"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(
            std::fs::File::create(dir.path().join("agent.log")).unwrap(),
        ))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "{}",
        std::fs::read_to_string(dir.path().join("agent.log")).unwrap()
    );
    let enrollment = service.resolve("metal").await.unwrap();
    assert_ne!(enrollment.node_id, owner.transport_key.public().to_string());
    let env: serde_json::Value = hellas_cloud::config::read_json(&bootstrap).unwrap();
    // Simulate theft of the entire receipt: valid token and server key, wrong caller key.
    let stolen = Credentials {
        admin_secret: env["HELLAS_REMOTE_KEY"].as_str().unwrap().into(),
        token: env["HELLAS_REMOTE_TOKEN"].as_str().unwrap().into(),
        owner: None,
    };
    let denied = wire::call_as(
        &stolen,
        Some(admin_addr),
        Operation::Restart,
        Some(&stranger.transport_key),
    )
    .await
    .unwrap();
    assert!(matches!(denied, Response::Error { .. }));
    let configuration = hellas_cloud::configuration::Configuration {
        fetch_config: serde_json::json!({
            "routes": [{"service": "openai", "method": "responses",
                "destination": {"type": "openai-responses", "api_key_env": "TEST_UPSTREAM_KEY"}},
                {"service": "codex", "method": "responses",
                "destination": {"type": "codex-responses", "auth_path": "@files/auth.json"}}],
            "callers": []
        }),
        env: [(
            "TEST_UPSTREAM_KEY".into(),
            "integration-fixture-value".into(),
        )]
        .into(),
        files: [(
            "auth.json".into(),
            serde_json::json!({
                "version": 1, "tokens": {"access_token": "integration-file-value",
                    "refresh_token": "integration-refresh-value", "account_id": "test-account"},
                "last_refresh": null, "refresh_token_blocked": null
            }),
        )]
        .into(),
    };
    let denied = wire::call_as(
        &stolen,
        Some(admin_addr),
        Operation::Configure {
            configuration: configuration.clone(),
        },
        Some(&stranger.transport_key),
    )
    .await
    .unwrap();
    assert!(matches!(denied, Response::Error { .. }));
    let configuration_path = dir.path().join("worker/configuration.json");
    assert!(!configuration_path.exists());
    let configured = service
        .execute(Request::Configure {
            name: "metal".into(),
            configuration: configuration.clone(),
        })
        .await
        .unwrap();
    assert_eq!(configured["running"], true);
    assert_eq!(service.resolve("metal").await.unwrap(), enrollment);
    assert!(
        !service
            .list()
            .unwrap()
            .to_string()
            .contains("integration-fixture-value")
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&configuration_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let saved = std::fs::read(&configuration_path).unwrap();
    let installed: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    let private_fetch = PathBuf::from(installed["fetch_config"].as_str().unwrap());
    let private_file = private_fetch.parent().unwrap().join("files/auth.json");
    assert_eq!(
        std::fs::metadata(&private_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut refreshed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&private_file).unwrap()).unwrap();
    refreshed["tokens"]["access_token"] = serde_json::json!("rotated-fixture-value");
    std::fs::write(&private_file, serde_json::to_vec(&refreshed).unwrap()).unwrap();
    let mut invalid = configuration;
    invalid.fetch_config["unknown_field"] = serde_json::json!(true);
    assert!(
        service
            .execute(Request::Configure {
                name: "metal".into(),
                configuration: invalid,
            })
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&configuration_path).unwrap(), saved);
    assert_eq!(service.resolve("metal").await.unwrap(), enrollment);
    // The legitimate owner can restart without changing the worker's enrollment.
    service
        .execute(Request::Restart {
            name: "metal".into(),
        })
        .await
        .unwrap();
    assert_eq!(service.resolve("metal").await.unwrap(), enrollment);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let after_restart: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&private_file).unwrap()).unwrap();
    assert_eq!(
        after_restart, refreshed,
        "restart must preserve refreshed provider credentials"
    );
    for (caller, allowed) in [(&owner_path, true), (&stranger_path, false)] {
        let address = node_addr.to_string();
        for args in [
            vec!["rpc", &enrollment.node_id, "--node-addr", &address],
            vec![
                "output-cache",
                "--node-id",
                &enrollment.node_id,
                "--node-addr",
                &address,
                "stats",
            ],
        ] {
            let output = tokio::time::timeout(
                Duration::from_secs(30),
                tokio::process::Command::new(&cli)
                    .arg("--identity")
                    .arg(caller)
                    .args(&args)
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                output.status.success(),
                allowed,
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    // A bare-metal inventory entry selects the same authenticated Fetch route.
    // No caller grant is installed, so this must reach the remote policy denial
    // without making an upstream API call.
    let output = tokio::time::timeout(Duration::from_secs(30),
        tokio::process::Command::new(&cli)
            .env("HELLAS_MACHINES_DIR", dir.path().join("inventory"))
            .arg("--identity").arg(&owner_path)
            .args(["fetch", "--machine", "metal", "--node-addr", &node_addr.to_string(),
                "--service", "openai", "--method", "responses", "--execution-environment", "openai-responses",
                "--payload", r#"{"model":"fixture","input":"hello","stream":true,"store":false,"max_output_tokens":1}"#])
            .kill_on_drop(true).output()
    ).await.unwrap().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fetch caller key is not authorized"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    #[cfg(feature = "gateway")]
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let bearer = dir.path().join("gateway.bearer");
        let mut gateway = tokio::process::Command::new(&cli)
            .env("HELLAS_MACHINES_DIR", dir.path().join("inventory"))
            .arg("--identity")
            .arg(&owner_path)
            .args([
                "gateway",
                "--machine",
                "metal",
                "--node-addr",
                &node_addr.to_string(),
                "--responses-backend",
                "fetch",
                "--responses-fetch-route-service",
                "openai",
                "--responses-fetch-execution-environment",
                "openai-responses",
                "--port",
                &port.to_string(),
                "--bearer-token-file",
            ])
            .arg(&bearer)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::from(
                std::fs::File::create(dir.path().join("gateway.log")).unwrap(),
            ))
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let client = reqwest::Client::new();
        let mut response = None;
        for _ in 0..100 {
            assert!(
                gateway.try_wait().unwrap().is_none(),
                "{}",
                std::fs::read_to_string(dir.path().join("gateway.log")).unwrap()
            );
            if let Ok(token) = std::fs::read_to_string(&bearer)
                && let Ok(result) = client
                    .post(format!("http://127.0.0.1:{port}/v1/responses"))
                    .bearer_auth(token.trim())
                    .json(
                        &serde_json::json!({"model":"fixture", "input":"hello", "stream":false,
                        "store":false, "max_output_tokens":1}),
                    )
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await
            {
                response = Some(result);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let response = response.expect("fetch gateway became ready");
        assert!(!response.status().is_success());
        let body = response.text().await.unwrap();
        assert!(
            body.contains("fetch caller key is not authorized"),
            "{body}"
        );
        gateway.kill().await.unwrap();
        gateway.wait().await.unwrap();
    }
    unsafe {
        libc::kill(child.id().unwrap() as i32, libc::SIGTERM);
    }
    tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .unwrap()
        .unwrap();
    // An existing worker volume cannot silently change owners on restart.
    let mut changed = env;
    changed["HELLAS_REMOTE_OWNER"] = serde_json::json!(stranger.transport_key.public().to_string());
    let changed_path = dir.path().join("changed.json");
    std::fs::write(&changed_path, serde_json::to_vec(&changed).unwrap()).unwrap();
    let output = tokio::process::Command::new(&agent)
        .args(["--bootstrap"])
        .arg(changed_path)
        .arg("--cli")
        .arg(cli)
        .arg("--data")
        .arg(dir.path().join("worker"))
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("machine owner changed"));
}
