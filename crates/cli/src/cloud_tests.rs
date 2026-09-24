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
    // The legitimate owner can restart without changing the worker's enrollment.
    service
        .execute(Request::Restart {
            name: "metal".into(),
        })
        .await
        .unwrap();
    assert_eq!(service.resolve("metal").await.unwrap(), enrollment);
    tokio::time::sleep(Duration::from_secs(1)).await;
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
