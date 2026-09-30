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
        vec!["hellas", "admin", "serve"],
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

#[cfg(feature = "gateway")]
#[test]
fn http_gateway_requires_a_paid_pool_instead_of_an_owned_machine() {
    let error = Cli::try_parse_from([
        "hellas",
        "gateway",
        "--machine",
        "metal",
        "--http-fetch-config",
        "gateway.json",
    ])
    .err()
    .expect("HTTP gateway cannot select a machine without a paid pool");
    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[cfg(feature = "gateway")]
#[test]
fn machine_gateway_can_discover_http_resources_without_an_environment() {
    let cli = Cli::try_parse_from([
        "hellas",
        "gateway",
        "--machine",
        "metal",
        "--grant-policy",
        "glm",
    ])
    .unwrap();
    assert_eq!(cli.command.owned_machine(), Some("metal"));
}
