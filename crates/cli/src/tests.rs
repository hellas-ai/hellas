use super::*;

#[cfg(unix)]
mod machines;

const TEST_REMOTE_TRUST_ARGS: &[&str] = &[
    "--trust-store",
    "/state/trust",
    "--trust-policy",
    "provider",
    "--assurance",
    "apple-app-attest",
];

fn assert_test_remote_trust(remote_trust: &RemoteTrustArgs) {
    assert_eq!(
        remote_trust.trust_store.as_deref(),
        Some(Path::new("/state/trust"))
    );
    assert_eq!(remote_trust.trust_policy.as_deref(), Some("provider"));
    assert_eq!(
        remote_trust.assurance,
        hellas_rpc::Assurance::AppleAppAttest
    );
}

fn parse_gateway(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(
        ["hellas", "gateway"]
            .into_iter()
            .chain(args.iter().copied()),
    )
}

#[test]
fn identity_init_has_an_explicit_dispatch_command() {
    let cli = Cli::try_parse_from(["hellas", "identity", "init"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Identity {
            command: IdentityCommand::Init,
        }
    ));
}

#[test]
fn identity_free_commands_reject_global_identity_options() {
    for args in [
        vec![
            "hellas",
            "--identity",
            "unused.identity",
            "offer",
            "import",
            "provider.offer",
            "--name",
            "provider",
        ],
        vec![
            "hellas",
            "offer",
            "import",
            "provider.offer",
            "--name",
            "provider",
            "--software-root",
        ],
    ] {
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(
            validate_identity_options(&cli.command, cli.identity.as_deref(), cli.software_root,)
                .is_err()
        );
    }
}

#[test]
fn identity_queries_reject_a_root_selection_they_cannot_use() {
    let cli =
        Cli::try_parse_from(["hellas", "identity", "show-node-id", "--software-root"]).unwrap();
    assert!(
        validate_identity_options(&cli.command, cli.identity.as_deref(), cli.software_root,)
            .is_err()
    );
}

#[test]
fn identity_enrollment_id_has_an_explicit_dispatch_command() {
    let cli = Cli::try_parse_from(["hellas", "identity", "show-enrollment-id"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Identity {
            command: IdentityCommand::ShowEnrollmentId,
        }
    ));
}

#[test]
fn remote_trust_flags_are_rejected_by_irrelevant_commands() {
    let commands: &[&[&str]] = &[
        &["hellas", "store", "status"],
        &[
            "hellas",
            "environment",
            "inspect",
            "--environment",
            "model.environment",
        ],
        &["hellas", "identity", "init"],
    ];
    for command in commands {
        for flag in TEST_REMOTE_TRUST_ARGS.as_chunks::<2>().0 {
            assert!(
                Cli::try_parse_from(command.iter().copied().chain(flag.iter().copied())).is_err(),
                "{} accepted {}",
                command.join(" "),
                flag[0]
            );
        }
    }
}

#[test]
fn serve_accepts_only_its_command_local_assurance() {
    let cli = Cli::try_parse_from(["hellas", "serve", "--assurance", "apple-app-attest"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Serve {
            assurance: hellas_rpc::Assurance::AppleAppAttest,
            ..
        }
    ));

    for flag in TEST_REMOTE_TRUST_ARGS.as_chunks::<2>().0 {
        if flag[0] == "--assurance" {
            continue;
        }
        assert!(
            Cli::try_parse_from(["hellas", "serve"].into_iter().chain(flag.iter().copied()))
                .is_err(),
            "serve accepted requester-only {}",
            flag[0]
        );
    }
}

#[test]
fn gateway_accepts_remote_trust_policy() {
    let cli = parse_gateway(TEST_REMOTE_TRUST_ARGS).unwrap();
    let Commands::Gateway { remote_trust, .. } = cli.command else {
        panic!("gateway");
    };
    assert_test_remote_trust(&remote_trust);
}

#[test]
fn gateway_rejects_address_without_node_id() {
    let result = parse_gateway(&["--address", "127.0.0.1:31145"]);

    assert!(result.is_err());
}

#[test]
fn admin_target_is_shared_and_requires_an_identity_pin() {
    for operation in [vec!["status"], vec!["grant", "change.json"]] {
        for before in [true, false] {
            let target = [
                "--node",
                "node.enrollment",
                "--address",
                "127.0.0.1:9000,[::1]:9000",
            ];
            let mut argv = vec!["hellas", "admin"];
            if before {
                argv.extend(target);
            }
            argv.extend(operation.iter().copied());
            if !before {
                argv.extend(target);
            }
            let Commands::Admin(args) = Cli::try_parse_from(argv).unwrap().command else {
                panic!("admin");
            };
            assert_eq!(args.node_enrollment.as_deref(), Some("node.enrollment"));
            assert_eq!(args.addresses.len(), 2);
        }
        for invalid in [
            vec!["--address", "127.0.0.1:9000"],
            vec!["--node", "node.enrollment", "--control-socket", "node.sock"],
            vec!["--store-dir", "store"],
            vec!["--output-cache", "off"],
        ] {
            let mut argv = vec!["hellas", "admin"];
            argv.extend(operation.iter().copied());
            argv.extend(invalid);
            assert!(Cli::try_parse_from(argv).is_err());
        }
    }
}

#[test]
fn serve_rejects_software_root_with_apple_assurance() {
    assert!(validate_serve_assurance(true, hellas_rpc::Assurance::AppleAppAttest, None).is_err());
    assert!(
        validate_serve_assurance(
            false,
            hellas_rpc::Assurance::AppleAppAttest,
            Some(hellas_rpc::RootKind::Software),
        )
        .is_err()
    );
    assert!(
        validate_serve_assurance(
            false,
            hellas_rpc::Assurance::AppleAppAttest,
            Some(hellas_rpc::RootKind::SecureEnclave),
        )
        .is_ok()
    );
}

#[test]
fn gateway_rejects_a_zero_default_output_limit() {
    assert!(parse_gateway(&["--default-max-tokens", "0"]).is_err());
}

#[test]
fn gateway_wrap_forwards_trailing_args() {
    let cli = parse_gateway(&["--wrap", "pi", "--", "-p", "--no-session", "say hello"]).unwrap();
    match cli.command {
        Commands::Gateway {
            wrap, wrap_args, ..
        } => {
            assert_eq!(wrap.as_deref(), Some("pi"));
            assert_eq!(wrap_args, vec!["-p", "--no-session", "say hello"]);
        }
        _ => panic!("expected gateway command"),
    }
}

#[test]
fn gateway_wrap_args_require_wrap() {
    let result = parse_gateway(&["--", "-p", "hi"]);
    assert!(result.is_err(), "trailing args without --wrap should error");
}

#[test]
fn gateway_responses_fetch_takes_overrides_and_its_models() {
    let cli = parse_gateway(&[
        "--responses-overrides",
        r#"{"store":false}"#,
        "--responses-model",
        "gpt-x,gpt-y",
    ])
    .unwrap();
    let Commands::Gateway {
        responses_overrides,
        responses_models,
        ..
    } = cli.command
    else {
        panic!("expected gateway command");
    };
    assert_eq!(responses_overrides.unwrap()["store"], false);
    assert_eq!(responses_models, ["gpt-x", "gpt-y"]);
}

#[test]
fn identity_show_holder_accepts_global_identity_path() {
    let cli = Cli::try_parse_from([
        "hellas",
        "--identity",
        "/tmp/hellas-identity",
        "identity",
        "show-holder",
    ])
    .unwrap();
    assert_eq!(
        cli.identity.as_deref(),
        Some(std::path::Path::new("/tmp/hellas-identity"))
    );
    assert!(matches!(
        cli.command,
        Commands::Identity {
            command: IdentityCommand::ShowHolder
        }
    ));
    assert!(Cli::try_parse_from(["hellas", "producer-key", "show"]).is_err());
}

#[test]
fn serve_accepts_work_config() {
    let cli =
        Cli::try_parse_from(["hellas", "serve", "--paid-work-config", "/tmp/work.toml"]).unwrap();
    match cli.command {
        Commands::Serve {
            work_config_file, ..
        } => assert_eq!(
            work_config_file.as_deref(),
            Some(std::path::Path::new("/tmp/work.toml"))
        ),
        _ => panic!("expected serve command"),
    }
}

#[test]
fn manual_provisioning_command_is_removed() {
    assert!(Cli::try_parse_from(["hellas", "provision"]).is_err());
}

/// An identity file that is there and is not one is a startup
/// failure naming that file.
#[test]
fn an_unreadable_settlement_identity_is_a_startup_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    std::fs::write(&path, b"not an identity").unwrap();
    let paid =
        Cli::try_parse_from(["hellas", "serve", "--paid-work-config", "/tmp/work.toml"]).unwrap();

    let Err(error) = load_command_identity(&paid.command, Some(&path)) else {
        panic!("an identity file that is not one is not a key to settle with");
    };

    assert!(
        format!("{error:#}").contains(&path.display().to_string()),
        "the refusal does not name the identity file: {error:#}",
    );
}

#[test]
fn serve_accepts_fetch_config() {
    let cli = Cli::try_parse_from([
        "hellas",
        "serve",
        "--fetch-max-in-flight",
        "3",
        "--fetch-queue-size",
        "0",
        "--fetch-config",
        "/tmp/fetch-config.json",
    ])
    .unwrap();
    match cli.command {
        Commands::Serve {
            fetch_max_in_flight,
            fetch_queue_size,
            fetch_config_file,
            ..
        } => {
            assert_eq!(fetch_max_in_flight, 3);
            assert_eq!(fetch_queue_size, 0);
            assert_eq!(
                fetch_config_file.as_deref(),
                Some(std::path::Path::new("/tmp/fetch-config.json"))
            );
        }
        _ => panic!("expected serve command"),
    }
}

#[test]
fn serve_rejects_zero_fetch_concurrency() {
    assert!(
        Cli::try_parse_from(["hellas", "serve", "--fetch-replay-max-in-flight", "0",]).is_err()
    );
    assert!(Cli::try_parse_from(["hellas", "serve", "--fetch-max-in-flight", "0"]).is_err());
}

#[test]
fn codex_auth_status_accepts_auth_path() {
    let cli = Cli::try_parse_from([
        "hellas",
        "codex-auth",
        "status",
        "--auth-path",
        "/tmp/codex-auth.json",
    ])
    .unwrap();
    match cli.command {
        Commands::CodexAuth {
            command: CodexAuthCommand::Status { auth_path },
        } => assert_eq!(
            auth_path.as_deref(),
            Some(std::path::Path::new("/tmp/codex-auth.json"))
        ),
        _ => panic!("expected codex-auth status command"),
    }
}

#[test]
fn codex_auth_import_accepts_paths() {
    let cli = Cli::try_parse_from([
        "hellas",
        "codex-auth",
        "import",
        "--auth-path",
        "/tmp/hellas-codex-auth.json",
        "--from",
        "/tmp/codex-auth.json",
    ])
    .unwrap();
    match cli.command {
        Commands::CodexAuth {
            command:
                CodexAuthCommand::Import {
                    auth_path,
                    source_path,
                },
        } => {
            assert_eq!(
                auth_path.as_deref(),
                Some(std::path::Path::new("/tmp/hellas-codex-auth.json"))
            );
            assert_eq!(
                source_path.as_deref(),
                Some(std::path::Path::new("/tmp/codex-auth.json"))
            );
        }
        _ => panic!("expected codex-auth import command"),
    }
}

#[test]
fn retired_commands_are_not_exposed() {
    for command in ["llm", "fetch", "artifact", "output-cache"] {
        assert!(Cli::try_parse_from(["hellas", command]).is_err());
    }
}

#[test]
fn serve_uses_bounded_fetch_defaults() {
    let cli = Cli::try_parse_from(["hellas", "serve"]).unwrap();
    let Commands::Serve {
        fetch_max_in_flight,
        fetch_queue_size,
        ..
    } = cli.command
    else {
        panic!("serve");
    };
    assert_eq!(fetch_max_in_flight, hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT);
    assert_eq!(fetch_queue_size, hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY);
}

#[test]
fn offer_gateway_uses_its_private_resources_and_existing_identity() {
    let cli = Cli::try_parse_from([
        "hellas",
        "gateway",
        "--offer",
        "lan-model",
        "--grant-policy",
        "chat",
        "--work-profile",
        "/work.json",
        "--gateway-profile",
        "/gateway.json",
    ])
    .unwrap();
    assert!(validate_identity_options(&cli.command, None, true).is_err());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("missing-identity");
    assert!(load_command_identity(&cli.command, Some(&path)).is_err());
    assert!(!path.exists());
    let Commands::Gateway {
        grant_policy,
        work_profile,
        gateway_profile,
        ..
    } = &cli.command
    else {
        panic!("gateway")
    };
    assert_eq!(grant_policy.as_deref(), Some("chat"));
    assert_eq!(work_profile.as_deref(), Some(Path::new("/work.json")));
    assert_eq!(gateway_profile.as_deref(), Some(Path::new("/gateway.json")));
    for args in [
        vec!["--paid-work-config", "/pool.json"],
        vec!["--local-grant", "00000000000000000000000000000000"],
    ] {
        let mut argv = vec!["hellas", "gateway", "--offer", "lan-model"];
        argv.extend(args);
        assert!(Cli::try_parse_from(argv).is_err());
    }
}

#[test]
fn offer_gateway_accepts_independent_apple_trust_policy() {
    let cli = Cli::try_parse_from(
        ["hellas", "gateway", "--offer", "provider"]
            .into_iter()
            .chain(TEST_REMOTE_TRUST_ARGS.iter().copied()),
    )
    .unwrap();
    let Commands::Gateway { remote_trust, .. } = cli.command else {
        panic!("gateway");
    };
    assert_test_remote_trust(&remote_trust);
    for flag in [
        "--provider",
        "--apple-app-attest-app-id",
        "--apple-app-attest-cdhashes",
    ] {
        assert!(
            Cli::try_parse_from([
                "hellas",
                "gateway",
                "--offer",
                "provider",
                flag,
                "unapproved"
            ])
            .is_err()
        );
    }
}

#[test]
fn metrics_address_defaults_to_loopback_and_accepts_an_explicit_ip() {
    for command in ["serve", "gateway"] {
        for (args, expected) in [
            (
                vec!["hellas", command, "--metrics-port", "9400"],
                "127.0.0.1",
            ),
            (
                vec![
                    "hellas",
                    command,
                    "--metrics-port",
                    "9400",
                    "--metrics-addr",
                    "0.0.0.0",
                ],
                "0.0.0.0",
            ),
            (
                vec![
                    "hellas",
                    command,
                    "--metrics-port",
                    "9400",
                    "--metrics-addr",
                    "::1",
                ],
                "::1",
            ),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            let (port, address) = match cli.command {
                Commands::Serve {
                    metrics_port,
                    metrics_addr,
                    ..
                }
                | Commands::Gateway {
                    metrics_port,
                    metrics_addr,
                    ..
                } => (metrics_port, metrics_addr),
                _ => unreachable!(),
            };
            assert_eq!(port, Some(9400));
            assert_eq!(address, expected.parse::<std::net::IpAddr>().unwrap());
        }
        assert!(Cli::try_parse_from(["hellas", command, "--metrics-addr", "not-an-ip"]).is_err());
    }
}
