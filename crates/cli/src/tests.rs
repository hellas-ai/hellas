use super::*;

#[test]
fn durability_is_global_and_defaults_to_crash() {
    use hellas_private::Durability;
    for args in [
        vec![
            "hellas",
            "--durability",
            "power",
            "identity",
            "show-node-id",
        ],
        vec![
            "hellas",
            "identity",
            "show-node-id",
            "--durability",
            "power",
        ],
        vec!["hellas", "serve", "--durability", "power"],
    ] {
        assert_eq!(
            Cli::try_parse_from(args).unwrap().durability,
            Durability::Power
        );
    }
    assert_eq!(
        Cli::try_parse_from(["hellas", "identity", "show-node-id"])
            .unwrap()
            .durability,
        Durability::Crash,
    );
    assert!(Cli::try_parse_from(["hellas", "serve", "--durability", "off"]).is_err());
}

#[test]
fn image_cli_and_gateway_surfaces_are_available() {
    let commit = "ab".repeat(20);
    let snapshot = format!("org/klein@{commit}");
    for command in ["convert-flux", "convert-whisper"] {
        let convert = Cli::try_parse_from(["hellas", command, &snapshot, "-o", "out"]).unwrap();
        assert!(matches!(
            convert.command,
            Commands::ConvertFlux { .. } | Commands::ConvertWhisper { .. }
        ));
        assert!(
            Cli::try_parse_from(["hellas", command, "--checkpoint", "dir", "-o", "out"]).is_err()
        );
        assert!(Cli::try_parse_from(["hellas", command, "org/klein@main", "-o", "out"]).is_err());
    }
    let provider = format!("{}@{}", "11".repeat(32), "22".repeat(32));
    let image = Cli::try_parse_from([
        "hellas",
        "image",
        "--provider",
        &provider,
        "--model",
        "klein",
        "--prompt",
        "fox",
        "--pay",
        "20",
        "--seed",
        "42",
        "--steps",
        "4",
        "--width",
        "512",
        "--height",
        "512",
    ])
    .unwrap();
    assert!(matches!(image.command, Commands::Image(_)));
    let gateway = parse_gateway(&["--image-model", "klein"]).unwrap();
    assert!(matches!(
        gateway.command,
        Commands::Gateway {
            image_model: Some(_),
            ..
        }
    ));
}

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

/// A gateway under an access file, plus `args`.
fn parse_gateway(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(
        ["hellas", "gateway", "--access", "friend.access"]
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
        &["hellas", "store", "collect"],
        &["hellas", "identity", "init"],
    ];
    for command in commands {
        assert!(
            Cli::try_parse_from(command.iter().copied()).is_ok(),
            "{} must be a valid command",
            command.join(" ")
        );
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
fn gateway_takes_the_job_commands_targets() {
    let provider = format!("{}@{}", "11".repeat(32), "22".repeat(32));
    let gateway = |args: &[&str]| {
        Cli::try_parse_from(["hellas", "gateway"].into_iter().chain(args.iter().copied()))
    };
    assert!(gateway(&["--access", "friend.access"]).is_ok());
    assert!(gateway(&["--pay", "20", "--provider", &provider]).is_ok());
    assert_eq!(cfg!(feature = "compute"), gateway(&["--local"]).is_ok());
    for refused in [
        &[][..],
        &["--pay", "20"][..],
        &["--access", "friend.access", "--pay", "20", "--provider", &provider][..],
        &["--offer", "lan"][..],
        &["--paid-work-config", "pool.json", "--access", "friend.access"][..],
    ] {
        assert!(gateway(refused).is_err(), "{refused:?}");
    }
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
        ] {
            let mut argv = vec!["hellas", "admin"];
            argv.extend(operation.iter().copied());
            argv.extend(invalid);
            assert!(Cli::try_parse_from(argv).is_err());
        }
    }
}

#[test]
fn apple_assurance_requires_a_secure_enclave_root() {
    assert!(
        validate_serve_assurance(
            hellas_rpc::Assurance::AppleAppAttest,
            hellas_rpc::RootKind::Software,
        )
        .is_err()
    );
    assert!(
        validate_serve_assurance(
            hellas_rpc::Assurance::AppleAppAttest,
            hellas_rpc::RootKind::SecureEnclave,
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
fn identity_commands_accept_global_home() {
    let cli = Cli::try_parse_from([
        "hellas",
        "--home",
        "/state/hellas",
        "identity",
        "show-node-id",
    ])
    .unwrap();
    assert_eq!(
        cli.home.as_deref(),
        Some(std::path::Path::new("/state/hellas"))
    );
    assert!(Cli::try_parse_from(["hellas", "identity", "show-holder"]).is_err());
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

/// An identity file that is there and is not one is a startup
/// failure naming that file.
#[test]
fn an_unreadable_settlement_identity_is_a_startup_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    std::fs::write(&path, b"not an identity").unwrap();
    let Err(error) = identity::load_or_create(&path) else {
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
fn codex_auth_status_uses_home() {
    let cli =
        Cli::try_parse_from(["hellas", "codex-auth", "status", "--home", "/state/hellas"]).unwrap();
    match cli.command {
        Commands::CodexAuth {
            command: CodexAuthCommand::Status,
        } => assert_eq!(
            cli.home.as_deref(),
            Some(std::path::Path::new("/state/hellas"))
        ),
        _ => panic!("expected codex-auth status command"),
    }
}

#[test]
fn codex_auth_import_accepts_external_source() {
    let cli = Cli::try_parse_from([
        "hellas",
        "codex-auth",
        "import",
        "--from",
        "/state/external-codex-auth.json",
    ])
    .unwrap();
    match cli.command {
        Commands::CodexAuth {
            command: CodexAuthCommand::Import { source_path },
        } => {
            assert_eq!(
                source_path.as_deref(),
                Some(std::path::Path::new("/state/external-codex-auth.json"))
            );
        }
        _ => panic!("expected codex-auth import command"),
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
#[cfg(feature = "otel")]
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
            let target = ["--access", "friend.access"];
            let cli = Cli::try_parse_from(
                args.into_iter()
                    .chain(target.into_iter().filter(|_| command == "gateway")),
            )
            .unwrap();
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

#[test]
#[cfg(not(feature = "otel"))]
fn metrics_flags_require_the_otel_build() {
    for command in ["serve", "gateway"] {
        for (flag, value) in [("--metrics-port", "9400"), ("--metrics-addr", "0.0.0.0")] {
            let error = Cli::try_parse_from(["hellas", command, flag, value])
                .err()
                .expect("metrics flag must be absent");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
}

#[test]
fn serve_admits_configured_programs_and_acknowledges_any_only_from_configuration() {
    let manifest = "ab".repeat(32);
    let Commands::Serve {
        programs,
        knowingly_unsafe,
        ..
    } = Cli::try_parse_from(["hellas", "serve", "--program", &manifest])
        .unwrap()
        .command
    else {
        panic!("serve")
    };
    assert_eq!(programs, vec![manifest.parse().unwrap()]);
    assert!(!knowingly_unsafe);
    // An acknowledgement for configuration that admits any program, never a mode.
    for args in [
        vec![
            "hellas",
            "serve",
            "--knowingly-unsafe",
            "--grant-config",
            "g.json",
        ],
        vec![
            "hellas",
            "serve",
            "--knowingly-unsafe",
            "--paid-work-config",
            "p.toml",
        ],
    ] {
        assert!(Cli::try_parse_from(&args).is_ok(), "{args:?}");
    }
    for args in [
        vec![
            "hellas",
            "serve",
            "--program",
            &manifest,
            "--paid-work-config",
            "p.toml",
        ],
        vec![
            "hellas",
            "serve",
            "--program",
            &manifest,
            "--grant-config",
            "g.json",
        ],
        vec!["hellas", "serve", "--program", "not-a-hash"],
        vec!["hellas", "serve", "--await-owner"],
    ] {
        assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
    }
}

#[test]
fn pair_takes_one_invite_and_an_optional_name() {
    let Commands::Pair { invite, name } =
        Cli::try_parse_from(["hellas", "pair", "hellas-invite:abc"])
            .unwrap()
            .command
    else {
        panic!("pair")
    };
    assert_eq!(
        (invite.as_str(), name.as_str()),
        ("hellas-invite:abc", "default")
    );
    assert!(acts_for_principal(
        &Cli::try_parse_from(["hellas", "pair", "x", "--name", "gpu"])
            .unwrap()
            .command
    ));
    assert!(Cli::try_parse_from(["hellas", "pair"]).is_err());
    assert!(Cli::try_parse_from(["hellas", "admin", "bootstrap-remote"]).is_err());
}
