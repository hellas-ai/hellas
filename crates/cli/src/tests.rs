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

/// The route-document gateway command, plus process arguments.
fn parse_gateway(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(
        ["hellas", "gateway", "--model", "model.gguf"]
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
fn gateway_wrap_forwards_trailing_args() {
    let cli = parse_gateway(&["--wrap", "pi", "--", "-p", "--no-session", "say hello"]).unwrap();
    match cli.command {
        Commands::Gateway { args, .. } => {
            assert_eq!(args.wrap.as_deref(), Some("pi"));
            assert_eq!(args.wrap_args, vec!["-p", "--no-session", "say hello"]);
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
            let target = ["--model", "model.gguf"];
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
