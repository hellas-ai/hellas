use super::*;

#[cfg(unix)]
mod machines;

const TEST_ENVIRONMENT: &str = "/path/to/model.environment";
const TEST_MANIFEST_ID: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const TEST_TOKENIZER: &str = "/path/to/tokenizer.json";
const TEST_CONTENT: &str = "/path/to/model.hex";
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

fn fetch_environment_cases() -> [(&'static str, hellas_rpc::ContentId); 1] {
    [(
        "0909090909090909090909090909090909090909090909090909090909090909",
        hellas_rpc::ContentId::from_bytes([9; 32]),
    )]
}

fn parse_gateway(args: &[&str]) -> Result<Cli, clap::Error> {
    let local_content: &[&str] = if args.contains(&"--local") {
        &[
            "--content",
            TEST_CONTENT,
            "--local-grant",
            "07070707070707070707070707070707",
        ]
    } else {
        &[]
    };
    Cli::try_parse_from(
        [
            "hellas",
            "gateway",
            "--environment",
            TEST_ENVIRONMENT,
            "--tokenizer",
            TEST_TOKENIZER,
        ]
        .into_iter()
        .chain(local_content.iter().copied())
        .chain(args.iter().copied()),
    )
}

fn causal_lm_args(command: Commands) -> CausalLmArgs {
    match command {
        Commands::Gateway { causal_lm, .. } => causal_lm.expect("causal-LM arguments"),
        _ => panic!("expected causal-LM command"),
    }
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
            "environment",
            "inspect",
            "--environment",
            "model.environment",
        ],
        vec![
            "hellas",
            "environment",
            "inspect",
            "--environment",
            "model.environment",
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
fn gateway_accepts_the_optional_environment_pin() {
    let pinned = causal_lm_args(
        parse_gateway(&["--manifest-id", TEST_MANIFEST_ID])
            .unwrap()
            .command,
    );
    assert_eq!(
        pinned.manifest_id,
        Some(hellas_rpc::ContentId::from_bytes([0x44; 32]))
    );
}

#[test]
fn gateway_requires_explicit_environment_and_tokenizer() {
    assert!(Cli::try_parse_from(["hellas", "gateway"]).is_err());
    assert!(
        Cli::try_parse_from(["hellas", "gateway", "--environment", TEST_ENVIRONMENT,]).is_err()
    );
    assert!(Cli::try_parse_from(["hellas", "gateway", "--tokenizer", TEST_TOKENIZER]).is_err());
}

#[test]
fn http_gateway_requires_a_paid_pool() {
    assert!(
        Cli::try_parse_from(["hellas", "gateway", "--http-fetch-config", "/http.json"]).is_err()
    );
    assert!(
        Cli::try_parse_from([
            "hellas",
            "gateway",
            "--http-fetch-config",
            "/http.json",
            "--paid-work-config",
            "/pool.json"
        ])
        .is_ok()
    );
}

#[test]
fn gateway_model_is_only_an_optional_api_label() {
    let args = causal_lm_args(parse_gateway(&["--model", "api-label"]).unwrap().command);
    assert_eq!(args.model.as_deref(), Some("api-label"));
    let args = causal_lm_args(parse_gateway(&[]).unwrap().command);
    assert!(args.model.is_none());
}

fn gateway_trust(args: &[&str]) -> anyhow::Result<Option<hellas_client::ProviderTrustAnchor>> {
    let cli = parse_gateway(args).expect("valid gateway arguments");
    let Commands::Gateway {
        responses_backend, ..
    } = cli.command
    else {
        panic!("gateway");
    };
    gateway_provider_trust(responses_backend)
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
fn gateway_accepts_explicit_stop_tokens() {
    let cli = parse_gateway(&["--stop-token", "1,2", "--stop-token", "3"]).unwrap();
    assert_eq!(causal_lm_args(cli.command).stop_token_ids, vec![1, 2, 3]);
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
fn gateway_fetch_backend_accepts_exact_contract_id() {
    for (spelling, expected) in fetch_environment_cases() {
        let cli = parse_gateway(&[
            "--responses-backend",
            "fetch",
            "--responses-fetch-route-service",
            "codex",
            "--responses-fetch-route-method",
            "responses",
            "--responses-fetch-execution-environment",
            spelling,
            "--responses-fetch-request-overrides",
            r#"{"store":false}"#,
        ])
        .unwrap();
        match cli.command {
            Commands::Gateway {
                responses_backend,
                responses_fetch_route_service,
                responses_fetch_route_method,
                responses_fetch_execution_environment,
                responses_fetch_request_overrides,
                ..
            } => {
                assert_eq!(responses_backend, GatewayResponsesBackend::Fetch);
                assert_eq!(responses_fetch_route_service, "codex");
                assert_eq!(responses_fetch_route_method, "responses");
                assert_eq!(responses_fetch_execution_environment, Some(expected));
                assert_eq!(responses_fetch_request_overrides.unwrap()["store"], false);
            }
            _ => panic!("expected gateway command"),
        }
    }
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
    let cli = Cli::try_parse_from(["hellas", "serve", "--paid-work-config", "/tmp/work.toml"]).unwrap();
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
    let paid = Cli::try_parse_from(["hellas", "serve", "--paid-work-config", "/tmp/work.toml"]).unwrap();

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
fn content_id_parser_round_trips_xet_text_encoding() {
    let displayed = "87d327b23e941d6932610a282834a2d7d5edd761fe0a1b948e5f0d7ca73392ca";
    assert_eq!(
        parse_content_id_hex(displayed).unwrap().to_string(),
        displayed
    );
}
#[test]
fn proxy_cache_needs_no_causal_lm_files() {
    let cli = Cli::try_parse_from([
        "hellas",
        "gateway",
        "--responses-backend",
        "proxy",
        "--output-cache",
        "replay-only",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Gateway {
            causal_lm: None,
            ..
        }
    ));
}

#[test]
fn unfunded_gateway_routes_require_a_work_backend() {
    assert!(
        gateway_trust(&["--responses-backend", "proxy"])
            .unwrap()
            .is_none()
    );
    for args in [
        vec![],
        vec![
            "--responses-backend",
            "fetch",
            "--responses-fetch-execution-environment",
            "a05c3a1d598166d4a85f6a6a0ff0302e71647b53109902ae5752f6bc04a1acac",
        ],
    ] {
        let error = gateway_trust(&args).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<hellas_client::ClientError>(),
            Some(hellas_client::ClientError::FundingRequired)
        ));
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
        vec!["--responses-backend", "proxy"],
        vec![
            "--node-id",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        vec!["--http-fetch-config", "/http.json"],
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

#[cfg(feature = "evaluate")]
mod evaluate;
