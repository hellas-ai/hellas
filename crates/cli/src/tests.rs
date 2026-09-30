use super::*;

#[cfg(all(feature = "cloud", unix))]
#[path = "cloud_tests.rs"]
mod cloud;

#[cfg(feature = "gateway")]
const TEST_ENVIRONMENT: &str = "/path/to/model.environment";
#[cfg(feature = "gateway")]
const TEST_MANIFEST_ID: &str = "4444444444444444444444444444444444444444444444444444444444444444";
#[cfg(feature = "gateway")]
const TEST_TOKENIZER: &str = "/path/to/tokenizer.json";
#[cfg(feature = "evaluate")]
const TEST_CONTENT: &str = "/path/to/model.hex";
const TEST_PROVIDER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const TEST_APP_ID: &str = "2F53L9ZR3N.ai.hellas.app";
const TEST_CDHASHES: &str = "2222222222222222222222222222222222222222222222222222222222222222,3333333333333333333333333333333333333333333333333333333333333333";
const TEST_REMOTE_TRUST_ARGS: &[&str] = &[
    "--provider",
    TEST_PROVIDER,
    "--assurance",
    "apple-app-attest",
    "--apple-app-attest-app-id",
    TEST_APP_ID,
    "--apple-app-attest-cdhashes",
    TEST_CDHASHES,
];

#[cfg(feature = "gateway")]
fn assert_test_remote_trust(remote_trust: &RemoteTrustArgs) {
    assert_eq!(
        remote_trust.provider_genesis,
        Some(hellas_rpc::ContentId::from_bytes([0x11; 32]))
    );
    assert_eq!(
        remote_trust.assurance,
        hellas_rpc::Assurance::AppleAppAttest
    );
    assert_eq!(
        remote_trust.apple_app_attest_app_id.as_deref(),
        Some(TEST_APP_ID)
    );
    assert_eq!(
        remote_trust.apple_app_attest_cdhashes,
        vec![[0x22; 32], [0x33; 32]]
    );
}

#[cfg(feature = "gateway")]
fn fetch_environment_cases() -> [(&'static str, hellas_rpc::ContentId); 3] {
    [
        (
            "codex-responses",
            hellas_rpc::FetchEnvironment::CodexResponses.manifest_id(),
        ),
        (
            "openai-responses",
            hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id(),
        ),
        (
            "0909090909090909090909090909090909090909090909090909090909090909",
            hellas_rpc::ContentId::from_bytes([9; 32]),
        ),
    ]
}

#[cfg(feature = "gateway")]
fn parse_gateway(args: &[&str]) -> Result<Cli, clap::Error> {
    #[cfg(feature = "evaluate")]
    let local = args.contains(&"--local");
    #[cfg(feature = "evaluate")]
    let local_content: &[&str] = if local {
        &["--content", TEST_CONTENT]
    } else {
        &[]
    };
    #[cfg(not(feature = "evaluate"))]
    let local_content: &[&str] = &[];
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

#[cfg(feature = "gateway")]
fn causal_lm_args(command: Commands) -> CausalLmArgs {
    match command {
        #[cfg(feature = "gateway")]
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
        for flag in TEST_REMOTE_TRUST_ARGS.chunks_exact(2) {
            assert!(
                Cli::try_parse_from(command.iter().copied().chain(flag.iter().copied())).is_err(),
                "{} accepted {}",
                command.join(" "),
                flag[0]
            );
        }
    }
}

#[cfg(feature = "node")]
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

    for flag in TEST_REMOTE_TRUST_ARGS.chunks_exact(2) {
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

#[cfg(feature = "gateway")]
#[test]
fn gateway_accepts_remote_trust_policy() {
    let cli = parse_gateway(TEST_REMOTE_TRUST_ARGS).unwrap();
    let Commands::Gateway { remote_trust, .. } = cli.command else {
        panic!("gateway");
    };
    assert_test_remote_trust(&remote_trust);
}

#[cfg(feature = "gateway")]
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

#[cfg(feature = "gateway")]
#[test]
fn gateway_requires_explicit_environment_and_tokenizer() {
    assert!(Cli::try_parse_from(["hellas", "gateway"]).is_err());
    assert!(
        Cli::try_parse_from(["hellas", "gateway", "--environment", TEST_ENVIRONMENT,]).is_err()
    );
    assert!(Cli::try_parse_from(["hellas", "gateway", "--tokenizer", TEST_TOKENIZER]).is_err());
}

#[cfg(all(feature = "gateway", feature = "node"))]
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

#[cfg(feature = "gateway")]
#[test]
fn gateway_model_is_only_an_optional_api_label() {
    let args = causal_lm_args(parse_gateway(&["--model", "api-label"]).unwrap().command);
    assert_eq!(args.model.as_deref(), Some("api-label"));
    let args = causal_lm_args(parse_gateway(&[]).unwrap().command);
    assert!(args.model.is_none());
}

#[cfg(feature = "evaluate")]
#[test]
fn local_content_flags_are_scoped_to_local_modes() {
    assert!(parse_gateway(&["--content", TEST_CONTENT]).is_err());
    assert!(parse_gateway(&["--content-index", "/state/index.bin"]).is_err());
}

#[cfg(feature = "evaluate")]
#[test]
fn local_modes_accept_repeatable_content_and_roots() {
    let cli = Cli::try_parse_from([
        "hellas",
        "gateway",
        "--environment",
        TEST_ENVIRONMENT,
        "--tokenizer",
        TEST_TOKENIZER,
        "--local",
        "--content",
        "/content/program.hex",
        "--content",
        "/content/weights.bin",
        "--content-root",
        "/content/cache",
        "--content-index",
        "/state/index.bin",
    ])
    .unwrap();
    let args = causal_lm_args(cli.command);
    assert_eq!(
        args.content_paths,
        ["/content/program.hex", "/content/weights.bin"].map(PathBuf::from)
    );
    assert_eq!(args.content_roots, vec![PathBuf::from("/content/cache")]);
    assert_eq!(args.content_index, Some(PathBuf::from("/state/index.bin")));
}

#[cfg(feature = "evaluate")]
#[test]
fn gateway_local_modes_require_and_accept_explicit_content() {
    let cli = parse_gateway(&["--local"]).unwrap();
    match cli.command {
        Commands::Gateway {
            causal_lm,
            node_id,
            node_addrs,
            local,
            ..
        } => {
            assert!(node_id.is_none());
            assert!(node_addrs.is_empty());
            assert!(local);
            assert_eq!(
                causal_lm.unwrap().content_paths,
                vec![PathBuf::from(TEST_CONTENT)]
            );
        }
        _ => panic!("expected gateway command"),
    }

    assert!(
        Cli::try_parse_from([
            "hellas",
            "gateway",
            "--environment",
            TEST_ENVIRONMENT,
            "--tokenizer",
            TEST_TOKENIZER,
            "--local",
        ])
        .is_err(),
        "a local route without explicit content was accepted"
    );
}

#[cfg(feature = "evaluate")]
#[test]
fn gateway_rejects_local_with_node_id() {
    let result = parse_gateway(&[
        "--local",
        "--node-id",
        "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
    ]);

    assert!(result.is_err());
}

#[cfg(feature = "gateway")]
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

#[cfg(feature = "gateway")]
#[test]
fn gateway_rejects_node_addr_without_node_id() {
    let result = parse_gateway(&["--node-addr", "127.0.0.1:31145"]);

    assert!(result.is_err());
}

#[cfg(feature = "node")]
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

#[cfg(feature = "gateway")]
#[test]
fn gateway_accepts_explicit_stop_tokens() {
    let cli = parse_gateway(&["--stop-token", "1,2", "--stop-token", "3"]).unwrap();
    assert_eq!(causal_lm_args(cli.command).stop_token_ids, vec![1, 2, 3]);
}

#[cfg(feature = "gateway")]
#[test]
fn gateway_rejects_a_zero_default_output_limit() {
    assert!(parse_gateway(&["--default-max-tokens", "0"]).is_err());
}

#[cfg(feature = "gateway")]
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

#[cfg(feature = "gateway")]
#[test]
fn gateway_wrap_args_require_wrap() {
    let result = parse_gateway(&["--", "-p", "hi"]);
    assert!(result.is_err(), "trailing args without --wrap should error");
}

#[cfg(feature = "gateway")]
#[test]
fn gateway_fetch_backend_accepts_builtin_environment_aliases_and_exact_id() {
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
fn producer_key_show_accepts_global_identity_path() {
    let cli = Cli::try_parse_from([
        "hellas",
        "--identity",
        "/tmp/hellas-identity",
        "producer-key",
        "show",
    ])
    .unwrap();
    assert_eq!(
        cli.identity.as_deref(),
        Some(std::path::Path::new("/tmp/hellas-identity"))
    );
    match cli.command {
        Commands::ProducerKey {
            command: ProducerKeyCommand::Show,
        } => {}
        _ => panic!("expected producer-key show command"),
    }
}

#[cfg(all(feature = "node", feature = "evaluate"))]
#[test]
fn serve_accepts_gpu_resource_envelope() {
    let cli = Cli::try_parse_from([
        "hellas",
        "serve",
        "--gpu-backend",
        "cuda",
        "--gpu-session-programs",
        "3",
        "--gpu-session-asset-bytes",
        "5",
        "--gpu-max-generation-capacity",
        "7",
        "--gpu-max-generation-device-bytes",
        "11",
        "--gpu-compile-timeout-secs",
        "13",
        "--gpu-execution-timeout-secs",
        "17",
    ])
    .unwrap();
    match cli.command {
        Commands::Serve {
            gpu_backend,
            gpu_session_programs,
            gpu_session_asset_bytes,
            gpu_max_generation_capacity,
            gpu_max_generation_device_bytes,
            gpu_compile_timeout_secs,
            gpu_execution_timeout_secs,
            ..
        } => {
            assert_eq!(gpu_backend, hellas_executor::GpuBackend::Cuda);
            assert_eq!(gpu_session_programs, 3);
            assert_eq!(gpu_session_asset_bytes, 5);
            assert_eq!(gpu_max_generation_capacity, 7);
            assert_eq!(gpu_max_generation_device_bytes, 11);
            assert_eq!(gpu_compile_timeout_secs, 13);
            assert_eq!(gpu_execution_timeout_secs, 17);
        }
        _ => panic!("expected serve command"),
    }
}

#[cfg(all(feature = "node", feature = "evaluate"))]
#[test]
fn serve_rejects_a_generation_capacity_above_the_transport_bound() {
    let over_limit = (hellas_executor::MAX_GPU_GENERATION_CAPACITY + 1).to_string();
    assert!(
        Cli::try_parse_from([
            "hellas",
            "serve",
            "--gpu-max-generation-capacity",
            &over_limit,
        ])
        .is_err()
    );
}

#[cfg(feature = "node")]
#[test]
fn serve_accepts_work_config() {
    let cli = Cli::try_parse_from(["hellas", "serve", "--work-config", "/tmp/work.json"]).unwrap();
    match cli.command {
        Commands::Serve {
            work_config_file, ..
        } => assert_eq!(
            work_config_file.as_deref(),
            Some(std::path::Path::new("/tmp/work.json"))
        ),
        _ => panic!("expected serve command"),
    }
}

/// An offer names every term of the bond it stakes, and the coins it
/// stakes them with come one flag at a time.
#[cfg(feature = "node")]
#[test]
fn provision_accepts_the_terms_of_one_bond() {
    let cli = Cli::try_parse_from([
        "hellas",
        "provision",
        "--work-config",
        "/tmp/work.json",
        "--client",
        "02aa",
        "--stake-coin",
        "a1",
        "--stake-coin",
        "a2",
        "--bond-timeout",
        "500",
        "--timeout-payout",
        "64",
        "--max-job-price",
        "40",
    ])
    .unwrap();
    match cli.command {
        Commands::Provision {
            work_config,
            client,
            stake_coin,
            bond_timeout,
            timeout_payout,
            max_job_price,
            print_bond_only,
        } => {
            assert_eq!(work_config, PathBuf::from("/tmp/work.json"));
            assert_eq!(client, "02aa");
            assert_eq!(stake_coin, vec!["a1".to_string(), "a2".to_string()]);
            assert_eq!(bond_timeout, 500);
            assert_eq!(timeout_payout, 64);
            assert_eq!(max_job_price, 40);
            assert!(!print_bond_only);
        }
        _ => panic!("expected provision command"),
    }
}

#[cfg(feature = "node")]
#[test]
fn provision_accepts_a_bond_only_preview() {
    let cli = Cli::try_parse_from([
        "hellas",
        "provision",
        "--work-config",
        "/tmp/work.json",
        "--client",
        "02aa",
        "--stake-coin",
        "a1",
        "--bond-timeout",
        "500",
        "--timeout-payout",
        "64",
        "--max-job-price",
        "40",
        "--print-bond-only",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Provision {
            print_bond_only: true,
            ..
        }
    ));
}

/// A bond funded by no coin is not one, so the stake is required
/// rather than defaulted to an empty list.
#[cfg(feature = "node")]
#[test]
fn provision_rejects_an_offer_with_nothing_staked() {
    assert!(
        Cli::try_parse_from([
            "hellas",
            "provision",
            "--work-config",
            "/tmp/work.json",
            "--client",
            "02aa",
            "--bond-timeout",
            "500",
            "--timeout-payout",
            "64",
            "--max-job-price",
            "40",
        ])
        .is_err(),
        "an offer staking nothing was accepted",
    );
}

/// The bond an offer stakes is settled with the key an operator
/// already made, exactly as a paid `serve` is: the same refusal, and
/// the same file named by it.
#[cfg(feature = "node")]
#[test]
fn provisioning_an_offer_loads_a_stored_settlement_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    let provision = Cli::try_parse_from([
        "hellas",
        "provision",
        "--work-config",
        "/tmp/work.json",
        "--client",
        "02aa",
        "--stake-coin",
        "a1",
        "--bond-timeout",
        "500",
        "--timeout-payout",
        "64",
        "--max-job-price",
        "40",
    ])
    .unwrap();

    let Err(error) = load_command_identity(&provision.command, Some(&path)) else {
        panic!("a bond is staked with a key an operator already made");
    };
    assert!(
        format!("{error:#}").contains(&path.display().to_string()),
        "the refusal does not name the identity file: {error:#}",
    );
    assert!(!path.exists(), "no identity was created by the refusal");
}

/// A node asked to serve paid work loads its settlement identity
/// before anything binds, and a missing one is a startup failure
/// naming the file.
///
/// The whole point is what it does *not* do: the same `serve`
/// without a work configuration creates the file, so the refusal
/// below is this rule and not a loader that always refuses. A node
/// that minted its own settlement key would advertise two paid ALPNs
/// as a party nobody has funded — and would say nothing about it.
#[cfg(feature = "node")]
#[test]
fn serving_paid_work_loads_a_stored_settlement_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    let paid = Cli::try_parse_from(["hellas", "serve", "--work-config", "/tmp/work.json"]).unwrap();
    let unpaid = Cli::try_parse_from(["hellas", "serve"]).unwrap();

    let Err(error) = load_command_identity(&paid.command, Some(&path)) else {
        panic!("paid work is settled with a key an operator already made");
    };
    assert!(
        format!("{error:#}").contains(&path.display().to_string()),
        "the refusal does not name the identity file: {error:#}",
    );
    assert!(!path.exists(), "no identity was created by the refusal");

    // The key is the identity's own, and the identity is the one on
    // disk: created here by a `serve` that was asked for no paid
    // work, and read back by the paid one that would not create it.
    let created = load_command_identity(&unpaid.command, Some(&path))
        .expect("a serve with no paid work still creates its transport identity");
    let loaded = load_command_identity(&paid.command, Some(&path))
        .expect("the stored identity is what paid work settles with");
    assert_eq!(
        identity::settlement_signer(&loaded).party_key(),
        identity::settlement_signer(&created).party_key(),
    );
    assert_eq!(
        &identity::settlement_signer(&loaded).party_key().to_bytes()[..],
        loaded.producer_key.public_key().bytes(),
        "the settlement party is the producer identity, not a second key",
    );
}

/// An identity file that is there and is not one is the same
/// startup failure, and names the same file.
#[cfg(feature = "node")]
#[test]
fn an_unreadable_settlement_identity_is_a_startup_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    std::fs::write(&path, b"not an identity").unwrap();
    let paid = Cli::try_parse_from(["hellas", "serve", "--work-config", "/tmp/work.json"]).unwrap();

    let Err(error) = load_command_identity(&paid.command, Some(&path)) else {
        panic!("an identity file that is not one is not a key to settle with");
    };

    assert!(
        format!("{error:#}").contains(&path.display().to_string()),
        "the refusal does not name the identity file: {error:#}",
    );
}

#[cfg(feature = "node")]
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

#[cfg(feature = "node")]
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
#[cfg(feature = "gateway")]
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

#[cfg(feature = "gateway")]
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
            "openai-responses",
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

#[cfg(feature = "node")]
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

#[cfg(feature = "gateway")]
#[test]
fn offer_gateway_uses_its_private_resources_and_existing_identity() {
    let cli = Cli::try_parse_from([
        "hellas",
        "gateway",
        "--offer",
        "lan-model",
        "--grant-policy",
        "chat",
    ])
    .unwrap();
    assert!(validate_identity_options(&cli.command, None, true).is_err());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("missing-identity");
    assert!(load_command_identity(&cli.command, Some(&path)).is_err());
    assert!(!path.exists());
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

#[cfg(feature = "gateway")]
#[test]
fn offer_gateway_accepts_independent_apple_trust_policy() {
    let cli = Cli::try_parse_from([
        "hellas",
        "gateway",
        "--offer",
        "provider",
        "--assurance",
        "apple-app-attest",
        "--apple-app-attest-app-id",
        "TEAM.app",
        "--apple-app-attest-cdhashes",
        &"11".repeat(32),
    ])
    .unwrap();
    let Commands::Gateway { remote_trust, .. } = cli.command else {
        panic!("gateway");
    };
    assert_eq!(
        remote_trust.assurance,
        hellas_rpc::Assurance::AppleAppAttest
    );
    assert_eq!(
        remote_trust.apple_app_attest_app_id.as_deref(),
        Some("TEAM.app")
    );
    assert_eq!(remote_trust.apple_app_attest_cdhashes, vec![[0x11; 32]]);
}
