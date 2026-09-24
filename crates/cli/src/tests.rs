use super::*;

#[cfg(all(feature = "cloud", unix))]
#[path = "cloud_tests.rs"]
mod cloud;

#[cfg(feature = "llm")]
const TEST_ENVIRONMENT: &str = "/path/to/model.environment";
#[cfg(feature = "llm")]
const TEST_MANIFEST_ID: &str = "4444444444444444444444444444444444444444444444444444444444444444";
#[cfg(feature = "llm")]
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

#[cfg(feature = "llm")]
fn parse_llm(args: &[&str]) -> Result<Cli, clap::Error> {
    #[cfg(feature = "evaluate")]
    let local = args.contains(&"--local") || args.contains(&"--verify-local");
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
            "llm",
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
fn parse_gateway(args: &[&str]) -> Result<Cli, clap::Error> {
    #[cfg(feature = "evaluate")]
    let local = args.contains(&"--local") || args.contains(&"--verify-local");
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

#[cfg(feature = "llm")]
fn causal_lm_args(command: Commands) -> CausalLmArgs {
    match command {
        Commands::Llm { causal_lm, .. } => causal_lm,
        #[cfg(feature = "gateway")]
        Commands::Gateway { causal_lm, .. } => causal_lm.expect("causal-LM arguments"),
        _ => panic!("expected causal-LM command"),
    }
}

#[test]
fn cache_reset_can_target_a_live_control_socket_without_an_identity() {
    let cli = Cli::try_parse_from([
        "hellas",
        "output-cache",
        "--socket",
        "/run/user/1000/hellas/control.sock",
        "reset",
    ])
    .unwrap();
    assert!(matches!(&cli.command, Commands::OutputCache(_)));
    assert!(validate_identity_options(&cli.command, None, false).is_ok());
}

#[test]
fn remote_cache_management_uses_an_existing_identity_and_exclusive_transport() {
    let peer = "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550";
    let cli = Cli::try_parse_from([
        "hellas",
        "--identity",
        "owner.identity",
        "output-cache",
        "--node-id",
        peer,
        "--kind",
        "proxy",
        "--key",
        peer,
        "show",
    ])
    .unwrap();
    assert!(validate_identity_options(&cli.command, cli.identity.as_deref(), false).is_ok());
    assert!(validate_identity_options(&cli.command, cli.identity.as_deref(), true).is_err());
    assert_eq!(
        cli.identity.as_deref(),
        Some(std::path::Path::new("owner.identity"))
    );
    let Commands::OutputCache(args) = cli.command else {
        panic!()
    };
    assert_eq!(args.key.as_deref(), Some(peer));
    let offline = Cli::try_parse_from([
        "hellas",
        "output-cache",
        "--kind",
        "proxy",
        "--key",
        peer,
        "show",
    ])
    .unwrap();
    assert!(offline.identity.is_none());
    assert!(
        Cli::try_parse_from([
            "hellas",
            "output-cache",
            "--node-id",
            peer,
            "--socket",
            "control.sock",
            "clear"
        ])
        .is_err()
    );
}

#[cfg(feature = "node")]
#[test]
fn remote_admin_is_explicitly_granted() {
    let cli = Cli::try_parse_from(["hellas", "serve"]).unwrap();
    let Commands::Serve { admin_peers, .. } = cli.command else {
        panic!()
    };
    assert!(admin_peers.is_empty());
    let peer = "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550";
    let cli = Cli::try_parse_from(["hellas", "serve", "--admin-peer", peer]).unwrap();
    let Commands::Serve { admin_peers, .. } = cli.command else {
        panic!()
    };
    assert_eq!(admin_peers, [peer.parse::<iroh::EndpointId>().unwrap()]);
}

#[cfg(feature = "gateway")]
#[test]
fn control_socket_is_not_cache_specific_and_does_not_require_record_mode() {
    let cli = Cli::try_parse_from([
        "hellas",
        "--control-socket",
        "/run/user/1000/hellas/control.sock",
        "gateway",
        "--responses-backend",
        "proxy",
    ])
    .unwrap();
    assert_eq!(
        cli.control_socket.as_deref(),
        Some(std::path::Path::new("/run/user/1000/hellas/control.sock"))
    );
    assert_eq!(cli.output_cache, hellas_rpc::cache::CachePolicy::Off);
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

#[cfg(feature = "llm")]
#[test]
fn llm_accepts_remote_trust_policy() {
    let mut args = TEST_REMOTE_TRUST_ARGS.to_vec();
    args.extend(["-p", "hello"]);
    assert!(parse_llm(&args).is_ok());
}

#[cfg(feature = "llm")]
#[test]
fn llm_accepts_an_optional_strict_environment_pin() {
    let pinned = causal_lm_args(
        parse_llm(&["--manifest-id", TEST_MANIFEST_ID, "-p", "hello"])
            .unwrap()
            .command,
    );
    assert_eq!(
        pinned.manifest_id,
        Some(hellas_rpc::ContentId::from_bytes([0x44; 32]))
    );

    let derived = causal_lm_args(parse_llm(&["-p", "hello"]).unwrap().command);
    assert!(derived.manifest_id.is_none());
    assert!(parse_llm(&["--manifest-id", "not-a-content-id", "-p", "hello"]).is_err());
}

#[cfg(feature = "gateway")]
#[test]
fn gateway_accepts_remote_trust_policy() {
    assert!(parse_gateway(TEST_REMOTE_TRUST_ARGS).is_ok());
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

#[cfg(feature = "evaluate")]
#[test]
fn llm_accepts_local_mode() {
    let cli = parse_llm(&["--local", "-p", "hello"]).unwrap();
    match cli.command {
        Commands::Llm {
            causal_lm,
            node_id,
            node_addrs,
            local,
            verify_local,
            ..
        } => {
            assert!(node_id.is_none());
            assert!(node_addrs.is_empty());
            assert!(local);
            assert!(!verify_local);
            assert_eq!(causal_lm.environment, PathBuf::from(TEST_ENVIRONMENT));
            assert!(causal_lm.manifest_id.is_none());
            assert_eq!(causal_lm.content_paths, vec![PathBuf::from(TEST_CONTENT)]);
            assert_eq!(causal_lm.tokenizer, PathBuf::from(TEST_TOKENIZER));
            assert!(causal_lm.stop_token_ids.is_empty());
        }
        _ => panic!("expected llm command"),
    }
}

#[cfg(feature = "llm")]
#[test]
fn llm_requires_explicit_environment_and_tokenizer() {
    assert!(Cli::try_parse_from(["hellas", "llm", "-p", "hello"]).is_err());
    assert!(
        Cli::try_parse_from([
            "hellas",
            "llm",
            "--environment",
            TEST_ENVIRONMENT,
            "-p",
            "hello",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "hellas",
            "llm",
            "--tokenizer",
            TEST_TOKENIZER,
            "-p",
            "hello",
        ])
        .is_err()
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

#[cfg(feature = "llm")]
#[test]
fn package_flags_are_not_accepted_as_compatibility_aliases() {
    assert!(
        parse_llm(&["--package", "old-package", "-p", "hello"]).is_err(),
        "the removed package selector was accepted"
    );
    assert!(
        parse_llm(&[
            "--package-id",
            "0808080808080808080808080808080808080808080808080808080808080808",
            "-p",
            "hello",
        ])
        .is_err(),
        "the removed package identity was accepted"
    );
}

#[cfg(feature = "llm")]
#[test]
fn llm_model_is_only_an_optional_label() {
    let args = causal_lm_args(
        parse_llm(&["--model", "friendly-name", "-p", "hello"])
            .unwrap()
            .command,
    );
    assert_eq!(args.model.as_deref(), Some("friendly-name"));
    let args = causal_lm_args(parse_llm(&["-p", "hello"]).unwrap().command);
    assert!(args.model.is_none());
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
    assert!(parse_llm(&["--content", TEST_CONTENT, "-p", "hello"]).is_err());
    assert!(parse_llm(&["--content-root", "/content", "-p", "hello"]).is_err());
    assert!(parse_gateway(&["--content", TEST_CONTENT]).is_err());
    assert!(parse_gateway(&["--content-index", "/state/index.bin"]).is_err());
}

#[cfg(feature = "evaluate")]
#[test]
fn local_modes_accept_repeatable_content_and_roots() {
    let cli = Cli::try_parse_from([
        "hellas",
        "llm",
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
        "-p",
        "hello",
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

#[cfg(feature = "llm")]
#[test]
fn llm_retention_defaults_off_and_can_be_enabled() {
    let default = parse_llm(&["-p", "hello"]).unwrap();
    assert!(matches!(
        default.command,
        Commands::Llm { retain: false, .. }
    ));

    let enabled = parse_llm(&["--retain", "-p", "hello"]).unwrap();
    assert!(matches!(
        enabled.command,
        Commands::Llm { retain: true, .. }
    ));
}

#[cfg(feature = "evaluate")]
#[test]
fn llm_rejects_local_with_node_id() {
    let result = parse_llm(&[
        "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
        "--local",
        "-p",
        "hello",
    ]);

    assert!(result.is_err());
}

#[cfg(feature = "evaluate")]
#[test]
fn llm_rejects_conflicting_local_modes() {
    let result = parse_llm(&["--local", "--verify-local", "-p", "hello"]);

    assert!(result.is_err());
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

/// The anchor `hellas gateway <args>` would run with.
#[cfg(feature = "gateway")]
fn gateway_trust(args: &[&str]) -> anyhow::Result<Option<hellas_client::ProviderTrustAnchor>> {
    let cli = parse_gateway(args).expect("valid gateway arguments");
    let Commands::Gateway {
        remote_trust,
        responses_backend,
        #[cfg(feature = "evaluate")]
        local,
        ..
    } = cli.command
    else {
        panic!("expected gateway command");
    };
    #[cfg(not(feature = "evaluate"))]
    let local = false;
    gateway_provider_trust(
        local,
        responses_backend,
        remote_trust.provider_genesis,
        remote_trust.assurance,
        remote_trust.apple_app_attest_app_id,
        remote_trust.apple_app_attest_cdhashes,
    )
}

#[cfg(feature = "gateway")]
#[test]
fn gateway_demands_a_provider_anchor_exactly_where_it_dials_one() {
    const NODE: &str = "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550";
    const SHADOW: &str = "edfadcefb3917925de1111087f11925542c97e14ab00cf42b9447f7567a25b62";
    const PROVIDER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const ENVIRONMENT: &str = "0909090909090909090909090909090909090909090909090909090909090909";

    // Local and proxy-only modes do not dial a Hellas provider.
    #[cfg(feature = "evaluate")]
    assert!(gateway_trust(&["--local"]).unwrap().is_none());
    assert!(
        gateway_trust(&["--responses-backend", "proxy"])
            .unwrap()
            .is_none()
    );

    // Names one: `--provider` is required, and its absence is refused
    // by the flag that would supply it.
    for dialling in [
        vec![],
        vec!["--node-id", NODE],
        vec!["--node-id", NODE, "--verify", SHADOW],
        vec![
            "--responses-backend",
            "fetch",
            "--responses-fetch-execution-environment",
            ENVIRONMENT,
        ],
    ] {
        let refusal = gateway_trust(&dialling).unwrap_err().to_string();
        assert!(refusal.contains("--provider <content-id>"), "{refusal}");
    }

    #[cfg(feature = "evaluate")]
    {
        let refusal = gateway_trust(&["--verify-local"]).unwrap_err().to_string();
        assert!(refusal.contains("--provider <content-id>"), "{refusal}");
    }

    // Named with its pin: the anchor carries the provider it pins.
    let anchor = gateway_trust(&["--node-id", NODE, "--provider", PROVIDER])
        .unwrap()
        .expect("a dialling gateway carries an anchor");
    assert_eq!(
        anchor.expected_genesis,
        hellas_rpc::ContentId::from_bytes([0x11; 32])
    );
    // A discovery gateway given one keeps the routes it always had.
    assert!(gateway_trust(&["--provider", PROVIDER]).unwrap().is_some());
}

#[cfg(feature = "llm")]
#[test]
fn llm_rejects_node_addr_without_node_id() {
    let result = parse_llm(&["--node-addr", "127.0.0.1:31145", "-p", "hello"]);

    assert!(result.is_err());
}

#[cfg(feature = "gateway")]
#[test]
fn gateway_rejects_node_addr_without_node_id() {
    let result = parse_gateway(&["--node-addr", "127.0.0.1:31145"]);

    assert!(result.is_err());
}

#[test]
fn fetch_accepts_payload() {
    let cli = Cli::try_parse_from([
        "hellas",
        "fetch",
        "--service",
        "echo",
        "--method",
        "run",
        "--execution-environment",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "--payload",
        r#"{"x":1}"#,
        "--assurance",
        "apple-app-attest",
    ])
    .unwrap();
    match cli.command {
        Commands::Fetch {
            remote_trust,
            service,
            method,
            payload,
            retain,
            ..
        } => {
            assert_eq!(
                remote_trust.assurance,
                hellas_rpc::Assurance::AppleAppAttest
            );
            assert_eq!(service, "echo");
            assert_eq!(method, "run");
            assert_eq!(payload.as_deref(), Some(r#"{"x":1}"#));
            assert!(!retain);
        }
        _ => panic!("expected fetch command"),
    }
}

#[test]
fn direct_fetch_accepts_builtin_environment_aliases_and_exact_id() {
    for (spelling, expected) in fetch_environment_cases() {
        let cli = Cli::try_parse_from([
            "hellas",
            "fetch",
            "--service",
            "echo",
            "--method",
            "run",
            "--execution-environment",
            spelling,
            "--payload",
            r#"{"x":1}"#,
        ])
        .unwrap();
        let Commands::Fetch {
            execution_environment,
            ..
        } = cli.command
        else {
            panic!("expected fetch command");
        };
        assert_eq!(execution_environment, expected);
    }
}

#[test]
fn fetch_output_signer_is_derived_from_the_pinned_provider() {
    let result = Cli::try_parse_from([
        "hellas",
        "fetch",
        "--service",
        "echo",
        "--method",
        "run",
        "--execution-environment",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "--payload",
        r#"{"x":1}"#,
        "--trusted-producer-public-key",
        "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]);
    assert!(result.is_err());
}

#[test]
fn fetch_accepts_remote_trust_policy() {
    let cli = Cli::try_parse_from(
        [
            "hellas",
            "fetch",
            "--service",
            "echo",
            "--method",
            "run",
            "--execution-environment",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "--payload",
            r#"{"x":1}"#,
        ]
        .into_iter()
        .chain(TEST_REMOTE_TRUST_ARGS.iter().copied()),
    )
    .unwrap();
    let Commands::Fetch { remote_trust, .. } = cli.command else {
        panic!("expected fetch command");
    };
    assert_test_remote_trust(&remote_trust);
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

#[test]
fn fetch_retention_defaults_off_and_can_be_enabled() {
    let base = [
        "hellas",
        "fetch",
        "--service",
        "echo",
        "--method",
        "run",
        "--execution-environment",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "--payload",
        r#"{"x":1}"#,
    ];
    let default = Cli::try_parse_from(base).unwrap();
    assert!(matches!(
        default.command,
        Commands::Fetch { retain: false, .. }
    ));

    let enabled = Cli::try_parse_from(base.into_iter().chain(["--retain"])).unwrap();
    assert!(matches!(
        enabled.command,
        Commands::Fetch { retain: true, .. }
    ));
}

#[test]
fn fetch_rejects_node_addr_without_a_target() {
    let result = Cli::try_parse_from([
        "hellas",
        "fetch",
        "--service",
        "echo",
        "--method",
        "run",
        "--execution-environment",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "--payload",
        r#"{"x":1}"#,
        "--node-addr",
        "127.0.0.1:31145",
    ]);

    let error = result
        .err()
        .expect("node address must be rejected")
        .to_string();
    assert!(error.contains("NODE_ID"), "{error}");
}

#[test]
fn fetch_rejects_missing_payload() {
    let result = Cli::try_parse_from([
        "hellas",
        "fetch",
        "--service",
        "echo",
        "--method",
        "run",
        "--execution-environment",
        "0909090909090909090909090909090909090909090909090909090909090909",
    ]);

    let error = result
        .err()
        .expect("missing payload must be rejected")
        .to_string();
    assert!(error.contains("--payload"), "{error}");
}

#[test]
fn artifact_get_accepts_digest_and_output() {
    let digest = "00".repeat(32);
    let cli = Cli::try_parse_from([
        "hellas",
        "artifact",
        "get",
        "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
        &digest,
        "--output",
        "/tmp/artifact.cbor",
    ])
    .unwrap();
    match cli.command {
        Commands::Artifact {
            command:
                commands::artifact::ArtifactCommand::Get {
                    node_id: _,
                    node_addrs,
                    digest: parsed_digest,
                    output,
                },
        } => {
            assert!(node_addrs.is_empty());
            assert_eq!(parsed_digest, hellas_rpc::Digest::ZERO);
            assert_eq!(output, std::path::Path::new("/tmp/artifact.cbor"));
        }
        _ => panic!("expected artifact get command"),
    }
}

#[cfg(feature = "llm")]
#[test]
fn llm_accepts_explicit_stop_tokens_without_inference() {
    let cli = parse_llm(&[
        "--stop-token",
        "1,2",
        "--stop-token",
        "3",
        "--max-new-tokens",
        "32",
        "-p",
        "hi",
    ])
    .unwrap();
    match cli.command {
        Commands::Llm {
            causal_lm: CausalLmArgs { stop_token_ids, .. },
            max_new_tokens,
            ..
        } => {
            assert_eq!(stop_token_ids, vec![1, 2, 3]);
            assert_eq!(max_new_tokens, 32);
        }
        _ => panic!("expected llm command"),
    }
}

#[cfg(feature = "llm")]
#[test]
fn llm_rejects_an_explicit_zero_output_limit() {
    assert!(parse_llm(&["--max-new-tokens", "0", "-p", "hi"]).is_err());
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

#[cfg(feature = "node")]
#[test]
fn serve_accepts_artifact_store_path() {
    let cli = Cli::try_parse_from([
        "hellas",
        "serve",
        "--artifact-store-path",
        "/tmp/hellas-artifacts",
    ])
    .unwrap();
    match cli.command {
        Commands::Serve {
            artifact_store_path,
            ..
        } => assert_eq!(
            artifact_store_path.as_deref(),
            Some(std::path::Path::new("/tmp/hellas-artifacts"))
        ),
        _ => panic!("expected serve command"),
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
        "--fetch-retained-transcript-capacity",
        "0",
        "--fetch-replay-max-in-flight",
        "2",
        "--fetch-config",
        "/tmp/fetch-config.json",
    ])
    .unwrap();
    match cli.command {
        Commands::Serve {
            fetch_max_in_flight,
            fetch_queue_size,
            fetch_retained_transcript_capacity,
            fetch_replay_max_in_flight,
            fetch_config_file,
            ..
        } => {
            assert_eq!(fetch_max_in_flight, 3);
            assert_eq!(fetch_queue_size, 0);
            assert_eq!(fetch_retained_transcript_capacity, 0);
            assert_eq!(fetch_replay_max_in_flight, 2);
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

#[cfg(feature = "node")]
#[test]
fn serve_uses_bounded_fetch_defaults() {
    let cli = Cli::try_parse_from(["hellas", "serve"]).unwrap();
    let Commands::Serve {
        fetch_retained_transcript_capacity,
        #[cfg(feature = "evaluate")]
        evaluate_retained_execution_capacity,
        fetch_replay_max_in_flight,
        ..
    } = cli.command
    else {
        panic!("expected serve command");
    };
    assert_eq!(
        fetch_retained_transcript_capacity,
        hellas_rpc::DEFAULT_FETCH_RETAINED_TRANSCRIPT_CAPACITY
    );
    #[cfg(feature = "evaluate")]
    assert_eq!(
        evaluate_retained_execution_capacity,
        hellas_executor::DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY
    );
    assert_eq!(
        fetch_replay_max_in_flight,
        hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT
    );
}

#[cfg(all(feature = "node", feature = "evaluate"))]
#[test]
fn serve_accepts_and_defaults_evaluate_retention_capacity() {
    let configured = Cli::try_parse_from([
        "hellas",
        "serve",
        "--evaluate-retained-execution-capacity",
        "0",
    ])
    .unwrap();
    let Commands::Serve {
        evaluate_retained_execution_capacity,
        ..
    } = configured.command
    else {
        panic!("expected serve command");
    };
    assert_eq!(evaluate_retained_execution_capacity, 0);

    let defaulted = Cli::try_parse_from(["hellas", "serve"]).unwrap();
    let Commands::Serve {
        evaluate_retained_execution_capacity,
        ..
    } = defaulted.command
    else {
        panic!("expected serve command");
    };
    assert_eq!(
        evaluate_retained_execution_capacity,
        hellas_executor::DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY
    );
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
