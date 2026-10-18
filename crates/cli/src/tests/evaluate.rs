//! CLI argument relationships for the optional evaluator.
use super::*;
use clap::error::ErrorKind;

fn refused(result: Result<Cli, clap::Error>, kind: ErrorKind) {
    let error = result.err().expect("arguments must be refused");
    assert_eq!(error.kind(), kind, "{error}");
}

#[test]
fn local_content_flags_are_scoped_to_local_modes() {
    refused(
        parse_gateway(&["--local-grant", "07070707070707070707070707070707"]),
        ErrorKind::MissingRequiredArgument,
    );
    refused(
        parse_gateway(&["--content", TEST_CONTENT]),
        ErrorKind::MissingRequiredArgument,
    );
    refused(
        parse_gateway(&["--content-index", "/state/index.bin"]),
        ErrorKind::MissingRequiredArgument,
    );
}

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
        "--local-grant",
        "07070707070707070707070707070707",
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
    let Commands::Gateway {
        evaluation: args, ..
    } = cli.command
    else {
        panic!("expected gateway");
    };
    assert_eq!(
        args.content_paths,
        ["/content/program.hex", "/content/weights.bin"].map(PathBuf::from)
    );
    assert_eq!(args.content_roots, vec![PathBuf::from("/content/cache")]);
    assert_eq!(args.content_index, Some(PathBuf::from("/state/index.bin")));
}

#[test]
fn gateway_local_mode_uses_explicit_content() {
    let cli = parse_gateway(&["--local"]).unwrap();
    match cli.command {
        Commands::Gateway {
            node_id,
            node_addrs,
            evaluation,
            ..
        } => {
            assert!(node_id.is_none());
            assert!(node_addrs.is_empty());
            assert!(evaluation.local);
            assert_eq!(evaluation.content_paths, vec![PathBuf::from(TEST_CONTENT)]);
        }
        _ => panic!("expected gateway command"),
    }
}

#[test]
fn local_backend_override_still_requires_an_environment() {
    refused(
        Cli::try_parse_from([
            "hellas",
            "gateway",
            "--local",
            "--local-grant",
            "07070707070707070707070707070707",
            "--content",
            TEST_CONTENT,
            "--responses-backend",
            "proxy",
        ]),
        ErrorKind::MissingRequiredArgument,
    );
}

#[test]
fn local_route_requires_explicit_content() {
    refused(
        Cli::try_parse_from([
            "hellas",
            "gateway",
            "--environment",
            TEST_ENVIRONMENT,
            "--tokenizer",
            TEST_TOKENIZER,
            "--local",
            "--local-grant",
            "07070707070707070707070707070707",
        ]),
        ErrorKind::MissingRequiredArgument,
    );
}

#[test]
fn local_route_requires_an_existing_allowance() {
    refused(
        Cli::try_parse_from([
            "hellas",
            "gateway",
            "--environment",
            TEST_ENVIRONMENT,
            "--tokenizer",
            TEST_TOKENIZER,
            "--local",
            "--content",
            TEST_CONTENT,
        ]),
        ErrorKind::MissingRequiredArgument,
    );
}

#[test]
fn gateway_rejects_local_with_another_work_source() {
    for target in [
        [
            "--node-id",
            "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
        ],
        ["--offer", "friend"],
        ["--paid-work-config", "/pool.json"],
    ] {
        refused(
            parse_gateway(&["--local", target[0], target[1]]),
            ErrorKind::ArgumentConflict,
        );
    }
}

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
        Commands::Serve { evaluation, .. } => {
            assert_eq!(evaluation.gpu_backend, hellas_executor::GpuBackend::Cuda);
            assert_eq!(evaluation.gpu_session_programs, 3);
            assert_eq!(evaluation.gpu_session_asset_bytes, 5);
            assert_eq!(evaluation.gpu_max_generation_capacity, 7);
            assert_eq!(evaluation.gpu_max_generation_device_bytes, 11);
            assert_eq!(evaluation.gpu_compile_timeout_secs, 13);
            assert_eq!(evaluation.gpu_execution_timeout_secs, 17);
        }
        _ => panic!("expected serve command"),
    }
}

#[test]
fn serve_rejects_a_generation_capacity_above_the_transport_bound() {
    let over_limit = (hellas_executor::MAX_GPU_GENERATION_CAPACITY + 1).to_string();
    refused(
        Cli::try_parse_from([
            "hellas",
            "serve",
            "--gpu-max-generation-capacity",
            &over_limit,
        ]),
        ErrorKind::ValueValidation,
    );
}
