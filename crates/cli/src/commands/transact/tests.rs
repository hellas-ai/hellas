use super::*;
use clap::Parser as _;
use hellas_private::Durability::Crash;
use hellas_private::StoreLocation;

#[tokio::test]
async fn paid_output_is_flushed_before_a_failed_settlement() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("output");
    let result = deliver_then_settle(
        || {
            let mut writer = std::io::BufWriter::new(std::fs::File::create(&output)?);
            writer.write_all(b"paid result")?;
            writer.flush()?;
            Ok(())
        },
        async {
            assert_eq!(std::fs::read(&output).unwrap(), b"paid result");
            bail!("injected settlement failure")
        },
    )
    .await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("injected settlement failure")
    );
    assert_eq!(std::fs::read(output).unwrap(), b"paid result");
}

#[test]
fn grant_execution_requires_explicit_access_and_refuses_paid_options() {
    let base = ["hellas", "transact", "--job", "job"];
    let grant = ["--offer", "shared.model"];
    let parse = |extra: &[&str]| {
        crate::Cli::try_parse_from(base.iter().chain(grant.iter()).chain(extra.iter()).copied())
    };
    assert!(parse(&[]).is_ok());
    for extra in [
        &["--settle"][..],
        &["--buy-again"],
        &["--validator", "ws://localhost"],
        &["--address", "127.0.0.1:1"],
        &["--acceptance-blocks", "300"],
        &["--terminal-blocks", "3000"],
        &["--payment-blocks", "600"],
    ] {
        assert!(parse(extra).is_err(), "{extra:?}");
    }
    assert!(parse(&["--work-profile", "profile.json"]).is_err());
    let resource = hellas_auth::Digest::hash(b"selected resource").to_string();
    assert!(parse(&["--resource", &resource]).is_ok());
    let provider = provider();
    assert!(parse(&["--provider", &provider]).is_ok());
}

#[tokio::test]
async fn paid_deadline_options_reach_the_signed_job_configuration() {
    let root = tempfile::tempdir().unwrap();
    let identity_path = root.path().join("identity");
    let identity = crate::identity::load_or_create(&identity_path).unwrap();
    let cli = crate::Cli::try_parse_from(["hellas", "--faucet-account", "7", "serve"]).unwrap();
    let owner = cli
        .owner
        .load(&hellas_chain::genesis::ChainProfile::known(
            hellas_chain::genesis::Chain::Devnet,
        ))
        .unwrap()
        .unwrap();
    let location = StoreLocation::for_test(root.path());
    let context = Context::new(
        &identity,
        Some(&owner),
        &location,
        &hellas_chain::genesis::ChainProfile::known(hellas_chain::genesis::Chain::Devnet),
    )
    .unwrap();
    for (extra, expected) in [
        (vec![], (300, 3000, 600)),
        (
            vec![
                "--acceptance-blocks",
                "444",
                "--terminal-blocks",
                "555",
                "--payment-blocks",
                "666",
            ],
            (444, 555, 666),
        ),
    ] {
        let args = fetch_args(&extra).client;
        let location = StoreLocation::for_test(root.path());
        let config = hellas_sdk::work_config::WorkConfig::for_chain(
            hellas_chain::genesis::ChainProfile::known(hellas_chain::genesis::Chain::Devnet),
            &location,
        )
        .unwrap();
        let content = client::content(&context, config.network()).await.unwrap();
        let options = args
            .options_with_config(
                &context,
                20,
                Assurance::ProducerSigned,
                config,
                content.clone(),
            )
            .unwrap();
        assert_eq!(
            (
                options.acceptance_blocks,
                options.terminal_blocks,
                options.payment_blocks
            ),
            expected
        );
        content.close().await;
    }
}

#[test]
fn repurchase_uses_a_new_attempt_and_missing_records_do_not_reexecute() {
    let request = fetch_args(&[]).request().unwrap();
    let job = Job::fetch(
        20,
        hellas_rpc::FetchContract::http().unwrap(),
        "http".into(),
        "request".into(),
        serde_json::to_vec(&request).unwrap(),
        Assurance::ProducerSigned,
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let chain = hellas_chain::chain_dir::ChainDir::open(
        root.path(),
        &hellas_chain::genesis::ChainProfile::known(hellas_chain::genesis::Chain::Devnet),
        Crash,
    )
    .unwrap();
    let passkey = hellas_kernel::SoftPasskey::from_secret_scalar([1; 32]).unwrap();
    let owner = hellas_auth::authority::PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
        passkey.party_key().to_bytes(),
    ))
    .unwrap();
    let legacy = PaidAttemptPath::new(&chain, provider().parse().unwrap(), owner, job.digest());
    let pointer = legacy.as_path().with_extension("latest");
    drop(select_attempt(&legacy, &job, false).unwrap());
    let first = std::fs::read_to_string(&pointer).unwrap();
    drop(select_attempt(&legacy, &job, false).unwrap());
    assert_eq!(std::fs::read_to_string(&pointer).unwrap(), first);
    std::fs::remove_file(&pointer).unwrap();
    assert!(select_attempt(&legacy, &job, false).is_err());
    std::fs::write(&pointer, &first).unwrap();
    drop(select_attempt(&legacy, &job, true).unwrap());
    let second = std::fs::read_to_string(&pointer).unwrap();
    assert_ne!(first, second);
    assert!(
        legacy
            .as_path()
            .parent()
            .unwrap()
            .join(format!("{}.{}.json", job.digest(), first))
            .exists()
    );
    let second_path =
        legacy
            .as_path()
            .parent()
            .unwrap()
            .join(format!("{}.{}.json", job.digest(), second));
    std::fs::remove_file(second_path).unwrap();
    assert!(select_attempt(&legacy, &job, false).is_err());
    assert_eq!(std::fs::read_to_string(&pointer).unwrap(), second);
}

fn node() -> iroh::EndpointId {
    iroh::SecretKey::from_bytes(&[7; 32]).public()
}

fn provider() -> String {
    hellas_sdk::client::ProviderAddress {
        enrollment: hellas_rpc::ContentId::from_bytes([9; 32]),
        node: node(),
    }
    .to_string()
}

fn fetch_args(extra: &[&str]) -> FetchArgs {
    let id = provider();
    let mut args = vec![
        "hellas",
        "fetch",
        "https://example.test/path",
        "--provider",
        &id,
        "--payment",
        "20",
    ];
    if !extra.contains(&"--max-response-bytes") {
        args.extend(["--max-response-bytes", "4096"]);
    }
    if !extra.contains(&"--contract") {
        args.extend(["--contract", "http"]);
    }
    args.extend_from_slice(extra);
    let crate::Commands::Fetch(args) = crate::Cli::try_parse_from(args).unwrap().command else {
        panic!("Fetch");
    };
    args
}

#[test]
fn provider_is_named_only_by_its_enrollment_and_node() {
    let id = provider();
    let p: Provider = id.parse().unwrap();
    assert_eq!(p.address.to_string(), id);
    assert!(p.addresses.is_empty());
    let node = node().to_string();
    for invalid in [node.clone(), format!("{node}@127.0.0.1:1234")] {
        for command in [
            &["hellas", "transact", "--settle", "--provider", &invalid][..],
            &["hellas", "transact", "--job", "job", "--provider", &invalid],
            &[
                "hellas",
                "fetch",
                "https://example.test",
                "--payment",
                "1",
                "--contract",
                "http",
                "--provider",
                &invalid,
            ],
            &[
                "hellas",
                "run",
                "--source",
                "s",
                "--entry",
                "e",
                "--provider",
                &invalid,
            ],
        ] {
            let error = crate::Cli::try_parse_from(command)
                .err()
                .expect("node ID alone");
            assert!(
                error.to_string().contains("ENROLLMENT_ID@NODE_ID"),
                "{command:?}: {error}"
            );
        }
    }
    assert!(format!("{id}@not-an-address").parse::<Provider>().is_err());
}

#[test]
fn command_shapes_require_a_job_or_settlement_and_remove_paid_work() {
    let id = provider();
    assert!(crate::Cli::try_parse_from(["hellas", "transact", "--provider", &id]).is_err());
    assert!(
        crate::Cli::try_parse_from(["hellas", "transact", "--provider", &id, "--settle"]).is_ok()
    );
    assert!(
        crate::Cli::try_parse_from([
            "hellas",
            "transact",
            "--provider",
            &id,
            "--settle",
            "-o",
            "out"
        ])
        .is_err()
    );
    assert!(crate::Cli::try_parse_from(["hellas", "paid-work", "--help"]).is_err());
    for invalid in ["0s", "300", "18446744073709551615m"] {
        assert!(
            crate::Cli::try_parse_from([
                "hellas",
                "transact",
                "--provider",
                &id,
                "--job",
                "job",
                "--timeout",
                invalid
            ])
            .is_err()
        );
    }
    let p: Provider = format!("{id}@127.0.0.1:1234").parse().unwrap();
    assert_eq!(p.address.to_string(), id);
    assert_eq!(
        p.addresses,
        vec!["127.0.0.1:1234".parse::<SocketAddr>().unwrap()]
    );
    assert!(fetch_args(&["--faucet"]).client.timeout.is_none());
}

#[test]
fn fetch_runs_only_under_a_contract_the_buyer_names() {
    let id = provider();
    let error = crate::Cli::try_parse_from([
        "hellas",
        "fetch",
        "https://example.test/path",
        "--provider",
        &id,
        "--payment",
        "20",
    ])
    .err()
    .expect("a Fetch without a named contract");
    assert!(error.to_string().contains("--contract"), "{error}");
    assert_eq!(
        fetch_args(&[]).contract().unwrap(),
        hellas_rpc::FetchContract::http().unwrap()
    );
    let root = tempfile::tempdir().unwrap();
    let http = root.path().join("http.json");
    std::fs::write(
        &http,
        serde_json::to_vec(&hellas_rpc::FetchContract::http().unwrap()).unwrap(),
    )
    .unwrap();
    let http = http.display().to_string();
    assert_eq!(
        fetch_args(&["--contract", &http]).contract().unwrap(),
        hellas_rpc::FetchContract::http().unwrap()
    );
    let responses = root.path().join("responses.json");
    std::fs::write(
        &responses,
        serde_json::to_vec(
            &hellas_rpc::FetchContract::new(
                "openai-responses-0.0.3",
                hellas_rpc::FetchSchema::StatelessResponsesV1,
                "openai-responses-driver-0.0.2",
                hellas_rpc::protocol::fetch_contract::FetchEgress::FixedHttps(
                    "https://api.openai.com/v1/responses".into(),
                ),
            )
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let responses = responses.display().to_string();
    assert!(fetch_args(&["--contract", &responses]).contract().is_err());
    let missing = root.path().join("missing.json").display().to_string();
    assert!(fetch_args(&["--contract", &missing]).contract().is_err());
}

#[tokio::test]
async fn helper_and_hand_written_folder_produce_identical_signed_input() {
    let args = fetch_args(&[]);
    let request = args.request().unwrap();
    let contract = hellas_rpc::FetchContract::http().unwrap();
    let helper = Job::fetch(
        20,
        contract.clone(),
        "http".into(),
        "request".into(),
        serde_json::to_vec(&request).unwrap(),
        Assurance::ProducerSigned,
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    // Deliberately write the public format independently of Job::save.
    std::fs::write(
        root.path().join("contract.json"),
        serde_json::to_vec(&contract).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.path().join("request.json"),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.path().join("job.toml"),
        format!(
            r#"format = "hellas.job.v1"
[application]
evaluator = "{}"
adaptor = "{}"
[payment]
price = 20
[fetch]
contract = "contract.json"
service = "http"
method = "request"
request = "request.json"
assurance = "producer-signed"
"#,
            contract.manifest().application().evaluator(),
            contract.manifest().application().adaptor()
        ),
    )
    .unwrap();
    let raw = Job::load(root.path()).await.unwrap();
    let key = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
    assert_eq!(raw.digest(), helper.digest());
    let runner = ProducerSigningKey::from_secret_bytes([0x22; 32])
        .unwrap()
        .public_key();
    let policy = hellas_rpc::protocol::invocation::InvocationPolicy {
        admissions: vec![hellas_rpc::protocol::invocation::Admission::Fetch {
            admission: hellas_rpc::protocol::invocation::fetch::FetchAdmission {
                contract: contract.clone(),
                route: hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy::open_fetch(
                    false,
                    vec![],
                ),
                limits: hellas_rpc::protocol::invocation::fetch::FetchLimits {
                    max_request_body_bytes: 65536,
                    max_output_events: 64,
                    max_spool_bytes: 65536,
                    max_encoded_result_frame: 65536,
                    max_encoded_prepared_input: 65536,
                },
            },
        }],
        limits: hellas_rpc::protocol::invocation::Limits {
            max_upload_bytes: 65536,
            max_output_bytes: 65536,
            max_steps: 1,
            execution_timeout_ms: 60_000,
        },
    };
    assert_eq!(
        raw.prepare(&key, [9; 32], runner, &policy)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        helper
            .prepare(&key, [9; 32], runner, &policy)
            .unwrap()
            .canonical_bytes()
            .unwrap()
    );
}

#[test]
fn fetch_body_and_headers_are_bounded_and_validated_before_signing() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("body");
    std::fs::write(&file, [0, 255, 4]).unwrap();
    let args = fetch_args(&[
        "-X",
        "POST",
        "-H",
        "Content-Type: application/octet-stream",
        "--data",
        &format!("@{}", file.display()),
    ]);
    assert_eq!(args.request().unwrap().body().unwrap(), [0, 255, 4]);
    assert!(fetch_args(&["-H", "broken"]).request().is_err());
    assert!(fetch_args(&["--data", "literal"]).request().is_err());
    assert!(fetch_args(&["-H", "Host: forbidden"]).request().is_err());
    assert!(
        fetch_args(&["--max-response-bytes", "0"])
            .request()
            .is_err()
    );
}

#[test]
fn output_claims_only_provider_signature_and_job_binding() {
    let args = fetch_args(&[]);
    let job = Job::fetch(
        20,
        hellas_rpc::FetchContract::http().unwrap(),
        "http".into(),
        "request".into(),
        serde_json::to_vec(&args.request().unwrap()).unwrap(),
        Assurance::ProducerSigned,
    )
    .unwrap();
    let result = PaidCompletion {
        bond_edge: hellas_kernel::EdgeId::from_bytes([1; 32]),
        channel_id: hellas_auth::Digest::from_bytes([3; 32]),
        transcript: vec![],
        output: hellas_rpc::protocol::invocation::output::InvocationOutput {
            outcome: hellas_rpc::protocol::invocation::output::Outcome::Succeeded,
            artifacts: vec![],
            metadata: hellas_rpc::JsonBytes(vec![]),
        },
        work_id: hellas_auth::Digest::from_bytes([4; 32]),
        job_price: 20,
        provider_key: ProducerSigningKey::from_secret_bytes([8; 32])
            .unwrap()
            .public_key(),
    };
    let output = wording(args.client.paid_provider().unwrap(), &job, &result);
    assert_eq!(
        output.lines().nth(1),
        Some(
            "Hellas did not re-run this job. The signature shows who answered, not that the answer is right."
        )
    );
    assert!(output.starts_with(&format!(
        "signed by provider {} and matches this job {}",
        provider(),
        job.digest()
    )));
    assert!(output.contains("paid 20 · work "));
    for forbidden in ["verified", "correct"] {
        assert!(!output.to_lowercase().contains(forbidden), "{output}");
    }
}

#[tokio::test]
async fn run_writes_one_call_job_that_transact_loads_unchanged() {
    use hellas_rpc::protocol::invocation::compute::*;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("increment.hex");
    let input = root.path().join("data.bin");
    std::fs::write(&source, b"source bytes").unwrap();
    std::fs::write(&input, [1, 2, 3]).unwrap();
    let (source, input, id) = (
        source.display().to_string(),
        input.display().to_string(),
        provider(),
    );
    let crate::Commands::Run(args) = crate::Cli::try_parse_from([
        "hellas",
        "run",
        "--provider",
        &id,
        "--source",
        &source,
        "--entry",
        "increment",
        "--arg",
        "u64:41",
        "--input",
        &input,
        "--arg",
        "input:data.bin",
        "--returns",
        "u64",
        "--returns",
        "buffer:16",
        "--payment",
        "20",
    ])
    .unwrap()
    .command
    else {
        panic!("run");
    };
    assert!(args.client.timeout.is_none());
    let job = args.job().await.unwrap();
    let folder = root.path().join("job");
    job.save(&folder).await.unwrap();
    let loaded = Job::load(&folder).await.unwrap();
    assert_eq!(loaded.digest(), job.digest());
    let JobInput::Compute {
        plan,
        inputs,
        environment,
        ..
    } = loaded.input()
    else {
        panic!("compute job");
    };
    assert_eq!(environment.sources.len(), 1);
    assert_eq!(inputs[0].name, "data.bin");
    let slots = ["output-0000", "output-0001"];
    assert_eq!(
        plan,
        &Plan {
            calls: vec![Call {
                entry: "increment".into(),
                args: vec![
                    Arg::U64(41),
                    Arg::Input {
                        object: "data.bin".into()
                    }
                ],
                bind: slots.iter().map(|s| Bind::Name((*s).into())).collect(),
            }],
            step: None,
            outputs: vec![
                Declared {
                    slot: slots[0].into(),
                    kind: OutputKind::Scalar(ValueKind::U64)
                },
                Declared {
                    slot: slots[1].into(),
                    kind: OutputKind::Buffer { max_bytes: 16 }
                },
            ],
        }
    );
}

#[test]
fn execution_helpers_choose_payment_or_an_imported_offer() {
    let provider = provider();
    for helper in [
        vec!["run", "--source", "program.hex", "--entry", "main"],
        vec!["image", "--model", "model", "--prompt", "fox"],
        vec!["transcribe", "--model", "model", "--audio", "speech.wav"],
    ] {
        let mut base = vec!["hellas"];
        base.extend(helper);
        let parse = |flags: &[&str]| {
            crate::Cli::try_parse_from(base.iter().copied().chain(flags.iter().copied()))
        };
        assert!(parse(&[]).is_err());
        assert!(parse(&["--payment", "20"]).is_err());
        assert!(parse(&["--payment", "20", "--provider", &provider]).is_ok());
        assert!(parse(&["--payment", "0", "--provider", &provider]).is_err());
        assert!(parse(&["--offer", "box.model"]).is_ok());
        assert!(parse(&["--offer", "box.model", "--provider", &provider]).is_ok());
        assert!(parse(&["--payment", "20", "--offer", "box.model"]).is_err());
        assert!(parse(&["--offer", "box.model", "--buy-again"]).is_err());
    }
}

#[test]
fn paid_commands_require_a_provider_before_opening_chain_state() {
    for args in [
        vec!["hellas", "transact", "--job", "job"],
        vec!["hellas", "transact", "--settle"],
        vec![
            "hellas",
            "fetch",
            "https://example.test",
            "--contract",
            "http",
            "--payment",
            "20",
        ],
    ] {
        let error = crate::Cli::try_parse_from(args)
            .err()
            .expect("missing paid provider");
        assert!(error.to_string().contains("--provider"), "{error}");
    }
}
