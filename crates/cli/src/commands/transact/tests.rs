use super::*;
use clap::Parser as _;

fn provider() -> String {
    iroh::SecretKey::from_bytes(&[7; 32]).public().to_string()
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
    args.extend_from_slice(extra);
    let crate::Commands::Fetch(args) = crate::Cli::try_parse_from(args).unwrap().command else {
        panic!("Fetch");
    };
    args
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
    assert!(crate::Cli::try_parse_from(["hellas", "run", "--help"]).is_err());
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
    assert_eq!(
        p.addresses,
        vec!["127.0.0.1:1234".parse::<SocketAddr>().unwrap()]
    );
    assert!(fetch_args(&["--faucet"]).client.timeout == Duration::from_secs(300));
}

#[test]
fn helper_and_hand_written_folder_produce_identical_signed_input() {
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
    let raw = Job::load(root.path()).unwrap();
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
        raw.prepare(&key, [9; 32], runner.clone(), &policy)
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
    let result = PaidWorkResult {
        bond_edge: hellas_kernel::EdgeId::from_bytes([1; 32]),
        payment_edge: hellas_kernel::EdgeId::from_bytes([2; 32]),
        channel_id: hellas_auth::Digest::from_bytes([3; 32]),
        transcript: vec![],
        output: hellas_rpc::protocol::invocation::output::InvocationOutput {
            outcome: hellas_rpc::protocol::invocation::output::Outcome::Succeeded,
            artifacts: vec![],
            metadata: hellas_rpc::JsonBytes(vec![]),
        },
        work_id: hellas_auth::Digest::from_bytes([4; 32]),
        credited_cumulative: 20,
        job_price: 20,
        provider_key: ProducerSigningKey::from_secret_bytes([8; 32])
            .unwrap()
            .public_key(),
        input: hellas_rpc::InputCommitment::from_digest(hellas_auth::Digest::from_bytes([5; 32])),
        settled_provider_payout: None,
    };
    let output = wording(&args.client.provider, &job, &result);
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
