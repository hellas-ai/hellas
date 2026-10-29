//! Manual Strix check: `gateway --local-grant` serves a real Qwen3 GGUF from
//! this machine's own allowance, with no chain and no remote provider.
//!
//! ```sh
//! nix develop .#rocm -c env HELLAS_TEST_TEXT_MODEL=/path/Qwen3-0.6B-BF16.gguf \
//!   HELLAS_TEST_CONTENT_INDEX=/path/content-index.bin cargo test -p hellas-cli --test grant_http local_text -- --ignored --nocapture
//! ```
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a HIP device and HELLAS_TEST_TEXT_MODEL; run manually on Strix"]
async fn local_grant_serves_a_text_model_without_a_chain() {
    use hellas_authority::model::grant::{grant_network, owner_grant_id, records::*};
    use hellas_rpc::protocol::invocation::{Admission, InvocationPolicy, Limits, compute};
    let model =
        PathBuf::from(std::env::var("HELLAS_TEST_TEXT_MODEL").expect("HELLAS_TEST_TEXT_MODEL"));
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    hellas_private::restrict_directory(root).unwrap();
    let owner = Cli::new(root, "owner", AGENT_PASSKEY);
    owner.run(&["--software-root", "identity", "init"]).await;
    let export = owner.output(&["identity", "export-enrollment"]).await;
    assert!(export.status.success());
    let enrollment = decode_enrollment(&export.stdout).unwrap();
    let principal = owner.principal();
    let journal = root
        .join("grants")
        .join(format!("p256-{}", hex::encode(principal.as_bytes())))
        .join("provider");
    let now = hellas_auth::authority::UnixMillis::now().unwrap_or_default();
    let (store, secret) = common_node::bootstrap_node_with_credential(
        &journal,
        grant_network(),
        Some(enrollment.clone()),
        now,
    )
    .await
    .unwrap();
    let policy = GrantPolicy {
        name: "local".into(),
        invocation_policy: InvocationPolicy {
            admissions: vec![Admission::Compute {
                evaluator: compute::EVALUATOR.into(),
            }],
            limits: Limits {
                max_upload_bytes: 64 << 20,
                max_output_bytes: 1 << 20,
                max_steps: 256,
                execution_timeout_ms: 600_000,
            },
        },
        https: None,
        responses: None,
        ..hellas_authority::test_support::policy()
    };
    let allowance = owner_grant_id(grant_network(), enrollment.content_id(), principal);
    // Read this fixture identity's node key to provision its own service.
    let identity_bytes = std::fs::read(&owner.identity).unwrap();
    let mut decoder = hellas_rpc::DagCborDecoder::new(&identity_bytes);
    decoder.array(6, "identity").unwrap();
    decoder
        .tag("hellas.provider.identity.persistence.v3")
        .unwrap();
    assert_eq!(decoder.u64("version").unwrap(), 3);
    decoder.array(2, "root").unwrap();
    assert_eq!(decoder.u64("root kind").unwrap(), 0);
    let _: [u8; 32] = decoder.fixed_bytes("root key").unwrap();
    let signer = hellas_auth::ProducerSigningKey::from_secret_bytes(
        decoder.fixed_bytes("node key").unwrap(),
    )
    .unwrap();
    let store = common_node::provision(
        &journal,
        store,
        &secret,
        signer,
        (1, vec![]),
        common_node::allowance(allowance, principal, vec![policy]),
        (vec![], 256),
    )
    .await;
    let node = hellas_authority::node::NodeCoordinator::new(
        store,
        Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
    );
    let credential =
        execution_credential(&node, &secret, principal, allowance, owner.holder().await).await;
    let authority = hellas_authority::test_support::session(&node, &secret)
        .await
        .authority();
    let work_profile = work_profile(root, authority, &credential);
    drop(node);
    let (gateway_profile, gateway_token) = gateway_profile(root).await;
    let trust_root = approve(root, "local", enrollment.content_id());
    // Hashing a multi-GB GGUF outlasts the startup wait; keep the index across runs.
    let index = std::env::var("HELLAS_TEST_CONTENT_INDEX")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("content-index.bin"));
    let mut gateway = owner.spawn(
        &[
            "gateway",
            "--trust-store",
            string(&trust_root),
            "--trust-policy",
            "local",
            "--local-grant",
            &hex::encode(allowance.0),
            "--work-profile",
            string(&work_profile),
            "--text-model",
            string(&model),
            "--content",
            string(&model),
            "--content-index",
            string(&index),
            "--gpu-backend",
            "hip",
            "--port",
            "0",
            "--gateway-profile",
            string(&gateway_profile),
            "--archive-dir",
            string(&root.join("archive")),
            "--zdr",
        ],
        "local-text-gateway.log",
    );
    let address = gateway.wait_for("gateway listening on ").await;
    // Compiling the model and loading its weights takes far longer than the
    // shared fixture client's 10 s.
    let http = reqwest::Client::builder()
        .default_headers(
            [(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {gateway_token}")).unwrap(),
            )]
            .into_iter()
            .collect(),
        )
        .build()
        .unwrap();
    let url = format!("http://{address}/v1/completions");
    let label = model.file_stem().unwrap().to_string_lossy().into_owned();
    for max_tokens in [1, 2, 8, 60, 256] {
        let response = post(
            &http,
            &url,
            json!({"model": label, "prompt": "The capital of France is", "max_tokens": max_tokens}),
        )
        .await;
        let status = response.status();
        let body = response.text().await.unwrap();
        println!("max_tokens={max_tokens} status={status} body={body}");
        if !status.is_success() {
            println!("{}", std::fs::read_to_string(&gateway.log).unwrap());
        }
        assert_eq!(status, reqwest::StatusCode::OK, "{body}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let completion_tokens = body["usage"]["completion_tokens"].as_u64().unwrap();
        assert!((1..=max_tokens).contains(&completion_tokens), "{body}");
        match body["choices"][0]["finish_reason"].as_str().unwrap() {
            "length" => assert_eq!(completion_tokens, max_tokens, "{body}"),
            "stop" => {}
            reason => panic!("unexpected finish reason {reason}: {body}"),
        }
    }
    gateway.stop().await;
}
