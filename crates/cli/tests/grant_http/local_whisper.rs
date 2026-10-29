//! Manual local-grant smoke on a supported gfx11 HIP GPU. Set the three
//! HELLAS_TEST_WHISPER_* paths to a converted package, the reference WAV,
//! and tokens.json produced by pinned catena-models whisper-asr (en, max 64).
//! Run with `nix develop .#rocm -c cargo test -p hellas-cli --test grant_http local_grant_whisper -- --ignored --nocapture`.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs gfx11 HIP, HELLAS_TEST_WHISPER_MODEL, HELLAS_TEST_WHISPER_WAV and HELLAS_TEST_WHISPER_TOKENS"]
async fn local_grant_whisper_matches_reference_tokens_without_a_chain() {
    use hellas_authority::model::grant::{grant_network, owner_grant_id, records::*};
    use hellas_rpc::protocol::invocation::{Admission, InvocationPolicy, Limits, compute};
    let model = PathBuf::from(
        std::env::var("HELLAS_TEST_WHISPER_MODEL").expect("HELLAS_TEST_WHISPER_MODEL"),
    );
    let wav =
        PathBuf::from(std::env::var("HELLAS_TEST_WHISPER_WAV").expect("HELLAS_TEST_WHISPER_WAV"));
    let tokens: Vec<u64> = serde_json::from_slice(
        &std::fs::read(
            std::env::var("HELLAS_TEST_WHISPER_TOKENS").expect("HELLAS_TEST_WHISPER_TOKENS"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        tokens.len() < 64,
        "reference must finish before the token budget"
    );
    let weights = model.join("weights.bf16");
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
                max_upload_bytes: 4 << 20,
                max_output_bytes: 1 << 20,
                max_steps: 64,
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
    let client = hellas_authority::model::grant::ChannelClient {
        principal,
        node: hellas_auth::authority::NodeKey::from_public_key(signer.public_key()).unwrap(),
    };
    let mut definition = common_node::allowance(allowance, principal, vec![policy]);
    // This owner's smoke allowance includes cold compilation and native loading.
    definition.max_job_millis = std::num::NonZeroU64::new(600_000).unwrap();
    let store = common_node::provision(
        &journal,
        store,
        &secret,
        signer,
        (1, vec![]),
        definition,
        (vec![], 256),
    )
    .await;
    let generation = store.state().generation(allowance).unwrap();
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
    // Keep the ordinary weight asset index across manual GPU runs.
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
            "--audio-model",
            string(&model),
            "--content",
            string(&weights),
            "--content-index",
            string(&index),
            "--gpu-backend",
            "hip",
            "--default-max-tokens",
            "64",
            "--port",
            "0",
            "--gateway-profile",
            string(&gateway_profile),
            "--archive-dir",
            string(&root.join("archive")),
            "--zdr",
        ],
        "local-whisper-gateway.log",
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
    let label = model.file_name().unwrap().to_string_lossy();
    let mut body = format!("--whisper-test\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{label}\r\n--whisper-test\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\nen\r\n--whisper-test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"jfk.wav\"\r\nContent-Type: audio/wav\r\n\r\n").into_bytes();
    body.extend(std::fs::read(&wav).unwrap());
    body.extend(b"\r\n--whisper-test--\r\n");
    let response = http
        .post(format!("http://{address}/v1/audio/transcriptions"))
        .header("content-type", "multipart/form-data; boundary=whisper-test")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    println!("status={status} body={body}");
    println!("{}", std::fs::read_to_string(&gateway.log).unwrap());
    gateway.stop().await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");

    let config: Value =
        serde_json::from_slice(&std::fs::read(model.join("config.json")).unwrap()).unwrap();
    let generation_config: Value =
        serde_json::from_slice(&std::fs::read(model.join("generation_config.json")).unwrap())
            .unwrap();
    let mut words = vec![0u64; config["max_target_positions"].as_u64().unwrap() as usize - 1];
    words[0] = tokens.len() as u64;
    words[1] = generation_config["lang_to_id"]["<|en|>"].as_u64().unwrap();
    words[2] = 1;
    words[3..3 + tokens.len()].copy_from_slice(&tokens);
    let expected = hellas_rpc::protocol::invocation::output::InvocationOutput {
        outcome: hellas_rpc::protocol::invocation::output::Outcome::Succeeded,
        artifacts: vec![hellas_rpc::protocol::invocation::Artifact::new(
            "transcription",
            "catena.bytes.v1",
            words.into_iter().flat_map(u64::to_le_bytes).collect(),
        )],
        metadata: hellas_rpc::JsonBytes(
            hellas_rpc::canonical_dag_cbor(&compute::RunMetadata {
                steps: 0,
                stop: None,
            })
            .unwrap(),
        ),
    };
    let hellas_client::model::ModelResponse::Transcription(expected_text) =
        hellas_client::model::ModelPackage::open(&model)
            .unwrap()
            .decode(&expected)
            .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["text"],
        expected_text.text
    );
    // The provider's durable signed result commits the exact padded output,
    // including every token ID. Compare that binding with the upstream tokens;
    // the HTTP presentation need not expose token IDs or internal buffers.
    let store = hellas_authority::work_store::grant::NodeStore::open(
        &journal,
        grant_network(),
        Some(enrollment.clone()),
        hellas_auth::authority::UnixMillis::now().unwrap(),
    )
    .await
    .unwrap();
    let channel_id = hellas_authority::model::grant::grant_channel_id(
        grant_network(),
        enrollment.content_id(),
        allowance,
        client,
        generation,
    );
    let book = store.state().channel(channel_id).unwrap().job_book();
    let actual: Vec<_> = book
        .jobs()
        .filter_map(|job| {
            job.result()
                .map(|(result, _)| result.canonical_output_digest)
        })
        .chain(book.terminals().filter_map(|terminal| {
            terminal
                .outcome
                .result
                .as_ref()
                .map(|signed| signed.result.canonical_output_digest)
        }))
        .collect();
    assert_eq!(
        actual,
        [expected.content_id().unwrap().digest()],
        "signed output must contain exactly the upstream token IDs"
    );
    println!(
        "verified {} reference token IDs via signed output digest",
        tokens.len()
    );
}
