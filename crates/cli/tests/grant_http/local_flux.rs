//! Manual HIP comparison with catena-models' Flux2 Klein reference PNG.
use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs HIP, HELLAS_TEST_FLUX_MODEL and HELLAS_TEST_FLUX_REFERENCE_DIR"]
async fn local_grant_flux_matches_reference_image_without_a_chain() {
    use hellas_authority::model::grant::{grant_network, owner_grant_id, records::*};
    use hellas_rpc::protocol::invocation::{Admission, InvocationPolicy, Limits, compute};
    let model = PathBuf::from(std::env::var("HELLAS_TEST_FLUX_MODEL").unwrap());
    let reference = PathBuf::from(std::env::var("HELLAS_TEST_FLUX_REFERENCE_DIR").unwrap());
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
                max_upload_bytes: 8 << 20,
                max_output_bytes: 4 << 20,
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
    definition.max_job_millis = std::num::NonZeroU64::new(1_200_000).unwrap();
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
    // Hash the 14 GB checkpoint before the gateway's ordinary startup check.
    let started = std::time::Instant::now();
    let content = hellas_store::ContentStore::new();
    let _ = content.records().load(&index);
    content.adopt(&model).unwrap();
    content.records().save(&index).unwrap();
    println!("prepared Flux content index in {:?}", started.elapsed());
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
            "--image-model",
            string(&model),
            "--content-root",
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
        "local-flux-gateway.log",
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
    let response = http.post(format!("http://{address}/v1/images/generations"))
        .json(&serde_json::json!({"model":label,"prompt":"a small red fox","seed":42,"size":"512x512","steps":4}))
        .send().await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap();
    println!("image response status={status}, bytes={}", body.len());
    println!("{}", std::fs::read_to_string(&gateway.log).unwrap());
    gateway.stop().await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    use base64::Engine as _;
    use hellas_rpc::provenance::{COMMITMENT_KEY, PROVIDER_KEY, encode_public_key};
    let provider =
        hellas_auth::PublicKey::Secp256k1(grant_producer(&enrollment).unwrap().to_bytes());
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(headers[PROVIDER_KEY], encode_public_key(&provider));
    assert_eq!(value["hellas"]["provider"], encode_public_key(&provider));
    let commitment = value["hellas"]["commitment"].as_str().unwrap();
    assert_eq!(headers[COMMITMENT_KEY], commitment);
    let png = base64::engine::general_purpose::STANDARD
        .decode(value["data"][0]["b64_json"].as_str().unwrap())
        .unwrap();
    let expected_png = std::fs::read(reference.join("noise.png")).unwrap();
    std::fs::write(reference.join("hellas.png"), &png).unwrap();
    assert_eq!(
        hellas_rpc::ContentRef::for_bytes(&png),
        hellas_rpc::ContentRef::for_bytes(&expected_png),
        "Hellas PNG must equal catena-models for the same prompt/seed/steps"
    );
    let transcript = base64::engine::general_purpose::STANDARD
        .decode(value["hellas"]["transcript"].as_str().unwrap())
        .unwrap();
    let envelopes = hellas_channel::model::work::decode_transcript(
        &transcript,
        hellas_channel::work_store::journal::MAX_RECORD_BYTES,
    )
    .unwrap();
    assert!(!envelopes.is_empty());
    use hellas_rpc::protocol::invocation::output::{
        ARTIFACT_CHUNK, ArtifactPrefix, InvocationOutput, Outcome,
    };
    let mut prefix = ArtifactPrefix::default();
    let mut pixels = Vec::new();
    for envelope in &envelopes {
        envelope.verify(&provider).unwrap();
        if envelope.event().body().kind() == ARTIFACT_CHUNK {
            let chunk = prefix.push(envelope).unwrap();
            assert_eq!(chunk.name, "image");
            assert_eq!(chunk.format, "catena.bytes.v1");
            pixels.extend_from_slice(chunk.bytes.as_bytes());
        }
    }
    assert_eq!(pixels.len(), 512 * 512 * 12);
    let output = InvocationOutput {
        outcome: Outcome::Succeeded,
        artifacts: vec![hellas_rpc::protocol::invocation::Artifact::new(
            "image",
            "catena.bytes.v1",
            pixels,
        )],
        metadata: hellas_rpc::JsonBytes(
            hellas_rpc::canonical_dag_cbor(&compute::RunMetadata {
                steps: 0,
                stop: None,
            })
            .unwrap(),
        ),
    };
    let package = hellas_client::model::ModelPackage::open(&model).unwrap();
    let hellas_client::model::ModelResponse::Image(image) = package.decode(&output).unwrap() else {
        panic!()
    };
    assert_eq!(
        image.png(512, 512).unwrap(),
        png,
        "HTTP image must match signed pixels"
    );
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
        .filter_map(|job| job.result().map(|(result, _)| result))
        .chain(book.terminals().filter_map(|terminal| {
            terminal
                .outcome
                .result
                .as_ref()
                .map(|signed| &signed.result)
        }))
        .collect();
    assert_eq!(actual.len(), 1, "one signed three-stage image job");
    assert_eq!(hex::encode(actual[0].work_id.as_bytes()), commitment);
    assert_eq!(
        actual[0].transcript_content,
        hellas_rpc::ContentRef::for_bytes(&transcript)
    );
    assert_eq!(
        actual[0].canonical_output_digest,
        output.content_id().unwrap().digest()
    );
    println!(
        "verified exact Flux PNG and signed pixels: seed42, 512x512, steps4, png={}",
        hellas_rpc::ContentRef::for_bytes(&png).id()
    );
}
