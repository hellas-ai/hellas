//! Manual local-grant smoke on a supported gfx11 HIP GPU. Set the three
//! HELLAS_TEST_WHISPER_* paths to a converted package, the reference WAV,
//! and tokens.json produced by pinned catena-models whisper-asr (en, max 64).
//! Run with `nix develop .#rocm -c cargo test -p hellas-cli --test grant_http local_grant_whisper -- --ignored --nocapture`.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs gfx11 HIP, HELLAS_TEST_WHISPER_MODEL, HELLAS_TEST_WHISPER_WAV and HELLAS_TEST_WHISPER_TOKENS"]
async fn local_grant_whisper_matches_reference_tokens_without_a_chain() {
    use hellas_rpc::protocol::invocation::{Limits, compute};
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
    let mut node = super::local_compute::LocalCompute::start(
        &model,
        "--audio-model",
        &weights,
        Limits {
            max_upload_bytes: 4 << 20,
            max_output_bytes: 1 << 20,
            max_steps: 64,
            execution_timeout_ms: 600_000,
        },
        std::num::NonZeroU64::new(600_000),
        &["--default-max-tokens", "64"],
    )
    .await;
    let http = &node.http;
    let address = &node.address;
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
    let headers = response.headers().clone();
    let body = response.text().await.unwrap();
    println!("status={status} body={body}");
    println!("{}", std::fs::read_to_string(&node.gateway.log).unwrap());
    node.gateway.stop().await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    use base64::Engine as _;
    use hellas_rpc::provenance::{COMMITMENT_KEY, PROVIDER_KEY, encode_public_key};
    let provider = node.provider;
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(headers[PROVIDER_KEY], encode_public_key(&provider));
    assert_eq!(value["hellas"]["provider"], encode_public_key(&provider));
    let commitment = value["hellas"]["commitment"].as_str().unwrap();
    assert_eq!(headers[COMMITMENT_KEY], commitment);
    let transcript = base64::engine::general_purpose::STANDARD
        .decode(value["hellas"]["transcript"].as_str().unwrap())
        .unwrap();
    let envelopes = hellas_channel::model::work::decode_transcript(
        &transcript,
        hellas_channel::work_store::journal::MAX_RECORD_BYTES,
    )
    .unwrap();
    assert!(!envelopes.is_empty());
    for envelope in &envelopes {
        envelope.verify(&provider).unwrap();
    }

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
    assert_eq!(value["text"], expected_text.text);
    // The provider's durable signed result commits the exact padded output,
    // including every token ID. Compare that binding with the upstream tokens;
    // the HTTP presentation need not expose token IDs or internal buffers.
    node.verify_result(commitment, &transcript, &expected).await;
    println!(
        "verified {} reference token IDs via signed output digest and delivered provenance",
        tokens.len()
    );
}
