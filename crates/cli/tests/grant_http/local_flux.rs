//! Manual HIP comparison with catena-models' Flux2 Klein reference PNG.
use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs HIP, HELLAS_TEST_FLUX_MODEL and HELLAS_TEST_FLUX_REFERENCE_DIR"]
async fn local_grant_flux_matches_reference_image_without_a_chain() {
    use hellas_rpc::protocol::invocation::{Limits, compute};
    let model = PathBuf::from(std::env::var("HELLAS_TEST_FLUX_MODEL").unwrap());
    let reference = PathBuf::from(std::env::var("HELLAS_TEST_FLUX_REFERENCE_DIR").unwrap());
    let mut node = super::local_compute::LocalCompute::start(
        &model,
        "--image-model",
        &model,
        Limits {
            max_upload_bytes: 8 << 20,
            max_output_bytes: 4 << 20,
            max_steps: 64,
            execution_timeout_ms: 600_000,
        },
        std::num::NonZeroU64::new(1_200_000),
        &[],
    )
    .await;
    let http = &node.http;
    let address = &node.address;
    let label = model.file_name().unwrap().to_string_lossy();
    let response = http.post(format!("http://{address}/v1/images/generations"))
        .json(&serde_json::json!({"model":label,"prompt":"a small red fox","seed":42,"size":"512x512","steps":4}))
        .send().await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap();
    println!("image response status={status}, bytes={}", body.len());
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
    let envelopes = hellas_channel::model::work::decode_transcript(&transcript, 8 << 20).unwrap();
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
    node.verify_result(commitment, &transcript, &output).await;
    println!(
        "verified exact Flux PNG and signed pixels: seed42, 512x512, steps4, png={}",
        hellas_rpc::ContentRef::for_bytes(&png).id()
    );
}
