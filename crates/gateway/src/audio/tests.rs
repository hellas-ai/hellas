use super::*;
use crate::{ComputeEvent, WorkEvent};
use crate::{WorkExecutionBackend, WorkGatewayError, WorkOutputStream, WorkShutdownError};
use axum::body::Body;
use hellas_rpc::{
    JsonBytes,
    protocol::invocation::{
        Artifact,
        compute::RunMetadata,
        output::{ArtifactChunk, InvocationOutput, Outcome},
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

#[derive(Default)]
struct Fake {
    calls: AtomicUsize,
    delay: Option<std::time::Duration>,
    started: tokio::sync::Notify,
    provenance: Option<(hellas_rpc::provenance::ExecutionProvenance, Vec<u8>)>,
    invalid_output: Option<Outcome>,
}
impl WorkExecutionBackend for Fake {
    fn backends(&self) -> Vec<crate::BackendInfo> {
        crate::test_support::backend({
            Some(hellas_client::model::evaluator(
                hellas_client::model::GpuDialect::Hip,
            ))
        })
    }
    fn run(
        &self,
        _backend: &str,
        _request_job: Arc<crate::jobs::Job>,
        job: hellas_client::model::ComputeJob,
    ) -> Result<WorkOutputStream<ComputeEvent>, WorkGatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        assert_eq!(job.plan.calls[0].entry, "whisper.transcribe");
        assert!(job.plan.step.is_none());
        assert_eq!(
            job.inputs
                .iter()
                .find(|a| a.name == "features")
                .unwrap()
                .bytes
                .as_bytes()
                .len(),
            960000
        );
        let artifact = Artifact::new(
            "transcription",
            "catena.bytes.v1",
            [2u64, 5, 1, 0, 1, 0, 0]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect(),
        );
        let chunk = ArtifactChunk {
            name: artifact.name.clone(),
            format: artifact.format.clone(),
            offset: 0,
            bytes: artifact.bytes.clone(),
        };
        let mut output = InvocationOutput {
            outcome: Outcome::Succeeded,
            artifacts: vec![artifact],
            metadata: JsonBytes(
                hellas_rpc::canonical_dag_cbor(&RunMetadata {
                    steps: 0,
                    stop: None,
                })
                .unwrap(),
            ),
        };
        if let Some(outcome) = self.invalid_output {
            output.outcome = outcome;
            output.artifacts.clear();
        }
        let events = [
            ComputeEvent::Output(chunk),
            ComputeEvent::Done {
                output,
                provider: hellas_auth::ProducerSigningKey::from_secret_bytes([9; 32])
                    .unwrap()
                    .public_key(),
            },
        ];
        let delay = self.delay;
        let provenance = self.provenance.clone();
        Ok(Box::pin(async_stream::stream! {
            for source in &job.environment.sources {
                let reader = job.content.0.open_verified(&job.content.1, *source, None).await.unwrap().unwrap();
                let bytes = reader.read_all(*source, &job.content.0.ram_pool()).await.unwrap();
                assert!(!bytes.is_empty());
            }
            if let Some((accepted, _)) = &provenance {
                yield Ok(WorkEvent::Accepted(accepted.clone()));
            }
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            for event in events {
                if matches!(event, ComputeEvent::Done { .. }) && let Some((_, transcript)) = &provenance {
                    yield Ok(WorkEvent::Transcript(transcript.clone()));
                }
                yield Ok(WorkEvent::Output(event));
            }
        }))
    }
    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}
fn options(name: &str) -> crate::Route {
    crate::test_support::route(crate::Presentation::Model {
        model: name.into(),
        package: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../client/src/model/whisper/mini"),
        max_tokens: 4,
    })
}
async fn app(names: &[&str], work: Arc<Fake>) -> Router {
    crate::router::router(
        names.iter().map(|n| options(n)).collect(),
        work,
        Arc::new(crate::jobs::Jobs::default()),
    )
    .await
    .unwrap()
    .layer(crate::provenance_layer::ProvenanceLayer)
}
fn wav(rate: u32, frames: usize) -> Vec<u8> {
    let bytes = frames as u32 * 2;
    let mut result = Vec::new();
    result.extend(b"RIFF");
    result.extend((36 + bytes).to_le_bytes());
    result.extend(b"WAVEfmt ");
    result.extend(16u32.to_le_bytes());
    result.extend(1u16.to_le_bytes());
    result.extend(1u16.to_le_bytes());
    result.extend(rate.to_le_bytes());
    result.extend((rate * 2).to_le_bytes());
    result.extend(2u16.to_le_bytes());
    result.extend(16u16.to_le_bytes());
    result.extend(b"data");
    result.extend(bytes.to_le_bytes());
    result.resize(44 + bytes as usize, 0);
    result
}
fn request(fields: &[(&str, &[u8])]) -> Request {
    let mut body = Vec::new();
    for (name, data) in fields {
        body.extend(
            format!("--audio-boundary\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend(b"\r\n");
    }
    body.extend(b"--audio-boundary--\r\n");
    Request::post(PATH)
        .header(
            "content-type",
            "multipart/form-data; boundary=audio-boundary",
        )
        .body(Body::from(body))
        .unwrap()
}
#[tokio::test]
async fn transcriptions_carry_provenance_through_archive_in_both_formats() {
    use base64::Engine as _;
    use hellas_rpc::provenance::{
        COMMITMENT_KEY, ExecutionProvenance, PROVIDER_KEY, TRANSCRIPT_KEY, encode_public_key,
    };
    use http_body_util::BodyExt as _;
    let accepted = ExecutionProvenance {
        commitment_id: [0xab; 32],
        provider: hellas_auth::ProducerSigningKey::from_secret_bytes([9; 32])
            .unwrap()
            .public_key(),
    };
    let transcript = b"exact canonical signed bytes".to_vec();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&transcript);
    let fake = Arc::new(Fake {
        provenance: Some((accepted.clone(), transcript)),
        ..Default::default()
    });
    let base = app(&["tiny"], fake.clone()).await;
    let root = tempfile::tempdir().unwrap();
    for zdr in [false, true] {
        let policy = crate::archive::Policy::new(crate::ArchiveOptions {
            directory: root.path().join(if zdr { "zdr" } else { "retaining" }),
            zdr,
        });
        policy.prepare();
        let app = base.clone().layer(axum::middleware::from_fn_with_state(
            policy,
            crate::archive::record,
        ));
        for format in ["json", "text"] {
            let response = app
                .clone()
                .oneshot(request(&[
                    ("model", b"tiny"),
                    ("file", &wav(16000, 160)),
                    ("language", b"en"),
                    ("response_format", format.as_bytes()),
                ]))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[COMMITMENT_KEY], "ab".repeat(32));
            assert_eq!(
                response.headers()[PROVIDER_KEY],
                encode_public_key(&accepted.provider)
            );
            if format == "text" {
                assert_eq!(response.headers()["trailer"], TRANSCRIPT_KEY);
            }
            let collected = response.into_body().collect().await.unwrap();
            if format == "text" {
                assert_eq!(collected.trailers().unwrap()[TRANSCRIPT_KEY], encoded);
                assert_eq!(&collected.to_bytes()[..], b"hi there");
            } else {
                let value: serde_json::Value =
                    serde_json::from_slice(&collected.to_bytes()).unwrap();
                assert_eq!(
                    value,
                    serde_json::json!({"text": "hi there", "hellas": {
                        "commitment": "ab".repeat(32), "provider": encode_public_key(&accepted.provider), "transcript": encoded,
                    }})
                );
            }
        }
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn completed_transcription_errors_preserve_the_verified_transcript() {
    use base64::Engine as _;
    use hellas_rpc::provenance::{COMMITMENT_KEY, ExecutionProvenance};
    for outcome in [
        Outcome::Succeeded,
        Outcome::Failed(hellas_rpc::protocol::invocation::output::FailureReason::Execution),
    ] {
        let fake = Arc::new(Fake {
            invalid_output: Some(outcome),
            provenance: Some((
                ExecutionProvenance {
                    commitment_id: [0xab; 32],
                    provider: hellas_auth::ProducerSigningKey::from_secret_bytes([9; 32])
                        .unwrap()
                        .public_key(),
                },
                b"verified transcript".to_vec(),
            )),
            ..Default::default()
        });
        let app = app(&["tiny"], fake).await;
        for format in ["json", "text"] {
            let response = app
                .clone()
                .oneshot(request(&[
                    ("model", b"tiny"),
                    ("file", &wav(16000, 160)),
                    ("response_format", format.as_bytes()),
                ]))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(response.headers()[COMMITMENT_KEY], "ab".repeat(32));
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(value["error"]["message"].is_string());
            assert_eq!(
                value["hellas"]["transcript"],
                base64::engine::general_purpose::STANDARD.encode(b"verified transcript")
            );
        }
    }
}

#[tokio::test]
async fn shared_audio_path_uses_multipart_model_and_its_own_body_limit() {
    let fake = Arc::new(Fake::default());
    let base = app(&["tiny", "second"], fake.clone()).await;
    let root = tempfile::tempdir().unwrap();
    for zdr in [false, true] {
        let policy = crate::archive::Policy::new(crate::ArchiveOptions {
            directory: root.path().join(if zdr { "zdr" } else { "retaining" }),
            zdr,
        });
        policy.prepare();
        let app = base.clone().layer(axum::middleware::from_fn_with_state(
            policy,
            crate::archive::record,
        ));
        // Valid 30s mono 48kHz WAV exceeds axum's ordinary 2 MiB limit.
        let large = wav(48000, 48000 * 30);
        let response = app
            .clone()
            .oneshot(request(&[("file", &large), ("model", b"second")]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(request(&[("file", &large), ("model", b"missing")]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = app
            .clone()
            .oneshot(request(&[("model", b"tiny"), ("model", b"second")]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            !response
                .headers()
                .contains_key(hellas_rpc::provenance::COMMITMENT_KEY)
        );
        assert!(
            !response
                .headers()
                .contains_key(hellas_rpc::provenance::PROVIDER_KEY)
        );
        let ordinary = Request::post("/v1/completions")
            .body(Body::from(vec![0; 3 << 20]))
            .unwrap();
        assert_eq!(
            app.oneshot(ordinary).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn malformed_audio_and_unsupported_options_never_reach_work() {
    let fake = Arc::new(Fake::default());
    let app = app(&["tiny"], fake.clone()).await;
    let wav = wav(16000, 400);
    for fields in [
        vec![("model", &b"tiny"[..]), ("file", &b"not wav"[..])],
        vec![
            ("model", &b"tiny"[..]),
            ("file", &wav[..]),
            ("language", &b"xx"[..]),
        ],
    ] {
        let response = app.clone().oneshot(request(&fields)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let response = app
        .oneshot(request(&[
            ("model", b"tiny"),
            ("file", &vec![0; MAX_REQUEST_BYTES]),
        ]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_family_and_capacity_are_startup_errors() {
    let mut route = options("tiny");
    let crate::Presentation::Model { max_tokens, .. } = &mut route.presentation else {
        unreachable!()
    };
    *max_tokens = 5;
    assert!(
        crate::router::router(
            vec![route],
            Arc::new(Fake::default()),
            Arc::new(crate::jobs::Jobs::default())
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn zdr_accepts_large_valid_multipart_wav() {
    let fake = Arc::new(Fake::default());
    let base = app(&["tiny"], fake.clone()).await;
    let root = tempfile::tempdir().unwrap();
    let policy = crate::archive::Policy::new(crate::ArchiveOptions {
        directory: root.path().into(),
        zdr: true,
    });
    policy.prepare();
    let app = base.layer(axum::middleware::from_fn_with_state(
        policy,
        crate::archive::record,
    ));
    // Six seconds of stereo 32-bit PCM at 192 kHz is valid and exceeds 8 MiB.
    let frames = 192_000u32 * 6;
    let bytes = frames * 8;
    let mut wav = Vec::new();
    wav.extend(b"RIFF");
    wav.extend((36 + bytes).to_le_bytes());
    wav.extend(b"WAVEfmt ");
    wav.extend(16u32.to_le_bytes());
    wav.extend(1u16.to_le_bytes());
    wav.extend(2u16.to_le_bytes());
    wav.extend(192_000u32.to_le_bytes());
    wav.extend((192_000u32 * 8).to_le_bytes());
    wav.extend(8u16.to_le_bytes());
    wav.extend(32u16.to_le_bytes());
    wav.extend(b"data");
    wav.extend(bytes.to_le_bytes());
    wav.resize(44 + bytes as usize, 0);
    assert!(wav.len() > 8 * 1024 * 1024);
    let response = app
        .oneshot(request(&[("file", &wav), ("model", b"tiny")]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}
