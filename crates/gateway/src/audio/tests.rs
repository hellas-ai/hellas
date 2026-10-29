use super::*;
use crate::{ModelOptions, Presentations, WorkGatewayError, WorkOutputStream, WorkShutdownError};
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
    timeout: Option<std::time::Duration>,
    delay: Option<std::time::Duration>,
    started: tokio::sync::Notify,
}
impl WorkExecutionBackend for Fake {
    fn timeout(&self) -> Option<std::time::Duration> {
        self.timeout
    }
    fn run(
        &self,
        job: hellas_client::model::ComputeJob,
    ) -> Result<WorkOutputStream<ComputeEvent>, WorkGatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        assert_eq!(job.plan.calls[0].entry, "whisper.transcribe");
        assert!(job.plan.step.is_none());
        for source in &job.environment.sources {
            assert!(!job.content.read(*source).unwrap().is_empty());
        }
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
        let output = InvocationOutput {
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
        let events = [
            Ok(ComputeEvent::Output(chunk)),
            Ok(ComputeEvent::Done {
                output,
                provider: hellas_auth::ProducerSigningKey::from_secret_bytes([9; 32])
                    .unwrap()
                    .public_key(),
            }),
        ];
        let delay = self.delay;
        Ok(Box::pin(async_stream::stream! {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            for event in events { yield event; }
        }))
    }
    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}
fn options(name: &str) -> ModelOptions {
    ModelOptions::Whisper(AudioOptions {
        model: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../client/src/model/whisper/mini"),
        model_name: name.into(),
        default_max_tokens: 4,
    })
}
async fn app(names: &[&str], work: Arc<Fake>) -> Router {
    let work: Arc<dyn WorkExecutionBackend> = work;
    crate::compose::router(
        &Presentations {
            models: names.iter().map(|n| options(n)).collect(),
            ..Default::default()
        },
        &work,
    )
    .await
    .unwrap()
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
async fn multipart_wav_returns_json_or_text_through_compute() {
    let fake = Arc::new(Fake::default());
    let app = app(&["tiny"], fake.clone()).await;
    let wav = wav(48000, 480);
    for format in ["json", "text"] {
        let response = app
            .clone()
            .oneshot(request(&[
                ("file", &wav),
                ("model", b"tiny"),
                ("language", b"en"),
                ("response_format", format.as_bytes()),
            ]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        if format == "json" {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                serde_json::json!({"text":"hi there"})
            );
        } else {
            assert_eq!(&bytes[..], b"hi there");
        }
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
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
        vec![("model", &b"tiny"[..])],
        vec![("model", &b"tiny"[..]), ("file", &b"not wav"[..])],
        vec![
            ("model", &b"tiny"[..]),
            ("file", &wav[..]),
            ("response_format", &b"srt"[..]),
        ],
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
    let ModelOptions::Whisper(mut options) = options("tiny") else {
        unreachable!()
    };
    options.default_max_tokens = 5;
    assert!(router(&options, Arc::new(Fake::default())).await.is_err());
    options.default_max_tokens = 1;
    options.model = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../client/src/model/package/mini-qwen3.gguf");
    assert!(router(&options, Arc::new(Fake::default())).await.is_err());
}
#[tokio::test]
async fn expired_preparation_never_submits_work() {
    let fake = Arc::new(Fake {
        calls: AtomicUsize::new(0),
        timeout: Some(std::time::Duration::ZERO),
        ..Default::default()
    });
    let app = app(&["tiny"], fake.clone()).await;
    let response = app
        .oneshot(request(&[("model", b"tiny"), ("file", &wav(16000, 400))]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn audio_waits_without_a_client_deadline_but_keeps_explicit_budgets() {
    for timeout in [None, Some(std::time::Duration::from_secs(5))] {
        let fake = Arc::new(Fake {
            timeout,
            delay: Some(std::time::Duration::from_secs(600)),
            ..Default::default()
        });
        let app = app(&["tiny"], fake.clone()).await;
        let response =
            tokio::spawn(app.oneshot(request(&[("model", b"tiny"), ("file", &wav(16000, 160))])));
        fake.started.notified().await;
        tokio::time::pause();
        let response = response.await.unwrap().unwrap();
        tokio::time::resume();
        assert_eq!(
            response.status(),
            if timeout.is_some() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::OK
            }
        );
    }
}
