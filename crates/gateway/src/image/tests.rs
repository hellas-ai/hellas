use super::*;
use axum::body::Body;
use hellas_rpc::{
    JsonBytes,
    protocol::invocation::{
        Artifact,
        compute::{OutputKind, RunMetadata},
        output::{FailureReason, InvocationOutput, Outcome},
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

#[derive(Default)]
struct Fake {
    calls: AtomicUsize,
    fail: bool,
    missing: bool,
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
    ) -> Result<crate::WorkOutputStream<ComputeEvent>, crate::WorkGatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        assert_eq!(job.environment.sources.len(), 1);
        assert!(job.content.read(job.environment.sources[0]).unwrap().len() > 500_000);
        assert_eq!(job.plan.calls.len(), 3);
        assert_eq!(job.inputs.len(), 2);
        let OutputKind::Buffer { max_bytes } = job.plan.outputs[0].kind else {
            panic!()
        };
        let output = InvocationOutput {
            outcome: if self.fail {
                Outcome::Failed(FailureReason::Execution)
            } else {
                Outcome::Succeeded
            },
            artifacts: vec![Artifact::new(
                "image",
                "catena.bytes.v1",
                (0..max_bytes / 4)
                    .flat_map(|_| 0.5f32.to_le_bytes())
                    .collect(),
            )],
            metadata: JsonBytes(
                hellas_rpc::canonical_dag_cbor(&RunMetadata {
                    steps: 0,
                    stop: None,
                })
                .unwrap(),
            ),
        };
        let mut events = vec![Ok(WorkEvent::Transcript(
            b"signed image transcript".to_vec(),
        ))];
        if !self.missing {
            events.push(Ok(WorkEvent::Output(ComputeEvent::Done {
                output,
                provider: hellas_auth::ProducerSigningKey::from_secret_bytes([9; 32])
                    .unwrap()
                    .public_key(),
            })));
        }
        let delay = self.delay;
        Ok(Box::pin(async_stream::stream! {
            yield Ok(WorkEvent::Accepted(hellas_rpc::provenance::ExecutionProvenance {
                commitment_id:[0xab;32],
                provider:hellas_auth::ProducerSigningKey::from_secret_bytes([9;32]).unwrap().public_key(),
            }));
            if let Some(delay)=delay { tokio::time::sleep(delay).await; }
            for event in events { yield event; }
        }))
    }
    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}
async fn app(fake: Arc<Fake>) -> Router {
    let work: Arc<dyn WorkExecutionBackend> = fake;
    crate::compose::router(
        &crate::Presentations {
            models: vec![crate::ModelOptions::Flux(ImageOptions {
                model: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../client/src/model/flux/fixture"),
                model_name: "klein".into(),
            })],
            ..Default::default()
        },
        &work,
    )
    .await
    .unwrap()
    .layer(crate::provenance_layer::ProvenanceLayer)
}
fn request(body: serde_json::Value) -> axum::extract::Request {
    axum::extract::Request::post("/v1/images/generations")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}
fn body() -> serde_json::Value {
    serde_json::json!({"model":"klein","prompt":"a red fox","size":"16x16","seed":42,"steps":1})
}

#[tokio::test]
async fn image_route_returns_png_and_signed_evidence_from_one_job() {
    let fake = Arc::new(Fake::default());
    let response = app(fake.clone())
        .await
        .oneshot(request(body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[hellas_rpc::provenance::COMMITMENT_KEY],
        "ab".repeat(32)
    );
    assert_eq!(
        response.headers()[hellas_rpc::provenance::PROVIDER_KEY],
        hellas_rpc::provenance::encode_public_key(
            &hellas_auth::ProducerSigningKey::from_secret_bytes([9; 32])
                .unwrap()
                .public_key()
        )
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["hellas"]["commitment"], "ab".repeat(32));
    let png = base64::engine::general_purpose::STANDARD
        .decode(json["data"][0]["b64_json"].as_str().unwrap())
        .unwrap();
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(u32::from_be_bytes(png[16..20].try_into().unwrap()), 16);
    assert_eq!(u32::from_be_bytes(png[20..24].try_into().unwrap()), 16);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(json["hellas"]["transcript"].as_str().unwrap())
            .unwrap(),
        b"signed image transcript"
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn expired_image_preparation_never_submits_work() {
    let fake = Arc::new(Fake {
        timeout: Some(std::time::Duration::ZERO),
        ..Default::default()
    });
    let response = app(fake.clone())
        .await
        .oneshot(request(body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn image_waits_without_a_deadline_and_honors_an_explicit_budget() {
    for timeout in [None, Some(std::time::Duration::from_secs(5))] {
        let fake = Arc::new(Fake {
            timeout,
            delay: Some(std::time::Duration::from_secs(600)),
            ..Default::default()
        });
        let app = app(fake.clone()).await;
        let response = tokio::spawn(app.oneshot(request(body())));
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
        assert_eq!(
            response.headers()[hellas_rpc::provenance::COMMITMENT_KEY],
            "ab".repeat(32)
        );
    }
}

#[tokio::test]
async fn invalid_image_requests_never_reach_work() {
    let fake = Arc::new(Fake::default());
    let app = app(fake.clone()).await;
    for (key, value, status) in [
        ("model", serde_json::json!("unknown"), StatusCode::NOT_FOUND),
        (
            "size",
            serde_json::json!("1024x512"),
            StatusCode::BAD_REQUEST,
        ),
        ("size", serde_json::json!("15x16"), StatusCode::BAD_REQUEST),
        ("steps", serde_json::json!(0), StatusCode::BAD_REQUEST),
        ("steps", serde_json::json!(51), StatusCode::BAD_REQUEST),
        ("n", serde_json::json!(2), StatusCode::BAD_REQUEST),
        (
            "response_format",
            serde_json::json!("url"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "unexpected",
            serde_json::json!(true),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut body = body();
        body[key] = value;
        let response = app.clone().oneshot(request(body)).await.unwrap();
        assert_eq!(response.status(), status, "{key}");
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_or_missing_terminal_outcome_is_not_an_image() {
    for fake in [
        Fake {
            fail: true,
            ..Default::default()
        },
        Fake {
            missing: true,
            ..Default::default()
        },
    ] {
        let response = app(Arc::new(fake))
            .await
            .oneshot(request(body()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.get("data").is_none());
        assert!(json["hellas"]["transcript"].is_string());
    }
}
