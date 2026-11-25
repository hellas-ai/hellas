use super::*;
use crate::{ComputeEvent, WorkEvent, WorkExecutionBackend};
use axum::body::Body;
use hellas_rpc::{
    JsonBytes,
    protocol::invocation::{
        Artifact,
        compute::{OutputKind, RunMetadata},
        output::{InvocationOutput, Outcome},
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

#[derive(Default)]
struct Fake {
    calls: AtomicUsize,
}
impl WorkExecutionBackend for Fake {
    fn backends(&self) -> Vec<crate::BackendInfo> {
        crate::test_support::backend(Some(hellas_client::model::evaluator(
            hellas_client::model::GpuDialect::Hip,
        )))
    }
    fn run(
        &self,
        _backend: &str,
        _request_job: Arc<crate::jobs::Job>,
        job: hellas_client::model::ComputeJob,
    ) -> Result<crate::WorkOutputStream<ComputeEvent>, crate::WorkGatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(job.plan.calls.len(), 2 * job.plan.outputs.len());
        let provider = hellas_auth::ProducerSigningKey::from_secret_bytes([9; 32])
            .unwrap()
            .public_key();
        let output = InvocationOutput {
            outcome: Outcome::Succeeded,
            artifacts: job
                .plan
                .outputs
                .iter()
                .map(|declared| {
                    let OutputKind::Buffer { max_bytes } = declared.kind else {
                        panic!()
                    };
                    Artifact::new(
                        declared.slot.clone(),
                        "catena.bytes.v1",
                        vec![0; max_bytes as usize],
                    )
                })
                .collect(),
            metadata: JsonBytes(
                hellas_rpc::canonical_dag_cbor(&RunMetadata {
                    steps: 0,
                    stop: None,
                })
                .unwrap(),
            ),
        };
        Ok(Box::pin(futures::stream::iter([
            Ok(WorkEvent::Accepted(
                hellas_rpc::provenance::ExecutionProvenance {
                    commitment_id: [0xab; 32],
                    provider,
                },
            )),
            Ok(WorkEvent::Output(ComputeEvent::Done { output, provider })),
        ])))
    }
    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}
async fn app(work: Arc<Fake>) -> Router {
    crate::router::router(
        vec![crate::test_support::route(crate::Presentation::Model {
            modality: ModelKind::Decision,
            model: "mini".into(),
            package: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../client/src/model/package/mini-d1.gguf")
                .into(),
            max_tokens: 128,
        })],
        work,
        Arc::new(crate::jobs::Jobs::default()),
        Default::default(),
    )
    .await
    .unwrap()
}
fn body() -> serde_json::Value {
    serde_json::json!({
        "model": "mini",
        "state": "charged twice",
        "questions": {
            "refund": {"type": "noul", "instructions": "refund?"},
            "urgency": {"type": "score", "instructions": "urgent?", "criteria": ["wait", "now"]}
        }
    })
}
async fn post(app: &Router, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let request = axum::extract::Request::post(PATH)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn decision_route_answers_every_question_from_one_job() {
    let fake = Arc::new(Fake::default());
    let app = app(fake.clone()).await;
    let (status, json) = post(&app, body()).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["model"], "mini");
    // Uniform logits weigh every option equally.
    assert_eq!(json["answers"]["refund"]["noul"], 0.5);
    assert_eq!(json["answers"]["urgency"]["type"], "score");
    assert_eq!(json["usage"]["output_tokens"], 0);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_decision_requests_never_reach_work() {
    let fake = Arc::new(Fake::default());
    let app = app(fake.clone()).await;
    for (key, value, status, message) in [
        (
            "model",
            serde_json::json!("unknown"),
            StatusCode::NOT_FOUND,
            "no backend",
        ),
        (
            "questions",
            serde_json::json!({}),
            StatusCode::BAD_REQUEST,
            "question",
        ),
        (
            "images",
            // A 1x1 PNG.
            serde_json::json!([
                "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCC"
            ]),
            StatusCode::BAD_REQUEST,
            "text only",
        ),
    ] {
        let mut body = body();
        body[key] = value;
        let (found, json) = post(&app, body).await;
        assert_eq!(found, status, "{key}: {json}");
        assert!(
            json["error"]["message"].as_str().unwrap().contains(message),
            "{key}: {json}"
        );
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}
