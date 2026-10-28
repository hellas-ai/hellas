use super::*;
use crate::{
    FetchRoute, HttpGatewayConfig, ResponsesFetch, WorkFetchRequest, WorkFetchStream,
    WorkGatewayError, WorkShutdownError,
};
use std::sync::Mutex;

/// Records which Fetch route each request reached, then refuses it.
struct Recorder {
    provider: iroh::EndpointId,
    seen: Mutex<Vec<(String, String)>>,
}

impl WorkExecutionBackend for Recorder {
    fn fetch_routes(&self) -> Vec<FetchRoute> {
        vec![
            FetchRoute {
                provider: self.provider,
                schema: hellas_rpc::FetchSchema::HttpV1,
                sealed: Some(("http".into(), "request".into())),
            },
            FetchRoute {
                provider: self.provider,
                schema: hellas_rpc::FetchSchema::StatelessResponsesV1,
                sealed: Some(("openai".into(), "responses".into())),
            },
        ]
    }
    fn fetch(&self, request: WorkFetchRequest) -> Result<WorkFetchStream, WorkGatewayError> {
        self.seen
            .lock()
            .unwrap()
            .push((request.service, request.method));
        Err(WorkGatewayError::Rejected("recorded".into()))
    }
    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}

fn presentations(
    work: &Recorder,
    responses_models: &[&str],
    http_models: &[&str],
) -> Presentations {
    let http: HttpGatewayConfig = serde_json::from_value(serde_json::json!({
        "backends": {"upstream": {
            "models": http_models,
            "routes": [{"path": "/v1/responses", "method": "POST",
                        "url": "https://example.com/v1/responses"}],
        }},
    }))
    .unwrap();
    Presentations {
        text: None,
        responses: ResponsesFetch::from_routes(
            &work.fetch_routes(),
            Default::default(),
            responses_models.iter().map(|m| m.to_string()).collect(),
        )
        .unwrap(),
        http: Some(http),
    }
}

async fn post(app: &Router, model: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::post("/v1/responses")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"model": model, "input": "hi"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn a_shared_path_is_split_by_model() {
    let recorder = Arc::new(Recorder {
        provider: iroh::SecretKey::from_bytes(&[4; 32]).public(),
        seen: Mutex::new(Vec::new()),
    });
    let work: Arc<dyn WorkExecutionBackend> = recorder.clone();
    let app = router(&presentations(&recorder, &["gpt-x"], &["claude-y"]), &work)
        .await
        .unwrap();
    post(&app, "gpt-x").await;
    post(&app, "claude-y").await;
    assert_eq!(post(&app, "unknown").await, StatusCode::NOT_FOUND);
    assert_eq!(
        *recorder.seen.lock().unwrap(),
        [
            ("openai".to_string(), "responses".to_string()),
            ("http".to_string(), "request".to_string()),
        ]
    );
}

#[tokio::test]
async fn overlapping_or_unnamed_models_on_a_shared_path_refuse_to_start() {
    let recorder = Arc::new(Recorder {
        provider: iroh::SecretKey::from_bytes(&[4; 32]).public(),
        seen: Mutex::new(Vec::new()),
    });
    let work: Arc<dyn WorkExecutionBackend> = recorder.clone();
    for (responses, http) in [(&[][..], &["claude-y"][..]), (&["same"], &["same"])] {
        assert!(matches!(
            router(&presentations(&recorder, responses, http), &work).await,
            Err(crate::GatewayError::Config(GatewayConfigError::RouteConflict(path)))
                if path == "/v1/responses"
        ));
    }
    assert!(matches!(
        router(&Presentations::default(), &work).await,
        Err(crate::GatewayError::Config(
            GatewayConfigError::NoPresentation
        ))
    ));
}
