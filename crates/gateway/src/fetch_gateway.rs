//! Responses presentation over an already funded, authenticated Work backend.
use super::{GatewayHandle, WorkExecutionBackend, WorkFetchRequest, WorkGatewayError};
use axum::{Router, body::Bytes, extract::State, response::Response, routing::post};
use futures::StreamExt;
use hellas_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend, RenderContext,
    openai::responses::OpenAiResponsesAdaptor,
};
use serde_json::{Map, Value};
use std::sync::Arc;

pub struct FetchGatewayOptions {
    pub host: String,
    pub port: Option<u16>,
    pub provider: iroh::EndpointId,
    pub service: String,
    pub method: String,
    pub request_overrides: Map<String, Value>,
    pub work: Arc<dyn WorkExecutionBackend>,
}

pub async fn start_fetch(options: FetchGatewayOptions) -> anyhow::Result<GatewayHandle> {
    let work = options.work.clone();
    let result = async {
        let listener = super::bind_gateway(&options.host, options.port, false).await?;
        let bearer = Arc::new(super::access::Bearer::generate());
        let backend = Arc::new(FetchBackend {
            work: work.clone(),
            provider: options.provider,
            service: options.service,
            method: options.method,
            overrides: options.request_overrides,
        });
        let app = Router::new()
            .route("/v1/responses", post(handle))
            .with_state(backend)
            .layer(super::access::BearerLayer::new(bearer.clone()));
        super::launch_gateway(app, listener, bearer, None, &[], Some(work.clone())).await
    }
    .await;
    if result.is_err() {
        work.drain().await;
    }
    result
}

#[derive(Clone)]
struct FetchBackend {
    work: Arc<dyn WorkExecutionBackend>,
    provider: iroh::EndpointId,
    service: String,
    method: String,
    overrides: Map<String, Value>,
}

async fn handle(State(backend): State<Arc<FetchBackend>>, body: Bytes) -> Response {
    let adaptor = OpenAiResponsesAdaptor;
    let (parsed, request) =
        match super::dispatch::parse_backend_request(&adaptor, &body, "OpenAI Responses") {
            Ok(value) => value,
            Err(response) => return *response,
        };
    super::dispatch::backend_wire_response(
        parsed.stream.unwrap_or(false),
        adaptor,
        parsed,
        backend.as_ref().clone(),
        request,
        RenderContext::new(
            super::next_id("resp"),
            super::next_id("msg"),
            super::now_unix(),
        ),
        "OpenAI Responses",
    )
    .await
}

impl ExecutionBackend for FetchBackend {
    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let mut body = request
                .raw
                .value()
                .as_object()
                .cloned()
                .ok_or_else(|| BackendError::rejected("Responses body must be an object"))?;
            if body.get("store").is_some_and(|v| v != &Value::Bool(false))
                || self
                    .overrides
                    .get("store")
                    .is_some_and(|v| v != &Value::Bool(false))
            {
                return Err(BackendError::rejected(
                    "Work Fetch supports store:false only",
                ));
            }
            body.extend(self.overrides.clone());
            body.insert("stream".into(), Value::Bool(true));
            body.insert("store".into(), Value::Bool(false));
            let events = self
                .work
                .fetch(WorkFetchRequest {
                    provider: self.provider,
                    service: self.service.clone(),
                    method: self.method.clone(),
                    body: serde_json::to_vec(&body)
                        .map_err(|e| BackendError::rejected(e.to_string()))?,
                })
                .map_err(map_error)?;
            Ok(BackendStream::new(
                events.map(|event| event.map_err(map_error)),
                None,
            ))
        })
    }
}

fn map_error(error: WorkGatewayError) -> BackendError {
    match error {
        WorkGatewayError::Rejected(_) => BackendError::rejected(error.to_string()),
        WorkGatewayError::Denied(_) => BackendError::Denied(error.to_string()),
        WorkGatewayError::Quota(_) => BackendError::Quota(error.to_string()),
        WorkGatewayError::Busy(_) => BackendError::Busy(error.to_string()),
        _ => BackendError::failed(error.to_string()),
    }
}
