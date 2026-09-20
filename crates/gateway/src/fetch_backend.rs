use axum::body::Bytes;
use hellas_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend,
};
use hellas_rpc::fetch::{build_input_events_with_retention, verify_input_events};
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::stream::input_event_to_pb;
use hellas_rpc::{Assurance, ContentId, ProducerSigningKey, Retention};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::sync::Arc;

use crate::execution::CliRuntime;
use hellas_client::ExecutionRoute;
use hellas_client::cache::fetch_output_stream;

#[derive(Clone)]
pub(super) struct ResponsesFetchBackend {
    runtime: CliRuntime,
    route: Option<ExecutionRoute>,
    service: String,
    method: String,
    execution_environment: ContentId,
    caller_key: Arc<ProducerSigningKey>,
    assurance: Assurance,
    request_overrides: JsonMap<String, JsonValue>,
}

impl ResponsesFetchBackend {
    pub(super) fn new(
        runtime: CliRuntime,
        route: Option<ExecutionRoute>,
        target: (&str, &str, ContentId),
        caller_key: ProducerSigningKey,
        assurance: Assurance,
        request_overrides: JsonMap<String, JsonValue>,
    ) -> Self {
        let (service, method, execution_environment) = target;
        Self {
            runtime,
            route,
            service: service.to_string(),
            method: method.to_string(),
            execution_environment,
            caller_key: Arc::new(caller_key),
            assurance,
            request_overrides,
        }
    }

    pub(super) fn is_codex_responses(&self) -> bool {
        self.execution_environment == hellas_rpc::FetchEnvironment::CodexResponses.manifest_id()
    }
}

impl ExecutionBackend for ResponsesFetchBackend {
    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let ProviderRequestBody { payload, retention } =
                provider_request_body(&request, &self.request_overrides)?;
            let (input, _) = signed_input_events_with_commitment(
                &self.service,
                &self.method,
                &payload,
                self.execution_environment,
                self.assurance,
                self.caller_key.as_ref(),
                retention,
            )
            .map_err(|source| {
                BackendError::failed(format!("failed to sign fetch request: {source}"))
            })?;
            let fetch_request = FetchRequest { input };
            fetch_output_stream(
                self.runtime.clone(),
                fetch_request,
                self.route.clone(),
                self.caller_key.clone(),
                None,
            )
            .await
            .map_err(|error| BackendError::failed(error.to_string()))
        })
    }
}

impl super::cache::CacheIdentity for ResponsesFetchBackend {
    fn cache_key(&self, request: &BackendRequest) -> Result<super::cache::CacheKey, BackendError> {
        let body = provider_request_body(request, &self.request_overrides)?;
        super::cache::CacheKey::fetch(
            self.execution_environment,
            &self.service,
            &self.method,
            &body.payload,
        )
        .map_err(|error| BackendError::rejected(error.to_string()))
    }
}

fn signed_input_events_with_commitment(
    service: &str,
    method: &str,
    payload: &[u8],
    execution_environment: ContentId,
    assurance: Assurance,
    key: &ProducerSigningKey,
    retention: Retention,
) -> anyhow::Result<(Vec<hellas_rpc::pb::execute::InputEventEnvelope>, String)> {
    let events = build_input_events_with_retention(
        service,
        method,
        payload,
        execution_environment,
        assurance,
        key,
        retention,
    )?;
    let input_commitment = verify_input_events(&events)?.input_commitment;
    Ok((
        events.iter().map(input_event_to_pb).collect(),
        input_commitment.digest().to_string(),
    ))
}

#[derive(Debug)]
struct ProviderRequestBody {
    payload: Bytes,
    retention: Retention,
}

fn provider_request_body(
    request: &BackendRequest,
    request_overrides: &JsonMap<String, JsonValue>,
) -> Result<ProviderRequestBody, BackendError> {
    let JsonValue::Object(mut object) = request.raw.value().clone() else {
        return Err(BackendError::rejected(
            "Responses fetch request body must be a JSON object",
        ));
    };
    for (key, value) in request_overrides {
        object.insert(key.clone(), value.clone());
    }
    object.insert(
        "model".to_string(),
        JsonValue::String(request.execution.canonical.model.name.clone()),
    );
    object.insert("stream".to_string(), JsonValue::Bool(true));
    // The caller-facing Responses `store` switch controls Hellas Courtesy
    // transcript retention. Upstream account storage is a different trust
    // boundary: the sealed Fetch adaptor is always stateless.
    let retention = retention_from_json_object(&object)?;
    object.insert("store".to_string(), JsonValue::Bool(false));
    let payload = serde_json::to_vec(&JsonValue::Object(object))
        .map(Bytes::from)
        .map_err(|source| {
            BackendError::failed(format!(
                "failed to encode Responses fetch request: {source}"
            ))
        })?;
    Ok(ProviderRequestBody { payload, retention })
}

pub(super) fn retention_from_json(value: &JsonValue) -> Result<Retention, BackendError> {
    let object = value
        .as_object()
        .ok_or_else(|| BackendError::rejected("request body must be a JSON object"))?;
    retention_from_json_object(object)
}

fn retention_from_json_object(
    object: &JsonMap<String, JsonValue>,
) -> Result<Retention, BackendError> {
    match object.get("store") {
        None => Ok(Retention::Ephemeral),
        Some(JsonValue::Bool(store)) => Ok(Retention::from_retain(*store)),
        Some(_) => Err(BackendError::rejected("`store` must be a boolean")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_adaptors::{CanonicalExecution, ExecutionRequest, Input, ModelRef, RawRequest};

    fn backend_request(body: &[u8], model: &str) -> BackendRequest {
        BackendRequest::new(
            ExecutionRequest::new(CanonicalExecution::new(
                ModelRef::new(model),
                Input::Text("hello".to_string()),
            )),
            RawRequest::from_slice(body).unwrap(),
        )
    }

    #[test]
    fn provider_body_applies_request_overrides_stream_and_model() {
        let request = backend_request(
            br#"{"model":"client-model","input":"hello","stream":false,"store":true}"#,
            "gpt-5.5",
        );
        let overrides = JsonMap::from_iter([("store".to_string(), JsonValue::Bool(false))]);

        let body = provider_request_body(&request, &overrides).unwrap();
        let value: JsonValue = serde_json::from_slice(&body.payload).unwrap();

        assert_eq!(value["model"], "gpt-5.5");
        assert_eq!(value["input"], "hello");
        assert_eq!(value["stream"], true);
        assert_eq!(value["store"], false);
        assert_eq!(body.retention, Retention::Ephemeral);
    }

    #[test]
    fn provider_body_without_overrides_preserves_optional_fields() {
        let request = backend_request(br#"{"model":"m","input":"hello"}"#, "m");
        let overrides = JsonMap::new();

        let body = provider_request_body(&request, &overrides).unwrap();
        let value: JsonValue = serde_json::from_slice(&body.payload).unwrap();

        assert_eq!(value["stream"], true);
        assert_eq!(value["store"], false);
        assert_eq!(body.retention, Retention::Ephemeral);
    }

    #[test]
    fn responses_store_controls_hellas_retention_not_upstream_account_storage() {
        let request = backend_request(br#"{"model":"m","input":"hello","store":true}"#, "m");

        let body = provider_request_body(&request, &JsonMap::new()).unwrap();
        let value: JsonValue = serde_json::from_slice(&body.payload).unwrap();

        assert_eq!(body.retention, Retention::Retain);
        assert_eq!(value["store"], false);
    }

    #[test]
    fn provider_body_rejects_non_boolean_store_after_overrides() {
        let request = backend_request(br#"{"model":"m","input":"hello","store":"no"}"#, "m");
        let err = provider_request_body(&request, &JsonMap::new()).unwrap_err();
        assert!(err.to_string().contains("`store` must be a boolean"));
    }

    #[test]
    fn signed_input_helper_returns_request_commitment() {
        let key = ProducerSigningKey::from_secret_bytes([3; 32]).unwrap();
        let (events, commitment) = signed_input_events_with_commitment(
            "codex",
            "responses",
            br#"{"input":"hi"}"#,
            ContentId::from_bytes([9; 32]),
            Assurance::ProducerSigned,
            &key,
            Retention::Retain,
        )
        .unwrap();

        assert_eq!(events.len(), 8);
        assert_eq!(commitment.len(), 64);
    }
}
