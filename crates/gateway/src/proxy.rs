use axum::body::Bytes;
use futures::StreamExt;
use hellas_adaptors::openai::responses::{
    OpenAiResponsesAdaptor, ParsedResponseRequest, ResponsesSseProjector,
};
use hellas_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend, OutputEvent,
    WireAdaptor,
};
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value as JsonValue;
use std::time::Duration;

fn http_client(request_timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(request_timeout)
        .build()
        .expect("HTTP client configuration is valid")
}

#[derive(Clone)]
pub(super) struct ResponsesProxy {
    client: reqwest::Client,
    endpoint: Url,
    bearer_token: Option<String>,
}

impl ResponsesProxy {
    pub(super) fn new(endpoint: &str, api_key_env: &str) -> anyhow::Result<Self> {
        let endpoint = Url::parse(endpoint)?;
        let bearer_token = std::env::var(api_key_env)
            .ok()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());
        Ok(Self::with_client(
            http_client(Duration::from_secs(20 * 60)),
            endpoint,
            bearer_token,
        ))
    }

    fn with_client(client: reqwest::Client, endpoint: Url, bearer_token: Option<String>) -> Self {
        Self {
            client,
            endpoint,
            bearer_token,
        }
    }

    async fn send_raw(&self, body: Bytes) -> Result<reqwest::Response, BackendError> {
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(body);

        if let Some(token) = &self.bearer_token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }

        let upstream = request.send().await.map_err(|source| {
            BackendError::failed(format!("Responses proxy request failed: {source}"))
        })?;
        Ok(upstream)
    }
}

impl ExecutionBackend for ResponsesProxy {
    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let adaptor = OpenAiResponsesAdaptor;
            let parsed = adaptor
                .parse(request.raw.clone())
                .map_err(|err| BackendError::rejected(err.to_string()))?;
            let upstream = self.send_raw(forwarded_body(&request)?).await?;
            let status = upstream.status();
            if !status.is_success() {
                return Err(BackendError::failed(format!(
                    "Responses proxy returned HTTP {status}"
                )));
            }
            Ok(BackendStream::new(
                responses_event_stream(upstream, parsed),
                None,
            ))
        })
    }
}

fn forwarded_body(request: &BackendRequest) -> Result<Bytes, BackendError> {
    let upstream_model = request.execution.canonical.model.name.as_str();
    let JsonValue::Object(mut object) = request.raw.value().clone() else {
        return Err(BackendError::rejected(
            "Responses proxy request body must be a JSON object",
        ));
    };
    object.insert(
        "model".to_string(),
        JsonValue::String(upstream_model.to_string()),
    );
    object.insert("stream".to_string(), JsonValue::Bool(true));
    serde_json::to_vec(&JsonValue::Object(object))
        .map(Bytes::from)
        .map_err(|source| {
            BackendError::failed(format!(
                "failed to encode Responses proxy request: {source}"
            ))
        })
}

impl super::cache::CacheIdentity for ResponsesProxy {
    fn cache_key(&self, request: &BackendRequest) -> Result<super::cache::CacheKey, BackendError> {
        let body = forwarded_body(request)?;
        Ok(super::cache::CacheKey::hash(
            super::cache::CacheKind::Proxy,
            &[self.endpoint.as_str().as_bytes(), &body],
        ))
    }
}

fn responses_event_stream(
    upstream: reqwest::Response,
    parsed: ParsedResponseRequest,
) -> impl futures::Stream<Item = Result<OutputEvent, BackendError>> + Send + 'static {
    async_stream::stream! {
        let mut chunks = upstream.bytes_stream();
        let mut projector = ResponsesSseProjector::new(parsed);

        while let Some(chunk) = chunks.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(source) => {
                    yield Err(BackendError::failed(format!("Responses proxy stream failed: {source}")));
                    return;
                }
            };
            let events = match projector.push(&chunk) {
                Ok(events) => events,
                Err(err) => {
                    yield Err(err);
                    return;
                }
            };
            for event in events {
                yield Ok(event);
            }
        }

        let events = match projector.finish() {
            Ok(events) => events,
            Err(err) => {
                yield Err(err);
                return;
            }
        };
        for event in events {
            yield Ok(event);
        }
    }
}

#[cfg(test)]
mod tests;
