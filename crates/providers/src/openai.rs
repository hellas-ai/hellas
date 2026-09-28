use anyhow::{Context, bail};
use hellas_executor::{
    FetchProvider, FetchProviderError, FetchProviderFuture, FetchProviderResponse,
    PreparedFetchRequest,
};
use hellas_rpc::OPENAI_RESPONSES_ENDPOINT;
use reqwest::Url;

use super::responses_fetch::{execute_responses_request, responses_http_client};

#[derive(Debug, thiserror::Error)]
#[error("OpenAI API key is empty")]
pub struct EmptyOpenAiKey;

#[derive(Clone)]
pub struct OpenAiResponsesFetchProvider {
    client: reqwest::Client,
    endpoint: Url,
    bearer_token: String,
}

impl OpenAiResponsesFetchProvider {
    pub fn new(api_key_env: &str) -> anyhow::Result<Self> {
        let bearer_token = std::env::var(api_key_env)
            .with_context(|| format!("environment variable {api_key_env} is not set"))?;
        let bearer_token = bearer_token.trim().to_string();
        if bearer_token.is_empty() {
            bail!("environment variable {api_key_env} is empty");
        }
        Ok(Self::with_bearer(bearer_token)?)
    }

    /// Construct from a secret supplied by an embedding host without routing
    /// it through process-wide environment state.
    pub fn with_bearer(bearer_token: impl Into<String>) -> Result<Self, EmptyOpenAiKey> {
        let bearer_token = bearer_token.into();
        let bearer_token = bearer_token.trim().to_owned();
        if bearer_token.is_empty() {
            return Err(EmptyOpenAiKey);
        }
        let endpoint = Url::parse(OPENAI_RESPONSES_ENDPOINT)
            .expect("built-in OpenAI Responses endpoint is valid");
        Ok(Self::with_client(
            responses_http_client(),
            endpoint,
            bearer_token,
        ))
    }

    fn with_client(client: reqwest::Client, endpoint: Url, bearer_token: String) -> Self {
        Self {
            client,
            endpoint,
            bearer_token,
        }
    }

    async fn execute(
        &self,
        request: PreparedFetchRequest,
    ) -> Result<FetchProviderResponse, FetchProviderError> {
        execute_responses_request(
            &self.client,
            self.endpoint.clone(),
            &self.bearer_token,
            request.body.as_bytes().to_vec(),
            &request.idempotency_key(),
            "OpenAI Responses",
        )
        .await
    }
}

impl FetchProvider for OpenAiResponsesFetchProvider {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id()
    }

    fn run(&self, request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
        Box::pin(async move { self.execute(request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::{Body, Bytes};
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::response::Response;
    use axum::routing::post;
    use futures::StreamExt;
    use hellas_rpc::{Digest, InputCommitment, JsonBytes};
    use reqwest::header::AUTHORIZATION;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    type CapturedRequest = (Option<String>, Option<String>, Bytes);
    type CaptureSender = oneshot::Sender<CapturedRequest>;
    type SharedCaptureSender = Arc<tokio::sync::Mutex<Option<CaptureSender>>>;

    #[derive(Clone)]
    struct Capture {
        tx: SharedCaptureSender,
    }

    async fn capture_responses_sse(
        State(capture): State<Capture>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let auth = headers
            .get(AUTHORIZATION.as_str())
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let idempotency_key = headers
            .get("Idempotency-Key")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        if let Some(tx) = capture.tx.lock().await.take() {
            let _ = tx.send((auth, idempotency_key, body));
        }
        Response::builder()
            .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from(
                r#"event: response.created
data: {"type":"response.created","response":{"id":"resp_up","object":"response","created_at":42,"status":"in_progress"}}

event: response.output_item.added
data: {"type":"response.output_item.added","item":{"content":[],"id":"msg_up","role":"assistant","status":"in_progress","type":"message"}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_up","delta":"hel"}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_up","delta":"lo"}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_up","object":"response","created_at":42,"status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}

"#,
            ))
            .unwrap()
    }

    fn provider(addr: std::net::SocketAddr) -> OpenAiResponsesFetchProvider {
        OpenAiResponsesFetchProvider::with_client(
            reqwest::Client::new(),
            Url::parse(&format!("http://{addr}/v1/responses")).unwrap(),
            "test-key".to_string(),
        )
    }

    fn test_commitment() -> InputCommitment {
        InputCommitment::from_digest(Digest::from_bytes([7; 32]))
    }

    fn request(body: &[u8]) -> PreparedFetchRequest {
        let call = hellas_executor::FetchCall::new(
            "openai",
            "responses",
            JsonBytes::new(body.to_vec()),
            test_commitment(),
        );
        PreparedFetchRequest::new(&call, call.body.clone())
    }

    async fn collect(provider: &OpenAiResponsesFetchProvider, body: &[u8]) -> Vec<Vec<u8>> {
        let mut stream = provider.run(request(body)).await.unwrap().stream;
        let mut output = Vec::new();
        while let Some(chunk) = stream.next().await {
            output.push(chunk.unwrap());
        }
        output
    }

    #[tokio::test]
    async fn forwards_streaming_request_and_streams_raw_sse_chunks() {
        let (tx, rx) = oneshot::channel();
        let app = Router::new()
            .route("/v1/responses", post(capture_responses_sse))
            .with_state(Capture {
                tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let body = br#"{"model":"m","input":"hello","stream":true,"metadata":{"trace":"abc"}}"#;
        let output = collect(&provider(addr), body).await;

        let (auth, idempotency_key, forwarded_body) = rx.await.unwrap();
        assert_eq!(auth.as_deref(), Some("Bearer test-key"));
        assert_eq!(
            idempotency_key,
            Some(test_commitment().digest().to_string())
        );
        assert_eq!(forwarded_body.as_ref(), body);

        let joined = String::from_utf8(output.concat()).unwrap();
        assert!(joined.contains("event: response.created"));
        assert!(joined.contains(r#""id":"resp_up""#));
        assert!(joined.contains(r#""delta":"hel""#));
        assert!(joined.contains(r#""delta":"lo""#));
        assert!(joined.contains("event: response.completed"));
    }
}
