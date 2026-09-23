use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_core::Stream;
use futures_util::stream;
use hellas_rpc::{ContentId, InputCommitment, JsonBytes};

pub type FetchProviderResult<T> = Result<T, FetchProviderError>;
pub type FetchProviderStream =
    Pin<Box<dyn Stream<Item = FetchProviderResult<Vec<u8>>> + Send + 'static>>;
/// Closed, still-untrusted claims extracted from an HTTP response before its
/// body is exposed to a Fetch projector. This is deliberately not a header map;
/// the selected projector decides which claims are valid and may be signed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchProviderResponseHead {
    pub effective_model: Option<String>,
    pub http: Option<HttpResponseHead>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl FetchProviderResponseHead {
    pub const fn is_empty(&self) -> bool {
        self.effective_model.is_none() && self.http.is_none()
    }
}

pub struct FetchProviderResponse {
    pub head: FetchProviderResponseHead,
    pub stream: FetchProviderStream,
}

pub type FetchProviderFuture<'a> =
    Pin<Box<dyn Future<Output = FetchProviderResult<FetchProviderResponse>> + Send + 'a>>;

pub trait FetchProvider: Send + Sync + 'static {
    /// The exact built-in environment this provider driver implements.
    fn execution_environment(&self) -> ContentId;

    fn run(&self, request: PreparedFetchRequest) -> FetchProviderFuture<'_>;
}

/// Caller-signed adaptor input retained with a quote. It is never accepted by
/// a [`FetchProvider`]; only a trusted adaptor can turn it into provider wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchCall {
    pub service: String,
    pub method: String,
    pub body: JsonBytes,
    /// Commitment over the complete caller-signed input transcript.
    pub input_commitment: InputCommitment,
}

impl FetchCall {
    pub fn new(
        service: impl Into<String>,
        method: impl Into<String>,
        body: JsonBytes,
        input_commitment: InputCommitment,
    ) -> Self {
        Self {
            service: service.into(),
            method: method.into(),
            body,
            input_commitment,
        }
    }
}

/// Provider-only request produced after trusted adaptor validation and
/// structuring. Its constructor requires the signed call and distinct
/// provider-wire bytes, making raw-call dispatch a type error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PreparedFetchRequest {
    pub service: String,
    pub method: String,
    pub body: JsonBytes,
    input_commitment: InputCommitment,
}

impl PreparedFetchRequest {
    #[must_use]
    pub fn new(call: &FetchCall, body: JsonBytes) -> Self {
        Self {
            service: call.service.clone(),
            method: call.method.clone(),
            body,
            input_commitment: call.input_commitment,
        }
    }

    pub fn idempotency_key(&self) -> String {
        self.input_commitment.digest().to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct MockFetchRequestKey {
    service: String,
    method: String,
    body: JsonBytes,
}

impl From<&PreparedFetchRequest> for MockFetchRequestKey {
    fn from(request: &PreparedFetchRequest) -> Self {
        Self {
            service: request.service.clone(),
            method: request.method.clone(),
            body: request.body.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MockFetchProvider {
    execution_environment: ContentId,
    responses: Arc<Mutex<HashMap<MockFetchRequestKey, Vec<Vec<u8>>>>>,
    calls: Arc<Mutex<HashMap<MockFetchRequestKey, usize>>>,
}

impl MockFetchProvider {
    pub fn new(execution_environment: ContentId) -> Self {
        Self {
            execution_environment,
            responses: Arc::default(),
            calls: Arc::default(),
        }
    }

    pub fn insert(
        &self,
        service: impl Into<String>,
        method: impl Into<String>,
        body: impl Into<Vec<u8>>,
        chunks: impl IntoIterator<Item = Vec<u8>>,
    ) {
        let request = mock_key(service, method, body);
        let chunks = chunks.into_iter().collect();
        self.responses
            .lock()
            .expect("mock fetch responses lock poisoned")
            .insert(request, chunks);
    }

    pub fn calls(
        &self,
        service: impl Into<String>,
        method: impl Into<String>,
        body: impl Into<Vec<u8>>,
    ) -> usize {
        let request = mock_key(service, method, body);
        *self
            .calls
            .lock()
            .expect("mock fetch calls lock poisoned")
            .get(&request)
            .unwrap_or(&0)
    }
}

fn mock_key(
    service: impl Into<String>,
    method: impl Into<String>,
    body: impl Into<Vec<u8>>,
) -> MockFetchRequestKey {
    MockFetchRequestKey {
        service: service.into(),
        method: method.into(),
        body: JsonBytes::new(body.into()),
    }
}

impl FetchProvider for MockFetchProvider {
    fn execution_environment(&self) -> ContentId {
        self.execution_environment
    }

    fn run(&self, request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
        Box::pin(async move {
            let key = MockFetchRequestKey::from(&request);
            let chunks = {
                let mut calls = self
                    .calls
                    .lock()
                    .map_err(|_| FetchProviderError::failed("mock calls lock poisoned"))?;
                *calls.entry(key.clone()).or_default() += 1;

                self.responses
                    .lock()
                    .map_err(|_| FetchProviderError::failed("mock responses lock poisoned"))?
                    .get(&key)
                    .cloned()
            };

            let chunks = chunks.ok_or_else(|| {
                FetchProviderError::failed(format!(
                    "mock fetch response not programmed for {}/{}",
                    request.service, request.method
                ))
            })?;
            Ok(FetchProviderResponse {
                head: FetchProviderResponseHead::default(),
                stream: Box::pin(stream::iter(chunks.into_iter().map(Ok))) as FetchProviderStream,
            })
        })
    }
}

/// A provider error always means the provider actually failed. Routing
/// happens in [`crate::FetchRouteRegistry`] before a provider is invoked,
/// so there is no "not my route" rejection variant.
#[derive(Debug, thiserror::Error)]
#[error("fetch provider failed: {0}")]
pub struct FetchProviderError(String);

impl FetchProviderError {
    pub fn failed(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::Digest;

    #[test]
    fn prepared_request_identity_includes_the_signed_input() {
        let call = |byte| {
            FetchCall::new(
                "codex",
                "responses",
                JsonBytes::new(br#"{"input":"hello"}"#.to_vec()),
                InputCommitment::from_digest(Digest::from_bytes([byte; 32])),
            )
        };
        let first_call = call(1);
        let second_call = call(2);

        assert_ne!(
            PreparedFetchRequest::new(&first_call, first_call.body.clone()),
            PreparedFetchRequest::new(&second_call, second_call.body.clone()),
        );
    }
}
