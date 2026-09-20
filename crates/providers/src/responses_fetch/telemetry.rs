//! HTTP transport metadata only; the sealed Fetch transcript stays unchanged.
use futures::{Stream, StreamExt};
use hellas_executor::FetchProviderError;
use hellas_wire::metadata::Metadata;
use tracing::{Instrument, Span};

pub(super) struct Request {
    pub span: Span,
}
impl Request {
    pub fn new(endpoint: &reqwest::Url) -> Self {
        Self {
            span: hellas_rpc::request_span!(target: "hellas_request", "POST",
                otel.kind = "client", http.request.method = "POST",
                server.address = endpoint.host_str().unwrap_or(""),
                server.port = endpoint.port_or_known_default().map(i64::from),
                url.scheme = endpoint.scheme(),
                http.response.status_code = tracing::field::Empty,
                error.type = tracing::field::Empty,
                otel.status_code = tracing::field::Empty),
        }
    }
    pub fn propagate(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut metadata = Metadata::new();
        hellas_rpc::telemetry::inject(&self.span, &mut metadata);
        for name in ["traceparent", "tracestate"] {
            if let Some(value) = metadata.get(name).and_then(|v| v.as_text()) {
                request = request.header(name, value);
            }
        }
        request
    }
    pub fn status(&self, code: u16) {
        self.span
            .record("http.response.status_code", i64::from(code));
    }
    pub fn fail(&mut self, error: &'static str) {
        self.span.record("error.type", error);
        self.span.record("otel.status_code", "ERROR");
    }
    pub fn stream<S>(
        mut self,
        stream: S,
    ) -> impl Stream<Item = Result<Vec<u8>, FetchProviderError>> + Send
    where
        S: Stream<Item = Result<Vec<u8>, FetchProviderError>> + Send + 'static,
    {
        async_stream::stream! {
        futures::pin_mut!(stream);
        while let Some(chunk) = stream.next().instrument(self.span.clone()).await {
            if chunk.is_err() { self.fail("stream_error"); }
            yield chunk;
        }
        }
    }
}
