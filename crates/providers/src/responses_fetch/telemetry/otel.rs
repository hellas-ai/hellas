//! HTTP transport metadata only; the sealed Fetch transcript stays unchanged.
use futures::{Stream, StreamExt};
use hellas_executor::FetchProviderError;
use hellas_wire::metadata::Metadata;
use tracing::{Instrument, Span};

pub(crate) struct Request {
    pub span: Span,
    complete: bool,
}
impl Request {
    pub fn new(endpoint: &reqwest::Url) -> Self {
        Self::for_method(endpoint, "POST")
    }
    pub fn for_method(endpoint: &reqwest::Url, method: &str) -> Self {
        Self {
            complete: false,
            span: hellas_rpc::request_span!(target: "hellas_request", "http.upstream",
                otel.kind = "client", otel.name = method, http.request.method = method,
                server.address = endpoint.host_str().unwrap_or(""),
                server.port = endpoint.port_or_known_default().map(i64::from),
                url.scheme = endpoint.scheme(),
                http.response.status_code = tracing::field::Empty,
                error.type = tracing::field::Empty,
                otel.status_code = tracing::field::Empty),
        }
    }
    pub async fn send(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> reqwest::Result<reqwest::Response> {
        let (client, request) = builder.build_split();
        let mut request = request?;
        let mut metadata = Metadata::new();
        hellas_rpc::telemetry::inject(&self.span, &mut metadata);
        // Without an active tracing context, preserve the caller's headers.
        // Otherwise replace both fields, including stale tracestate when the
        // new context has none. RequestBuilder::header would append duplicates.
        if metadata.get("traceparent").is_some() {
            for name in ["traceparent", "tracestate"] {
                request.headers_mut().remove(name);
                if let Some(value) = metadata
                    .get(name)
                    .and_then(|v| v.as_text())
                    .filter(|value| !value.is_empty())
                    && let Ok(value) = value.parse()
                {
                    request.headers_mut().insert(name, value);
                }
            }
        }
        client.execute(request).await
    }
    pub fn status(&self, code: u16) {
        self.span
            .record("http.response.status_code", i64::from(code));
    }
    fn complete(&mut self) {
        self.complete = true;
    }

    pub fn fail(&mut self, error: &'static str) {
        self.complete = true;
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
        self.complete();
        }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if !self.complete {
            self.fail("cancelled");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TracerProvider;
    use tracing_subscriber::prelude::*;

    #[tokio::test]
    async fn propagation_replaces_duplicates_and_removes_stale_tracestate() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::registry()
                .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("headers"))),
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let tx = tx.clone();
                async move {
                    tx.send(headers).await.unwrap();
                    "ok"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        for active in [true, false] {
            let trace = if active {
                tracing::dispatcher::with_default(&dispatch, || Request::new(&url))
            } else {
                Request {
                    span: Span::none(),
                    complete: false,
                }
            };
            let mut context = Metadata::new();
            hellas_rpc::telemetry::inject(&trace.span, &mut context);
            let builder = client
                .get(url.clone())
                .header("traceparent", "old-one")
                .header("traceparent", "old-two")
                .header("tracestate", "vendor=stale")
                .header("x-extension", "one")
                .header("x-extension", "two");
            assert_eq!(
                trace.send(builder).await.unwrap().text().await.unwrap(),
                "ok"
            );
            let headers = rx.recv().await.unwrap();
            assert_eq!(headers.get_all("x-extension").iter().count(), 2);
            if active {
                assert_eq!(headers.get_all("traceparent").iter().count(), 1);
                assert_eq!(
                    headers["traceparent"],
                    context.get("traceparent").unwrap().as_text().unwrap()
                );
                assert!(!headers.contains_key("tracestate"));
            } else {
                assert_eq!(headers.get_all("traceparent").iter().count(), 2);
                assert_eq!(headers["tracestate"], "vendor=stale");
            }
        }
        server.abort();
    }
}
