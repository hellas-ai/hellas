//! Exercise actual metadata framing and independent async server dispatch.
#![cfg(feature = "otel")]

use bytes::Bytes;
use futures_util::StreamExt;
use hellas_rpc::{call, telemetry};
use hellas_wire::clock::DefaultClock;
use hellas_wire::metadata::Metadata;
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role};
use hellas_wire::{MethodMarker, ServiceMarker, StreamTransport};
use opentelemetry::trace::{SpanKind, TracerProvider};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
use tokio::sync::mpsc;
use tracing::Instrument;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

struct Pipe(mpsc::UnboundedSender<Bytes>, mpsc::UnboundedReceiver<Bytes>);
impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;
    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        self.0.send(bytes).map_err(std::io::Error::other)
    }
    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.1.recv().await)
    }
}

struct Service;
impl ServiceMarker for Service {
    const NAME: &'static str = "test.Trace";
    const ALPN: &'static str = "/test.Trace/1";
    const SERVICE_ID: u32 = 1;
}
#[derive(Clone, PartialEq, prost::Message)]
struct Message {
    #[prost(uint32, tag = "1")]
    value: u32,
}
struct Method;
impl MethodMarker for Method {
    type Service = Service;
    type Request = Message;
    type Response = Message;
    const NAME: &'static str = "Stream";
    const METHOD_ID: u32 = 2;
    const REQUEST_STREAMING: bool = false;
    const RESPONSE_STREAMING: bool = true;
}

#[tokio::test]
async fn remote_context_and_detached_job_share_trace_and_stream_lifetime() {
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test"))),
    );
    let (a_tx, a_rx) = mpsc::unbounded_channel();
    let (b_tx, b_rx) = mpsc::unbounded_channel();
    let client = MuxTransport::spawn::<8, _, _>(
        Role::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe(a_tx, b_rx),
        Default::default(),
    );
    let server = MuxTransport::spawn::<8, _, _>(
        Role::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe(b_tx, a_rx),
        Default::default(),
    );
    let server_dispatch = dispatch.clone();
    let serving = tokio::spawn(
        async move {
            let inbound = server.accept().await.unwrap().unwrap();
            assert!(inbound.headers.get("traceparent").is_some());
            assert!(inbound.headers.get("authorization").is_none());
            call::dispatch_server_streaming::<MuxTransport, Method, _, _, _>(
                inbound,
                |request| async move {
                    // Paid work leaves the RPC task, retaining the current parent.
                    let work = tracing::info_span!("paid.worker");
                    let result = tokio::spawn(
                        async move {
                            let child = tracing::info_span!("paid.compute");
                            async move { request }.instrument(child).await
                        }
                        .instrument(work)
                        .with_subscriber(tracing::dispatcher::get_default(Clone::clone)),
                    )
                    .await
                    .unwrap();
                    Ok(futures_util::stream::iter([Ok(result)]))
                },
            )
            .await
            .unwrap();
        }
        .with_subscriber(server_dispatch),
    );
    async {
        let mut incoming = Metadata::new();
        incoming.insert_text(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        );
        let http = tracing::info_span!("http.server");
        telemetry::set_remote_parent(&http, &incoming);
        async {
            let mut headers = Metadata::new();
            // Existing headers must be replaced, not duplicated.
            headers.insert_text("traceparent", "invalid-stale-context");
            let mut response =
                call::server_streaming::<_, Method>(&client, Message { value: 42 }, headers)
                    .await
                    .unwrap();
            assert_eq!(response.next().await.unwrap().unwrap().value, 42);
            assert!(response.next().await.is_none());
            serving.await.unwrap();
            assert!(
                !exporter
                    .get_finished_spans()
                    .unwrap()
                    .iter()
                    .any(|span| span.name == "test.Trace/Stream"
                        && span.span_kind == SpanKind::Client),
                "client span must remain alive until the terminal trailer is checked"
            );
            response.finish().unwrap();
        }
        .instrument(http)
        .await;
    }
    .with_subscriber(dispatch)
    .await;
    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    let named = |name: &str| spans.iter().find(|span| span.name == name).unwrap();
    let http = named("http.server");
    let client = spans
        .iter()
        .find(|span| span.span_kind == SpanKind::Client)
        .unwrap();
    let server = spans
        .iter()
        .find(|span| span.span_kind == SpanKind::Server)
        .unwrap();
    for span in [client, server] {
        assert_eq!(span.name, "test.Trace/Stream");
        for (key, value) in [
            ("rpc.system.name", "hellas"),
            ("rpc.method", "test.Trace/Stream"),
            ("rpc.response.status_code", "OK"),
        ] {
            assert!(
                span.attributes
                    .iter()
                    .any(|kv| kv.key.as_str() == key
                        && kv.value == opentelemetry::Value::from(value))
            );
        }
        assert!(
            !span
                .attributes
                .iter()
                .any(|kv| matches!(kv.key.as_str(), "rpc.system" | "rpc.service" | "error.type"))
        );
    }
    let worker = named("paid.worker");
    let compute = named("paid.compute");
    assert_eq!(
        http.span_context.trace_id().to_string(),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(http.parent_span_id.to_string(), "00f067aa0ba902b7");
    assert_eq!(client.parent_span_id, http.span_context.span_id());
    assert_eq!(server.parent_span_id, client.span_context.span_id());
    assert_eq!(worker.parent_span_id, server.span_context.span_id());
    assert_eq!(compute.parent_span_id, worker.span_context.span_id());
    assert!(
        spans
            .iter()
            .all(|span| span.span_context.trace_id() == http.span_context.trace_id())
    );
    provider.shutdown().unwrap();
}
