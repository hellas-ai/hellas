use super::*;
use crate::{ComputeEvent, WorkFetchStream, WorkGatewayError, WorkOutputStream, WorkShutdownError};
use hellas_rpc::output::{
    OutputEvent, StopReason, TextChannel, ToolCallArgumentsDelta, ToolCallEnd, ToolCallStart, Usage,
};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

struct RecordedFetch {
    request: Value,
    events: Vec<OutputEvent>,
    calls: AtomicUsize,
}

impl WorkExecutionBackend for RecordedFetch {
    fn fetch(&self, request: WorkFetchRequest) -> Result<WorkFetchStream, WorkGatewayError> {
        assert_eq!(request.provider, provider());
        assert_eq!(request.service, "openai");
        assert_eq!(request.method, "responses");
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).unwrap(),
            self.request
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Box::pin(futures::stream::iter(
            self.events.clone().into_iter().map(Ok),
        )))
    }

    fn run(
        &self,
        _: hellas_client::model::ComputeJob,
    ) -> Result<WorkOutputStream<ComputeEvent>, WorkGatewayError> {
        Err(WorkGatewayError::Unsupported)
    }

    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}

fn provider() -> iroh::EndpointId {
    iroh::SecretKey::from_bytes(&[9; 32]).public()
}

fn text(delta: &str, channel: TextChannel) -> OutputEvent {
    OutputEvent::TextDelta {
        index: 0,
        delta: delta.into(),
        channel,
    }
}

fn finished(stop_reason: StopReason) -> OutputEvent {
    OutputEvent::Finished {
        stop_reason,
        usage: Some(Usage {
            input_tokens: Some(3),
            output_tokens: Some(2),
            total_tokens: Some(5),
        }),
    }
}

async fn fixture(name: &str, request: Value, events: Vec<OutputEvent>, expected: &[u8]) {
    let work = Arc::new(RecordedFetch {
        request: request.clone(),
        events,
        calls: AtomicUsize::new(0),
    });
    let backend = FetchBackend {
        work: work.clone(),
        options: crate::ResponsesFetch {
            provider: provider(),
            service: "openai".into(),
            method: "responses".into(),
            overrides: serde_json::Map::new(),
            models: Vec::new(),
        },
    };
    let adaptor = OpenAiResponsesAdaptor;
    let (parsed, request) = super::super::dispatch::parse_backend_request(
        &adaptor,
        &Bytes::from(serde_json::to_vec(&request).unwrap()),
        "OpenAI Responses",
    )
    .unwrap();
    // Pin only rendering metadata; compare the actual SSE body without
    // parsing, normalizing, or reserializing any event bytes.
    let response = super::super::dispatch::backend_wire_response(
        true,
        adaptor,
        parsed,
        backend,
        request,
        RenderContext::new("resp-fixture", "msg-fixture", 1_700_000_000),
        "OpenAI Responses",
    )
    .await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(work.calls.load(Ordering::SeqCst), 1);
    assert_eq!(bytes.as_ref(), expected, "Fetch SSE fixture {name}");
}

#[tokio::test]
async fn text_fetch_sse_bytes() {
    fixture(
        "text",
        json!({"model":"fixture","input":"hello","stream":true,"store":false}),
        vec![
            text("Hello ", TextChannel::Output),
            text("κόσμε\n", TextChannel::Output),
            finished(StopReason::EndOfText),
        ],
        include_bytes!("../../tests/fixtures/fetch/text.sse"),
    )
    .await;
}

#[tokio::test]
async fn tool_fetch_sse_bytes() {
    fixture(
        "tool",
        json!({"model":"fixture","input":"weather?","stream":true,"store":false,
            "tools":[{"type":"function","name":"weather","parameters":{"type":"object"}}]}),
        vec![
            OutputEvent::ToolCallStart(ToolCallStart {
                index: 0,
                id: Some("call-fixture".into()),
                name: "weather".into(),
            }),
            OutputEvent::ToolCallArgumentsDelta(ToolCallArgumentsDelta {
                index: 0,
                delta: "{\"city\":".into(),
            }),
            OutputEvent::ToolCallArgumentsDelta(ToolCallArgumentsDelta {
                index: 0,
                delta: "\"Zürich\"}".into(),
            }),
            OutputEvent::ToolCallEnd(ToolCallEnd {
                index: 0,
                arguments: json!({"city":"Zürich"}),
            }),
            finished(StopReason::ToolCall),
        ],
        include_bytes!("../../tests/fixtures/fetch/tool.sse"),
    )
    .await;
}

#[tokio::test]
async fn limited_fetch_sse_bytes() {
    fixture(
        "limited",
        json!({"model":"fixture","input":"think","max_output_tokens":2,"stream":true,"store":false}),
        vec![
            text("Let me think.", TextChannel::Reasoning),
            text("Partial", TextChannel::Output),
            finished(StopReason::MaxOutputTokens),
        ],
        include_bytes!("../../tests/fixtures/fetch/limited.sse"),
    )
    .await;
}
