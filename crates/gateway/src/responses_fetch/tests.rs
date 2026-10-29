use super::*;
use crate::{
    ExecutionEvent, WorkEvent, WorkFetchStream, WorkGatewayError, WorkOutputStream,
    WorkShutdownError,
};
use hellas_rpc::output::{
    OutputEvent, StopReason, TextChannel, ToolCallArgumentsDelta, ToolCallEnd, ToolCallStart, Usage,
};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

struct RecordedFetch {
    request: Value,
    events: Vec<WorkEvent<OutputEvent>>,
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

    fn generate(
        &self,
        _: hellas_client::text::TextJob,
    ) -> Result<WorkOutputStream<ExecutionEvent>, WorkGatewayError> {
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
        events: events.into_iter().map(WorkEvent::Output).collect(),
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

/// Responses over Fetch names the accepted job and its provider in headers
/// and on `response.created`, and hands over the signed transcript on
/// `response.completed` or in the body.
#[tokio::test]
async fn responses_carry_provenance_at_start_and_end() {
    use base64::Engine as _;
    use hellas_rpc::provenance::{COMMITMENT_KEY, ExecutionProvenance, PROVIDER_KEY};
    use tower::ServiceExt as _;

    let transcript = b"provider-signed transcript".to_vec();
    let commitment = "6b".repeat(32);
    let key = format!("secp256k1:{}", "03".repeat(33));
    let encoded = base64::engine::general_purpose::STANDARD.encode(&transcript);
    let start = json!({"commitment": commitment, "provider": key});
    let end = json!({"commitment": commitment, "provider": key, "transcript": encoded});
    for stream in [false, true] {
        let request = json!({"model": "fixture", "input": "hello", "stream": stream});
        let work = Arc::new(RecordedFetch {
            request: json!({"model": "fixture", "input": "hello", "stream": true, "store": false}),
            events: vec![
                WorkEvent::Accepted(ExecutionProvenance {
                    commitment_id: [0x6b; 32],
                    provider: hellas_auth::PublicKey::Secp256k1([0x03; 33]),
                }),
                WorkEvent::Output(text("Hello", TextChannel::Output)),
                WorkEvent::Transcript(transcript.clone()),
                WorkEvent::Output(finished(StopReason::EndOfText)),
            ],
            calls: AtomicUsize::new(0),
        });
        let app = router(
            crate::ResponsesFetch {
                provider: provider(),
                service: "openai".into(),
                method: "responses".into(),
                overrides: serde_json::Map::new(),
                models: Vec::new(),
            },
            work,
        )
        .layer(crate::provenance_layer::ProvenanceLayer);
        let response = app
            .oneshot(
                axum::http::Request::post(PATH)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(response.headers()[COMMITMENT_KEY], commitment.as_str());
        assert_eq!(response.headers()[PROVIDER_KEY], key.as_str());
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        if !stream {
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["hellas"], end);
            continue;
        }
        let events = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .map(|data| serde_json::from_str::<Value>(data).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events[0]["type"], "response.created");
        assert_eq!(events[0]["response"]["hellas"], start);
        let last = events.last().unwrap();
        assert_eq!(last["type"], "response.completed");
        assert_eq!(last["response"]["hellas"], end);
    }
}
