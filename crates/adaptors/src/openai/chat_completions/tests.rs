use super::*;
use crate::{Provenance, ResponseFormat, StopReason, WireEventData};

fn adaptor() -> OpenAiChatCompletionsAdaptor {
    OpenAiChatCompletionsAdaptor
}

fn raw(value: JsonValue) -> RawRequest {
    RawRequest::from_value(value).unwrap()
}

fn sample_request() -> ParsedChatCompletionRequest {
    adaptor()
        .parse(raw(json!({
            "model": "gpt-4.1-mini",
            "messages": [
                {"role": "system", "content": "Be precise."},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Add two numbers"}
                    ]
                }
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "add",
                    "description": "add two numbers",
                    "parameters": {"type": "object"}
                }
            }],
            "tool_choice": {"type": "function", "function": {"name": "add"}},
            "max_tokens": 32,
            "reasoning_effort": "low",
            "response_format": {"type": "json_object"},
            "temperature": 0.3,
            "top_p": 0.8,
            "top_logprobs": 2,
            "parallel_tool_calls": true,
            "stop": ["END"],
            "stream": true,
            "stream_options": {"include_usage": true},
            "metadata": {"trace": "abc"},
            "seed": 7
        })))
        .unwrap()
}

#[test]
fn parse_preserves_stream_options_and_raw_request() {
    let request = sample_request();
    assert_eq!(request.model, "gpt-4.1-mini");
    assert_eq!(request.messages.len(), 2);
    assert_eq!(request.tools.len(), 1);
    assert_eq!(request.reasoning_effort.as_deref(), Some("low"));
    assert_eq!(request.stream, Some(true));
    assert!(request.include_usage);
    assert_eq!(request.raw.value()["metadata"]["trace"], "abc");
    assert_eq!(request.raw.value()["seed"], 7);
}

#[test]
fn projection_sets_chat_execution_fields() {
    let execution = adaptor()
        .to_execution_request(&sample_request())
        .expect("chat request projects");
    assert_eq!(execution.canonical.model.name, "gpt-4.1-mini");
    assert_eq!(execution.canonical.sampling.max_output_tokens, Some(32));
    assert_eq!(execution.canonical.tools[0].name, "add");
    assert!(matches!(
        execution.canonical.tool_choice,
        ToolChoice::Tool { .. }
    ));
    assert!(matches!(
        execution.canonical.response_format,
        Some(ResponseFormat::JsonObject)
    ));
    assert!(execution.canonical.reasoning.is_some());
    assert!(matches!(execution.canonical.input, Input::Items(_)));
}

#[test]
fn max_completion_tokens_projects_as_output_limit() {
    let request = adaptor()
        .parse(raw(json!({
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "hi"}],
            "max_completion_tokens": 12
        })))
        .unwrap();
    let execution = adaptor().to_execution_request(&request).unwrap();
    assert_eq!(execution.canonical.sampling.max_output_tokens, Some(12));
}

#[test]
fn render_response_accepts_raw_assistant_message() {
    let result = ExecutionResult {
        output: vec![OutputItem::Raw(json!({
            "role": "assistant",
            "content": "done"
        }))],
        usage: Some(Usage {
            input_tokens: Some(3),
            output_tokens: Some(2),
            total_tokens: Some(5),
        }),
        stop_reason: StopReason::EndOfText,
        provenance: Some(Provenance {
            commitment: Some("aa".repeat(32)),
            provider: Some("secp256k1:02".into()),
            transcript: Some("c2lnbmVk".into()),
        }),
        error: None,
    };
    let response = adaptor()
        .render_response(
            &sample_request(),
            result,
            RenderContext::new("chatcmpl-test", "msg-test", 123),
        )
        .unwrap();
    assert_eq!(response.status, 200);
    let crate::WireBody::Json(body) = response.body else {
        panic!("expected json body");
    };
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["choices"][0]["message"]["content"], "done");
    assert_eq!(body["usage"]["prompt_tokens"], 3);
    assert_eq!(
        body["hellas"],
        json!({"commitment": "aa".repeat(32), "provider": "secp256k1:02", "transcript": "c2lnbmVk"})
    );
}

#[test]
fn parse_project_render_uses_projected_request() {
    let request = sample_request();
    adaptor().to_execution_request(&request).unwrap();

    let response = adaptor()
        .render_response(
            &request,
            ExecutionResult {
                output: vec![OutputItem::Text {
                    text: "done".to_string(),
                    channel: TextChannel::Output,
                }],
                usage: None,
                stop_reason: StopReason::EndOfText,
                provenance: None,
                error: None,
            },
            RenderContext::new("chatcmpl-test", "msg-test", 123),
        )
        .unwrap();
    let crate::WireBody::Json(body) = response.body else {
        panic!("expected json body");
    };
    assert_eq!(body["model"], request.model);
    assert_eq!(body["choices"][0]["message"]["content"], "done");
}

#[test]
fn stream_event_renders_usage_and_done() {
    let request = sample_request();
    let mut state = adaptor().initial_state(
        &request,
        RenderContext::new("chatcmpl-test", "msg-test", 123),
    );
    let start = adaptor()
        .render_stream_start(&request, &mut state)
        .expect("start renders");
    assert_eq!(start.len(), 1);
    let events = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::Finished {
                stop_reason: StopReason::MaxOutputTokens,
                usage: Some(Usage {
                    input_tokens: Some(1),
                    output_tokens: Some(2),
                    total_tokens: Some(3),
                }),
            },
        )
        .expect("finish renders");
    assert_eq!(events.len(), 3);
    match &events[0].data {
        WireEventData::Json(value) => {
            assert_eq!(value["choices"][0]["finish_reason"], "length");
        }
        _ => panic!("expected json event"),
    }
    match &events[1].data {
        WireEventData::Json(value) => {
            assert_eq!(value["usage"]["total_tokens"], 3);
        }
        _ => panic!("expected json event"),
    }
    assert_eq!(events[2].data, WireEventData::Text("[DONE]".to_string()));
}

#[test]
fn stream_tool_call_events_render_openai_chunks() {
    let request = sample_request();
    let mut state = adaptor().initial_state(
        &request,
        RenderContext::new("chatcmpl-test", "msg-test", 123),
    );
    let start = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::ToolCallStart(crate::ToolCallStart {
                index: 0,
                id: Some("call_1".to_string()),
                name: "lookup".to_string(),
            }),
        )
        .unwrap();
    let args = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::ToolCallArgumentsDelta(crate::ToolCallArgumentsDelta {
                index: 0,
                delta: "{\"query\":\"tea\"}".to_string(),
            }),
        )
        .unwrap();
    let end = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::ToolCallEnd(crate::ToolCallEnd {
                index: 0,
                arguments: json!({"query": "tea"}),
            }),
        )
        .unwrap();
    let finish = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::Finished {
                stop_reason: StopReason::ToolCall,
                usage: None,
            },
        )
        .unwrap();

    let WireEventData::Json(start_json) = &start[0].data else {
        panic!("expected tool start json");
    };
    assert_eq!(
        start_json["choices"][0]["delta"]["tool_calls"][0]["id"],
        "call_1"
    );
    assert_eq!(
        start_json["choices"][0]["delta"]["tool_calls"][0]["function"]["name"],
        "lookup"
    );
    assert_eq!(
        start_json["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
        ""
    );

    let WireEventData::Json(args_json) = &args[0].data else {
        panic!("expected tool arguments json");
    };
    assert_eq!(
        args_json["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
        "{\"query\":\"tea\"}"
    );

    assert!(end.is_empty());
    let WireEventData::Json(finish_json) = &finish[0].data else {
        panic!("expected finish json");
    };
    assert_eq!(finish_json["choices"][0]["finish_reason"], "tool_calls");
    assert_eq!(
        finish.last().unwrap().data,
        WireEventData::Text("[DONE]".to_string())
    );
}
