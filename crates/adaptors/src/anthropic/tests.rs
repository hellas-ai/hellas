use super::*;
use crate::{Provenance, Usage, WireBody, WireEventData};

fn adaptor() -> AnthropicMessagesAdaptor {
    AnthropicMessagesAdaptor
}

fn raw(value: JsonValue) -> RawRequest {
    RawRequest::from_value(value).unwrap()
}

fn sample_request() -> ParsedAnthropicMessageRequest {
    adaptor()
        .parse(raw(json!({
            "model": "claude-3-5-sonnet",
            "system": [{"type": "text", "text": "Be brief"}],
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": "Hi"}]
            }],
            "max_tokens": 32,
            "stream": true,
            "thinking": {"type": "enabled", "budget_tokens": 1024},
            "metadata": {"user_id": "u-1"},
            "temperature": 0.4
        })))
        .unwrap()
}

#[test]
fn parse_preserves_raw_request() {
    let request = sample_request();
    assert_eq!(request.model, "claude-3-5-sonnet");
    assert_eq!(request.max_tokens, 32);
    assert_eq!(request.stream, Some(true));
    assert_eq!(request.raw.value()["metadata"]["user_id"], "u-1");
    assert_eq!(request.raw.value()["temperature"], 0.4);
}

#[test]
fn projection_sets_messages_system_tokens_and_thinking() {
    let execution = adaptor()
        .to_execution_request(&sample_request())
        .expect("request projects");
    assert_eq!(execution.canonical.model.name, "claude-3-5-sonnet");
    assert_eq!(execution.canonical.sampling.max_output_tokens, Some(32));
    assert!(execution.canonical.reasoning.is_some());
    let Input::Items(items) = execution.canonical.input else {
        panic!("expected raw input items");
    };
    assert_eq!(items.len(), 2);
}

#[test]
fn render_response_accepts_raw_blocks() {
    let result = ExecutionResult {
        output: vec![OutputItem::Raw(json!([
            {"type": "text", "text": "done"}
        ]))],
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
            RenderContext::new("msg-test", "msg-test", 0),
        )
        .unwrap();
    assert_eq!(response.status, 200);
    let WireBody::Json(body) = response.body else {
        panic!("expected json body");
    };
    assert_eq!(body["type"], "message");
    assert_eq!(body["content"][0]["text"], "done");
    assert_eq!(body["usage"]["input_tokens"], 3);
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
            RenderContext::new("msg-test", "msg-test", 0),
        )
        .unwrap();
    let WireBody::Json(body) = response.body else {
        panic!("expected json body");
    };
    assert_eq!(body["model"], request.model);
    assert_eq!(body["content"][0]["text"], "done");
}

#[test]
fn stream_finish_renders_delta_and_stop() {
    let request = sample_request();
    let mut state =
        adaptor().initial_state(&request, RenderContext::new("msg-test", "msg-test", 0));
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
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].name.as_deref(), Some("message_delta"));
    assert_eq!(events[1].name.as_deref(), Some("message_stop"));
}

#[test]
fn stream_text_delta_opens_and_finish_closes_content_block() {
    let request = sample_request();
    let mut state =
        adaptor().initial_state(&request, RenderContext::new("msg-test", "msg-test", 0));

    let text = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::TextDelta {
                index: 0,
                delta: "hello".to_string(),
                channel: TextChannel::Output,
            },
        )
        .unwrap();
    let finish = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::Finished {
                stop_reason: StopReason::EndOfText,
                usage: None,
            },
        )
        .unwrap();

    assert_eq!(text[0].name.as_deref(), Some("content_block_start"));
    assert_eq!(text[1].name.as_deref(), Some("content_block_delta"));
    let WireEventData::Json(start_json) = &text[0].data else {
        panic!("expected content block start json");
    };
    assert_eq!(start_json["index"], 0);
    assert_eq!(start_json["content_block"]["type"], "text");
    let WireEventData::Json(delta_json) = &text[1].data else {
        panic!("expected content block delta json");
    };
    assert_eq!(delta_json["index"], 0);
    assert_eq!(delta_json["delta"]["text"], "hello");

    assert_eq!(finish[0].name.as_deref(), Some("content_block_stop"));
    assert_eq!(finish[1].name.as_deref(), Some("message_delta"));
    assert_eq!(finish[2].name.as_deref(), Some("message_stop"));
}

#[test]
fn stream_tool_call_events_render_anthropic_blocks() {
    let request = sample_request();
    let mut state =
        adaptor().initial_state(&request, RenderContext::new("msg-test", "msg-test", 0));

    let start = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::ToolCallStart(crate::ToolCallStart {
                index: 0,
                id: Some("toolu_1".to_string()),
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
                usage: Some(Usage {
                    input_tokens: Some(4),
                    output_tokens: Some(2),
                    total_tokens: Some(6),
                }),
            },
        )
        .unwrap();

    assert_eq!(start[0].name.as_deref(), Some("content_block_start"));
    let WireEventData::Json(start_json) = &start[0].data else {
        panic!("expected tool start json");
    };
    assert_eq!(start_json["content_block"]["type"], "tool_use");
    assert_eq!(start_json["content_block"]["id"], "toolu_1");
    assert_eq!(start_json["content_block"]["name"], "lookup");

    assert_eq!(args[0].name.as_deref(), Some("content_block_delta"));
    let WireEventData::Json(args_json) = &args[0].data else {
        panic!("expected tool arguments json");
    };
    assert_eq!(args_json["delta"]["type"], "input_json_delta");
    assert_eq!(args_json["delta"]["partial_json"], "{\"query\":\"tea\"}");

    assert_eq!(end[0].name.as_deref(), Some("content_block_stop"));
    let WireEventData::Json(finish_json) = &finish[0].data else {
        panic!("expected finish json");
    };
    assert_eq!(finish_json["delta"]["stop_reason"], "tool_use");
    assert_eq!(finish[1].name.as_deref(), Some("message_stop"));
}

#[test]
fn tools_and_tool_history_reach_canonical_execution() {
    let request = adaptor()
        .parse(raw(json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 64,
            "tools": [{
                "name": "bash",
                "description": "Run a command",
                "input_schema": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"]
                }
            }],
            "tool_choice": {"type": "any"},
            "messages": [
                {"role": "user", "content": "Check disk usage"},
                {"role": "assistant", "content": [
                    {"type": "text", "text": "Running."},
                    {"type": "tool_use", "id": "toolu_1", "name": "bash",
                     "input": {"command": "df -h"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1",
                     "content": "/: 40% used"}
                ]}
            ]
        })))
        .unwrap();
    let canonical = adaptor().to_execution_request(&request).unwrap().canonical;
    assert_eq!(canonical.tools.len(), 1);
    assert_eq!(canonical.tools[0].name, "bash");
    assert_eq!(canonical.tools[0].kind, ToolKind::Function);
    assert_eq!(
        canonical.tools[0].parameters["required"],
        json!(["command"])
    );
    assert_eq!(canonical.tool_choice, ToolChoice::Required);
    assert_eq!(
        canonical.input,
        Input::Items(vec![
            InputItem::Message(Message::text("user", "Check disk usage")),
            InputItem::Message(Message {
                role: "assistant".into(),
                content: vec![ContentPart::Text {
                    text: "Running.".into()
                }],
                name: None,
                tool_calls: vec![HistoricalToolCall {
                    id: "toolu_1".into(),
                    name: "bash".into(),
                    arguments: json!({"command": "df -h"}),
                }],
            }),
            InputItem::ToolResult {
                call_id: "toolu_1".into(),
                output: vec![ContentPart::Text {
                    text: "/: 40% used".into(),
                }],
            },
        ])
    );

    let response = adaptor()
        .render_response(
            &request,
            ExecutionResult {
                output: vec![OutputItem::ToolCall {
                    id: "toolu_2".into(),
                    name: "bash".into(),
                    arguments: json!({"command": "ls"}),
                }],
                usage: None,
                stop_reason: StopReason::ToolCall,
                provenance: None,
                error: None,
            },
            RenderContext::new("msg-test", "msg-test", 0),
        )
        .unwrap();
    let WireBody::Json(body) = response.body else {
        panic!("expected json body");
    };
    assert_eq!(body["stop_reason"], "tool_use");
    assert_eq!(
        body["content"][0],
        json!({"type": "tool_use", "id": "toolu_2", "name": "bash", "input": {"command": "ls"}})
    );

    let follow_up = adaptor()
        .parse(raw(json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 64,
            "messages": [
                {"role": "user", "content": "Check disk usage"},
                {"role": "assistant", "content": body["content"].clone()},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_2", "content": "bin"}
                ]}
            ]
        })))
        .unwrap();
    let canonical = adaptor()
        .to_execution_request(&follow_up)
        .unwrap()
        .canonical;
    assert!(matches!(
        canonical.input,
        Input::Items(items) if items.iter().any(|item| {
            matches!(item, InputItem::Message(message) if message.tool_calls.iter().any(|call| call.id == "toolu_2"))
        })
    ));
}

#[test]
fn text_blocks_preserve_one_message() {
    let parsed = adaptor()
        .parse(raw(json!({
            "model": "m", "max_tokens": 8,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "hello"},
                {"type": "text", "text": " world"}
            ]}]
        })))
        .unwrap();
    let canonical = adaptor().to_execution_request(&parsed).unwrap().canonical;
    let Input::Items(items) = canonical.input else {
        panic!("message items")
    };
    assert_eq!(items.len(), 1, "content blocks must not create chat turns");
}

#[test]
fn sampling_controls_reach_canonical_validation() {
    let parsed = adaptor()
        .parse(raw(json!({
            "model": "m", "max_tokens": 8,
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 0.4, "top_p": 0.8, "stop_sequences": ["END"]
        })))
        .unwrap();
    let canonical = adaptor().to_execution_request(&parsed).unwrap().canonical;
    assert_eq!(canonical.sampling.temperature, Some(0.4));
    assert_eq!(canonical.sampling.top_p, Some(0.8));
    assert_eq!(canonical.sampling.stop, ["END"]);
}

#[test]
fn tool_results_keep_references_order_and_following_user_text() {
    let parsed = adaptor().parse(raw(json!({
        "model": "m", "max_tokens": 8,
        "messages": [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "a", "content": [{"type":"text","text":"one"}]},
            {"type": "tool_result", "tool_use_id": "b"},
            {"type": "text", "text": "now "}, {"type": "text", "text": "continue"}
        ]}]
    }))).unwrap();
    let Input::Items(items) = adaptor()
        .to_execution_request(&parsed)
        .unwrap()
        .canonical
        .input
    else {
        panic!()
    };
    assert_eq!(items.len(), 3);
    assert!(
        matches!(&items[0], InputItem::ToolResult { call_id, output } if call_id == "a" && output.len() == 1)
    );
    assert!(
        matches!(&items[1], InputItem::ToolResult { call_id, output } if call_id == "b" && output.is_empty())
    );
    assert!(matches!(&items[2], InputItem::Message(message) if message.content.len() == 2));
}

#[test]
fn unsupported_history_semantics_are_rejected_during_parse() {
    for (role, content) in [
        (
            "assistant",
            json!([{"type":"tool_use","id":"a","name":"f","input":{}},{"type":"text","text":"after"}]),
        ),
        (
            "user",
            json!([{"type":"text","text":"before"},{"type":"tool_result","tool_use_id":"a","content":"ok"}]),
        ),
        (
            "user",
            json!([{"type":"tool_result","tool_use_id":"a","content":"","is_error":true}]),
        ),
        (
            "user",
            json!([{"type":"tool_result","tool_use_id":"a","content":[{"type":"image","text":"not text"}]}]),
        ),
        (
            "user",
            json!([{"type":"tool_use","id":"a","name":"f","input":{}}]),
        ),
    ] {
        assert!(
            adaptor()
                .parse(raw(
                    json!({"model":"m","max_tokens":8,"messages":[{"role":role,"content":content}]})
                ))
                .is_err(),
            "accepted {content}"
        );
    }
}

#[test]
fn execution_options_are_validated_but_metadata_is_preserved() {
    for (key, value) in [
        ("temperature", json!(1.1)),
        ("top_p", json!(-0.1)),
        ("stop_sequences", json!([5])),
        ("top_k", json!(4)),
        ("output_config", json!({"format":{"type":"json_schema"}})),
    ] {
        let mut body =
            json!({"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hello"}]});
        body[key] = value;
        assert!(adaptor().parse(raw(body)).is_err(), "accepted {key}");
    }
    let parsed = adaptor().parse(raw(json!({"model":"m","max_tokens":8,
        "messages":[{"role":"user","content":[{"type":"text","text":"hello","citations":[],"cache_control":{"type":"ephemeral"}}]}],
        "thinking":{"type":"disabled"}, "metadata":{"user_id":"test"}}))).unwrap();
    assert!(
        adaptor()
            .to_execution_request(&parsed)
            .unwrap()
            .canonical
            .reasoning
            .is_none()
    );
    assert_eq!(parsed.raw.value()["metadata"]["user_id"], "test");
}

/// Claude Code 2.1.316's first request of a session, as it was sent with
/// only long texts shortened.
const CLAUDE_CODE: &str = include_str!("../../tests/fixtures/agents/claude-code-messages.json");

fn text_of(content: &[ContentPart]) -> String {
    content
        .iter()
        .map(|part| match part {
            ContentPart::Text { text } => text.as_str(),
            other => panic!("non-text part {other:?}"),
        })
        .collect()
}

#[test]
fn claude_code_requests_project_to_one_system_prompt_and_its_offered_tools() {
    let request: JsonValue = serde_json::from_str(CLAUDE_CODE).unwrap();
    let parsed = adaptor().parse(raw(request.clone())).unwrap();
    let canonical = adaptor().to_execution_request(&parsed).unwrap().canonical;
    assert_eq!(canonical.sampling.max_output_tokens, Some(128_000));
    // Adaptive thinking leaves the choice to the model.
    assert!(canonical.reasoning.is_none());
    // The deferred placeholder is never shown to the model.
    let offered = request["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|tool| tool.get("defer_loading").is_none())
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        offered.len() + 1,
        request["tools"].as_array().unwrap().len()
    );
    assert_eq!(
        canonical
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        offered
    );
    // The system-role message follows the system blocks in the one system
    // prompt, ahead of the conversation.
    let Input::Items(items) = &canonical.input else {
        panic!("expected input items");
    };
    let [InputItem::Message(system), InputItem::Message(user)] = &items[..] else {
        panic!("expected a system prompt and one user turn: {items:?}");
    };
    assert_eq!(
        (system.role.as_str(), user.role.as_str()),
        ("system", "user")
    );
    let blocks = |value: &JsonValue| {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|block| block["text"].as_str().unwrap())
            .collect::<String>()
    };
    assert_eq!(
        text_of(&system.content),
        format!(
            "{}\n\n{}",
            blocks(&request["system"]),
            blocks(&request["messages"][1]["content"])
        )
    );
}

/// Controls that only steer thinking or effort are accepted; those that would
/// change the prompt or the output's form are refused.
#[test]
fn agent_controls_are_honoured_accepted_or_refused() {
    let parse = |key: &str, value: JsonValue| {
        let mut body =
            json!({"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hello"}]});
        body[key] = value;
        adaptor()
            .parse(raw(body))
            .map(|parsed| adaptor().to_execution_request(&parsed).unwrap().canonical)
    };
    for (key, value) in [
        ("output_config", json!({"effort": "high"})),
        (
            "context_management",
            json!({"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]}),
        ),
        (
            "thinking",
            json!({"type": "adaptive", "display": "updates"}),
        ),
    ] {
        let canonical = parse(key, value).unwrap_or_else(|error| panic!("{key}: {error}"));
        assert!(canonical.reasoning.is_none(), "{key}");
    }
    assert!(
        parse(
            "thinking",
            json!({"type": "enabled", "budget_tokens": 1024})
        )
        .unwrap()
        .reasoning
        .is_some()
    );
    for (key, value) in [
        ("output_config", json!({"format": {"type": "json_schema"}})),
        ("output_config", json!({"effort": 3})),
        (
            "context_management",
            json!({"edits": [{"type": "clear_tool_uses_20250919"}]}),
        ),
        ("thinking", json!({"type": "sometimes"})),
    ] {
        assert!(parse(key, value.clone()).is_err(), "accepted {key} {value}");
    }
}

/// A failure after the stream began carries the error type the same failure
/// has before it: a deterministic output failure is no server error.
#[test]
fn stream_errors_carry_the_type_of_their_status() {
    let request = sample_request();
    let mut state = adaptor().initial_state(&request, RenderContext::new("msg_1", "m", 0));
    let events = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::Error {
                message: "unusable model output".into(),
                code: adaptor().error_code(422),
            },
        )
        .unwrap();
    let WireEventData::Json(error) = &events.last().unwrap().data else {
        panic!("expected a JSON error event");
    };
    assert_eq!(error["error"]["type"], "invalid_request_error");
    let WireBody::Json(body) = render_error(422, "unusable model output".into()).body else {
        panic!("expected a JSON body");
    };
    assert_eq!(body["error"]["type"], "invalid_request_error");
    assert_eq!(adaptor().error_code(500).as_deref(), Some("api_error"));
}

/// A failed tool call's result reaches the model as its message, as an
/// OpenAI tool message would: Claude Code reports a failed write this way.
#[test]
fn error_tool_results_reach_the_model_as_their_message() {
    let parsed = adaptor()
        .parse(raw(json!({"model":"m","max_tokens":8,"messages":[
            {"role":"user","content":"write it"},
            {"role":"assistant","content":[{"type":"tool_use","id":"a","name":"Write","input":{}}]},
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"a",
                "content":"EACCES: permission denied","is_error":true}]}
        ]})))
        .unwrap();
    let Input::Items(items) = adaptor()
        .to_execution_request(&parsed)
        .unwrap()
        .canonical
        .input
    else {
        panic!("expected input items");
    };
    let Some(InputItem::ToolResult { call_id, output }) = items.last() else {
        panic!("expected a tool result: {items:?}");
    };
    assert_eq!(call_id, "a");
    assert_eq!(text_of(output), "EACCES: permission denied");
}
