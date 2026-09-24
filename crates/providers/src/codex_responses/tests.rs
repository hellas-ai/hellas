use super::*;
use hellas_rpc::fetch::{decode_fetch_event_payload, decode_fetch_terminal_payload};
use hellas_rpc::{Digest, InputCommitment};
use serde_json::json;

fn call(value: JsonValue) -> FetchCall {
    FetchCall::new(
        "codex",
        "responses",
        JsonBytes::new(serde_json::to_vec(&value).unwrap()),
        InputCommitment::from_digest(Digest::from_bytes([9; 32])),
    )
}

fn request(input: Vec<JsonValue>) -> JsonValue {
    json!({
        "model": "gpt-5.5-codex",
        "instructions": "be concise",
        "input": input,
        "tools": [
            {
                "type": "function",
                "name": "exec_command",
                "description": "run",
                "strict": false,
                "parameters": {"type":"object"}
            },
            {
                "type": "custom",
                "name": "apply_patch",
                "description": "patch",
                "format": {"type":"grammar","syntax":"lark","definition":"start: /.+/"}
            },
            {
                "type": "function",
                "name": "calendar_create",
                "description": "Create an event",
                "strict": false,
                "defer_loading": true,
                "parameters": {"type":"object"}
            },
            {
                "type": "tool_search",
                "execution": "client",
                "description": "find tools",
                "parameters": {"type":"object"}
            },
            {"type":"web_search","external_web_access":false}
        ],
        "tool_choice": "auto",
        "parallel_tool_calls": true,
        "reasoning": {"effort":"medium","summary":"auto","context":"current_turn"},
        "store": false,
        "stream": true,
        "include": ["reasoning.encrypted_content"],
        "prompt_cache_key": "cache-1",
        "text": {"verbosity":"low"},
        "client_metadata": {"cwd":"/secret/local/path"}
    })
}

fn sse(events: &[JsonValue]) -> Vec<u8> {
    let mut out = String::new();
    for event in events {
        let kind = event["type"].as_str().unwrap();
        out.push_str("event: ");
        out.push_str(kind);
        out.push_str("\ndata: ");
        out.push_str(&serde_json::to_string(event).unwrap());
        out.push_str("\n\n");
    }
    out.into_bytes()
}

fn response_events() -> Vec<JsonValue> {
    vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({
            "type":"response.output_item.done",
            "item":{
                "type":"reasoning",
                "id":"rs_1",
                "summary":[{"type":"summary_text","text":"thinking"}],
                "content":[{"type":"reasoning_text","text":"private"}],
                "encrypted_content":"opaque-ciphertext"
            }
        }),
        json!({
            "type":"response.output_item.done",
            "item":{
                "type":"function_call",
                "id":"fc_1",
                "call_id":"call_1",
                "name":"exec_command",
                "arguments":"{\"cmd\":\"pwd\"}"
            }
        }),
        json!({
            "type":"response.completed",
            "response":{
                "id":"resp_1",
                "usage":{
                    "input_tokens":10,
                    "input_tokens_details":{"cached_tokens":4,"cache_write_tokens":2},
                    "output_tokens":5,
                    "output_tokens_details":{"reasoning_tokens":3},
                    "total_tokens":15,
                    "codex_rollout_budget_units":2.5
                },
                "usage_metadata":{"amount":"0.01"},
                "end_turn":false
            }
        }),
    ]
}

#[test]
fn request_is_fresh_built_strips_local_metadata_and_disabled_web_search() {
    let prepared = prepare_request(&call(request(vec![json!({
        "type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]
    })])))
    .unwrap();
    let body: JsonValue = serde_json::from_slice(prepared.body.as_bytes()).unwrap();
    assert!(body.get("client_metadata").is_none());
    assert_eq!(body["prompt_cache_key"], "cache-1");
    assert!(
        body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| tool["type"] != "web_search")
    );
}

#[test]
fn sparse_request_rebuilds_fixed_codex_stream_invariants() {
    let request = json!({
        "model": "gpt-5.5-codex",
        "input": [{
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "hi"}]
        }]
    });
    let prepared = prepare_request(&call(request)).unwrap();
    let body: JsonValue = serde_json::from_slice(prepared.body.as_bytes()).unwrap();
    assert_eq!(body["tool_choice"], "auto");
    assert_eq!(body["parallel_tool_calls"], true);
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert_eq!(body["include"], json!(["reasoning.encrypted_content"]));

    for (field, value) in [
        ("store", json!(true)),
        ("stream", json!(false)),
        ("include", json!([])),
    ] {
        let mut conflicting = body.clone();
        conflicting[field] = value;
        assert!(
            prepare_request(&call(conflicting)).is_err(),
            "accepted {field}"
        );
    }

    let mut caller_policy = body;
    caller_policy["tool_choice"] = json!("none");
    caller_policy["parallel_tool_calls"] = json!(false);
    let prepared = prepare_request(&call(caller_policy)).unwrap();
    let rebuilt: JsonValue = serde_json::from_slice(prepared.body.as_bytes()).unwrap();
    assert_eq!(rebuilt["tool_choice"], "none");
    assert_eq!(rebuilt["parallel_tool_calls"], false);
}

#[test]
fn request_rejects_provider_capabilities_and_enabled_web_search() {
    let mut value = request(Vec::new());
    value["service_tier"] = json!("priority");
    assert!(prepare_request(&call(value)).is_err());

    let mut value = request(Vec::new());
    value["access_programs"] = json!(["internal"]);
    assert!(prepare_request(&call(value)).is_err());

    let mut value = request(Vec::new());
    value["tools"][4]["external_web_access"] = json!(true);
    assert!(prepare_request(&call(value)).is_err());

    for (kind, content) in [
        (
            "input_image",
            json!({"type":"input_image","image_url":"data:image/png;base64,x"}),
        ),
        (
            "input_audio",
            json!({"type":"input_audio","audio_url":"data:audio/wav;base64,x"}),
        ),
    ] {
        let input = vec![json!({
            "type":"message","role":"user","content":[content]
        })];
        assert!(
            prepare_request(&call(request(input))).is_err(),
            "accepted {kind}"
        );
    }

    let input = vec![
        json!({
            "type":"function_call","call_id":"call_1",
            "name":"exec_command","arguments":"{}"
        }),
        json!({
            "type":"function_call_output","call_id":"call_1",
            "output":[{"type":"encrypted_content","encrypted_content":"cipher"}]
        }),
    ];
    assert!(prepare_request(&call(request(input))).is_err());
}

#[test]
fn two_turn_history_preserves_reasoning_and_all_local_tool_kinds() {
    let input = vec![
        json!({
            "type":"reasoning","id":"rs_1",
            "summary":[{"type":"summary_text","text":"thinking"}],
            "content":[{"type":"reasoning_text","text":"private"}],
            "encrypted_content":"opaque-ciphertext"
        }),
        json!({
            "type":"function_call","id":"fc_1","call_id":"call_1",
            "name":"exec_command","arguments":"{\"cmd\":\"pwd\"}"
        }),
        json!({
            "type":"function_call_output","call_id":"call_1","output":"/workspace"
        }),
        json!({
            "type":"custom_tool_call","call_id":"call_2",
            "name":"apply_patch","input":"*** Begin Patch\nraw\n*** End Patch"
        }),
        json!({
            "type":"custom_tool_call_output","call_id":"call_2",
            "name":"apply_patch","output":"Done"
        }),
        json!({
            "type":"tool_search_call","call_id":"search_1","status":"completed",
            "execution":"client","arguments":{"query":"calendar create","limit":1}
        }),
        json!({
            "type":"tool_search_output","call_id":"search_1","status":"completed",
            "execution":"client","tools":[{
                "type":"function","name":"calendar_create",
                "description":"Create an event","defer_loading":true,
                "parameters":{"type":"object"}
            }]
        }),
    ];
    let prepared = prepare_request(&call(request(input))).unwrap();
    let body: JsonValue = serde_json::from_slice(prepared.body.as_bytes()).unwrap();
    assert_eq!(body["input"][0]["encrypted_content"], "opaque-ciphertext");
    assert_eq!(body["input"][1]["arguments"], "{\"cmd\":\"pwd\"}");
    assert_eq!(body["input"][2]["output"], "/workspace");
    assert_eq!(
        body["input"][3]["input"],
        "*** Begin Patch\nraw\n*** End Patch"
    );
    assert_eq!(body["input"][6]["tools"][0]["name"], "calendar_create");

    let events = vec![
        json!({"type":"response.created","response":{"id":"resp_2"}}),
        json!({"type":"response.output_item.done","item":{
            "type":"function_call","call_id":"call_3","name":"calendar_create",
            "arguments":"{\"title\":\"Meeting\"}"
        }}),
        json!({"type":"response.completed","response":{
            "id":"resp_2","usage":{
                "input_tokens":1,"output_tokens":1,"total_tokens":2
            }
        }}),
    ];
    let mut projector = CodexProjector::new(prepared.contract);
    projector.project(&sse(&events)).unwrap();
    projector.finish().unwrap();
}

#[test]
fn sparse_official_lifecycle_round_trips_typed_items_and_fractional_usage() {
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    let mut projected = projector.project(&sse(&response_events())).unwrap();
    projected.extend(projector.finish().unwrap());
    let events = projected
        .iter()
        .filter_map(|event| match event {
            ProjectedFetch::Event(payload) => Some(decode_fetch_event_payload(payload).unwrap()),
            ProjectedFetch::Terminal(_) => None,
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        &events[1],
        OutputEvent::Adaptor(AdaptorEvent::CodexResponses(
            CodexResponsesEvent::OutputItemDone(CodexResponseItem::Reasoning {
                encrypted_content: Some(value), ..
            })
        )) if value == "opaque-ciphertext"
    ));
    assert!(matches!(
        events.last(),
        Some(OutputEvent::Adaptor(AdaptorEvent::CodexResponses(
            CodexResponsesEvent::Completed(CodexCompleted { usage, .. })
        ))) if usage.codex_rollout_budget_units.as_ref().map(ToString::to_string).as_deref() == Some("2.5")
    ));
    let terminal = projected
        .iter()
        .find_map(|event| match event {
            ProjectedFetch::Terminal(payload) => {
                Some(decode_fetch_terminal_payload(payload).unwrap())
            }
            ProjectedFetch::Event(_) => None,
        })
        .unwrap();
    assert_eq!(terminal.billable_units(), 5);
}

#[test]
fn current_codex_snapshot_presentation_fields_are_explicitly_ignored() {
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let events = vec![
        json!({"type":"response.created","response":{
            "id":"resp_live","object":"response","created_at":42,"status":"in_progress",
            "background":false,"completed_at":null,"error":null,"frequency_penalty":0,
            "incomplete_details":null,"instructions":"hi","max_output_tokens":null,
            "parallel_tool_calls":true,"presence_penalty":0,"previous_response_id":null,
            "prompt_cache_key":null,"prompt_cache_retention":"in_memory","reasoning":{},
            "safety_identifier":null,"service_tier":"default","store":false,"temperature":1,
            "text":{"format":{"type":"text"}},"tool_choice":"auto","tools":[],
            "top_logprobs":0,"top_p":1,"truncation":"disabled","usage":null,"user":null,
            "metadata":{},"output":[]
        }}),
        json!({"type":"response.output_item.added","output_index":0,"item":{
            "type":"message","id":"msg_live","role":"assistant","status":"in_progress",
            "content":[]
        }}),
        json!({"type":"response.output_text.delta","item_id":"msg_live","output_index":0,
            "content_index":0,"delta":"ok","logprobs":[],"obfuscation":"opaque"}),
        json!({"type":"response.content_part.done","item_id":"msg_live","output_index":0,
            "content_index":0,"part":{"type":"output_text","text":"ok","annotations":[],"logprobs":[]}}),
        json!({"type":"response.output_item.done","output_index":0,"item":{
            "type":"message","id":"msg_live","role":"assistant","status":"completed",
            "content":[{"type":"output_text","text":"ok","annotations":[],"logprobs":[]}]
        }}),
        json!({"type":"response.completed","response":{
            "id":"resp_live","object":"response","created_at":42,"status":"completed",
            "model":"gpt-5.5-codex","output":[{"type":"message","id":"msg_live"}],
            "background":false,"completed_at":43,"error":null,"frequency_penalty":0,
            "incomplete_details":null,"instructions":"hi","max_output_tokens":null,
            "parallel_tool_calls":true,"presence_penalty":0,"previous_response_id":null,
            "prompt_cache_key":null,"prompt_cache_retention":"in_memory","reasoning":{},
            "safety_identifier":null,"service_tier":"default","store":false,"temperature":1,
            "text":{"format":{"type":"text"}},"tool_choice":"auto","tools":[],
            "top_logprobs":0,"top_p":1,"truncation":"disabled","user":null,"metadata":{},
            "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}
        }}),
    ];
    let mut projector = CodexProjector::new(prepared.contract);
    projector.project(&sse(&events)).unwrap();
    projector.finish().unwrap();
}

#[test]
fn sparse_message_without_item_id_is_preserved() {
    let events = vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({
            "type":"response.output_item.done",
            "item":{
                "type":"message","role":"assistant",
                "content":[{"type":"output_text","text":"hello"}]
            }
        }),
        json!({
            "type":"response.completed",
            "response":{"id":"resp_1","usage":{
                "input_tokens":1,"output_tokens":1,"total_tokens":2
            }}
        }),
    ];
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    let projected = projector.project(&sse(&events)).unwrap();
    assert!(projected.iter().any(|event| {
        let ProjectedFetch::Event(payload) = event else {
            return false;
        };
        matches!(
            decode_fetch_event_payload(payload).unwrap(),
            OutputEvent::Adaptor(AdaptorEvent::CodexResponses(
                CodexResponsesEvent::OutputItemDone(CodexResponseItem::Message { id: None, .. })
            ))
        )
    }));
    projector.finish().unwrap();
}

#[test]
fn sparse_done_item_without_id_pairs_only_one_pending_item() {
    let events = vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({
            "type":"response.output_item.added",
            "item":{
                "type":"message","id":"msg_1","role":"assistant","content":[]
            }
        }),
        json!({
            "type":"response.output_item.done",
            "item":{
                "type":"message","role":"assistant",
                "content":[{"type":"output_text","text":"hello"}]
            }
        }),
        json!({
            "type":"response.completed",
            "response":{"id":"resp_1","usage":{
                "input_tokens":1,"output_tokens":1,"total_tokens":2
            }}
        }),
    ];
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    let projected = projector.project(&sse(&events)).unwrap();
    assert!(projected.iter().any(|event| {
        let ProjectedFetch::Event(payload) = event else {
            return false;
        };
        matches!(
            decode_fetch_event_payload(payload).unwrap(),
            OutputEvent::Adaptor(AdaptorEvent::CodexResponses(
                CodexResponsesEvent::OutputItemDone(CodexResponseItem::Message {
                    id: None,
                    content,
                    ..
                })
            )) if content == vec![CodexMessageContent::OutputText { text: "hello".to_string() }]
        )
    }));
    projector.finish().unwrap();
}

#[test]
fn sparse_done_item_rejects_ambiguous_or_mismatched_pending_identity() {
    let ambiguous = vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({"type":"response.output_item.added","item":{
            "type":"message","id":"msg_1","role":"assistant","content":[]
        }}),
        json!({"type":"response.output_item.added","item":{
            "type":"message","id":"msg_2","role":"assistant","content":[]
        }}),
        json!({"type":"response.output_item.done","item":{
            "type":"message","role":"assistant",
            "content":[{"type":"output_text","text":"hello"}]
        }}),
    ];
    let mismatched = vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({"type":"response.output_item.added","item":{
            "type":"message","id":"msg_1","role":"assistant","content":[]
        }}),
        json!({"type":"response.output_item.done","item":{
            "type":"message","id":"msg_2","role":"assistant",
            "content":[{"type":"output_text","text":"hello"}]
        }}),
    ];
    for (events, expected) in [
        (ambiguous, "ambiguously matched"),
        (mismatched, "contradicted output_item.added"),
    ] {
        let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
        let mut projector = CodexProjector::new(prepared.contract);
        let error = projector.project(&sse(&events)).unwrap_err().to_string();
        assert!(error.contains(expected), "unexpected error: {error}");
    }
}

#[test]
fn tool_search_call_is_projected_without_losing_its_client_contract() {
    let events = vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({
            "type":"response.output_item.done",
            "item":{
                "type":"tool_search_call","id":"ts_1","call_id":"search_1",
                "status":"completed","execution":"client",
                "arguments":{"query":"calendar create","limit":1}
            }
        }),
        json!({
            "type":"response.completed",
            "response":{"id":"resp_1","usage":{
                "input_tokens":1,"output_tokens":1,"total_tokens":2
            }}
        }),
    ];
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    let projected = projector.project(&sse(&events)).unwrap();
    assert!(projected.iter().any(|event| {
        let ProjectedFetch::Event(payload) = event else {
            return false;
        };
        matches!(
            decode_fetch_event_payload(payload).unwrap(),
            OutputEvent::Adaptor(AdaptorEvent::CodexResponses(
                CodexResponsesEvent::OutputItemDone(CodexResponseItem::ToolSearchCall {
                    id: Some(id),
                    call_id,
                    status: Some(CodexItemStatus::Completed),
                    arguments: CodexToolSearchArguments { query, limit: Some(1) },
                })
            )) if id == "ts_1" && call_id == "search_1" && query == "calendar create"
        )
    }));
    projector.finish().unwrap();
}

#[test]
fn projection_is_independent_of_every_byte_split() {
    let bytes = sse(&response_events());
    let expected = {
        let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
        let mut projector = CodexProjector::new(prepared.contract);
        let mut output = projector.project(&bytes).unwrap();
        output.extend(projector.finish().unwrap());
        output
    };
    for split in 0..=bytes.len() {
        let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
        let mut projector = CodexProjector::new(prepared.contract);
        let mut output = projector.project(&bytes[..split]).unwrap();
        output.extend(projector.project(&bytes[split..]).unwrap());
        output.extend(projector.finish().unwrap());
        assert_eq!(output, expected, "split at byte {split}");
    }
}

#[test]
fn post_terminal_bytes_comments_and_whitespace_are_rejected() {
    for suffix in [b" ".as_slice(), b"\n".as_slice(), b": ping\n\n".as_slice()] {
        let mut bytes = sse(&response_events());
        bytes.extend_from_slice(suffix);
        let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
        let mut projector = CodexProjector::new(prepared.contract);
        assert!(projector.project(&bytes).is_err());
    }

    let mut unterminated = sse(&response_events());
    unterminated.truncate(unterminated.len() - 2);
    unterminated.extend_from_slice(b"\n: late comment");
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    projector.project(&unterminated).unwrap();
    assert!(projector.finish().is_err());
}

#[test]
fn sealed_sse_requires_one_delimited_event_and_one_data_line_per_frame() {
    let mut unterminated = sse(&response_events());
    unterminated.truncate(unterminated.len() - 2);
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    projector.project(&unterminated).unwrap();
    let error = projector.finish().unwrap_err().to_string();
    assert!(error.contains("blank-line frame delimiter"));

    let data = json!({"type":"response.created","response":{"id":"resp_1"}});
    let split_json = serde_json::to_string(&data).unwrap();
    let split_at = split_json.find("\"response\"").unwrap();
    let noncanonical = format!(
        "event: response.created\ndata: {}\ndata: {}\n\n",
        &split_json[..split_at],
        &split_json[split_at..]
    );
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    let error = projector
        .project(noncanonical.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(error.contains("non-canonical SSE framing"));
}

#[test]
fn contract_rejects_undeclared_duplicate_and_invalid_function_calls() {
    let cases = [
        json!({"type":"response.output_item.done","item":{
            "type":"function_call","call_id":"x","name":"undeclared","arguments":"{}"
        }}),
        json!({"type":"response.output_item.done","item":{
            "type":"function_call","call_id":"x","name":"exec_command","arguments":"not-json"
        }}),
    ];
    for item in cases {
        let events = vec![json!({"type":"response.created","response":{}}), item];
        let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
        let mut projector = CodexProjector::new(prepared.contract);
        assert!(projector.project(&sse(&events)).is_err());
    }
}

#[test]
fn deferred_tools_require_client_search_discovery_before_they_are_callable() {
    let direct = vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({"type":"response.output_item.done","item":{
            "type":"function_call","call_id":"call_1","name":"calendar_create","arguments":"{}"
        }}),
    ];
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    assert!(projector.project(&sse(&direct)).is_err());

    let discovered = request(vec![
        json!({"type":"tool_search_call","call_id":"search_1","status":"completed",
            "execution":"client","arguments":{"query":"calendar","limit":1}}),
        json!({"type":"tool_search_output","call_id":"search_1","status":"completed",
            "execution":"client","tools":[{"type":"function","name":"calendar_create",
            "description":"Create an event","parameters":{"type":"object"}}]}),
    ]);
    let prepared = prepare_request(&call(discovered)).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    let events = vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({"type":"response.output_item.done","item":{
            "type":"function_call","call_id":"call_1","name":"calendar_create","arguments":"{}"
        }}),
    ];
    assert!(projector.project(&sse(&events)).is_ok());
}

#[test]
fn model_head_and_lifecycle_claims_are_correlated_before_signing() {
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    projector
        .begin(FetchProviderResponseHead {
            effective_model: Some("routed-model".to_string()),
        })
        .unwrap();
    let events = vec![
        json!({"type":"response.created","response":{"id":"resp_1","model":"routed-model"}}),
        json!({"type":"response.completed","response":{"id":"resp_1","model":"routed-model","usage":{
            "input_tokens":1,"output_tokens":1,"total_tokens":2
        }}}),
    ];
    let projected = projector.project(&sse(&events)).unwrap();
    assert!(projected.iter().any(|event| matches!(event, ProjectedFetch::Event(payload)
        if matches!(decode_fetch_event_payload(payload).unwrap(),
            OutputEvent::Adaptor(AdaptorEvent::CodexResponses(CodexResponsesEvent::Completed(CodexCompleted { server_model: Some(ref model), .. }))) if model == "routed-model"))));

    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    projector
        .begin(FetchProviderResponseHead {
            effective_model: Some("header-model".to_string()),
        })
        .unwrap();
    let conflicting =
        vec![json!({"type":"response.created","response":{"id":"resp_1","model":"wire-model"}})];
    assert!(projector.project(&sse(&conflicting)).is_err());
}

#[test]
fn deltas_must_name_the_pending_item_they_mutate() {
    let events = vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({"type":"response.output_item.added","output_index":0,"item":{
            "type":"message","id":"msg_1","role":"assistant","content":[]
        }}),
        json!({"type":"response.output_text.delta","item_id":"msg_other","output_index":0,
            "content_index":0,"delta":"forged"}),
    ];
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    assert!(projector.project(&sse(&events)).is_err());
}

#[test]
fn interleaved_message_and_reasoning_deltas_remain_item_correlated() {
    let events = vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({"type":"response.output_item.added","output_index":0,"item":{
            "type":"message","id":"msg_1","role":"assistant","content":[]
        }}),
        json!({"type":"response.output_item.added","output_index":1,"item":{
            "type":"message","id":"msg_2","role":"assistant","content":[]
        }}),
        json!({"type":"response.output_text.delta","item_id":"msg_1","output_index":0,
            "content_index":0,"delta":"one"}),
        json!({"type":"response.output_text.delta","item_id":"msg_2","output_index":1,
            "content_index":0,"delta":"two"}),
        json!({"type":"response.content_part.done","item_id":"msg_1","output_index":0,
            "content_index":0,"part":{"type":"output_text","text":"one"}}),
        json!({"type":"response.output_item.done","output_index":0,"item":{
            "type":"message","id":"msg_1","role":"assistant",
            "content":[{"type":"output_text","text":"one"}]
        }}),
        json!({"type":"response.content_part.done","item_id":"msg_2","output_index":1,
            "content_index":0,"part":{"type":"output_text","text":"two"}}),
        json!({"type":"response.output_item.done","output_index":1,"item":{
            "type":"message","id":"msg_2","role":"assistant",
            "content":[{"type":"output_text","text":"two"}]
        }}),
        json!({"type":"response.output_item.added","output_index":2,"item":{
            "type":"reasoning","id":"rs_1","summary":[]
        }}),
        json!({"type":"response.output_item.added","output_index":3,"item":{
            "type":"reasoning","id":"rs_2","summary":[]
        }}),
        json!({"type":"response.reasoning_summary_text.delta","item_id":"rs_1",
            "output_index":2,"summary_index":0,"delta":"first"}),
        json!({"type":"response.reasoning_summary_text.delta","item_id":"rs_2",
            "output_index":3,"summary_index":0,"delta":"second"}),
        json!({"type":"response.output_item.done","output_index":2,"item":{
            "type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"first"}]
        }}),
        json!({"type":"response.output_item.done","output_index":3,"item":{
            "type":"reasoning","id":"rs_2","summary":[{"type":"summary_text","text":"second"}]
        }}),
        json!({"type":"response.completed","response":{"id":"resp_1","usage":{
            "input_tokens":1,"output_tokens":1,"total_tokens":2
        }}}),
    ];
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    projector.project(&sse(&events)).unwrap();
    projector.finish().unwrap();
}

#[test]
fn content_part_cannot_claim_another_message_delta() {
    let events = vec![
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({"type":"response.output_item.added","output_index":0,"item":{
            "type":"message","id":"msg_1","role":"assistant","content":[]
        }}),
        json!({"type":"response.output_item.added","output_index":1,"item":{
            "type":"message","id":"msg_2","role":"assistant","content":[]
        }}),
        json!({"type":"response.output_text.delta","item_id":"msg_1","output_index":0,
            "content_index":0,"delta":"forged"}),
        json!({"type":"response.content_part.done","item_id":"msg_2","output_index":1,
            "content_index":0,"part":{"type":"output_text","text":"forged"}}),
    ];
    let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
    let mut projector = CodexProjector::new(prepared.contract);
    assert!(projector.project(&sse(&events)).is_err());
}

#[test]
fn excluded_codex_extensions_and_malformed_identities_fail_closed() {
    let mut unsafe_request = request(Vec::new());
    unsafe_request["safety_buffering"] = json!(false);
    assert!(
        prepare_request(&call(unsafe_request))
            .err()
            .expect("safety_buffering request must be rejected")
            .to_string()
            .contains("safety_buffering")
    );

    let cases = [
        (
            "present field must not be null",
            json!({"type":"response.created","response":{"id":null}}),
        ),
        (
            "safety_buffering",
            json!({
                "type":"response.output_item.done","safety_buffering":false,
                "item":{"type":"message","role":"assistant","content":[]}
            }),
        ),
        (
            "namespace",
            json!({
                "type":"response.output_item.done",
                "item":{
                    "type":"function_call","call_id":"call_1","name":"exec_command",
                    "arguments":"{}","namespace":"internal"
                }
            }),
        ),
        (
            "internal_chat_message_metadata_passthrough",
            json!({
                "type":"response.output_item.done",
                "item":{
                    "type":"message","role":"assistant","content":[],
                    "internal_chat_message_metadata_passthrough":{}
                }
            }),
        ),
        (
            "unsupported sealed Codex SSE event",
            json!({"type":"response.metadata","response":{"id":"resp_1"}}),
        ),
    ];
    for (label, event) in cases {
        let events = if event["type"] == "response.created" {
            vec![event]
        } else {
            vec![
                json!({"type":"response.created","response":{"id":"resp_1"}}),
                event,
            ]
        };
        let prepared = prepare_request(&call(request(Vec::new()))).unwrap();
        let mut projector = CodexProjector::new(prepared.contract);
        let error = projector.project(&sse(&events)).unwrap_err().to_string();
        assert!(
            error.contains(label),
            "unexpected error for {label}: {error}"
        );
    }
}
