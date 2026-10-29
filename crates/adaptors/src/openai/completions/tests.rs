use super::*;
use crate::{Provenance, Usage, WireBody, WireEventData};

fn adaptor() -> OpenAiCompletionsAdaptor {
    OpenAiCompletionsAdaptor
}

fn raw(value: JsonValue) -> RawRequest {
    RawRequest::from_value(value).unwrap()
}

#[test]
fn parse_preserves_raw_request() {
    let request = adaptor()
        .parse(raw(json!({
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hello",
            "max_tokens": 16,
            "stream": true,
            "temperature": 0.7
        })))
        .unwrap();
    assert_eq!(request.model, "gpt-3.5-turbo-instruct");
    assert_eq!(request.prompt, "Hello");
    assert_eq!(request.max_tokens, Some(16));
    assert_eq!(request.stream, Some(true));
    assert_eq!(request.raw.value()["temperature"], 0.7);
}

#[test]
fn projection_sets_model_prompt_and_limit() {
    let request = adaptor()
        .parse(raw(json!({
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hello",
            "max_tokens": 16
        })))
        .unwrap();
    let execution = adaptor().to_execution_request(&request).unwrap();
    assert_eq!(execution.canonical.model.name, "gpt-3.5-turbo-instruct");
    assert_eq!(execution.canonical.input, Input::Text("Hello".to_string()));
    assert_eq!(execution.canonical.sampling.max_output_tokens, Some(16));
}

#[test]
fn render_response_uses_completion_shape() {
    let request = adaptor()
        .parse(raw(json!({
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hello"
        })))
        .unwrap();
    let result = ExecutionResult {
        output: vec![OutputItem::Text {
            text: " world".to_string(),
            channel: TextChannel::Output,
        }],
        usage: Some(Usage {
            input_tokens: Some(1),
            output_tokens: Some(2),
            total_tokens: Some(3),
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
            &request,
            result,
            RenderContext::new("cmpl-test", "cmpl-test", 123),
        )
        .unwrap();
    assert_eq!(response.status, 200);
    let WireBody::Json(body) = response.body else {
        panic!("expected json body");
    };
    assert_eq!(body["object"], "text_completion");
    assert_eq!(body["choices"][0]["text"], " world");
    assert_eq!(body["usage"]["total_tokens"], 3);
    assert_eq!(
        body["hellas"],
        json!({"commitment": "aa".repeat(32), "provider": "secp256k1:02", "transcript": "c2lnbmVk"})
    );
}

#[test]
fn parse_project_render_uses_projected_request() {
    let request = adaptor()
        .parse(raw(json!({
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hello",
            "stream": false,
            "temperature": 0.7
        })))
        .unwrap();
    adaptor().to_execution_request(&request).unwrap();

    let response = adaptor()
        .render_response(
            &request,
            ExecutionResult {
                output: vec![OutputItem::Text {
                    text: " world".to_string(),
                    channel: TextChannel::Output,
                }],
                usage: None,
                stop_reason: StopReason::EndOfText,
                provenance: None,
                error: None,
            },
            RenderContext::new("cmpl-test", "cmpl-test", 123),
        )
        .unwrap();
    let WireBody::Json(body) = response.body else {
        panic!("expected json body");
    };
    assert_eq!(body["model"], request.model);
    assert_eq!(body["choices"][0]["text"], " world");
}

#[test]
fn render_stream_events_carry_provenance_in_chunks() {
    let request = adaptor()
        .parse(raw(json!({
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hello",
            "stream": true
        })))
        .unwrap();
    let mut state =
        adaptor().initial_state(&request, RenderContext::new("cmpl-test", "cmpl-test", 123));

    adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::Provenance(hellas_rpc::output::Provenance {
                call_commitment: Some("aa".repeat(32)),
            }),
        )
        .unwrap();
    let delta = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::TextDelta {
                index: 0,
                delta: " world".to_string(),
                channel: TextChannel::Output,
            },
        )
        .unwrap();
    let WireEventData::Json(delta_json) = &delta[0].data else {
        panic!("expected json delta");
    };
    assert_eq!(delta_json["choices"][0]["text"], " world");
    assert_eq!(delta_json["hellas"]["commitment"], "aa".repeat(32));

    adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::Provenance(hellas_rpc::output::Provenance {
                call_commitment: Some("aa".repeat(32)),
            }),
        )
        .unwrap();
    let finished = adaptor()
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::Finished {
                stop_reason: StopReason::EndOfText,
                usage: None,
            },
        )
        .unwrap();
    let WireEventData::Json(done_json) = &finished[0].data else {
        panic!("expected json terminal chunk");
    };
    assert_eq!(done_json["hellas"]["commitment"], "aa".repeat(32));
    assert!(matches!(finished[1].data, WireEventData::Text(ref text) if text == "[DONE]"));
}
