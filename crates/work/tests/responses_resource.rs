use hellas_work::model::grant::{resource::TemplateError, responses::*};
use serde_json::{Value, json};

fn resource() -> ResponsesResource {
    ResponsesResource {
        model: "fixture".into(),
        max_output_tokens: 8,
        settings: Default::default(),
    }
}
fn body() -> Value {
    json!({"model":"fixture","input":"private prompt","max_output_tokens":8})
}
fn check(resource: &ResponsesResource, body: Value) -> Result<(), TemplateError> {
    resource
        .matches(&serde_json::to_vec(&body).unwrap())
        .map(|_| ())
}

#[test]
fn exact_model_and_explicit_integral_generation_bound_are_required() {
    let policy = resource();
    for model in [
        json!(null),
        json!(3),
        json!("other"),
        json!("Fixture"),
        json!("fixture "),
    ] {
        let mut request = body();
        request["model"] = model;
        assert_eq!(check(&policy, request), Err(TemplateError::Model));
    }
    let mut request = body();
    request.as_object_mut().unwrap().remove("model");
    assert_eq!(check(&policy, request), Err(TemplateError::Model));
    for cap in [
        json!(null),
        json!(0),
        json!(-1),
        json!(8.0),
        json!(9),
        json!("8"),
        json!(u64::MAX),
    ] {
        let mut request = body();
        request["max_output_tokens"] = cap;
        assert_eq!(check(&policy, request), Err(TemplateError::GenerationCap));
    }
    let mut request = body();
    request.as_object_mut().unwrap().remove("max_output_tokens");
    assert_eq!(check(&policy, request), Err(TemplateError::GenerationCap));
    for cap in [1, 8] {
        let mut request = body();
        request["max_output_tokens"] = cap.into();
        assert_eq!(
            policy.matches(&serde_json::to_vec(&request).unwrap()),
            Ok(cap as u64)
        );
        assert_eq!(check(&policy, request), Ok(()));
    }
}

#[test]
fn restricted_defaults_deny_optional_settings_and_tool_history() {
    let policy = resource();
    assert_eq!(check(&policy, body()), Ok(()));
    for (key, value) in [
        ("temperature", json!(0.5)),
        ("top_p", json!(0.9)),
        ("tools", json!([])),
        ("tool_choice", json!("none")),
        ("parallel_tool_calls", json!(false)),
        ("truncation", json!("auto")),
        ("reasoning", json!({"effort":"low"})),
        ("reasoning", json!({"summary":"auto"})),
        ("reasoning", json!(null)),
        ("reasoning", json!({"unknown":true})),
        ("text", json!({"format":{"type":"json_object"}})),
        ("text", json!(null)),
        (
            "input",
            json!([{"type":"function_call","call_id":"a","name":"f","arguments":"{}"}]),
        ),
        (
            "input",
            json!([{"type":"function_call_output","call_id":"a","output":"result"}]),
        ),
    ] {
        let mut request = body();
        request[key] = value;
        assert_eq!(
            check(&policy, request),
            Err(TemplateError::Settings),
            "{key}"
        );
    }
    for value in [json!(null), json!(1), json!("disabled-ish")] {
        let mut request = body();
        request["truncation"] = value;
        assert_eq!(check(&policy, request), Err(TemplateError::Settings));
    }
    let mut request = body();
    request["truncation"] = json!("disabled");
    assert_eq!(check(&policy, request), Ok(()));
}

#[test]
fn configured_choices_require_explicit_supported_values() {
    let mut policy = resource();
    policy.settings = ResponsesSettings {
        temperature: true,
        top_p: true,
        tools: true,
        parallel_tool_calls: true,
        automatic_truncation: true,
        reasoning_efforts: [ReasoningEffort::Low].into(),
        reasoning_summaries: [ReasoningSummary::Concise].into(),
        output_formats: [ResponseFormat::JsonSchema].into(),
    };
    let mut request = body();
    request["reasoning"] = json!({"effort":"low","summary":"concise"});
    request["text"] =
        json!({"format":{"type":"json_schema","name":"answer","schema":{"type":"object"}}});
    request["temperature"] = json!(0.5);
    request["top_p"] = json!(0.9);
    request["tools"] = json!([]);
    request["tool_choice"] = json!("none");
    request["parallel_tool_calls"] = json!(false);
    request["truncation"] = json!("auto");
    assert_eq!(check(&policy, request.clone()), Ok(()));
    for field in ["effort", "summary"] {
        let mut missing = request.clone();
        missing["reasoning"].as_object_mut().unwrap().remove(field);
        assert_eq!(check(&policy, missing), Err(TemplateError::Settings));
        for wrong in [json!(null), json!("unknown"), json!("high"), json!("auto")] {
            let mut changed = request.clone();
            changed["reasoning"][field] = wrong;
            assert_eq!(check(&policy, changed), Err(TemplateError::Settings));
        }
    }
    request.as_object_mut().unwrap().remove("text");
    assert_eq!(check(&policy, request), Err(TemplateError::Settings));
}

#[test]
fn invalid_configuration_and_duplicate_or_oversized_json_fail_closed() {
    let policy = resource();
    for model in ["", "spaces here", "line\nbreak", "\0", &"x".repeat(257)] {
        let mut invalid = policy.clone();
        invalid.model = model.into();
        assert_eq!(invalid.validate(), Err(TemplateError::Model));
    }
    let mut invalid = policy.clone();
    invalid.max_output_tokens = 0;
    assert_eq!(invalid.validate(), Err(TemplateError::GenerationCap));
    invalid = policy.clone();
    invalid.settings.output_formats.clear();
    assert_eq!(invalid.validate(), Err(TemplateError::Settings));
    invalid = policy.clone();
    invalid.settings.parallel_tool_calls = true;
    assert_eq!(invalid.validate(), Err(TemplateError::Settings));
    assert!(serde_json::from_value::<ResponsesResource>(json!({"model":"fixture","max_output_tokens":8,"settings":{"reasoning_efforts":["invented"]}})).is_err());
    assert!(
        serde_json::from_value::<ResponsesResource>(
            json!({"model":"fixture","max_output_tokens":8,"settings":{"invented":true}})
        )
        .is_err()
    );
    for bytes in [
        br#"{"model":"fixture","model":"other","max_output_tokens":8}"#.as_slice(),
        br#"{"model":"fixture","max_output_tokens":8,"max_output_tokens":100}"#,
        br#"{"model":"fixture","max_output_tokens":8,"reasoning":{"effort":"low","effort":"high"}}"#,
        br#"{"model":"fixture","max_output_tokens":8,"input":{"x":1,"x":2}}"#,
        b"[]", b"{} {}",
    ] {
        assert_eq!(policy.matches(bytes), Err(TemplateError::Malformed));
    }
    let mut oversized = body();
    oversized["input"] = json!("x".repeat(hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES));
    assert_eq!(check(&policy, oversized), Err(TemplateError::Malformed));
}
