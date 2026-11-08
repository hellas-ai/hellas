pub mod audio_transcriptions;
pub mod chat_completions;
pub mod codex_responses;
pub mod completions;
pub mod images;
pub mod responses;

use serde_json::{Value as JsonValue, json};

/// A refusal or failure as the OpenAI APIs report it.
pub fn render_error(status: u16, message: String) -> crate::WireResponse {
    crate::WireResponse::json(status, error_json(message))
}

/// The body of an OpenAI error response.
pub fn error_json(message: impl Into<String>) -> JsonValue {
    json!({ "error": { "message": message.into() } })
}

/// A rejected request, with the HTTP status it is reported under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestError {
    pub status: u16,
    pub message: String,
}

impl RequestError {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

pub(super) fn project_response_format(value: &JsonValue) -> crate::ResponseFormat {
    match value.get("type").and_then(JsonValue::as_str) {
        Some("text") => crate::ResponseFormat::Text,
        Some("json_object") => crate::ResponseFormat::JsonObject,
        Some("json_schema") => {
            let schema_object = value.get("json_schema").unwrap_or(value);
            crate::ResponseFormat::JsonSchema {
                name: schema_object
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .map(ToString::to_string),
                schema: schema_object
                    .get("schema")
                    .cloned()
                    .unwrap_or_else(|| schema_object.clone()),
                strict: schema_object.get("strict").and_then(JsonValue::as_bool),
            }
        }
        _ => crate::ResponseFormat::Raw(value.clone()),
    }
}

pub(super) fn usage_json(usage: crate::Usage) -> JsonValue {
    let prompt_tokens = usage.input_tokens.unwrap_or(0);
    let completion_tokens = usage.output_tokens.unwrap_or(0);
    json!({
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": usage.total_tokens.unwrap_or_else(|| {
            prompt_tokens.saturating_add(completion_tokens)
        }),
    })
}

pub(super) fn finish_reason_json(stop_reason: crate::StopReason) -> JsonValue {
    let value = match stop_reason {
        crate::StopReason::EndOfText
        | crate::StopReason::StopSequence
        | crate::StopReason::Cancelled => "stop",
        crate::StopReason::MaxOutputTokens => "length",
        crate::StopReason::ToolCall => "tool_calls",
    };
    JsonValue::String(value.to_string())
}
