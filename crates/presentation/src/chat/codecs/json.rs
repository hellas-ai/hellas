// Adapted from catgrad-llm ac0e432 (MIT).
//! Qwen3 tool calls: JSON objects or lists inside a paired tool sentinel.
//! Preserve the supported permissive input shapes, including echoed tool-spec
//! wrappers and JSON-encoded arguments, without exposing unused dialect options.

use serde_json::{Map as JsonMap, Value as JsonValue};

use super::super::event::ParserError;
use super::super::sentinel_engine::{CodecOutcome, DecodedCall, PayloadCodec};

pub(in crate::chat) struct JsonObjectOrArrayCodec;

impl PayloadCodec for JsonObjectOrArrayCodec {
    fn parse(&self, payload: &str) -> CodecOutcome {
        let trimmed = payload.trim();
        if trimmed.is_empty() {
            return CodecOutcome::Error(ParserError::Malformed("empty tool-call payload".into()));
        }

        let value: JsonValue = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(err) => return CodecOutcome::Error(ParserError::from(err)),
        };

        let items = match value {
            JsonValue::Array(items) => items,
            JsonValue::Object(_) => vec![value],
            _ => {
                return CodecOutcome::Error(ParserError::Malformed(
                    "tool-call payload is not an object or array of objects".into(),
                ));
            }
        };

        let mut calls = Vec::new();
        for item in items {
            match call_from_value(item) {
                Ok((name, args)) => calls.push(DecodedCall { name, args }),
                Err(err) => return CodecOutcome::PartialThenError { calls, error: err },
            }
        }
        CodecOutcome::Calls(calls)
    }
}

fn call_from_value(value: JsonValue) -> Result<(String, JsonValue), ParserError> {
    let mut obj = peel_spec_shape_echo(value)
        .ok_or_else(|| ParserError::Malformed("tool-call entry is not a JSON object".into()))?;

    let name = match obj.remove("name") {
        Some(JsonValue::String(s)) => s,
        Some(_) => {
            return Err(ParserError::Malformed(
                "tool-call `name` is not a string".into(),
            ));
        }
        None => return Err(ParserError::MissingField("name")),
    };
    let args = obj
        .remove("arguments")
        .or_else(|| obj.remove("parameters"))
        .unwrap_or_else(|| JsonValue::Object(JsonMap::new()));
    let args = match args {
        JsonValue::String(encoded) => serde_json::from_str(&encoded).map_err(ParserError::from)?,
        other => other,
    };
    if !matches!(args, JsonValue::Object(_)) {
        return Err(ParserError::Malformed(
            "tool-call `arguments` must be an object".into(),
        ));
    }
    Ok((name, args))
}

/// Tolerate one echoed tool-spec wrapper around the generated call.
fn peel_spec_shape_echo(value: JsonValue) -> Option<JsonMap<String, JsonValue>> {
    let mut object = value.as_object()?.clone();
    let looks_like_wrapper = object
        .get("type")
        .and_then(JsonValue::as_str)
        .is_some_and(|s| s == "function")
        || object.contains_key("function");
    if !looks_like_wrapper {
        return Some(object);
    }
    if let Some(inner) = object.remove("function") {
        match inner {
            JsonValue::Object(inner_obj) => Some(inner_obj),
            JsonValue::String(name) => {
                let mut rebuilt = JsonMap::new();
                rebuilt.insert("name".into(), JsonValue::String(name));
                if let Some(args) = object.remove("arguments") {
                    rebuilt.insert("arguments".into(), args);
                } else if let Some(params) = object.remove("parameters") {
                    rebuilt.insert("parameters".into(), params);
                }
                Some(rebuilt)
            }
            _ => None,
        }
    } else {
        Some(object)
    }
}
