// Adapted from catgrad-llm ac0e432 (MIT); model-independent chat parsing.
//! JSON object-or-array payload codec.
//!
//! Wire shape: either
//!
//! - `[{"name": "...", "arguments": {...}}, ...]` — array of call
//!   objects (Granite, Mistral, Phi-4-mini, SmolLM2 list form), or
//! - `{"name": "...", "arguments": {...}}` — bare object, accepted as
//!   a single-call payload (Granite, Mistral, Phi-4-mini), or
//! - `[]` — empty array. Behavior depends on
//!   [`JsonCodecOptions::empty_array_is_zero_calls`]: a "no calls"
//!   signal (SmolLM2's `<tool_call>[]</tool_call>` reply) or a fatal
//!   "model committed but emitted nothing" error (Granite).
//!
//! Per-call shape concessions:
//! - `name`: required string.
//! - `arguments` OR `parameters`: optional, defaults to `{}`. Either
//!   key works — OpenAI vs Anthropic naming difference, tolerated
//!   everywhere.
//! - `arguments` may be a JSON-encoded string (the OpenAI legacy
//!   shape from `function_call.arguments`); the codec re-parses it.
//! - `arguments` after decoding must be a JSON object.
//! - When [`JsonCodecOptions::peel_spec_shape_echo`] is set, the codec
//!   peels `{"type":"function","function":{...}}` wrappers before
//!   extracting `name`/`arguments`. Models occasionally echo back the
//!   tool-spec shape (notably llama.cpp's auto-generated grammar);
//!   this lets Hermes-family parsers recover instead of failing.

use serde_json::{Map as JsonMap, Value as JsonValue};

use super::super::event::ParserError;
use super::super::sentinel_engine::{CodecOutcome, DecodedCall, PayloadCodec};

/// Per-codec policy switches. The space of variations across in-tree
/// protocols is small enough that a struct of bools is cleaner than
/// per-protocol codec types — and makes the variation axes obvious.
#[derive(Debug, Clone, Copy)]
pub struct JsonCodecOptions {
    /// Empty array `[]` produces zero calls (no error). SmolLM2's
    /// `<tool_call>[]</tool_call>` "no tool needed" reply is the
    /// canonical use. Default `false` (Granite-style: empty array is
    /// a malformed payload).
    pub empty_array_is_zero_calls: bool,
    /// Peel `{"type":"function","function":{...}}` wrappers and
    /// `{"type":"function","function":"NAME","parameters":{...}}`
    /// variants. Models occasionally echo back the OpenAI tool-spec
    /// shape (Llama-3.2-1B-Instruct does this for one variant);
    /// peeling lets the same code path recover. Default `false`
    /// (Granite-style: spec-shape echo is malformed).
    pub peel_spec_shape_echo: bool,
}

impl JsonCodecOptions {
    /// Conservative: empty array is fatal, no spec-shape peel. Used by
    /// Granite, Mistral, Phi-4-mini.
    pub const STRICT: Self = Self {
        empty_array_is_zero_calls: false,
        peel_spec_shape_echo: false,
    };
    /// Hermes-family permissive: empty array → zero calls, spec-shape
    /// echo peeled. Used by SmolLM2 (and by Qwen3 / SmolLM3 once they
    /// migrate off `json_sentinel`).
    pub const PERMISSIVE: Self = Self {
        empty_array_is_zero_calls: true,
        peel_spec_shape_echo: true,
    };
}

pub struct JsonObjectOrArrayCodec {
    pub options: JsonCodecOptions,
}

impl JsonObjectOrArrayCodec {
    pub fn strict() -> Self {
        Self {
            options: JsonCodecOptions::STRICT,
        }
    }

    pub fn permissive() -> Self {
        Self {
            options: JsonCodecOptions::PERMISSIVE,
        }
    }
}

impl Default for JsonObjectOrArrayCodec {
    fn default() -> Self {
        Self::strict()
    }
}

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

        if items.is_empty() {
            if self.options.empty_array_is_zero_calls {
                return CodecOutcome::Calls(Vec::new());
            }
            return CodecOutcome::Error(ParserError::Malformed(
                "tool-call payload contained no calls".into(),
            ));
        }

        let mut calls = Vec::new();
        for item in items {
            match call_from_value(item, &self.options) {
                Ok((name, args)) => calls.push(DecodedCall { name, args }),
                Err(err) => return CodecOutcome::PartialThenError { calls, error: err },
            }
        }
        CodecOutcome::Calls(calls)
    }
}

fn call_from_value(
    value: JsonValue,
    options: &JsonCodecOptions,
) -> Result<(String, JsonValue), ParserError> {
    let mut obj = if options.peel_spec_shape_echo {
        match peel_spec_shape_echo(value) {
            Some(obj) => obj,
            None => {
                return Err(ParserError::Malformed(
                    "tool-call entry is not a JSON object".into(),
                ));
            }
        }
    } else {
        match value {
            JsonValue::Object(obj) => obj,
            _ => {
                return Err(ParserError::Malformed(
                    "tool-call entry is not a JSON object".into(),
                ));
            }
        }
    };

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

/// Try to peel a single layer of OpenAI tool-spec wrapper. Models
/// occasionally echo back `{"type":"function","function":{...}}` shapes
/// (notably llama.cpp's auto-generated grammar bug); this lets parsers
/// recover the inner call. We only peel at most once: deeper nesting
/// is almost always a hallucination, not a real call. Public so the
/// llama3 protocol module can reuse it for its bare-JSON dialect.
pub fn peel_spec_shape_echo(value: JsonValue) -> Option<JsonMap<String, JsonValue>> {
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
