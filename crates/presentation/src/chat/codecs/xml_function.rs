// Adapted from catgrad-llm ac0e432 (MIT).
//! XML-style function-call codec.
//!
//! Wire shape (between sentinels):
//!
//! ```text
//! <function=NAME>
//!   <parameter=KEY1>VALUE1</parameter>
//!   <parameter=KEY2>VALUE2</parameter>
//! </function>
//! ```
//!
//! Used by Qwen3.5 and Nemotron / Nemotron-H — vLLM's
//! `qwen3_xml_tool_parser.py` and `nemotron_h_tool_parser.py` are the
//! reference implementations. Both protocols emit at most one call per
//! sentinel block.
//!
//! Values use JSON scalars unless the offered schema accepts the parameter as
//! text. The complete arguments are schema-checked before a call is emitted.

use super::super::ToolDirectory;
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::sync::Arc;

use super::super::event::ParserError;
use super::super::sentinel_engine::{CodecOutcome, DecodedCall, PayloadCodec};

const FUNCTION_OPEN: &str = "<function=";
const FUNCTION_CLOSE: &str = "</function>";
const PARAMETER_OPEN: &str = "<parameter=";
const PARAMETER_CLOSE: &str = "</parameter>";

#[derive(Default)]
pub struct XmlFunctionCodec {
    tools: Option<Arc<ToolDirectory>>,
}

impl XmlFunctionCodec {
    pub fn new(tools: Arc<ToolDirectory>) -> Self {
        Self { tools: Some(tools) }
    }
}

impl PayloadCodec for XmlFunctionCodec {
    fn parse(&self, payload: &str) -> CodecOutcome {
        let trimmed = payload.trim();
        if trimmed.is_empty() {
            return CodecOutcome::Error(ParserError::Malformed("empty tool-call payload".into()));
        }
        match parse_function_block_with_tools(trimmed, self.tools.as_deref()) {
            Ok((name, args)) => CodecOutcome::Calls(vec![DecodedCall { name, args }]),
            Err(err) => CodecOutcome::Error(err),
        }
    }
}

fn parse_function_block_with_tools(
    payload: &str,
    tools: Option<&ToolDirectory>,
) -> Result<(String, JsonValue), ParserError> {
    let header = payload.strip_prefix(FUNCTION_OPEN).ok_or_else(|| {
        ParserError::Malformed("tool-call payload must start with <function=...>".into())
    })?;
    let (name, body) = header
        .split_once('>')
        .ok_or_else(|| ParserError::Malformed("unterminated <function=...> tag".into()))?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(ParserError::MissingField("name"));
    }
    let body = body.strip_suffix(FUNCTION_CLOSE).ok_or_else(|| {
        ParserError::Malformed("tool-call payload must end with </function>".into())
    })?;
    let mut text_arguments = JsonMap::new();
    let mut rest = body.trim();
    while !rest.is_empty() {
        let block = rest
            .strip_prefix(PARAMETER_OPEN)
            .ok_or_else(|| ParserError::Malformed("unexpected content in function block".into()))?;
        let (key, value_text) = block
            .split_once('>')
            .ok_or_else(|| ParserError::Malformed("unterminated <parameter=...> tag".into()))?;
        let key = key.trim().to_string();
        if key.is_empty() || text_arguments.contains_key(&key) {
            return Err(ParserError::Malformed(
                "empty or duplicate tool-call parameter name".into(),
            ));
        }
        let (value, tail) = value_text.split_once(PARAMETER_CLOSE).ok_or_else(|| {
            ParserError::Malformed("missing </parameter> in tool-call payload".into())
        })?;
        text_arguments.insert(key, JsonValue::String(value.trim().to_string()));
        rest = tail.trim();
    }
    let mut arguments = JsonValue::Object(
        text_arguments
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    parse_scalar(value.as_str().expect("parameter text")),
                )
            })
            .collect(),
    );
    if let Some((_, validator)) = tools.and_then(|tools| tools.lookup(&name)) {
        let text = JsonValue::Object(text_arguments.clone());
        if validator.is_valid(&text) {
            return Ok((name, text));
        }
        // Let the compiled schema decide whether a value is text, including
        // references, allOf and union types. Ignore errors in other parameters
        // while considering this one; validate the complete object in the engine.
        for (key, text) in text_arguments {
            // Once the full object satisfies the schema, keep that solution.
            // An optional substitution could otherwise select a different
            // oneOf branch whose constraints conflict with earlier fields.
            if validator.is_valid(&arguments) {
                break;
            }
            let parsed = std::mem::replace(&mut arguments[&key], text);
            let pointer = format!("/{}", key.replace('~', "~0").replace('/', "~1"));
            let descendants = format!("{pointer}/");
            let invalid = validator
                .iter_errors(&arguments)
                .any(|error| rejects_parameter(&error, &pointer, &descendants));
            if invalid {
                arguments[&key] = parsed;
            }
        }
    }
    Ok((name, arguments))
}

// A root anyOf/oneOf failure may concern only another parameter. Inspect
// the validator's branch errors rather than treating that aggregate failure
// as rejection of every text value. The engine still validates the entire
// object, including relationships between fields, before emitting a call.
fn rejects_parameter(
    error: &jsonschema::ValidationError<'_>,
    pointer: &str,
    descendants: &str,
) -> bool {
    use jsonschema::error::ValidationErrorKind;
    match &error.kind {
        ValidationErrorKind::AnyOf { context } | ValidationErrorKind::OneOfNotValid { context } => {
            context.iter().all(|branch| {
                branch
                    .iter()
                    .any(|error| rejects_parameter(error, pointer, descendants))
            })
        }
        _ => {
            let path = error.instance_path.as_str();
            path.is_empty() || path == pointer || path.starts_with(descendants)
        }
    }
}

fn parse_scalar(text: &str) -> JsonValue {
    let trimmed = text.trim();
    serde_json::from_str(trimmed).unwrap_or_else(|_| JsonValue::String(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse_function_block(payload: &str) -> Result<(String, JsonValue), ParserError> {
        parse_function_block_with_tools(payload, None)
    }

    #[test]
    fn parse_scalar_promotes_json_values() {
        assert_eq!(parse_scalar("42"), json!(42));
        assert_eq!(parse_scalar("3.125"), json!(3.125));
        assert_eq!(parse_scalar("true"), json!(true));
        assert_eq!(parse_scalar("null"), json!(null));
        assert_eq!(parse_scalar("\"hi\""), json!("hi"));
        assert_eq!(parse_scalar("[1, 2, 3]"), json!([1, 2, 3]));
        assert_eq!(parse_scalar(r#"{"a": 1}"#), json!({"a": 1}));
    }

    #[test]
    fn parse_scalar_falls_back_to_string() {
        assert_eq!(parse_scalar("div"), json!("div"));
        assert_eq!(parse_scalar("  hello world  "), json!("hello world"));
        assert_eq!(parse_scalar("not json"), json!("not json"));
    }

    #[test]
    fn parse_function_block_extracts_name_and_args() {
        let (name, args) = parse_function_block(
            "<function=add><parameter=a>1</parameter><parameter=b>2</parameter></function>",
        )
        .unwrap();
        assert_eq!(name, "add");
        assert_eq!(args["a"], json!(1));
        assert_eq!(args["b"], json!(2));
    }

    #[test]
    fn parse_function_block_errors_on_missing_function_open() {
        assert!(parse_function_block("just text").is_err());
    }

    #[test]
    fn parse_function_block_errors_on_unclosed_function() {
        assert!(parse_function_block("<function=x><parameter=k>v</parameter>").is_err());
    }

    #[test]
    fn parse_function_block_errors_on_empty_name() {
        assert!(matches!(
            parse_function_block("<function=></function>"),
            Err(ParserError::MissingField("name"))
        ));
    }

    /// Decode through the codec, returning the single (name, args).
    fn decode_one(payload: &str) -> (String, JsonValue) {
        match XmlFunctionCodec::default().parse(payload) {
            CodecOutcome::Calls(mut calls) => {
                assert_eq!(calls.len(), 1, "expected one call");
                let c = calls.remove(0);
                (c.name, c.args)
            }
            other => panic!("expected Calls, got {other:?}"),
        }
    }

    fn decode_err(payload: &str) -> ParserError {
        match XmlFunctionCodec::default().parse(payload) {
            CodecOutcome::Error(e) => e,
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn valid_call_with_multiple_parameters() {
        let (name, args) = decode_one(
            "<function=greet>\n<parameter=name>\"Alice\"</parameter>\n<parameter=times>3</parameter>\n</function>",
        );
        assert_eq!(name, "greet");
        assert_eq!(args["name"], json!("Alice"));
        assert_eq!(args["times"], json!(3));
    }

    #[test]
    fn parameter_value_falls_back_to_bare_string() {
        // Unquoted string value — should fall back to bare-string
        // rather than raise a JSON parse error.
        let (_, args) = decode_one("<function=op><parameter=mode>div</parameter></function>");
        assert_eq!(args["mode"], json!("div"));
    }

    #[test]
    fn duplicate_parameters_and_unconsumed_content_are_rejected() {
        for payload in [
            "<function=f><parameter=x>1</parameter><parameter=x>2</parameter></function>",
            "prefix<function=f></function>",
            "<function=f></function>suffix",
            "<function=f>garbage<parameter=x>1</parameter></function>",
            "<function=f><parameter=x>1</parameter>garbage</function>",
            "<function=f></function><function=g></function>",
        ] {
            assert!(
                matches!(
                    XmlFunctionCodec::default().parse(payload),
                    CodecOutcome::Error(_)
                ),
                "accepted {payload}"
            );
        }
    }

    #[test]
    fn empty_payload_rejected() {
        assert!(matches!(decode_err(""), ParserError::Malformed(_)));
        assert!(matches!(decode_err("   \n  "), ParserError::Malformed(_)));
    }

    #[test]
    fn no_parameters_yields_empty_args() {
        let (name, args) = decode_one("<function=do_thing></function>");
        assert_eq!(name, "do_thing");
        assert_eq!(args, json!({}));
    }

    #[test]
    fn malformed_parameter_tag_rejected() {
        // `<parameter=k` — no closing `>` of the parameter open tag.
        let err = decode_err("<function=f><parameter=k</function>");
        assert!(matches!(err, ParserError::Malformed(_)));
    }

    #[test]
    fn missing_function_open_rejected() {
        let err = decode_err("<parameter=k>v</parameter>");
        assert!(matches!(err, ParserError::Malformed(m) if m.contains("<function=")));
    }
}
