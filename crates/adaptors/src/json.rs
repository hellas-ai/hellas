use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::{AdaptorError, AdaptorResult};

/// The `hellas` object: `commitment`, `provider` and `transcript`, each
/// present once known.
pub(crate) fn provenance_json(provenance: &crate::Provenance) -> Option<JsonValue> {
    let mut object = JsonMap::new();
    for (name, value) in [
        ("commitment", &provenance.commitment),
        ("provider", &provenance.provider),
        ("transcript", &provenance.transcript),
    ] {
        if let Some(value) = value {
            object.insert(name.to_string(), JsonValue::String(value.clone()));
        }
    }
    (!object.is_empty()).then_some(JsonValue::Object(object))
}

pub(crate) fn attach_hellas(
    mut body: JsonValue,
    provenance: Option<&crate::Provenance>,
) -> JsonValue {
    if let Some(hellas) = provenance.and_then(provenance_json) {
        body["hellas"] = hellas;
    }
    body
}

pub(crate) fn json_to_wire_string(value: &JsonValue) -> String {
    match value {
        JsonValue::String(value) => value.clone(),
        _ => serde_json::to_string(value).expect("serializing JSON value cannot fail"),
    }
}

pub(crate) fn structured_delta_string(delta: crate::StructuredDelta) -> String {
    match delta {
        crate::StructuredDelta::Text(text) => text,
        crate::StructuredDelta::Json(value) => json_to_wire_string(&value),
    }
}

pub(crate) fn required_string(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> AdaptorResult<String> {
    object
        .get(key)
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| AdaptorError::invalid_request(format!("missing or invalid `{key}`")))
}

pub(crate) fn optional_string(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> AdaptorResult<Option<String>> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(ToString::to_string)
            .map(Some)
            .ok_or_else(|| AdaptorError::invalid_request(format!("`{key}` must be a string"))),
    }
}

pub(crate) fn optional_bool(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> AdaptorResult<Option<bool>> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| AdaptorError::invalid_request(format!("`{key}` must be a bool"))),
    }
}

pub(crate) fn optional_u32(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> AdaptorResult<Option<u32>> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| AdaptorError::invalid_request(format!("`{key}` must be a u32"))),
    }
}

pub(crate) fn optional_f32(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> AdaptorResult<Option<f32>> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .map(|value| value as f32)
            .map(Some)
            .ok_or_else(|| AdaptorError::invalid_request(format!("`{key}` must be a number"))),
    }
}

pub(crate) fn required_array(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> AdaptorResult<Vec<JsonValue>> {
    match object.get(key) {
        Some(JsonValue::Array(values)) => Ok(values.clone()),
        _ => Err(AdaptorError::invalid_request(format!(
            "`{key}` must be an array"
        ))),
    }
}

pub(crate) fn optional_array(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> AdaptorResult<Option<Vec<JsonValue>>> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Array(values)) => Ok(Some(values.clone())),
        Some(_) => Err(AdaptorError::invalid_request(format!(
            "`{key}` must be an array"
        ))),
    }
}
