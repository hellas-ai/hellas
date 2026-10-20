//! Resource limits for the compiled stateless Responses request schema.
//! These checks constrain signed requests; they never rewrite provider input.
//! The adapter still owns complete request decoding and transport preparation.
use super::resource::TemplateError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsesResource {
    pub model: String,
    pub max_output_tokens: u32,
    #[serde(default)]
    pub settings: ResponsesSettings,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponsesSettings {
    pub temperature: bool,
    pub top_p: bool,
    pub tools: bool,
    pub parallel_tool_calls: bool,
    pub automatic_truncation: bool,
    /// A nonempty set requires an explicit selection in each request.
    pub reasoning_efforts: BTreeSet<ReasoningEffort>,
    /// A nonempty set requires an explicit selection in each request.
    pub reasoning_summaries: BTreeSet<ReasoningSummary>,
    pub output_formats: BTreeSet<ResponseFormat>,
}

impl Default for ResponsesSettings {
    fn default() -> Self {
        Self {
            temperature: false,
            top_p: false,
            tools: false,
            parallel_tool_calls: false,
            automatic_truncation: false,
            reasoning_efforts: BTreeSet::new(),
            reasoning_summaries: BTreeSet::new(),
            output_formats: BTreeSet::from([ResponseFormat::Text]),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningSummary {
    Auto,
    Concise,
    Detailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    Text,
    JsonObject,
    JsonSchema,
}

impl ResponsesResource {
    pub fn validate(&self) -> Result<(), TemplateError> {
        if self.model.is_empty()
            || self.model.len() > 256
            || self
                .model
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(TemplateError::Model);
        }
        if self.max_output_tokens == 0 {
            return Err(TemplateError::GenerationCap);
        }
        if self.settings.output_formats.is_empty()
            || self.settings.parallel_tool_calls && !self.settings.tools
        {
            return Err(TemplateError::Settings);
        }
        Ok(())
    }

    /// Returns the signed output-token reservation bound after checking all limits.
    pub fn matches(&self, bytes: &[u8]) -> Result<u64, TemplateError> {
        self.validate()?;
        if bytes.len() > hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES {
            return Err(TemplateError::Malformed);
        }
        let body =
            crate::model::http_usage::unique_json(bytes).map_err(|_| TemplateError::Malformed)?;
        let object = body.as_object().ok_or(TemplateError::Malformed)?;
        if object.get("model").and_then(Value::as_str) != Some(self.model.as_str()) {
            return Err(TemplateError::Model);
        }
        let cap = object
            .get("max_output_tokens")
            .and_then(Value::as_u64)
            .ok_or(TemplateError::GenerationCap)?;
        if cap == 0 || cap > u64::from(self.max_output_tokens) {
            return Err(TemplateError::GenerationCap);
        }
        for (name, allowed) in [
            ("temperature", self.settings.temperature),
            ("top_p", self.settings.top_p),
            ("tools", self.settings.tools),
            ("tool_choice", self.settings.tools),
            ("parallel_tool_calls", self.settings.parallel_tool_calls),
        ] {
            if !allowed && object.contains_key(name) {
                return Err(TemplateError::Settings);
            }
        }
        if !self.settings.tools
            && object
                .get("input")
                .and_then(Value::as_array)
                .is_some_and(|items| {
                    items.iter().any(|item| {
                        matches!(
                            item.get("type").and_then(Value::as_str),
                            Some("function_call" | "function_call_output")
                        )
                    })
                })
        {
            return Err(TemplateError::Settings);
        }
        if let Some(truncation) = object.get("truncation") {
            match truncation.as_str() {
                Some("disabled") => {}
                Some("auto") if self.settings.automatic_truncation => {}
                _ => return Err(TemplateError::Settings),
            }
        }
        let reasoning = object
            .get("reasoning")
            .map(|value| {
                let object = value.as_object().ok_or(TemplateError::Settings)?;
                if object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "effort" | "summary"))
                {
                    return Err(TemplateError::Settings);
                }
                Ok(object)
            })
            .transpose()?;
        choice(
            reasoning.and_then(|v| v.get("effort")),
            &self.settings.reasoning_efforts,
        )?;
        choice(
            reasoning.and_then(|v| v.get("summary")),
            &self.settings.reasoning_summaries,
        )?;
        let format = if let Some(text) = object.get("text") {
            let kind = text
                .pointer("/format/type")
                .ok_or(TemplateError::Settings)?;
            serde_json::from_value(kind.clone()).map_err(|_| TemplateError::Settings)?
        } else {
            ResponseFormat::Text
        };
        if !self.settings.output_formats.contains(&format) {
            return Err(TemplateError::Settings);
        }
        Ok(cap)
    }
}

fn choice<T: serde::de::DeserializeOwned + Ord>(
    value: Option<&Value>,
    allowed: &BTreeSet<T>,
) -> Result<(), TemplateError> {
    match value {
        None if allowed.is_empty() => Ok(()),
        Some(value) => {
            let value =
                serde_json::from_value(value.clone()).map_err(|_| TemplateError::Settings)?;
            if allowed.contains(&value) {
                Ok(())
            } else {
                Err(TemplateError::Settings)
            }
        }
        _ => Err(TemplateError::Settings),
    }
}
