use hellas_rpc::output::{StopReason, TextChannel, Usage};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    pub name: String,
    pub provider: Option<String>,
    pub revision: Option<String>,
}

impl ModelRef {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            provider: None,
            revision: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub canonical: CanonicalExecution,
}

impl ExecutionRequest {
    pub fn new(canonical: CanonicalExecution) -> Self {
        Self { canonical }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalExecution {
    pub model: ModelRef,
    pub input: Input,
    pub instructions: Option<String>,
    pub sampling: SamplingOptions,
    pub tools: Vec<ToolSpec>,
    pub tool_choice: ToolChoice,
    pub response_format: Option<ResponseFormat>,
    pub reasoning: Option<ReasoningOptions>,
    pub previous_response_id: Option<String>,
}

impl CanonicalExecution {
    pub fn new(model: ModelRef, input: Input) -> Self {
        Self {
            model,
            input,
            instructions: None,
            sampling: SamplingOptions::default(),
            tools: Vec::new(),
            tool_choice: ToolChoice::Auto,
            response_format: None,
            reasoning: None,
            previous_response_id: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Input {
    Text(String),
    Messages(Vec<Message>),
    Items(Vec<InputItem>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: Vec<ContentPart>,
    pub name: Option<String>,
}

impl Message {
    pub fn text(role: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: vec![ContentPart::Text { text: text.into() }],
            name: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum InputItem {
    Message(Message),
    ToolCall {
        id: String,
        name: String,
        arguments: JsonValue,
    },
    ToolResult {
        call_id: String,
        output: Vec<ContentPart>,
    },
    Raw(JsonValue),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ContentPart {
    Text {
        text: String,
    },
    Image {
        uri: Option<String>,
        media_type: Option<String>,
        data: Option<String>,
    },
    File {
        file_id: Option<String>,
        filename: Option<String>,
        data: Option<String>,
    },
    Json(JsonValue),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SamplingOptions {
    pub max_output_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_logprobs: Option<u32>,
    pub parallel_tool_calls: Option<bool>,
    pub truncation: Option<String>,
    pub stop: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: Option<String>,
    pub parameters: JsonValue,
    pub kind: ToolKind,
    pub raw: JsonValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolKind {
    Function,
    BuiltIn(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Tool { name: String },
    Raw(JsonValue),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ResponseFormat {
    Text,
    JsonObject,
    JsonSchema {
        name: Option<String>,
        schema: JsonValue,
        strict: Option<bool>,
    },
    Raw(JsonValue),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReasoningOptions {
    pub value: JsonValue,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub output: Vec<OutputItem>,
    pub usage: Option<Usage>,
    pub stop_reason: StopReason,
    pub provenance: Option<Provenance>,
    pub error: Option<ExecutionErrorInfo>,
}

/// Provenance of one job, rendered as the `hellas` object of each response
/// that carries it. A provider signs none of it: the gateway vouches for the
/// job it ran, apart from the signed output vocabulary.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Lowercase hex commitment: the work id the provider accepted.
    pub commitment: Option<String>,
    /// The accepting provider's key, as
    /// [`hellas_rpc::provenance::encode_public_key`] renders it.
    pub provider: Option<String>,
    /// Base64 of the canonical provider-signed transcript, once the job
    /// has completed.
    pub transcript: Option<String>,
}

impl Provenance {
    /// The fields `next` names replace these.
    pub fn merge(&mut self, next: Provenance) {
        if next.commitment.is_some() {
            self.commitment = next.commitment;
        }
        if next.provider.is_some() {
            self.provider = next.provider;
        }
        if next.transcript.is_some() {
            self.transcript = next.transcript;
        }
    }
}

/// A call commitment a provider signed into its output.
impl From<hellas_rpc::output::Provenance> for Provenance {
    fn from(provenance: hellas_rpc::output::Provenance) -> Self {
        Self {
            commitment: provenance.call_commitment,
            ..Self::default()
        }
    }
}

/// Merge `next` into `current`, starting it if there is none yet.
pub(crate) fn merge_provenance(current: &mut Option<Provenance>, next: Provenance) {
    current.get_or_insert_default().merge(next);
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionErrorInfo {
    pub message: String,
    pub code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum OutputItem {
    Text {
        text: String,
        channel: TextChannel,
    },
    ToolCall {
        id: String,
        name: String,
        arguments: JsonValue,
    },
    StructuredJson(JsonValue),
    Raw(JsonValue),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_request_keeps_canonical_shape() {
        let canonical =
            CanonicalExecution::new(ModelRef::new("model-a"), Input::Text("hello".to_string()));

        let request = ExecutionRequest::new(canonical);

        assert_eq!(request.canonical.model.name, "model-a");
        assert_eq!(request.canonical.input, Input::Text("hello".to_string()));
    }

    #[test]
    fn message_text_constructor_uses_content_parts() {
        let message = Message::text("user", "hi");
        assert_eq!(message.role, "user");
        assert_eq!(
            message.content,
            vec![ContentPart::Text {
                text: "hi".to_string()
            }]
        );
    }
}
