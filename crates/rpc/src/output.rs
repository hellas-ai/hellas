//! Canonical streaming output vocabulary.
//!
//! These are the semantic events a producer commits to inside signed
//! output transcripts: [`crate::fetch`] encodes them as dag-cbor payloads
//! of [`crate::OutputEventEnvelope`]s, and the gateway renders provider
//! streams into and out of them. Because the encoded bytes are signed,
//! every field here is protocol surface; changing any shape is a payload
//! codec version change (see the codec strings in [`crate::fetch`]).

use serde::{Deserialize, Serialize};
use serde_json::{Number as JsonNumber, Value as JsonValue};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum OutputEvent {
    TextDelta {
        index: usize,
        delta: String,
        channel: TextChannel,
    },
    ToolCallStart(ToolCallStart),
    ToolCallArgumentsDelta(ToolCallArgumentsDelta),
    ToolCallEnd(ToolCallEnd),
    StructuredOutputDelta(StructuredDelta),
    /// A provider-specific event that has already been decoded into a closed,
    /// owned adaptor vocabulary. Unlike [`StructuredDelta::Json`], this is not
    /// an arbitrary JSON escape hatch: the attested adaptor chooses one of the
    /// typed variants below before the event is signed.
    Adaptor(AdaptorEvent),
    Usage(Usage),
    Finished {
        stop_reason: StopReason,
        usage: Option<Usage>,
    },
    Error {
        message: String,
        code: Option<String>,
    },
    Provenance(Provenance),
}

impl OutputEvent {
    /// None for nonterminal events; Some indicates success or failure/cancellation.
    pub fn terminal(&self) -> Option<bool> {
        match self {
            Self::Finished { stop_reason, .. } => Some(*stop_reason != StopReason::Cancelled),
            Self::Error { .. } => Some(false),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AdaptorEvent {
    CodexResponses(CodexResponsesEvent),
    /// Exact HTTP metadata and bytes, without LLM-specific projection.
    Http(HttpResponseEvent),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpResponseEvent {
    Head {
        status: u16,
        headers: Vec<(String, String)>,
    },
    /// Standard padded base64, preserving arbitrary binary bodies.
    Body { base64: String },
}

/// The subset of Codex Responses streaming semantics committed by the sealed
/// Fetch adaptor. Each variant can be reconstructed without retaining any
/// untrusted provider JSON.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CodexResponsesEvent {
    Created {
        response_id: Option<String>,
    },
    OutputItemAdded(CodexResponseItem),
    OutputItemDone(CodexResponseItem),
    OutputTextDelta {
        delta: String,
    },
    CustomToolCallInputDelta {
        item_id: String,
        call_id: Option<String>,
        delta: String,
    },
    ReasoningSummaryDelta {
        delta: String,
        summary_index: u64,
    },
    ReasoningSummaryDone {
        item_id: String,
        text: String,
        summary_index: u64,
    },
    ReasoningContentDelta {
        delta: String,
        content_index: u64,
    },
    ReasoningSummaryPartAdded {
        summary_index: u64,
    },
    Completed(CodexCompleted),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CodexCompleted {
    pub response_id: String,
    /// The effective server model, correlated across the HTTP response head
    /// and every lifecycle claim before this terminal event is signed.
    pub server_model: Option<String>,
    pub usage: CodexUsage,
    pub usage_metadata: Option<CodexUsageMetadata>,
    pub end_turn: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexUsageMetadata {
    pub amount: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexUsage {
    pub input_tokens: u64,
    pub input_tokens_details: Option<CodexInputTokenDetails>,
    pub output_tokens: u64,
    pub output_tokens_details: Option<CodexOutputTokenDetails>,
    pub total_tokens: u64,
    /// Kept as a JSON number so fractional budget units (for example `2.5`)
    /// survive the signed round trip exactly instead of being coerced into
    /// Hellas' integer token billing vocabulary.
    pub codex_rollout_budget_units: Option<JsonNumber>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexInputTokenDetails {
    pub cached_tokens: u64,
    pub cache_write_tokens: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexOutputTokenDetails {
    pub reasoning_tokens: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CodexResponseItem {
    Message {
        id: Option<String>,
        content: Vec<CodexMessageContent>,
        phase: Option<CodexMessagePhase>,
    },
    Reasoning {
        id: Option<String>,
        summary: Vec<CodexReasoningSummary>,
        content: Option<Vec<CodexReasoningContent>>,
        encrypted_content: Option<String>,
    },
    FunctionCall {
        id: Option<String>,
        call_id: String,
        name: String,
        /// The provider wire type is a string containing JSON. It remains a
        /// string here so a custom-tool input can never be confused with it;
        /// the projector validates that it contains valid JSON before signing.
        arguments: String,
    },
    CustomToolCall {
        id: Option<String>,
        status: Option<CodexItemStatus>,
        call_id: String,
        name: String,
        input: String,
    },
    ToolSearchCall {
        id: Option<String>,
        call_id: String,
        status: Option<CodexItemStatus>,
        arguments: CodexToolSearchArguments,
    },
}

impl CodexResponseItem {
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Message { id, .. }
            | Self::Reasoning { id, .. }
            | Self::FunctionCall { id, .. }
            | Self::CustomToolCall { id, .. }
            | Self::ToolSearchCall { id, .. } => id.as_deref(),
        }
    }

    pub fn call_id(&self) -> Option<&str> {
        match self {
            Self::FunctionCall { call_id, .. }
            | Self::CustomToolCall { call_id, .. }
            | Self::ToolSearchCall { call_id, .. } => Some(call_id),
            Self::Message { .. } | Self::Reasoning { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodexMessageContent {
    OutputText { text: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodexMessagePhase {
    Commentary,
    FinalAnswer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexReasoningSummary {
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexReasoningContent {
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodexItemStatus {
    InProgress,
    Completed,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexToolSearchArguments {
    pub query: String,
    pub limit: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextChannel {
    Output,
    Reasoning,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCallStart {
    pub index: usize,
    pub id: Option<String>,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCallArgumentsDelta {
    pub index: usize,
    pub delta: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCallEnd {
    pub index: usize,
    pub arguments: JsonValue,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum StructuredDelta {
    Text(String),
    Json(JsonValue),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    EndOfText,
    MaxOutputTokens,
    StopSequence,
    ToolCall,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Lowercase hex commitment string ready for provider wire JSON.
    pub call_commitment: Option<String>,
}
