use super::stream::{project_events, push_sse};

use hellas_adaptors::{
    OutputEvent, SseDecoder, StopReason, TextChannel, ToolCallArgumentsDelta, ToolCallEnd,
    ToolCallStart, Usage, WireEventData, WireStreamEvent,
};
use hellas_executor::{
    FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchCall, FetchProjector,
    FetchProviderResponseHead, FetchRequestView, PreparedFetchRequest, ProjectedFetch,
};
use hellas_rpc::fetch::{MAX_FETCH_REQUEST_BODY_BYTES, encode_fetch_terminal_payload};
use hellas_rpc::{ContentId, FetchEnvironment, JsonBytes};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};

/// Maximum UTF-8 bytes retained from any projector failure. Every failure may
/// contain attacker-controlled JSON (including serde's diagnostic), so this is
/// enforced at the single constructor rather than only at known error fields.
const MAX_FETCH_FAILURE_DIAGNOSTIC_BYTES: usize = 512;

#[derive(Clone, Copy, Debug)]
pub struct ResponsesFetchAdaptorFactory {
    environment: FetchEnvironment,
}

impl ResponsesFetchAdaptorFactory {
    pub const fn new(environment: FetchEnvironment) -> Self {
        Self { environment }
    }
}

impl FetchAdaptorFactory for ResponsesFetchAdaptorFactory {
    fn execution_environment(&self) -> ContentId {
        self.environment.manifest_id()
    }

    fn create(&self, request: &FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError> {
        if self.environment == FetchEnvironment::Http {
            return Err(fetch_failed("HTTP requires the HTTP adaptor"));
        }
        if self.environment == FetchEnvironment::CodexResponses {
            return super::codex_responses::create_session(request);
        }
        let prepared = prepare_streaming_request(request)?;
        let request_view = FetchRequestView {
            service: request.service.clone(),
            method: request.method.clone(),
            model: Some(prepared.model.clone()),
            max_output_units: prepared.max_output_tokens.map(u64::from),
        };
        Ok(FetchAdaptorSession {
            request_view,
            provider_request: PreparedFetchRequest::new(request, prepared.body),
            projector: Box::new(ResponsesFetchProjector::new(prepared.max_output_tokens)),
        })
    }
}

struct PreparedResponsesRequest {
    body: JsonBytes,
    model: String,
    max_output_tokens: Option<u32>,
}

/// Strictly decodes the signed v0.0.1 request into closed typed shapes, then
/// serializes a fresh provider request. Only function arguments and JSON Schema
/// values are intentionally opaque after their enclosing shape is accepted.
fn prepare_streaming_request(
    request: &FetchCall,
) -> Result<PreparedResponsesRequest, FetchAdaptorError> {
    let body = request.body.as_bytes();
    if body.len() > MAX_FETCH_REQUEST_BODY_BYTES {
        return Err(fetch_failed(format!(
            "signed Fetch request body exceeds the {MAX_FETCH_REQUEST_BODY_BYTES}-byte v0.0.1 limit"
        )));
    }

    let mut trusted: TrustedResponsesRequest = serde_json::from_slice(body)
        .map_err(|err| fetch_failed(format!("invalid v0.0.1 Responses request: {err}")))?;
    trusted.validate_and_force_transport()?;
    let model = trusted.model.clone();
    let max_output_tokens = trusted.max_output_tokens;
    let rebuilt = serde_json::to_vec(&trusted)
        .map_err(|err| fetch_failed(format!("failed to rebuild Responses request: {err}")))?;
    if rebuilt.len() > MAX_FETCH_REQUEST_BODY_BYTES {
        return Err(fetch_failed(format!(
            "rebuilt upstream Responses body exceeds the {MAX_FETCH_REQUEST_BODY_BYTES}-byte v0.0.1 limit"
        )));
    }

    Ok(PreparedResponsesRequest {
        body: JsonBytes::new(rebuilt),
        model,
        max_output_tokens,
    })
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedResponsesRequest {
    model: String,
    input: TrustedInput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tools: Vec<TrustedTool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool_choice: Option<TrustedToolChoice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reasoning: Option<TrustedReasoning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<TrustedTextOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    temperature: Option<JsonNumber>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    top_p: Option<JsonNumber>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    top_logprobs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parallel_tool_calls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    truncation: Option<TrustedTruncation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stream_options: Option<TrustedStreamOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    store: Option<bool>,
}

impl TrustedResponsesRequest {
    fn validate_and_force_transport(&mut self) -> Result<(), FetchAdaptorError> {
        if self.model.is_empty() {
            return Err(fetch_failed("Responses model must not be empty"));
        }
        if self.stream == Some(false) {
            return Err(fetch_failed(
                "v0.0.1 Fetch does not accept stream=false; upstream streaming is mandatory",
            ));
        }
        if self.store == Some(true) {
            return Err(fetch_failed(
                "v0.0.1 Fetch does not accept store=true; upstream storage is forbidden",
            ));
        }
        validate_request_input(&self.input)?;
        let mut tool_names = std::collections::BTreeSet::new();
        for tool in &self.tools {
            let TrustedTool::Function {
                name,
                parameters,
                strict,
                ..
            } = tool;
            if name.is_empty() {
                return Err(fetch_failed("function tool name must not be empty"));
            }
            if !matches!(parameters, JsonValue::Object(_) | JsonValue::Null) {
                return Err(fetch_failed(
                    "function tool parameters must be a JSON Schema object or null",
                ));
            }
            if !matches!(strict, JsonValue::Bool(_) | JsonValue::Null) {
                return Err(fetch_failed(
                    "function tool strict must be a boolean or null",
                ));
            }
            if !tool_names.insert(name.as_str()) {
                return Err(fetch_failed(format!(
                    "duplicate function tool name `{name}`"
                )));
            }
        }
        if let Some(TrustedToolChoice::Function(TrustedFunctionToolChoice::Function { name })) =
            &self.tool_choice
            && !tool_names.contains(name.as_str())
        {
            return Err(fetch_failed(format!(
                "tool_choice names undeclared function `{name}`"
            )));
        }

        if self.max_output_tokens == Some(0) {
            return Err(fetch_failed("max_output_tokens must be greater than zero"));
        }
        validate_number_range("temperature", self.temperature.as_ref(), 0.0, 2.0)?;
        validate_number_range("top_p", self.top_p.as_ref(), 0.0, 1.0)?;
        if self.top_logprobs.is_some_and(|value| value != 0) {
            return Err(fetch_failed(
                "v0.0.1 only accepts top_logprobs=0 because logprobs are not projected",
            ));
        }
        if let Some(TrustedTextOptions {
            format: TrustedFormat::JsonSchema { name, schema, .. },
        }) = &self.text
            && (name.is_empty() || !schema.is_object())
        {
            return Err(fetch_failed(
                "json_schema format requires a non-empty name and object schema",
            ));
        }

        if self
            .stream_options
            .as_ref()
            .is_some_and(|options| options.include_obfuscation)
        {
            return Err(fetch_failed(
                "v0.0.1 Fetch does not accept stream obfuscation",
            ));
        }
        self.stream_options = Some(TrustedStreamOptions {
            include_obfuscation: false,
        });

        self.stream = Some(true);
        self.store = Some(false);
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum TrustedInput {
    Text(String),
    Items(Vec<TrustedInputItem>),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum TrustedInputItem {
    #[serde(rename = "message")]
    Message {
        role: String,
        content: TrustedMessageContent,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<TrustedItemStatus>,
    },
    #[serde(rename = "function_call")]
    FunctionCall {
        call_id: String,
        name: String,
        arguments: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<TrustedItemStatus>,
    },
    #[serde(rename = "function_call_output")]
    FunctionCallOutput {
        call_id: String,
        output: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<TrustedItemStatus>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TrustedItemStatus {
    InProgress,
    Completed,
    Incomplete,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum TrustedMessageContent {
    Text(String),
    Parts(Vec<TrustedTextPart>),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum TrustedTextPart {
    #[serde(rename = "input_text")]
    Input { text: String },
    #[serde(rename = "output_text")]
    Output { text: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum TrustedTool {
    #[serde(rename = "function")]
    Function {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        parameters: JsonValue,
        strict: JsonValue,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum TrustedToolChoice {
    Mode(TrustedToolChoiceMode),
    Function(TrustedFunctionToolChoice),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TrustedToolChoiceMode {
    Auto,
    None,
    Required,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum TrustedFunctionToolChoice {
    #[serde(rename = "function")]
    Function { name: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedReasoning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effort: Option<TrustedReasoningEffort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    summary: Option<TrustedReasoningSummary>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TrustedReasoningEffort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TrustedReasoningSummary {
    Auto,
    Concise,
    Detailed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TrustedTruncation {
    Auto,
    Disabled,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedTextOptions {
    format: TrustedFormat,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedStreamOptions {
    #[serde(default)]
    include_obfuscation: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum TrustedFormat {
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "json_object")]
    JsonObject,
    #[serde(rename = "json_schema")]
    JsonSchema {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        schema: JsonValue,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        strict: Option<bool>,
    },
}

fn validate_request_input(input: &TrustedInput) -> Result<(), FetchAdaptorError> {
    let TrustedInput::Items(items) = input else {
        return Ok(());
    };
    for item in items {
        match item {
            TrustedInputItem::Message { role, content, .. } => {
                if !matches!(role.as_str(), "developer" | "system" | "user" | "assistant") {
                    return Err(fetch_failed(format!(
                        "unsupported text-message role `{role}`"
                    )));
                }
                if let TrustedMessageContent::Parts(parts) = content {
                    if parts.is_empty() {
                        return Err(fetch_failed("text-message content must not be empty"));
                    }
                    if role != "assistant"
                        && parts
                            .iter()
                            .any(|part| matches!(part, TrustedTextPart::Output { .. }))
                    {
                        return Err(fetch_failed(
                            "output_text history is only valid for assistant messages",
                        ));
                    }
                }
            }
            TrustedInputItem::FunctionCall { call_id, name, .. } => {
                if call_id.is_empty() || name.is_empty() {
                    return Err(fetch_failed(
                        "function_call requires non-empty call_id and name",
                    ));
                }
            }
            TrustedInputItem::FunctionCallOutput { call_id, .. } => {
                if call_id.is_empty() {
                    return Err(fetch_failed(
                        "function_call_output requires a non-empty call_id",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_number_range(
    field: &str,
    value: Option<&JsonNumber>,
    minimum: f64,
    maximum: f64,
) -> Result<(), FetchAdaptorError> {
    if value
        .and_then(JsonNumber::as_f64)
        .is_some_and(|value| (minimum..=maximum).contains(&value))
        || value.is_none()
    {
        Ok(())
    } else {
        Err(fetch_failed(format!(
            "{field} must be between {minimum} and {maximum}"
        )))
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum WireOutputItem {
    #[serde(rename = "message")]
    Message {
        id: String,
        status: String,
        role: String,
        content: Vec<WireOutputText>,
    },
    #[serde(rename = "reasoning")]
    Reasoning {
        id: String,
        status: String,
        #[serde(default)]
        summary: Vec<WireSummaryText>,
    },
    #[serde(rename = "function_call")]
    Function {
        id: String,
        call_id: String,
        name: String,
        arguments: String,
        status: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum WireOutputText {
    #[serde(rename = "output_text")]
    Text {
        text: String,
        #[serde(default)]
        annotations: Vec<JsonValue>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum WireSummaryText {
    #[serde(rename = "summary_text")]
    Text { text: String },
}

#[derive(Debug, PartialEq, Eq)]
struct ItemSnapshot {
    id: String,
    status: String,
    body: SnapshotBody,
}

#[derive(Debug, PartialEq, Eq)]
enum SnapshotBody {
    Message(String),
    Reasoning(String),
    Function {
        call_id: String,
        name: String,
        arguments: String,
    },
}

fn item_snapshot(value: &JsonValue) -> Result<ItemSnapshot, FetchAdaptorError> {
    let item: WireOutputItem = serde_json::from_value(value.clone())
        .map_err(|err| fetch_failed(format!("malformed Responses output item: {err}")))?;
    match item {
        WireOutputItem::Message {
            id,
            status,
            role,
            content,
        } => {
            if role != "assistant" {
                return Err(fetch_failed(
                    "v0.0.1 output messages require role=assistant",
                ));
            }
            if content.len() > 1 {
                return Err(fetch_failed(
                    "v0.0.1 output messages support one text content part",
                ));
            }
            let text = content
                .into_iter()
                .next()
                .map(|part| match part {
                    WireOutputText::Text { text, annotations } if annotations.is_empty() => {
                        Ok(text)
                    }
                    WireOutputText::Text { .. } => Err(fetch_failed(
                        "v0.0.1 does not support output-text annotations",
                    )),
                })
                .transpose()?
                .unwrap_or_default();
            Ok(ItemSnapshot {
                id,
                status,
                body: SnapshotBody::Message(text),
            })
        }
        WireOutputItem::Reasoning {
            id,
            status,
            summary,
        } => {
            if summary.len() > 1 {
                return Err(fetch_failed(
                    "v0.0.1 reasoning supports one summary text part",
                ));
            }
            let text = summary
                .into_iter()
                .next()
                .map(|part| match part {
                    WireSummaryText::Text { text } => text,
                })
                .unwrap_or_default();
            Ok(ItemSnapshot {
                id,
                status,
                body: SnapshotBody::Reasoning(text),
            })
        }
        WireOutputItem::Function {
            id,
            call_id,
            name,
            arguments,
            status,
        } => Ok(ItemSnapshot {
            id,
            status,
            body: SnapshotBody::Function {
                call_id,
                name,
                arguments,
            },
        }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ItemKind {
    Message,
    Reasoning,
    Function,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum TextPhase {
    #[default]
    AwaitingPart,
    Open,
    TextDone,
    PartDone,
}

#[derive(Debug, Default)]
struct TextState {
    value: String,
    saw_delta: bool,
    phase: TextPhase,
}

#[derive(Debug)]
enum ItemState {
    Message {
        id: String,
        text: TextState,
        done_status: Option<String>,
    },
    Reasoning {
        id: String,
        text: TextState,
        done_status: Option<String>,
    },
    Function {
        id: String,
        call_id: String,
        name: String,
        arguments: String,
        saw_delta: bool,
        arguments_done: bool,
        done_status: Option<String>,
        tool_index: usize,
    },
}

impl ItemState {
    fn id(&self) -> &str {
        match self {
            Self::Message { id, .. } | Self::Reasoning { id, .. } | Self::Function { id, .. } => id,
        }
    }

    fn kind(&self) -> ItemKind {
        match self {
            Self::Message { .. } => ItemKind::Message,
            Self::Reasoning { .. } => ItemKind::Reasoning,
            Self::Function { .. } => ItemKind::Function,
        }
    }

    fn done_status(&self) -> Option<&str> {
        match self {
            Self::Message { done_status, .. }
            | Self::Reasoning { done_status, .. }
            | Self::Function { done_status, .. } => done_status.as_deref(),
        }
    }
}

struct PendingTerminal {
    stop_reason: StopReason,
    usage: Option<Usage>,
}

struct ResponsesFetchProjector {
    max_output_tokens: Option<u32>,
    decoder: SseDecoder,
    response_id: Option<String>,
    response_model: Option<String>,
    created: bool,
    in_progress: bool,
    next_sequence: u64,
    items: Vec<ItemState>,
    next_tool_index: usize,
    terminal: Option<PendingTerminal>,
    finished: bool,
}

impl ResponsesFetchProjector {
    fn new(max_output_tokens: Option<u32>) -> Self {
        Self {
            max_output_tokens,
            decoder: SseDecoder::new(),
            response_id: None,
            response_model: None,
            created: false,
            in_progress: false,
            next_sequence: 0,
            items: Vec::new(),
            next_tool_index: 0,
            terminal: None,
            finished: false,
        }
    }

    fn decode_frames(
        &mut self,
        frames: Vec<WireStreamEvent>,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let mut output = Vec::new();
        for frame in frames {
            if self.terminal.is_some() {
                return Err(fetch_failed(
                    "Responses stream contained an event after its terminal event",
                ));
            }
            output.extend(self.decode_frame(frame)?);
        }
        Ok(output)
    }

    fn decode_frame(
        &mut self,
        frame: WireStreamEvent,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let name = frame.name;
        let data = match frame.data {
            WireEventData::Json(value) => value,
            WireEventData::Text(value) if value == "[DONE]" => {
                return Err(fetch_failed(
                    "Responses [DONE] arrived without a verified semantic terminal",
                ));
            }
            WireEventData::Text(value) => serde_json::from_str(&value)
                .map_err(|err| fetch_failed(format!("invalid Responses SSE JSON: {err}")))?,
            WireEventData::Bytes(bytes) => serde_json::from_slice(&bytes)
                .map_err(|err| fetch_failed(format!("invalid Responses SSE JSON: {err}")))?,
        };
        let event = data
            .as_object()
            .ok_or_else(|| fetch_failed("Responses SSE data must be a JSON object"))?;
        let kind = required_string(event, "type", "Responses SSE event")?;
        if name.as_deref() != Some(kind) {
            return Err(fetch_failed(
                "Responses SSE event name must exactly match its data type",
            ));
        }
        self.validate_sequence(event)?;

        match kind {
            "response.created" => self.lifecycle(event, false),
            "response.in_progress" => self.lifecycle(event, true),
            "response.output_item.added" => self.item_added(event),
            "response.content_part.added" => self.text_part(event, ItemKind::Message, false),
            "response.output_text.delta" => self.text_delta(event, ItemKind::Message),
            "response.output_text.done" => self.text_done(event, ItemKind::Message),
            "response.content_part.done" => self.text_part(event, ItemKind::Message, true),
            "response.reasoning_summary_part.added" => {
                self.text_part(event, ItemKind::Reasoning, false)
            }
            "response.reasoning_summary_text.delta" => self.text_delta(event, ItemKind::Reasoning),
            "response.reasoning_summary_text.done" => self.text_done(event, ItemKind::Reasoning),
            "response.reasoning_summary_part.done" => {
                self.text_part(event, ItemKind::Reasoning, true)
            }
            "response.function_call_arguments.delta" => self.arguments_delta(event),
            "response.function_call_arguments.done" => self.arguments_done(event),
            "response.output_item.done" => self.item_done(event),
            "response.completed" => self.terminal(event, false),
            "response.incomplete" => self.terminal(event, true),
            "response.failed" => self.failed(event),
            "error" => self.error(event),
            other => Err(fetch_failed(format!(
                "unsupported Responses SSE event type `{other}` in v0.0.1"
            ))),
        }
    }

    fn validate_sequence(
        &mut self,
        event: &JsonMap<String, JsonValue>,
    ) -> Result<(), FetchAdaptorError> {
        let sequence = event.get("sequence_number");
        let sequence = sequence
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| fetch_failed("Responses SSE event requires integer sequence_number"))?;
        if sequence != self.next_sequence {
            return Err(fetch_failed(format!(
                "OpenAI Responses sequence_number {sequence} is not expected {}",
                self.next_sequence
            )));
        }
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| fetch_failed("Responses sequence_number overflow"))?;
        Ok(())
    }

    fn require_created(&self) -> Result<(), FetchAdaptorError> {
        if self.created {
            Ok(())
        } else {
            Err(fetch_failed(
                "Responses semantic output arrived before response.created",
            ))
        }
    }

    fn lifecycle(
        &mut self,
        event: &JsonMap<String, JsonValue>,
        in_progress: bool,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        exact_event_fields(event, &["response"])?;
        let response = required_object(event, "response", "Responses lifecycle event")?;
        validate_response_fields(response)?;
        let (id, model) = response_identity(response, "in_progress")?;
        let output = response
            .get("output")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| fetch_failed("Responses lifecycle event requires output array"))?;
        if !output.is_empty() {
            return Err(fetch_failed(
                "Responses lifecycle event contained early semantic output",
            ));
        }
        if in_progress {
            if !self.created || self.in_progress {
                return Err(fetch_failed("response.in_progress was early or duplicated"));
            }
            self.require_response(id, model)?;
            self.in_progress = true;
        } else {
            if self.created {
                return Err(fetch_failed("duplicate response.created"));
            }
            self.created = true;
            self.response_id = Some(id.to_string());
            self.response_model = Some(model.to_string());
        }
        Ok(Vec::new())
    }

    fn item_added(
        &mut self,
        event: &JsonMap<String, JsonValue>,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        self.require_created()?;
        exact_event_fields(event, &["output_index", "item"])?;
        let index = required_index(event, "output_index", "response.output_item.added")?;
        if index != self.items.len() {
            return Err(fetch_failed(format!(
                "output_index {index} is not the next contiguous index {}",
                self.items.len()
            )));
        }
        let snapshot = item_snapshot(
            event
                .get("item")
                .ok_or_else(|| fetch_failed("output_item.added missing item"))?,
        )?;
        if snapshot.id.is_empty() || snapshot.status != "in_progress" {
            return Err(fetch_failed(
                "added output item requires non-empty id and status=in_progress",
            ));
        }
        if self.items.iter().any(|item| item.id() == snapshot.id) {
            return Err(fetch_failed("duplicate Responses output item id"));
        }

        let mut output = Vec::new();
        let state = match snapshot.body {
            SnapshotBody::Message(text) if text.is_empty() => ItemState::Message {
                id: snapshot.id,
                text: TextState::default(),
                done_status: None,
            },
            SnapshotBody::Reasoning(text) if text.is_empty() => ItemState::Reasoning {
                id: snapshot.id,
                text: TextState::default(),
                done_status: None,
            },
            SnapshotBody::Function {
                call_id,
                name,
                arguments,
            } if !call_id.is_empty() && !name.is_empty() && arguments.is_empty() => {
                let tool_index = self.next_tool_index;
                self.next_tool_index = self
                    .next_tool_index
                    .checked_add(1)
                    .ok_or_else(|| fetch_failed("too many Responses function calls"))?;
                output.push(OutputEvent::ToolCallStart(ToolCallStart {
                    index: tool_index,
                    id: Some(call_id.clone()),
                    name: name.clone(),
                }));
                ItemState::Function {
                    id: snapshot.id,
                    call_id,
                    name,
                    arguments,
                    saw_delta: false,
                    arguments_done: false,
                    done_status: None,
                    tool_index,
                }
            }
            _ => {
                return Err(fetch_failed(
                    "added output item must have an empty v0.0.1 body",
                ));
            }
        };
        self.items.push(state);
        Ok(output)
    }

    fn text_part(
        &mut self,
        event: &JsonMap<String, JsonValue>,
        kind: ItemKind,
        done: bool,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let index_field = if kind == ItemKind::Reasoning {
            "summary_index"
        } else {
            "content_index"
        };
        exact_event_fields(event, &["item_id", "output_index", index_field, "part"])?;
        let (output_index, item_id) = self.item_identity(event)?;
        require_zero_index(event, index_field)?;
        let part_text = match kind {
            ItemKind::Message => {
                let part: WireOutputText = serde_json::from_value(
                    event
                        .get("part")
                        .ok_or_else(|| fetch_failed("content-part event missing part"))?
                        .clone(),
                )
                .map_err(|err| fetch_failed(format!("malformed output text part: {err}")))?;
                match part {
                    WireOutputText::Text { text, annotations } if annotations.is_empty() => text,
                    WireOutputText::Text { .. } => {
                        return Err(fetch_failed("output annotations are unsupported"));
                    }
                }
            }
            ItemKind::Reasoning => {
                let part: WireSummaryText = serde_json::from_value(
                    event
                        .get("part")
                        .ok_or_else(|| fetch_failed("reasoning-part event missing part"))?
                        .clone(),
                )
                .map_err(|err| fetch_failed(format!("malformed reasoning part: {err}")))?;
                match part {
                    WireSummaryText::Text { text } => text,
                }
            }
            ItemKind::Function => {
                return Err(fetch_failed(
                    "content-part event cannot target a function output item",
                ));
            }
        };
        let text = text_state_mut(self.item_mut(output_index, &item_id)?, kind)?;
        if done {
            if text.phase != TextPhase::TextDone || text.value != part_text {
                return Err(fetch_failed("part.done contradicted text.done"));
            }
            text.phase = TextPhase::PartDone;
        } else if text.phase == TextPhase::AwaitingPart && part_text.is_empty() {
            text.phase = TextPhase::Open;
        } else {
            return Err(fetch_failed("part.added was duplicate, late, or non-empty"));
        }
        Ok(Vec::new())
    }

    fn text_delta(
        &mut self,
        event: &JsonMap<String, JsonValue>,
        kind: ItemKind,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let index_field = if kind == ItemKind::Reasoning {
            "summary_index"
        } else {
            "content_index"
        };
        exact_event_fields(
            event,
            &["item_id", "output_index", index_field, "delta", "logprobs"],
        )?;
        let (output_index, item_id) = self.item_identity(event)?;
        require_zero_index(event, index_field)?;
        validate_empty_logprobs(event)?;
        let delta = required_string(event, "delta", "Responses text delta")?;
        let text = text_state_mut(self.item_mut(output_index, &item_id)?, kind)?;
        if text.phase != TextPhase::Open {
            return Err(fetch_failed(
                "text delta arrived outside an open content part",
            ));
        }
        text.saw_delta = true;
        text.value.push_str(delta);
        Ok(vec![OutputEvent::TextDelta {
            index: output_index,
            delta: delta.to_string(),
            channel: if kind == ItemKind::Reasoning {
                TextChannel::Reasoning
            } else {
                TextChannel::Output
            },
        }])
    }

    fn text_done(
        &mut self,
        event: &JsonMap<String, JsonValue>,
        kind: ItemKind,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let index_field = if kind == ItemKind::Reasoning {
            "summary_index"
        } else {
            "content_index"
        };
        exact_event_fields(
            event,
            &["item_id", "output_index", index_field, "text", "logprobs"],
        )?;
        let (output_index, item_id) = self.item_identity(event)?;
        require_zero_index(event, index_field)?;
        validate_empty_logprobs(event)?;
        let done = required_string(event, "text", "Responses text done")?;
        let text = text_state_mut(self.item_mut(output_index, &item_id)?, kind)?;
        if text.phase != TextPhase::Open {
            return Err(fetch_failed(
                "text.done arrived outside an open content part",
            ));
        }
        let mut output = Vec::new();
        if text.saw_delta {
            if text.value != done {
                return Err(fetch_failed(
                    "semantic text deltas contradicted done representation",
                ));
            }
        } else {
            text.value.push_str(done);
            if !done.is_empty() {
                output.push(OutputEvent::TextDelta {
                    index: output_index,
                    delta: done.to_string(),
                    channel: if kind == ItemKind::Reasoning {
                        TextChannel::Reasoning
                    } else {
                        TextChannel::Output
                    },
                });
            }
        }
        text.phase = TextPhase::TextDone;
        Ok(output)
    }

    fn arguments_delta(
        &mut self,
        event: &JsonMap<String, JsonValue>,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        exact_event_fields(event, &["item_id", "output_index", "delta"])?;
        let (index, id) = self.item_identity(event)?;
        let delta = required_string(event, "delta", "function arguments delta")?;
        let ItemState::Function {
            arguments,
            saw_delta,
            arguments_done,
            tool_index,
            ..
        } = self.item_mut(index, &id)?
        else {
            return Err(fetch_failed(
                "function arguments delta targeted a non-function output item",
            ));
        };
        if *arguments_done {
            return Err(fetch_failed("arguments delta arrived after arguments.done"));
        }
        *saw_delta = true;
        arguments.push_str(delta);
        Ok(vec![OutputEvent::ToolCallArgumentsDelta(
            ToolCallArgumentsDelta {
                index: *tool_index,
                delta: delta.to_string(),
            },
        )])
    }

    fn arguments_done(
        &mut self,
        event: &JsonMap<String, JsonValue>,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        exact_event_fields(event, &["item_id", "output_index", "arguments", "name"])?;
        let (index, id) = self.item_identity(event)?;
        let done = required_string(event, "arguments", "function arguments done")?;
        let done_name = event
            .get("name")
            .map(|_| required_string(event, "name", "function arguments done"))
            .transpose()?;
        let ItemState::Function {
            name,
            arguments,
            saw_delta,
            arguments_done,
            tool_index,
            ..
        } = self.item_mut(index, &id)?
        else {
            return Err(fetch_failed(
                "function arguments done targeted a non-function output item",
            ));
        };
        if *arguments_done || done_name.is_some_and(|value| value != name) {
            return Err(fetch_failed(
                "arguments.done was duplicate or changed function name",
            ));
        }
        let mut output = Vec::new();
        if *saw_delta {
            if arguments != done {
                return Err(fetch_failed("argument deltas contradicted arguments.done"));
            }
        } else {
            arguments.push_str(done);
            if !done.is_empty() {
                output.push(OutputEvent::ToolCallArgumentsDelta(
                    ToolCallArgumentsDelta {
                        index: *tool_index,
                        delta: done.to_string(),
                    },
                ));
            }
        }
        *arguments_done = true;
        Ok(output)
    }

    fn item_done(
        &mut self,
        event: &JsonMap<String, JsonValue>,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        exact_event_fields(event, &["output_index", "item"])?;
        let index = required_index(event, "output_index", "response.output_item.done")?;
        let snapshot = item_snapshot(
            event
                .get("item")
                .ok_or_else(|| fetch_failed("output_item.done missing item"))?,
        )?;
        if !matches!(snapshot.status.as_str(), "completed" | "incomplete") {
            return Err(fetch_failed("invalid output_item.done status"));
        }
        let item = self
            .items
            .get_mut(index)
            .ok_or_else(|| fetch_failed(format!("unknown output_index {index}")))?;
        if item.id() != snapshot.id || item.done_status().is_some() {
            return Err(fetch_failed(
                "output_item.done id contradicted added item or was duplicate",
            ));
        }

        let mut output = Vec::new();
        match (item, snapshot.body) {
            (
                ItemState::Message {
                    text, done_status, ..
                },
                SnapshotBody::Message(done),
            )
            | (
                ItemState::Reasoning {
                    text, done_status, ..
                },
                SnapshotBody::Reasoning(done),
            ) => {
                if text.phase != TextPhase::PartDone || text.value != done {
                    return Err(fetch_failed("output_item.done contradicted streamed text"));
                }
                *done_status = Some(snapshot.status);
            }
            (
                ItemState::Function {
                    call_id,
                    name,
                    arguments,
                    arguments_done,
                    done_status,
                    tool_index,
                    ..
                },
                SnapshotBody::Function {
                    call_id: done_id,
                    name: done_name,
                    arguments: done_arguments,
                },
            ) => {
                if !*arguments_done
                    || call_id != &done_id
                    || name != &done_name
                    || arguments != &done_arguments
                {
                    return Err(fetch_failed(
                        "function output_item.done contradicted streamed call",
                    ));
                }
                *done_status = Some(snapshot.status);
                output.push(OutputEvent::ToolCallEnd(ToolCallEnd {
                    index: *tool_index,
                    arguments: decode_arguments(arguments),
                }));
            }
            _ => return Err(fetch_failed("output_item.done changed item type")),
        }
        Ok(output)
    }

    fn terminal(
        &mut self,
        event: &JsonMap<String, JsonValue>,
        incomplete: bool,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        self.require_created()?;
        exact_event_fields(event, &["response"])?;
        let response = required_object(event, "response", "Responses terminal event")?;
        validate_response_fields(response)?;
        let status = if incomplete {
            "incomplete"
        } else {
            "completed"
        };
        let (id, model) = response_identity(response, status)?;
        self.require_response(id, model)?;
        if response.get("error").is_some_and(|value| !value.is_null()) {
            return Err(fetch_failed("successful/incomplete terminal carried error"));
        }
        let output = response
            .get("output")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| fetch_failed("Responses terminal response missing output array"))?;
        if output.len() != self.items.len() {
            return Err(fetch_failed(
                "terminal response.output length contradicted streamed items",
            ));
        }
        for (index, value) in output.iter().enumerate() {
            let snapshot = item_snapshot(value)?;
            let item = self
                .items
                .get(index)
                .ok_or_else(|| fetch_failed(format!("terminal unknown output index {index}")))?;
            compare_terminal(item, &snapshot)?;
        }
        let usage = parse_usage(response.get("usage"))?;
        if let (Some(limit), Some(actual)) = (
            self.max_output_tokens,
            usage.and_then(|usage| usage.output_tokens),
        ) && actual > u64::from(limit)
        {
            return Err(fetch_failed(format!(
                "terminal usage output_tokens {actual} exceeds admitted max_output_tokens {limit}"
            )));
        }
        let stop_reason = if incomplete {
            incomplete_stop_reason(response)?
        } else if self
            .items
            .iter()
            .any(|item| item.kind() == ItemKind::Function)
        {
            StopReason::ToolCall
        } else {
            StopReason::EndOfText
        };
        self.terminal = Some(PendingTerminal { stop_reason, usage });
        Ok(Vec::new())
    }

    fn failed(
        &self,
        event: &JsonMap<String, JsonValue>,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        self.require_created()?;
        exact_event_fields(event, &["response"])?;
        let response = required_object(event, "response", "response.failed")?;
        validate_response_fields(response)?;
        let (id, model) = response_identity(response, "failed")?;
        self.require_response(id, model)?;
        let message = response
            .get("error")
            .and_then(JsonValue::as_object)
            .and_then(|error| error.get("message"))
            .and_then(JsonValue::as_str)
            .ok_or_else(|| fetch_failed("response.failed missing error.message"))?;
        Err(fetch_failed(format!(
            "upstream Responses failure: {message}"
        )))
    }

    fn error(
        &self,
        event: &JsonMap<String, JsonValue>,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        exact_event_fields(event, &["code", "message", "param"])?;
        let message = required_string(event, "message", "Responses error event")?;
        Err(fetch_failed(format!("upstream Responses error: {message}")))
    }

    fn item_identity(
        &self,
        event: &JsonMap<String, JsonValue>,
    ) -> Result<(usize, String), FetchAdaptorError> {
        let index = event
            .get("output_index")
            .and_then(JsonValue::as_u64)
            .and_then(|value| usize::try_from(value).ok());
        let id = event.get("item_id").and_then(JsonValue::as_str);
        if let (Some(index), Some(id)) = (index, id) {
            return Ok((index, id.to_string()));
        }
        Err(fetch_failed(
            "Responses semantic event requires output_index and item_id",
        ))
    }

    fn item_mut(&mut self, index: usize, id: &str) -> Result<&mut ItemState, FetchAdaptorError> {
        let item = self
            .items
            .get_mut(index)
            .ok_or_else(|| fetch_failed(format!("unknown output_index {index}")))?;
        if item.id() != id || item.done_status().is_some() {
            return Err(fetch_failed(
                "item identity contradicted output_item.added or item was done",
            ));
        }
        Ok(item)
    }

    fn require_response(&self, id: &str, model: &str) -> Result<(), FetchAdaptorError> {
        if self.response_id.as_deref() == Some(id) && self.response_model.as_deref() == Some(model)
        {
            Ok(())
        } else {
            Err(fetch_failed(
                "Responses id/model claim contradicted response.created",
            ))
        }
    }
}

impl FetchProjector for ResponsesFetchProjector {
    fn begin(
        &mut self,
        head: FetchProviderResponseHead,
    ) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if head.is_empty() {
            Ok(Vec::new())
        } else {
            Err(fetch_failed(
                "public OpenAI Responses v0.0.1 has no response-head model contract",
            ))
        }
    }

    fn project(&mut self, bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if self.finished {
            return Err(fetch_failed("Responses projector received bytes after EOF"));
        }
        if self.terminal.is_some() && !bytes.is_empty() {
            return Err(fetch_failed(
                "Responses stream contained bytes after terminal",
            ));
        }
        let frames = push_sse(&mut self.decoder, bytes, "Responses").map_err(fetch_failed)?;
        let events = self.decode_frames(frames)?;
        if self.terminal.is_some() && !self.decoder.pending_bytes().is_empty() {
            return Err(fetch_failed(
                "Responses stream contained bytes after terminal",
            ));
        }
        project_events(&events).map_err(fetch_payload_error)
    }

    fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if self.finished {
            return Err(fetch_failed("Responses projector was finished twice"));
        }
        if !self.decoder.pending_bytes().is_empty() {
            return Err(fetch_failed(
                "Responses SSE stream ended without a blank-line frame delimiter",
            ));
        }
        // Complete frames were consumed by project(); an empty buffer has no tail to decode.
        let terminal = self
            .terminal
            .take()
            .ok_or_else(|| fetch_failed("Responses stream ended without verified terminal"))?;
        let projected = ProjectedFetch::Terminal(
            encode_fetch_terminal_payload(&OutputEvent::Finished {
                stop_reason: terminal.stop_reason,
                usage: terminal.usage,
            })
            .map_err(fetch_payload_error)?,
        );
        self.finished = true;
        Ok(vec![projected])
    }
}

fn text_state_mut(
    item: &mut ItemState,
    kind: ItemKind,
) -> Result<&mut TextState, FetchAdaptorError> {
    match (item, kind) {
        (ItemState::Message { text, .. }, ItemKind::Message)
        | (ItemState::Reasoning { text, .. }, ItemKind::Reasoning) => Ok(text),
        _ => Err(fetch_failed("text event targeted incompatible output item")),
    }
}

fn compare_terminal(item: &ItemState, snapshot: &ItemSnapshot) -> Result<(), FetchAdaptorError> {
    if item.id() != snapshot.id || item.done_status() != Some(snapshot.status.as_str()) {
        return Err(fetch_failed(
            "terminal output contradicted output_item.done identity/status",
        ));
    }
    match (item, &snapshot.body) {
        (ItemState::Message { text, .. }, SnapshotBody::Message(done))
        | (ItemState::Reasoning { text, .. }, SnapshotBody::Reasoning(done))
            if text.phase == TextPhase::PartDone && &text.value == done =>
        {
            Ok(())
        }
        (
            ItemState::Function {
                call_id,
                name,
                arguments,
                arguments_done,
                ..
            },
            SnapshotBody::Function {
                call_id: done_id,
                name: done_name,
                arguments: done_arguments,
            },
        ) if *arguments_done
            && call_id == done_id
            && name == done_name
            && arguments == done_arguments =>
        {
            Ok(())
        }
        _ => Err(fetch_failed(
            "terminal output contradicted streamed output item",
        )),
    }
}

fn exact_event_fields(
    event: &JsonMap<String, JsonValue>,
    allowed: &[&str],
) -> Result<(), FetchAdaptorError> {
    if let Some(field) = event.keys().find(|field| {
        field.as_str() != "type"
            && field.as_str() != "sequence_number"
            && !allowed.contains(&field.as_str())
    }) {
        return Err(fetch_failed(format!(
            "unsupported field `{field}` in Responses SSE event"
        )));
    }
    Ok(())
}

fn require_zero_index(
    event: &JsonMap<String, JsonValue>,
    field: &str,
) -> Result<(), FetchAdaptorError> {
    if event.get(field).and_then(JsonValue::as_u64) == Some(0) {
        Ok(())
    } else {
        Err(fetch_failed(format!("v0.0.1 requires {field}=0")))
    }
}

const RESPONSE_FIELDS: &[&str] = &[
    "id",
    "created_at",
    "error",
    "incomplete_details",
    "instructions",
    "metadata",
    "model",
    "object",
    "output",
    "parallel_tool_calls",
    "temperature",
    "tool_choice",
    "tools",
    "top_p",
    "background",
    "completed_at",
    "conversation",
    "max_output_tokens",
    "max_tool_calls",
    "moderation",
    "previous_response_id",
    "prompt",
    "prompt_cache_key",
    "prompt_cache_options",
    "prompt_cache_retention",
    "reasoning",
    "safety_identifier",
    "service_tier",
    "status",
    "text",
    "top_logprobs",
    "truncation",
    "usage",
    "user",
    "store",
    "billing",
];

fn validate_response_fields(
    response: &JsonMap<String, JsonValue>,
) -> Result<(), FetchAdaptorError> {
    if let Some(field) = response
        .keys()
        .find(|field| !RESPONSE_FIELDS.contains(&field.as_str()))
    {
        return Err(fetch_failed(format!(
            "unsupported field `{field}` in Responses response object"
        )));
    }
    Ok(())
}

fn response_identity<'a>(
    response: &'a JsonMap<String, JsonValue>,
    status: &str,
) -> Result<(&'a str, &'a str), FetchAdaptorError> {
    let id = required_string(response, "id", "Responses response object")?;
    let model = required_string(response, "model", "Responses response object")?;
    if id.is_empty()
        || model.is_empty()
        || required_string(response, "object", "Responses response object")? != "response"
        || required_string(response, "status", "Responses response object")? != status
    {
        return Err(fetch_failed(
            "Responses response id/object/status is malformed or contradictory",
        ));
    }
    Ok((id, model))
}

fn incomplete_stop_reason(
    response: &JsonMap<String, JsonValue>,
) -> Result<StopReason, FetchAdaptorError> {
    let details = required_object(response, "incomplete_details", "incomplete response")?;
    if details.len() != 1 || !details.contains_key("reason") {
        return Err(fetch_failed("malformed incomplete_details"));
    }
    match required_string(details, "reason", "incomplete_details")? {
        "max_output_tokens" | "max_tokens" => Ok(StopReason::MaxOutputTokens),
        "cancelled" => Ok(StopReason::Cancelled),
        other => Err(fetch_failed(format!(
            "unsupported incomplete reason `{other}`"
        ))),
    }
}

fn parse_usage(value: Option<&JsonValue>) -> Result<Option<Usage>, FetchAdaptorError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or_else(|| fetch_failed("Responses usage must be object or null"))?;
    const FIELDS: &[&str] = &[
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "input_tokens_details",
        "output_tokens_details",
    ];
    if let Some(field) = object
        .keys()
        .find(|field| !FIELDS.contains(&field.as_str()))
    {
        return Err(fetch_failed(format!(
            "unsupported Responses usage field `{field}`"
        )));
    }
    for field in ["input_tokens_details", "output_tokens_details"] {
        if object
            .get(field)
            .is_some_and(|value| !value.is_object() && !value.is_null())
        {
            return Err(fetch_failed(format!(
                "usage {field} must be object or null"
            )));
        }
    }
    let usage = Usage {
        input_tokens: optional_u64(object, "input_tokens")?,
        output_tokens: optional_u64(object, "output_tokens")?,
        total_tokens: optional_u64(object, "total_tokens")?,
    };
    if let (Some(input), Some(output), Some(total)) =
        (usage.input_tokens, usage.output_tokens, usage.total_tokens)
        && input.checked_add(output) != Some(total)
    {
        return Err(fetch_failed(
            "Responses usage total contradicted input + output",
        ));
    }
    Ok(Some(usage))
}

fn validate_empty_logprobs(event: &JsonMap<String, JsonValue>) -> Result<(), FetchAdaptorError> {
    if event
        .get("logprobs")
        .is_some_and(|value| !value.as_array().is_some_and(Vec::is_empty))
    {
        return Err(fetch_failed(
            "v0.0.1 does not project non-empty output logprobs",
        ));
    }
    Ok(())
}

fn required_object<'a>(
    object: &'a JsonMap<String, JsonValue>,
    key: &str,
    context: &str,
) -> Result<&'a JsonMap<String, JsonValue>, FetchAdaptorError> {
    object
        .get(key)
        .and_then(JsonValue::as_object)
        .ok_or_else(|| fetch_failed(format!("{context} requires object field `{key}`")))
}

fn required_string<'a>(
    object: &'a JsonMap<String, JsonValue>,
    key: &str,
    context: &str,
) -> Result<&'a str, FetchAdaptorError> {
    object
        .get(key)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| fetch_failed(format!("{context} requires string field `{key}`")))
}

fn required_index(
    object: &JsonMap<String, JsonValue>,
    key: &str,
    context: &str,
) -> Result<usize, FetchAdaptorError> {
    object
        .get(key)
        .and_then(JsonValue::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| fetch_failed(format!("{context} requires integer `{key}`")))
}

fn optional_u64(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> Result<Option<u64>, FetchAdaptorError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| fetch_failed(format!("Responses `{key}` must be integer")))
        })
        .transpose()
}

fn decode_arguments(arguments: &str) -> JsonValue {
    serde_json::from_str(arguments).unwrap_or_else(|_| JsonValue::String(arguments.to_string()))
}

fn bounded_failure_diagnostic(value: &str) -> String {
    let mut bounded = String::with_capacity(value.len().min(MAX_FETCH_FAILURE_DIAGNOSTIC_BYTES));
    let mut pending_space = false;

    for character in value.chars() {
        if character.is_whitespace() || character.is_control() {
            pending_space |= !bounded.is_empty();
            continue;
        }

        let separator_bytes = usize::from(pending_space);
        if bounded
            .len()
            .checked_add(separator_bytes)
            .and_then(|len| len.checked_add(character.len_utf8()))
            .is_none_or(|len| len > MAX_FETCH_FAILURE_DIAGNOSTIC_BYTES)
        {
            break;
        }
        if pending_space {
            bounded.push(' ');
            pending_space = false;
        }
        bounded.push(character);
    }

    bounded
}

fn fetch_payload_error(err: impl std::fmt::Display) -> FetchAdaptorError {
    fetch_failed(format!("fetch payload encoding failed: {err}"))
}

fn fetch_failed(message: impl Into<String>) -> FetchAdaptorError {
    let message = message.into();
    FetchAdaptorError::failed(bounded_failure_diagnostic(&message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::{Digest, InputCommitment};
    use serde_json::json;

    const TEST_MODEL: &str = "gpt-5.5-codex";

    fn call(body: Vec<u8>) -> FetchCall {
        FetchCall::new(
            "codex",
            "responses",
            JsonBytes::new(body),
            InputCommitment::from_digest(Digest::from_bytes([7; 32])),
        )
    }

    fn basic_request() -> FetchCall {
        call(
            format!(r#"{{"model":"{TEST_MODEL}","input":"hi","max_output_tokens":8}}"#)
                .into_bytes(),
        )
    }

    fn create(
        environment: FetchEnvironment,
        body: &[u8],
    ) -> Result<FetchAdaptorSession, FetchAdaptorError> {
        ResponsesFetchAdaptorFactory::new(environment).create(&call(body.to_vec()))
    }

    fn message_item(id: &str, status: &str, text: Option<&str>) -> JsonValue {
        let content = text
            .map(|text| {
                vec![json!({
                    "type": "output_text",
                    "text": text,
                    "annotations": [],
                })]
            })
            .unwrap_or_default();
        json!({
            "type": "message",
            "id": id,
            "status": status,
            "role": "assistant",
            "content": content,
        })
    }

    fn base_events() -> Vec<JsonValue> {
        vec![
            json!({
                "type": "response.created",
                "response": {
                    "id": "resp_1",
                    "object": "response",
                    "status": "in_progress",
                    "model": TEST_MODEL,
                    "output": [],
                },
            }),
            json!({
                "type": "response.output_item.added",
                "output_index": 0,
                "item": message_item("msg_1", "in_progress", None),
            }),
            json!({
                "type": "response.content_part.added",
                "item_id": "msg_1",
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []},
            }),
            json!({
                "type": "response.output_text.delta",
                "item_id": "msg_1",
                "output_index": 0,
                "content_index": 0,
                "delta": "hel",
            }),
            json!({
                "type": "response.output_text.delta",
                "item_id": "msg_1",
                "output_index": 0,
                "content_index": 0,
                "delta": "lo",
            }),
            json!({
                "type": "response.output_text.done",
                "item_id": "msg_1",
                "output_index": 0,
                "content_index": 0,
                "text": "hello",
            }),
            json!({
                "type": "response.content_part.done",
                "item_id": "msg_1",
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": "hello", "annotations": []},
            }),
            json!({
                "type": "response.output_item.done",
                "output_index": 0,
                "item": message_item("msg_1", "completed", Some("hello")),
            }),
            json!({
                "type": "response.completed",
                "response": {
                    "id": "resp_1",
                    "object": "response",
                    "status": "completed",
                    "model": TEST_MODEL,
                    "output": [message_item("msg_1", "completed", Some("hello"))],
                    "usage": {
                        "input_tokens": 1,
                        "output_tokens": 2,
                        "total_tokens": 3,
                    },
                },
            }),
        ]
    }

    fn with_sequences(events: &mut [JsonValue]) {
        for (sequence, event) in events.iter_mut().enumerate() {
            event["sequence_number"] = json!(sequence);
        }
    }

    fn sse(events: &[JsonValue]) -> Vec<u8> {
        let mut bytes = String::new();
        for event in events {
            let event_type = event["type"].as_str().expect("test event type");
            bytes.push_str("event: ");
            bytes.push_str(event_type);
            bytes.push('\n');
            bytes.push_str("data: ");
            bytes.push_str(&serde_json::to_string(event).unwrap());
            bytes.push_str("\n\n");
        }
        bytes.into_bytes()
    }

    fn openai_sse(events: &[JsonValue]) -> Vec<u8> {
        let mut events = events.to_vec();
        with_sequences(&mut events);
        sse(&events)
    }

    fn projector(environment: FetchEnvironment) -> ResponsesFetchProjector {
        assert_eq!(environment, FetchEnvironment::OpenAiResponses);
        ResponsesFetchProjector::new(Some(8))
    }

    fn project_all(
        environment: FetchEnvironment,
        chunks: &[&[u8]],
    ) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        let mut projector = projector(environment);
        let mut projected = Vec::new();
        for chunk in chunks {
            projected.extend(projector.project(chunk)?);
        }
        projected.extend(projector.finish()?);
        Ok(projected)
    }

    fn assert_rejected(body: &[u8], expected: &str) {
        let Err(error) = create(FetchEnvironment::OpenAiResponses, body) else {
            panic!("unsafe request accepted: {}", String::from_utf8_lossy(body));
        };
        assert!(
            error.to_string().contains(expected),
            "{error} did not contain {expected:?}"
        );
    }

    fn assert_bounded_projector_failure(error: FetchAdaptorError) -> String {
        const PREFIX: &str = "fetch adaptor failed: ";
        let rendered = error.to_string();
        let diagnostic = rendered
            .strip_prefix(PREFIX)
            .unwrap_or_else(|| panic!("unexpected Fetch adaptor error: {rendered}"));
        assert!(
            diagnostic.len() <= MAX_FETCH_FAILURE_DIAGNOSTIC_BYTES,
            "{}-byte diagnostic exceeded the {}-byte limit: {diagnostic}",
            diagnostic.len(),
            MAX_FETCH_FAILURE_DIAGNOSTIC_BYTES,
        );
        rendered
    }

    #[test]
    fn trusted_request_is_fresh_built_and_forces_transport_flags() {
        let raw = br#"{
            "model":"gpt-5.5-codex",
            "input":[
                {"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},
                {"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{\"q\":\"x\"}","id":"fc_1","status":"completed"},
                {"type":"function_call_output","call_id":"call_1","output":"ok","status":"completed"}
            ],
            "tools":[{"type":"function","name":"lookup","description":"Lookup","parameters":{"type":"object"},"strict":true}],
            "tool_choice":{"type":"function","name":"lookup"},
            "reasoning":{"effort":"low","summary":"auto"},
            "text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object","additionalProperties":false},"strict":true}},
            "max_output_tokens":8
        }"#;
        let session = create(FetchEnvironment::OpenAiResponses, raw).unwrap();
        let rebuilt: JsonValue =
            serde_json::from_slice(session.provider_request.body.as_bytes()).unwrap();

        assert_ne!(session.provider_request.body.as_bytes(), raw);
        assert_eq!(rebuilt["stream"], true);
        assert_eq!(rebuilt["store"], false);
        assert_eq!(rebuilt["text"]["format"]["type"], "json_schema");
        assert_eq!(rebuilt["tools"][0]["parameters"], json!({"type": "object"}));
        assert_eq!(rebuilt["input"][1]["arguments"], json!("{\"q\":\"x\"}"));
    }

    #[test]
    fn request_rejects_unknown_fields_at_every_nested_seam() {
        let rejected = [
            br#"{"model":"m","input":"hi","metadata":{"trace":"x"}}"#.as_slice(),
            br#"{"model":"m","input":[{"type":"message","role":"user","content":"hi","surprise":1}]}"#.as_slice(),
            br#"{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi","surprise":1}]}]}"#.as_slice(),
            br#"{"model":"m","input":[{"type":"function_call","call_id":"c","name":"f","arguments":"{}","surprise":1}]}"#.as_slice(),
            br#"{"model":"m","input":[{"type":"function_call_output","call_id":"c","output":"ok","surprise":1}]}"#.as_slice(),
            br#"{"model":"m","input":"hi","tools":[{"type":"function","name":"f","parameters":{},"strict":true,"surprise":1}]}"#.as_slice(),
            br#"{"model":"m","input":"hi","tools":[{"type":"function","name":"f","parameters":{},"strict":true}],"tool_choice":{"type":"function","name":"f","surprise":1}}"#.as_slice(),
            br#"{"model":"m","input":"hi","reasoning":{"effort":"low","surprise":"raw"}}"#.as_slice(),
            br#"{"model":"m","input":"hi","text":{"format":{"type":"text"},"surprise":1}}"#.as_slice(),
            br#"{"model":"m","input":"hi","text":{"format":{"type":"json_schema","name":"x","schema":{},"surprise":1}}}"#.as_slice(),
        ];
        for body in rejected {
            assert_rejected(body, "invalid v0.0.1 Responses request");
        }
    }

    #[test]
    fn request_rejects_raw_metadata_reasoning_and_format_variants() {
        let rejected = [
            (
                br#"{"model":"m","input":"hi","metadata":null}"#.as_slice(),
                "unknown field `metadata`",
            ),
            (
                br#"{"model":"m","input":"hi","reasoning":"raw"}"#.as_slice(),
                "invalid v0.0.1 Responses request",
            ),
            (
                br#"{"model":"m","input":"hi","response_format":{"type":"text"}}"#.as_slice(),
                "unknown field `response_format`",
            ),
            (
                br#"{"model":"m","input":"hi","text":{"format":{"type":"grammar","grammar":"x"}}}"#
                    .as_slice(),
                "unknown variant `grammar`",
            ),
            (
                br#"{"model":"m","input":"hi","tools":[{"type":"web_search"}]}"#.as_slice(),
                "unknown variant `web_search`",
            ),
        ];
        for (body, expected) in rejected {
            assert_rejected(body, expected);
        }
    }

    #[test]
    fn request_enforces_closed_values_and_opaque_object_boundaries() {
        let rejected = [
            br#"{"model":"m","input":[{"type":"function_call","call_id":"c","name":"f","arguments":{}}]}"#.as_slice(),
            br#"{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"output_text","text":"x"}]}]}"#.as_slice(),
            br#"{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"text","text":"x"}]}]}"#.as_slice(),
            br#"{"model":"m","input":"hi","reasoning":{"effort":"future"}}"#.as_slice(),
            br#"{"model":"m","input":"hi","reasoning":{"summary":"raw"}}"#.as_slice(),
            br#"{"model":"m","input":"hi","truncation":"future"}"#.as_slice(),
            br#"{"model":"m","input":"hi","temperature":2.1}"#.as_slice(),
            br#"{"model":"m","input":"hi","top_p":1.1}"#.as_slice(),
            br#"{"model":"m","input":"hi","top_logprobs":21}"#.as_slice(),
            br#"{"model":"m","input":"hi","max_output_tokens":0}"#.as_slice(),
            br#"{"model":"m","input":"hi","text":{"format":{"type":"json_schema","name":"x","schema":"raw"}}}"#.as_slice(),
        ];
        for body in rejected {
            assert_rejected(body, "");
        }
    }

    #[test]
    fn openai_forces_unobfuscated_streams_and_rejects_obfuscation() {
        let session = create(
            FetchEnvironment::OpenAiResponses,
            br#"{"model":"m","input":"hi"}"#,
        )
        .unwrap();
        let rebuilt: JsonValue =
            serde_json::from_slice(session.provider_request.body.as_bytes()).unwrap();
        assert_eq!(rebuilt["stream_options"]["include_obfuscation"], false);

        let body = br#"{"model":"m","input":"hi","stream_options":{"include_obfuscation":true}}"#;
        let Err(error) = create(FetchEnvironment::OpenAiResponses, body) else {
            panic!("stream obfuscation was accepted");
        };
        assert!(error.to_string().contains("stream obfuscation"));
    }

    #[test]
    fn request_rejects_contradictory_storage_or_streaming() {
        assert_rejected(br#"{"model":"m","input":"hi","store":true}"#, "store=true");
        assert_rejected(
            br#"{"model":"m","input":"hi","stream":false}"#,
            "stream=false",
        );
    }

    fn request_of_exact_size(size: usize, force_fields: bool) -> Vec<u8> {
        let prefix = br#"{"model":"m","input":""#;
        let suffix = if force_fields {
            br#"","stream":true,"store":false,"stream_options":{"include_obfuscation":false}}"#
                .as_slice()
        } else {
            br#""}"#.as_slice()
        };
        assert!(size >= prefix.len() + suffix.len());
        let mut body = Vec::with_capacity(size);
        body.extend_from_slice(prefix);
        body.resize(size - suffix.len(), b'a');
        body.extend_from_slice(suffix);
        assert_eq!(body.len(), size);
        body
    }

    #[test]
    fn request_body_limits_accept_exact_boundary_and_reject_each_oversize_path() {
        let exact = request_of_exact_size(MAX_FETCH_REQUEST_BODY_BYTES, true);
        create(FetchEnvironment::OpenAiResponses, &exact).unwrap();

        let caller_oversize = request_of_exact_size(MAX_FETCH_REQUEST_BODY_BYTES + 1, true);
        assert_rejected(&caller_oversize, "signed Fetch request body exceeds");

        let rebuilt_oversize = request_of_exact_size(MAX_FETCH_REQUEST_BODY_BYTES, false);
        assert_rejected(&rebuilt_oversize, "rebuilt upstream Responses body exceeds");
    }

    #[test]
    fn projection_is_independent_of_sse_chunk_boundaries() {
        let bytes = openai_sse(&base_events());
        let single = [&bytes[..]];
        let split = [&bytes[..17], &bytes[17..103], &bytes[103..]];

        let projected_a = project_all(FetchEnvironment::OpenAiResponses, &single).unwrap();
        let projected_b = project_all(FetchEnvironment::OpenAiResponses, &split).unwrap();

        assert_eq!(projected_a, projected_b);
        assert_eq!(projected_a.len(), 3);
        assert!(matches!(projected_a[0], ProjectedFetch::Event(_)));
        assert!(matches!(projected_a[1], ProjectedFetch::Event(_)));
        assert!(matches!(projected_a[2], ProjectedFetch::Terminal(_)));
    }

    #[test]
    fn openai_sse_wire_grammar_is_closed() {
        let mut created = base_events().remove(0);
        created["sequence_number"] = json!(0);
        let kind = created["type"].as_str().unwrap();
        let data = serde_json::to_string(&created).unwrap();
        let split_at = data.find(',').unwrap() + 1;
        let cases = [
            (
                "comment",
                format!(": ping\nevent: {kind}\ndata: {data}\n\n"),
                "non-canonical SSE lines",
            ),
            (
                "unknown line",
                format!("event: {kind}\nid: hidden\ndata: {data}\n\n"),
                "non-canonical SSE lines",
            ),
            (
                "duplicate event line",
                format!("event: {kind}\nevent: {kind}\ndata: {data}\n\n"),
                "non-canonical SSE lines",
            ),
            (
                "late event line",
                format!("data: {data}\nevent: {kind}\n\n"),
                "non-canonical SSE framing",
            ),
            (
                "multiline data",
                format!(
                    "event: {kind}\ndata: {}\ndata: {}\n\n",
                    &data[..split_at],
                    &data[split_at..]
                ),
                "non-canonical SSE framing",
            ),
            (
                "missing event line",
                format!("data: {data}\n\n"),
                "non-canonical SSE framing",
            ),
            ("empty frame", "\n\n".to_string(), "non-data SSE frame"),
            (
                "comment-only frame",
                ": ping\n\n".to_string(),
                "non-data SSE frame",
            ),
        ];

        for (label, bytes, expected) in cases {
            let mut projector = projector(FetchEnvironment::OpenAiResponses);
            let error = projector.project(bytes.as_bytes()).unwrap_err().to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn openai_sse_requires_an_explicit_final_frame_delimiter() {
        let mut bytes = openai_sse(&base_events());
        bytes.truncate(bytes.len() - 2);
        let mut projector = projector(FetchEnvironment::OpenAiResponses);
        projector.project(&bytes).unwrap();
        let error = projector.finish().unwrap_err().to_string();
        assert!(error.contains("blank-line frame delimiter"), "{error}");
    }

    #[test]
    fn openai_requires_sequences_and_all_delta_indices() {
        let mut events = base_events();
        with_sequences(&mut events);
        project_all(FetchEnvironment::OpenAiResponses, &[&openai_sse(&events)]).unwrap();

        let mut missing_sequence = events.clone();
        missing_sequence[3]
            .as_object_mut()
            .unwrap()
            .remove("sequence_number");
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&sse(&missing_sequence)],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires integer sequence_number"),
            "{error}"
        );

        let mut missing_index = events;
        missing_index[3]
            .as_object_mut()
            .unwrap()
            .remove("output_index");
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&missing_index)],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires output_index and item_id")
        );
    }

    #[test]
    fn unknown_or_malformed_semantic_events_fail_closed() {
        let mut unknown = base_events();
        unknown[3]["type"] = json!("response.future_semantics.delta");
        let error =
            project_all(FetchEnvironment::OpenAiResponses, &[&openai_sse(&unknown)]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported Responses SSE event")
        );

        let mut unknown_field = base_events();
        unknown_field[3]["account_state"] = json!("sentinel");
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&unknown_field)],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported field `account_state`")
        );

        let mut missing_id = base_events();
        missing_id[5].as_object_mut().unwrap().remove("item_id");
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&missing_id)],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires output_index and item_id")
        );
    }

    #[test]
    fn upstream_failure_diagnostics_are_bounded_and_sanitized() {
        let created = base_events().remove(0);
        for failed in [
            json!({
                "type": "response.failed",
                "response": {
                    "id": "resp_1",
                    "object": "response",
                    "status": "failed",
                    "model": TEST_MODEL,
                    "output": [],
                    "error": {"message": format!("{}\nsecret", "x".repeat(4_096))},
                },
            }),
            json!({
                "type": "error",
                "code": "upstream_error",
                "message": format!("{}\nsecret", "y".repeat(4_096)),
                "param": null,
            }),
        ] {
            let mut projector = projector(FetchEnvironment::OpenAiResponses);
            let error = projector
                .project(&openai_sse(&[created.clone(), failed]))
                .unwrap_err();
            let error = assert_bounded_projector_failure(error);
            assert!(!error.contains('\n'), "{error:?}");
            assert!(!error.contains("secret"), "{error}");
        }
    }

    #[test]
    fn every_attacker_controlled_projector_diagnostic_is_byte_bounded() {
        let hostile = format!("{}secret", "🧨".repeat(1_024));

        let unknown_type = json!({"type": hostile.clone()});
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&[unknown_type])],
        )
        .unwrap_err();
        assert!(!assert_bounded_projector_failure(error).contains("secret"));

        let mut unknown_field = base_events().remove(0);
        unknown_field
            .as_object_mut()
            .unwrap()
            .insert(hostile.clone(), JsonValue::Null);
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&[unknown_field])],
        )
        .unwrap_err();
        assert!(!assert_bounded_projector_failure(error).contains("secret"));

        let mut malformed_discriminator = base_events();
        malformed_discriminator[1]["item"]["type"] = json!(hostile.clone());
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&malformed_discriminator)],
        )
        .unwrap_err();
        assert!(!assert_bounded_projector_failure(error).contains("secret"));

        let mut incomplete = base_events();
        incomplete[7]["item"]["status"] = json!("incomplete");
        incomplete[8]["type"] = json!("response.incomplete");
        incomplete[8]["response"]["status"] = json!("incomplete");
        incomplete[8]["response"]["output"][0]["status"] = json!("incomplete");
        incomplete[8]["response"]["incomplete_details"] = json!({"reason": hostile});
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&incomplete)],
        )
        .unwrap_err();
        assert!(!assert_bounded_projector_failure(error).contains("secret"));
    }

    #[test]
    fn delta_done_item_and_terminal_representations_must_agree() {
        let mut delta_done = base_events();
        delta_done[5]["text"] = json!("hullo");
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&delta_done)],
        )
        .unwrap_err();
        assert!(error.to_string().contains("deltas contradicted"));

        let mut item_done = base_events();
        item_done[7]["item"] = message_item("msg_1", "completed", Some("hullo"));
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&item_done)],
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("contradicted streamed text"),
            "{error}"
        );

        let mut terminal = base_events();
        terminal[8]["response"]["output"][0] = message_item("msg_1", "completed", Some("hullo"));
        let error =
            project_all(FetchEnvironment::OpenAiResponses, &[&openai_sse(&terminal)]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("terminal output contradicted streamed output item"),
            "{error}"
        );
    }

    #[test]
    fn semantic_items_require_the_exact_open_delta_done_lifecycle() {
        let mut missing_part_added = base_events();
        missing_part_added.remove(2);
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&missing_part_added)],
        )
        .unwrap_err();
        assert!(error.to_string().contains("outside an open content part"));

        let mut missing_part_done = base_events();
        missing_part_done.remove(6);
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&missing_part_done)],
        )
        .unwrap_err();
        assert!(error.to_string().contains("output_item.done contradicted"));

        let mut missing_created_output = base_events();
        missing_created_output[0]["response"]
            .as_object_mut()
            .unwrap()
            .remove("output");
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&missing_created_output)],
        )
        .unwrap_err();
        assert!(error.to_string().contains("requires output array"));
    }

    #[test]
    fn response_model_claim_must_be_present_and_stable() {
        let mut missing = base_events();
        missing[0]["response"]
            .as_object_mut()
            .unwrap()
            .remove("model");
        let error =
            project_all(FetchEnvironment::OpenAiResponses, &[&openai_sse(&missing)]).unwrap_err();
        assert!(error.to_string().contains("requires string field `model`"));

        let mut changed = base_events();
        changed[8]["response"]["model"] = json!("different-model");
        let error =
            project_all(FetchEnvironment::OpenAiResponses, &[&openai_sse(&changed)]).unwrap_err();
        assert!(error.to_string().contains("contradicted response.created"));
    }

    #[test]
    fn terminal_requires_output_and_admitted_usage() {
        let mut missing = base_events();
        missing[8]["response"]
            .as_object_mut()
            .unwrap()
            .remove("output");
        let error =
            project_all(FetchEnvironment::OpenAiResponses, &[&openai_sse(&missing)]).unwrap_err();
        assert!(error.to_string().contains("missing output array"));

        let mut over_limit = base_events();
        over_limit[8]["response"]["usage"] = json!({
            "input_tokens": 1,
            "output_tokens": 9,
            "total_tokens": 10,
        });
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&over_limit)],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exceeds admitted max_output_tokens")
        );

        let mut contradictory = base_events();
        contradictory[8]["response"]["usage"]["total_tokens"] = json!(99);
        let error = project_all(
            FetchEnvironment::OpenAiResponses,
            &[&openai_sse(&contradictory)],
        )
        .unwrap_err();
        assert!(error.to_string().contains("usage total contradicted"));
    }

    #[test]
    fn terminal_is_deferred_until_eof_and_post_terminal_data_is_rejected() {
        let bytes = openai_sse(&base_events());
        let mut first = projector(FetchEnvironment::OpenAiResponses);
        let projected = first.project(&bytes).unwrap();
        assert!(
            !projected
                .iter()
                .any(|event| matches!(event, ProjectedFetch::Terminal(_)))
        );
        assert!(matches!(
            first.finish().unwrap().as_slice(),
            [ProjectedFetch::Terminal(_)]
        ));

        let mut post_terminal = projector(FetchEnvironment::OpenAiResponses);
        post_terminal.project(&bytes).unwrap();
        let error = post_terminal.project(b"data: {}\n\n").unwrap_err();
        assert!(error.to_string().contains("bytes after terminal"));

        for suffix in [
            b" ".as_slice(),
            b"data: {\"type\":\"response.future".as_slice(),
            b": ping\n\n".as_slice(),
        ] {
            let mut with_suffix = bytes.clone();
            with_suffix.extend_from_slice(suffix);
            let mut projector = projector(FetchEnvironment::OpenAiResponses);
            assert!(projector.project(&with_suffix).is_err());
        }
    }

    #[test]
    fn duplicate_terminal_or_missing_terminal_is_rejected() {
        let mut duplicate = base_events();
        duplicate.push(duplicate.last().unwrap().clone());
        let mut projector = projector(FetchEnvironment::OpenAiResponses);
        let error = projector.project(&openai_sse(&duplicate)).unwrap_err();
        assert!(error.to_string().contains("event after its terminal"));

        let mut missing = base_events();
        missing.pop();
        let error =
            project_all(FetchEnvironment::OpenAiResponses, &[&openai_sse(&missing)]).unwrap_err();
        assert!(error.to_string().contains("without verified terminal"));
    }

    #[test]
    fn later_terminal_contradiction_never_yields_a_signed_completion() {
        let events = base_events();
        let prefix = openai_sse(&events[..8]);
        let mut projector = projector(FetchEnvironment::OpenAiResponses);

        let streamed = projector.project(&prefix).unwrap();
        assert_eq!(
            streamed
                .iter()
                .filter(|event| matches!(event, ProjectedFetch::Event(_)))
                .count(),
            2
        );

        let mut contradictory: JsonValue = events[8].clone();
        contradictory["response"]["output"][0] =
            message_item("msg_1", "completed", Some("different"));
        assert!(projector.project(&openai_sse(&[contradictory])).is_err());
    }

    #[test]
    fn reasoning_and_function_calls_are_accumulated_and_cross_checked() {
        let reasoning = |status: &str, text: &str| {
            json!({
                "type": "reasoning",
                "id": "reason_1",
                "status": status,
                "summary": if text.is_empty() {
                    Vec::<JsonValue>::new()
                } else {
                    vec![json!({"type":"summary_text","text":text})]
                },
            })
        };
        let function = |status: &str, arguments: &str| {
            json!({
                "type": "function_call",
                "id": "item_call_1",
                "call_id": "call_1",
                "name": "lookup",
                "arguments": arguments,
                "status": status,
            })
        };
        let events = vec![
            json!({"type":"response.created","response":{"id":"resp_1","object":"response","status":"in_progress","model":TEST_MODEL,"output":[]}}),
            json!({"type":"response.output_item.added","output_index":0,"item":reasoning("in_progress", "")}),
            json!({"type":"response.reasoning_summary_part.added","item_id":"reason_1","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":""}}),
            json!({"type":"response.reasoning_summary_text.delta","item_id":"reason_1","output_index":0,"summary_index":0,"delta":"think"}),
            json!({"type":"response.reasoning_summary_text.done","item_id":"reason_1","output_index":0,"summary_index":0,"text":"think"}),
            json!({"type":"response.reasoning_summary_part.done","item_id":"reason_1","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":"think"}}),
            json!({"type":"response.output_item.done","output_index":0,"item":reasoning("completed", "think")}),
            json!({"type":"response.output_item.added","output_index":1,"item":function("in_progress", "")}),
            json!({"type":"response.function_call_arguments.delta","item_id":"item_call_1","output_index":1,"delta":"{\"x\":"}),
            json!({"type":"response.function_call_arguments.delta","item_id":"item_call_1","output_index":1,"delta":"1}"}),
            json!({"type":"response.function_call_arguments.done","item_id":"item_call_1","output_index":1,"name":"lookup","arguments":"{\"x\":1}"}),
            json!({"type":"response.output_item.done","output_index":1,"item":function("completed", "{\"x\":1}")}),
            json!({"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","model":TEST_MODEL,"output":[reasoning("completed", "think"),function("completed", "{\"x\":1}")],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}}),
        ];

        let projected =
            project_all(FetchEnvironment::OpenAiResponses, &[&openai_sse(&events)]).unwrap();
        assert_eq!(projected.len(), 6);
        assert!(matches!(
            projected.last(),
            Some(ProjectedFetch::Terminal(_))
        ));
    }

    #[test]
    fn function_argument_events_reject_non_function_items_without_panicking() {
        let prefix = vec![
            json!({"type":"response.created","response":{"id":"resp_1","object":"response","status":"in_progress","model":TEST_MODEL,"output":[]}}),
            json!({"type":"response.output_item.added","output_index":0,"item":message_item("msg_1", "in_progress", None)}),
        ];
        let cases = [
            json!({"type":"response.function_call_arguments.delta","item_id":"msg_1","output_index":0,"delta":"{}"}),
            json!({"type":"response.function_call_arguments.done","item_id":"msg_1","output_index":0,"name":"lookup","arguments":"{}"}),
        ];

        for event in cases {
            let mut events = prefix.clone();
            events.push(event);
            let mut projector = projector(FetchEnvironment::OpenAiResponses);
            let error = projector.project(&openai_sse(&events)).unwrap_err();
            assert!(
                error.to_string().contains("non-function output item"),
                "{error}"
            );
        }
    }

    #[test]
    fn well_shaped_incomplete_terminal_is_signed() {
        let mut events = base_events();
        events[7]["item"]["status"] = json!("incomplete");
        events[8]["type"] = json!("response.incomplete");
        events[8]["response"]["status"] = json!("incomplete");
        events[8]["response"]["output"][0]["status"] = json!("incomplete");
        events[8]["response"]["incomplete_details"] = json!({"reason":"max_output_tokens"});

        let projected =
            project_all(FetchEnvironment::OpenAiResponses, &[&openai_sse(&events)]).unwrap();
        assert!(matches!(
            projected.last(),
            Some(ProjectedFetch::Terminal(_))
        ));
    }

    #[test]
    fn exact_fetch_manifest_identity_selects_each_strict_variant() {
        for environment in [
            FetchEnvironment::OpenAiResponses,
            FetchEnvironment::OpenAiResponses,
        ] {
            let factory = ResponsesFetchAdaptorFactory::new(environment);
            assert_eq!(factory.execution_environment(), environment.manifest_id());
        }
    }

    #[test]
    fn factory_builds_a_strict_session_for_a_basic_request() {
        let session = ResponsesFetchAdaptorFactory::new(FetchEnvironment::OpenAiResponses)
            .create(&basic_request())
            .unwrap();
        let body: JsonValue =
            serde_json::from_slice(session.provider_request.body.as_bytes()).unwrap();
        assert_eq!(body["stream"], true);
        assert_eq!(body["store"], false);
    }
}
