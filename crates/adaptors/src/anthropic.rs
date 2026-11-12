use serde_json::{Map as JsonMap, Value as JsonValue, json};

use crate::{
    AdaptorError, AdaptorResult, CanonicalExecution, ContentPart, ExecutionRequest,
    ExecutionResult, HistoricalToolCall, Input, InputItem, Message, ModelRef, OutputEvent,
    OutputItem, RawRequest, ReasoningOptions, RenderContext, StopReason, TextChannel, ToolChoice,
    ToolKind, ToolSpec, WireAdaptor, WireResponse, WireStreamEvent,
    json::{
        attach_hellas, json_to_wire_string, optional_array, optional_bool, optional_f32,
        optional_string, required_array, required_string, structured_delta_string,
    },
};

#[derive(Clone, Copy, Debug, Default)]
pub struct AnthropicMessagesAdaptor;

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedAnthropicMessageRequest {
    pub raw: RawRequest,
    pub model: String,
    pub max_tokens: u32,
    pub stream: Option<bool>,
    canonical: CanonicalExecution,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnthropicMessagesStreamState {
    id: String,
    model: String,
    started: bool,
    usage: Option<crate::Usage>,
    provenance: Option<crate::Provenance>,
    next_block_index: usize,
    open_block: Option<AnthropicOpenBlock>,
    tool_calls: Vec<AnthropicToolCallState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AnthropicOpenBlock {
    index: usize,
    kind: AnthropicBlockKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnthropicBlockKind {
    Text,
    Thinking,
    Tool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AnthropicToolCallState {
    parser_index: usize,
    block_index: usize,
}

/// The Anthropic error type of a failure reported with HTTP `status`.
fn error_type(status: u16) -> &'static str {
    match status {
        400 | 409 | 422 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        413 => "request_too_large",
        429 => "rate_limit_error",
        503 | 529 => "overloaded_error",
        _ => "api_error",
    }
}

/// A refusal or failure as the Anthropic Messages API reports it.
pub fn render_error(status: u16, message: String) -> WireResponse {
    WireResponse::json(
        status,
        json!({ "type": "error", "error": { "type": error_type(status), "message": message } }),
    )
}

impl WireAdaptor for AnthropicMessagesAdaptor {
    type ParsedRequest = ParsedAnthropicMessageRequest;
    type StreamState = AnthropicMessagesStreamState;

    fn parse(&self, raw: RawRequest) -> AdaptorResult<Self::ParsedRequest> {
        ParsedAnthropicMessageRequest::parse(raw)
    }

    fn to_execution_request(
        &self,
        request: &Self::ParsedRequest,
    ) -> AdaptorResult<ExecutionRequest> {
        request.to_execution_request()
    }

    fn initial_state(
        &self,
        request: &Self::ParsedRequest,
        context: RenderContext,
    ) -> Self::StreamState {
        AnthropicMessagesStreamState {
            id: context.response_id,
            model: request.model.clone(),
            started: false,
            usage: None,
            provenance: None,
            next_block_index: 0,
            open_block: None,
            tool_calls: Vec::new(),
        }
    }

    fn render_response(
        &self,
        request: &Self::ParsedRequest,
        result: ExecutionResult,
        context: RenderContext,
    ) -> AdaptorResult<WireResponse> {
        if let Some(error) = result.error {
            return Ok(WireResponse::json(
                500,
                attach_hellas(
                    json!({
                        "type": "error",
                        "error": {
                            "type": error.code.unwrap_or_else(|| "api_error".to_string()),
                            "message": error.message,
                        }
                    }),
                    result.provenance.as_ref(),
                ),
            ));
        }
        let mut body = json!({
            "id": context.response_id,
            "type": "message",
            "role": "assistant",
            "content": output_blocks_json(&result.output),
            "model": request.model,
            "stop_reason": stop_reason_json(result.stop_reason),
        });
        if let Some(usage) = result.usage {
            body["usage"] = usage_json(usage);
        }
        Ok(WireResponse::json(
            200,
            attach_hellas(body, result.provenance.as_ref()),
        ))
    }

    fn render_stream_start(
        &self,
        _request: &Self::ParsedRequest,
        state: &mut Self::StreamState,
    ) -> AdaptorResult<Vec<WireStreamEvent>> {
        if state.started {
            return Ok(Vec::new());
        }
        state.started = true;
        Ok(vec![WireStreamEvent::json(
            Some("message_start".to_string()),
            attach_hellas(
                json!({
                    "type": "message_start",
                    "message": {
                        "id": state.id,
                        "type": "message",
                        "role": "assistant",
                        "content": [],
                        "model": state.model,
                        "usage": usage_json(crate::Usage {
                            input_tokens: Some(0),
                            output_tokens: Some(0),
                            total_tokens: Some(0),
                        }),
                    },
                }),
                state.provenance.as_ref(),
            ),
        )])
    }

    fn render_error(&self, status: u16, message: String) -> WireResponse {
        render_error(status, message)
    }

    fn error_code(&self, status: u16) -> Option<String> {
        Some(error_type(status).to_string())
    }

    fn attest(&self, state: &mut Self::StreamState, provenance: crate::Provenance) {
        crate::execution::merge_provenance(&mut state.provenance, provenance);
    }

    fn render_stream_event(
        &self,
        _request: &Self::ParsedRequest,
        state: &mut Self::StreamState,
        event: OutputEvent,
    ) -> AdaptorResult<Vec<WireStreamEvent>> {
        match event {
            OutputEvent::TextDelta {
                delta,
                channel: TextChannel::Output,
                ..
            } => render_text_delta(state, AnthropicBlockKind::Text, delta),
            OutputEvent::TextDelta {
                delta,
                channel: TextChannel::Reasoning,
                ..
            } => render_text_delta(state, AnthropicBlockKind::Thinking, delta),
            OutputEvent::StructuredOutputDelta(delta) => render_text_delta(
                state,
                AnthropicBlockKind::Text,
                structured_delta_string(delta),
            ),
            OutputEvent::Adaptor(_) => Err(AdaptorError::unsupported(
                "Anthropic Messages cannot render adaptor-specific events",
            )),
            OutputEvent::ToolCallStart(start) => render_tool_call_start(state, start),
            OutputEvent::ToolCallArgumentsDelta(delta) => {
                render_tool_call_arguments_delta(state, delta.index, delta.delta)
            }
            OutputEvent::ToolCallEnd(end) => render_tool_call_end(state, end.index),
            OutputEvent::Usage(usage) => {
                state.usage = Some(usage);
                Ok(Vec::new())
            }
            OutputEvent::Provenance(provenance) => {
                self.attest(state, provenance.into());
                Ok(Vec::new())
            }
            OutputEvent::Error { message, code } => {
                let mut events = close_open_block(state);
                events.push(WireStreamEvent::json(
                    Some("error".to_string()),
                    json!({
                        "type": "error",
                        "error": {
                            "type": code.unwrap_or_else(|| "api_error".to_string()),
                            "message": message,
                        },
                    }),
                ));
                Ok(events)
            }
            OutputEvent::Finished { stop_reason, usage } => {
                if let Some(usage) = usage {
                    state.usage = Some(usage);
                }
                let mut events = close_open_block(state);
                events.push(WireStreamEvent::json(
                    Some("message_delta".to_string()),
                    json!({
                        "type": "message_delta",
                        "delta": {"stop_reason": stop_reason_json(stop_reason)},
                        "usage": state.usage.map(usage_json).unwrap_or_else(|| {
                            usage_json(crate::Usage::default())
                        }),
                    }),
                ));
                events.push(WireStreamEvent::json(
                    Some("message_stop".to_string()),
                    attach_hellas(json!({"type": "message_stop"}), state.provenance.as_ref()),
                ));
                Ok(events)
            }
        }
    }
}

impl ParsedAnthropicMessageRequest {
    fn parse(raw: RawRequest) -> AdaptorResult<Self> {
        let object = raw.value().as_object().ok_or_else(|| {
            AdaptorError::invalid_request("Anthropic Messages request must be a JSON object")
        })?;
        // These controls have no canonical equivalent. Metadata and cache hints
        // remain harmless, but execution-affecting options must not disappear.
        reject_fields(
            object,
            &["top_k", "output_format", "container", "mcp_servers"],
        )?;
        if let Some(config) = object.get("output_config").filter(|v| !v.is_null()) {
            validate_output_config(config)?;
        }
        if let Some(edits) = object.get("context_management").filter(|v| !v.is_null()) {
            validate_context_management(edits)?;
        }
        let model = required_string(object, "model")?;
        let max_tokens = required_u32(object, "max_tokens")?;
        let stream = optional_bool(object, "stream")?;
        let mut tools = optional_array(object, "tools")?
            .unwrap_or_default()
            .iter()
            .map(project_tool)
            .collect::<AdaptorResult<Vec<_>>>()?;
        let mut items = Vec::new();
        let system = text_content(object.get("system"))?;
        if !system.is_empty() {
            items.push(InputItem::Message(Message {
                role: "system".into(),
                content: system,
                name: None,
                tool_calls: Vec::new(),
            }));
        }
        for message in required_array(object, "messages")? {
            project_message(&message, &mut items, &mut tools)?;
        }
        let mut canonical =
            CanonicalExecution::new(ModelRef::new(model.clone()), Input::Items(items));
        canonical.sampling.max_output_tokens = Some(max_tokens);
        canonical.sampling.temperature = probability(object, "temperature")?;
        canonical.sampling.top_p = probability(object, "top_p")?;
        canonical.sampling.stop = optional_array(object, "stop_sequences")?
            .unwrap_or_default()
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    AdaptorError::invalid_request("`stop_sequences` entries must be strings")
                })
            })
            .collect::<AdaptorResult<_>>()?;
        canonical.tools = tools
            .into_iter()
            .filter_map(|(tool, loaded)| loaded.then_some(tool))
            .collect();
        if let Some(value) = object.get("tool_choice") {
            let projected = project_tool_choice(value)?;
            canonical.tool_choice = projected.choice;
            canonical.sampling.parallel_tool_calls = projected.parallel_tool_calls;
        }
        if let Some(thinking) = object.get("thinking")
            && thinking_requested(thinking)?
        {
            canonical.reasoning = Some(ReasoningOptions {
                value: thinking.clone(),
            });
        }
        Ok(Self {
            raw,
            model,
            max_tokens,
            stream,
            canonical,
        })
    }

    fn to_execution_request(&self) -> AdaptorResult<ExecutionRequest> {
        Ok(ExecutionRequest::new(self.canonical.clone()))
    }
}

fn reject_fields(object: &JsonMap<String, JsonValue>, fields: &[&str]) -> AdaptorResult<()> {
    for field in fields {
        if object.get(*field).is_some_and(|value| !value.is_null()) {
            return Err(AdaptorError::invalid_request(format!(
                "Anthropic `{field}` is not supported"
            )));
        }
    }
    Ok(())
}

fn probability(object: &JsonMap<String, JsonValue>, key: &str) -> AdaptorResult<Option<f32>> {
    let value = optional_f32(object, key)?;
    if value.is_some_and(|value| !(0.0..=1.0).contains(&value)) {
        return Err(AdaptorError::invalid_request(format!(
            "`{key}` must be between 0 and 1"
        )));
    }
    Ok(value)
}

fn project_message(
    value: &JsonValue,
    items: &mut Vec<InputItem>,
    tools: &mut [(ToolSpec, bool)],
) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("Anthropic message must be a JSON object"))?;
    let role = required_string(object, "role")?;
    if !matches!(role.as_str(), "user" | "assistant" | "system") {
        return Err(AdaptorError::invalid_request(
            "Anthropic message role must be user, assistant or system",
        ));
    }
    let content = object
        .get("content")
        .ok_or_else(|| AdaptorError::invalid_request("Anthropic message missing `content`"))?;
    if let JsonValue::String(text) = content {
        items.push(InputItem::Message(Message::text(role, text.clone())));
        return Ok(());
    }
    let blocks = content.as_array().ok_or_else(|| {
        AdaptorError::invalid_request("Anthropic message `content` must be a string or block array")
    })?;
    let mut message = Message {
        role,
        content: Vec::new(),
        name: None,
        tool_calls: Vec::new(),
    };
    let start = items.len();
    for block in blocks {
        let block = block.as_object().ok_or_else(|| {
            AdaptorError::invalid_request("Anthropic content block must be a JSON object")
        })?;
        match required_string(block, "type")?.as_str() {
            "text" => {
                if !message.tool_calls.is_empty() {
                    return Err(AdaptorError::invalid_request(
                        "text after tool_use cannot be represented by the chat template",
                    ));
                }
                message.content.push(text_part(block)?);
            }
            "tool_use" if message.role == "assistant" => {
                message.tool_calls.push(HistoricalToolCall {
                    id: required_string(block, "id")?,
                    name: required_string(block, "name")?,
                    arguments: required_object(block, "input", "tool_use")?,
                });
            }
            "tool_result" if message.role == "user" => {
                if !message.content.is_empty() {
                    return Err(AdaptorError::invalid_request(
                        "tool_result blocks must precede user text",
                    ));
                }
                let output = tool_result_content(block.get("content"), tools)?;
                // Chat templates carry the result text, without an error flag.
                optional_bool(block, "is_error")?;
                items.push(InputItem::ToolResult {
                    call_id: required_string(block, "tool_use_id")?,
                    output,
                });
            }
            kind => {
                return Err(AdaptorError::invalid_request(format!(
                    "unsupported Anthropic {kind} block in {} message",
                    message.role
                )));
            }
        }
    }
    if !message.content.is_empty() || !message.tool_calls.is_empty() || items.len() == start {
        items.push(InputItem::Message(message));
    }
    Ok(())
}

/// A tool definition and whether it has been loaded into the conversation.
fn project_tool(value: &JsonValue) -> AdaptorResult<(ToolSpec, bool)> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("Anthropic tool must be a JSON object"))?;
    if optional_string(object, "type")?.is_some_and(|kind| kind != "custom") {
        return Err(AdaptorError::invalid_request(
            "only custom function tools are supported",
        ));
    }
    if optional_bool(object, "strict")? == Some(true) {
        return Err(AdaptorError::invalid_request(
            "tool `strict` is not supported",
        ));
    }
    reject_fields(object, &["allowed_callers", "input_examples"])?;
    let tool = ToolSpec {
        name: required_string(object, "name")?,
        description: optional_string(object, "description")?,
        parameters: required_object(object, "input_schema", "tool")?,
        kind: ToolKind::Function,
        raw: value.clone(),
    };
    Ok((tool, optional_bool(object, "defer_loading")? != Some(true)))
}

/// Client-side ToolSearch returns references to definitions in this request.
/// Expand them in place and allow the discovered tools in subsequent output.
fn tool_result_content(
    value: Option<&JsonValue>,
    tools: &mut [(ToolSpec, bool)],
) -> AdaptorResult<Vec<ContentPart>> {
    let Some(JsonValue::Array(blocks)) = value else {
        return text_content(value);
    };
    let mut output = Vec::new();
    for block in blocks {
        let block = block.as_object().ok_or_else(|| {
            AdaptorError::invalid_request("tool result block must be a JSON object")
        })?;
        match required_string(block, "type")?.as_str() {
            "text" => output.push(text_part(block)?),
            "tool_reference" => {
                let name = required_string(block, "tool_name")?;
                let (tool, loaded) = tools
                    .iter_mut()
                    .find(|(tool, _)| tool.name == name)
                    .ok_or_else(|| {
                        AdaptorError::invalid_request(format!(
                            "tool_reference names unknown tool `{name}`"
                        ))
                    })?;
                *loaded = true;
                output.push(ContentPart::Text { text: json!({
                    "type": "function", "function": {"name": tool.name, "description": tool.description, "parameters": tool.parameters}
                }).to_string() });
            }
            _ => {
                return Err(AdaptorError::invalid_request(
                    "only text and tool_reference result blocks are supported",
                ));
            }
        }
    }
    Ok(output)
}

/// An Anthropic `tool_choice` and the parallel-call permission it carries.
struct ProjectedToolChoice {
    choice: ToolChoice,
    parallel_tool_calls: Option<bool>,
}

fn project_tool_choice(value: &JsonValue) -> AdaptorResult<ProjectedToolChoice> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("`tool_choice` must be a JSON object"))?;
    let tool_type = required_string(object, "type")?;
    let disable_parallel = optional_bool(object, "disable_parallel_tool_use")?;
    let choice = match tool_type.as_str() {
        "auto" => ToolChoice::Auto,
        "any" => ToolChoice::Required,
        "none" => {
            if disable_parallel.is_some() {
                return Err(AdaptorError::invalid_request(
                    "`disable_parallel_tool_use` is not valid on Anthropic tool_choice type `none`",
                ));
            }
            ToolChoice::None
        }
        "tool" => ToolChoice::Tool {
            name: required_string(object, "name")?,
        },
        tool_type => {
            return Err(AdaptorError::invalid_request(format!(
                "unsupported Anthropic tool_choice type `{tool_type}`"
            )));
        }
    };
    Ok(ProjectedToolChoice {
        choice,
        parallel_tool_calls: disable_parallel.map(|disable| !disable),
    })
}

fn required_object(
    object: &JsonMap<String, JsonValue>,
    key: &str,
    owner: &str,
) -> AdaptorResult<JsonValue> {
    object
        .get(key)
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| {
            AdaptorError::invalid_request(format!("Anthropic {owner} `{key}` must be an object"))
        })
}

fn text_part(block: &JsonMap<String, JsonValue>) -> AdaptorResult<ContentPart> {
    if optional_array(block, "citations")?.is_some_and(|citations| !citations.is_empty()) {
        return Err(AdaptorError::invalid_request(
            "text citations are not supported by the chat template",
        ));
    }
    Ok(ContentPart::Text {
        text: required_string(block, "text")?,
    })
}

fn text_content(value: Option<&JsonValue>) -> AdaptorResult<Vec<ContentPart>> {
    match value {
        None => Ok(Vec::new()),
        Some(JsonValue::String(text)) => Ok(vec![ContentPart::Text { text: text.clone() }]),
        Some(JsonValue::Array(blocks)) => blocks
            .iter()
            .map(|block| {
                let block = block.as_object().ok_or_else(|| {
                    AdaptorError::invalid_request("text block must be a JSON object")
                })?;
                if required_string(block, "type")? != "text" {
                    return Err(AdaptorError::invalid_request(
                        "only text content blocks are supported",
                    ));
                }
                text_part(block)
            })
            .collect(),
        _ => Err(AdaptorError::invalid_request(
            "content must be a string or text block array",
        )),
    }
}

/// Whether `thinking` asks the model to think. Adaptive thinking leaves the
/// choice to the model, so a model that does not think satisfies it.
fn thinking_requested(value: &JsonValue) -> AdaptorResult<bool> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("`thinking` must be a JSON object"))?;
    match required_string(object, "type")?.as_str() {
        "enabled" => {
            required_u32(object, "budget_tokens")?;
            Ok(true)
        }
        "adaptive" | "disabled" => Ok(false),
        other => Err(AdaptorError::invalid_request(format!(
            "unsupported Anthropic thinking type `{other}`"
        ))),
    }
}

/// `effort` steers how much a model spends on a response, which a model
/// without that control cannot honour or violate. Any other output control,
/// such as a response format, would change the result and is refused.
fn validate_output_config(value: &JsonValue) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("`output_config` must be a JSON object"))?;
    for key in object.keys() {
        if key != "effort" {
            return Err(AdaptorError::invalid_request(format!(
                "Anthropic `output_config.{key}` is not supported"
            )));
        }
    }
    optional_string(object, "effort")?;
    Ok(())
}

/// Clearing thinking from earlier turns changes nothing here: history never
/// carries thinking blocks. Any other edit would rewrite the prompt.
fn validate_context_management(value: &JsonValue) -> AdaptorResult<()> {
    let object = value.as_object().ok_or_else(|| {
        AdaptorError::invalid_request("`context_management` must be a JSON object")
    })?;
    for edit in optional_array(object, "edits")?.unwrap_or_default() {
        let kind = edit
            .get("type")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| AdaptorError::invalid_request("context edit requires a `type`"))?;
        if !kind.starts_with("clear_thinking_") {
            return Err(AdaptorError::invalid_request(format!(
                "Anthropic context edit `{kind}` is not supported"
            )));
        }
    }
    Ok(())
}

fn output_blocks_json(output: &[OutputItem]) -> Vec<JsonValue> {
    let mut text = String::new();
    let mut blocks = Vec::new();
    for item in output {
        match item {
            OutputItem::Text {
                text: part,
                channel: TextChannel::Output | TextChannel::Reasoning,
            } => text.push_str(part),
            OutputItem::StructuredJson(value) => text.push_str(&json_to_wire_string(value)),
            OutputItem::ToolCall {
                id,
                name,
                arguments,
            } => blocks.push(json!({
                "type": "tool_use",
                "id": id,
                "name": name,
                "input": arguments,
            })),
            OutputItem::Raw(value) => match value {
                JsonValue::Array(values) => blocks.extend(values.clone()),
                JsonValue::Object(_) => blocks.push(value.clone()),
                _ => text.push_str(&json_to_wire_string(value)),
            },
        }
    }
    if !text.is_empty() || blocks.is_empty() {
        blocks.insert(0, json!({"type": "text", "text": text}));
    }
    blocks
}

fn render_text_delta(
    state: &mut AnthropicMessagesStreamState,
    kind: AnthropicBlockKind,
    delta: String,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let mut events = ensure_open_block(state, kind);
    let index = state
        .open_block
        .as_ref()
        .expect("ensure_open_block leaves a block open")
        .index;
    let delta = match kind {
        AnthropicBlockKind::Text => json!({"type": "text_delta", "text": delta}),
        AnthropicBlockKind::Thinking => json!({"type": "thinking_delta", "thinking": delta}),
        AnthropicBlockKind::Tool => {
            return Err(AdaptorError::render(
                "tool blocks cannot render text deltas",
            ));
        }
    };
    events.push(WireStreamEvent::json(
        Some("content_block_delta".to_string()),
        json!({
            "type": "content_block_delta",
            "index": index,
            "delta": delta,
        }),
    ));
    Ok(events)
}

fn ensure_open_block(
    state: &mut AnthropicMessagesStreamState,
    kind: AnthropicBlockKind,
) -> Vec<WireStreamEvent> {
    if state
        .open_block
        .as_ref()
        .is_some_and(|block| block.kind == kind)
    {
        return Vec::new();
    }

    let mut events = close_open_block(state);
    let index = next_block_index(state);
    state.open_block = Some(AnthropicOpenBlock { index, kind });
    events.push(WireStreamEvent::json(
        Some("content_block_start".to_string()),
        json!({
            "type": "content_block_start",
            "index": index,
            "content_block": block_start_json(kind),
        }),
    ));
    events
}

fn block_start_json(kind: AnthropicBlockKind) -> JsonValue {
    match kind {
        AnthropicBlockKind::Text => json!({"type": "text", "text": ""}),
        AnthropicBlockKind::Thinking => json!({"type": "thinking", "thinking": ""}),
        AnthropicBlockKind::Tool => unreachable!("tool block start requires tool metadata"),
    }
}

fn close_open_block(state: &mut AnthropicMessagesStreamState) -> Vec<WireStreamEvent> {
    let Some(block) = state.open_block.take() else {
        return Vec::new();
    };
    vec![WireStreamEvent::json(
        Some("content_block_stop".to_string()),
        json!({
            "type": "content_block_stop",
            "index": block.index,
        }),
    )]
}

fn next_block_index(state: &mut AnthropicMessagesStreamState) -> usize {
    let index = state.next_block_index;
    state.next_block_index = state.next_block_index.saturating_add(1);
    index
}

fn render_tool_call_start(
    state: &mut AnthropicMessagesStreamState,
    start: crate::ToolCallStart,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let id = start
        .id
        .ok_or_else(|| AdaptorError::render("Anthropic tool call start requires an id"))?;
    if state
        .tool_calls
        .iter()
        .any(|call| call.parser_index == start.index)
    {
        return Err(AdaptorError::render(format!(
            "duplicate tool call start for index {}",
            start.index
        )));
    }

    let mut events = close_open_block(state);
    let block_index = next_block_index(state);
    state.open_block = Some(AnthropicOpenBlock {
        index: block_index,
        kind: AnthropicBlockKind::Tool,
    });
    state.tool_calls.push(AnthropicToolCallState {
        parser_index: start.index,
        block_index,
    });

    events.push(WireStreamEvent::json(
        Some("content_block_start".to_string()),
        json!({
            "type": "content_block_start",
            "index": block_index,
            "content_block": {
                "type": "tool_use",
                "id": id,
                "name": start.name,
                "input": {},
            },
        }),
    ));
    Ok(events)
}

fn render_tool_call_arguments_delta(
    state: &AnthropicMessagesStreamState,
    index: usize,
    delta: String,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let block_index = tool_call_block_index(state, index)?;
    Ok(vec![WireStreamEvent::json(
        Some("content_block_delta".to_string()),
        json!({
            "type": "content_block_delta",
            "index": block_index,
            "delta": {
                "type": "input_json_delta",
                "partial_json": delta,
            },
        }),
    )])
}

fn render_tool_call_end(
    state: &mut AnthropicMessagesStreamState,
    index: usize,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let block_index = tool_call_block_index(state, index)?;
    state.tool_calls.retain(|call| call.parser_index != index);
    if state
        .open_block
        .as_ref()
        .is_some_and(|block| block.index == block_index && block.kind == AnthropicBlockKind::Tool)
    {
        return Ok(close_open_block(state));
    }
    Err(AdaptorError::render(format!(
        "tool call index {index} is not open"
    )))
}

fn tool_call_block_index(
    state: &AnthropicMessagesStreamState,
    parser_index: usize,
) -> AdaptorResult<usize> {
    state
        .tool_calls
        .iter()
        .find(|call| call.parser_index == parser_index)
        .map(|call| call.block_index)
        .ok_or_else(|| AdaptorError::render(format!("unknown tool call index {parser_index}")))
}

fn usage_json(usage: crate::Usage) -> JsonValue {
    json!({
        "input_tokens": usage.input_tokens.unwrap_or(0),
        "output_tokens": usage.output_tokens.unwrap_or(0),
    })
}

fn stop_reason_json(stop_reason: StopReason) -> JsonValue {
    let value = match stop_reason {
        StopReason::EndOfText | StopReason::StopSequence | StopReason::Cancelled => "end_turn",
        StopReason::MaxOutputTokens => "max_tokens",
        StopReason::ToolCall => "tool_use",
    };
    JsonValue::String(value.to_string())
}

fn required_u32(object: &JsonMap<String, JsonValue>, key: &str) -> AdaptorResult<u32> {
    object
        .get(key)
        .and_then(JsonValue::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| AdaptorError::invalid_request(format!("missing or invalid `{key}`")))
}

#[cfg(test)]
mod tests;
