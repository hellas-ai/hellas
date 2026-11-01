use serde_json::{Map as JsonMap, Value as JsonValue, json};

use crate::{
    AdaptorError, AdaptorResult, CanonicalExecution, ContentPart, ExecutionRequest,
    ExecutionResult, Input, InputItem, Message, ModelRef, OutputEvent, OutputItem, RawRequest,
    ReasoningOptions, RenderContext, StopReason, TextChannel, ToolChoice, ToolKind, ToolSpec,
    WireAdaptor, WireResponse, WireStreamEvent,
    json::{
        attach_hellas, json_to_wire_string, optional_array, optional_bool, optional_string,
        required_array, required_string, structured_delta_string,
    },
};

#[derive(Clone, Copy, Debug, Default)]
pub struct AnthropicMessagesAdaptor;

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedAnthropicMessageRequest {
    pub raw: RawRequest,
    pub model: String,
    pub messages: Vec<JsonValue>,
    pub max_tokens: u32,
    pub system: Option<JsonValue>,
    pub tools: Vec<JsonValue>,
    pub tool_choice: Option<JsonValue>,
    pub stream: Option<bool>,
    pub thinking: Option<JsonValue>,
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
                            "type": code.unwrap_or_else(|| "invalid_request_error".to_string()),
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
        let model = required_string(object, "model")?;
        let messages = required_array(object, "messages")?;
        for message in &messages {
            validate_message(message)?;
        }
        let max_tokens = required_u32(object, "max_tokens")?;
        let system = object.get("system").cloned();
        if let Some(system) = &system {
            validate_system(system)?;
        }
        let tools = optional_array(object, "tools")?.unwrap_or_default();
        for tool in &tools {
            project_tool(tool)?;
        }
        let tool_choice = object.get("tool_choice").cloned();
        if let Some(tool_choice) = &tool_choice {
            project_tool_choice(tool_choice)?;
        }
        let stream = optional_bool(object, "stream")?;
        let thinking = object.get("thinking").cloned();
        if let Some(thinking) = &thinking {
            validate_thinking(thinking)?;
        }
        Ok(Self {
            raw,
            model,
            messages,
            max_tokens,
            system,
            tools,
            tool_choice,
            stream,
            thinking,
        })
    }

    fn to_execution_request(&self) -> AdaptorResult<ExecutionRequest> {
        let mut items =
            Vec::with_capacity(self.messages.len() + usize::from(self.system.is_some()));
        if let Some(system) = &self.system {
            items.push(InputItem::Raw(json!({
                "role": "system",
                "content": system,
            })));
        }
        for message in &self.messages {
            project_message(message, &mut items)?;
        }

        let mut canonical =
            CanonicalExecution::new(ModelRef::new(self.model.clone()), Input::Items(items));
        canonical.sampling.max_output_tokens = Some(self.max_tokens);
        canonical.tools = self
            .tools
            .iter()
            .map(project_tool)
            .collect::<AdaptorResult<Vec<_>>>()?;
        if let Some(tool_choice) = &self.tool_choice {
            let projected = project_tool_choice(tool_choice)?;
            canonical.tool_choice = projected.choice;
            if let Some(parallel_tool_calls) = projected.parallel_tool_calls {
                canonical.sampling.parallel_tool_calls = Some(parallel_tool_calls);
            }
        }
        if let Some(thinking) = &self.thinking {
            canonical.reasoning = Some(ReasoningOptions {
                value: thinking.clone(),
            });
        }

        Ok(ExecutionRequest::new(canonical))
    }
}

fn project_message(value: &JsonValue, items: &mut Vec<InputItem>) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("Anthropic message must be a JSON object"))?;
    let role = required_string(object, "role")?;
    let content = object
        .get("content")
        .ok_or_else(|| AdaptorError::invalid_request("Anthropic message missing `content`"))?;
    match content {
        JsonValue::String(text) => {
            items.push(InputItem::Message(Message::text(role, text.clone())));
        }
        JsonValue::Array(blocks) => {
            for block in blocks {
                let block = block.as_object().ok_or_else(|| {
                    AdaptorError::invalid_request("Anthropic content block must be a JSON object")
                })?;
                match required_string(block, "type")?.as_str() {
                    "text" => items.push(InputItem::Message(Message::text(
                        role.clone(),
                        required_string(block, "text")?,
                    ))),
                    "tool_use" => items.push(InputItem::ToolCall {
                        id: required_string(block, "id")?,
                        name: required_string(block, "name")?,
                        arguments: required_object(block, "input", "tool_use")?,
                    }),
                    "tool_result" => items.push(InputItem::ToolResult {
                        call_id: required_string(block, "tool_use_id")?,
                        output: tool_result_content(block.get("content"))?,
                    }),
                    block_type => {
                        return Err(AdaptorError::invalid_request(format!(
                            "unsupported Anthropic content block type `{block_type}`"
                        )));
                    }
                }
            }
        }
        _ => {
            return Err(AdaptorError::invalid_request(
                "Anthropic message `content` must be a string or block array",
            ));
        }
    }
    Ok(())
}

fn project_tool(value: &JsonValue) -> AdaptorResult<ToolSpec> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("Anthropic tool must be a JSON object"))?;
    Ok(ToolSpec {
        name: required_string(object, "name")?,
        description: optional_string(object, "description")?,
        parameters: required_object(object, "input_schema", "tool")?,
        kind: ToolKind::Function,
        raw: value.clone(),
    })
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

fn tool_result_content(value: Option<&JsonValue>) -> AdaptorResult<Vec<ContentPart>> {
    match value {
        Some(JsonValue::String(text)) => Ok(vec![ContentPart::Text { text: text.clone() }]),
        Some(JsonValue::Array(blocks)) => blocks
            .iter()
            .map(|block| {
                let block = block.as_object().ok_or_else(|| {
                    AdaptorError::invalid_request(
                        "Anthropic tool_result block must be a JSON object",
                    )
                })?;
                Ok(ContentPart::Text {
                    text: required_string(block, "text")?,
                })
            })
            .collect(),
        _ => Err(AdaptorError::invalid_request(
            "`tool_result` content must be a string or text block array",
        )),
    }
}

fn validate_message(value: &JsonValue) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("Anthropic message must be a JSON object"))?;
    let role = required_string(object, "role")?;
    let content = object
        .get("content")
        .ok_or_else(|| AdaptorError::invalid_request("Anthropic message missing `content`"))?;
    validate_content(content, &role)
}

fn validate_system(value: &JsonValue) -> AdaptorResult<()> {
    match value {
        JsonValue::String(_) => Ok(()),
        JsonValue::Array(blocks) => {
            for block in blocks {
                validate_text_block(block, "system block")?;
            }
            Ok(())
        }
        _ => Err(AdaptorError::invalid_request(
            "`system` must be a string or text block array",
        )),
    }
}

fn validate_content(value: &JsonValue, role: &str) -> AdaptorResult<()> {
    match value {
        JsonValue::String(_) => Ok(()),
        JsonValue::Array(blocks) => {
            for block in blocks {
                validate_content_block(block, role)?;
            }
            Ok(())
        }
        _ => Err(AdaptorError::invalid_request(
            "Anthropic message `content` must be a string or block array",
        )),
    }
}

fn validate_content_block(value: &JsonValue, role: &str) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("content block must be a JSON object"))?;
    match required_string(object, "type")?.as_str() {
        "text" => {
            required_string(object, "text")?;
            Ok(())
        }
        "tool_use" => {
            if role != "assistant" {
                return Err(AdaptorError::invalid_request(
                    "`tool_use` blocks are only valid in assistant messages",
                ));
            }
            required_string(object, "id")?;
            required_string(object, "name")?;
            required_object(object, "input", "tool_use")?;
            Ok(())
        }
        "tool_result" => {
            if role != "user" {
                return Err(AdaptorError::invalid_request(
                    "`tool_result` blocks are only valid in user messages",
                ));
            }
            required_string(object, "tool_use_id")?;
            tool_result_content(object.get("content"))?;
            Ok(())
        }
        block_type => Err(AdaptorError::invalid_request(format!(
            "unsupported Anthropic content block type `{block_type}`"
        ))),
    }
}

fn validate_text_block(value: &JsonValue, label: &str) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request(format!("{label} must be a JSON object")))?;
    let block_type = required_string(object, "type")?;
    match block_type.as_str() {
        "text" => {
            required_string(object, "text")?;
            Ok(())
        }
        _ => Err(AdaptorError::invalid_request(format!(
            "unsupported Anthropic {label} type `{block_type}`"
        ))),
    }
}

fn validate_thinking(value: &JsonValue) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("`thinking` must be a JSON object"))?;
    match required_string(object, "type")?.as_str() {
        "enabled" => {
            required_u32(object, "budget_tokens")?;
            Ok(())
        }
        "disabled" => Ok(()),
        other => Err(AdaptorError::invalid_request(format!(
            "unsupported Anthropic thinking type `{other}`"
        ))),
    }
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
