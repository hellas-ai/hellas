use serde_json::{Map as JsonMap, Value as JsonValue, json};

use super::{finish_reason_json, project_response_format, usage_json};

use crate::{
    AdaptorError, AdaptorResult, CanonicalExecution, ExecutionRequest, ExecutionResult, Input,
    InputItem, ModelRef, OutputEvent, OutputItem, RawRequest, ReasoningOptions, RenderContext,
    TextChannel, ToolChoice, ToolKind, ToolSpec, Usage, WireAdaptor, WireEventData, WireResponse,
    WireStreamEvent,
    json::{
        attach_hellas, json_to_wire_string, optional_array, optional_bool, optional_f32,
        optional_string, optional_u32, required_array, required_string, structured_delta_string,
    },
};

#[derive(Clone, Copy, Debug, Default)]
pub struct OpenAiChatCompletionsAdaptor;

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedChatCompletionRequest {
    pub raw: RawRequest,
    pub model: String,
    pub messages: Vec<JsonValue>,
    pub tools: Vec<JsonValue>,
    pub tool_choice: Option<JsonValue>,
    pub max_tokens: Option<u32>,
    pub stream: Option<bool>,
    pub include_usage: bool,
    pub reasoning_effort: Option<String>,
    pub response_format: Option<JsonValue>,
    pub sampling: ChatSampling,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChatSampling {
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_logprobs: Option<u32>,
    pub parallel_tool_calls: Option<bool>,
    pub stop: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatCompletionsStreamState {
    id: String,
    created: i64,
    model: String,
    include_usage: bool,
    started: bool,
    usage: Option<Usage>,
    provenance: Option<crate::Provenance>,
}

impl WireAdaptor for OpenAiChatCompletionsAdaptor {
    type ParsedRequest = ParsedChatCompletionRequest;
    type StreamState = ChatCompletionsStreamState;

    fn parse(&self, raw: RawRequest) -> AdaptorResult<Self::ParsedRequest> {
        ParsedChatCompletionRequest::parse(raw)
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
        ChatCompletionsStreamState {
            id: context.response_id,
            created: context.created_at,
            model: request.model.clone(),
            include_usage: request.include_usage,
            started: false,
            usage: None,
            provenance: None,
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
                        "error": {
                            "message": error.message,
                            "type": "server_error",
                            "code": error.code.unwrap_or_else(|| "server_error".to_string()),
                        }
                    }),
                    result.provenance.as_ref(),
                ),
            ));
        }
        let message = output_message_json(&result.output)?;
        let finish_reason = finish_reason_json(result.stop_reason);
        let mut body = json!({
            "id": context.response_id,
            "object": "chat.completion",
            "created": context.created_at,
            "model": request.model,
            "choices": [{
                "index": 0,
                "message": message,
                "finish_reason": finish_reason,
            }],
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
            None,
            chat_chunk_json(
                state,
                vec![json!({
                    "index": 0,
                    "delta": {"role": "assistant"},
                    "finish_reason": null,
                })],
                None,
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
            } => Ok(vec![WireStreamEvent::json(
                None,
                chat_chunk_json(
                    state,
                    vec![json!({
                        "index": 0,
                        "delta": {"content": delta},
                        "finish_reason": null,
                    })],
                    None,
                ),
            )]),
            OutputEvent::TextDelta {
                delta,
                channel: TextChannel::Reasoning,
                ..
            } => Ok(vec![WireStreamEvent::json(
                None,
                chat_chunk_json(
                    state,
                    vec![json!({
                        "index": 0,
                        "delta": {"reasoning_content": delta},
                        "finish_reason": null,
                    })],
                    None,
                ),
            )]),
            OutputEvent::ToolCallStart(start) => render_tool_call_start(state, start),
            OutputEvent::ToolCallArgumentsDelta(delta) => {
                render_tool_call_arguments_delta(state, delta.index, delta.delta)
            }
            OutputEvent::ToolCallEnd(_) => Ok(Vec::new()),
            OutputEvent::StructuredOutputDelta(delta) => Ok(vec![WireStreamEvent::json(
                None,
                chat_chunk_json(
                    state,
                    vec![json!({
                        "index": 0,
                        "delta": {"content": structured_delta_string(delta)},
                        "finish_reason": null,
                    })],
                    None,
                ),
            )]),
            OutputEvent::Adaptor(_) => Err(AdaptorError::unsupported(
                "Chat Completions cannot render adaptor-specific events",
            )),
            OutputEvent::Usage(usage) => {
                state.usage = Some(usage);
                Ok(Vec::new())
            }
            OutputEvent::Provenance(provenance) => {
                self.attest(state, provenance.into());
                Ok(Vec::new())
            }
            OutputEvent::Error { message, code } => Ok(vec![WireStreamEvent::json(
                None,
                json!({
                    "error": {
                        "message": message,
                        "code": code,
                    }
                }),
            )]),
            OutputEvent::Finished { stop_reason, usage } => {
                if let Some(usage) = usage {
                    state.usage = Some(usage);
                }
                let mut events = Vec::new();
                events.push(WireStreamEvent::json(
                    None,
                    chat_chunk_json(
                        state,
                        vec![json!({
                            "index": 0,
                            "delta": {},
                            "finish_reason": finish_reason_json(stop_reason),
                        })],
                        None,
                    ),
                ));
                if state.include_usage {
                    events.push(WireStreamEvent::json(
                        None,
                        chat_chunk_json(state, Vec::new(), state.usage.map(usage_json)),
                    ));
                }
                events.push(WireStreamEvent {
                    name: None,
                    data: WireEventData::Text("[DONE]".to_string()),
                });
                Ok(events)
            }
        }
    }
}

impl ParsedChatCompletionRequest {
    fn parse(raw: RawRequest) -> AdaptorResult<Self> {
        let object = raw.value().as_object().ok_or_else(|| {
            AdaptorError::invalid_request("Chat Completions request must be a JSON object")
        })?;

        let model = required_string(object, "model")?;
        let messages = required_array(object, "messages")?;
        for message in &messages {
            validate_message(message)?;
        }

        let tools = optional_array(object, "tools")?.unwrap_or_default();
        let tool_choice = object.get("tool_choice").cloned();
        let max_tokens = max_tokens(object)?;
        let stream = optional_bool(object, "stream")?;
        let include_usage = stream_include_usage(object)?;
        let reasoning_effort = optional_string(object, "reasoning_effort")?;
        if let Some(effort) = &reasoning_effort {
            validate_reasoning_effort(effort)?;
        }
        let response_format = object.get("response_format").cloned();
        let sampling = ChatSampling {
            temperature: optional_f32(object, "temperature")?,
            top_p: optional_f32(object, "top_p")?,
            top_logprobs: optional_u32(object, "top_logprobs")?,
            parallel_tool_calls: optional_bool(object, "parallel_tool_calls")?,
            stop: stop_strings(object)?,
        };
        Ok(Self {
            raw,
            model,
            messages,
            tools,
            tool_choice,
            max_tokens,
            stream,
            include_usage,
            reasoning_effort,
            response_format,
            sampling,
        })
    }

    fn to_execution_request(&self) -> AdaptorResult<ExecutionRequest> {
        let mut canonical = CanonicalExecution::new(
            ModelRef::new(self.model.clone()),
            Input::Items(
                self.messages
                    .iter()
                    .cloned()
                    .map(InputItem::Raw)
                    .collect::<Vec<_>>(),
            ),
        );
        apply_sampling(&mut canonical, self);

        canonical.tools = self
            .tools
            .iter()
            .map(project_tool)
            .collect::<AdaptorResult<Vec<_>>>()?;

        if let Some(tool_choice) = &self.tool_choice {
            canonical.tool_choice = project_tool_choice(tool_choice);
        }
        if let Some(response_format) = &self.response_format {
            canonical.response_format = Some(project_response_format(response_format));
        }
        if let Some(reasoning_effort) = &self.reasoning_effort {
            canonical.reasoning = Some(ReasoningOptions {
                value: JsonValue::String(reasoning_effort.clone()),
            });
        }

        Ok(ExecutionRequest::new(canonical))
    }
}

fn apply_sampling(canonical: &mut CanonicalExecution, request: &ParsedChatCompletionRequest) {
    if let Some(max_tokens) = request.max_tokens {
        canonical.sampling.max_output_tokens = Some(max_tokens);
    }
    if let Some(temperature) = request.sampling.temperature {
        canonical.sampling.temperature = Some(temperature);
    }
    if let Some(top_p) = request.sampling.top_p {
        canonical.sampling.top_p = Some(top_p);
    }
    if let Some(top_logprobs) = request.sampling.top_logprobs {
        canonical.sampling.top_logprobs = Some(top_logprobs);
    }
    if let Some(parallel_tool_calls) = request.sampling.parallel_tool_calls {
        canonical.sampling.parallel_tool_calls = Some(parallel_tool_calls);
    }
    if !request.sampling.stop.is_empty() {
        canonical.sampling.stop = request.sampling.stop.clone();
    }
}

fn validate_message(value: &JsonValue) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("chat message must be a JSON object"))?;
    required_string(object, "role")?;
    if let Some(content) = object.get("content") {
        validate_message_content(content)?;
    }
    if let Some(tool_calls) = object.get("tool_calls") {
        tool_calls.as_array().ok_or_else(|| {
            AdaptorError::invalid_request("chat message `tool_calls` must be an array")
        })?;
    }
    if object.contains_key("tool_call_id") {
        optional_string(object, "tool_call_id")?;
    }
    if object.contains_key("name") {
        optional_string(object, "name")?;
    }
    Ok(())
}

fn validate_message_content(value: &JsonValue) -> AdaptorResult<()> {
    match value {
        JsonValue::Null | JsonValue::String(_) => Ok(()),
        JsonValue::Array(parts) => {
            for part in parts {
                part.as_object().ok_or_else(|| {
                    AdaptorError::invalid_request("chat content part must be a JSON object")
                })?;
            }
            Ok(())
        }
        _ => Err(AdaptorError::invalid_request(
            "chat message `content` must be null, a string, or an array",
        )),
    }
}

fn validate_reasoning_effort(value: &str) -> AdaptorResult<()> {
    match value {
        "none" | "low" | "medium" | "high" => Ok(()),
        _ => Err(AdaptorError::invalid_request(
            "`reasoning_effort` must be one of none, low, medium, high",
        )),
    }
}

fn project_tool(value: &JsonValue) -> AdaptorResult<ToolSpec> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("tool must be a JSON object"))?;
    let tool_type = required_string(object, "type")?;
    match tool_type.as_str() {
        "function" => {
            let function = object.get("function").and_then(JsonValue::as_object);
            let source = function.unwrap_or(object);
            Ok(ToolSpec {
                name: required_string(source, "name")?,
                description: optional_string(source, "description")?,
                parameters: source
                    .get("parameters")
                    .cloned()
                    .unwrap_or_else(|| json!({"type": "object"})),
                kind: ToolKind::Function,
                raw: value.clone(),
            })
        }
        other => Ok(ToolSpec {
            name: object
                .get("name")
                .and_then(JsonValue::as_str)
                .unwrap_or(other)
                .to_string(),
            description: optional_string(object, "description")?,
            parameters: JsonValue::Object(object.clone()),
            kind: ToolKind::BuiltIn(other.to_string()),
            raw: value.clone(),
        }),
    }
}

fn project_tool_choice(value: &JsonValue) -> ToolChoice {
    match value.as_str() {
        Some("auto") => ToolChoice::Auto,
        Some("none") => ToolChoice::None,
        Some("required") => ToolChoice::Required,
        _ => value
            .get("function")
            .and_then(|function| function.get("name"))
            .or_else(|| value.get("name"))
            .and_then(JsonValue::as_str)
            .map(|name| ToolChoice::Tool {
                name: name.to_string(),
            })
            .unwrap_or_else(|| ToolChoice::Raw(value.clone())),
    }
}

fn output_message_json(output: &[OutputItem]) -> AdaptorResult<JsonValue> {
    if let [OutputItem::Raw(value)] = output
        && value.get("role").and_then(JsonValue::as_str).is_some()
    {
        return Ok(value.clone());
    }

    let mut content = String::new();
    let mut tool_calls = Vec::new();
    for item in output {
        match item {
            OutputItem::Text {
                text,
                channel: TextChannel::Output,
            } => content.push_str(text),
            OutputItem::Text {
                text,
                channel: TextChannel::Reasoning,
            } => content.push_str(text),
            OutputItem::ToolCall {
                id,
                name,
                arguments,
            } => tool_calls.push(json!({
                "id": id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json_to_wire_string(arguments),
                },
            })),
            OutputItem::StructuredJson(value) => content.push_str(&json_to_wire_string(value)),
            OutputItem::Raw(value) => content.push_str(&json_to_wire_string(value)),
        }
    }

    let mut message = JsonMap::new();
    message.insert(
        "role".to_string(),
        JsonValue::String("assistant".to_string()),
    );
    if content.is_empty() && !tool_calls.is_empty() {
        message.insert("content".to_string(), JsonValue::Null);
    } else {
        message.insert("content".to_string(), JsonValue::String(content));
    }
    if !tool_calls.is_empty() {
        message.insert("tool_calls".to_string(), JsonValue::Array(tool_calls));
    }
    Ok(JsonValue::Object(message))
}

fn render_tool_call_start(
    state: &mut ChatCompletionsStreamState,
    start: crate::ToolCallStart,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let mut function = JsonMap::new();
    function.insert("name".to_string(), JsonValue::String(start.name));
    function.insert("arguments".to_string(), JsonValue::String(String::new()));

    let mut tool_call = JsonMap::new();
    tool_call.insert(
        "index".to_string(),
        JsonValue::Number(serde_json::Number::from(start.index)),
    );
    if let Some(id) = start.id {
        tool_call.insert("id".to_string(), JsonValue::String(id));
    }
    tool_call.insert(
        "type".to_string(),
        JsonValue::String("function".to_string()),
    );
    tool_call.insert("function".to_string(), JsonValue::Object(function));

    Ok(vec![WireStreamEvent::json(
        None,
        chat_chunk_json(
            state,
            vec![json!({
                "index": 0,
                "delta": {"tool_calls": [JsonValue::Object(tool_call)]},
                "finish_reason": null,
            })],
            None,
        ),
    )])
}

fn render_tool_call_arguments_delta(
    state: &mut ChatCompletionsStreamState,
    index: usize,
    delta: String,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    Ok(vec![WireStreamEvent::json(
        None,
        chat_chunk_json(
            state,
            vec![json!({
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": index,
                        "function": { "arguments": delta },
                    }],
                },
                "finish_reason": null,
            })],
            None,
        ),
    )])
}

fn chat_chunk_json(
    state: &ChatCompletionsStreamState,
    choices: Vec<JsonValue>,
    usage: Option<JsonValue>,
) -> JsonValue {
    let mut body = json!({
        "id": state.id,
        "object": "chat.completion.chunk",
        "created": state.created,
        "model": state.model,
        "choices": choices,
    });
    if let Some(usage) = usage {
        body["usage"] = usage;
    }
    attach_hellas(body, state.provenance.as_ref())
}

fn stream_include_usage(object: &JsonMap<String, JsonValue>) -> AdaptorResult<bool> {
    let Some(value) = object.get("stream_options") else {
        return Ok(false);
    };
    if value.is_null() {
        return Ok(false);
    }
    let options = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("`stream_options` must be a JSON object"))?;
    optional_bool(options, "include_usage").map(|value| value.unwrap_or(false))
}

fn max_tokens(object: &JsonMap<String, JsonValue>) -> AdaptorResult<Option<u32>> {
    let max_tokens = optional_u32(object, "max_tokens")?;
    let max_completion_tokens = optional_u32(object, "max_completion_tokens")?;
    match (max_tokens, max_completion_tokens) {
        (Some(_), Some(_)) => Err(AdaptorError::invalid_request(
            "`max_tokens` and `max_completion_tokens` cannot both be set",
        )),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn stop_strings(object: &JsonMap<String, JsonValue>) -> AdaptorResult<Vec<String>> {
    match object.get("stop") {
        None | Some(JsonValue::Null) => Ok(Vec::new()),
        Some(JsonValue::String(value)) => Ok(vec![value.clone()]),
        Some(JsonValue::Array(values)) => values
            .iter()
            .map(|value| {
                value.as_str().map(ToString::to_string).ok_or_else(|| {
                    AdaptorError::invalid_request("`stop` array entries must be strings")
                })
            })
            .collect(),
        Some(_) => Err(AdaptorError::invalid_request(
            "`stop` must be a string or string array",
        )),
    }
}

#[cfg(test)]
mod tests;
