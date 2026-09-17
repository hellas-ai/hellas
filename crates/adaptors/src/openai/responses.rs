use std::collections::HashMap;

use serde_json::{Map as JsonMap, Value as JsonValue, json};

use super::project_response_format;

use crate::{
    AdaptorError, AdaptorResult, BackendError, CanonicalExecution, ContentPart, ExecutionRequest,
    ExecutionResult, Input, InputItem, Message, ModelRef, OutputEvent, OutputItem, RawRequest,
    ReasoningOptions, RenderContext, SseDecoder, StopReason, StructuredDelta, TextChannel,
    ToolCallArgumentsDelta, ToolCallEnd, ToolCallStart, ToolChoice, ToolKind, ToolSpec, Usage,
    WireAdaptor, WireEventData, WireIngress, WireResponse, WireStreamEvent,
    json::{
        optional_array, optional_bool, optional_f32, optional_string, optional_u32,
        provenance_json, required_string,
    },
};

#[derive(Clone, Copy, Debug, Default)]
pub struct OpenAiResponsesAdaptor;

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedResponseRequest {
    pub raw: RawRequest,
    pub model: String,
    pub input: JsonValue,
    pub instructions: Option<String>,
    pub tools: Vec<JsonValue>,
    pub max_output_tokens: Option<u32>,
    pub stream: Option<bool>,
    pub sampling: ResponseSampling,
    pub tool_choice: Option<JsonValue>,
    pub response_format: Option<JsonValue>,
    pub reasoning: Option<JsonValue>,
    pub previous_response_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResponseSampling {
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_logprobs: Option<u32>,
    pub parallel_tool_calls: Option<bool>,
    pub truncation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponsesStreamState {
    response_id: String,
    reasoning_id: String,
    message_id: String,
    created_at: i64,
    sequence_number: u64,
    reasoning_text: String,
    text: String,
    started: bool,
    next_output_index: usize,
    reasoning_output_index: Option<usize>,
    message_output_index: Option<usize>,
    usage: Option<Usage>,
    provenance: Option<crate::Provenance>,
    tool_calls: Vec<ResponseToolCallState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResponseToolCallState {
    parser_index: usize,
    output_index: usize,
    id: String,
    name: String,
    arguments: String,
}

impl WireAdaptor for OpenAiResponsesAdaptor {
    type ParsedRequest = ParsedResponseRequest;
    type StreamState = ResponsesStreamState;

    fn parse(&self, raw: RawRequest) -> AdaptorResult<Self::ParsedRequest> {
        ParsedResponseRequest::parse(raw)
    }

    fn to_execution_request(
        &self,
        request: &Self::ParsedRequest,
    ) -> AdaptorResult<ExecutionRequest> {
        request.to_execution_request()
    }

    fn initial_state(
        &self,
        _request: &Self::ParsedRequest,
        context: RenderContext,
    ) -> Self::StreamState {
        ResponsesStreamState {
            reasoning_id: format!("{}_reasoning", context.response_id),
            response_id: context.response_id,
            message_id: context.message_id,
            created_at: context.created_at,
            sequence_number: 0,
            reasoning_text: String::new(),
            text: String::new(),
            started: false,
            next_output_index: 0,
            reasoning_output_index: None,
            message_output_index: None,
            usage: None,
            provenance: None,
            tool_calls: Vec::new(),
        }
    }

    fn render_response(
        &self,
        request: &Self::ParsedRequest,
        result: ExecutionResult,
        context: RenderContext,
    ) -> AdaptorResult<WireResponse> {
        let failed = result.error.as_ref();
        let body = response_json(ResponseJsonParts {
            response_id: &context.response_id,
            created_at: context.created_at,
            model: &request.model,
            status: if failed.is_some() {
                "failed"
            } else {
                "completed"
            },
            output: output_items_json(
                &context.message_id,
                &result.output,
                if failed.is_some() {
                    "incomplete"
                } else {
                    "completed"
                },
            )?,
            usage: result.usage,
            metadata: request_metadata(request),
            provenance: result.provenance.as_ref(),
        });
        let body = if let Some(error) = failed {
            let mut body = body;
            body["error"] = json!({
                "code": error.code.clone().unwrap_or_else(|| "server_error".to_string()),
                "message": error.message.clone(),
            });
            body
        } else {
            body
        };
        Ok(WireResponse::json(200, body))
    }

    fn render_stream_start(
        &self,
        request: &Self::ParsedRequest,
        state: &mut Self::StreamState,
    ) -> AdaptorResult<Vec<WireStreamEvent>> {
        if state.started {
            return Ok(Vec::new());
        }
        state.started = true;

        let created = response_event(
            "response.created",
            response_status_payload(state, request, "queued", Vec::new(), None),
            state,
        );
        let in_progress = response_event(
            "response.in_progress",
            response_status_payload(state, request, "in_progress", Vec::new(), None),
            state,
        );

        Ok(vec![created, in_progress])
    }

    fn render_stream_event(
        &self,
        request: &Self::ParsedRequest,
        state: &mut Self::StreamState,
        event: OutputEvent,
    ) -> AdaptorResult<Vec<WireStreamEvent>> {
        match event {
            OutputEvent::TextDelta {
                delta,
                channel: TextChannel::Output,
                ..
            } => {
                let mut events = ensure_message_item_started(state);
                let output_index = state
                    .message_output_index
                    .expect("message item is started before text deltas");
                state.text.push_str(&delta);
                events.push(response_event(
                    "response.output_text.delta",
                    json!({
                        "item_id": state.message_id,
                        "output_index": output_index,
                        "content_index": 0,
                        "delta": delta,
                    }),
                    state,
                ));
                Ok(events)
            }
            OutputEvent::TextDelta {
                delta,
                channel: TextChannel::Reasoning,
                ..
            } => Ok(render_reasoning_delta(state, delta)),
            OutputEvent::ToolCallStart(start) => render_tool_call_start(state, start),
            OutputEvent::ToolCallArgumentsDelta(delta) => {
                render_tool_call_arguments_delta(state, delta.index, delta.delta)
            }
            OutputEvent::ToolCallEnd(end) => render_tool_call_end(state, end),
            OutputEvent::StructuredOutputDelta(delta) => render_structured_delta(state, delta),
            OutputEvent::Adaptor(_) => Err(AdaptorError::unsupported(
                "OpenAI Responses cannot render another adaptor's signed events",
            )),
            OutputEvent::Usage(usage) => {
                state.usage = Some(usage);
                Ok(Vec::new())
            }
            OutputEvent::Provenance(provenance) => {
                state.provenance = Some(provenance);
                Ok(Vec::new())
            }
            OutputEvent::Error { message, code } => {
                let mut events = finish_open_items(state, "incomplete");
                let mut response = response_json(ResponseJsonParts {
                    response_id: &state.response_id,
                    created_at: state.created_at,
                    model: &request.model,
                    status: "failed",
                    output: completed_output_items(state, "incomplete"),
                    usage: state.usage,
                    metadata: request_metadata(request),
                    provenance: state.provenance.as_ref(),
                });
                response["error"] = json!({
                    "code": code.unwrap_or_else(|| "server_error".to_string()),
                    "message": message,
                });
                events.push(response_event(
                    "response.failed",
                    json!({
                        "response": response,
                    }),
                    state,
                ));
                Ok(events)
            }
            OutputEvent::Finished { usage, stop_reason } => {
                if let Some(usage) = usage {
                    state.usage = Some(usage);
                }
                let item_status = terminal_item_status(stop_reason);
                let mut events = finish_open_items(state, item_status);
                let output = completed_output_items(state, item_status);
                let mut response = response_json(ResponseJsonParts {
                    response_id: &state.response_id,
                    created_at: state.created_at,
                    model: &request.model,
                    status: terminal_response_status(stop_reason),
                    output,
                    usage: state.usage,
                    metadata: request_metadata(request),
                    provenance: state.provenance.as_ref(),
                });
                apply_terminal_details(&mut response, stop_reason);
                let completed = response_event(
                    terminal_response_event(stop_reason),
                    json!({
                        "response": response,
                    }),
                    state,
                );
                events.push(completed);
                Ok(events)
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResponsesIngressState {
    item_to_tool_index: HashMap<String, usize>,
    output_to_tool_index: HashMap<usize, usize>,
    next_tool_index: usize,
    saw_text_delta: bool,
    saw_reasoning_delta: bool,
    saw_tool_call: bool,
}

pub struct ResponsesSseProjector {
    adaptor: OpenAiResponsesAdaptor,
    parsed: ParsedResponseRequest,
    state: ResponsesIngressState,
    decoder: SseDecoder,
}

impl ResponsesSseProjector {
    pub fn new(parsed: ParsedResponseRequest) -> Self {
        let adaptor = OpenAiResponsesAdaptor;
        let state = adaptor.initial_ingress_state(&parsed);
        Self {
            adaptor,
            parsed,
            state,
            decoder: SseDecoder::new(),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<OutputEvent>, BackendError> {
        let frames = self
            .decoder
            .push(bytes)
            .map_err(|err| BackendError::failed(err.to_string()))?;
        self.decode_frames(frames)
    }

    pub fn finish(&mut self) -> Result<Vec<OutputEvent>, BackendError> {
        let frames = self
            .decoder
            .finish()
            .map_err(|err| BackendError::failed(err.to_string()))?;
        self.decode_frames(frames)
    }

    fn decode_frames(
        &mut self,
        frames: Vec<WireStreamEvent>,
    ) -> Result<Vec<OutputEvent>, BackendError> {
        let mut output = Vec::new();
        for frame in frames {
            output.extend(
                self.adaptor
                    .decode_stream_event(&self.parsed, &mut self.state, frame)
                    .map_err(|err| BackendError::failed(err.to_string()))?,
            );
        }
        Ok(output)
    }
}

impl WireIngress for OpenAiResponsesAdaptor {
    type IngressState = ResponsesIngressState;

    fn decode_response(
        &self,
        _request: &Self::ParsedRequest,
        bytes: &[u8],
    ) -> AdaptorResult<ExecutionResult> {
        let value: JsonValue = serde_json::from_slice(bytes).map_err(|source| {
            AdaptorError::invalid_response(format!("invalid Responses JSON: {source}"))
        })?;
        let output = value
            .get("output")
            .and_then(JsonValue::as_array)
            .map(|items| decode_output_items(items))
            .unwrap_or_else(|| {
                value
                    .get("output_text")
                    .and_then(JsonValue::as_str)
                    .map(|text| {
                        vec![OutputItem::Text {
                            text: text.to_string(),
                            channel: TextChannel::Output,
                        }]
                    })
                    .unwrap_or_default()
            });

        Ok(ExecutionResult {
            output,
            usage: value.get("usage").map(decode_usage),
            stop_reason: decode_stop_reason(&value),
            provenance: None,
            error: decode_response_error(&value),
        })
    }

    fn initial_ingress_state(&self, _request: &Self::ParsedRequest) -> Self::IngressState {
        ResponsesIngressState::default()
    }

    fn decode_stream_event(
        &self,
        _request: &Self::ParsedRequest,
        state: &mut Self::IngressState,
        event: WireStreamEvent,
    ) -> AdaptorResult<Vec<OutputEvent>> {
        if matches!(&event.data, WireEventData::Text(value) if value == "[DONE]") {
            return Ok(Vec::new());
        }
        let data = event_json(event)?;
        let event_type = data
            .get("type")
            .and_then(JsonValue::as_str)
            .unwrap_or_default();

        match event_type {
            "response.output_text.delta" => {
                let Some(delta) = data.get("delta").and_then(JsonValue::as_str) else {
                    return Ok(Vec::new());
                };
                state.saw_text_delta = true;
                Ok(vec![OutputEvent::TextDelta {
                    index: output_index(&data),
                    delta: delta.to_string(),
                    channel: TextChannel::Output,
                }])
            }
            "response.reasoning_text.delta" | "response.reasoning_summary_text.delta" => {
                let Some(delta) = data.get("delta").and_then(JsonValue::as_str) else {
                    return Ok(Vec::new());
                };
                state.saw_reasoning_delta = true;
                Ok(vec![OutputEvent::TextDelta {
                    index: output_index(&data),
                    delta: delta.to_string(),
                    channel: TextChannel::Reasoning,
                }])
            }
            "response.reasoning_summary_text.done" if !state.saw_reasoning_delta => {
                let Some(text) = data.get("text").and_then(JsonValue::as_str) else {
                    return Ok(Vec::new());
                };
                Ok(vec![OutputEvent::TextDelta {
                    index: output_index(&data),
                    delta: text.to_string(),
                    channel: TextChannel::Reasoning,
                }])
            }
            "response.output_text.done" if !state.saw_text_delta => {
                let Some(text) = data.get("text").and_then(JsonValue::as_str) else {
                    return Ok(Vec::new());
                };
                Ok(vec![OutputEvent::TextDelta {
                    index: output_index(&data),
                    delta: text.to_string(),
                    channel: TextChannel::Output,
                }])
            }
            "response.output_item.added" => decode_output_item_added(state, &data),
            "response.function_call_arguments.delta" => {
                let Some(delta) = data.get("delta").and_then(JsonValue::as_str) else {
                    return Ok(Vec::new());
                };
                let Some(index) = tool_index_for_event(state, &data) else {
                    return Err(AdaptorError::invalid_response(
                        "Responses stream tool-call arguments arrived before tool-call start",
                    ));
                };
                Ok(vec![OutputEvent::ToolCallArgumentsDelta(
                    ToolCallArgumentsDelta {
                        index,
                        delta: delta.to_string(),
                    },
                )])
            }
            "response.output_item.done" => decode_output_item_done(state, &data),
            "response.completed" => {
                let response = data.get("response").unwrap_or(&data);
                Ok(vec![OutputEvent::Finished {
                    stop_reason: decode_stream_stop_reason(response, state),
                    usage: response.get("usage").map(decode_usage),
                }])
            }
            "response.incomplete" => {
                let response = data.get("response").unwrap_or(&data);
                Ok(vec![OutputEvent::Finished {
                    stop_reason: decode_stop_reason(response),
                    usage: response.get("usage").map(decode_usage),
                }])
            }
            "response.failed" => {
                let response = data.get("response").unwrap_or(&data);
                let message = response
                    .get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(JsonValue::as_str)
                    .unwrap_or("Responses stream failed")
                    .to_string();
                Ok(vec![OutputEvent::Error {
                    message,
                    code: response
                        .get("error")
                        .and_then(|error| error.get("code"))
                        .and_then(JsonValue::as_str)
                        .map(ToString::to_string),
                }])
            }
            _ => Ok(Vec::new()),
        }
    }
}

impl ParsedResponseRequest {
    fn parse(raw: RawRequest) -> AdaptorResult<Self> {
        let object = raw.value().as_object().ok_or_else(|| {
            AdaptorError::invalid_request("Responses request must be a JSON object")
        })?;

        let model = required_string(object, "model")?;
        let input = object
            .get("input")
            .cloned()
            .ok_or_else(|| AdaptorError::invalid_request("Responses request missing `input`"))?;
        let instructions = optional_string(object, "instructions")?;
        let tools = optional_array(object, "tools")?.unwrap_or_default();
        let max_output_tokens = optional_u32(object, "max_output_tokens")?;
        let stream = optional_bool(object, "stream")?;
        let sampling = ResponseSampling {
            temperature: optional_f32(object, "temperature")?,
            top_p: optional_f32(object, "top_p")?,
            top_logprobs: optional_u32(object, "top_logprobs")?,
            parallel_tool_calls: optional_bool(object, "parallel_tool_calls")?,
            truncation: optional_string(object, "truncation")?,
        };
        let tool_choice = object.get("tool_choice").cloned();
        let response_format = response_format_value(object);
        let reasoning = object.get("reasoning").cloned();
        let previous_response_id = optional_string(object, "previous_response_id")?;

        Ok(Self {
            raw,
            model,
            input,
            instructions,
            tools,
            max_output_tokens,
            stream,
            sampling,
            tool_choice,
            response_format,
            reasoning,
            previous_response_id,
        })
    }

    fn to_execution_request(&self) -> AdaptorResult<ExecutionRequest> {
        let mut canonical = CanonicalExecution::new(
            ModelRef::new(self.model.clone()),
            project_input(&self.input)?,
        );

        if let Some(instructions) = &self.instructions {
            canonical.instructions = Some(instructions.clone());
        }
        if let Some(max_output_tokens) = self.max_output_tokens {
            canonical.sampling.max_output_tokens = Some(max_output_tokens);
        }
        if let Some(temperature) = self.sampling.temperature {
            canonical.sampling.temperature = Some(temperature);
        }
        if let Some(top_p) = self.sampling.top_p {
            canonical.sampling.top_p = Some(top_p);
        }
        if let Some(top_logprobs) = self.sampling.top_logprobs {
            canonical.sampling.top_logprobs = Some(top_logprobs);
        }
        if let Some(parallel_tool_calls) = self.sampling.parallel_tool_calls {
            canonical.sampling.parallel_tool_calls = Some(parallel_tool_calls);
        }
        if let Some(truncation) = &self.sampling.truncation {
            canonical.sampling.truncation = Some(truncation.clone());
        }

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
        if let Some(reasoning) = &self.reasoning {
            canonical.reasoning = Some(ReasoningOptions {
                value: reasoning.clone(),
            });
        }
        if let Some(previous_response_id) = &self.previous_response_id {
            canonical.previous_response_id = Some(previous_response_id.clone());
        }

        Ok(ExecutionRequest::new(canonical))
    }
}

fn response_format_value(object: &JsonMap<String, JsonValue>) -> Option<JsonValue> {
    object
        .get("text")
        .and_then(|text| text.get("format").cloned())
        .or_else(|| object.get("response_format").cloned())
}

fn project_input(value: &JsonValue) -> AdaptorResult<Input> {
    match value {
        JsonValue::String(text) => Ok(Input::Text(text.clone())),
        JsonValue::Array(items) => Ok(Input::Items(
            items
                .iter()
                .map(project_input_item)
                .collect::<AdaptorResult<Vec<_>>>()?,
        )),
        _ => Err(AdaptorError::invalid_request(
            "`input` must be a string or array",
        )),
    }
}

fn project_input_item(value: &JsonValue) -> AdaptorResult<InputItem> {
    let Some(object) = value.as_object() else {
        return Ok(InputItem::Raw(value.clone()));
    };
    let item_type = object
        .get("type")
        .and_then(JsonValue::as_str)
        .unwrap_or("message");
    match item_type {
        "message" => {
            let role = required_string(object, "role")?;
            let content = object
                .get("content")
                .ok_or_else(|| AdaptorError::invalid_request("message item missing `content`"))?;
            Ok(InputItem::Message(Message {
                role,
                content: project_content(content)?,
                name: optional_string(object, "name")?,
            }))
        }
        "function_call_output" => Ok(InputItem::ToolResult {
            call_id: required_string(object, "call_id")?,
            output: vec![ContentPart::Text {
                text: required_string(object, "output")?,
            }],
        }),
        "function_call" => Ok(InputItem::ToolCall {
            id: required_string(object, "call_id").or_else(|_| required_string(object, "id"))?,
            name: required_string(object, "name")?,
            arguments: object.get("arguments").cloned().unwrap_or(JsonValue::Null),
        }),
        _ => Ok(InputItem::Raw(value.clone())),
    }
}

fn project_content(value: &JsonValue) -> AdaptorResult<Vec<ContentPart>> {
    match value {
        JsonValue::String(text) => Ok(vec![ContentPart::Text { text: text.clone() }]),
        JsonValue::Array(parts) => parts.iter().map(project_content_part).collect(),
        _ => Ok(vec![ContentPart::Json(value.clone())]),
    }
}

fn project_content_part(value: &JsonValue) -> AdaptorResult<ContentPart> {
    let Some(object) = value.as_object() else {
        return Ok(ContentPart::Json(value.clone()));
    };
    match object.get("type").and_then(JsonValue::as_str) {
        Some("input_text" | "output_text" | "text") => Ok(ContentPart::Text {
            text: required_string(object, "text")?,
        }),
        Some("input_image" | "image_url") => Ok(ContentPart::Image {
            uri: image_url(object),
            media_type: None,
            data: None,
        }),
        Some("input_file" | "file") => Ok(ContentPart::File {
            file_id: optional_string(object, "file_id")?,
            filename: optional_string(object, "filename")?,
            data: optional_string(object, "file_data")?
                .or_else(|| optional_string(object, "data").ok().flatten()),
        }),
        _ => Ok(ContentPart::Json(value.clone())),
    }
}

fn image_url(object: &JsonMap<String, JsonValue>) -> Option<String> {
    object
        .get("image_url")
        .and_then(|value| {
            value.as_str().map(ToString::to_string).or_else(|| {
                value
                    .get("url")
                    .and_then(JsonValue::as_str)
                    .map(ToString::to_string)
            })
        })
        .or_else(|| {
            object
                .get("url")
                .and_then(JsonValue::as_str)
                .map(ToString::to_string)
        })
}

fn project_tool(value: &JsonValue) -> AdaptorResult<ToolSpec> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("tool must be a JSON object"))?;
    let tool_type = required_string(object, "type")?;
    match tool_type.as_str() {
        "function" => Ok(ToolSpec {
            name: required_string(object, "name")?,
            description: optional_string(object, "description")?,
            parameters: object
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({"type": "object"})),
            kind: ToolKind::Function,
            raw: value.clone(),
        }),
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
            .get("name")
            .and_then(JsonValue::as_str)
            .map(|name| ToolChoice::Tool {
                name: name.to_string(),
            })
            .unwrap_or_else(|| ToolChoice::Raw(value.clone())),
    }
}

fn output_items_json(
    message_id: &str,
    output: &[OutputItem],
    status: &str,
) -> AdaptorResult<Vec<JsonValue>> {
    let mut text = String::new();
    let mut items = Vec::new();
    for item in output {
        match item {
            OutputItem::Text {
                text: part,
                channel: TextChannel::Output,
            } => text.push_str(part),
            OutputItem::Text {
                text: part,
                channel: TextChannel::Reasoning,
            } => items.push(json!({
                "id": format!("{message_id}_reasoning"),
                "type": "reasoning",
                "summary": [],
                "content": [{"type": "reasoning_text", "text": part}],
            })),
            OutputItem::ToolCall {
                id,
                name,
                arguments,
            } => items.push(json!({
                "id": id,
                "type": "function_call",
                "call_id": id,
                "name": name,
                "arguments": json_to_output_string(arguments),
                "status": status,
            })),
            OutputItem::StructuredJson(value) => text.push_str(&json_to_output_string(value)),
            OutputItem::Raw(value) => items.push(value.clone()),
        }
    }
    if !text.is_empty() || items.is_empty() {
        items.insert(
            0,
            message_item_json(message_id, status, vec![output_text_json(&text)]),
        );
    }
    Ok(items)
}

fn decode_output_items(items: &[JsonValue]) -> Vec<OutputItem> {
    items.iter().flat_map(decode_output_item).collect()
}

fn decode_output_item(item: &JsonValue) -> Vec<OutputItem> {
    match item.get("type").and_then(JsonValue::as_str) {
        Some("message") => item
            .get("content")
            .and_then(JsonValue::as_array)
            .map(|parts| parts.iter().map(decode_message_content_part).collect())
            .unwrap_or_default(),
        Some("function_call") => vec![OutputItem::ToolCall {
            id: item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            name: item
                .get("name")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            arguments: decode_arguments(item.get("arguments")),
        }],
        Some("reasoning") => decode_reasoning_item(item),
        _ => vec![OutputItem::Raw(item.clone())],
    }
}

fn decode_reasoning_item(item: &JsonValue) -> Vec<OutputItem> {
    item.get("summary")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|part| {
            let text = part
                .get("text")
                .and_then(JsonValue::as_str)
                .filter(|text| !text.is_empty())?;
            Some(OutputItem::Text {
                text: text.to_string(),
                channel: TextChannel::Reasoning,
            })
        })
        .collect()
}

fn decode_message_content_part(part: &JsonValue) -> OutputItem {
    match part.get("type").and_then(JsonValue::as_str) {
        Some("output_text" | "text") => OutputItem::Text {
            text: part
                .get("text")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            channel: TextChannel::Output,
        },
        Some("reasoning_text") => OutputItem::Text {
            text: part
                .get("text")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            channel: TextChannel::Reasoning,
        },
        _ => OutputItem::Raw(part.clone()),
    }
}

fn decode_arguments(arguments: Option<&JsonValue>) -> JsonValue {
    match arguments {
        Some(JsonValue::String(value)) => {
            serde_json::from_str(value).unwrap_or_else(|_| JsonValue::String(value.clone()))
        }
        Some(value) => value.clone(),
        None => JsonValue::Null,
    }
}

fn decode_usage(value: &JsonValue) -> Usage {
    Usage {
        input_tokens: value.get("input_tokens").and_then(JsonValue::as_u64),
        output_tokens: value.get("output_tokens").and_then(JsonValue::as_u64),
        total_tokens: value.get("total_tokens").and_then(JsonValue::as_u64),
    }
}

fn decode_stop_reason(value: &JsonValue) -> StopReason {
    match value.get("status").and_then(JsonValue::as_str) {
        Some("incomplete")
            if value
                .get("incomplete_details")
                .and_then(|details| details.get("reason"))
                .and_then(JsonValue::as_str)
                .is_some_and(|reason| matches!(reason, "max_output_tokens" | "max_tokens")) =>
        {
            StopReason::MaxOutputTokens
        }
        Some("incomplete")
            if value
                .get("incomplete_details")
                .and_then(|details| details.get("reason"))
                .and_then(JsonValue::as_str)
                == Some("cancelled") =>
        {
            StopReason::Cancelled
        }
        Some("cancelled") => StopReason::Cancelled,
        _ => StopReason::EndOfText,
    }
}

fn decode_response_error(value: &JsonValue) -> Option<crate::ExecutionErrorInfo> {
    let failed = value
        .get("status")
        .and_then(JsonValue::as_str)
        .is_some_and(|status| status == "failed");
    let error = value.get("error");
    if !failed && error.is_none() {
        return None;
    }
    Some(crate::ExecutionErrorInfo {
        message: error
            .and_then(|error| error.get("message"))
            .and_then(JsonValue::as_str)
            .unwrap_or("response failed")
            .to_string(),
        code: error
            .and_then(|error| error.get("code"))
            .and_then(JsonValue::as_str)
            .map(ToString::to_string),
    })
}

fn event_json(event: WireStreamEvent) -> AdaptorResult<JsonValue> {
    match event.data {
        WireEventData::Json(value) => Ok(value),
        WireEventData::Text(value) => serde_json::from_str(&value).map_err(|source| {
            AdaptorError::invalid_response(format!("invalid Responses stream JSON: {source}"))
        }),
        WireEventData::Bytes(bytes) => serde_json::from_slice(&bytes).map_err(|source| {
            AdaptorError::invalid_response(format!("invalid Responses stream JSON: {source}"))
        }),
    }
}

fn output_index(data: &JsonValue) -> usize {
    data.get("output_index")
        .and_then(JsonValue::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0)
}

fn decode_output_item_added(
    state: &mut ResponsesIngressState,
    data: &JsonValue,
) -> AdaptorResult<Vec<OutputEvent>> {
    let Some(item) = data.get("item") else {
        return Ok(Vec::new());
    };
    if item.get("type").and_then(JsonValue::as_str) != Some("function_call") {
        return Ok(Vec::new());
    }
    let id = tool_call_id(item);
    let Some(name) = item.get("name").and_then(JsonValue::as_str) else {
        return Ok(Vec::new());
    };
    let index = state.next_tool_index;
    state.next_tool_index = state.next_tool_index.saturating_add(1);
    state.saw_tool_call = true;
    if let Some(id) = id.as_ref() {
        state.item_to_tool_index.insert(id.clone(), index);
    }
    // Argument deltas name the output item, not its distinct call_id. Output
    // indexes also include non-tool items, so neither is our tool ordinal.
    if let Some(id) = item.get("id").and_then(JsonValue::as_str) {
        state.item_to_tool_index.insert(id.to_string(), index);
    }
    if let Some(output_index) = data.get("output_index").and_then(JsonValue::as_u64)
        && let Ok(output_index) = usize::try_from(output_index)
    {
        state.output_to_tool_index.insert(output_index, index);
    }

    let mut events = vec![OutputEvent::ToolCallStart(ToolCallStart {
        index,
        id,
        name: name.to_string(),
    })];
    if let Some(arguments) = item
        .get("arguments")
        .and_then(JsonValue::as_str)
        .filter(|arguments| !arguments.is_empty())
    {
        events.push(OutputEvent::ToolCallArgumentsDelta(
            ToolCallArgumentsDelta {
                index,
                delta: arguments.to_string(),
            },
        ));
    }
    Ok(events)
}

fn decode_output_item_done(
    state: &mut ResponsesIngressState,
    data: &JsonValue,
) -> AdaptorResult<Vec<OutputEvent>> {
    let Some(item) = data.get("item") else {
        return Ok(Vec::new());
    };
    if item.get("type").and_then(JsonValue::as_str) != Some("function_call") {
        return Ok(Vec::new());
    }
    let Some(index) = tool_index_for_item(state, item) else {
        return Ok(Vec::new());
    };
    Ok(vec![OutputEvent::ToolCallEnd(ToolCallEnd {
        index,
        arguments: decode_arguments(item.get("arguments")),
    })])
}

fn tool_index_for_event(state: &ResponsesIngressState, data: &JsonValue) -> Option<usize> {
    data.get("item_id")
        .and_then(JsonValue::as_str)
        .and_then(|id| state.item_to_tool_index.get(id).copied())
        .or_else(|| {
            data.get("output_index")
                .and_then(JsonValue::as_u64)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| state.output_to_tool_index.get(&index).copied())
        })
}

fn tool_index_for_item(state: &ResponsesIngressState, item: &JsonValue) -> Option<usize> {
    tool_call_id(item).and_then(|id| state.item_to_tool_index.get(&id).copied())
}

fn tool_call_id(item: &JsonValue) -> Option<String> {
    item.get("call_id")
        .or_else(|| item.get("id"))
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
}

fn decode_stream_stop_reason(response: &JsonValue, state: &ResponsesIngressState) -> StopReason {
    match decode_stop_reason(response) {
        StopReason::EndOfText if state.saw_tool_call => StopReason::ToolCall,
        reason => reason,
    }
}

fn render_tool_call_start(
    state: &mut ResponsesStreamState,
    start: ToolCallStart,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let id = start
        .id
        .ok_or_else(|| AdaptorError::render("Responses tool call start requires an id"))?;
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
    let output_index = next_output_index(state);
    state.tool_calls.push(ResponseToolCallState {
        parser_index: start.index,
        output_index,
        id: id.clone(),
        name: start.name.clone(),
        arguments: String::new(),
    });

    Ok(vec![response_event(
        "response.output_item.added",
        json!({
            "output_index": output_index,
            "item": {
                "id": id,
                "type": "function_call",
                "call_id": id,
                "name": start.name,
                "arguments": "",
                "status": "in_progress",
            },
        }),
        state,
    )])
}

fn ensure_message_item_started(state: &mut ResponsesStreamState) -> Vec<WireStreamEvent> {
    if state.message_output_index.is_some() {
        return Vec::new();
    }
    let output_index = next_output_index(state);
    state.message_output_index = Some(output_index);
    let item = message_item_json(&state.message_id, "in_progress", Vec::new());
    let part = output_text_json("");
    vec![
        response_event(
            "response.output_item.added",
            json!({
                "output_index": output_index,
                "item": item,
            }),
            state,
        ),
        response_event(
            "response.content_part.added",
            json!({
                "item_id": state.message_id,
                "output_index": output_index,
                "content_index": 0,
                "part": part,
            }),
            state,
        ),
    ]
}

fn render_reasoning_delta(state: &mut ResponsesStreamState, delta: String) -> Vec<WireStreamEvent> {
    let mut events = ensure_reasoning_item_started(state);
    let output_index = state
        .reasoning_output_index
        .expect("reasoning item is started before reasoning deltas");
    state.reasoning_text.push_str(&delta);
    events.push(response_event(
        "response.reasoning_summary_text.delta",
        json!({
            "item_id": state.reasoning_id,
            "output_index": output_index,
            "summary_index": 0,
            "delta": delta,
        }),
        state,
    ));
    events
}

fn ensure_reasoning_item_started(state: &mut ResponsesStreamState) -> Vec<WireStreamEvent> {
    if state.reasoning_output_index.is_some() {
        return Vec::new();
    }
    let output_index = next_output_index(state);
    state.reasoning_output_index = Some(output_index);
    vec![
        response_event(
            "response.output_item.added",
            json!({
                "output_index": output_index,
                "item": reasoning_item_json(&state.reasoning_id, "in_progress", &state.reasoning_text),
            }),
            state,
        ),
        response_event(
            "response.reasoning_summary_part.added",
            json!({
                "item_id": state.reasoning_id,
                "output_index": output_index,
                "summary_index": 0,
                "part": {
                    "type": "summary_text",
                    "text": "",
                },
            }),
            state,
        ),
    ]
}

fn finish_open_items(state: &mut ResponsesStreamState, item_status: &str) -> Vec<WireStreamEvent> {
    let mut events = finish_reasoning_item(state, item_status);
    events.extend(finish_message_item(state, item_status));
    events
}

fn finish_reasoning_item(
    state: &mut ResponsesStreamState,
    item_status: &str,
) -> Vec<WireStreamEvent> {
    let Some(output_index) = state.reasoning_output_index else {
        return Vec::new();
    };
    vec![
        response_event(
            "response.reasoning_summary_text.done",
            json!({
                "item_id": state.reasoning_id,
                "output_index": output_index,
                "summary_index": 0,
                "text": state.reasoning_text,
            }),
            state,
        ),
        response_event(
            "response.reasoning_summary_part.done",
            json!({
                "item_id": state.reasoning_id,
                "output_index": output_index,
                "summary_index": 0,
                "part": {
                    "type": "summary_text",
                    "text": state.reasoning_text,
                },
            }),
            state,
        ),
        response_event(
            "response.output_item.done",
            json!({
                "output_index": output_index,
                "item": reasoning_item_json(&state.reasoning_id, item_status, &state.reasoning_text),
            }),
            state,
        ),
    ]
}

fn finish_message_item(
    state: &mut ResponsesStreamState,
    item_status: &str,
) -> Vec<WireStreamEvent> {
    let Some(output_index) = state.message_output_index else {
        return Vec::new();
    };
    let completed_text = output_text_json(&state.text);
    let item = message_item_json(&state.message_id, item_status, vec![completed_text.clone()]);
    vec![
        response_event(
            "response.output_text.done",
            json!({
                "item_id": state.message_id,
                "output_index": output_index,
                "content_index": 0,
                "text": state.text,
            }),
            state,
        ),
        response_event(
            "response.content_part.done",
            json!({
                "item_id": state.message_id,
                "output_index": output_index,
                "content_index": 0,
                "part": completed_text,
            }),
            state,
        ),
        response_event(
            "response.output_item.done",
            json!({
                "output_index": output_index,
                "item": item,
            }),
            state,
        ),
    ]
}

fn completed_output_items(state: &ResponsesStreamState, item_status: &str) -> Vec<JsonValue> {
    let mut items = Vec::with_capacity(state.tool_calls.len() + 2);
    if let Some(output_index) = state.reasoning_output_index {
        items.push((
            output_index,
            reasoning_item_json(&state.reasoning_id, item_status, &state.reasoning_text),
        ));
    }
    if let Some(output_index) = state.message_output_index {
        items.push((
            output_index,
            message_item_json(
                &state.message_id,
                item_status,
                vec![output_text_json(&state.text)],
            ),
        ));
    }
    items.extend(state.tool_calls.iter().map(|call| {
        (
            call.output_index,
            response_tool_call_item(call, item_status),
        )
    }));
    items.sort_by_key(|(output_index, _)| *output_index);
    items.into_iter().map(|(_, item)| item).collect()
}

fn render_tool_call_arguments_delta(
    state: &mut ResponsesStreamState,
    index: usize,
    delta: String,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let (id, output_index) = {
        let call = response_tool_call_mut(state, index)?;
        call.arguments.push_str(&delta);
        (call.id.clone(), call.output_index)
    };
    Ok(vec![response_event(
        "response.function_call_arguments.delta",
        json!({
            "item_id": id,
            "output_index": output_index,
            "delta": delta,
        }),
        state,
    )])
}

fn render_tool_call_end(
    state: &mut ResponsesStreamState,
    end: ToolCallEnd,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let (id, output_index, item, arguments) = {
        let call = response_tool_call_mut(state, end.index)?;
        if !end.arguments.is_null() {
            call.arguments = json_to_output_string(&end.arguments);
        }
        (
            call.id.clone(),
            call.output_index,
            response_tool_call_item(call, "completed"),
            call.arguments.clone(),
        )
    };
    Ok(vec![
        response_event(
            "response.function_call_arguments.done",
            json!({
                "item_id": id,
                "output_index": output_index,
                "arguments": arguments,
            }),
            state,
        ),
        response_event(
            "response.output_item.done",
            json!({
                "output_index": output_index,
                "item": item,
            }),
            state,
        ),
    ])
}

fn response_tool_call_mut(
    state: &mut ResponsesStreamState,
    parser_index: usize,
) -> AdaptorResult<&mut ResponseToolCallState> {
    state
        .tool_calls
        .iter_mut()
        .find(|call| call.parser_index == parser_index)
        .ok_or_else(|| AdaptorError::render(format!("unknown tool call index {parser_index}")))
}

fn response_tool_call_item(call: &ResponseToolCallState, status: &str) -> JsonValue {
    json!({
        "id": call.id,
        "type": "function_call",
        "call_id": call.id,
        "name": call.name,
        "arguments": call.arguments,
        "status": status,
    })
}

fn render_structured_delta(
    state: &mut ResponsesStreamState,
    delta: StructuredDelta,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let rendered = match delta {
        StructuredDelta::Text(text) => text,
        StructuredDelta::Json(value) => json_to_output_string(&value),
    };
    let mut events = ensure_message_item_started(state);
    let output_index = state
        .message_output_index
        .expect("message item is started before structured deltas");
    state.text.push_str(&rendered);
    events.push(response_event(
        "response.output_text.delta",
        json!({
            "item_id": state.message_id,
            "output_index": output_index,
            "content_index": 0,
            "delta": rendered,
        }),
        state,
    ));
    Ok(events)
}

fn response_status_payload(
    state: &ResponsesStreamState,
    request: &ParsedResponseRequest,
    status: &str,
    output: Vec<JsonValue>,
    usage: Option<Usage>,
) -> JsonValue {
    json!({
        "response": response_json(ResponseJsonParts {
            response_id: &state.response_id,
            created_at: state.created_at,
            model: &request.model,
            status,
            output,
            usage,
            metadata: request_metadata(request),
            provenance: state.provenance.as_ref(),
        }),
    })
}

struct ResponseJsonParts<'a> {
    response_id: &'a str,
    created_at: i64,
    model: &'a str,
    status: &'a str,
    output: Vec<JsonValue>,
    usage: Option<Usage>,
    metadata: Option<&'a JsonValue>,
    provenance: Option<&'a crate::Provenance>,
}

fn response_json(parts: ResponseJsonParts<'_>) -> JsonValue {
    let mut object = json!({
        "id": parts.response_id,
        "object": "response",
        "created_at": parts.created_at,
        "status": parts.status,
        "model": parts.model,
        "output": parts.output,
    });
    if let Some(usage) = parts.usage {
        object["usage"] = usage_json(usage);
    }
    if let Some(metadata) = parts.metadata {
        object["metadata"] = metadata.clone();
    }
    if let Some(provenance) = parts.provenance.and_then(provenance_json) {
        object["hellas"] = provenance;
    }
    object
}

fn request_metadata(request: &ParsedResponseRequest) -> Option<&JsonValue> {
    request.raw.value().get("metadata")
}

fn message_item_json(message_id: &str, status: &str, content: Vec<JsonValue>) -> JsonValue {
    json!({
        "id": message_id,
        "type": "message",
        "status": status,
        "role": "assistant",
        "content": content,
        "annotations": [],
    })
}

fn reasoning_item_json(reasoning_id: &str, status: &str, text: &str) -> JsonValue {
    let summary = if text.is_empty() {
        Vec::new()
    } else {
        vec![json!({
            "type": "summary_text",
            "text": text,
        })]
    };
    json!({
        "id": reasoning_id,
        "type": "reasoning",
        "status": status,
        "summary": summary,
    })
}

fn output_text_json(text: &str) -> JsonValue {
    json!({
        "type": "output_text",
        "text": text,
        "annotations": [],
    })
}

fn terminal_item_status(stop_reason: StopReason) -> &'static str {
    match stop_reason {
        StopReason::MaxOutputTokens | StopReason::Cancelled => "incomplete",
        StopReason::EndOfText | StopReason::StopSequence | StopReason::ToolCall => "completed",
    }
}

fn terminal_response_status(stop_reason: StopReason) -> &'static str {
    match stop_reason {
        StopReason::MaxOutputTokens | StopReason::Cancelled => "incomplete",
        StopReason::EndOfText | StopReason::StopSequence | StopReason::ToolCall => "completed",
    }
}

fn terminal_response_event(stop_reason: StopReason) -> &'static str {
    match stop_reason {
        StopReason::MaxOutputTokens | StopReason::Cancelled => "response.incomplete",
        StopReason::EndOfText | StopReason::StopSequence | StopReason::ToolCall => {
            "response.completed"
        }
    }
}

fn apply_terminal_details(response: &mut JsonValue, stop_reason: StopReason) {
    match stop_reason {
        StopReason::MaxOutputTokens => {
            response["incomplete_details"] = json!({"reason": "max_output_tokens"});
        }
        StopReason::Cancelled => {
            response["incomplete_details"] = json!({"reason": "cancelled"});
        }
        StopReason::EndOfText | StopReason::StopSequence | StopReason::ToolCall => {}
    }
}

fn usage_json(usage: Usage) -> JsonValue {
    json!({
        "input_tokens": usage.input_tokens.unwrap_or(0),
        "output_tokens": usage.output_tokens.unwrap_or(0),
        "total_tokens": usage.total_tokens.unwrap_or_else(|| {
            usage.input_tokens.unwrap_or(0).saturating_add(usage.output_tokens.unwrap_or(0))
        }),
    })
}

fn response_event(
    name: &str,
    mut data: JsonValue,
    state: &mut ResponsesStreamState,
) -> WireStreamEvent {
    data["type"] = json!(name);
    data["sequence_number"] = json!(state.sequence_number);
    state.sequence_number = state.sequence_number.saturating_add(1);
    WireStreamEvent::json(Some(name.to_string()), data)
}

fn next_output_index(state: &mut ResponsesStreamState) -> usize {
    let current = state.next_output_index;
    state.next_output_index = state.next_output_index.saturating_add(1);
    current
}

fn json_to_output_string(value: &JsonValue) -> String {
    match value {
        JsonValue::String(value) => value.clone(),
        _ => serde_json::to_string(value).expect("serializing JSON value cannot fail"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Provenance, StopReason, WireEventData, WireIngress};

    fn adaptor() -> OpenAiResponsesAdaptor {
        OpenAiResponsesAdaptor
    }

    fn raw(value: JsonValue) -> RawRequest {
        RawRequest::from_value(value).unwrap()
    }

    fn event_names(events: &[WireStreamEvent]) -> Vec<&str> {
        events
            .iter()
            .enumerate()
            .map(|(sequence, event)| {
                let name = event.name.as_deref().expect("named SSE event");
                let WireEventData::Json(data) = &event.data else {
                    panic!("expected JSON event");
                };
                assert_eq!(data["type"], name);
                assert_eq!(data["sequence_number"], sequence as u64);
                name
            })
            .collect()
    }

    fn sample_request() -> ParsedResponseRequest {
        adaptor()
            .parse(raw(json!({
                "model": "gpt-4.1-mini",
                "input": [
                    {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {"type": "input_text", "text": "Describe this"},
                            {"type": "input_image", "image_url": {"url": "https://example.com/a.png"}}
                        ]
                    }
                ],
                "instructions": "Be brief.",
                "tools": [
                    {
                        "type": "function",
                        "name": "lookup",
                        "description": "Look up a value",
                        "parameters": {"type": "object"}
                    }
                ],
                "tool_choice": {"type": "function", "name": "lookup"},
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "answer",
                        "schema": {"type": "object"},
                        "strict": true
                    }
                },
                "reasoning": {"effort": "low"},
                "max_output_tokens": 64,
                "temperature": 0.2,
                "top_p": 0.9,
                "top_logprobs": 2,
                "parallel_tool_calls": true,
                "truncation": "auto",
                "previous_response_id": "resp_prev",
                "stream": true,
                "metadata": {"request_id": "r1"},
                "seed": 42
            })))
            .unwrap()
    }

    #[test]
    fn parse_preserves_raw_request() {
        let parsed = sample_request();
        assert_eq!(parsed.model, "gpt-4.1-mini");
        assert_eq!(parsed.max_output_tokens, Some(64));
        assert_eq!(parsed.stream, Some(true));
        assert_eq!(parsed.raw.value()["metadata"]["request_id"], "r1");
        assert_eq!(parsed.raw.value()["seed"], 42);
        assert!(parsed.raw.bytes().starts_with(b"{"));
    }

    #[test]
    fn projection_sets_responses_execution_fields() {
        let parsed = sample_request();
        let execution = adaptor().to_execution_request(&parsed).unwrap();
        assert_eq!(execution.canonical.model.name, "gpt-4.1-mini");
        assert_eq!(
            execution.canonical.instructions.as_deref(),
            Some("Be brief.")
        );
        assert_eq!(execution.canonical.sampling.max_output_tokens, Some(64));
        assert_eq!(execution.canonical.tools.len(), 1);
        assert!(execution.canonical.reasoning.is_some());
        assert_eq!(
            execution.canonical.previous_response_id.as_deref(),
            Some("resp_prev")
        );
    }

    #[test]
    fn projection_handles_string_input() {
        let parsed = adaptor()
            .parse(raw(json!({"model": "m", "input": "hello"})))
            .unwrap();
        let execution = adaptor().to_execution_request(&parsed).unwrap();
        assert_eq!(execution.canonical.input, Input::Text("hello".to_string()));
    }

    #[test]
    fn projection_preserves_builtin_tool_specs_as_raw_canonical_tools() {
        let tool = json!({
            "type": "web_search_preview",
            "user_location": {"type": "approximate", "city": "Zurich"}
        });
        let parsed = adaptor()
            .parse(raw(json!({
                "model": "m",
                "input": "hello",
                "tools": [tool.clone()]
            })))
            .unwrap();
        let execution = adaptor().to_execution_request(&parsed).unwrap();

        assert_eq!(execution.canonical.tools.len(), 1);
        assert_eq!(execution.canonical.tools[0].name, "web_search_preview");
        assert_eq!(
            execution.canonical.tools[0].kind,
            ToolKind::BuiltIn("web_search_preview".to_string())
        );
        assert_eq!(execution.canonical.tools[0].raw, tool);
    }

    #[test]
    fn render_non_streaming_text_response() {
        let parsed = sample_request();
        adaptor().to_execution_request(&parsed).unwrap();
        let response = adaptor()
            .render_response(
                &parsed,
                ExecutionResult {
                    output: vec![OutputItem::Text {
                        text: "hello".to_string(),
                        channel: TextChannel::Output,
                    }],
                    usage: Some(Usage {
                        input_tokens: Some(5),
                        output_tokens: Some(1),
                        total_tokens: Some(6),
                    }),
                    stop_reason: StopReason::EndOfText,
                    provenance: Some(Provenance {
                        call_commitment: Some("aa".repeat(32)),
                    }),
                    error: None,
                },
                RenderContext::new("resp_1", "msg_1", 123),
            )
            .unwrap();

        assert_eq!(response.status, 200);
        let body = match response.body {
            crate::WireBody::Json(body) => body,
            crate::WireBody::Bytes(_) => panic!("expected JSON response"),
        };
        assert_eq!(body["id"], "resp_1");
        assert_eq!(body["output"][0]["content"][0]["text"], "hello");
        assert_eq!(body["metadata"]["request_id"], "r1");
        assert_eq!(body["hellas"]["commitment"], "aa".repeat(32));
    }

    #[test]
    fn render_non_streaming_failed_response() {
        let parsed = sample_request();
        let response = adaptor()
            .render_response(
                &parsed,
                ExecutionResult {
                    output: vec![OutputItem::Text {
                        text: "partial".to_string(),
                        channel: TextChannel::Output,
                    }],
                    usage: None,
                    stop_reason: StopReason::Cancelled,
                    provenance: Some(Provenance {
                        call_commitment: Some("aa".repeat(32)),
                    }),
                    error: Some(crate::ExecutionErrorInfo {
                        message: "provider failed".to_string(),
                        code: Some("upstream_error".to_string()),
                    }),
                },
                RenderContext::new("resp_1", "msg_1", 123),
            )
            .unwrap();

        assert_eq!(response.status, 200);
        let body = match response.body {
            crate::WireBody::Json(body) => body,
            crate::WireBody::Bytes(_) => panic!("expected JSON response"),
        };
        assert_eq!(body["status"], "failed");
        assert_eq!(body["error"]["code"], "upstream_error");
        assert_eq!(body["error"]["message"], "provider failed");
        assert_eq!(body["output"][0]["status"], "incomplete");
        assert_eq!(body["output"][0]["content"][0]["text"], "partial");
        assert_eq!(body["hellas"]["commitment"], "aa".repeat(32));
    }

    #[test]
    fn render_non_streaming_tool_call_response() {
        let parsed = sample_request();
        let response = adaptor()
            .render_response(
                &parsed,
                ExecutionResult {
                    output: vec![OutputItem::ToolCall {
                        id: "call_1".to_string(),
                        name: "lookup".to_string(),
                        arguments: json!({"query": "tea"}),
                    }],
                    usage: None,
                    stop_reason: StopReason::ToolCall,
                    provenance: None,
                    error: None,
                },
                RenderContext::new("resp_1", "msg_1", 123),
            )
            .unwrap();

        let body = match response.body {
            crate::WireBody::Json(body) => body,
            crate::WireBody::Bytes(_) => panic!("expected JSON response"),
        };
        assert_eq!(body["output"][0]["type"], "function_call");
        assert_eq!(body["output"][0]["call_id"], "call_1");
        assert_eq!(body["output"][0]["arguments"], "{\"query\":\"tea\"}");
    }

    #[test]
    fn decode_non_streaming_response() {
        let parsed = sample_request();
        let result = adaptor()
            .decode_response(
                &parsed,
                br#"{
                    "id": "resp_test",
                    "object": "response",
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {"type": "output_text", "text": "done"}
                            ]
                        },
                        {
                            "type": "function_call",
                            "call_id": "call_1",
                            "name": "lookup",
                            "arguments": "{\"query\":\"tea\"}"
                        }
                    ],
                    "usage": {
                        "input_tokens": 3,
                        "output_tokens": 2,
                        "total_tokens": 5
                    }
                }"#,
            )
            .unwrap();

        assert_eq!(
            result.output,
            vec![
                OutputItem::Text {
                    text: "done".to_string(),
                    channel: TextChannel::Output,
                },
                OutputItem::ToolCall {
                    id: "call_1".to_string(),
                    name: "lookup".to_string(),
                    arguments: json!({"query": "tea"}),
                },
            ]
        );
        assert_eq!(result.usage.unwrap().total_tokens, Some(5));
        assert_eq!(result.stop_reason, StopReason::EndOfText);
    }

    #[test]
    fn decode_non_streaming_reasoning_item_as_reasoning_text() {
        let parsed = sample_request();
        let result = adaptor()
            .decode_response(
                &parsed,
                br#"{
                    "id": "resp_test",
                    "object": "response",
                    "status": "completed",
                    "output": [
                        {
                            "id": "rs_1",
                            "type": "reasoning",
                            "status": "completed",
                            "summary": [
                                {"type": "summary_text", "text": "thinking"}
                            ]
                        },
                        {
                            "type": "message",
                            "content": [
                                {"type": "output_text", "text": "done"}
                            ]
                        }
                    ]
                }"#,
            )
            .unwrap();

        assert_eq!(
            result.output,
            vec![
                OutputItem::Text {
                    text: "thinking".to_string(),
                    channel: TextChannel::Reasoning,
                },
                OutputItem::Text {
                    text: "done".to_string(),
                    channel: TextChannel::Output,
                },
            ]
        );
    }

    #[test]
    fn decode_stream_text_events_without_indexes() {
        let parsed = sample_request();
        let mut state = adaptor().initial_ingress_state(&parsed);
        let mut events = Vec::new();
        for event in [
            WireStreamEvent::text(
                Some("response.output_text.delta".to_string()),
                r#"{"type":"response.output_text.delta","item_id":"msg_1","delta":"hel"}"#,
            ),
            WireStreamEvent::text(
                Some("response.output_text.delta".to_string()),
                r#"{"type":"response.output_text.delta","item_id":"msg_1","delta":"lo"}"#,
            ),
            WireStreamEvent::text(
                Some("response.completed".to_string()),
                r#"{"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}"#,
            ),
        ] {
            events.extend(
                adaptor()
                    .decode_stream_event(&parsed, &mut state, event)
                    .unwrap(),
            );
        }

        assert_eq!(
            events,
            vec![
                OutputEvent::TextDelta {
                    index: 0,
                    delta: "hel".to_string(),
                    channel: TextChannel::Output,
                },
                OutputEvent::TextDelta {
                    index: 0,
                    delta: "lo".to_string(),
                    channel: TextChannel::Output,
                },
                OutputEvent::Finished {
                    stop_reason: StopReason::EndOfText,
                    usage: Some(Usage {
                        input_tokens: Some(3),
                        output_tokens: Some(2),
                        total_tokens: Some(5),
                    }),
                },
            ]
        );
    }

    #[test]
    fn decode_stream_tool_call_events_without_indexes() {
        let parsed = sample_request();
        let mut state = adaptor().initial_ingress_state(&parsed);
        let mut events = Vec::new();
        for event in [
            WireStreamEvent::text(
                Some("response.output_item.added".to_string()),
                r#"{"type":"response.output_item.added","item":{"id":"call_1","call_id":"call_1","type":"function_call","name":"bash","arguments":"","status":"in_progress"}}"#,
            ),
            WireStreamEvent::text(
                Some("response.function_call_arguments.delta".to_string()),
                r#"{"type":"response.function_call_arguments.delta","item_id":"call_1","delta":"{\"command\":\"printf hi\"}"}"#,
            ),
            WireStreamEvent::text(
                Some("response.output_item.done".to_string()),
                r#"{"type":"response.output_item.done","item":{"id":"call_1","call_id":"call_1","type":"function_call","name":"bash","arguments":"{\"command\":\"printf hi\"}","status":"completed"}}"#,
            ),
            WireStreamEvent::text(
                Some("response.completed".to_string()),
                r#"{"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}"#,
            ),
        ] {
            events.extend(
                adaptor()
                    .decode_stream_event(&parsed, &mut state, event)
                    .unwrap(),
            );
        }

        assert_eq!(
            events,
            vec![
                OutputEvent::ToolCallStart(ToolCallStart {
                    index: 0,
                    id: Some("call_1".to_string()),
                    name: "bash".to_string(),
                }),
                OutputEvent::ToolCallArgumentsDelta(ToolCallArgumentsDelta {
                    index: 0,
                    delta: r#"{"command":"printf hi"}"#.to_string(),
                }),
                OutputEvent::ToolCallEnd(ToolCallEnd {
                    index: 0,
                    arguments: json!({"command": "printf hi"}),
                }),
                OutputEvent::Finished {
                    stop_reason: StopReason::ToolCall,
                    usage: Some(Usage {
                        input_tokens: Some(3),
                        output_tokens: Some(2),
                        total_tokens: Some(5),
                    }),
                },
            ]
        );
    }

    #[test]
    fn decode_stream_tool_indexes_exclude_other_output_items() {
        let parsed = sample_request();
        for reference in [json!({"item_id": "fc_1"}), json!({"output_index": 3})] {
            let mut state = adaptor().initial_ingress_state(&parsed);
            let item = json!({
                "type": "function_call", "id": "fc_1", "call_id": "call_1",
                "name": "write", "arguments": ""
            });
            let start =
                decode_output_item_added(&mut state, &json!({"output_index": 3, "item": item}))
                    .unwrap();
            assert!(matches!(&start[0], OutputEvent::ToolCallStart(call)
                if call.index == 0 && call.id.as_deref() == Some("call_1")));
            let mut delta = reference;
            delta["type"] = json!("response.function_call_arguments.delta");
            delta["delta"] = json!("{}");
            assert_eq!(
                adaptor()
                    .decode_stream_event(&parsed, &mut state, WireStreamEvent::json(None, delta))
                    .unwrap(),
                vec![OutputEvent::ToolCallArgumentsDelta(
                    ToolCallArgumentsDelta {
                        index: 0,
                        delta: "{}".into(),
                    }
                )]
            );
            assert_eq!(tool_index_for_item(&state, &item), Some(0));
        }
    }

    #[test]
    fn decode_stream_rejects_unknown_tool_output_index() {
        let parsed = sample_request();
        let mut state = adaptor().initial_ingress_state(&parsed);
        assert!(
            adaptor()
                .decode_stream_event(
                    &parsed,
                    &mut state,
                    WireStreamEvent::json(
                        None,
                        json!({
                            "type": "response.function_call_arguments.delta",
                            "output_index": 0, "delta": "{}"
                        })
                    ),
                )
                .is_err()
        );
    }

    #[test]
    fn decode_stream_accepts_ds4_reasoning_and_incomplete_reason() {
        let parsed = sample_request();
        let mut state = adaptor().initial_ingress_state(&parsed);
        let mut events = Vec::new();
        for event in [
            WireStreamEvent::text(
                Some("response.reasoning_summary_text.delta".to_string()),
                r#"{"type":"response.reasoning_summary_text.delta","item_id":"rs_1","output_index":0,"summary_index":0,"delta":"thinking"}"#,
            ),
            WireStreamEvent::text(
                Some("response.incomplete".to_string()),
                r#"{"type":"response.incomplete","response":{"id":"resp_1","object":"response","status":"incomplete","incomplete_details":{"reason":"max_tokens"},"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}}"#,
            ),
        ] {
            events.extend(
                adaptor()
                    .decode_stream_event(&parsed, &mut state, event)
                    .unwrap(),
            );
        }

        assert_eq!(
            events,
            vec![
                OutputEvent::TextDelta {
                    index: 0,
                    delta: "thinking".to_string(),
                    channel: TextChannel::Reasoning,
                },
                OutputEvent::Finished {
                    stop_reason: StopReason::MaxOutputTokens,
                    usage: Some(Usage {
                        input_tokens: Some(3),
                        output_tokens: Some(4),
                        total_tokens: Some(7),
                    }),
                },
            ]
        );
    }

    #[test]
    fn render_stream_text_sequence() {
        let parsed = sample_request();
        let mut state =
            adaptor().initial_state(&parsed, RenderContext::new("resp_1", "msg_1", 123));
        let mut events = adaptor().render_stream_start(&parsed, &mut state).unwrap();
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::TextDelta {
                        index: 0,
                        delta: "hel".to_string(),
                        channel: TextChannel::Output,
                    },
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::TextDelta {
                        index: 0,
                        delta: "lo".to_string(),
                        channel: TextChannel::Output,
                    },
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::Finished {
                        stop_reason: StopReason::EndOfText,
                        usage: Some(Usage {
                            input_tokens: Some(5),
                            output_tokens: Some(1),
                            total_tokens: Some(6),
                        }),
                    },
                )
                .unwrap(),
        );

        let names = event_names(&events);
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.in_progress",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
        let completed = match &events.last().unwrap().data {
            WireEventData::Json(value) => value,
            _ => panic!("expected JSON event"),
        };
        assert_eq!(
            completed["response"]["output"][0]["content"][0]["text"],
            "hello"
        );
        assert_eq!(completed["response"]["usage"]["total_tokens"], 6);
    }

    #[test]
    fn render_stream_max_output_emits_incomplete_response() {
        let parsed = sample_request();
        let mut state =
            adaptor().initial_state(&parsed, RenderContext::new("resp_1", "msg_1", 123));
        let mut events = adaptor().render_stream_start(&parsed, &mut state).unwrap();
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::TextDelta {
                        index: 0,
                        delta: "hel".to_string(),
                        channel: TextChannel::Output,
                    },
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::Finished {
                        stop_reason: StopReason::MaxOutputTokens,
                        usage: None,
                    },
                )
                .unwrap(),
        );

        let names = event_names(&events);
        assert_eq!(names.last().copied(), Some("response.incomplete"));
        let incomplete = match &events.last().unwrap().data {
            WireEventData::Json(value) => value,
            _ => panic!("expected JSON event"),
        };
        assert_eq!(incomplete["type"], "response.incomplete");
        assert_eq!(incomplete["response"]["status"], "incomplete");
        assert_eq!(
            incomplete["response"]["incomplete_details"]["reason"],
            "max_output_tokens"
        );
        assert_eq!(incomplete["response"]["output"][0]["status"], "incomplete");
    }

    #[test]
    fn render_stream_error_emits_failed_response() {
        let parsed = sample_request();
        let mut state =
            adaptor().initial_state(&parsed, RenderContext::new("resp_1", "msg_1", 123));
        let mut events = adaptor().render_stream_start(&parsed, &mut state).unwrap();
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::TextDelta {
                        index: 0,
                        delta: "hel".to_string(),
                        channel: TextChannel::Output,
                    },
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::Error {
                        message: "provider failed".to_string(),
                        code: Some("upstream_error".to_string()),
                    },
                )
                .unwrap(),
        );

        let failed = match &events.last().unwrap().data {
            WireEventData::Json(value) => value,
            _ => panic!("expected JSON event"),
        };
        assert_eq!(
            events.last().unwrap().name.as_deref(),
            Some("response.failed")
        );
        assert_eq!(failed["response"]["status"], "failed");
        assert_eq!(failed["response"]["error"]["code"], "upstream_error");
        assert_eq!(failed["response"]["error"]["message"], "provider failed");
        assert_eq!(failed["response"]["output"][0]["status"], "incomplete");
    }

    #[test]
    fn render_stream_reasoning_sequence() {
        let parsed = sample_request();
        let mut state =
            adaptor().initial_state(&parsed, RenderContext::new("resp_1", "msg_1", 123));
        let mut events = adaptor().render_stream_start(&parsed, &mut state).unwrap();
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::TextDelta {
                        index: 0,
                        delta: "thinking".to_string(),
                        channel: TextChannel::Reasoning,
                    },
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::Finished {
                        stop_reason: StopReason::EndOfText,
                        usage: None,
                    },
                )
                .unwrap(),
        );

        let names = event_names(&events);
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.in_progress",
                "response.output_item.added",
                "response.reasoning_summary_part.added",
                "response.reasoning_summary_text.delta",
                "response.reasoning_summary_text.done",
                "response.reasoning_summary_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );

        let added = match &events[2].data {
            WireEventData::Json(value) => value,
            _ => panic!("expected reasoning added event"),
        };
        assert_eq!(added["output_index"], 0);
        assert_eq!(added["item"]["type"], "reasoning");

        let completed = match &events.last().unwrap().data {
            WireEventData::Json(value) => value,
            _ => panic!("expected completed event"),
        };
        assert_eq!(completed["response"]["output"][0]["type"], "reasoning");
        assert_eq!(
            completed["response"]["output"][0]["summary"][0]["text"],
            "thinking"
        );
    }

    #[test]
    fn render_stream_tool_call_sequence() {
        let parsed = sample_request();
        let mut state =
            adaptor().initial_state(&parsed, RenderContext::new("resp_1", "msg_1", 123));
        let mut events = adaptor().render_stream_start(&parsed, &mut state).unwrap();
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::ToolCallStart(crate::ToolCallStart {
                        index: 0,
                        id: Some("call_1".to_string()),
                        name: "lookup".to_string(),
                    }),
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::ToolCallArgumentsDelta(crate::ToolCallArgumentsDelta {
                        index: 0,
                        delta: "{\"query\":\"tea\"}".to_string(),
                    }),
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::ToolCallEnd(crate::ToolCallEnd {
                        index: 0,
                        arguments: json!({"query": "tea"}),
                    }),
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::Finished {
                        stop_reason: StopReason::ToolCall,
                        usage: Some(Usage {
                            input_tokens: Some(5),
                            output_tokens: Some(1),
                            total_tokens: Some(6),
                        }),
                    },
                )
                .unwrap(),
        );

        let names = event_names(&events);
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.in_progress",
                "response.output_item.added",
                "response.function_call_arguments.delta",
                "response.function_call_arguments.done",
                "response.output_item.done",
                "response.completed",
            ]
        );

        let tool_added = match &events[2].data {
            WireEventData::Json(value) => value,
            _ => panic!("expected tool-call added event"),
        };
        assert_eq!(tool_added["output_index"], 0);
        assert_eq!(tool_added["item"]["id"], "call_1");
        assert_eq!(tool_added["item"]["name"], "lookup");
        assert_eq!(tool_added["item"]["arguments"], "");

        let args_delta = match &events[3].data {
            WireEventData::Json(value) => value,
            _ => panic!("expected tool-call arguments delta"),
        };
        assert_eq!(args_delta["item_id"], "call_1");
        assert_eq!(args_delta["delta"], "{\"query\":\"tea\"}");

        let args_done = match &events[4].data {
            WireEventData::Json(value) => value,
            _ => panic!("expected tool-call arguments done"),
        };
        assert_eq!(args_done["arguments"], "{\"query\":\"tea\"}");

        let completed = match &events.last().unwrap().data {
            WireEventData::Json(value) => value,
            _ => panic!("expected completed event"),
        };
        assert_eq!(completed["response"]["output"][0]["type"], "function_call");
        assert_eq!(completed["response"]["output"][0]["call_id"], "call_1");
        assert_eq!(
            completed["response"]["output"][0]["arguments"],
            "{\"query\":\"tea\"}"
        );
    }

    #[test]
    fn render_stream_tool_first_then_text_preserves_output_order() {
        let parsed = sample_request();
        let mut state =
            adaptor().initial_state(&parsed, RenderContext::new("resp_1", "msg_1", 123));
        let mut events = adaptor().render_stream_start(&parsed, &mut state).unwrap();
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::ToolCallStart(crate::ToolCallStart {
                        index: 0,
                        id: Some("call_1".to_string()),
                        name: "lookup".to_string(),
                    }),
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::ToolCallEnd(crate::ToolCallEnd {
                        index: 0,
                        arguments: json!({"query": "tea"}),
                    }),
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::TextDelta {
                        index: 0,
                        delta: "after".to_string(),
                        channel: TextChannel::Output,
                    },
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::Finished {
                        stop_reason: StopReason::ToolCall,
                        usage: None,
                    },
                )
                .unwrap(),
        );

        let tool_added = match &events[2].data {
            WireEventData::Json(value) => value,
            _ => panic!("expected tool-call added event"),
        };
        assert_eq!(tool_added["output_index"], 0);
        let text_added = events
            .iter()
            .find_map(|event| match &event.data {
                WireEventData::Json(value)
                    if event.name.as_deref() == Some("response.output_item.added")
                        && value["item"]["type"] == "message" =>
                {
                    Some(value)
                }
                _ => None,
            })
            .expect("text item should be added after tool call");
        assert_eq!(text_added["output_index"], 1);

        let completed = match &events.last().unwrap().data {
            WireEventData::Json(value) => value,
            _ => panic!("expected completed event"),
        };
        assert_eq!(completed["response"]["output"][0]["type"], "function_call");
        assert_eq!(completed["response"]["output"][1]["type"], "message");
        assert_eq!(
            completed["response"]["output"][1]["content"][0]["text"],
            "after"
        );
    }

    #[test]
    fn render_stream_structured_delta_starts_message_item_after_tool_call() {
        let parsed = sample_request();
        let mut state =
            adaptor().initial_state(&parsed, RenderContext::new("resp_1", "msg_1", 123));
        let mut events = adaptor().render_stream_start(&parsed, &mut state).unwrap();
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::ToolCallStart(crate::ToolCallStart {
                        index: 0,
                        id: Some("call_1".to_string()),
                        name: "lookup".to_string(),
                    }),
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::StructuredOutputDelta(crate::StructuredDelta::Json(json!({
                        "answer": "after"
                    }))),
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::Finished {
                        stop_reason: StopReason::ToolCall,
                        usage: None,
                    },
                )
                .unwrap(),
        );

        let text_delta = events
            .iter()
            .find_map(|event| match &event.data {
                WireEventData::Json(value)
                    if event.name.as_deref() == Some("response.output_text.delta") =>
                {
                    Some(value)
                }
                _ => None,
            })
            .expect("structured delta should render as output text");
        assert_eq!(text_delta["output_index"], 1);
        assert_eq!(text_delta["delta"], "{\"answer\":\"after\"}");

        let completed = match &events.last().unwrap().data {
            WireEventData::Json(value) => value,
            _ => panic!("expected completed event"),
        };
        assert_eq!(completed["response"]["output"][0]["type"], "function_call");
        assert_eq!(completed["response"]["output"][1]["type"], "message");
        assert_eq!(
            completed["response"]["output"][1]["content"][0]["text"],
            "{\"answer\":\"after\"}"
        );
    }
}
