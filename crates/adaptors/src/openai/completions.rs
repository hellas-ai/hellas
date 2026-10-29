use serde_json::{Value as JsonValue, json};

use super::{finish_reason_json, usage_json};

use crate::{
    AdaptorError, AdaptorResult, CanonicalExecution, ExecutionRequest, ExecutionResult, Input,
    ModelRef, OutputEvent, OutputItem, RawRequest, RenderContext, StopReason, TextChannel,
    WireAdaptor, WireEventData, WireResponse, WireStreamEvent,
    json::{attach_hellas, json_to_wire_string, optional_bool, optional_u32, required_string},
};

#[derive(Clone, Copy, Debug, Default)]
pub struct OpenAiCompletionsAdaptor;

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedCompletionRequest {
    pub raw: RawRequest,
    pub model: String,
    pub prompt: String,
    pub max_tokens: Option<u32>,
    pub stream: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionStreamState {
    id: String,
    created: i64,
    model: String,
    provenance: Option<crate::Provenance>,
}

impl WireAdaptor for OpenAiCompletionsAdaptor {
    type ParsedRequest = ParsedCompletionRequest;
    type StreamState = CompletionStreamState;

    fn parse(&self, raw: RawRequest) -> AdaptorResult<Self::ParsedRequest> {
        ParsedCompletionRequest::parse(raw)
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
        CompletionStreamState {
            id: context.response_id,
            created: context.created_at,
            model: request.model.clone(),
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
        let mut body = json!({
            "id": context.response_id,
            "object": "text_completion",
            "created": context.created_at,
            "model": request.model,
            "choices": [{
                "index": 0,
                "text": output_text(&result.output),
                "finish_reason": finish_reason_json(result.stop_reason),
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
                channel: TextChannel::Output | TextChannel::Reasoning,
                ..
            }
            | OutputEvent::StructuredOutputDelta(crate::StructuredDelta::Text(delta)) => {
                Ok(vec![WireStreamEvent::json(
                    None,
                    completion_chunk_json(state, delta, None),
                )])
            }
            OutputEvent::StructuredOutputDelta(crate::StructuredDelta::Json(value)) => {
                Ok(vec![WireStreamEvent::json(
                    None,
                    completion_chunk_json(state, json_to_wire_string(&value), None),
                )])
            }
            OutputEvent::ToolCallStart(_)
            | OutputEvent::ToolCallArgumentsDelta(_)
            | OutputEvent::ToolCallEnd(_)
            | OutputEvent::Adaptor(_) => Err(AdaptorError::unsupported(
                "text completions cannot render tool or adaptor-specific events",
            )),
            OutputEvent::Usage(_) => Ok(Vec::new()),
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
                    },
                }),
            )]),
            OutputEvent::Finished { stop_reason, .. } => Ok(vec![
                WireStreamEvent::json(
                    None,
                    completion_chunk_json(state, String::new(), Some(stop_reason)),
                ),
                WireStreamEvent {
                    name: None,
                    data: WireEventData::Text("[DONE]".to_string()),
                },
            ]),
        }
    }
}

impl ParsedCompletionRequest {
    fn parse(raw: RawRequest) -> AdaptorResult<Self> {
        let object = raw.value().as_object().ok_or_else(|| {
            AdaptorError::invalid_request("Completions request must be a JSON object")
        })?;
        let model = required_string(object, "model")?;
        let prompt = required_string(object, "prompt")?;
        let max_tokens = optional_u32(object, "max_tokens")?;
        let stream = optional_bool(object, "stream")?;
        Ok(Self {
            raw,
            model,
            prompt,
            max_tokens,
            stream,
        })
    }

    fn to_execution_request(&self) -> AdaptorResult<ExecutionRequest> {
        let mut canonical = CanonicalExecution::new(
            ModelRef::new(self.model.clone()),
            Input::Text(self.prompt.clone()),
        );
        if let Some(max_tokens) = self.max_tokens {
            canonical.sampling.max_output_tokens = Some(max_tokens);
        }
        Ok(ExecutionRequest::new(canonical))
    }
}

fn output_text(output: &[OutputItem]) -> String {
    output
        .iter()
        .map(|item| match item {
            OutputItem::Text { text, .. } => text.clone(),
            OutputItem::StructuredJson(value) | OutputItem::Raw(value) => {
                json_to_wire_string(value)
            }
            OutputItem::ToolCall {
                id,
                name,
                arguments,
            } => json_to_wire_string(&json!({
                "id": id,
                "name": name,
                "arguments": arguments,
            })),
        })
        .collect::<Vec<_>>()
        .join("")
}

fn completion_chunk_json(
    state: &CompletionStreamState,
    text: String,
    stop_reason: Option<StopReason>,
) -> JsonValue {
    attach_hellas(
        json!({
            "id": state.id,
            "object": "text_completion",
            "created": state.created,
            "model": state.model,
            "choices": [{
                "index": 0,
                "text": text,
                "finish_reason": stop_reason.map(finish_reason_json).unwrap_or(JsonValue::Null),
            }],
        }),
        state.provenance.as_ref(),
    )
}

#[cfg(test)]
mod tests;
