use std::future::Future;
use std::pin::Pin;

use futures_core::Stream;
use futures_util::StreamExt;
use serde_json::Value as JsonValue;
use thiserror::Error;

use crate::execution::merge_provenance;
use crate::{
    ExecutionErrorInfo, ExecutionRequest, ExecutionResult, OutputEvent, OutputItem, Provenance,
    RawRequest, StructuredDelta, TextChannel, ToolCallStart,
};

pub type BackendResult<T> = Result<T, BackendError>;
pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = BackendResult<T>> + Send + 'a>>;
pub type BackendEventStream = Pin<Box<dyn Stream<Item = BackendResult<BackendEvent>> + Send>>;

/// One event of a backend's stream: signed output, or provenance the
/// gateway vouches for, which responses rendered after it carry.
#[derive(Clone, Debug, PartialEq)]
pub enum BackendEvent {
    Output(OutputEvent),
    Provenance(Provenance),
}

impl From<OutputEvent> for BackendEvent {
    fn from(event: OutputEvent) -> Self {
        Self::Output(event)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BackendRequest {
    pub execution: ExecutionRequest,
    pub raw: RawRequest,
}

impl BackendRequest {
    pub fn new(execution: ExecutionRequest, raw: RawRequest) -> Self {
        Self { execution, raw }
    }
}

pub trait ExecutionBackend {
    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream>;
}

pub struct BackendStream {
    pub events: BackendEventStream,
    /// Provenance known before the first event, for response headers.
    pub initial_provenance: Option<Provenance>,
}

impl BackendStream {
    pub fn new(
        events: impl Stream<Item = BackendResult<BackendEvent>> + Send + 'static,
        initial_provenance: Option<Provenance>,
    ) -> Self {
        Self {
            events: Box::pin(events),
            initial_provenance,
        }
    }

    pub async fn collect(mut self) -> BackendResult<ExecutionResult> {
        let mut output = CollectedOutput::default();
        let mut usage = None;
        let mut provenance = self.initial_provenance.take();

        while let Some(event) = self.events.next().await {
            let event = match event? {
                BackendEvent::Output(event) => event,
                BackendEvent::Provenance(next) => {
                    merge_provenance(&mut provenance, next);
                    continue;
                }
            };
            match event {
                OutputEvent::TextDelta {
                    index,
                    delta,
                    channel,
                } => output.push_text(index, channel, delta),
                OutputEvent::ToolCallStart(start) => output.start_tool_call(start),
                OutputEvent::ToolCallArgumentsDelta(delta) => {
                    output.push_tool_arguments(delta.index, delta.delta)
                }
                OutputEvent::ToolCallEnd(end) => output.finish_tool_call(end.index, end.arguments),
                OutputEvent::StructuredOutputDelta(delta) => output.push_structured(delta),
                OutputEvent::Adaptor(_) => {
                    return Err(BackendError::failed(
                        "adaptor-specific streams cannot be collected as generic output",
                    ));
                }
                OutputEvent::Usage(next) => usage = Some(next),
                OutputEvent::Provenance(next) => merge_provenance(&mut provenance, next.into()),
                OutputEvent::Error { message, code } => {
                    return Ok(ExecutionResult {
                        output: output.finish(),
                        usage,
                        stop_reason: crate::StopReason::Cancelled,
                        provenance,
                        error: Some(ExecutionErrorInfo { message, code }),
                    });
                }
                OutputEvent::Finished {
                    stop_reason,
                    usage: final_usage,
                } => {
                    return Ok(ExecutionResult {
                        output: output.finish(),
                        usage: final_usage.or(usage),
                        stop_reason,
                        provenance,
                        error: None,
                    });
                }
            }
        }

        Err(BackendError::failed(
            "backend stream ended without terminal event",
        ))
    }
}

#[derive(Default)]
struct CollectedOutput {
    text: Vec<CollectedText>,
    tools: Vec<CollectedToolCall>,
    structured: Vec<OutputItem>,
}

impl CollectedOutput {
    fn push_text(&mut self, index: usize, channel: TextChannel, delta: String) {
        if let Some(text) = self
            .text
            .iter_mut()
            .find(|text| text.index == index && text.channel == channel)
        {
            text.text.push_str(&delta);
        } else {
            self.text.push(CollectedText {
                index,
                channel,
                text: delta,
            });
        }
    }

    fn start_tool_call(&mut self, start: ToolCallStart) {
        if let Some(tool) = self.tools.iter_mut().find(|tool| tool.index == start.index) {
            tool.id = start.id;
            tool.name = start.name;
            tool.arguments_delta.clear();
            tool.arguments = None;
        } else {
            self.tools.push(CollectedToolCall {
                index: start.index,
                id: start.id,
                name: start.name,
                arguments_delta: String::new(),
                arguments: None,
            });
        }
    }

    fn push_tool_arguments(&mut self, index: usize, delta: String) {
        let tool = self.tool_mut(index);
        tool.arguments_delta.push_str(&delta);
    }

    fn finish_tool_call(&mut self, index: usize, arguments: JsonValue) {
        self.tool_mut(index).arguments = Some(arguments);
    }

    fn push_structured(&mut self, delta: StructuredDelta) {
        match delta {
            StructuredDelta::Text(text) => self.structured.push(OutputItem::Text {
                text,
                channel: TextChannel::Output,
            }),
            StructuredDelta::Json(value) => self.structured.push(OutputItem::StructuredJson(value)),
        }
    }

    fn finish(mut self) -> Vec<OutputItem> {
        let mut indexed = Vec::with_capacity(self.text.len() + self.tools.len());
        for text in self.text {
            indexed.push((
                text.index,
                OutputItem::Text {
                    text: text.text,
                    channel: text.channel,
                },
            ));
        }
        for tool in self.tools {
            let arguments = tool.arguments.unwrap_or_else(|| {
                serde_json::from_str(&tool.arguments_delta)
                    .unwrap_or(JsonValue::String(tool.arguments_delta))
            });
            indexed.push((
                tool.index,
                OutputItem::ToolCall {
                    id: tool.id.unwrap_or_default(),
                    name: tool.name,
                    arguments,
                },
            ));
        }
        indexed.sort_by_key(|(index, _)| *index);
        let mut output = indexed
            .into_iter()
            .map(|(_, item)| item)
            .collect::<Vec<_>>();
        output.append(&mut self.structured);
        output
    }

    fn tool_mut(&mut self, index: usize) -> &mut CollectedToolCall {
        if let Some(position) = self.tools.iter().position(|tool| tool.index == index) {
            &mut self.tools[position]
        } else {
            self.tools.push(CollectedToolCall {
                index,
                id: None,
                name: String::new(),
                arguments_delta: String::new(),
                arguments: None,
            });
            self.tools.last_mut().expect("inserted tool call")
        }
    }
}

struct CollectedText {
    index: usize,
    channel: TextChannel,
    text: String,
}

struct CollectedToolCall {
    index: usize,
    id: Option<String>,
    name: String,
    arguments_delta: String,
    arguments: Option<JsonValue>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
    use serde_json::json;

    #[test]
    fn collect_reconstructs_terminal_execution_result() {
        let stream = BackendStream::new(
            stream::iter([
                Ok(OutputEvent::TextDelta {
                    index: 0,
                    delta: "hel".to_string(),
                    channel: TextChannel::Output,
                }),
                Ok(OutputEvent::TextDelta {
                    index: 0,
                    delta: "lo".to_string(),
                    channel: TextChannel::Output,
                }),
                Ok(OutputEvent::ToolCallStart(ToolCallStart {
                    index: 1,
                    id: Some("call_1".to_string()),
                    name: "lookup".to_string(),
                })),
                Ok(OutputEvent::ToolCallArgumentsDelta(
                    crate::ToolCallArgumentsDelta {
                        index: 1,
                        delta: r#"{"query":"tea"}"#.to_string(),
                    },
                )),
                Ok(OutputEvent::ToolCallEnd(crate::ToolCallEnd {
                    index: 1,
                    arguments: json!({"query": "tea"}),
                })),
                Ok(OutputEvent::Provenance(hellas_rpc::output::Provenance {
                    call_commitment: Some("signed".to_string()),
                })),
            ])
            .map(|event| event.map(BackendEvent::from))
            .chain(stream::iter([
                Ok(BackendEvent::Provenance(Provenance {
                    transcript: Some("dHJhbnNjcmlwdA==".to_string()),
                    ..Provenance::default()
                })),
                Ok(OutputEvent::Finished {
                    stop_reason: crate::StopReason::EndOfText,
                    usage: Some(crate::Usage {
                        input_tokens: Some(3),
                        output_tokens: Some(2),
                        total_tokens: Some(5),
                    }),
                }
                .into()),
            ])),
            Some(Provenance {
                commitment: Some("call".to_string()),
                provider: Some("secp256k1:02".to_string()),
                transcript: None,
            }),
        );

        let result = futures_executor::block_on(stream.collect()).unwrap();

        assert_eq!(result.stop_reason, crate::StopReason::EndOfText);
        // Each later source replaces only the fields it names.
        assert_eq!(
            result.provenance,
            Some(Provenance {
                commitment: Some("signed".to_string()),
                provider: Some("secp256k1:02".to_string()),
                transcript: Some("dHJhbnNjcmlwdA==".to_string()),
            })
        );
        assert_eq!(
            result.output,
            vec![
                OutputItem::Text {
                    text: "hello".to_string(),
                    channel: TextChannel::Output,
                },
                OutputItem::ToolCall {
                    id: "call_1".to_string(),
                    name: "lookup".to_string(),
                    arguments: json!({"query": "tea"}),
                },
            ]
        );
        assert_eq!(
            result.usage,
            Some(crate::Usage {
                input_tokens: Some(3),
                output_tokens: Some(2),
                total_tokens: Some(5),
            })
        );
    }

    #[test]
    fn collect_returns_failed_result_on_error_event() {
        let stream = BackendStream::new(
            stream::iter([
                Ok(OutputEvent::TextDelta {
                    index: 0,
                    delta: "partial".to_string(),
                    channel: TextChannel::Output,
                }),
                Ok(OutputEvent::Error {
                    message: "provider failed".to_string(),
                    code: Some("upstream_error".to_string()),
                }),
            ])
            .map(|event| event.map(BackendEvent::from)),
            Some(Provenance {
                commitment: Some("call".to_string()),
                ..Provenance::default()
            }),
        );

        let result = futures_executor::block_on(stream.collect()).unwrap();

        assert_eq!(result.stop_reason, crate::StopReason::Cancelled);
        assert_eq!(
            result.error,
            Some(ExecutionErrorInfo {
                message: "provider failed".to_string(),
                code: Some("upstream_error".to_string()),
            })
        );
        assert_eq!(
            result.output,
            vec![OutputItem::Text {
                text: "partial".to_string(),
                channel: TextChannel::Output,
            }]
        );
        assert_eq!(
            result.provenance,
            Some(Provenance {
                commitment: Some("call".to_string()),
                ..Provenance::default()
            })
        );
    }
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("backend rejected request: {0}")]
    Rejected(String),
    #[error("backend access denied: {0}")]
    Denied(String),
    #[error("backend allowance exhausted: {0}")]
    Quota(String),
    #[error("backend busy: {0}")]
    Busy(String),
    #[error("backend conflict: {0}")]
    Conflict(String),
    #[error("backend timed out: {0}")]
    Timeout(String),
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("backend failed: {0}")]
    Failed(String),
}

impl BackendError {
    pub fn rejected(message: impl Into<String>) -> Self {
        Self::Rejected(message.into())
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }
}
