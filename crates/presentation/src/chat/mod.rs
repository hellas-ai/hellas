//! Shared model presentation: a turn binds input formatting and output parsing
//! to the same offered tools. The incremental decoder is adapted from
//! catgrad-llm ac0e432; it has no GPU, HTTP server, or payment dependency.

mod codecs;
mod event;
mod input;
mod parser;
mod sentinel_engine;
mod tool_spec;

use crate::{ChatTemplate, TextPresentation};
use anyhow::{Context, Result, ensure};
use event::{DecodeEvent, SchemaError, StopReason};
use hellas_adaptors::{CanonicalExecution, Input, OutputEvent, TextChannel, ToolChoice};
use parser::{IncrementalToolCallParser, PassthroughParser};
use std::sync::Arc;
use tool_spec::ToolDirectory;

pub struct PreparedChat {
    pub input_ids: Vec<u32>,
    pub turn: ChatTurn,
}

/// A request's model adapter, retained while its token-native execution runs.
pub struct ChatTurn {
    parser: Box<dyn IncrementalToolCallParser>,
    called: bool,
    require_tool: bool,
    id: String,
}

impl TextPresentation {
    pub fn prepare(&self, request: &CanonicalExecution) -> Result<PreparedChat> {
        ensure!(
            request.reasoning.is_none(),
            "reasoning options are not supported by the configured chat template"
        );
        let tools = input::chat_tools(request)?;
        let selected = request
            .tools
            .iter()
            .filter(|tool| {
                tools
                    .iter()
                    .any(|item| item["function"]["name"] == tool.name)
            })
            .cloned()
            .collect::<Vec<_>>();
        let require_tool = matches!(
            request.tool_choice,
            ToolChoice::Required | ToolChoice::Tool { .. }
        );
        let parser: Box<dyn IncrementalToolCallParser> = if tools.is_empty() {
            Box::new(PassthroughParser)
        } else {
            let directory = Arc::new(ToolDirectory::new(selected)?);
            let codec: Box<dyn sentinel_engine::PayloadCodec> = match self.chat_template {
                Some(ChatTemplate::Qwen3) => Box::new(codecs::json::JsonObjectOrArrayCodec),
                Some(ChatTemplate::Qwen35) => Box::new(
                    codecs::xml_function::XmlFunctionCodec::new(directory.clone()),
                ),
                None => anyhow::bail!("tools require a model adapter supporting them"),
            };
            Box::new(sentinel_engine::SentinelEngine::new_pair(
                directory,
                codec,
                "<tool_call>",
                "</tool_call>",
            ))
        };
        let input_ids = match &request.input {
            Input::Text(text) if request.instructions.is_none() && tools.is_empty() => {
                self.encode(text)?
            }
            input => {
                let mut messages =
                    input::text_chat_messages(input, request.instructions.as_deref())?;
                if require_tool {
                    messages.insert(
                        0,
                        crate::ChatMessage {
                            role: "system".into(),
                            content: "Use one of the provided tools to answer this turn.".into(),
                            ..Default::default()
                        },
                    );
                }
                self.encode_chat_with_tools(&messages, &tools)?
            }
        };
        Ok(PreparedChat {
            input_ids,
            turn: ChatTurn {
                parser,
                called: false,
                require_tool,
                id: uuid::Uuid::new_v4().simple().to_string(),
            },
        })
    }
}

impl ChatTurn {
    pub fn plain() -> Self {
        Self {
            parser: Box::new(PassthroughParser),
            called: false,
            require_tool: false,
            id: String::new(),
        }
    }

    pub fn feed(&mut self, text: &str) -> Result<Vec<OutputEvent>> {
        let events = self.parser.feed(text);
        self.map(events)
    }

    pub fn finish(&mut self, reason: hellas_adaptors::StopReason) -> Result<Vec<OutputEvent>> {
        let reason = match reason {
            hellas_adaptors::StopReason::MaxOutputTokens => StopReason::MaxTokens,
            _ => StopReason::EndOfText,
        };
        let events = self.parser.finish(reason);
        let mapped = self.map(events)?;
        ensure!(
            !self.require_tool || self.called,
            "model did not produce the required tool call"
        );
        Ok(mapped)
    }

    pub fn called(&self) -> bool {
        self.called
    }

    fn map(&mut self, events: Vec<DecodeEvent>) -> Result<Vec<OutputEvent>> {
        let mut output = Vec::new();
        for event in events {
            output.push(match event {
                DecodeEvent::TextDelta(delta) => OutputEvent::TextDelta {
                    index: 0,
                    delta,
                    channel: TextChannel::Output,
                },
                DecodeEvent::ToolCallStart { index, name } => {
                    self.called = true;
                    OutputEvent::ToolCallStart(hellas_adaptors::ToolCallStart {
                        index,
                        name,
                        id: Some(format!("call_{}_{index}", self.id)),
                    })
                }
                DecodeEvent::ToolCallArgsDelta { index, delta } => {
                    OutputEvent::ToolCallArgumentsDelta(hellas_adaptors::ToolCallArgumentsDelta {
                        index,
                        delta,
                    })
                }
                DecodeEvent::ToolCallEnd { index, args } => {
                    OutputEvent::ToolCallEnd(hellas_adaptors::ToolCallEnd {
                        index,
                        arguments: args,
                    })
                }
                DecodeEvent::Stop { reason } => {
                    ensure!(
                        reason != StopReason::ProtocolError,
                        "model tool protocol failed"
                    );
                    continue;
                }
                DecodeEvent::UnknownTool { name, .. } => {
                    anyhow::bail!("model called an unavailable tool: {name}")
                }
                DecodeEvent::InvalidArgs { name, errors, .. } => {
                    anyhow::bail!("model produced invalid arguments for {name}: {errors:?}")
                }
                DecodeEvent::ParseError { sentinel, source } => {
                    return Err(source).with_context(|| {
                        format!("model tool call at {sentinel} could not be decoded")
                    });
                }
            });
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_adaptors::{
        RawRequest, WireAdaptor, openai::chat_completions::OpenAiChatCompletionsAdaptor,
    };
    use serde_json::json;

    fn request() -> CanonicalExecution {
        let adaptor = OpenAiChatCompletionsAdaptor;
        let request = adaptor.parse(RawRequest::from_value(json!({
            "model": "qwen3", "messages": [{"role": "user", "content": "Inspect disk usage"}],
            "tools": [{"type": "function", "function": {
                "name": "bash", "description": "Run a command",
                "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}
            }}]
        })).unwrap()).unwrap();
        adaptor.to_execution_request(&request).unwrap().canonical
    }

    fn presentation() -> TextPresentation {
        TextPresentation {
            tokenizer: tokenizers::Tokenizer::from_bytes(br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":null,"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"<unk>":0},"unk_token":"<unk>"}}"#).unwrap(),
            chat_template: Some(ChatTemplate::Qwen3),
        }
    }

    #[test]
    fn fragmented_tool_turn_round_trips_through_shared_adapter() {
        let mut turn = presentation().prepare(&request()).unwrap().turn;
        let mut events = Vec::new();
        for character in "Checking 😊<tool_call>\n{\"name\":\"bash\",\"arguments\":{\"command\":\"df -h\"}}\n</tool_call>".chars() {
            events.extend(turn.feed(&character.to_string()).unwrap());
        }
        events.extend(turn.finish(hellas_adaptors::StopReason::EndOfText).unwrap());
        assert!(turn.called());
        let text: String = events
            .iter()
            .filter_map(|event| match event {
                OutputEvent::TextDelta { delta, .. } => Some(delta.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, "Checking 😊");
        let name = events
            .iter()
            .find_map(|event| match event {
                OutputEvent::ToolCallStart(call) => Some(&call.name),
                _ => None,
            })
            .unwrap();
        let arguments = events
            .iter()
            .find_map(|event| match event {
                OutputEvent::ToolCallEnd(call) => Some(&call.arguments),
                _ => None,
            })
            .unwrap();
        assert_eq!(name, "bash");
        assert_eq!(arguments, &json!({"command": "df -h"}));
        let input = Input::Items(vec![
            hellas_adaptors::InputItem::Raw(
                json!({"role": "user", "content": "Inspect disk usage"}),
            ),
            hellas_adaptors::InputItem::Raw(json!({"role": "assistant", "content": null,
                "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": name, "arguments": arguments.to_string()}}]})),
            hellas_adaptors::InputItem::Raw(
                json!({"role": "tool", "tool_call_id": "call_1", "content": "/home: 74% used"}),
            ),
        ]);
        let messages = input::text_chat_messages(&input, None).unwrap();
        let rendered = ChatTemplate::Qwen3
            .render_with_tools(&messages, &input::chat_tools(&request()).unwrap())
            .unwrap();
        assert!(rendered.contains(
            "<tool_call>\n{\"arguments\":{\"command\":\"df -h\"},\"name\":\"bash\"}\n</tool_call>"
        ));
        assert!(rendered.contains("<tool_response>\n/home: 74% used\n</tool_response>"));
    }

    #[test]
    fn qwen36_fragmented_xml_preserves_string_arguments_and_tool_history() {
        let mut presentation = presentation();
        presentation.chat_template = Some(ChatTemplate::Qwen35);
        for command in ["df -h", "true", "123", "echo café"] {
            let mut turn = presentation.prepare(&request()).unwrap().turn;
            let output = format!(
                "<tool_call>\n<function=bash>\n<parameter=command>\n{command}\n</parameter>\n</function>\n</tool_call>"
            );
            let mut events = Vec::new();
            for character in output.chars() {
                events.extend(turn.feed(&character.to_string()).unwrap());
            }
            events.extend(turn.finish(hellas_adaptors::StopReason::EndOfText).unwrap());
            let arguments = events
                .iter()
                .find_map(|event| match event {
                    OutputEvent::ToolCallEnd(call) => Some(&call.arguments),
                    _ => None,
                })
                .unwrap();
            assert_eq!(arguments, &json!({"command": command}));
            let input = Input::Items(vec![
                hellas_adaptors::InputItem::Raw(
                    json!({"role": "user", "content": "Inspect disk usage"}),
                ),
                hellas_adaptors::InputItem::Raw(json!({"role": "assistant", "content": null,
                    "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "bash", "arguments": arguments.to_string()}}]})),
                hellas_adaptors::InputItem::Raw(
                    json!({"role": "tool", "tool_call_id": "call_1", "content": "/home: 74% used"}),
                ),
            ]);
            let messages = input::text_chat_messages(&input, None).unwrap();
            let rendered = ChatTemplate::Qwen35
                .render_with_tools(&messages, &input::chat_tools(&request()).unwrap())
                .unwrap();
            assert!(rendered.contains(&output));
            assert!(rendered.ends_with("<|im_start|>user\n<tool_response>\n/home: 74% used\n</tool_response><|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"));
        }
    }

    #[test]
    fn unsupported_reasoning_is_rejected_for_text_and_chat() {
        let mut request = request();
        request.reasoning = Some(hellas_adaptors::ReasoningOptions {
            value: json!({"effort": "high"}),
        });
        assert!(presentation().prepare(&request).is_err());
        request.input = Input::Text("hello".into());
        request.tools.clear();
        assert!(presentation().prepare(&request).is_err());
    }

    #[test]
    fn xml_string_types_use_schema_validation_including_references() {
        for string_schema in [
            json!({"type": ["string"]}),
            json!({"allOf": [{"type": "string"}]}),
            json!({"$ref": "#/$defs/text"}),
        ] {
            let mut request = request();
            request.tools[0].parameters = json!({
                "type": "object", "$defs": {"text": {"type": "string"}},
                "properties": {"command": string_schema, "count": {"type": "integer"}},
                "required": ["command", "count"], "additionalProperties": false
            });
            let mut presentation = presentation();
            presentation.chat_template = Some(ChatTemplate::Qwen35);
            for text in ["123", "true", "null"] {
                let mut turn = presentation.prepare(&request).unwrap().turn;
                let events = turn.feed(&format!("<tool_call><function=bash><parameter=command>{text}</parameter><parameter=count>2</parameter></function></tool_call>")).unwrap();
                let args = events
                    .iter()
                    .find_map(|event| match event {
                        OutputEvent::ToolCallEnd(call) => Some(&call.arguments),
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(args, &json!({"command": text, "count": 2}));
            }
        }
    }

    #[test]
    fn xml_composed_object_schemas_coerce_multiple_strings_and_numbers() {
        for combinator in ["oneOf", "anyOf"] {
            let mut request = request();
            let properties = json!({"a": {"type": "string"}, "b": {"$ref": "#/$defs/text"}, "c": {"type": "integer"}});
            request.tools[0].parameters = json!({
                "type": "object", "$defs": {"text": {"type": "string"}},
                "properties": properties, "required": ["a", "b", "c"],
                (combinator): [{"properties": properties}]
            });
            let mut presentation = presentation();
            presentation.chat_template = Some(ChatTemplate::Qwen35);
            let mut turn = presentation.prepare(&request).unwrap().turn;
            let events = turn.feed("<tool_call><function=bash><parameter=a>1</parameter><parameter=b>2</parameter><parameter=c>3</parameter></function></tool_call>").unwrap();
            let args = events
                .iter()
                .find_map(|event| match event {
                    OutputEvent::ToolCallEnd(call) => Some(&call.arguments),
                    _ => None,
                })
                .unwrap();
            assert_eq!(args, &json!({"a": "1", "b": "2", "c": 3}));
        }
    }

    #[test]
    fn incomplete_or_invalid_tool_calls_cannot_finish_as_success() {
        for output in [
            "<tool_call>{\"name\":\"bash\",\"arguments\":{",
            "<tool_call>{\"name\":\"bash\",\"arguments\":{\"command\":123}}</tool_call>",
            "<tool_call>{\"name\":\"unavailable\",\"arguments\":{}}</tool_call>",
        ] {
            let mut turn = presentation().prepare(&request()).unwrap().turn;
            let result = turn
                .feed(output)
                .and_then(|_| turn.finish(hellas_adaptors::StopReason::MaxOutputTokens));
            assert!(result.is_err(), "invalid output was accepted: {output}");
        }
    }
}
