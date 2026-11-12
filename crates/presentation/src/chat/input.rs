use crate::ChatMessage;
use anyhow::Context;
use hellas_adaptors::{ContentPart, Input, InputItem, Message, ToolChoice};

pub(super) fn chat_tools(
    request: &hellas_adaptors::CanonicalExecution,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let bad = |message: &str| anyhow::anyhow!("{message}");
    if matches!(request.tool_choice, ToolChoice::Raw(_)) {
        return Err(bad("unsupported tool_choice"));
    }
    if matches!(request.tool_choice, ToolChoice::None) {
        return Ok(Vec::new());
    }
    let mut tools = Vec::new();
    for tool in &request.tools {
        if let ToolChoice::Tool { name } = &request.tool_choice
            && tool.name != *name
        {
            continue;
        }
        if tool.kind != hellas_adaptors::ToolKind::Function {
            return Err(bad("Qwen chat supports function tools"));
        }
        tools.push(serde_json::json!({
            "type": "function",
            "function": {"name": tool.name, "description": tool.description, "parameters": tool.parameters}
        }));
    }
    if tools.is_empty()
        && matches!(
            request.tool_choice,
            ToolChoice::Tool { .. } | ToolChoice::Required
        )
    {
        return Err(bad("tool_choice requires an available function tool"));
    }
    Ok(tools)
}

pub(super) fn text_chat_messages(
    input: &Input,
    instructions: Option<&str>,
    require_tool: bool,
) -> anyhow::Result<Vec<ChatMessage>> {
    let mut messages = Vec::new();
    if let Some(instructions) = instructions {
        messages.push(ChatMessage {
            role: "system".into(),
            content: instructions.into(),
            ..Default::default()
        });
    }
    match input {
        Input::Text(text) => messages.push(ChatMessage {
            role: "user".into(),
            content: text.clone(),
            ..Default::default()
        }),
        Input::Messages(input) => {
            for message in input {
                messages.push(text_chat_message(message)?);
            }
        }
        Input::Items(items) => {
            for item in items {
                messages.push(match item {
                    InputItem::Message(message) => text_chat_message(message)?,
                    InputItem::Raw(value) => raw_text_chat_message(value)?,
                    InputItem::ToolCall {
                        name, arguments, ..
                    } => ChatMessage {
                        role: "assistant".into(),
                        tool_calls: vec![serde_json::json!({"name": name, "arguments": arguments})],
                        ..Default::default()
                    },
                    InputItem::ToolResult { output, .. } => text_chat_message(&Message {
                        role: "tool".into(),
                        content: output.clone(),
                        name: None,
                        tool_calls: Vec::new(),
                    })?,
                });
            }
        }
    }
    let mut system = Vec::new();
    if require_tool {
        system.push("Use one of the provided tools to answer this turn.".to_owned());
    }
    messages.retain(|message| {
        if matches!(message.role.as_str(), "system" | "developer") {
            if !message.content.is_empty() {
                system.push(message.content.clone());
            }
            false
        } else {
            true
        }
    });
    if !system.is_empty() {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: system.join("\n\n"),
                ..Default::default()
            },
        );
    }
    for message in &mut messages {
        anyhow::ensure!(
            matches!(
                message.role.as_str(),
                "system" | "user" | "assistant" | "tool"
            ),
            "unsupported chat role {:?}",
            message.role
        );
        for call in &mut message.tool_calls {
            let function = if call.get("function").is_some() {
                &mut call["function"]
            } else {
                call
            };
            function
                .get("name")
                .and_then(serde_json::Value::as_str)
                .context("tool call requires a function name")?;
            let arguments = function
                .get_mut("arguments")
                .context("tool call requires arguments")?;
            if let Some(json) = arguments.as_str() {
                *arguments =
                    serde_json::from_str(json).context("tool call arguments must be JSON")?;
            }
            anyhow::ensure!(
                arguments.is_object(),
                "tool call arguments must be an object"
            );
        }
    }
    Ok(messages)
}

fn text_chat_message(message: &Message) -> anyhow::Result<ChatMessage> {
    anyhow::ensure!(
        message.name.is_none(),
        "text chat does not support named messages"
    );
    anyhow::ensure!(
        message.tool_calls.is_empty() || message.role == "assistant",
        "only assistant messages may call tools"
    );
    let mut content = String::new();
    for part in &message.content {
        match part {
            ContentPart::Text { text } => content.push_str(text),
            _ => anyhow::bail!("text chat requires text content parts"),
        }
    }
    Ok(ChatMessage {
        role: message.role.clone(),
        content,
        tool_calls: message
            .tool_calls
            .iter()
            .map(|call| {
                serde_json::json!({
                    "name": call.name, "arguments": call.arguments
                })
            })
            .collect(),
    })
}

fn raw_text_chat_message(value: &serde_json::Value) -> anyhow::Result<ChatMessage> {
    let message = value
        .as_object()
        .context("chat input must be a message object")?;
    for field in ["name", "function_call", "reasoning_content"] {
        if let Some(value) = message.get(field) {
            anyhow::ensure!(
                value.is_null() || value.as_array().is_some_and(Vec::is_empty),
                "text chat does not support message field {field}"
            );
        }
    }
    anyhow::ensure!(
        message.get("type").is_none_or(|kind| kind == "message"),
        "text chat requires message input items"
    );
    let role = message
        .get("role")
        .and_then(serde_json::Value::as_str)
        .context("chat message requires a role")?
        .to_string();
    let value = message
        .get("content")
        .context("chat message requires text content")?;
    let content = if value.is_null() {
        String::new()
    } else if let Some(text) = value.as_str() {
        text.to_string()
    } else {
        let parts = value
            .as_array()
            .context("chat message content must be text or text parts")?;
        let mut text = String::new();
        for part in parts {
            anyhow::ensure!(
                matches!(
                    part.get("type").and_then(serde_json::Value::as_str),
                    Some("text" | "input_text" | "output_text")
                ),
                "text chat requires text content parts"
            );
            text.push_str(
                part.get("text")
                    .and_then(serde_json::Value::as_str)
                    .context("chat text part requires a text string")?,
            );
        }
        text
    };
    let tool_calls = message
        .get("tool_calls")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_array()
                .cloned()
                .context("tool_calls must be an array")
        })
        .transpose()?
        .unwrap_or_default();
    anyhow::ensure!(
        tool_calls.is_empty() || role == "assistant",
        "only assistant messages may call tools"
    );
    Ok(ChatMessage {
        role,
        content,
        tool_calls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chat_adaptor_text_parts_reach_explicit_qwen_template() {
        use hellas_adaptors::{
            RawRequest, WireAdaptor, openai::chat_completions::OpenAiChatCompletionsAdaptor,
        };
        use serde_json::json;

        let adaptor = OpenAiChatCompletionsAdaptor;
        let request = adaptor.parse(RawRequest::from_value(json!({
        "model": "qwen3",
        "messages": [
            {"role": "system", "content": "Be concise."},
            {"role": "user", "content": [{"type": "text", "text": "Say "}, {"type": "text", "text": "hello"}]}
        ]
    })).unwrap()).unwrap();
        let request = adaptor.to_execution_request(&request).unwrap();
        let messages = text_chat_messages(&request.canonical.input, None, false).unwrap();
        assert_eq!(
            crate::tests::template(false).render(&messages).unwrap(),
            concat!(
                "<|im_start|>system\nBe concise.<|im_end|>\n",
                "<|im_start|>user\nSay hello<|im_end|>\n",
                "<|im_start|>assistant\n<think>\n\n</think>\n\n",
            )
        );
        assert!(raw_text_chat_message(&json!({"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://example.com/image.png"}}]})).is_err());
        assert!(
            text_chat_messages(
                &Input::Items(vec![InputItem::Raw(
                    json!({"role": "assistant", "content": "", "tool_calls": [{"id": "call"}]})
                )]),
                None,
                false
            )
            .is_err()
        );
    }
    use hellas_adaptors::{
        HistoricalToolCall, RawRequest, WireAdaptor, anthropic::AnthropicMessagesAdaptor,
    };
    use serde_json::json;

    fn anthropic(content: serde_json::Value, role: &str) -> Input {
        let adaptor = AnthropicMessagesAdaptor;
        let request = adaptor
            .parse(
                RawRequest::from_value(json!({
                    "model":"m", "max_tokens":8, "messages":[{"role":role,"content":content}]
                }))
                .unwrap(),
            )
            .unwrap();
        adaptor
            .to_execution_request(&request)
            .unwrap()
            .canonical
            .input
    }

    #[test]
    fn anthropic_text_blocks_have_the_same_template_message_as_string_input() {
        let a = text_chat_messages(&anthropic(json!("hello world"), "user"), None, false).unwrap();
        let b = text_chat_messages(
            &anthropic(
                json!([
                    {"type":"text","text":"hello"}, {"type":"text","text":" world"}
                ]),
                "user",
            ),
            None,
            false,
        )
        .unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(a[0].role, b[0].role);
        assert_eq!(a[0].content, b[0].content);
        assert_eq!(a[0].tool_calls, b[0].tool_calls);
        for template in [crate::tests::template(false), crate::tests::template(true)] {
            assert_eq!(template.render(&a).unwrap(), template.render(&b).unwrap());
        }
    }

    #[test]
    fn assistant_text_and_calls_lower_to_one_template_turn() {
        let input = anthropic(
            json!([
                {"type":"text","text":"Checking."},
                {"type":"tool_use","id":"a","name":"first","input":{"n":1}},
                {"type":"tool_use","id":"b","name":"second","input":{"n":2}}
            ]),
            "assistant",
        );
        let Input::Items(items) = &input else {
            panic!()
        };
        let InputItem::Message(message) = &items[0] else {
            panic!()
        };
        assert_eq!(
            message
                .tool_calls
                .iter()
                .map(|call| call.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        let messages = text_chat_messages(&input, None, false).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, "Checking.");
        for template in [crate::tests::template(false), crate::tests::template(true)] {
            let mut conversation = text_chat_messages(&input, None, false).unwrap();
            conversation.insert(
                0,
                ChatMessage {
                    role: "user".into(),
                    content: "Check both.".into(),
                    ..Default::default()
                },
            );
            let prompt = template.render(&conversation).unwrap();
            // One historical assistant turn and the generation prompt.
            assert_eq!(prompt.matches("<|im_start|>assistant").count(), 2);
            assert_eq!(prompt.matches("<tool_call>").count(), 2);
        }
        assert_eq!(
            messages[0].tool_calls,
            vec![
                json!({"name":"first","arguments":{"n":1}}),
                json!({"name":"second","arguments":{"n":2}})
            ]
        );
    }

    #[test]
    fn standalone_tool_call_items_keep_their_individual_turns() {
        let input = Input::Items(vec![
            InputItem::ToolCall {
                id: "a".into(),
                name: "first".into(),
                arguments: json!({}),
            },
            InputItem::ToolCall {
                id: "b".into(),
                name: "second".into(),
                arguments: json!({}),
            },
        ]);
        let messages = text_chat_messages(&input, None, false).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].tool_calls.len(), 1);
        assert_eq!(messages[1].tool_calls.len(), 1);
    }

    #[test]
    fn canonical_calls_require_an_assistant_message() {
        let mut message = Message::text("user", "hello");
        message.tool_calls.push(HistoricalToolCall {
            id: "a".into(),
            name: "f".into(),
            arguments: json!({}),
        });
        assert!(text_chat_message(&message).is_err());
    }

    #[test]
    fn mid_conversation_system_messages_render_on_qwen35_for_every_format() {
        use hellas_adaptors::openai::{
            chat_completions::OpenAiChatCompletionsAdaptor, responses::OpenAiResponsesAdaptor,
        };
        let messages = json!([
            {"role":"system","content":"First."},
            {"role":"user","content":"Question"},
            {"role":"system","content":"Second."},
            {"role":"developer","content":"Third."}
        ]);
        let chat = OpenAiChatCompletionsAdaptor;
        let responses = OpenAiResponsesAdaptor;
        let inputs = [
            chat.to_execution_request(
                &chat
                    .parse(
                        RawRequest::from_value(json!({"model":"qwen3.5", "messages":messages}))
                            .unwrap(),
                    )
                    .unwrap(),
            )
            .unwrap()
            .canonical
            .input,
            responses
                .to_execution_request(
                    &responses
                        .parse(
                            RawRequest::from_value(json!({"model":"qwen3.5", "input":messages}))
                                .unwrap(),
                        )
                        .unwrap(),
                )
                .unwrap()
                .canonical
                .input,
        ];
        for input in inputs {
            for require_tool in [false, true] {
                let messages =
                    text_chat_messages(&input, Some("Instructions."), require_tool).unwrap();
                assert_eq!(messages.len(), 2);
                let prompt = crate::tests::template(true).render(&messages).unwrap();
                assert_eq!(prompt.matches("<|im_start|>system").count(), 1);
                assert!(prompt.contains("Instructions.\n\nFirst.\n\nSecond.\n\nThird.<|im_end|>\n<|im_start|>user\nQuestion"));
                assert_eq!(
                    prompt.contains("Use one of the provided tools"),
                    require_tool
                );
            }
        }
    }

    /// Claude Code puts a system-role message after the user's turn and
    /// offers a deferred placeholder tool. Both Qwen formats render the
    /// request with one system prompt ahead of the conversation.
    #[test]
    fn claude_code_requests_render_in_both_qwen_formats() {
        let adaptor = AnthropicMessagesAdaptor;
        let raw = RawRequest::from_slice(include_bytes!(
            "../../../adaptors/tests/fixtures/agents/claude-code-messages.json"
        ))
        .unwrap();
        let canonical = adaptor
            .to_execution_request(&adaptor.parse(raw).unwrap())
            .unwrap()
            .canonical;
        let messages = text_chat_messages(&canonical.input, None, false).unwrap();
        let tools = chat_tools(&canonical).unwrap();
        for template in [crate::tests::template(false), crate::tests::template(true)] {
            let prompt = template.render_with_tools(&messages, &tools).unwrap();
            assert_eq!(prompt.matches("<|im_start|>system").count(), 1);
            assert!(prompt.starts_with("<|im_start|>system"));
            assert!(!prompt.contains("DeferredToolPlaceholder"));
        }
    }
}
