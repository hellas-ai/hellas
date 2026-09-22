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
                    })?,
                });
            }
        }
    }
    Ok(messages)
}

fn text_chat_message(message: &Message) -> anyhow::Result<ChatMessage> {
    anyhow::ensure!(
        message.name.is_none(),
        "text chat does not support named messages"
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
        ..Default::default()
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
        use crate::ChatTemplate;
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
        let messages = text_chat_messages(&request.canonical.input, None).unwrap();
        assert_eq!(
            ChatTemplate::Qwen3.render(&messages).unwrap(),
            concat!(
                "<|im_start|>system\nBe concise.<|im_end|>\n",
                "<|im_start|>user\nSay hello<|im_end|>\n",
                "<|im_start|>assistant\n<think>\n\n</think>\n\n",
            )
        );
        assert!(raw_text_chat_message(&json!({"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://example.com/image.png"}}]})).is_err());
        let malformed = raw_text_chat_message(
            &json!({"role": "assistant", "content": "", "tool_calls": [{"id": "call"}]}),
        )
        .unwrap();
        assert!(ChatTemplate::Qwen3.render(&[malformed]).is_err());
    }
}
