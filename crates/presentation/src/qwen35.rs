//! Text branch of Qwen3.6's chat template, thinking disabled.
//! Source: Qwen/Qwen3.6-35B-A3B, revision 995ad96eacd98c81ed38be0c5b274b04031597b0.

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use crate::ChatMessage;

const TOOL_INSTRUCTIONS: &str = "\n\nIf you choose to call a function ONLY reply in the following format with NO suffix:\n\n<tool_call>\n<function=example_function_name>\n<parameter=example_parameter_1>\nvalue_1\n</parameter>\n<parameter=example_parameter_2>\nThis is the value for the second parameter\nthat can span\nmultiple lines\n</parameter>\n</function>\n</tool_call>\n\n<IMPORTANT>\nReminder:\n- Function calls MUST follow the specified format: an inner <function=...></function> block must be nested within <tool_call></tool_call> XML tags\n- Required parameters MUST be specified\n- You may provide optional reasoning for your function call in natural language BEFORE the function call, but NOT after\n- If there is no function call available, answer the question like normal with your current knowledge and do not tell the user about function calls\n</IMPORTANT>";

pub(super) fn render(messages: &[ChatMessage], tools: &[Value]) -> Result<String> {
    let system_count = messages
        .iter()
        .take_while(|message| message.role == "system")
        .count();
    let system = messages[..system_count]
        .iter()
        .map(|message| message.content.trim())
        .filter(|content| !content.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    let last_query = messages
        .iter()
        .rposition(|message| {
            let content = message.content.trim();
            message.role == "user"
                && !(content.starts_with("<tool_response>")
                    && content.ends_with("</tool_response>"))
        })
        .context("qwen3.5 chat requires a user query")?;
    let mut prompt = String::new();
    if !tools.is_empty() {
        prompt.push_str(
            "<|im_start|>system\n# Tools\n\nYou have access to the following functions:\n\n<tools>",
        );
        for tool in tools {
            prompt.push('\n');
            prompt.push_str(&serde_json::to_string(tool)?);
        }
        prompt.push_str("\n</tools>");
        prompt.push_str(TOOL_INSTRUCTIONS);
        if !system.is_empty() {
            prompt.push_str("\n\n");
            prompt.push_str(&system);
        }
        prompt.push_str("<|im_end|>\n");
    } else if system_count > 0 {
        prompt.push_str("<|im_start|>system\n");
        prompt.push_str(&system);
        prompt.push_str("<|im_end|>\n");
    }
    for (index, message) in messages.iter().enumerate().skip(system_count) {
        let mut content = message.content.trim();
        if message.role == "tool" {
            if index == 0 || messages[index - 1].role != "tool" {
                prompt.push_str("<|im_start|>user");
            }
            prompt.push_str("\n<tool_response>\n");
            prompt.push_str(content);
            prompt.push_str("\n</tool_response>");
            if index + 1 == messages.len() || messages[index + 1].role != "tool" {
                prompt.push_str("<|im_end|>\n");
            }
            continue;
        }
        ensure!(
            matches!(message.role.as_str(), "user" | "assistant"),
            "qwen3.5 system messages must precede the conversation"
        );
        prompt.push_str("<|im_start|>");
        prompt.push_str(&message.role);
        prompt.push('\n');
        if message.role == "assistant" {
            let mut reasoning = "";
            if let Some((before, _)) = content.split_once("</think>") {
                reasoning = before.rsplit("<think>").next().unwrap_or("").trim();
                content = content
                    .rsplit("</think>")
                    .next()
                    .unwrap_or("")
                    .trim_start_matches('\n');
            }
            if index > last_query {
                prompt.push_str("<think>\n");
                prompt.push_str(reasoning);
                prompt.push_str("\n</think>\n\n");
            }
            prompt.push_str(content);
            for (call_index, call) in message.tool_calls.iter().enumerate() {
                if call_index > 0 {
                    prompt.push('\n');
                } else if !content.trim().is_empty() {
                    prompt.push_str("\n\n");
                }
                let function = call.get("function").unwrap_or(call);
                let name = function
                    .get("name")
                    .and_then(Value::as_str)
                    .context("tool call requires a function name")?;
                let arguments = function
                    .get("arguments")
                    .context("tool call requires arguments")?;
                let arguments = if let Some(json) = arguments.as_str() {
                    serde_json::from_str(json).context("tool call arguments must be JSON")?
                } else {
                    arguments.clone()
                };
                let arguments = arguments
                    .as_object()
                    .context("tool call arguments must be an object")?;
                prompt.push_str("<tool_call>\n<function=");
                prompt.push_str(name);
                prompt.push_str(">\n");
                for (key, value) in arguments {
                    prompt.push_str("<parameter=");
                    prompt.push_str(key);
                    prompt.push_str(">\n");
                    if let Some(text) = value.as_str() {
                        prompt.push_str(text);
                    } else {
                        prompt.push_str(&serde_json::to_string(value)?);
                    }
                    prompt.push_str("\n</parameter>\n");
                }
                prompt.push_str("</function>\n</tool_call>");
            }
        } else {
            prompt.push_str(content);
        }
        prompt.push_str("<|im_end|>\n");
    }
    prompt.push_str("<|im_start|>assistant\n<think>\n\n</think>\n\n");
    Ok(prompt)
}
