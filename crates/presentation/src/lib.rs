//! Optional conversion between user-facing text and token IDs.
//!
//! Nothing in this crate is part of the Catena causal-LM environment or
//! Hellas's execution guarantee. The protocol commits the resulting input
//! token IDs, caller-selected generation policy, exact execution environment,
//! and output token IDs. A caller selects this local presentation
//! configuration independently.

pub mod chat;
mod qwen35;

use std::{path::Path, str::FromStr};

use anyhow::{Context, Result};
use tokenizers::Tokenizer;
use tokenizers::tokenizer::{
    DecodeStream, DecoderWrapper, ModelWrapper, NormalizerWrapper, PostProcessorWrapper,
    PreTokenizerWrapper,
};

pub struct TextPresentation {
    tokenizer: Tokenizer,
    chat_template: Option<ChatTemplate>,
}

/// An explicitly selected local chat format, independent of execution policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChatTemplate {
    /// Qwen3 text chat, with thinking disabled for new generations.
    Qwen3,
    /// Qwen3.5/3.6 text chat and XML function calls, with thinking disabled.
    Qwen35,
}

impl FromStr for ChatTemplate {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "qwen3" => Ok(Self::Qwen3),
            "qwen3.5" | "qwen3.6" => Ok(Self::Qwen35),
            _ => anyhow::bail!("unsupported chat template {value:?}; expected qwen3 or qwen3.5"),
        }
    }
}

/// Chat messages supplied by a host application.
#[derive(Default)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    pub tool_calls: Vec<serde_json::Value>,
}

impl ChatTemplate {
    pub fn render(self, messages: &[ChatMessage]) -> Result<String> {
        self.render_with_tools(messages, &[])
    }

    pub fn render_with_tools(
        self,
        messages: &[ChatMessage],
        tools: &[serde_json::Value],
    ) -> Result<String> {
        anyhow::ensure!(!messages.is_empty(), "chat requires at least one message");
        if self == Self::Qwen35 {
            return qwen35::render(messages, tools);
        }
        // Qwen/Qwen3-30B-A3B tokenizer_config.json at
        // ad44e777bcd18fa416d9da3bd8f70d33ebb85d39: text-only branch,
        // add_generation_prompt=true, enable_thinking=false.
        let last_query = messages
            .iter()
            .rposition(|message| {
                message.role == "user"
                    && !(message.content.starts_with("<tool_response>")
                        && message.content.ends_with("</tool_response>"))
            })
            .unwrap_or(messages.len() - 1);
        let mut prompt = String::new();
        if !tools.is_empty() {
            prompt.push_str("<|im_start|>system\n");
            if messages[0].role == "system" {
                prompt.push_str(&messages[0].content);
                prompt.push_str("\n\n");
            }
            prompt.push_str("# Tools\n\nYou may call one or more functions to assist with the user query.\n\nYou are provided with function signatures within <tools></tools> XML tags:\n<tools>");
            for tool in tools {
                prompt.push('\n');
                prompt.push_str(&serde_json::to_string(tool)?);
            }
            prompt.push_str("\n</tools>\n\nFor each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:\n<tool_call>\n{\"name\": <function-name>, \"arguments\": <args-json-object>}\n</tool_call><|im_end|>\n");
        }
        for (index, message) in messages.iter().enumerate() {
            if index == 0 && message.role == "system" && !tools.is_empty() {
                continue;
            }
            if message.role == "tool" {
                if index == 0 || messages[index - 1].role != "tool" {
                    prompt.push_str("<|im_start|>user");
                }
                prompt.push_str("\n<tool_response>\n");
                prompt.push_str(&message.content);
                prompt.push_str("\n</tool_response>");
                if index + 1 == messages.len() || messages[index + 1].role != "tool" {
                    prompt.push_str("<|im_end|>\n");
                }
                continue;
            }
            anyhow::ensure!(
                matches!(message.role.as_str(), "system" | "user" | "assistant"),
                "qwen3 text chat does not support role {:?}",
                message.role
            );
            prompt.push_str("<|im_start|>");
            prompt.push_str(&message.role);
            prompt.push('\n');
            if message.role == "assistant" {
                let mut content = message.content.as_str();
                let mut reasoning = "";
                if let Some((before, _)) = content.split_once("</think>") {
                    reasoning = before
                        .trim_end_matches('\n')
                        .rsplit("<think>")
                        .next()
                        .unwrap_or("")
                        .trim_start_matches('\n');
                    content = content
                        .rsplit("</think>")
                        .next()
                        .unwrap_or("")
                        .trim_start_matches('\n');
                }
                if index > last_query && (index + 1 == messages.len() || !reasoning.is_empty()) {
                    prompt.push_str("<think>\n");
                    prompt.push_str(reasoning.trim_matches('\n'));
                    prompt.push_str("\n</think>\n\n");
                    content = content.trim_start_matches('\n');
                }
                prompt.push_str(content);
                for (call_index, call) in message.tool_calls.iter().enumerate() {
                    if !content.is_empty() || call_index > 0 {
                        prompt.push('\n');
                    }
                    let function = call.get("function").unwrap_or(call);
                    let name = function
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .context("tool call requires a function name")?;
                    let arguments = function
                        .get("arguments")
                        .context("tool call requires arguments")?;
                    let arguments = if let Some(json) = arguments.as_str() {
                        serde_json::from_str(json).context("tool call arguments must be JSON")?
                    } else {
                        arguments.clone()
                    };
                    prompt.push_str("<tool_call>\n");
                    prompt.push_str(&serde_json::to_string(
                        &serde_json::json!({"name": name, "arguments": arguments}),
                    )?);
                    prompt.push_str("\n</tool_call>");
                }
            } else {
                prompt.push_str(&message.content);
            }
            prompt.push_str("<|im_end|>\n");
        }
        prompt.push_str("<|im_start|>assistant\n<think>\n\n</think>\n\n");
        Ok(prompt)
    }
}

impl TextPresentation {
    /// Load an application-selected tokenizer.
    ///
    /// This performs local file I/O only. It deliberately has no environment
    /// directory, URL, or model-name argument: neither Catena nor an RPC peer
    /// selects presentation for the caller.
    pub fn load(tokenizer_path: &Path) -> Result<Self> {
        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("failed to load tokenizer {}", tokenizer_path.display()))?;
        Ok(Self {
            tokenizer,
            chat_template: None,
        })
    }

    pub fn with_chat_template(mut self, template: Option<ChatTemplate>) -> Self {
        self.chat_template = template;
        self
    }

    pub fn encode_chat(&self, messages: &[ChatMessage]) -> Result<Vec<u32>> {
        self.encode_chat_with_tools(messages, &[])
    }

    pub fn encode_chat_with_tools(
        &self,
        messages: &[ChatMessage],
        tools: &[serde_json::Value],
    ) -> Result<Vec<u32>> {
        let template = self.chat_template.context(
            "chat requires an explicitly configured --chat-template (qwen3 or qwen3.5/qwen3.6)",
        )?;
        self.encode(&template.render_with_tools(messages, tools)?)
    }

    /// Plain text tokenization, independent of the selected chat template.
    pub fn encode(&self, text: &str) -> Result<Vec<u32>> {
        Ok(self
            .tokenizer
            .encode(text, true)
            .map_err(anyhow::Error::msg)
            .context("failed to tokenize prompt")?
            .get_ids()
            .to_vec())
    }

    pub fn decode(&self, tokens: &[u32]) -> Result<String> {
        self.tokenizer
            .decode(tokens, true)
            .map_err(anyhow::Error::msg)
            .context("failed to decode tokens")
    }
}

/// Stateful streamed-token decoder for presentation UIs.
pub struct TextOutputDecoder<'a> {
    presentation: &'a TextPresentation,
    stream: DecodeStream<
        'a,
        ModelWrapper,
        NormalizerWrapper,
        PreTokenizerWrapper,
        PostProcessorWrapper,
        DecoderWrapper,
    >,
    token_ids: Vec<u32>,
    decoded: String,
}

impl<'a> TextOutputDecoder<'a> {
    pub fn new(presentation: &'a TextPresentation) -> Self {
        Self {
            presentation,
            stream: presentation.tokenizer.decode_stream(true),
            token_ids: Vec::new(),
            decoded: String::new(),
        }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<String> {
        let tokens = hellas_rpc::decode_token_ids(bytes)?;
        if tokens.is_empty() {
            return Ok(String::new());
        }
        self.token_ids.extend(&tokens);
        let mut delta = String::new();
        for token in tokens {
            if let Some(text) = self
                .stream
                .step(token)
                .map_err(anyhow::Error::msg)
                .context("failed to decode streamed token")?
            {
                delta.push_str(&text);
            }
        }
        self.decoded.push_str(&delta);
        Ok(delta)
    }

    /// Flush a terminal incomplete byte sequence using the tokenizer's full
    /// decode. During generation it must stay buffered: a following token may
    /// complete its UTF-8 character instead of leaving a replacement character.
    pub fn finish(self) -> Result<String> {
        self.presentation
            .decode(&self.token_ids)?
            .strip_prefix(&self.decoded)
            .context("final tokenizer decode revised already-emitted text")
            .map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn presentation() -> Arc<TextPresentation> {
        let tokenizer = Tokenizer::from_bytes(
            br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"world":1,"<unk>":2},"unk_token":"<unk>"}}"#,
        )
        .unwrap();
        Arc::new(TextPresentation {
            tokenizer,
            chat_template: None,
        })
    }

    #[test]
    fn plain_text_is_only_local_presentation() {
        let presentation = presentation();
        assert_eq!(presentation.encode("hello world").unwrap(), [0, 1]);
    }

    #[test]
    fn qwen3_text_chat_matches_non_thinking_template() {
        let messages = [
            ChatMessage {
                role: "system".into(),
                content: "Be concise.".into(),
                ..Default::default()
            },
            ChatMessage {
                role: "user".into(),
                content: "First question".into(),
                ..Default::default()
            },
            ChatMessage {
                role: "assistant".into(),
                content: "<think>\nold reasoning\n</think>\n\nFirst answer".into(),
                ..Default::default()
            },
            ChatMessage {
                role: "user".into(),
                content: "Next question".into(),
                ..Default::default()
            },
        ];
        assert_eq!(
            ChatTemplate::Qwen3.render(&messages).unwrap(),
            concat!(
                "<|im_start|>system\nBe concise.<|im_end|>\n",
                "<|im_start|>user\nFirst question<|im_end|>\n",
                "<|im_start|>assistant\nFirst answer<|im_end|>\n",
                "<|im_start|>user\nNext question<|im_end|>\n",
                "<|im_start|>assistant\n<think>\n\n</think>\n\n",
            )
        );
        assert!(presentation().encode_chat(&messages).is_err());
        let selected = TextPresentation {
            tokenizer: presentation().tokenizer.clone(),
            chat_template: Some(ChatTemplate::Qwen3),
        };
        assert_eq!(selected.encode("hello world").unwrap(), [0, 1]);
    }

    #[test]
    fn streamed_decode_emits_only_new_text() {
        let presentation = presentation();
        let mut decoder = TextOutputDecoder::new(&presentation);
        assert_eq!(
            decoder
                .push_bytes(&hellas_rpc::encode_token_ids(&[0]))
                .unwrap(),
            "hello"
        );
        assert_eq!(
            decoder
                .push_bytes(&hellas_rpc::encode_token_ids(&[1]))
                .unwrap(),
            " world"
        );
        assert_eq!(decoder.finish().unwrap(), "");
    }

    #[test]
    fn streamed_decode_waits_for_complete_utf8_and_flushes_terminal_bytes() {
        let tokenizer = Tokenizer::from_bytes(
            r#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":null,"post_processor":null,"decoder":{"type":"ByteLevel","add_prefix_space":false,"trim_offsets":true,"use_regex":true},"model":{"type":"WordLevel","vocab":{"Ã":0,"©":1,"<unk>":2},"unk_token":"<unk>"}}"#,
        )
        .unwrap();
        let presentation = TextPresentation {
            tokenizer,
            chat_template: None,
        };
        let first = hellas_rpc::encode_token_ids(&[0]);
        let second = hellas_rpc::encode_token_ids(&[1]);
        let mut decoder = TextOutputDecoder::new(&presentation);
        assert_eq!(decoder.push_bytes(&first).unwrap(), "");
        assert_eq!(decoder.push_bytes(&second).unwrap(), "é");
        assert_eq!(decoder.finish().unwrap(), "");

        let mut decoder = TextOutputDecoder::new(&presentation);
        assert_eq!(decoder.push_bytes(&first).unwrap(), "");
        assert_eq!(decoder.finish().unwrap(), "�");
    }
}
