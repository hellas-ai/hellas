//! Optional conversion between user-facing text and token IDs.
//!
//! Nothing in this crate is part of the Catena causal-LM environment or
//! Hellas's execution guarantee. The protocol commits the resulting input
//! token IDs, caller-selected generation policy, exact execution environment,
//! and output token IDs. The chat format follows the caller's own model file.

pub mod chat;
mod qwen35;

use std::path::Path;

use anyhow::{Context, Result};
use catena_models::{
    checkpoint::read_gguf_model_config,
    spec::ModelArchitecture,
    tokenizer::{QwenDecodeStream, QwenTokenizer},
};

pub struct TextPresentation {
    tokenizer: QwenTokenizer,
    chat_template: ChatTemplate,
}

/// A local chat format, independent of execution policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChatTemplate {
    /// Qwen3 text chat, with thinking disabled for new generations.
    Qwen3,
    /// Qwen3.5/3.6 text chat and XML function calls, with thinking disabled.
    Qwen35,
}

impl ChatTemplate {
    /// The chat format a model of `architecture` was trained on.
    pub fn of(architecture: ModelArchitecture) -> Self {
        match architecture {
            ModelArchitecture::Qwen3Dense => Self::Qwen3,
            ModelArchitecture::Qwen35Dense | ModelArchitecture::Qwen35Moe => Self::Qwen35,
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
    /// The tokenizer embedded in an application-selected GGUF model, and the
    /// chat format of its architecture.
    ///
    /// This performs local file I/O only. Neither Catena nor an RPC peer
    /// selects presentation for the caller.
    pub fn from_gguf(path: &Path) -> Result<Self> {
        let tokenizer = QwenTokenizer::from_gguf(path)?
            .with_context(|| format!("{} has no embedded tokenizer", path.display()))?;
        Ok(Self {
            tokenizer,
            chat_template: ChatTemplate::of(read_gguf_model_config(path)?.architecture),
        })
    }

    pub fn encode_chat(&self, messages: &[ChatMessage]) -> Result<Vec<u32>> {
        self.encode_chat_with_tools(messages, &[])
    }

    pub fn encode_chat_with_tools(
        &self,
        messages: &[ChatMessage],
        tools: &[serde_json::Value],
    ) -> Result<Vec<u32>> {
        self.encode(&self.chat_template.render_with_tools(messages, tools)?)
    }

    /// Plain text tokenization, independent of the selected chat template.
    pub fn encode(&self, text: &str) -> Result<Vec<u32>> {
        self.tokenizer
            .encode(text)?
            .into_iter()
            .map(|id| u32::try_from(id).context("token ID exceeds u32"))
            .collect()
    }

    pub fn decode(&self, tokens: &[u32]) -> Result<String> {
        let tokens = tokens.iter().copied().map(u64::from).collect::<Vec<_>>();
        self.tokenizer.decode(&tokens, true)
    }
}

/// Stateful streamed-token decoder for presentation UIs.
pub struct TextOutputDecoder<'a> {
    presentation: &'a TextPresentation,
    stream: QwenDecodeStream<'a>,
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

    pub(crate) fn tokenizer(json: &str) -> QwenTokenizer {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), json).unwrap();
        QwenTokenizer::open(file.path()).unwrap()
    }

    const WORDS: &str = r#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"world":1,"<unk>":2},"unk_token":"<unk>"}}"#;

    fn presentation() -> Arc<TextPresentation> {
        Arc::new(TextPresentation {
            tokenizer: tokenizer(WORDS),
            chat_template: ChatTemplate::Qwen3,
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
    }

    /// A Qwen3.5 model rendered with the Qwen3 template writes tool calls its
    /// parser cannot decode, so the format follows the GGUF's architecture.
    #[test]
    fn chat_template_follows_the_gguf_architecture() {
        let model = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../client/src/model/package/mini-qwen3.gguf");
        assert_eq!(
            TextPresentation::from_gguf(&model).unwrap().chat_template,
            ChatTemplate::Qwen3
        );
        assert_eq!(
            ChatTemplate::of(ModelArchitecture::Qwen35Dense),
            ChatTemplate::Qwen35
        );
        assert_eq!(
            ChatTemplate::of(ModelArchitecture::Qwen35Moe),
            ChatTemplate::Qwen35
        );
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
        let presentation = TextPresentation {
            tokenizer: tokenizer(
                r#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":null,"post_processor":null,"decoder":{"type":"ByteLevel","add_prefix_space":false,"trim_offsets":true,"use_regex":true},"model":{"type":"WordLevel","vocab":{"Ã":0,"©":1,"<unk>":2},"unk_token":"<unk>"}}"#,
            ),
            chat_template: ChatTemplate::Qwen3,
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
