//! Optional conversion between user-facing text and token IDs.
//!
//! Nothing in this crate is part of the Catena causal-LM environment or
//! Hellas's execution guarantee. The protocol commits the resulting input
//! token IDs, caller-selected generation policy, exact execution environment,
//! and output token IDs. The chat format follows the caller's own model file.

pub mod chat;

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
    architecture: ModelArchitecture,
}

/// The model-provided Jinja chat template, independent of execution policy.
pub struct ChatTemplate {
    environment: minijinja::Environment<'static>,
}

/// Chat messages supplied by a host application.
#[derive(Default, serde::Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    pub tool_calls: Vec<serde_json::Value>,
}

impl ChatTemplate {
    pub fn new(source: String) -> Result<Self> {
        let mut environment = minijinja::Environment::new();
        environment
            .set_unknown_method_callback(minijinja_contrib::pycompat::unknown_method_callback);
        environment.add_function(
            "raise_exception",
            |message: String| -> Result<String, minijinja::Error> {
                Err(minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    message,
                ))
            },
        );
        environment.add_template_owned("chat", source)?;
        Ok(Self { environment })
    }

    pub fn render(&self, messages: &[ChatMessage], tools: &[serde_json::Value]) -> Result<String> {
        anyhow::ensure!(!messages.is_empty(), "chat requires at least one message");
        self.environment
            .get_template("chat")?
            .render(minijinja::context! {
                messages => messages, tools => tools, enable_thinking => false,
                add_generation_prompt => true, add_vision_id => false,
                bos_token => "<|endoftext|>", eos_token => "<|im_end|>",
            })
            .context("failed to render GGUF chat template")
    }
}

impl TextPresentation {
    /// The tokenizer embedded in an application-selected GGUF model, and the
    /// chat template embedded alongside it.
    ///
    /// This performs local file I/O only. Neither Catena nor an RPC peer
    /// selects presentation for the caller.
    pub fn from_gguf(path: &Path) -> Result<Self> {
        let tokenizer = QwenTokenizer::from_gguf(path)?
            .with_context(|| format!("{} has no embedded tokenizer", path.display()))?;
        let chat_template = ChatTemplate::new(
            tokenizer
                .chat_template()
                .context("GGUF has no chat template")?
                .to_owned(),
        )?;
        Ok(Self {
            tokenizer,
            chat_template,
            architecture: read_gguf_model_config(path)?.architecture,
        })
    }

    pub fn encode_chat(
        &self,
        messages: &[ChatMessage],
        tools: &[serde_json::Value],
    ) -> Result<Vec<u32>> {
        self.encode(&self.chat_template.render(messages, tools)?)
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

    pub(crate) fn template(qwen35: bool) -> ChatTemplate {
        ChatTemplate::new(
            if qwen35 {
                include_str!("../tests/fixtures/qwen35_chat.jinja")
            } else {
                include_str!("../tests/fixtures/qwen3_chat.jinja")
            }
            .into(),
        )
        .unwrap()
    }

    const WORDS: &str = r#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"world":1,"<unk>":2},"unk_token":"<unk>"}}"#;

    fn presentation() -> Arc<TextPresentation> {
        Arc::new(TextPresentation {
            tokenizer: tokenizer(WORDS),
            chat_template: template(false),
            architecture: ModelArchitecture::Qwen3Dense,
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
            template(false).render(&messages, &[]).unwrap(),
            concat!(
                "<|im_start|>system\nBe concise.<|im_end|>\n",
                "<|im_start|>user\nFirst question<|im_end|>\n",
                "<|im_start|>assistant\nFirst answer<|im_end|>\n",
                "<|im_start|>user\nNext question<|im_end|>\n",
                "<|im_start|>assistant\n<think>\n\n</think>\n\n",
            )
        );
    }

    #[test]
    fn chat_template_comes_from_the_gguf() {
        let model = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../client/src/model/package/mini-qwen3.gguf");
        let presentation = TextPresentation::from_gguf(&model).unwrap();
        let source = presentation.tokenizer.chat_template().unwrap();
        assert_eq!(source, include_str!("../tests/fixtures/qwen3_chat.jinja"));
        let messages = [ChatMessage {
            role: "user".into(),
            content: "hi".into(),
            ..Default::default()
        }];
        assert_eq!(
            presentation.chat_template.render(&messages, &[]).unwrap(),
            template(false).render(&messages, &[]).unwrap()
        );
        // Change only the embedded template, keeping architecture and weights.
        let mut bytes = std::fs::read(&model).unwrap();
        let old = b"<|im_start|>assistant";
        let offset = bytes
            .windows(old.len())
            .position(|bytes| bytes == old)
            .unwrap();
        bytes[offset..offset + old.len()].copy_from_slice(b"<|im_start|>different");
        let custom = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(custom.path(), bytes).unwrap();
        let custom = TextPresentation::from_gguf(custom.path()).unwrap();
        assert_eq!(custom.architecture, presentation.architecture);
        assert!(
            custom
                .chat_template
                .render(&messages, &[])
                .unwrap()
                .ends_with("<|im_start|>different\n<think>\n\n</think>\n\n")
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
            chat_template: template(false),
            architecture: ModelArchitecture::Qwen3Dense,
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
