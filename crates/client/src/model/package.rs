//! Model families render the same opaque program-and-bytes Compute contract.
use super::{qwen3::Qwen3, whisper::Whisper};
use anyhow::{Result, bail, ensure};
use hellas_channel::content::EphemeralContent;
use hellas_rpc::protocol::invocation::{
    Artifact,
    compute::{Environment, Plan},
    output::InvocationOutput,
};
use std::path::Path;

enum Family {
    Qwen3(Qwen3),
    Whisper(Whisper),
}

pub struct ModelPackage {
    family: Family,
}

pub enum ModelRequest<'a> {
    Text {
        prompt_ids: &'a [u64],
        max_new: u64,
        stops: &'a [u64],
    },
    Transcription {
        samples: &'a [f32],
        language: Option<&'a str>,
        max_new_tokens: usize,
    },
}

/// One request, ready for `Job::compute` on any admitting provider.
pub struct ComputeJob {
    pub environment: Environment,
    pub plan: Plan,
    pub inputs: Vec<Artifact>,
    /// Always includes the environment and rendered program. Weight assets are
    /// ordinary content-addressed objects held by the provider.
    pub content: EphemeralContent,
}

#[derive(Debug)]
pub enum ModelResponse {
    Tokens(Vec<u32>),
    Transcription(super::whisper::Transcription),
}

impl ModelPackage {
    /// A Qwen3 GGUF, or a Whisper directory created by `convert_whisper`.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            family: if path.is_dir() {
                Family::Whisper(Whisper::open(path)?)
            } else {
                Family::Qwen3(Qwen3::open(path)?)
            },
        })
    }
    pub fn environment(&self) -> &Environment {
        match &self.family {
            Family::Qwen3(model) => model.environment(),
            Family::Whisper(model) => model.environment(),
        }
    }
    /// Maximum generated tokens when this is a transcription model.
    pub fn transcription_capacity(&self) -> Option<usize> {
        match &self.family {
            Family::Whisper(model) => Some(model.transcription_capacity()),
            Family::Qwen3(_) => None,
        }
    }
    pub fn render_job(&self, request: &ModelRequest<'_>) -> Result<ComputeJob> {
        match (&self.family, request) {
            (
                Family::Qwen3(model),
                ModelRequest::Text {
                    prompt_ids,
                    max_new,
                    stops,
                },
            ) => model.render_job(prompt_ids, *max_new, stops),
            (
                Family::Whisper(model),
                ModelRequest::Transcription {
                    samples,
                    language,
                    max_new_tokens,
                },
            ) => model.render_job(samples, *language, *max_new_tokens),
            _ => bail!("request does not match model family"),
        }
    }
    pub fn decode(&self, output: &InvocationOutput) -> Result<ModelResponse> {
        ensure!(
            output.is_success(),
            "model job failed: {:?}",
            output.outcome
        );
        match &self.family {
            Family::Whisper(model) => Ok(ModelResponse::Transcription(model.decode(output)?)),
            Family::Qwen3(_) => {
                let artifact = output
                    .artifacts
                    .iter()
                    .find(|a| a.name == "emitted")
                    .ok_or_else(|| anyhow::anyhow!("missing emitted tokens"))?;
                ensure!(
                    artifact.format == "catena.u64le.v1"
                        && artifact.bytes.as_bytes().len().is_multiple_of(8),
                    "invalid token artifact"
                );
                let tokens = artifact
                    .bytes
                    .as_bytes()
                    .chunks_exact(8)
                    .map(|b| u32::try_from(u64::from_le_bytes(b.try_into().unwrap())))
                    .collect::<Result<_, _>>()?;
                Ok(ModelResponse::Tokens(tokens))
            }
        }
    }
}

#[cfg(test)]
mod tests;
