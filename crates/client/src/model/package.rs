//! Model families render the same opaque program-and-bytes Compute contract.
use super::{
    flux::{Flux, Image, ImageRequest},
    qwen3::Qwen3,
    whisper::Whisper,
};
use anyhow::{Result, bail, ensure};
use hellas_rpc::protocol::invocation::{
    Artifact,
    compute::{Environment, Plan},
    output::InvocationOutput,
};
use hellas_store::content::{LocalStore, Scope};
use std::{path::Path, sync::Arc};

enum Family {
    Qwen3(Arc<Qwen3>),
    Whisper(Arc<Whisper>),
    Flux(Arc<Flux>),
}

pub struct ModelPackage {
    family: Family,
}

pub enum ModelRequest<'a> {
    Image(ImageRequest<'a>),
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
    pub content: (LocalStore, Scope),
}

#[derive(Debug)]
pub enum ModelResponse {
    Tokens(Vec<u32>),
    Transcription(super::whisper::Transcription),
    Image(Image),
}

impl ModelPackage {
    /// A Qwen GGUF, or a converted Whisper or Flux package directory.
    pub async fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            family: if path.join("model_index.json").is_file() {
                Family::Flux(Arc::new({
                    let path = path.to_owned();
                    tokio::task::spawn_blocking(move || Flux::open(&path)).await??
                }))
            } else if path.is_dir() {
                Family::Whisper(Arc::new(Whisper::open(path).await?))
            } else {
                Family::Qwen3(Arc::new(Qwen3::open(path).await?))
            },
        })
    }
    pub fn is_image(&self) -> bool {
        matches!(self.family, Family::Flux(_))
    }
    /// Maximum generated tokens when this is a transcription model.
    pub fn transcription_capacity(&self) -> Option<usize> {
        match &self.family {
            Family::Whisper(model) => Some(model.transcription_capacity()),
            Family::Qwen3(_) | Family::Flux(_) => None,
        }
    }
    pub async fn render_job(&self, request: &ModelRequest<'_>) -> Result<ComputeJob> {
        match (&self.family, request) {
            (Family::Flux(model), ModelRequest::Image(request)) => {
                let model = model.clone();
                let prompt = request.prompt.to_owned();
                let (seed, width, height, steps) =
                    (request.seed, request.width, request.height, request.steps);
                let (job, source) = tokio::task::spawn_blocking(move || {
                    model.render_job(&ImageRequest {
                        prompt: &prompt,
                        seed,
                        width,
                        height,
                        steps,
                    })
                })
                .await??;
                hellas_channel::content::upload_object(&job.content.0, source.as_bytes()).await?;
                hellas_channel::content::upload_object(
                    &job.content.0,
                    &job.environment.canonical_bytes()?,
                )
                .await?;
                Ok(job)
            }
            (
                Family::Qwen3(model),
                ModelRequest::Text {
                    prompt_ids,
                    max_new,
                    stops,
                },
            ) => {
                let model = model.clone();
                let (prompt, max_new, stops) = (prompt_ids.to_vec(), *max_new, stops.to_vec());
                tokio::task::spawn_blocking(move || model.render_job(&prompt, max_new, &stops))
                    .await?
            }
            (
                Family::Whisper(model),
                ModelRequest::Transcription {
                    samples,
                    language,
                    max_new_tokens,
                },
            ) => {
                let model = model.clone();
                let (samples, language, max_new_tokens) = (
                    samples.to_vec(),
                    language.map(str::to_owned),
                    *max_new_tokens,
                );
                tokio::task::spawn_blocking(move || {
                    model.render_job(&samples, language.as_deref(), max_new_tokens)
                })
                .await?
            }
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
            Family::Flux(_) => Ok(ModelResponse::Image(Image::decode(output)?)),
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
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .copied()
                    .map(u64::from_le_bytes)
                    .map(u32::try_from)
                    .collect::<Result<_, _>>()?;
                Ok(ModelResponse::Tokens(tokens))
            }
        }
    }
}

#[cfg(test)]
mod tests;
