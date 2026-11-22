//! Model families render the same opaque program-and-bytes Compute contract.
use super::{
    descriptor,
    flux::{Flux, Image, ImageRequest},
    native,
    qwen3::Qwen3,
    speech::{Audio, Speech},
    whisper::Whisper,
};
use anyhow::{Context, Result, bail, ensure};
use hellas_rpc::protocol::invocation::{
    Artifact,
    compute::{Environment, Plan},
    output::InvocationOutput,
};
use hellas_store::content::{DiskStore, LocalStore, Scope};
use std::{path::Path, sync::Arc};

enum Family {
    Qwen3(Arc<Qwen3>),
    Whisper(Arc<Whisper>),
    Flux(Arc<Flux>),
    Speech(Arc<Speech>),
}

pub struct ModelPackage {
    family: Family,
    evaluator: String,
}

/// What a model path serves, from its layout alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    /// A local or pinned Hub text GGUF.
    Text,
    /// A local or pinned Hub d1 GGUF.
    Decision,
    /// A converted Whisper package or descriptor directory.
    Transcription,
    /// A converted Flux package directory.
    Image,
    /// A converted MMS English package or descriptor, or a converted Phonon package.
    Speech,
}

impl ModelKind {
    pub fn of(path: &Path) -> Result<Self> {
        Ok(Self::named(path)?.0)
    }
    /// Gateway and request name, taken from the selected model file.
    pub fn named(path: &Path) -> Result<(Self, String)> {
        descriptor::Source::open(path)?.named()
    }
}

pub(super) fn model_name(path: &Path) -> Result<&str> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .context("model needs a UTF-8 name")
}

#[derive(Clone, Copy)]
pub enum ModelRequest<'a> {
    Speech {
        text: &'a str,
        voice: &'a str,
        speed: f32,
    },
    Image(ImageRequest<'a>),
    Text {
        prompt_ids: &'a [u64],
        max_new: u64,
        stops: &'a [u64],
    },
    /// One complete prompt per question; see [`super::decision`].
    Decision {
        prompts: &'a [Vec<u64>],
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
    /// Final-position vocabulary logits of each decision prompt.
    Logits(Vec<Vec<f32>>),
    Transcription(super::whisper::Transcription),
    Image(Image),
    Speech(Audio),
}

impl ModelPackage {
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn flux_fixture(model: Flux, dialect: super::GpuDialect) -> Self {
        Self {
            family: Family::Flux(Arc::new(model)),
            evaluator: super::evaluator(dialect),
        }
    }

    /// GGUF metadata used by this package's tokenizer and template.
    pub fn gguf_path(&self) -> Result<&Path> {
        match &self.family {
            Family::Qwen3(model) => Ok(model.path.as_ref().as_ref()),
            _ => bail!("model package is not GGUF"),
        }
    }

    pub fn gguf_name(&self) -> Result<&str> {
        match &self.family {
            Family::Qwen3(model) => model_name(model.path.source()),
            _ => bail!("model package is not GGUF"),
        }
    }
    pub fn is_descriptor(path: &Path) -> Result<bool> {
        Ok(super::hf_uri(path).is_none() && descriptor::classify(path)?.is_descriptor())
    }
    /// A local executing backend must have the full model package.
    pub fn require_local_weights(path: &Path) -> Result<()> {
        ensure!(
            super::hf_uri(path).is_some() || !descriptor::classify(path)?.is_descriptor(),
            "local execution requires the full model weights, not a descriptor"
        );
        Ok(())
    }

    /// Create a new metadata-only package directory from a converted Whisper or MMS package.
    pub async fn describe(path: &Path, output: &Path) -> Result<hellas_rpc::ContentRef> {
        let (path, output) = (path.to_owned(), output.to_owned());
        tokio::task::spawn_blocking(move || descriptor::describe(&path, &output)).await?
    }

    /// A Qwen GGUF, converted Whisper, MMS or Flux package, or model descriptor,
    /// rendering programs with the renderer registered under `evaluator`.
    pub async fn open(path: &Path, evaluator: &str) -> Result<Self> {
        let dialect = super::renderer(evaluator)?;
        let source = Self::resolve(path, None).await?;
        Self::open_resolved(&source, evaluator, dialect).await
    }

    /// Open each distinct renderer once, sharing one resolved weight identity.
    /// A supplied content store reuses its inspected identity across calls.
    pub async fn open_many(
        path: &Path,
        evaluators: impl IntoIterator<Item = String>,
        store: Option<&DiskStore>,
    ) -> Result<std::collections::BTreeMap<String, Arc<Self>>> {
        let evaluators: std::collections::BTreeSet<_> = evaluators.into_iter().collect();
        let evaluators = evaluators
            .into_iter()
            .map(|evaluator| {
                let dialect = super::renderer(&evaluator)?;
                Ok((evaluator, dialect))
            })
            .collect::<Result<Vec<_>>>()?;
        if evaluators.is_empty() {
            return Ok(Default::default());
        }
        let source = Self::resolve(path, store).await?;
        let mut packages = std::collections::BTreeMap::new();
        for (evaluator, dialect) in evaluators {
            let package = Self::open_resolved(&source, &evaluator, dialect).await?;
            packages.insert(evaluator, Arc::new(package));
        }
        Ok(packages)
    }

    async fn resolve(path: &Path, store: Option<&DiskStore>) -> Result<descriptor::Resolved> {
        let (path, store) = (path.to_owned(), store.cloned());
        tokio::task::spawn_blocking(move || {
            descriptor::Source::open(&path)?.resolve(store.as_ref())
        })
        .await?
    }

    async fn open_resolved(
        source: &descriptor::Resolved,
        evaluator: &str,
        dialect: super::GpuDialect,
    ) -> Result<Self> {
        Ok(Self {
            evaluator: evaluator.into(),
            family: match source {
                descriptor::Resolved::Native(native::Kind::OmniVoice, source) => Family::Speech(
                    Arc::new(Speech::open_omni(source.as_ref().clone(), dialect).await?),
                ),
                descriptor::Resolved::Speech { path, weights } => {
                    Family::Speech(Arc::new(Speech::open(path, dialect, *weights).await?))
                }
                descriptor::Resolved::Phonon(path) => {
                    Family::Speech(Arc::new(Speech::open_phonon(path, dialect).await?))
                }
                descriptor::Resolved::Native(native::Kind::Flux, path) => Family::Flux(Arc::new({
                    let path = path.clone();
                    tokio::task::spawn_blocking(move || Flux::open(path, dialect)).await??
                })),
                descriptor::Resolved::Whisper { path, weights } => {
                    Family::Whisper(Arc::new(Whisper::open(path, dialect, *weights).await?))
                }
                descriptor::Resolved::Gguf {
                    path,
                    header,
                    weights,
                } => Family::Qwen3(Arc::new(
                    Qwen3::open(path.clone(), dialect, *weights, header.clone()).await?,
                )),
            },
        })
    }
    pub(super) fn decisions(&self) -> Result<&catena_models::systemone::Decisions> {
        match &self.family {
            Family::Qwen3(model) => model.decisions(),
            _ => bail!("model does not answer decisions"),
        }
    }
    /// The exact programs this package can render for its evaluator.
    pub fn programs(&self) -> Result<Vec<hellas_rpc::protocol::invocation::compute::ProgramId>> {
        let environment = match &self.family {
            Family::Whisper(model) => model.environment(),
            Family::Speech(model) => model.environment(),
            Family::Qwen3(model) => model.environment(),
            Family::Flux(model) => return model.programs(&self.evaluator),
        };
        Ok(vec![hellas_rpc::protocol::invocation::compute::ProgramId {
            evaluator: self.evaluator.clone(),
            manifest: environment.manifest(&self.evaluator)?.content_id(),
        }])
    }

    /// Admit the exact programs rendered by this model and its known preparation entries.
    pub fn compute_admissions(&self) -> Result<Vec<hellas_rpc::protocol::invocation::Admission>> {
        use hellas_rpc::protocol::invocation::{Admission, ComputePrograms};
        let programs = self.programs()?;
        let mut admission = Admission::compute_only(&programs)?;
        let entries: &[&str] = match &self.family {
            Family::Flux(_) => &["flux.setup-text", "flux.setup-denoise", "flux.setup-vae"],
            Family::Speech(model) => model.setup_entries(),
            _ => &[],
        };
        if !entries.is_empty()
            && let Admission::Compute {
                programs:
                    ComputePrograms::Only {
                        pure_setup_entries, ..
                    },
                ..
            } = &mut admission
        {
            for p in programs {
                pure_setup_entries.insert(
                    p.manifest.to_string(),
                    entries.iter().map(|e| (*e).to_owned()).collect(),
                );
            }
        }
        Ok(vec![admission])
    }
    pub fn kind(&self) -> ModelKind {
        match &self.family {
            Family::Whisper(_) => ModelKind::Transcription,
            Family::Speech(_) => ModelKind::Speech,
            Family::Qwen3(model) if model.is_decision() => ModelKind::Decision,
            Family::Qwen3(_) => ModelKind::Text,
            Family::Flux(_) => ModelKind::Image,
        }
    }
    /// Maximum generated tokens when this is a transcription model.
    pub fn transcription_capacity(&self) -> Option<usize> {
        match &self.family {
            Family::Whisper(model) => Some(model.transcription_capacity()),
            Family::Qwen3(_) | Family::Flux(_) | Family::Speech(_) => None,
        }
    }
    pub async fn render_job(&self, request: &ModelRequest<'_>) -> Result<ComputeJob> {
        match (&self.family, request) {
            (Family::Speech(model), ModelRequest::Speech { text, voice, speed }) => {
                let (model, text, voice, speed) =
                    (model.clone(), text.to_string(), voice.to_string(), *speed);
                tokio::task::spawn_blocking(move || model.render_job(&text, &voice, speed)).await?
            }
            (Family::Flux(model), ModelRequest::Image(request)) => {
                let model = model.clone();
                let prompt = request.prompt.to_owned();
                let (seed, width, height, steps) =
                    (request.seed, request.width, request.height, request.steps);
                let assets = model.assets();
                let (plan, inputs, source) = tokio::task::spawn_blocking(move || {
                    model.render_job(&ImageRequest {
                        prompt: &prompt,
                        seed,
                        width,
                        height,
                        steps,
                    })
                })
                .await??;
                let (environment, content) = super::program::environment(&source, assets).await?;
                Ok(ComputeJob {
                    environment,
                    plan,
                    inputs,
                    content,
                })
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
            (Family::Qwen3(model), ModelRequest::Decision { prompts }) => {
                let (model, prompts) = (model.clone(), prompts.to_vec());
                tokio::task::spawn_blocking(move || model.render_decisions(&prompts)).await?
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
            Family::Speech(model) => Ok(ModelResponse::Speech(model.decode(output)?)),
            Family::Flux(_) => Ok(ModelResponse::Image(Image::decode(output)?)),
            Family::Whisper(model) => Ok(ModelResponse::Transcription(model.decode(output)?)),
            Family::Qwen3(model) if model.is_decision() => {
                Ok(ModelResponse::Logits(model.decode_logits(output)?))
            }
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
