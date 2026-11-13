//! Qwen text generation as a client-rendered Compute job.
//!
//! The provider runs only the opaque program: catena-models renders the Hex
//! from the GGUF configuration, this package maps its weight order onto byte
//! ranges of the GGUF asset, and the provider's step loop feeds each emitted
//! token back until a stop id or the token budget.
use super::gguf::{self, Dtype};
use super::package::ComputeJob;
use anyhow::{Context, Result, ensure};
use catena_models::{
    catena,
    catena::InferenceOptions,
    checkpoint::read_gguf_model_config,
    spec::{ModelArchitecture, ModelConfig, WeightDtype, weight_specs},
};
use hellas_channel::content::{DEFAULT_MAX_STAGING_BYTES, upload_object};
use hellas_rpc::protocol::invocation::{Artifact, compute::*};
use hellas_store::content::{LocalStore, MemoryStore, Reservations, Scope};
use std::{collections::BTreeMap, path::Path, sync::Arc};

const PROMPT: &str = "prompt";
const WEIGHTS: &str = "weights";

pub(super) struct Qwen3 {
    config: ModelConfig,
    environment: Environment,
    content: (LocalStore, Scope),
    views: Vec<(u64, u64)>,
    states: Vec<String>,
}

pub(super) fn metadata(
    path: &Path,
    header: &gguf::Header,
) -> Result<(ModelConfig, Vec<(u64, u64)>)> {
    let config = read_gguf_model_config(path)?;
    let tensors: BTreeMap<_, _> = header
        .tensors
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();
    let mut views = Vec::new();
    for spec in weight_specs(&config)? {
        let tensor = tensors
            .get(spec.gguf_name.as_str())
            .with_context(|| format!("missing weight {}", spec.gguf_name))?;
        let dtype = match spec.dtype {
            WeightDtype::F32 => Dtype::F32,
            WeightDtype::Bf16 => Dtype::Bf16,
        };
        ensure!(
            tensor.dtype == dtype
                && tensor.shape == spec.shape.iter().map(|n| *n as u64).collect::<Vec<_>>(),
            "weight shape or dtype mismatch: {}",
            spec.gguf_name
        );
        views.push((tensor.offset, tensor.bytes));
    }
    Ok((config, views))
}

impl Qwen3 {
    pub async fn open(
        path: &Path,
        dialect: super::GpuDialect,
        object: hellas_rpc::ContentRef,
        header: Arc<gguf::Header>,
    ) -> Result<Self> {
        let path = path.to_owned();
        let (config, views, object, source, states) =
            tokio::task::spawn_blocking(move || -> Result<_> {
                let (config, views) = metadata(&path, &header)?;
                // Qwen3.5 prefills with matrix cores; Qwen3 has only SIMT kernels.
                let wmma = matches!(
                    config.architecture,
                    ModelArchitecture::Qwen35Dense | ModelArchitecture::Qwen35Moe
                );
                let options = InferenceOptions::default().with_wmma_prefill(wmma);
                let model = catena::generated_model_source_for_options(&config, options)?;
                let source = super::program::render(&model, dialect)?;
                let raw = metacat::theory::RawTheorySet::from_text(&source)?;
                let init = raw
                    .theories
                    .get(&"program".parse()?)
                    .and_then(|program| program.arrows.get(&"qwen3.init".parse().unwrap()))
                    .context("model has no qwen3.init entry")?;
                let hexpr::Hexpr::Tensor(outputs) = &init.type_maps.1 else {
                    anyhow::bail!("model init must declare a tuple of state outputs");
                };
                let states = (0..outputs.len()).map(|i| format!("s{i}")).collect();
                Ok((config, views, object, source, states))
            })
            .await??;
        let content = (
            LocalStore::Memory(MemoryStore::new(Reservations::ram(
                DEFAULT_MAX_STAGING_BYTES,
            ))),
            Scope::Owner,
        );
        let source = upload_object(&content.0, source.as_bytes()).await?;
        let environment = Environment {
            sources: vec![source],
            assets: vec![NamedAsset {
                name: WEIGHTS.into(),
                object,
            }],
        };
        upload_object(&content.0, &environment.canonical_bytes()?).await?;
        Ok(Self {
            config,
            environment,
            content,
            views,
            states,
        })
    }

    pub(super) fn environment(&self) -> &Environment {
        &self.environment
    }
    /// Stops are the caller's ids plus the GGUF end-of-sequence id.
    pub fn render_job(
        &self,
        prompt_ids: &[u64],
        max_new: u64,
        stops: &[u64],
    ) -> Result<ComputeJob> {
        let prompt = u64::try_from(prompt_ids.len())?;
        ensure!(
            prompt > 0 && max_new > 0,
            "prompt and generation must be nonempty"
        );
        ensure!(
            prompt_ids
                .iter()
                .chain(stops)
                .all(|id| *id < self.config.vocabulary_size as u64),
            "token id exceeds vocabulary"
        );
        let capacity = prompt
            .checked_add(max_new)
            .context("generation capacity overflow")?;
        ensure!(
            capacity <= self.config.max_position_embeddings as u64,
            "generation exceeds model context"
        );
        let mut any_of = stops.to_vec();
        any_of.extend(self.config.eos_token_id);
        any_of.sort_unstable();
        any_of.dedup();
        let mut args = vec![StepArg::FirstThen {
            first: Arg::Input {
                object: PROMPT.into(),
            },
            then: Arg::Slot {
                name: "next".into(),
            },
        }];
        args.extend(
            self.states
                .iter()
                .map(|name| StepArg::Arg(Arg::Slot { name: name.clone() })),
        );
        args.extend([
            StepArg::Arg(Arg::U64(capacity)),
            StepArg::FirstThen {
                first: Arg::U64(0),
                then: Arg::Counter { base: prompt - 1 },
            },
        ]);
        args.extend(self.views.iter().map(|(offset, bytes)| {
            StepArg::Arg(Arg::Asset {
                name: WEIGHTS.into(),
                offset: *offset,
                bytes: *bytes,
            })
        }));
        let plan = Plan {
            calls: vec![Call {
                entry: "qwen3.init".into(),
                args: vec![Arg::U64(capacity)],
                bind: self.states.iter().cloned().map(Bind::Name).collect(),
            }],
            step: Some(Step {
                entry: "qwen3".into(),
                args,
                bind: self
                    .states
                    .iter()
                    .cloned()
                    .map(Bind::Name)
                    .chain([Bind::Discard, Bind::Name("next".into())])
                    .collect(),
                emit: "next".into(),
                stop: Stop {
                    any_of,
                    max_steps: max_new,
                },
            }),
            outputs: vec![],
        };
        Ok(ComputeJob {
            environment: self.environment.clone(),
            plan,
            inputs: vec![Artifact::new(
                PROMPT,
                OutputKind::Scalar(ValueKind::U64).format(),
                prompt_ids.iter().flat_map(|n| n.to_le_bytes()).collect(),
            )],
            content: self.content.clone(),
        })
    }
}
