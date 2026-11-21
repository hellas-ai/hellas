//! Qwen text generation and d1 decisions as client-rendered Compute jobs.
//!
//! The provider runs only the opaque program: catena-models renders the Hex
//! from the GGUF configuration and this package maps its weight order onto
//! byte ranges of the GGUF asset. For text, the provider's step loop feeds each
//! emitted token back until a stop id or the token budget. A decision model
//! instead prefills each prompt once and returns its final logits.
use super::gguf::{self, Dtype};
use super::package::ComputeJob;
use anyhow::{Context, Result, ensure};
use catena_models::{
    catena,
    catena::InferenceOptions,
    checkpoint::read_gguf_model_config,
    spec::{ModelArchitecture, ModelConfig, WeightDtype, weight_specs},
};
use hellas_rpc::protocol::invocation::{
    Artifact, MAX_ARTIFACTS, compute::*, output::InvocationOutput,
};
use hellas_store::content::{LocalStore, Scope};
use std::{collections::BTreeMap, path::Path, sync::Arc};

const PROMPT: &str = "prompt";
const WEIGHTS: &str = "weights";
const LOGITS: &str = "logits";

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
            WeightDtype::F16 => anyhow::bail!("unsupported F16 weight {}", spec.gguf_name),
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
                // Qwen3.5 and LFM3 prefill with matrix cores; Qwen3 uses SIMT kernels.
                let wmma = matches!(
                    config.architecture,
                    ModelArchitecture::Qwen35Dense
                        | ModelArchitecture::Qwen35Moe
                        | ModelArchitecture::Lfm3
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
        let (environment, content) = super::program::environment(
            &source,
            vec![NamedAsset {
                name: WEIGHTS.into(),
                object,
            }],
        )
        .await?;
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
    /// Bidirectional models answer decisions and do not generate text.
    pub(super) fn is_decision(&self) -> bool {
        is_decision(&self.config)
    }
    fn weights(&self) -> impl Iterator<Item = Arg> {
        self.views.iter().map(|&(offset, bytes)| Arg::Asset {
            name: WEIGHTS.into(),
            offset,
            bytes,
        })
    }
    fn logits_bytes(&self) -> u64 {
        self.config.vocabulary_size as u64 * 2
    }
    /// One full prefill per prompt, each returning its final-position logits.
    pub fn render_decisions(&self, prompts: &[Vec<u64>]) -> Result<ComputeJob> {
        ensure!(self.is_decision(), "model does not answer decisions");
        ensure!(
            (1..=MAX_ARTIFACTS).contains(&prompts.len()),
            "a decision job answers 1 to {MAX_ARTIFACTS} questions"
        );
        let (mut calls, mut inputs, mut outputs) = (Vec::new(), Vec::new(), Vec::new());
        for (i, prompt) in prompts.iter().enumerate() {
            let capacity = prompt.len() as u64;
            ensure!(
                capacity > 0 && capacity <= self.config.max_position_embeddings as u64,
                "decision prompt exceeds model context"
            );
            ensure!(
                prompt
                    .iter()
                    .all(|id| *id < self.config.vocabulary_size as u64),
                "token id exceeds vocabulary"
            );
            let (object, slot) = (format!("{PROMPT}-{i:02}"), format!("{LOGITS}-{i:02}"));
            calls.push(Call {
                entry: "qwen3.init".into(),
                args: vec![Arg::U64(capacity)],
                bind: self.states.iter().cloned().map(Bind::Name).collect(),
            });
            let mut args = vec![Arg::Input {
                object: object.clone(),
            }];
            args.extend(
                self.states
                    .iter()
                    .map(|name| Arg::Slot { name: name.clone() }),
            );
            args.extend([Arg::U64(capacity), Arg::U64(0)]);
            args.extend(self.weights());
            calls.push(Call {
                entry: "qwen3".into(),
                args,
                bind: self
                    .states
                    .iter()
                    .map(|_| Bind::Discard)
                    .chain([Bind::Name(slot.clone()), Bind::Discard])
                    .collect(),
            });
            inputs.push(tokens(&object, prompt));
            outputs.push(Declared {
                slot,
                kind: OutputKind::Buffer {
                    max_bytes: self.logits_bytes(),
                },
            });
        }
        Ok(ComputeJob {
            environment: self.environment.clone(),
            plan: Plan {
                calls,
                step: None,
                outputs,
            },
            inputs,
            content: self.content.clone(),
        })
    }
    /// The BF16 logits of each prompt, widened to F32, in prompt order.
    pub fn decode_logits(&self, output: &InvocationOutput) -> Result<Vec<Vec<f32>>> {
        (0..output.artifacts.len())
            .map(|i| {
                let name = format!("{LOGITS}-{i:02}");
                let artifact = output
                    .artifacts
                    .iter()
                    .find(|a| a.name == name)
                    .with_context(|| format!("missing {name}"))?;
                let bytes = artifact.bytes.as_bytes();
                ensure!(
                    artifact.format == "catena.bytes.v1"
                        && bytes.len() as u64 == self.logits_bytes(),
                    "invalid logits artifact"
                );
                Ok(bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| f32::from_bits(u32::from(u16::from_le_bytes(*b)) << 16))
                    .collect())
            })
            .collect()
    }
    /// Stops are the caller's ids plus the GGUF end-of-sequence id.
    pub fn render_job(
        &self,
        prompt_ids: &[u64],
        max_new: u64,
        stops: &[u64],
    ) -> Result<ComputeJob> {
        ensure!(!self.is_decision(), "decision models do not generate text");
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
        args.extend(self.weights().map(StepArg::Arg));
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
            inputs: vec![tokens(PROMPT, prompt_ids)],
            content: self.content.clone(),
        })
    }
}

pub(super) fn is_decision(config: &ModelConfig) -> bool {
    config
        .lfm3
        .as_ref()
        .is_some_and(|lfm3| !lfm3.causal_attention)
}

fn tokens(name: &str, ids: &[u64]) -> Artifact {
    Artifact::new(
        name,
        OutputKind::Scalar(ValueKind::U64).format(),
        ids.iter().flat_map(|n| n.to_le_bytes()).collect(),
    )
}
