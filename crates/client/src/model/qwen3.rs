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
    checkpoint::read_gguf_model_config,
    spec::{ModelConfig, WeightDtype, weight_specs},
};
use hellas_channel::content::EphemeralContent;
use hellas_rpc::protocol::invocation::{Artifact, compute::*};
use std::{collections::BTreeMap, fs::File, path::Path};

const PROMPT: &str = "prompt";
const WEIGHTS: &str = "weights";

pub(super) struct Qwen3 {
    config: ModelConfig,
    environment: Environment,
    content: EphemeralContent,
    views: Vec<(u64, u64)>,
    states: Vec<String>,
}

impl Qwen3 {
    pub fn open(path: &Path) -> Result<Self> {
        let header = gguf::read_header(&mut File::open(path)?)?;
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
        let object = super::file_content(path)?;
        let mut content = EphemeralContent::default();
        let model = catena::generated_model_source_for(&config)?;
        let source = super::program::render(&model)?;
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
        let source = content.insert(source.into_bytes());
        let environment = Environment {
            sources: vec![source],
            assets: vec![NamedAsset {
                name: WEIGHTS.into(),
                object,
            }],
        };
        content.insert(environment.canonical_bytes()?);
        Ok(Self {
            config,
            environment,
            content,
            views,
            states,
        })
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
