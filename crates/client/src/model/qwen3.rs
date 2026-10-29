//! Qwen3 text generation as a client-rendered Compute job.
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
    spec::{ModelArchitecture, ModelConfig, WeightDtype, weight_specs},
};
use hellas_channel::content::EphemeralContent;
use hellas_rpc::{
    ContentId, ContentRef,
    protocol::invocation::{Artifact, compute::*},
};
use std::{collections::BTreeMap, fs::File, path::Path};

const PROMPT: &str = "prompt";
const WEIGHTS: &str = "weights";

pub(super) struct Qwen3 {
    config: ModelConfig,
    environment: Environment,
    content: EphemeralContent,
    views: Vec<(u64, u64)>,
}

impl Qwen3 {
    pub fn open(path: &Path) -> Result<Self> {
        let header = gguf::read_header(&mut File::open(path)?)?;
        let config = read_gguf_model_config(path)?;
        ensure!(
            config.architecture == ModelArchitecture::Qwen3Dense,
            "text package requires dense Qwen3"
        );
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
        let indexed = hellas_store::ContentStore::new().index(path)?;
        let mut content = EphemeralContent::default();
        let source = content.insert(catena::generated_model_source_for(&config)?.into_bytes());
        let environment = Environment {
            sources: vec![source],
            assets: vec![NamedAsset {
                name: WEIGHTS.into(),
                object: ContentRef::new(ContentId::from_bytes(*indexed.id.as_bytes()), indexed.len),
            }],
        };
        content.insert(environment.canonical_bytes()?);
        Ok(Self {
            config,
            environment,
            content,
            views,
        })
    }

    pub fn environment(&self) -> &Environment {
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
        let mut args = vec![
            StepArg::FirstThen {
                first: Arg::Input {
                    object: PROMPT.into(),
                },
                then: Arg::Slot {
                    name: "next".into(),
                },
            },
            StepArg::Arg(Arg::Slot { name: "s0".into() }),
            StepArg::Arg(Arg::Slot { name: "s1".into() }),
            StepArg::Arg(Arg::U64(capacity)),
            StepArg::FirstThen {
                first: Arg::U64(0),
                then: Arg::Counter { base: prompt - 1 },
            },
        ];
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
                bind: vec![Bind::Name("s0".into()), Bind::Name("s1".into())],
            }],
            step: Some(Step {
                entry: "qwen3".into(),
                args,
                bind: vec![
                    Bind::Name("s0".into()),
                    Bind::Name("s1".into()),
                    Bind::Discard,
                    Bind::Name("next".into()),
                ],
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
