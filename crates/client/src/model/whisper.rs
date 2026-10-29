//! Whisper preprocessing and model bytes stay on the caller's side of Compute.
use super::package::ComputeJob;
use anyhow::{Context, Result, bail, ensure};
use catena_models::{
    weights::{Weights, f32_to_bf16},
    whisper::{Config, audio, graph},
};
use hellas_channel::content::EphemeralContent;
use hellas_rpc::{
    ContentId, ContentRef,
    protocol::invocation::{Artifact, compute::*, output::InvocationOutput},
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

pub const WEIGHTS_FILE: &str = "weights.bf16";
pub const OUTPUT: &str = "transcription";
const METADATA: [&str; 3] = ["config.json", "generation_config.json", "tokenizer.json"];

#[derive(Deserialize)]
struct Generation {
    lang_to_id: BTreeMap<String, u32>,
    task_to_id: BTreeMap<String, u32>,
    no_timestamps_token_id: u32,
    #[serde(default)]
    suppress_tokens: Vec<u32>,
    #[serde(default)]
    begin_suppress_tokens: Vec<u32>,
}
impl Generation {
    fn validate(&self, config: &Config) -> Result<()> {
        ensure!(
            !self.lang_to_id.is_empty() && self.task_to_id.contains_key("transcribe"),
            "missing language or transcribe tokens"
        );
        ensure!(
            self.lang_to_id
                .values()
                .chain(self.task_to_id.values())
                .chain(&self.suppress_tokens)
                .chain(&self.begin_suppress_tokens)
                .chain(std::iter::once(&self.no_timestamps_token_id))
                .all(|id| (*id as usize) < config.vocab_size),
            "generation token exceeds vocabulary"
        );
        Ok(())
    }
    fn masks(&self, config: &Config) -> [Vec<f32>; 3] {
        let mut language = vec![f32::NEG_INFINITY; config.vocab_size];
        for &id in self.lang_to_id.values() {
            language[id as usize] = 0.;
        }
        let mut text = vec![0.; config.vocab_size];
        text[config.eos_token_id as usize + 1..].fill(f32::NEG_INFINITY);
        for &id in &self.suppress_tokens {
            text[id as usize] = f32::NEG_INFINITY;
        }
        let mut begin = vec![0.; config.vocab_size];
        for &id in &self.begin_suppress_tokens {
            begin[id as usize] = f32::NEG_INFINITY;
        }
        [language, text, begin]
    }
}

fn metadata(dir: &Path) -> Result<(Config, Generation, tokenizers::Tokenizer)> {
    let config = Config::read(dir)?;
    let generation: Generation = serde_json::from_reader(File::open(dir.join(METADATA[1]))?)?;
    generation.validate(&config)?;
    let tokenizer =
        tokenizers::Tokenizer::from_file(dir.join(METADATA[2])).map_err(anyhow::Error::msg)?;
    ensure!(
        tokenizer.get_vocab_size(true) == config.vocab_size,
        "tokenizer vocabulary does not match model"
    );
    Ok((config, generation, tokenizer))
}

// The public graph lists specify the call ABI. Shapes follow Whisper's validated
// architecture; offsets always refer to the once-converted, all-BF16 asset.
fn tensors(config: &Config) -> Vec<(String, Vec<usize>)> {
    let d = config.d_model;
    graph::encoder_names(config)
        .into_iter()
        .chain(graph::cross_names(config))
        .chain(graph::decoder_names(config))
        .map(|name| {
            let shape = if name == "model.encoder.conv1.weight" {
                vec![d, config.num_mel_bins, 3]
            } else if name == "model.encoder.conv2.weight" {
                vec![d, d, 3]
            } else if name == "model.encoder.embed_positions.weight" {
                vec![config.max_source_positions, d]
            } else if name == "model.decoder.embed_positions.weight" {
                vec![config.max_target_positions, d]
            } else if name == "model.decoder.embed_tokens.weight" {
                vec![config.vocab_size, d]
            } else if name.ends_with("fc1.weight") {
                vec![config.encoder_ffn_dim, d]
            } else if name.ends_with("fc2.weight") {
                vec![d, config.decoder_ffn_dim]
            } else if name.ends_with("fc1.bias") {
                vec![config.encoder_ffn_dim]
            } else if name.ends_with("bias") || name.contains("layer_norm") {
                vec![d]
            } else {
                vec![d, d]
            };
            (name, shape)
        })
        .collect()
}
fn views(config: &Config) -> Result<Vec<(u64, u64)>> {
    let mut offset = 0u64;
    tensors(config)
        .into_iter()
        .map(|(_, shape)| {
            let bytes = shape
                .into_iter()
                .try_fold(2u64, |n, dim| n.checked_mul(dim as u64))
                .context("weight size overflow")?;
            let start = offset;
            offset = offset
                .checked_add(bytes)
                .context("weight offset overflow")?;
            Ok((start, bytes))
        })
        .collect()
}

/// Convert a published local checkpoint into a client package directory. The
/// derived weight file is an ordinary content-addressed provider asset.
pub fn convert_whisper(checkpoint: &Path, destination: &Path) -> Result<ContentRef> {
    ensure!(!destination.exists(), "destination already exists");
    let (config, _, _) = metadata(checkpoint)?;
    let weights = Weights::open(&checkpoint.join("model.safetensors"))?;
    catena_models::whisper::validate_weights(&weights, &config)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".whisper-")
        .tempdir_in(parent)?;
    let path = staging.path().join(WEIGHTS_FILE);
    let mut file = BufWriter::new(File::create(&path)?);
    for (name, shape) in tensors(&config) {
        weights.validate(&name, &shape)?;
        let values = weights.host_f32(&name)?;
        let as_is = weights.tensors[&name].dtype == safetensors::Dtype::BF16;
        for value in values {
            let bits = if as_is {
                (value.to_bits() >> 16) as u16
            } else {
                f32_to_bf16(value)
            };
            file.write_all(&bits.to_le_bytes())?;
        }
    }
    file.flush()?;
    file.get_ref().sync_all()?;
    drop(file);
    for name in METADATA {
        std::fs::copy(checkpoint.join(name), staging.path().join(name))?;
    }
    let indexed = hellas_store::ContentStore::new().index(&path)?;
    std::fs::rename(staging.path(), destination)?;
    Ok(ContentRef::new(
        ContentId::from_bytes(*indexed.id.as_bytes()),
        indexed.len,
    ))
}

pub(super) struct Whisper {
    config: Config,
    generation: Generation,
    tokenizer: tokenizers::Tokenizer,
    environment: Environment,
    content: EphemeralContent,
    views: Vec<(u64, u64)>,
}
#[derive(Debug, serde::Serialize)]
pub struct Transcription {
    pub text: String,
    pub tokens: Vec<u32>,
    pub language: String,
    pub truncated: bool,
}
impl Whisper {
    pub fn open(dir: &Path) -> Result<Self> {
        let (config, generation, tokenizer) = metadata(dir)?;
        let views = views(&config)?;
        let indexed = hellas_store::ContentStore::new().index(&dir.join(WEIGHTS_FILE))?;
        let (offset, bytes) = views.last().context("model has no weights")?;
        ensure!(
            indexed.len == offset + bytes,
            "derived weight file has wrong length"
        );
        let mut content = EphemeralContent::default();
        let source =
            content.insert(super::program::render(&graph::bundle(&config, false)?)?.into_bytes());
        let environment = Environment {
            sources: vec![source],
            assets: vec![NamedAsset {
                name: "weights".into(),
                object: ContentRef::new(ContentId::from_bytes(*indexed.id.as_bytes()), indexed.len),
            }],
        };
        content.insert(environment.canonical_bytes()?);
        Ok(Self {
            config,
            generation,
            tokenizer,
            environment,
            content,
            views,
        })
    }
    pub fn transcription_capacity(&self) -> usize {
        self.config.max_target_positions - 4
    }
    pub fn render_job(
        &self,
        samples: &[f32],
        language: Option<&str>,
        max_new_tokens: usize,
    ) -> Result<ComputeJob> {
        ensure!(
            max_new_tokens > 0 && max_new_tokens <= self.config.max_target_positions - 4,
            "token limit exceeds decoder capacity"
        );
        let language = language
            .map(|code| {
                self.generation
                    .lang_to_id
                    .get(&format!("<|{code}|>"))
                    .copied()
                    .with_context(|| format!("unknown language code {code}"))
            })
            .transpose()?
            .unwrap_or(0);
        let features = audio::log_mel(samples)?;
        let mut inputs = vec![floats("features", &features)];
        for (name, values) in ["language-mask", "text-mask", "begin-mask"]
            .into_iter()
            .zip(self.generation.masks(&self.config))
        {
            inputs.push(floats(name, &values));
        }
        inputs.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        let input = |name: &str| Arg::Input {
            object: name.into(),
        };
        let mut args = vec![
            input("features"),
            Arg::U64(max_new_tokens as u64),
            Arg::U64(language.into()),
            Arg::U64(self.config.decoder_start_token_id.into()),
            Arg::U64(self.generation.task_to_id["transcribe"].into()),
            Arg::U64(self.generation.no_timestamps_token_id.into()),
            Arg::U64(self.config.eos_token_id.into()),
            input("language-mask"),
            input("text-mask"),
            input("begin-mask"),
        ];
        args.extend(self.views.iter().map(|&(offset, bytes)| Arg::Asset {
            name: "weights".into(),
            offset,
            bytes,
        }));
        Ok(ComputeJob {
            environment: self.environment.clone(),
            content: self.content.clone(),
            inputs,
            plan: Plan {
                calls: vec![Call {
                    entry: "whisper.transcribe".into(),
                    args,
                    bind: vec![Bind::Name(OUTPUT.into())],
                }],
                step: None,
                outputs: vec![Declared {
                    slot: OUTPUT.into(),
                    kind: OutputKind::Buffer {
                        max_bytes: self.output_bytes()?,
                    },
                }],
            },
        })
    }
    fn output_bytes(&self) -> Result<u64> {
        (self.config.max_target_positions as u64 - 1)
            .checked_mul(8)
            .context("result size overflow")
    }
    pub fn decode(&self, output: &InvocationOutput) -> Result<Transcription> {
        let [artifact] = output.artifacts.as_slice() else {
            bail!("expected one transcription artifact")
        };
        ensure!(
            artifact.name == OUTPUT
                && artifact.format == "catena.bytes.v1"
                && artifact.bytes.as_bytes().len() as u64 == self.output_bytes()?,
            "invalid transcription artifact"
        );
        let values: Vec<_> = artifact
            .bytes
            .as_bytes()
            .as_chunks::<8>()
            .0
            .iter()
            .copied()
            .map(u64::from_le_bytes)
            .collect();
        let (count, language, status) = (usize::try_from(values[0])?, values[1], values[2]);
        ensure!(
            count <= values.len() - 3,
            "invalid transcription token count"
        );
        ensure!(
            status <= 1,
            "model produced nonfinite or entirely suppressed logits"
        );
        let language = self
            .generation
            .lang_to_id
            .iter()
            .find(|(_, id)| u64::from(**id) == language)
            .map(|(name, _)| {
                name.trim_start_matches("<|")
                    .trim_end_matches("|>")
                    .to_owned()
            })
            .context("invalid detected language")?;
        let tokens = values[3..3 + count]
            .iter()
            .map(|id| {
                ensure!(
                    *id < self.config.vocab_size as u64,
                    "transcription token exceeds vocabulary"
                );
                Ok(u32::try_from(*id)?)
            })
            .collect::<Result<Vec<_>>>()?;
        let text = self
            .tokenizer
            .decode(&tokens, true)
            .map_err(anyhow::Error::msg)?
            .trim()
            .to_owned();
        Ok(Transcription {
            text,
            tokens,
            language,
            truncated: status == 0,
        })
    }
}
fn floats(name: &str, values: &[f32]) -> Artifact {
    Artifact::new(
        name,
        "catena.f32le.v1",
        values.iter().flat_map(|x| x.to_le_bytes()).collect(),
    )
}

#[cfg(test)]
mod tests;
