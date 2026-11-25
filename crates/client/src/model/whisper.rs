//! Whisper preprocessing and model bytes stay on the caller's side of Compute.
use super::{native::Native, package::ComputeJob};
use anyhow::{Context, Result, bail, ensure};
use catena_models::{
    weights::preparation::Binding,
    whisper::{Config, Generation, audio, setup},
};
use hellas_rpc::protocol::invocation::{Artifact, compute::*, output::InvocationOutput};
use hellas_store::content::{LocalStore, Scope};
use std::sync::Arc;

pub const CHECKPOINT: [&str; 4] = [
    "config.json",
    "generation_config.json",
    "tokenizer.json",
    "model.safetensors",
];
pub const OUTPUT: &str = "transcription";

pub(super) struct Whisper {
    config: Config,
    generation: Generation,
    tokenizer: tokenizers::Tokenizer,
    environment: Environment,
    content: (LocalStore, Scope),
    setup: Option<Call>,
    weights: Vec<Arg>,
}
#[derive(Debug, serde::Serialize)]
pub struct Transcription {
    pub text: String,
    pub tokens: Vec<u32>,
    pub language: String,
    pub truncated: bool,
}
impl Whisper {
    pub async fn open(source: Arc<Native>, dialect: super::GpuDialect) -> Result<Self> {
        let (config, generation, tokenizer, setup, weights, bundle, native) =
            tokio::task::spawn_blocking(move || -> Result<_> {
                let dir = source.dir();
                let config = Config::read(dir)?;
                let generation = Generation::read(dir, &config)?;
                let tokenizer = tokenizers::Tokenizer::from_file(dir.join("tokenizer.json"))
                    .map_err(anyhow::Error::msg)?;
                ensure!(
                    tokenizer.get_vocab_size(true) == config.vocab_size,
                    "tokenizer vocabulary does not match model"
                );
                let program = setup::program(&config, false, |name, shape| {
                    let tensor = source.tensor("model.safetensors", name)?;
                    ensure!(tensor.shape == shape, "unexpected Whisper shape for {name}");
                    Ok((tensor.arg.clone(), tensor.dtype))
                })?;
                let slot = |index| format!("weight-{index}");
                let setup = (!program.inputs.is_empty()).then(|| Call {
                    entry: setup::ENTRY.into(),
                    bind: (0..program.inputs.len())
                        .map(|i| Bind::Name(slot(i)))
                        .collect(),
                    args: program.inputs,
                });
                let weights = program
                    .weights
                    .into_iter()
                    .map(|w| match w {
                        Binding::Asset(arg) => arg,
                        Binding::Prepared(i) => Arg::Slot { name: slot(i) },
                    })
                    .collect();
                Ok((
                    config,
                    generation,
                    tokenizer,
                    setup,
                    weights,
                    super::program::render(&program.source, dialect)?,
                    source,
                ))
            })
            .await??;
        let (environment, content) = native.environment(&bundle).await?;
        Ok(Self {
            config,
            generation,
            tokenizer,
            environment,
            content,
            setup,
            weights,
        })
    }
    pub(super) fn environment(&self) -> &Environment {
        &self.environment
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
            .zip(<[_; 3]>::from(
                self.generation
                    .masks(self.config.vocab_size, self.config.eos_token_id),
            ))
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
        args.extend_from_slice(&self.weights);
        let mut calls = Vec::from_iter(self.setup.iter().cloned());
        calls.push(Call {
            entry: "whisper.transcribe".into(),
            args,
            bind: vec![Bind::Name(OUTPUT.into())],
        });
        Ok(ComputeJob {
            environment: self.environment.clone(),
            content: self.content.clone(),
            inputs,
            plan: Plan {
                calls,
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
