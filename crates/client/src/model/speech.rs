//! Speech synthesis: MMS English and Phonon render one request shape into
//! their portable synthesis ABIs and decode one audio shape back.
use super::package::ComputeJob;
use anyhow::{Context, Result, ensure};
use catena_models::{
    tts,
    weights::{Weights, f32_to_bf16},
};
use hellas_rpc::{
    ContentRef,
    protocol::invocation::{Artifact, compute::*, output::InvocationOutput},
};
use hellas_store::content::{LocalStore, Scope};
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

mod omnivoice;
pub mod phonon;
pub use catena_models::tts::Audio;

pub const WEIGHTS_FILE: &str = "weights.bf16";
pub const WAVEFORM: &str = "waveform";
pub const RESULT: &str = "result";
pub(super) const MAX_METADATA_BYTES: usize = 1 << 20;
pub(super) const METADATA: [&str; 4] = [
    "config.json",
    "vocab.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
];
pub const CHECKPOINT: [&str; 5] = [
    METADATA[0],
    METADATA[1],
    METADATA[2],
    METADATA[3],
    "model.safetensors",
];

fn metadata(dir: &Path) -> Result<(tts::Config, tts::tokenizer::Tokenizer)> {
    // Bound all input files before the pinned model's readers interpret them.
    for name in METADATA {
        hellas_private::read_bounded_regular_file(&dir.join(name), MAX_METADATA_BYTES)?;
    }
    Ok((
        tts::Config::read(dir)?,
        tts::tokenizer::Tokenizer::read(dir)?,
    ))
}
fn views() -> Result<Vec<(u64, u64)>> {
    let mut offset = 0u64;
    tts::bindings()
        .into_iter()
        .map(|(_, binding)| {
            let bytes = binding
                .shape
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
pub(super) fn validate_metadata(dir: &Path, object: ContentRef) -> Result<()> {
    metadata(dir)?;
    validate_length(object)
}
fn validate_length(object: ContentRef) -> Result<()> {
    let views = views()?;
    let (offset, bytes) = views.last().context("missing MMS weights")?;
    ensure!(
        object.bytes() == offset + bytes,
        "derived MMS weight file has wrong length"
    );
    Ok(())
}

/// Convert the pinned MMS layout, including weight normalization and transpose.
pub fn convert_speech(checkpoint: &Path, destination: &Path) -> Result<ContentRef> {
    ensure!(!destination.try_exists()?, "destination already exists");
    let (config, _) = metadata(checkpoint)?;
    let weights = Weights::open(&checkpoint.join("model.safetensors"))?;
    tts::validate_weights(&weights, &config)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".speech-")
        .tempdir_in(parent)?;
    let path = staging.path().join(WEIGHTS_FILE);
    let mut file = BufWriter::new(File::create(&path)?);
    for (name, binding) in tts::bindings() {
        let as_is = !binding.normalized
            && !binding.transpose
            && weights.tensors[&name].dtype == safetensors::Dtype::BF16;
        for value in tts::materialize(&weights, &name, &binding)? {
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
        std::fs::write(
            staging.path().join(name),
            hellas_private::read_bounded_regular_file(&checkpoint.join(name), MAX_METADATA_BYTES)?,
        )?;
    }
    let object = hellas_store::content::file_content(&path)?;
    validate_metadata(staging.path(), object)?;
    std::fs::rename(staging.path(), destination)?;
    Ok(object)
}

pub(super) struct Speech {
    environment: Environment,
    content: (LocalStore, Scope),
    model: Model,
}
enum Model {
    Mms {
        tokenizer: tts::tokenizer::Tokenizer,
        views: Vec<(u64, u64)>,
    },
    Phonon(Box<phonon::Phonon>),
    OmniVoice(Box<omnivoice::OmniVoice>),
}
impl Speech {
    pub async fn open(dir: &Path, dialect: super::GpuDialect, object: ContentRef) -> Result<Self> {
        let dir = dir.to_owned();
        let (tokenizer, source, views) = tokio::task::spawn_blocking(move || -> Result<_> {
            let (config, tokenizer) = metadata(&dir)?;
            validate_length(object)?;
            Ok((
                tokenizer,
                super::program::render(&tts::graph::bundle(&config)?, dialect)?,
                views()?,
            ))
        })
        .await??;
        let (environment, content) = super::program::environment(
            &source,
            vec![NamedAsset {
                name: "weights".into(),
                object,
            }],
        )
        .await?;
        Ok(Self {
            environment,
            content,
            model: Model::Mms { tokenizer, views },
        })
    }
    pub async fn open_native(
        source: super::native::Native,
        kind: super::native::Kind,
        dialect: super::GpuDialect,
    ) -> Result<Self> {
        let (model, source, assets) = tokio::task::spawn_blocking(move || -> Result<_> {
            let (model, bundle) = match kind {
                super::native::Kind::Phonon => {
                    let (m, s) = phonon::Phonon::open(&source, dialect)?;
                    (Model::Phonon(Box::new(m)), s)
                }
                super::native::Kind::OmniVoice => {
                    let (m, s) = omnivoice::OmniVoice::open(&source, dialect)?;
                    (Model::OmniVoice(Box::new(m)), s)
                }
                super::native::Kind::Flux => unreachable!(),
            };
            Ok((
                model,
                super::program::render(&bundle, dialect)?,
                source.assets(),
            ))
        })
        .await??;
        let (environment, content) = super::program::environment(&source, assets).await?;
        Ok(Self {
            environment,
            content,
            model,
        })
    }
    pub(super) fn setup_entries(&self) -> &'static [&'static str] {
        match &self.model {
            Model::OmniVoice(_) => &["omnivoice.setup"],
            _ => &[],
        }
    }
    pub(super) fn environment(&self) -> &Environment {
        &self.environment
    }
    pub fn render_job(&self, text: &str, voice: &str, speed: f32) -> Result<ComputeJob> {
        ensure!(
            speed.is_finite() && (0.25..=4.).contains(&speed),
            "speed must be between 0.25 and 4"
        );
        let (tokenizer, views) = match &self.model {
            Model::Mms { tokenizer, views } => (tokenizer, views),
            Model::OmniVoice(model) => {
                return model.render_job(&self.environment, &self.content, text, voice, speed);
            }
            Model::Phonon(model) => {
                return model.render_job(&self.environment, &self.content, text, voice, speed);
            }
        };
        ensure!(voice == "default", "MMS English has one voice, default");
        let tokens = tokenizer.encode(text)?;
        let options = tts::Options::default();
        let mut args = vec![
            Arg::Input {
                object: "tokens".into(),
            },
            Arg::U64(tokens.len() as u64),
            Arg::U32(0),
            Arg::U32(0),
            Arg::F32Bits(options.noise_scale_duration.to_bits()),
            Arg::F32Bits(options.noise_scale.to_bits()),
            Arg::F32Bits(speed.to_bits()),
        ];
        args.extend(views.iter().map(|&(offset, bytes)| Arg::Asset {
            name: "weights".into(),
            offset,
            bytes,
        }));
        Ok(ComputeJob {
            environment: self.environment.clone(),
            content: self.content.clone(),
            inputs: vec![Artifact::new(
                "tokens",
                "catena.u64le.v1",
                tokens.iter().flat_map(|x| x.to_le_bytes()).collect(),
            )],
            plan: Plan {
                calls: vec![Call {
                    entry: "tts.synthesize".into(),
                    args,
                    bind: vec![Bind::Name(WAVEFORM.into()), Bind::Name(RESULT.into())],
                }],
                step: None,
                outputs: vec![
                    Declared {
                        slot: RESULT.into(),
                        kind: OutputKind::Buffer { max_bytes: 16 },
                    },
                    Declared {
                        slot: WAVEFORM.into(),
                        kind: OutputKind::Buffer {
                            max_bytes: (tts::MAX_SAMPLES * 4) as u64,
                        },
                    },
                ],
            },
        })
    }
    pub fn decode(&self, output: &InvocationOutput) -> Result<Audio> {
        match self.model {
            Model::Mms { .. } => Self::decode_mms(output),
            Model::Phonon(_) => phonon::decode(output),
            Model::OmniVoice(_) => omnivoice::decode(output),
        }
    }
    pub(super) fn decode_phonon(output: &InvocationOutput) -> Result<Audio> {
        phonon::decode(output)
    }
    fn decode_mms(output: &InvocationOutput) -> Result<Audio> {
        ensure!(
            output.artifacts.len() == 2,
            "expected waveform and result descriptor"
        );
        let artifact = |name: &str, len| -> Result<&[u8]> {
            let a = output
                .artifacts
                .iter()
                .find(|a| a.name == name)
                .context("missing speech artifact")?;
            ensure!(
                a.format == "catena.bytes.v1" && a.bytes.as_bytes().len() == len,
                "invalid speech artifact"
            );
            Ok(a.bytes.as_bytes())
        };
        let result = artifact(RESULT, 16)?;
        let count = usize::try_from(u64::from_le_bytes(result[..8].try_into()?))?;
        ensure!(
            u64::from_le_bytes(result[8..].try_into()?) == 0,
            "predicted audio exceeds capacity or has invalid durations"
        );
        ensure!(
            count > 0 && count <= tts::MAX_SAMPLES,
            "invalid speech sample count"
        );
        let waveform = artifact(WAVEFORM, tts::MAX_SAMPLES * 4)?;
        let samples = floats_f32(&waveform[..count * 4])?;
        ensure!(
            samples.iter().all(|x| x.is_finite()),
            "nonfinite speech waveform"
        );
        Ok(Audio {
            samples,
            sample_rate: tts::SAMPLE_RATE,
        })
    }
}
fn floats_f32(bytes: &[u8]) -> Result<Vec<f32>> {
    let (floats, []) = bytes.as_chunks::<4>() else {
        anyhow::bail!("waveform is not whole F32 samples");
    };
    Ok(floats.iter().copied().map(f32::from_le_bytes).collect())
}

#[cfg(test)]
mod tests;
