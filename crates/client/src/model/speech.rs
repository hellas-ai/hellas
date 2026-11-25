//! Speech synthesis: MMS English and Phonon render one request shape into
//! their portable synthesis ABIs and decode one audio shape back.
use super::package::ComputeJob;
use anyhow::{Context, Result, ensure};
use catena_models::{tts, weights::preparation::Binding};
use hellas_rpc::protocol::invocation::{Artifact, compute::*, output::InvocationOutput};
use hellas_store::content::{LocalStore, Scope};
use std::path::Path;

mod omnivoice;
pub mod phonon;
pub use catena_models::tts::Audio;

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
pub(super) struct Speech {
    environment: Environment,
    content: (LocalStore, Scope),
    model: Model,
}
enum Model {
    Mms {
        tokenizer: tts::tokenizer::Tokenizer,
        setup: Call,
        weights: Vec<Arg>,
    },
    Phonon(Box<phonon::Phonon>),
    OmniVoice(Box<omnivoice::OmniVoice>),
}
impl Speech {
    pub async fn open_native(
        source: std::sync::Arc<super::native::Native>,
        kind: super::native::Kind,
        dialect: super::GpuDialect,
    ) -> Result<Self> {
        let (model, bundle, native) = tokio::task::spawn_blocking(move || -> Result<_> {
            let (model, bundle) = match kind {
                super::native::Kind::Mms => {
                    let (config, tokenizer) = metadata(source.dir())?;
                    let program = tts::preparation::build(&config, |name, shape| {
                        let tensor = source.tensor("model.safetensors", name)?;
                        ensure!(tensor.shape == shape, "unexpected MMS shape for {name}");
                        let Arg::Asset { offset, .. } = &tensor.arg else {
                            anyhow::bail!("expected original MMS weight range");
                        };
                        Ok((tensor.arg.clone(), tensor.dtype, usize::try_from(*offset)?))
                    })?;
                    let slot = |i| format!("weight-{i}");
                    let setup = Call {
                        entry: tts::preparation::SETUP_ENTRY.into(),
                        args: program.inputs,
                        bind: (0..program.outputs).map(|i| Bind::Name(slot(i))).collect(),
                    };
                    let weights = program
                        .weights
                        .into_iter()
                        .map(|binding| match binding {
                            Binding::Asset(arg) => arg,
                            Binding::Prepared(i) => Arg::Slot { name: slot(i) },
                        })
                        .collect();
                    (
                        Model::Mms {
                            tokenizer,
                            setup,
                            weights,
                        },
                        program.source,
                    )
                }
                super::native::Kind::Phonon => {
                    let (m, s) = phonon::Phonon::open(source.clone(), dialect)?;
                    (Model::Phonon(Box::new(m)), s)
                }
                super::native::Kind::OmniVoice => {
                    let (m, s) = omnivoice::OmniVoice::open(&source, dialect)?;
                    (Model::OmniVoice(Box::new(m)), s)
                }
                super::native::Kind::Flux | super::native::Kind::Whisper => unreachable!(),
            };
            Ok((model, super::program::render(&bundle, dialect)?, source))
        })
        .await??;
        let (environment, content) = native.environment(&bundle).await?;
        Ok(Self {
            environment,
            content,
            model,
        })
    }
    pub(super) fn setup_entries(&self) -> &'static [&'static str] {
        match &self.model {
            Model::Mms { .. } => &[tts::preparation::SETUP_ENTRY],
            Model::OmniVoice(_) => &["omnivoice.setup"],
            Model::Phonon(_) => &["phonon.prepare-weights", "phonon.prepare-voice"],
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
        let (tokenizer, setup, weights) = match &self.model {
            Model::Mms {
                tokenizer,
                setup,
                weights,
            } => (tokenizer, setup, weights),
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
        args.extend(weights.iter().cloned());
        Ok(ComputeJob {
            environment: self.environment.clone(),
            content: self.content.clone(),
            inputs: vec![Artifact::new(
                "tokens",
                "catena.u64le.v1",
                tokens.iter().flat_map(|x| x.to_le_bytes()).collect(),
            )],
            plan: Plan {
                calls: vec![
                    setup.clone(),
                    Call {
                        entry: "tts.synthesize".into(),
                        args,
                        bind: vec![Bind::Name(WAVEFORM.into()), Bind::Name(RESULT.into())],
                    },
                ],
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

#[cfg(any(test, feature = "test-support"))]
mod fixture;
#[cfg(any(test, feature = "test-support"))]
pub use fixture::write_test_checkpoint;

#[cfg(test)]
mod tests;
