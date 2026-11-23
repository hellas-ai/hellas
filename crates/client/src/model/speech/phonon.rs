//! Phonon speech plans over original model, codec and catalog voice tensors.
use super::{Audio, floats_f32};
use crate::model::{native::Native, package::ComputeJob};
use anyhow::{Context, Result, bail, ensure};
use catena_lang::codegen::GpuDialect;
use catena_models::{
    phonon::{
        self, Config, Prompt,
        preparation::{Program, VOICE_ENTRY, WEIGHT_ENTRY},
    },
    weights::preparation::Binding,
};
use hellas_rpc::protocol::invocation::{
    Artifact, MAX_ARTIFACTS, compute::*, output::InvocationOutput,
};
use hellas_store::content::{LocalStore, Scope};
use std::path::Path;

const SEED: u64 = 0;

/// A voice name as a single file name: it names a package file and an asset.
pub fn validate_voice(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name != "."
            && name != ".."
            && !name.contains(['/', '\\'])
            && !name.chars().any(char::is_control),
        "invalid voice name {name:?}"
    );
    Ok(())
}

/// The catalog's checkpoint file for a voice, as a path within its repository.
pub fn voice_file(catalog: &str, name: &str) -> Result<String> {
    validate_voice(name)?;
    let file = phonon::voice_filename(catalog, name)?;
    ensure!(
        !file.contains('\\')
            && Path::new(&file)
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_))),
        "voice {name:?} has an unsafe checkpoint path {file:?}"
    );
    Ok(file)
}

pub(in crate::model) struct Phonon {
    tokenizer: tokenizers::Tokenizer,
    program: Program<Arg>,
    voice: String,
    voice_arg: Arg,
    frames: u64,
}

impl Phonon {
    pub(crate) fn open(source: &Native, _dialect: GpuDialect) -> Result<(Self, String)> {
        let config = Config::read(&source.dir().join("model"), &source.dir().join("codec"))?;
        let tokenizer = phonon::read_tokenizer(&source.dir().join("model"))?;
        ensure!(
            source.voices.len() == 1,
            "each Phonon manifest selects one voice"
        );
        let (voice, key) = source
            .voices
            .first_key_value()
            .context("missing catalog voice")?;
        let tensor = source.tensor(key, "speaker_wavs")?;
        let frames = phonon::voice_frames(&tensor.shape)? as u64;
        let mut program =
            phonon::preparation::build(&config, tensor.dtype, |codec, name, shape| {
                let file = if codec {
                    "codec/model.safetensors"
                } else {
                    "model/model.safetensors"
                };
                let tensor = source.tensor(file, name)?;
                ensure!(
                    tensor.shape == shape,
                    "wrong shape for Phonon tensor {name}"
                );
                let Arg::Asset { offset, .. } = &tensor.arg else {
                    bail!("expected asset range")
                };
                Ok((tensor.arg.clone(), tensor.dtype, usize::try_from(*offset)?))
            })?;
        let hex = std::mem::take(&mut program.source);
        Ok((
            Self {
                tokenizer,
                program,
                voice: voice.clone(),
                voice_arg: tensor.arg.clone(),
                frames,
            },
            hex,
        ))
    }

    fn operand(operand: &Binding<Arg>) -> Arg {
        match operand {
            Binding::Asset(asset) => asset.clone(),
            Binding::Prepared(index) => Arg::Slot {
                name: format!("weight-{index}"),
            },
        }
    }
    pub fn render_job(
        &self,
        environment: &Environment,
        content: &(LocalStore, Scope),
        text: &str,
        voice: &str,
        speed: f32,
    ) -> Result<ComputeJob> {
        ensure!(speed == 1., "this speech model supports speed 1 only");
        let voice = if voice == "default" {
            phonon::DEFAULT_VOICE
        } else {
            voice
        };
        ensure!(
            voice == self.voice,
            "voice {voice:?} is outside this manifest"
        );
        let frames = self.frames;
        let prompts = Prompt::split(&self.tokenizer, text)?;
        ensure!(
            prompts.len() <= MAX_ARTIFACTS / 2,
            "text splits into more than {} utterances",
            MAX_ARTIFACTS / 2
        );
        let slot = |name: &str| Arg::Slot { name: name.into() };
        let mut setup = vec![slot("speaker"), Arg::U64(frames)];
        setup.extend(self.program.setup.iter().map(Self::operand));
        let mut calls = vec![
            Call {
                entry: WEIGHT_ENTRY.into(),
                args: self.program.raw.clone(),
                bind: (0..self.program.outputs)
                    .map(|i| Bind::Name(format!("weight-{i}")))
                    .collect(),
            },
            Call {
                entry: VOICE_ENTRY.into(),
                args: vec![self.voice_arg.clone()],
                bind: vec![Bind::Name("speaker".into())],
            },
            Call {
                entry: "phonon.setup".into(),
                args: setup,
                // The text budget is checked when the package is opened.
                bind: ["voice", "cond", "bos", "time"]
                    .map(|name| Bind::Name(name.into()))
                    .into_iter()
                    .chain([Bind::Discard])
                    .collect(),
            },
        ];
        let (mut inputs, mut outputs) = (Vec::new(), Vec::new());
        for (i, prompt) in prompts.iter().enumerate() {
            let (ids, waveform, result) = (
                format!("ids-{i:02}"),
                format!("waveform-{i:02}"),
                format!("result-{i:02}"),
            );
            let tokens = prompt.ids.len();
            let [std, mean] = self.program.latents.each_ref().map(Self::operand);
            let mut args = vec![
                Arg::Input {
                    object: ids.clone(),
                },
                slot("voice"),
                slot("bos"),
                slot("cond"),
                slot("time"),
                Arg::Zeroed {
                    bytes: phonon::SCRATCH as u64 * 4,
                },
                std,
                mean,
                Arg::U64(frames),
                Arg::U64(tokens as u64),
                Arg::U64(prompt.words as u64),
                Arg::U64(SEED),
                Arg::U64(i as u64),
            ];
            args.extend(self.program.synth.iter().map(Self::operand));
            calls.push(Call {
                entry: "phonon.synthesize".into(),
                args,
                bind: vec![Bind::Name(waveform.clone()), Bind::Name(result.clone())],
            });
            inputs.push(Artifact::new(
                ids,
                "catena.u64le.v1",
                prompt.ids.iter().flat_map(|id| id.to_le_bytes()).collect(),
            ));
            outputs.extend([
                Declared {
                    slot: result,
                    kind: OutputKind::Buffer { max_bytes: 16 },
                },
                Declared {
                    slot: waveform,
                    kind: OutputKind::Buffer {
                        max_bytes: phonon::waveform_samples(tokens) as u64 * 4,
                    },
                },
            ]);
        }
        Ok(ComputeJob {
            environment: environment.clone(),
            content: content.clone(),
            inputs,
            plan: Plan {
                calls,
                step: None,
                outputs,
            },
        })
    }
}

/// Utterances in order, separated by short pauses.
pub(super) fn decode(output: &InvocationOutput) -> Result<Audio> {
    let artifact = |name: String| -> Result<&[u8]> {
        let artifact = output
            .artifacts
            .iter()
            .find(|a| a.name == name)
            .with_context(|| format!("missing speech artifact {name}"))?;
        ensure!(
            artifact.format == "catena.bytes.v1",
            "invalid speech artifact"
        );
        Ok(artifact.bytes.as_bytes())
    };
    let mut samples = Vec::new();
    let utterances = output.artifacts.len() / 2;
    if utterances == 0 || output.artifacts.len() != utterances * 2 {
        bail!("expected a waveform and result per utterance");
    }
    for i in 0..utterances {
        let (result, []) = artifact(format!("result-{i:02}"))?.as_chunks::<8>() else {
            bail!("invalid speech result descriptor");
        };
        let result: Vec<u64> = result
            .iter()
            .map(|bytes| u64::from_le_bytes(*bytes))
            .collect();
        let waveform = floats_f32(artifact(format!("waveform-{i:02}"))?)?;
        if i > 0 {
            samples.resize(samples.len() + phonon::PAUSE_SAMPLES, 0.);
        }
        samples.extend(phonon::decode_utterance(&result, waveform)?);
    }
    Ok(Audio {
        samples,
        sample_rate: phonon::SAMPLE_RATE,
    })
}

#[cfg(test)]
mod tests;
