//! Phonon voices, weight packaging and the portable synthesis ABI.
use super::{Audio, floats_f32};
use crate::model::package::ComputeJob;
use anyhow::{Context, Result, bail, ensure};
/// The codec and voice repositories every checkpoint shares, and the
/// published files a conversion reads.
pub use catena_models::phonon::{
    CODEC as CODEC_REPO, CODEC_FILES, MODEL_FILES, VOICE_CATALOG, VOICE_REPO,
};
use catena_models::{
    phonon::{self, Binding, Config, Prompt},
    weights::{Weights, f32_to_bf16},
};
use hellas_rpc::protocol::invocation::{
    Artifact, MAX_ARTIFACTS, compute::*, output::InvocationOutput,
};
use hellas_store::content::{LocalStore, Scope};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

const WEIGHTS: &str = "weights";
const ASSETS_FILE: &str = "assets.json";
const MODEL: &str = "model";
const CODEC: &str = "codec";
const VOICES: &str = "voices";
/// A converted package holds the model's processor configuration here.
pub(in crate::model) const MARKER: &str = "model/processor_config.json";
/// Bytes per frame of a converted BF16 voice.
const VOICE_FRAME_BYTES: u64 = phonon::VOICE_CHANNELS as u64 * 2;
/// Sampling is seeded; the speech API has no seed, so every request uses this.
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

fn voice_asset(name: &str) -> String {
    format!("voice-{name}")
}

/// The frames of a converted voice, which must leave room for text.
fn voice_frames(bytes: u64) -> Result<u64> {
    let frames = bytes / VOICE_FRAME_BYTES;
    ensure!(bytes == frames * VOICE_FRAME_BYTES, "invalid voice length");
    phonon::text_limit(usize::try_from(frames)?)?;
    Ok(frames)
}

/// Byte ranges of the weight asset: each distinct binding once, in entry
/// order, then the two latent statistics. Every range starts on a four-byte
/// boundary, as separately allocated tensors would.
struct Views {
    bindings: BTreeMap<Vec<String>, (u64, u64)>,
    latents: [(u64, u64); 2],
    bytes: u64,
}
const LATENTS: [&str; 2] = [phonon::LATENT_STD, phonon::LATENT_MEAN];
const LATENT_BYTES: u64 = phonon::LATENT as u64 * 2;

fn entries(config: &Config) -> Result<[Vec<Binding>; 2]> {
    Ok([
        phonon::bindings(config, "setup")?,
        phonon::bindings(config, "synthesize")?,
    ])
}

fn distinct(entries: &[Vec<Binding>; 2]) -> impl Iterator<Item = &Binding> {
    let mut seen = std::collections::BTreeSet::new();
    entries
        .iter()
        .flatten()
        .filter(move |binding| seen.insert(&binding.names))
}

fn views(entries: &[Vec<Binding>; 2]) -> Views {
    let mut end = 0u64;
    let mut place = |bytes: u64| {
        let offset = end.next_multiple_of(4);
        end = offset + bytes;
        (offset, bytes)
    };
    let bindings = distinct(entries)
        .map(|binding| (binding.names.clone(), place(binding.bytes() as u64)))
        .collect();
    let latents = [place(LATENT_BYTES), place(LATENT_BYTES)];
    Views {
        bindings,
        latents,
        bytes: end,
    }
}

fn read_config(dir: &Path) -> Result<Config> {
    Config::read(&dir.join(MODEL), &dir.join(CODEC))
}

/// Convert published model and codec snapshots and catalog voices into one
/// package. `voices` pairs each voice name with its checkpoint file.
pub fn convert(
    model: &Path,
    codec: &Path,
    voices: &[(String, PathBuf)],
    destination: &Path,
) -> Result<Vec<NamedAsset>> {
    ensure!(!destination.try_exists()?, "destination already exists");
    ensure!(!voices.is_empty(), "a speech package needs a voice");
    let config = Config::read(model, codec)?;
    phonon::read_tokenizer(model)?;
    let (model_weights, codec_weights) = (
        Weights::open(&model.join("model.safetensors"))?,
        Weights::open(&codec.join("model.safetensors"))?,
    );
    phonon::validate_weights(&model_weights, &codec_weights, &config)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".speech-")
        .tempdir_in(parent)?;
    let asset =
        |name: String, path: &Path, values: &mut dyn FnMut(&mut dyn Write) -> Result<()>| {
            let mut file = BufWriter::new(File::create(path)?);
            values(&mut file)?;
            file.flush()?;
            file.get_ref().sync_all()?;
            drop(file);
            Ok::<_, anyhow::Error>(NamedAsset {
                name,
                object: hellas_store::content::file_content(path)?,
            })
        };
    let bf16 = |file: &mut dyn Write, values: &[f32]| -> Result<()> {
        for &value in values {
            file.write_all(&f32_to_bf16(value).to_le_bytes())?;
        }
        Ok(())
    };
    let entries = entries(&config)?;
    let layout = views(&entries);
    let mut assets = vec![asset(
        WEIGHTS.into(),
        &staging.path().join("weights.bin"),
        &mut |file| {
            let mut written = 0;
            let mut put = |(offset, bytes): (u64, u64), values: &[f32], f32: bool| {
                let mut encoded = Vec::new();
                if f32 {
                    encoded.extend(values.iter().flat_map(|value| value.to_le_bytes()));
                } else {
                    bf16(&mut encoded, values)?;
                }
                ensure!(
                    encoded.len() as u64 == bytes,
                    "weight has an unexpected size"
                );
                file.write_all(&vec![0; (offset - written) as usize])?;
                written = offset + bytes;
                file.write_all(&encoded)?;
                Ok(())
            };
            for binding in distinct(&entries) {
                let values = phonon::materialize(&model_weights, &codec_weights, binding)?;
                put(layout.bindings[&binding.names], &values, binding.codec)?;
            }
            for (name, view) in LATENTS.into_iter().zip(layout.latents) {
                put(view, &model_weights.host_f32(name)?, false)?;
            }
            Ok(())
        },
    )?];
    ensure!(
        assets[0].object.bytes() == layout.bytes,
        "derived weight file has wrong length"
    );
    std::fs::create_dir(staging.path().join(VOICES))?;
    for (name, path) in voices {
        validate_voice(name)?;
        let voice = phonon::read_voice(path)?;
        let path = staging.path().join(VOICES).join(format!("{name}.bf16"));
        let voice = asset(voice_asset(name), &path, &mut |file| {
            bf16(file, &voice.values)
        })?;
        voice_frames(voice.object.bytes())?;
        ensure!(
            assets.iter().all(|asset| asset.name != voice.name),
            "duplicate voice {name:?}"
        );
        assets.push(voice);
    }
    for (directory, source, files) in [
        (MODEL, model, &phonon::MODEL_FILES[..]),
        (CODEC, codec, &phonon::CODEC_FILES[..]),
    ] {
        std::fs::create_dir(staging.path().join(directory))?;
        for name in files.iter().filter(|name| name.ends_with(".json")) {
            std::fs::copy(source.join(name), staging.path().join(directory).join(name))?;
        }
    }
    std::fs::write(
        staging.path().join(ASSETS_FILE),
        serde_json::to_vec_pretty(&assets)?,
    )?;
    std::fs::rename(staging.path(), destination)?;
    Ok(assets)
}

pub(in crate::model) struct Phonon {
    tokenizer: tokenizers::Tokenizer,
    entries: [Vec<Binding>; 2],
    views: Views,
    /// Frames of each packaged voice, by name.
    voices: BTreeMap<String, u64>,
}

impl Phonon {
    /// The package's program source and assets.
    pub fn open(dir: &Path) -> Result<(Self, String, Vec<NamedAsset>)> {
        let config = read_config(dir)?;
        let assets: Vec<NamedAsset> = serde_json::from_reader(File::open(dir.join(ASSETS_FILE))?)?;
        let entries = entries(&config)?;
        let views = views(&entries);
        let (weights, voice_assets) = assets.split_first().context("package has no assets")?;
        ensure!(
            weights.name == WEIGHTS && weights.object.bytes() == views.bytes,
            "derived weight file has wrong length"
        );
        let mut voices = BTreeMap::new();
        for asset in voice_assets {
            let name = asset
                .name
                .strip_prefix("voice-")
                .context("unexpected package asset")?;
            validate_voice(name)?;
            ensure!(
                voices
                    .insert(name.to_owned(), voice_frames(asset.object.bytes())?)
                    .is_none(),
                "duplicate voice {name:?}"
            );
        }
        ensure!(!voices.is_empty(), "a speech package needs a voice");
        Ok((
            Self {
                tokenizer: phonon::read_tokenizer(&dir.join(MODEL))?,
                entries,
                views,
                voices,
            },
            phonon::bundle(&config),
            assets,
        ))
    }

    fn weights(&self, entry: usize) -> impl Iterator<Item = Arg> {
        self.entries[entry].iter().map(|binding| {
            let (offset, bytes) = self.views.bindings[&binding.names];
            Arg::Asset {
                name: WEIGHTS.into(),
                offset,
                bytes,
            }
        })
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
        let frames = *self
            .voices
            .get(voice)
            .with_context(|| format!("unknown voice {voice:?}"))?;
        let prompts = Prompt::split(&self.tokenizer, text)?;
        ensure!(
            prompts.len() <= MAX_ARTIFACTS / 2,
            "text splits into more than {} utterances",
            MAX_ARTIFACTS / 2
        );
        let slot = |name: &str| Arg::Slot { name: name.into() };
        let mut setup = vec![
            Arg::Asset {
                name: voice_asset(voice),
                offset: 0,
                bytes: frames * VOICE_FRAME_BYTES,
            },
            Arg::U64(frames),
        ];
        setup.extend(self.weights(0));
        let mut calls = vec![Call {
            entry: "phonon.setup".into(),
            args: setup,
            // The text budget is checked when the package is opened.
            bind: ["voice", "cond", "bos", "time"]
                .map(|name| Bind::Name(name.into()))
                .into_iter()
                .chain([Bind::Discard])
                .collect(),
        }];
        let (mut inputs, mut outputs) = (Vec::new(), Vec::new());
        for (i, prompt) in prompts.iter().enumerate() {
            let (ids, waveform, result) = (
                format!("ids-{i:02}"),
                format!("waveform-{i:02}"),
                format!("result-{i:02}"),
            );
            let tokens = prompt.ids.len();
            let [std, mean] = self.views.latents.map(|(offset, bytes)| Arg::Asset {
                name: WEIGHTS.into(),
                offset,
                bytes,
            });
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
            args.extend(self.weights(1));
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
