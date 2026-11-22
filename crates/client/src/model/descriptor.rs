//! A model's native metadata and the identity of its separately held weights.
use super::{ModelKind, gguf, qwen3, speech, whisper};
use anyhow::{Result, bail, ensure};
use hellas_rpc::ContentRef;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write as _};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const MANIFEST: &str = "descriptor.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    weights: ContentRef,
}

#[derive(Clone, Copy)]
pub(super) enum Layout {
    Gguf,
    Whisper,
    WhisperDescriptor,
    Speech,
    SpeechDescriptor,
    Phonon,
    Flux,
}

pub(super) enum GgufPath {
    Local(PathBuf),
    Header(tempfile::NamedTempFile, PathBuf),
}
impl GgufPath {
    pub(super) fn source(&self) -> &Path {
        match self {
            Self::Local(path) | Self::Header(_, path) => path,
        }
    }
}
impl AsRef<Path> for GgufPath {
    fn as_ref(&self) -> &Path {
        match self {
            Self::Local(path) => path,
            Self::Header(file, _) => file.path(),
        }
    }
}

pub(super) fn remote(uri: &str) -> Result<Resolved> {
    let file = super::pinned_gguf(uri)?;
    let (header, bytes) = gguf::remote_header(&file)?;
    let mut output = tempfile::Builder::new().suffix(".gguf").tempfile()?;
    std::io::Write::write_all(&mut output, &bytes)?;
    Ok(Resolved::Gguf {
        path: Arc::new(GgufPath::Header(output, file.path.into())),
        header: Arc::new(header),
        weights: file.object,
    })
}

pub(super) enum Resolved {
    Gguf {
        path: Arc<GgufPath>,
        header: Arc<gguf::Header>,
        weights: ContentRef,
    },
    Whisper {
        path: PathBuf,
        weights: ContentRef,
    },
    Speech {
        path: PathBuf,
        weights: ContentRef,
    },
    Phonon(PathBuf),
    Flux(PathBuf),
}

/// Classify the native layout before interpreting any weight identity.
pub(super) fn classify(path: &Path) -> Result<Layout> {
    let metadata = std::fs::metadata(path)?;
    if metadata.is_file() {
        return Ok(Layout::Gguf);
    }
    ensure!(
        metadata.is_dir(),
        "model package is not a regular file or directory"
    );
    let manifest = path.join(MANIFEST).try_exists()?;
    let weights = path.join(whisper::WEIGHTS_FILE).try_exists()?;
    let whisper = whisper::METADATA.iter().try_fold(false, |found, name| {
        Ok::<_, std::io::Error>(path.join(name).try_exists()? || found)
    })?;
    let speech = speech::METADATA[1..]
        .iter()
        .try_fold(false, |found, name| {
            Ok::<_, std::io::Error>(path.join(name).try_exists()? || found)
        })?;
    let flux = path.join("model_index.json").try_exists()?;
    let phonon = path.join(speech::phonon::MARKER).try_exists()?;
    ensure!(
        !((flux || phonon) && (manifest || whisper || speech || weights)
            || flux && phonon
            || manifest && weights),
        "mixed model layout: descriptor, GGUF, Whisper, MMS, Phonon and Flux files cannot overlap"
    );
    if flux {
        return Ok(Layout::Flux);
    }
    if phonon {
        return Ok(Layout::Phonon);
    }
    if speech {
        ensure!(
            manifest || weights,
            "MMS package requires weights or a descriptor"
        );
        ensure!(
            !path.join("generation_config.json").try_exists()?
                && !path.join("tokenizer.json").try_exists()?,
            "mixed MMS and Whisper metadata"
        );
        return Ok(if manifest {
            Layout::SpeechDescriptor
        } else {
            Layout::Speech
        });
    }
    if manifest {
        ensure!(whisper, "descriptor.json requires GGUF or Whisper metadata");
        return Ok(Layout::WhisperDescriptor);
    }
    ensure!(
        whisper && weights,
        "Whisper package requires metadata and weights.bf16"
    );
    Ok(Layout::Whisper)
}

impl Layout {
    pub(super) fn kind(self, path: &Path) -> Result<ModelKind> {
        Ok(match self {
            Self::Gguf => {
                if qwen3::is_decision(path)? {
                    ModelKind::Decision
                } else {
                    ModelKind::Text
                }
            }
            Self::Whisper | Self::WhisperDescriptor => ModelKind::Transcription,
            Self::Flux => ModelKind::Image,
            Self::Speech | Self::SpeechDescriptor | Self::Phonon => ModelKind::Speech,
        })
    }
    pub(super) fn is_descriptor(self) -> bool {
        matches!(self, Self::WhisperDescriptor | Self::SpeechDescriptor)
    }
    pub(super) fn weights_path(self, path: &Path) -> Option<PathBuf> {
        match self {
            Self::Gguf => Some(path.to_owned()),
            Self::Whisper | Self::Speech => Some(path.join(whisper::WEIGHTS_FILE)),
            Self::WhisperDescriptor | Self::SpeechDescriptor | Self::Phonon | Self::Flux => None,
        }
    }
    pub(super) fn resolve(self, path: &Path, inspected: Option<ContentRef>) -> Result<Resolved> {
        let weights =
            |file: &Path| inspected.map_or_else(|| hellas_store::content::file_content(file), Ok);
        match self {
            Self::Gguf => Ok(Resolved::Gguf {
                path: Arc::new(GgufPath::Local(path.to_owned())),
                header: Arc::new(gguf::read_header(&mut hellas_private::open_regular_file(
                    path,
                )?)?),
                weights: weights(path)?,
            }),
            Self::Whisper => Ok(Resolved::Whisper {
                path: path.to_owned(),
                weights: weights(&path.join(whisper::WEIGHTS_FILE))?,
            }),
            Self::WhisperDescriptor => Ok(Resolved::Whisper {
                path: path.to_owned(),
                weights: read_weights(path)?,
            }),
            Self::Speech => Ok(Resolved::Speech {
                path: path.to_owned(),
                weights: weights(&path.join(speech::WEIGHTS_FILE))?,
            }),
            Self::SpeechDescriptor => Ok(Resolved::Speech {
                path: path.to_owned(),
                weights: read_weights(path)?,
            }),
            Self::Phonon => Ok(Resolved::Phonon(path.to_owned())),
            Self::Flux => Ok(Resolved::Flux(path.to_owned())),
        }
    }
}

fn read_weights(path: &Path) -> Result<ContentRef> {
    let bytes = hellas_private::read_bounded_regular_file(&path.join(MANIFEST), 4096)?;
    let descriptor: Descriptor = serde_json::from_slice(&bytes)?;
    ensure!(
        descriptor.weights.bytes() > 0,
        "descriptor weights are empty"
    );
    Ok(descriptor.weights)
}

/// Write a new descriptor directory, without copying any tensor data.
pub(super) fn describe(path: &Path, output: &Path) -> Result<ContentRef> {
    ensure!(!output.try_exists()?, "destination already exists");
    match classify(path)? {
        Layout::Gguf => bail!("use a pinned hf:// reference or the local GGUF file"),
        Layout::Whisper => write_descriptor(
            &path.join(whisper::WEIGHTS_FILE),
            output,
            |staging, object| {
                for name in whisper::METADATA {
                    let bytes = hellas_private::read_bounded_regular_file(
                        &path.join(name),
                        whisper::MAX_METADATA_BYTES,
                    )?;
                    std::fs::write(staging.join(name), bytes)?;
                }
                whisper::validate_metadata(staging, object)
            },
        ),
        Layout::Speech => write_descriptor(
            &path.join(speech::WEIGHTS_FILE),
            output,
            |staging, object| {
                for name in speech::METADATA {
                    std::fs::write(
                        staging.join(name),
                        hellas_private::read_bounded_regular_file(
                            &path.join(name),
                            speech::MAX_METADATA_BYTES,
                        )?,
                    )?;
                }
                speech::validate_metadata(staging, object)
            },
        ),
        Layout::WhisperDescriptor | Layout::SpeechDescriptor => {
            bail!("source is already a descriptor")
        }
        Layout::Flux | Layout::Phonon => {
            bail!("the package already describes its assets in assets.json")
        }
    }
}

fn write_descriptor(
    weights: &Path,
    output: &Path,
    metadata: impl FnOnce(&Path, ContentRef) -> Result<()>,
) -> Result<ContentRef> {
    let identity = hellas_store::fastresume::FileIdentity::of(&std::fs::metadata(weights)?);
    let object = hellas_store::content::file_content(weights)?;
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".descriptor-")
        .tempdir_in(parent)?;
    metadata(staging.path(), object)?;
    ensure!(
        identity == hellas_store::fastresume::FileIdentity::of(&std::fs::metadata(weights)?),
        "weights changed while describing model"
    );
    let mut manifest = File::create(staging.path().join(MANIFEST))?;
    serde_json::to_writer_pretty(&mut manifest, &Descriptor { weights: object })?;
    manifest.write_all(b"\n")?;
    std::fs::rename(staging.path(), output)?;
    Ok(object)
}
