//! A model's native metadata and the identity of its separately held weights.
use super::{ModelKind, gguf, qwen3, whisper};
use anyhow::{Result, bail, ensure};
use hellas_rpc::ContentRef;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

const MANIFEST: &str = "descriptor.json";
const GGUF: &str = "header.gguf";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    weights: ContentRef,
}

#[derive(Clone, Copy)]
pub(super) enum Layout {
    Gguf,
    GgufDescriptor,
    Whisper,
    WhisperDescriptor,
    Flux,
}

pub(super) enum Resolved {
    Gguf {
        path: PathBuf,
        header: Arc<gguf::Header>,
        weights: ContentRef,
    },
    Whisper {
        path: PathBuf,
        weights: ContentRef,
    },
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
    let gguf = path.join(GGUF).try_exists()?;
    let weights = path.join(whisper::WEIGHTS_FILE).try_exists()?;
    let whisper = whisper::METADATA.iter().try_fold(false, |found, name| {
        Ok::<_, std::io::Error>(path.join(name).try_exists()? || found)
    })?;
    let flux = path.join("model_index.json").try_exists()?;
    ensure!(
        !(flux && (manifest || gguf || whisper || weights)
            || gguf && (whisper || weights)
            || manifest && weights),
        "mixed model layout: descriptor, GGUF, Whisper and Flux files cannot overlap"
    );
    if flux {
        return Ok(Layout::Flux);
    }
    if gguf {
        ensure!(manifest, "header.gguf requires descriptor.json");
        return Ok(Layout::GgufDescriptor);
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
    pub(super) fn kind(self) -> ModelKind {
        match self {
            Self::Gguf | Self::GgufDescriptor => ModelKind::Text,
            Self::Whisper | Self::WhisperDescriptor => ModelKind::Transcription,
            Self::Flux => ModelKind::Image,
        }
    }
    pub(super) fn is_descriptor(self) -> bool {
        matches!(self, Self::GgufDescriptor | Self::WhisperDescriptor)
    }
    pub(super) fn gguf_path(self, path: &Path) -> Result<PathBuf> {
        match self {
            Self::Gguf => Ok(path.to_owned()),
            Self::GgufDescriptor => Ok(path.join(GGUF)),
            _ => bail!("model package is not GGUF"),
        }
    }
    pub(super) fn weights_path(self, path: &Path) -> Option<PathBuf> {
        match self {
            Self::Gguf => Some(path.to_owned()),
            Self::Whisper => Some(path.join(whisper::WEIGHTS_FILE)),
            Self::GgufDescriptor | Self::WhisperDescriptor | Self::Flux => None,
        }
    }
    pub(super) fn resolve(self, path: &Path, inspected: Option<ContentRef>) -> Result<Resolved> {
        let weights =
            |file: &Path| inspected.map_or_else(|| hellas_store::content::file_content(file), Ok);
        match self {
            Self::Gguf => Ok(Resolved::Gguf {
                path: path.to_owned(),
                header: Arc::new(gguf::read_header(&mut hellas_private::open_regular_file(
                    path,
                )?)?),
                weights: weights(path)?,
            }),
            Self::GgufDescriptor => {
                let weights = read_weights(path)?;
                let path = path.join(GGUF);
                let header = gguf::read_descriptor(
                    &mut hellas_private::open_regular_file(&path)?,
                    weights.bytes(),
                )?;
                Ok(Resolved::Gguf {
                    path,
                    header: Arc::new(header),
                    weights,
                })
            }
            Self::Whisper => Ok(Resolved::Whisper {
                path: path.to_owned(),
                weights: weights(&path.join(whisper::WEIGHTS_FILE))?,
            }),
            Self::WhisperDescriptor => Ok(Resolved::Whisper {
                path: path.to_owned(),
                weights: read_weights(path)?,
            }),
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
        Layout::Gguf => write_descriptor(path, output, |staging, object| {
            let mut input = hellas_private::open_regular_file(path)?;
            let header = gguf::read_header(&mut input)?;
            use std::io::{Seek, SeekFrom};
            input.seek(SeekFrom::Start(0))?;
            let header_path = staging.join(GGUF);
            let mut out = File::create(&header_path)?;
            ensure!(
                std::io::copy(&mut input.take(header.data_offset), &mut out)? == header.data_offset,
                "GGUF header changed while describing model"
            );
            let header = gguf::read_descriptor(&mut File::open(&header_path)?, object.bytes())?;
            qwen3::metadata(&header_path, &header)?;
            Ok(())
        }),
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
        Layout::GgufDescriptor | Layout::WhisperDescriptor => {
            bail!("source is already a descriptor")
        }
        Layout::Flux => bail!("Flux already describes its assets in assets.json"),
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
