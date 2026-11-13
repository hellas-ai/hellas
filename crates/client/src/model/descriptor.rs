//! A model's native metadata and the identity of its separately held weights.
use super::{ModelKind, gguf, qwen3, whisper};
use anyhow::{Result, ensure};
use hellas_rpc::{ContentId, ContentRef};
use hellas_store::{content::Reservations, fastresume::Records};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
};

const MANIFEST: &str = "descriptor.json";
pub(super) const GGUF: &str = "header.gguf";
const MAX_METADATA: usize = 64 << 20;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    weights: ContentRef,
}

pub(super) fn is_descriptor(path: &Path) -> bool {
    path.join(MANIFEST).is_file()
}

pub(super) fn weights(path: &Path) -> Result<Option<ContentRef>> {
    if !is_descriptor(path) {
        return Ok(None);
    }
    let bytes = hellas_private::read_bounded_regular_file(&path.join(MANIFEST), 4096)?;
    let descriptor: Descriptor = serde_json::from_slice(&bytes)?;
    ensure!(
        descriptor.weights.bytes() > 0,
        "descriptor weights are empty"
    );
    Ok(Some(descriptor.weights))
}

pub(super) fn gguf_path(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join(GGUF)
    } else {
        path.to_owned()
    }
}

pub(super) fn weights_path(path: &Path) -> Option<PathBuf> {
    if is_descriptor(path) {
        return None;
    }
    match ModelKind::of(path) {
        ModelKind::Text => Some(path.to_owned()),
        ModelKind::Transcription => Some(path.join(whisper::WEIGHTS_FILE)),
        ModelKind::Image => None,
    }
}

/// Direct clients share file identities across opens and evaluators. Daemon
/// callers supply the reference already inspected by their content store.
/// Serialize inspection so concurrent first opens cannot hash the same file twice.
pub(super) fn file_content(path: &Path) -> Result<ContentRef> {
    static RECORDS: LazyLock<Mutex<Records>> = LazyLock::new(Mutex::default);
    let indexed = RECORDS.lock().unwrap().index_file(
        path,
        &Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
        false,
    )?;
    Ok(ContentRef::new(
        ContentId::from_bytes(indexed.id.into_bytes()),
        indexed.len,
    ))
}

/// Write a new descriptor directory, without copying any tensor data.
pub(super) fn describe(path: &Path, output: &Path) -> Result<ContentRef> {
    ensure!(!output.try_exists()?, "destination already exists");
    ensure!(!is_descriptor(path), "source is already a descriptor");
    let kind = ModelKind::of(path);
    ensure!(
        kind != ModelKind::Image,
        "Flux already describes its assets in assets.json"
    );
    let weights_path = weights_path(path).expect("Qwen and Whisper have weights");
    let identity = hellas_store::fastresume::FileIdentity::of(&std::fs::metadata(&weights_path)?);
    let object = file_content(&weights_path)?;
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".descriptor-")
        .tempdir_in(parent)?;
    match kind {
        ModelKind::Text => {
            let mut input = hellas_private::open_regular_file(path)?;
            let header = gguf::read_header(&mut input)?;
            ensure!(
                header.data_offset <= MAX_METADATA as u64,
                "GGUF header is too large"
            );
            use std::io::{Seek, SeekFrom};
            input.seek(SeekFrom::Start(0))?;
            let mut out = File::create(staging.path().join(GGUF))?;
            ensure!(
                std::io::copy(&mut input.take(header.data_offset), &mut out)? == header.data_offset,
                "GGUF header changed while describing model"
            );
            out.sync_all()?;
            qwen3::metadata(&staging.path().join(GGUF), Some(object.bytes()))?;
        }
        ModelKind::Transcription => {
            for name in whisper::METADATA {
                let bytes =
                    hellas_private::read_bounded_regular_file(&path.join(name), MAX_METADATA)?;
                std::fs::write(staging.path().join(name), bytes)?;
            }
            whisper::validate_metadata(staging.path(), object)?;
        }
        ModelKind::Image => unreachable!("Flux has its own asset descriptors"),
    }
    ensure!(
        identity == hellas_store::fastresume::FileIdentity::of(&std::fs::metadata(&weights_path)?),
        "weights changed while describing model"
    );
    let mut manifest = File::create(staging.path().join(MANIFEST))?;
    serde_json::to_writer_pretty(&mut manifest, &Descriptor { weights: object })?;
    manifest.write_all(b"\n")?;
    manifest.sync_all()?;
    std::fs::rename(staging.path(), output)?;
    Ok(object)
}
