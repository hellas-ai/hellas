//! Model selection and resolution from immutable Hub references or local checkpoints.
mod peer;
use super::{ModelFiles, ModelKind, gguf, native, qwen3};
use anyhow::{Context, Result, ensure};
use hellas_rpc::ContentRef;
use hellas_store::{content::DiskStore, hf::PinnedFile};
pub(crate) use peer::PeerModel;
pub use peer::{CatalogUnavailable, acquire_peer_model, publish_model};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

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

pub(super) struct Gguf {
    pub path: Arc<GgufPath>,
    pub header: Arc<gguf::Header>,
    pub weights: ContentRef,
}

impl Gguf {
    fn remote(
        name: &Path,
        object: ContentRef,
        read: impl FnMut(std::ops::Range<u64>, &mut Vec<u8>) -> std::io::Result<()>,
    ) -> Result<Self> {
        let (header, bytes) = gguf::remote_header(object.bytes(), read)?;
        let mut output = tempfile::Builder::new().suffix(".gguf").tempfile()?;
        output.write_all(&bytes)?;
        Ok(Self {
            path: Arc::new(GgufPath::Header(output, name.to_owned())),
            header: Arc::new(header),
            weights: object,
        })
    }
    fn hub(file: &PinnedFile) -> Result<Self> {
        Self::remote(Path::new(&file.path), file.object, |range, bytes| {
            file.read_range(range, bytes).map_err(std::io::Error::other)
        })
    }

    fn peer(peer: &PeerModel) -> Result<Self> {
        Self::remote(
            Path::new("model.gguf"),
            peer.object("weights")?,
            |range, bytes| {
                bytes.extend_from_slice(
                    &peer.read("weights", range).map_err(std::io::Error::other)?,
                );
                Ok(())
            },
        )
    }
}

pub(super) enum Resolved {
    Gguf(Gguf),
    Native(native::Kind, Arc<native::Native>),
}

pub(super) enum Source {
    LocalGguf(PathBuf),
    HubGguf(PinnedFile),
    PeerGguf(PeerModel),
    Checkpoint(native::Kind, native::Origin, String),
}
impl Source {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(uri) = path.to_str().filter(|s| s.starts_with("hellas://")) {
            return Self::peer(PeerModel::open(uri)?);
        }
        if let Some(uri) = super::hf_uri(path) {
            let (repo, selector) = native::hub(uri)?;
            if selector.as_deref().is_some_and(|key| {
                Path::new(key)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("gguf"))
            }) {
                return Ok(Self::HubGguf(repo.select("gguf", selector.as_deref())?));
            }
            let name = repo.repo.id.rsplit('/').next().unwrap().to_owned();
            let origin = native::Origin::Hub(repo);
            if let Some(kind) = origin.kind()? {
                ensure!(
                    selector
                        .as_deref()
                        .is_none_or(|s| s == "model.safetensors" && kind != native::Kind::Flux),
                    "select the checkpoint root for this model"
                );
                return Ok(Self::Checkpoint(kind, origin, name));
            }
            let native::Origin::Hub(repo) = origin else {
                unreachable!()
            };
            return Ok(Self::HubGguf(repo.select("gguf", selector.as_deref())?));
        }
        let directory = if std::fs::metadata(path)?.is_file() {
            if path.extension().is_none_or(|ext| ext != "safetensors") {
                return Ok(Self::LocalGguf(path.to_owned()));
            }
            ensure!(
                path.file_name().is_some_and(|s| s == "model.safetensors"),
                "select the checkpoint root or model.safetensors"
            );
            path.parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
        } else {
            path
        };
        let origin = native::Origin::Local(directory.to_owned());
        let kind = origin.kind()?.context("unrecognized model checkpoint")?;
        let name = directory
            .canonicalize()?
            .file_name()
            .and_then(|n| n.to_str())
            .context("checkpoint needs a UTF-8 directory name")?
            .to_owned();
        Ok(Self::Checkpoint(kind, origin, name))
    }

    fn peer(peer: PeerModel) -> Result<Self> {
        if peer.model.assets.len() == 1 && peer.model.assets[0].name == "weights" {
            return Ok(Self::PeerGguf(peer));
        }
        let name = peer.model.content_id()?.to_string();
        let origin = native::Origin::Peer(peer);
        let kind = origin.kind()?.context("unrecognized peer checkpoint")?;
        Ok(Self::Checkpoint(kind, origin, name))
    }

    pub fn named(&self) -> Result<(ModelKind, String)> {
        fn gguf_kind(path: &Path) -> Result<ModelKind> {
            Ok(if qwen3::is_decision(path)? {
                ModelKind::Decision
            } else {
                ModelKind::Text
            })
        }
        Ok(match self {
            Self::LocalGguf(path) => (gguf_kind(path)?, super::package::model_name(path)?.into()),
            Self::HubGguf(file) => {
                let gguf = Gguf::hub(file)?;
                (
                    gguf_kind(gguf.path.as_ref().as_ref())?,
                    super::package::model_name(gguf.path.source())?.into(),
                )
            }
            Self::PeerGguf(peer) => {
                let gguf = Gguf::peer(peer)?;
                (
                    gguf_kind(gguf.path.as_ref().as_ref())?,
                    peer.model.content_id()?.to_string(),
                )
            }
            Self::Checkpoint(kind, _, name) => (
                match kind {
                    native::Kind::Flux => ModelKind::Image,
                    native::Kind::Whisper => ModelKind::Transcription,
                    native::Kind::OmniVoice | native::Kind::Phonon | native::Kind::Mms => {
                        ModelKind::Speech
                    }
                },
                name.clone(),
            ),
        })
    }

    pub fn files(self) -> Result<ModelFiles> {
        Ok(match self {
            Self::LocalGguf(path) => ModelFiles {
                local: vec![path],
                hub: vec![],
            },
            Self::PeerGguf(_) => ModelFiles {
                local: vec![],
                hub: vec![],
            },
            Self::HubGguf(file) => ModelFiles {
                local: vec![],
                hub: vec![file],
            },
            Self::Checkpoint(kind, origin, _) => native::Snapshot::open(origin, kind)?.files(),
        })
    }
    pub fn resolve(self, store: Option<&DiskStore>) -> Result<Resolved> {
        Ok(match self {
            Self::PeerGguf(peer) => Resolved::Gguf(Gguf::peer(&peer)?),
            Self::HubGguf(file) => Resolved::Gguf(Gguf::hub(&file)?),
            Self::LocalGguf(path) => {
                let weights = match store {
                    Some(store) => tokio::runtime::Handle::current()
                        .block_on(store.inspect_files(vec![path.clone()]))?
                        .get(&path)
                        .copied()
                        .context("missing inspected GGUF file")?,
                    None => hellas_store::content::file_content(&path)?,
                };
                let header = gguf::read_header(&mut hellas_private::open_regular_file(&path)?)?;
                Resolved::Gguf(Gguf {
                    path: Arc::new(GgufPath::Local(path)),
                    header: Arc::new(header),
                    weights,
                })
            }
            Self::Checkpoint(kind, origin, _) => Resolved::Native(
                kind,
                Arc::new(native::Snapshot::open(origin, kind)?.resolve(store)?),
            ),
        })
    }
}

impl super::ModelPackage {
    /// Render from an existing Content connection, using its server-bound read authority.
    pub async fn open_peer(
        id: hellas_rpc::ContentId,
        store: impl hellas_store::content::ContentStore + 'static,
        evaluator: &str,
    ) -> Result<Self> {
        let dialect = super::renderer(evaluator)?;
        let resolved = tokio::task::spawn_blocking(move || {
            Source::peer(PeerModel::connect(id, async move { Ok((store, None)) })?)?.resolve(None)
        })
        .await??;
        Self::open_resolved(&resolved, evaluator, dialect).await
    }
}
