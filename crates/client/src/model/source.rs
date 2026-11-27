//! Model selection and resolution from immutable Hub references or local checkpoints.
mod peer;
use super::{ModelFiles, ModelKind, ModelSpec, gguf, native, qwen3};
use anyhow::{Context, Result, ensure};
use hellas_rpc::ContentRef;
use hellas_store::{
    content::{DiskStore, Locator},
    hf::PinnedFile,
};
use native::{Kind, Origin};
pub(crate) use peer::PeerModel;
pub use peer::{CatalogUnavailable, acquire_peer_model, publish_model};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

pub(super) struct GgufPath {
    pub source: PathBuf,
    header: Option<tempfile::TempPath>,
}

impl GgufPath {
    pub(super) fn metadata(&self) -> &Path {
        self.header.as_deref().unwrap_or(&self.source)
    }
}

pub(super) struct Gguf {
    pub path: Arc<GgufPath>,
    pub header: Arc<gguf::Header>,
    pub weights: ContentRef,
}

pub(super) enum File {
    Local(PathBuf),
    Remote(RemoteFile),
}

pub(super) enum RemoteFile {
    Hub(PinnedFile),
    Peer(PeerModel, ContentRef),
}

impl RemoteFile {
    pub(super) fn object(&self) -> ContentRef {
        match self {
            Self::Hub(file) => file.object,
            Self::Peer(_, object) => *object,
        }
    }
    pub(super) fn read_range(
        &self,
        range: std::ops::Range<u64>,
        out: &mut impl Write,
    ) -> Result<()> {
        match self {
            Self::Hub(file) => file.read_range(range, out)?,
            Self::Peer(peer, object) => out.write_all(&peer.read(*object, range)?)?,
        }
        Ok(())
    }
}
impl File {
    fn path(&self) -> &Path {
        match self {
            Self::Local(path) => path,
            Self::Remote(RemoteFile::Hub(file)) => Path::new(&file.path),
            Self::Remote(RemoteFile::Peer(..)) => Path::new("model.gguf"),
        }
    }

    pub(super) fn register(&self, files: &mut ModelFiles) {
        match self {
            Self::Local(path) => files.local.push(path.clone()),
            Self::Remote(RemoteFile::Hub(file)) => files.hub.push(file.clone()),
            Self::Remote(RemoteFile::Peer(..)) => {}
        }
    }

    pub(super) fn object(
        &self,
        inspected: &std::collections::BTreeMap<PathBuf, ContentRef>,
    ) -> Result<ContentRef> {
        Ok(match self {
            Self::Local(path) => match inspected.get(path) {
                Some(object) => *object,
                None => hellas_store::content::file_content(path)?,
            },
            Self::Remote(file) => file.object(),
        })
    }

    fn gguf(&self, store: Option<&DiskStore>) -> Result<Gguf> {
        let (path, header, weights) = match self {
            Self::Local(path) => {
                let inspected = match store {
                    Some(store) => tokio::runtime::Handle::current()
                        .block_on(store.inspect_files(vec![path.clone()]))?,
                    None => Default::default(),
                };
                let header = gguf::read_header(&mut hellas_private::open_regular_file(path)?)?;
                (None, header, self.object(&inspected)?)
            }
            Self::Remote(file) => {
                let weights = file.object();
                let (header, bytes) = gguf::remote_header(weights.bytes(), |range, bytes| {
                    file.read_range(range, bytes).map_err(std::io::Error::other)
                })?;
                let mut output = tempfile::Builder::new().suffix(".gguf").tempfile()?;
                output.write_all(&bytes)?;
                (Some(output.into_temp_path()), header, weights)
            }
        };
        Ok(Gguf {
            path: Arc::new(GgufPath {
                source: self.path().into(),
                header: path,
            }),
            header: Arc::new(header),
            weights,
        })
    }
}

pub(super) enum Resolved {
    Gguf(Gguf),
    Native(native::Kind, Arc<native::Native>),
}

pub(super) enum Source<'a> {
    Gguf(File),
    Checkpoint(Kind, Origin, Option<&'a ModelSpec>),
}
impl<'a> Source<'a> {
    pub fn open(spec: &'a ModelSpec) -> Result<Self> {
        let path = &spec.model;
        spec.check_locator()?;
        let (origin, selector) = match super::model_locator(path)? {
            Some(Locator::Hellas { id, seeds }) => return Self::peer(PeerModel::open(id, seeds)?),
            Some(Locator::Hub(reference)) => {
                let (repo, selector) = native::hub(reference)?;
                (Origin::Hub(repo), selector)
            }
            Some(Locator::Https(_)) => {
                anyhow::bail!("--model takes a local path, an hf:// locator or hellas://ID")
            }
            None => {
                let metadata = std::fs::metadata(path)?;
                let directory = if metadata.is_dir() {
                    path.as_path()
                } else {
                    ensure!(
                        metadata.is_file(),
                        "checkpoint must be a regular file or directory"
                    );
                    if path.extension().is_none_or(|ext| ext != "safetensors") {
                        return Self::gguf(File::Local(path.clone()), spec);
                    }
                    ensure!(
                        path.file_name()
                            .is_some_and(|name| name == "model.safetensors"),
                        "select the checkpoint root or model.safetensors"
                    );
                    path.parent()
                        .filter(|dir| !dir.as_os_str().is_empty())
                        .unwrap_or(Path::new("."))
                };
                (Origin::Local(directory.into()), None)
            }
        };
        let explicit_gguf = selector.as_deref().is_some_and(|key| {
            Path::new(key)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("gguf"))
        });
        if !explicit_gguf && let Some(kind) = origin.kind()? {
            ensure!(
                !spec.has_companions() || kind == Kind::Phonon,
                "codec and voices companions require a Phonon model"
            );
            ensure!(
                selector
                    .as_deref()
                    .is_none_or(|s| s == "model.safetensors" && kind != Kind::Flux),
                "select the checkpoint root for this model"
            );
            return Ok(Self::Checkpoint(kind, origin, Some(spec)));
        }
        let Origin::Hub(repo) = origin else {
            anyhow::bail!("unrecognized model checkpoint");
        };
        Self::gguf(
            File::Remote(RemoteFile::Hub(repo.select("gguf", selector.as_deref())?)),
            spec,
        )
    }

    fn gguf(file: File, spec: &ModelSpec) -> Result<Self> {
        ensure!(
            !spec.has_companions(),
            "codec and voices companions require a Phonon model"
        );
        Ok(Self::Gguf(file))
    }

    fn peer(peer: PeerModel) -> Result<Self> {
        if let [asset] = peer.model.assets.as_slice()
            && asset.name == "weights"
        {
            let object = asset.object;
            return Ok(Self::Gguf(File::Remote(RemoteFile::Peer(peer, object))));
        }
        let origin = Origin::Peer(peer);
        let kind = origin.kind()?.context("unrecognized peer checkpoint")?;
        Ok(Self::Checkpoint(kind, origin, None))
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
            Self::Gguf(file) => {
                let kind = match file {
                    File::Local(path) => gguf_kind(path)?,
                    _ => gguf_kind(file.gguf(None)?.path.metadata())?,
                };
                let name = match file {
                    File::Remote(RemoteFile::Peer(peer, _)) => peer.model.content_id()?.to_string(),
                    _ => super::package::model_name(file.path())?.into(),
                };
                (kind, name)
            }
            Self::Checkpoint(kind, origin, _) => (
                match kind {
                    native::Kind::Flux => ModelKind::Image,
                    native::Kind::Whisper => ModelKind::Transcription,
                    native::Kind::OmniVoice | native::Kind::Phonon | native::Kind::Mms => {
                        ModelKind::Speech
                    }
                },
                match origin {
                    Origin::Hub(repo) => repo.repo.id.rsplit('/').next().unwrap().into(),
                    Origin::Peer(peer) => peer.model.content_id()?.to_string(),
                    Origin::Local(path) => path
                        .canonicalize()?
                        .file_name()
                        .and_then(|name| name.to_str())
                        .context("checkpoint needs a UTF-8 directory name")?
                        .into(),
                },
            ),
        })
    }

    pub fn files(self) -> Result<ModelFiles> {
        Ok(match self {
            Self::Gguf(file) => {
                let mut files = ModelFiles::default();
                file.register(&mut files);
                files
            }
            Self::Checkpoint(kind, origin, companions) => {
                native::Snapshot::open(origin, kind, companions)?.originals
            }
        })
    }
    pub fn resolve(self, store: Option<&DiskStore>) -> Result<Resolved> {
        Ok(match self {
            Self::Gguf(file) => Resolved::Gguf(file.gguf(store)?),
            Self::Checkpoint(kind, origin, companions) => Resolved::Native(
                kind,
                Arc::new(native::Snapshot::open(origin, kind, companions)?.resolve(store)?),
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
        let peer = PeerModel::connect(id, store, None).await?;
        let resolved =
            tokio::task::spawn_blocking(move || Source::peer(peer)?.resolve(None)).await??;
        Self::open_resolved(&resolved, evaluator, dialect).await
    }
}
