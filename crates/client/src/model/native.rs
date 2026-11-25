//! Resolve the published checkpoint once for local and Hub-backed model renderers.
use super::{ModelFiles, flux, source::PeerModel};
use anyhow::{Context, Result, bail, ensure};
use catena_models::{omnivoice, phonon};
use hellas_rpc::{
    ContentRef,
    protocol::invocation::compute::{Arg, Model, NamedAsset},
};
use hellas_store::{
    content::{ContentStore, DiskStore, LocalStore, Scope},
    hf::{PinnedFile, PinnedRepo},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Mms,
    Whisper,
    Flux,
    OmniVoice,
    Phonon,
}

pub(super) enum Origin {
    Local(PathBuf),
    Hub(PinnedRepo),
    Peer(PeerModel),
}

impl Origin {
    fn has(&self, key: &str) -> Result<bool> {
        Ok(match self {
            Self::Local(dir) => dir.join(key).try_exists()?,
            Self::Hub(repo) => repo.contains(key),
            Self::Peer(peer) => peer.model.assets.iter().any(|asset| asset.name == key),
        })
    }
    fn file(&self, key: &str) -> Result<Weight> {
        Ok(match self {
            Self::Local(dir) => Weight::Local(dir.join(key)),
            Self::Hub(repo) => Weight::Hub(repo.file(key)?),
            Self::Peer(peer) => Weight::Peer(peer.clone(), peer.object(key)?),
        })
    }
    fn metadata(&self, key: &str) -> Result<Vec<u8>> {
        const MAX: usize = 32 << 20;
        Ok(match self {
            Self::Local(dir) => hellas_private::read_bounded_regular_file(&dir.join(key), MAX)?,
            Self::Hub(repo) => repo.metadata(key, MAX as u64)?,
            Self::Peer(peer) => {
                let object = peer.object(key)?;
                ensure!(
                    object.bytes() <= MAX as u64,
                    "checkpoint metadata exceeds limit: {key}"
                );
                let bytes = peer.read(key, 0..object.bytes())?;
                ensure!(
                    ContentRef::for_bytes(&bytes) == object,
                    "metadata identity mismatch: {key}"
                );
                bytes
            }
        })
    }
    pub(super) fn kind(&self) -> Result<Option<Kind>> {
        Ok(if self.has("model_index.json")? {
            Some(Kind::Flux)
        } else if self.has("audio_tokenizer/config.json")? {
            Some(Kind::OmniVoice)
        } else if self.has(phonon::TOKENIZER)? || self.has("model/processor_config.json")? {
            Some(Kind::Phonon)
        } else if self.has("model.safetensors")? && self.has("config.json")? {
            #[derive(serde::Deserialize)]
            struct Config {
                model_type: Option<String>,
            }
            match serde_json::from_slice::<Config>(&self.metadata("config.json")?)?
                .model_type
                .as_deref()
            {
                Some("vits") => Some(Kind::Mms),
                Some("whisper") => Some(Kind::Whisper),
                _ => None,
            }
        } else {
            None
        })
    }
}
pub(super) fn hub(uri: &str) -> Result<(PinnedRepo, Option<String>)> {
    Ok(PinnedRepo::open(
        uri,
        &hellas_store::content::Reservations::ram(
            hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
        ),
    )?)
}

enum Weight {
    Local(PathBuf),
    Hub(PinnedFile),
    Peer(PeerModel, ContentRef),
}

struct RangeReader<F> {
    file_bytes: u64,
    offset: u64,
    read: F,
}
impl<F: FnMut(std::ops::Range<u64>, &mut [u8]) -> Result<()>> Read for RangeReader<F> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let count = (out.len() as u64).min(self.file_bytes - self.offset);
        if count != 0 {
            (self.read)(self.offset..self.offset + count, &mut out[..count as usize])
                .map_err(std::io::Error::other)?;
            self.offset += count;
        }
        Ok(count as usize)
    }
}

pub(super) struct Snapshot {
    dir: Arc<tempfile::TempDir>,
    local_metadata: Vec<PathBuf>,
    hub_metadata: Vec<PinnedFile>,
    metadata: BTreeMap<String, ContentRef>,
    expected: Option<Arc<Model>>,
    weights: BTreeMap<String, Weight>,
    indexed_names: BTreeMap<String, BTreeSet<String>>,
    voices: BTreeMap<String, String>,
}

pub(super) fn relative(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && !name.contains('\\')
            && name
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != "..")
            && Path::new(name)
                .components()
                .all(|p| matches!(p, Component::Normal(_))),
        "invalid checkpoint path {name:?}"
    );
    Ok(())
}

impl Snapshot {
    fn add(&mut self, origin: &Origin, prefix: &str, key: &str) -> Result<()> {
        relative(key)?;
        let name = format!("{prefix}{key}");
        let key = if matches!(origin, Origin::Peer(_)) {
            name.as_str()
        } else {
            key
        };
        if key.ends_with(".safetensors") {
            let weight = origin.file(key)?;
            self.weights.insert(name, weight);
        } else {
            let path = self.dir.path().join(&name);
            std::fs::create_dir_all(path.parent().unwrap())?;
            let bytes = origin.metadata(key)?;
            let object = ContentRef::for_bytes(&bytes);
            self.metadata.insert(name.clone(), object);
            std::fs::write(path, &bytes)?;
            if let Origin::Hub(repo) = origin {
                self.hub_metadata.push(PinnedFile {
                    repo: repo.repo.clone(),
                    path: key.to_string(),
                    object,
                });
            }
            if let Origin::Local(root) = origin {
                self.local_metadata.push(root.join(key));
            }
        }
        Ok(())
    }
    fn shards(&mut self, origin: &Origin, key: &str) -> Result<()> {
        self.add(origin, "", key)?;
        if !key.ends_with(".index.json") {
            return Ok(());
        }
        #[derive(serde::Deserialize)]
        struct Index {
            weight_map: BTreeMap<String, String>,
        }
        let index: Index =
            serde_json::from_reader(std::fs::File::open(self.dir.path().join(key))?)?;
        ensure!(
            !index.weight_map.is_empty(),
            "empty checkpoint shard index {key}"
        );
        let directory = key.rsplit_once('/').context("missing shard directory")?.0;
        let mut shards = BTreeMap::<String, BTreeSet<String>>::new();
        for (tensor, name) in index.weight_map {
            ensure!(
                !name.contains('/') && name.ends_with(".safetensors"),
                "invalid checkpoint shard {name:?}"
            );
            shards
                .entry(format!("{directory}/{name}"))
                .or_default()
                .insert(tensor);
        }
        for (key, names) in shards {
            self.add(origin, "", &key)?;
            self.indexed_names.insert(key, names);
        }
        Ok(())
    }
    pub(super) fn open(origin: Origin, kind: Kind) -> Result<Self> {
        let mut result = Self {
            dir: Arc::new(tempfile::tempdir()?),
            metadata: BTreeMap::new(),
            local_metadata: vec![],
            hub_metadata: vec![],
            expected: match &origin {
                Origin::Peer(peer) => Some(peer.model.clone()),
                _ => None,
            },
            weights: BTreeMap::new(),
            indexed_names: BTreeMap::new(),
            voices: BTreeMap::new(),
        };
        match kind {
            Kind::Mms => {
                for &key in &super::speech::CHECKPOINT {
                    result.add(&origin, "", key)?;
                }
            }
            Kind::Whisper => {
                for &key in &super::whisper::CHECKPOINT {
                    result.add(&origin, "", key)?;
                }
            }
            Kind::OmniVoice => {
                for &key in omnivoice::FILES {
                    result.add(&origin, "", key)?;
                }
            }
            Kind::Flux => {
                for key in flux::METADATA {
                    result.add(&origin, "", key)?;
                }
                if origin.has("variants.json")? {
                    result.add(&origin, "", "variants.json")?;
                }
                result.shards(&origin, flux::TEXT_INDEX)?;
                let transformer = if origin.has(flux::TRANSFORMER_INDEX)? {
                    flux::TRANSFORMER_INDEX
                } else {
                    flux::TRANSFORMER
                };
                result.shards(&origin, transformer)?;
                result.add(&origin, "", flux::VAE)?;
            }
            Kind::Phonon => {
                let (model, codec, catalog) = match origin {
                    Origin::Local(root)
                        if root.join("model/processor_config.json").try_exists()? =>
                    {
                        (
                            Origin::Local(root.join("model")),
                            Origin::Local(root.join("codec")),
                            Origin::Local(root.join("voices")),
                        )
                    }
                    Origin::Peer(peer) => (
                        Origin::Peer(peer.clone()),
                        Origin::Peer(peer.clone()),
                        Origin::Peer(peer),
                    ),
                    model => {
                        let dep = |id, revision| {
                            Ok::<_, anyhow::Error>(Origin::Hub(
                                hub(&format!("hf://{id}@{revision}"))?.0,
                            ))
                        };
                        (
                            model,
                            dep(phonon::CODEC, phonon::CODEC_REVISION)?,
                            dep(phonon::VOICE_REPO, phonon::VOICE_REPO_REVISION)?,
                        )
                    }
                };
                for key in phonon::MODEL_FILES {
                    result.add(&model, "model/", key)?;
                }
                for key in phonon::CODEC_FILES {
                    result.add(&codec, "codec/", key)?;
                }
                result.add(&catalog, "voices/", phonon::VOICE_CATALOG)?;
                let listing = std::fs::read_to_string(
                    result.dir.path().join("voices").join(phonon::VOICE_CATALOG),
                )?;
                for (name, key) in super::speech::phonon::catalog(&listing)? {
                    let asset = format!("voices/{key}");
                    if !result.weights.contains_key(&asset) {
                        result.add(&catalog, "voices/", &key)?;
                    }
                    result.voices.insert(name, asset);
                }
            }
        }
        Ok(result)
    }

    pub(super) fn files(&self) -> ModelFiles {
        let mut local = self.local_metadata.clone();
        let mut hub = self.hub_metadata.clone();
        for file in self.weights.values() {
            match file {
                Weight::Local(path) => local.push(path.clone()),
                Weight::Hub(file) => hub.push(file.clone()),
                Weight::Peer(_, _) => {}
            }
        }
        ModelFiles { local, hub }
    }
    pub(super) fn resolve(self, store: Option<&DiskStore>) -> Result<Native> {
        let paths = self
            .weights
            .values()
            .filter_map(|w| match w {
                Weight::Local(path) => Some(path.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let inspected = match store {
            Some(store) if !paths.is_empty() => {
                tokio::runtime::Handle::current().block_on(store.inspect_files(paths))?
            }
            _ => BTreeMap::new(),
        };
        let mut hub_files = self.hub_metadata;
        let mut files = BTreeMap::new();
        let mut voice_files = BTreeMap::new();
        for (key, weight) in self.weights {
            let object = match &weight {
                Weight::Local(path) => match inspected.get(path) {
                    Some(object) => *object,
                    None => hellas_store::content::file_content(path)?,
                },
                Weight::Hub(file) => {
                    hub_files.push(file.clone());
                    file.object
                }
                Weight::Peer(_, object) => *object,
            };
            let tensors = if key.starts_with("voices/") {
                voice_files.insert(key.clone(), weight);
                BTreeMap::new()
            } else {
                weight.tensors(&key, object)?
            };
            if let Some(expected) = self.indexed_names.get(&key) {
                ensure!(tensors.keys().eq(expected), "invalid shard index for {key}");
            }
            files.insert(key, (object, tensors));
        }
        let model = Native::model_from_files(&files, &self.metadata)?;
        if let Some(expected) = self.expected {
            ensure!(
                model == *expected,
                "checkpoint assets disagree with the named model"
            );
        }
        Ok(Native {
            hub_files: hub_files.into(),
            model,
            dir: self.dir,
            files: Arc::new(files),
            voices: self.voices,
            voice_files: Arc::new(voice_files),
        })
    }
}

impl Weight {
    fn tensors(&self, key: &str, object: ContentRef) -> Result<BTreeMap<String, Tensor>> {
        let file_bytes = object.bytes();
        let (base, metadata) = match self {
            Self::Local(path) => catena_models::weights::read_safetensors_header(
                hellas_private::open_regular_file(path)?,
                file_bytes,
            )?,
            Self::Hub(file) => catena_models::weights::read_safetensors_header(
                RangeReader {
                    file_bytes,
                    offset: 0,
                    read: |range, out: &mut [u8]| Ok(file.read_range(range, &mut &mut *out)?),
                },
                file_bytes,
            )?,
            Self::Peer(peer, _) => catena_models::weights::read_safetensors_header(
                RangeReader {
                    file_bytes,
                    offset: 0,
                    read: |range, out: &mut [u8]| {
                        let bytes = peer.read(key, range)?;
                        ensure!(bytes.len() == out.len(), "incomplete header range");
                        out.copy_from_slice(&bytes);
                        Ok(())
                    },
                },
                file_bytes,
            )?,
        };
        Ok(metadata
            .tensors()
            .into_iter()
            .map(|(name, t)| {
                let (a, b) = t.data_offsets;
                (
                    name.to_string(),
                    Tensor {
                        dtype: t.dtype,
                        shape: t.shape.clone(),
                        arg: Arg::Asset {
                            name: key.to_owned(),
                            offset: (base + a) as u64,
                            bytes: (b - a) as u64,
                        },
                    },
                )
            })
            .collect())
    }
}

pub(crate) struct Tensor {
    pub arg: Arg,
    pub dtype: safetensors::Dtype,
    pub shape: Vec<usize>,
}
type Files = BTreeMap<String, (ContentRef, BTreeMap<String, Tensor>)>;
#[derive(Clone)]
pub(crate) struct Native {
    pub hub_files: Arc<[PinnedFile]>,
    pub model: Model,
    dir: Arc<tempfile::TempDir>,
    files: Arc<Files>,
    voices: BTreeMap<String, String>,
    voice_files: Arc<BTreeMap<String, Weight>>,
}
impl Native {
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }
    fn model_from_files(files: &Files, metadata: &BTreeMap<String, ContentRef>) -> Result<Model> {
        let assets = files
            .iter()
            .map(|(name, (object, _))| (name, object))
            .chain(metadata.iter())
            .map(|(name, object)| NamedAsset {
                name: name.clone(),
                object: *object,
            })
            .collect();
        Ok(Model::new(assets)?)
    }
    async fn stage_metadata(&self, store: &impl ContentStore) -> Result<()> {
        for NamedAsset { name, object } in self
            .model
            .assets
            .iter()
            .filter(|asset| !asset.name.ends_with(".safetensors"))
        {
            let bytes = tokio::fs::read(self.dir().join(name)).await?;
            ensure!(
                ContentRef::for_bytes(&bytes) == *object,
                "checkpoint metadata changed: {name}"
            );
            hellas_channel::content::upload_object(store, &bytes).await?;
        }
        Ok(())
    }
    pub async fn environment(
        &self,
        source: &str,
    ) -> Result<(
        hellas_rpc::protocol::invocation::compute::Environment,
        (LocalStore, Scope),
    )> {
        let (environment, content) =
            super::program::environment(source, self.model.clone()).await?;
        self.stage_metadata(&content.0).await?;
        Ok((environment, content))
    }
    pub fn voice(&self, name: &str) -> Result<Tensor> {
        let key = self
            .voices
            .get(name)
            .with_context(|| format!("unknown Phonon voice {name:?}"))?;
        let weight = self
            .voice_files
            .get(key)
            .context("missing catalog voice file")?;
        let (object, _) = self
            .files
            .get(key)
            .context("missing catalog weight reference")?;
        if let Weight::Local(path) = weight {
            ensure!(
                hellas_store::content::file_content(path)? == *object,
                "catalog voice changed: {key}"
            );
        }
        weight
            .tensors(key, *object)?
            .remove("speaker_wavs")
            .context("voice has no speaker_wavs")
    }
    pub fn tensor(&self, file: &str, tensor: &str) -> Result<&Tensor> {
        self.files
            .get(file)
            .and_then(|(_, ts)| ts.get(tensor))
            .with_context(|| format!("missing tensor {tensor} in {file}"))
    }
    pub fn tensor_in(&self, prefix: &str, tensor: &str) -> Result<&Tensor> {
        let mut hits = self
            .files
            .iter()
            .filter(|(file, _)| file.starts_with(prefix))
            .filter_map(|(_, (_, ts))| ts.get(tensor));
        let value = hits
            .next()
            .with_context(|| format!("missing {prefix} tensor {tensor}"))?;
        if hits.next().is_some() {
            bail!("duplicate {prefix} tensor {tensor}");
        }
        Ok(value)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture(dir: &Path, files: Files) -> Self {
        fn copy(src: &Path, dst: &Path, root: &Path, metadata: &mut BTreeMap<String, ContentRef>) {
            for item in std::fs::read_dir(src).unwrap() {
                let item = item.unwrap();
                let path = dst.join(item.file_name());
                if item.file_type().unwrap().is_dir() {
                    std::fs::create_dir(&path).unwrap();
                    copy(&item.path(), &path, root, metadata);
                } else if item.path().extension().is_some_and(|ext| ext == "json") {
                    let bytes = std::fs::read(item.path()).unwrap();
                    metadata.insert(
                        path.strip_prefix(root)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string(),
                        ContentRef::for_bytes(&bytes),
                    );
                    std::fs::write(path, bytes).unwrap();
                }
            }
        }
        let root = tempfile::tempdir().unwrap();
        let mut metadata = BTreeMap::new();
        copy(dir, root.path(), root.path(), &mut metadata);
        Self {
            hub_files: Arc::default(),
            model: Self::model_from_files(&files, &metadata).unwrap(),
            dir: Arc::new(root),
            files: Arc::new(files),
            voices: Default::default(),
            voice_files: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safetensors::{Dtype, tensor::TensorView};

    #[test]
    #[cfg(unix)]
    fn local_snapshot_names_the_original_file_and_indexes_its_symlink() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let snapshot = temp.path().join("snapshot");
        std::fs::create_dir_all(snapshot.join("audio_tokenizer"))?;
        for name in [
            "config.json",
            "tokenizer.json",
            "audio_tokenizer/config.json",
        ] {
            std::fs::write(snapshot.join(name), "{}")?;
        }
        let object_path = temp.path().join("blob");
        let weights = [0x80u8, 0x3f, 0x00, 0x40];
        safetensors::serialize_to_file(
            [("weight", TensorView::new(Dtype::BF16, vec![2], &weights)?)],
            None,
            &object_path,
        )?;
        for name in ["model.safetensors", "audio_tokenizer/model.safetensors"] {
            std::os::unix::fs::symlink(&object_path, snapshot.join(name))?;
        }
        let parsed = Snapshot::open(Origin::Local(snapshot.clone()), Kind::OmniVoice)?;
        let files = parsed.files();
        assert!(files.hub.is_empty());
        assert!(
            files
                .local
                .contains(&snapshot.join("audio_tokenizer/model.safetensors"))
        );
        let model = parsed.resolve(None)?;
        let content = hellas_store::content::file_content(&object_path)?;
        let pick = model.tensor("model.safetensors", "weight")?;
        assert_eq!(model.model.assets.len(), 5);
        assert!(
            model
                .model
                .assets
                .iter()
                .filter(|asset| asset.name.ends_with(".safetensors"))
                .all(|asset| asset.object == content)
        );
        assert_eq!(pick.shape, [2]);
        assert_eq!(pick.dtype, Dtype::BF16);
        assert_eq!(
            pick.arg,
            Arg::Asset {
                name: "model.safetensors".into(),
                offset: content.bytes() - 4,
                bytes: 4
            }
        );
        assert_eq!(std::fs::read(model.dir().join("config.json"))?, b"{}");
        assert!(!model.dir().join("model.safetensors").exists());
        Ok(())
    }

    #[test]
    fn gateway_voice_allowlist_recognizes_default_alias() {
        assert!(super::super::voice_allowed(&[], "default"));
        assert!(super::super::voice_allowed(&[], "Easton"));
        assert!(!super::super::voice_allowed(&[], "Zoey"));
        assert!(super::super::voice_allowed(&["Zoey".into()], "Zoey"));
        assert!(!super::super::voice_allowed(&["Zoey".into()], "default"));
    }
}
