//! Resolve the published checkpoint once for local and Hub-backed model renderers.
mod companion;
use super::{
    ModelFiles, ModelSpec, flux,
    source::{File, PeerModel, RemoteFile},
};
use anyhow::{Context, Result, bail, ensure};
use catena_models::{omnivoice, phonon};
use hellas_rpc::{
    ContentRef,
    protocol::invocation::compute::{Arg, Model, NamedAsset},
};
use hellas_store::{
    content::{DiskStore, LocalStore, Scope},
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
            Self::Peer(peer) => peer.object(key).is_ok(),
        })
    }
    fn file(&self, key: &str, metadata: Option<ContentRef>) -> Result<File> {
        Ok(match self {
            Self::Local(dir) => File::Local(dir.join(key)),
            Self::Hub(repo) => File::Remote(RemoteFile::Hub(match metadata {
                Some(object) => PinnedFile::new(repo.repo.clone(), key.into(), object),
                None => repo.file(key)?,
            })),
            Self::Peer(peer) => File::Remote(RemoteFile::Peer(peer.clone(), peer.object(key)?)),
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
                peer.read(object, 0..object.bytes())?
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

struct RangeReader<'a> {
    file: &'a RemoteFile,
    position: u64,
}
impl Read for RangeReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let count = out.len().min(
            (self.file.object().bytes() - self.position)
                .try_into()
                .unwrap_or(usize::MAX),
        );
        if count != 0 {
            let end = self.position + count as u64;
            self.file
                .read_range(self.position..end, &mut &mut out[..count])
                .map_err(std::io::Error::other)?;
            self.position = end;
        }
        Ok(count)
    }
}

pub(super) struct Snapshot {
    dir: tempfile::TempDir,
    pub(super) originals: ModelFiles,
    assets: Vec<NamedAsset>,
    expected: Option<Arc<Model>>,
    weights: BTreeMap<String, File>,
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
        self.add_from(origin, &format!("{prefix}{key}"), key)
    }
    fn add_from(&mut self, origin: &Origin, name: &str, key: &str) -> Result<()> {
        relative(name)?;
        relative(key)?;
        let key = if matches!(origin, Origin::Peer(_)) {
            name
        } else {
            key
        };
        if key.ends_with(".safetensors") {
            let weight = origin.file(key, None)?;
            weight.register(&mut self.originals);
            self.weights.insert(name.to_owned(), weight);
        } else {
            let path = self.dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap())?;
            let bytes = origin.metadata(key)?;
            let object = ContentRef::for_bytes(&bytes);
            self.assets.push(NamedAsset {
                name: name.to_owned(),
                object,
            });
            std::fs::write(path, &bytes)?;
            origin
                .file(key, Some(object))?
                .register(&mut self.originals);
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
    pub(super) fn open(origin: Origin, kind: Kind, companions: Option<&ModelSpec>) -> Result<Self> {
        let mut result = Self {
            dir: tempfile::tempdir()?,
            assets: Vec::new(),
            originals: ModelFiles::default(),
            expected: match &origin {
                Origin::Peer(peer) => Some(peer.model.clone()),
                _ => None,
            },
            weights: BTreeMap::new(),
            indexed_names: BTreeMap::new(),
            voices: BTreeMap::new(),
        };
        let fixed: &[&str] = match kind {
            Kind::Mms => &super::speech::CHECKPOINT,
            Kind::Whisper => &super::whisper::CHECKPOINT,
            Kind::OmniVoice => omnivoice::FILES,
            Kind::Flux => &flux::METADATA,
            Kind::Phonon => &[],
        };
        for key in fixed {
            result.add(&origin, "", key)?;
        }
        match kind {
            Kind::Flux => {
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
                let (model, codec, catalog) = companion::resolve(origin, companions)?;
                for key in phonon::MODEL_FILES {
                    result.add(&model, "model/", key)?;
                }
                for key in phonon::CODEC_FILES {
                    codec.add(&mut result, "codec/", key)?;
                }
                catalog.add(&mut result, "voices/", phonon::VOICE_CATALOG)?;
                let listing = std::fs::read_to_string(
                    result.dir.path().join("voices").join(phonon::VOICE_CATALOG),
                )?;
                for (name, key) in super::speech::phonon::catalog(&listing)? {
                    let asset = format!("voices/{key}");
                    if !result.weights.contains_key(&asset) {
                        catalog.add(&mut result, "voices/", &key)?;
                    }
                    result.voices.insert(name, asset);
                }
            }
            _ => {}
        }
        Ok(result)
    }

    pub(super) fn resolve(mut self, store: Option<&DiskStore>) -> Result<Native> {
        let paths = self.weights.values().filter_map(|file| match file {
            File::Local(path) => Some(path.clone()),
            _ => None,
        });
        let inspected = match store {
            Some(store) => {
                tokio::runtime::Handle::current().block_on(store.inspect_files(paths.collect()))?
            }
            None => BTreeMap::new(),
        };
        let mut files = BTreeMap::new();
        let mut voice_files = BTreeMap::new();
        for (key, weight) in self.weights {
            let object = weight.object(&inspected)?;
            if key.starts_with("voices/") {
                voice_files.insert(key.clone(), (weight, object));
            } else {
                let tensors = weight.tensors(&key, object)?;
                if let Some(expected) = self.indexed_names.get(&key) {
                    ensure!(tensors.keys().eq(expected), "invalid shard index for {key}");
                }
                files.insert(key.clone(), tensors);
            }
            self.assets.push(NamedAsset { name: key, object });
        }
        let model = Model::new(self.assets)?;
        if let Some(expected) = self.expected {
            ensure!(
                model == *expected,
                "checkpoint assets disagree with the named model"
            );
        }
        Ok(Native {
            model,
            dir: self.dir,
            files,
            voices: self.voices,
            voice_files,
        })
    }
}

impl File {
    fn tensors(&self, key: &str, object: ContentRef) -> Result<BTreeMap<String, Tensor>> {
        let file_bytes = object.bytes();
        let reader: Box<dyn Read + '_> = match self {
            Self::Local(path) => Box::new(hellas_private::open_regular_file(path)?),
            Self::Remote(file) => Box::new(RangeReader { file, position: 0 }),
        };
        let (base, metadata) = catena_models::weights::read_safetensors_header(reader, file_bytes)?;
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
type Tensors = BTreeMap<String, Tensor>;
pub(crate) struct Native {
    pub model: Model,
    dir: tempfile::TempDir,
    files: BTreeMap<String, Tensors>,
    voices: BTreeMap<String, String>,
    voice_files: BTreeMap<String, (File, ContentRef)>,
}
impl Native {
    pub fn dir(&self) -> &Path {
        self.dir.path()
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
            hellas_channel::content::upload_object(&content.0, &bytes).await?;
        }
        Ok((environment, content))
    }
    pub fn voice(&self, name: &str) -> Result<Tensor> {
        let key = self
            .voices
            .get(name)
            .with_context(|| format!("unknown Phonon voice {name:?}"))?;
        let (weight, object) = self
            .voice_files
            .get(key)
            .context("missing catalog voice file")?;
        if let File::Local(path) = weight {
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
            .and_then(|ts| ts.get(tensor))
            .with_context(|| format!("missing tensor {tensor} in {file}"))
    }
    pub fn tensor_in(&self, prefix: &str, tensor: &str) -> Result<&Tensor> {
        let mut hits = self
            .files
            .iter()
            .filter(|(file, _)| file.starts_with(prefix))
            .filter_map(|(_, ts)| ts.get(tensor));
        let value = hits
            .next()
            .with_context(|| format!("missing {prefix} tensor {tensor}"))?;
        if hits.next().is_some() {
            bail!("duplicate {prefix} tensor {tensor}");
        }
        Ok(value)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture(dir: &Path, files: BTreeMap<String, (ContentRef, Tensors)>) -> Self {
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
        let files = files
            .into_iter()
            .map(|(name, (object, tensors))| {
                metadata.insert(name.clone(), object);
                (name, tensors)
            })
            .collect();
        let assets = metadata
            .into_iter()
            .map(|(name, object)| NamedAsset { name, object })
            .collect();
        Self {
            model: Model::new(assets).unwrap(),
            dir: root,
            files,
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
        let parsed = Snapshot::open(
            Origin::Local(snapshot.clone()),
            Kind::OmniVoice,
            Default::default(),
        )?;
        let files = &parsed.originals;
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
