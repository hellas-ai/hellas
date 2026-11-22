//! Resolve the published checkpoint once for local and Hub-backed model renderers.
use super::{ModelFiles, flux};
use anyhow::{Context, Result, bail, ensure};
use catena_models::omnivoice;
use hellas_rpc::{
    ContentRef,
    protocol::invocation::compute::{Arg, NamedAsset},
};
use hellas_store::{
    content::DiskStore,
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
    Flux,
    OmniVoice,
}

pub(super) enum Origin {
    Local(PathBuf),
    Hub(PinnedRepo),
}

impl Origin {
    fn has(&self, key: &str) -> Result<bool> {
        Ok(match self {
            Self::Local(dir) => dir.join(key).try_exists()?,
            Self::Hub(repo) => repo.contains(key),
        })
    }
    fn file(&self, key: &str) -> Result<Weight> {
        Ok(match self {
            Self::Local(dir) => Weight::Local(dir.join(key)),
            Self::Hub(repo) => Weight::Hub(repo.file(key)?),
        })
    }
    fn metadata(&self, key: &str) -> Result<Vec<u8>> {
        const MAX: usize = 32 << 20;
        Ok(match self {
            Self::Local(dir) => hellas_private::read_bounded_regular_file(&dir.join(key), MAX)?,
            Self::Hub(repo) => repo.metadata(key, MAX as u64)?,
        })
    }
    pub(super) fn kind(&self) -> Result<Option<Kind>> {
        Ok(if self.has("model_index.json")? {
            Some(Kind::Flux)
        } else if self.has("audio_tokenizer/config.json")? {
            Some(Kind::OmniVoice)
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
}

struct RangeReader<'a> {
    file: &'a PinnedFile,
    offset: u64,
}
impl Read for RangeReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let count = (out.len() as u64).min(self.file.object.bytes() - self.offset);
        if count != 0 {
            self.file
                .read_range(
                    self.offset..self.offset + count,
                    &mut &mut out[..count as usize],
                )
                .map_err(std::io::Error::other)?;
            self.offset += count;
        }
        Ok(count as usize)
    }
}

pub(super) struct Snapshot {
    dir: Arc<tempfile::TempDir>,
    metadata: Vec<PathBuf>,
    weights: BTreeMap<String, Weight>,
    indexed_names: BTreeMap<String, BTreeSet<String>>,
}

fn relative(name: &str) -> Result<()> {
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
        if key.ends_with(".safetensors") {
            self.weights.insert(name, origin.file(key)?);
        } else {
            let path = self.dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(path, origin.metadata(key)?)?;
            if let Origin::Local(root) = origin {
                self.metadata.push(root.join(key));
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
            metadata: vec![],
            weights: BTreeMap::new(),
            indexed_names: BTreeMap::new(),
        };
        match kind {
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
        }
        Ok(result)
    }

    pub(super) fn files(&self) -> ModelFiles {
        let mut local = self.metadata.clone();
        let mut hub = Vec::new();
        for file in self.weights.values() {
            match file {
                Weight::Local(path) => local.push(path.clone()),
                Weight::Hub(file) => hub.push(file.clone()),
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
        let mut files = BTreeMap::new();
        for (key, weight) in self.weights {
            let (object, header) = match weight {
                Weight::Hub(file) => (
                    file.object,
                    catena_models::weights::read_safetensors_header(
                        RangeReader {
                            file: &file,
                            offset: 0,
                        },
                        file.object.bytes(),
                    )?,
                ),
                Weight::Local(path) => {
                    let object = match inspected.get(&path) {
                        Some(o) => *o,
                        None => hellas_store::content::file_content(&path)?,
                    };
                    (
                        object,
                        catena_models::weights::read_safetensors_header(
                            hellas_private::open_regular_file(&path)?,
                            object.bytes(),
                        )?,
                    )
                }
            };
            let (base, metadata) = header;
            let tensors: BTreeMap<_, _> = metadata
                .tensors()
                .into_iter()
                .map(|(name, t)| {
                    let (a, b) = t.data_offsets;
                    (
                        name.to_owned(),
                        Tensor {
                            dtype: t.dtype,
                            shape: t.shape.clone(),
                            arg: Arg::Asset {
                                name: key.clone(),
                                offset: (base + a) as u64,
                                bytes: (b - a) as u64,
                            },
                        },
                    )
                })
                .collect();
            if let Some(expected) = self.indexed_names.get(&key) {
                ensure!(tensors.keys().eq(expected), "invalid shard index for {key}");
            }
            files.insert(key, (object, tensors));
        }
        Ok(Native {
            dir: self.dir,
            files: Arc::new(files),
        })
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
    dir: Arc<tempfile::TempDir>,
    files: Arc<Files>,
}
impl Native {
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }
    pub fn assets(&self) -> Vec<NamedAsset> {
        self.files
            .iter()
            .map(|(name, (object, _))| NamedAsset {
                name: name.clone(),
                object: *object,
            })
            .collect()
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
        fn copy(src: &Path, dst: &Path) {
            for item in std::fs::read_dir(src).unwrap() {
                let item = item.unwrap();
                let path = dst.join(item.file_name());
                if item.file_type().unwrap().is_dir() {
                    std::fs::create_dir(&path).unwrap();
                    copy(&item.path(), &path);
                } else if item.path().extension().is_some_and(|ext| ext == "json") {
                    std::fs::copy(item.path(), path).unwrap();
                }
            }
        }
        let root = tempfile::tempdir().unwrap();
        copy(dir, root.path());
        Self {
            dir: Arc::new(root),
            files: Arc::new(files),
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
        assert_eq!(model.assets().len(), 2);
        assert!(model.assets().iter().all(|asset| asset.object == content));
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
}
