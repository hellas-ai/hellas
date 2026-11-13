//! Static content declarations for explicit local store and job commands.
use anyhow::{Context, Result};
use hellas_store::content::config::Config;
#[cfg(feature = "compute")]
use hellas_store::content::{DiskStore, config::Reconciler};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// A file or directory served to jobs, and every object it holds.
type Content = (PathBuf, Vec<hellas_rpc::ContentRef>);

pub(crate) struct ContentConfiguration {
    config: Config,
}

impl ContentConfiguration {
    /// Every regular file under each of `content` (a file or a directory) is
    /// served to jobs that name it, as one `config/content-NNNN` Jobs pin.
    /// They are hashed once, here.
    pub(crate) fn load(path: Option<PathBuf>, content: Vec<PathBuf>) -> Result<Self> {
        let path = path.map(std::path::absolute).transpose()?;
        let content: Vec<Content> = content
            .into_iter()
            .map(|root| {
                let root = std::path::absolute(&root)?;
                let objects = files(&root)?
                    .iter()
                    .map(|file| {
                        hellas_store::content::file_content(file)
                            .with_context(|| format!("failed to hash {}", file.display()))
                    })
                    .collect::<Result<_>>()?;
                Ok((root, objects))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            config: read(path.as_deref(), &content)?,
        })
    }

    #[cfg(feature = "compute")]
    pub(crate) fn with_default_upper(mut self, upper: PathBuf) -> Self {
        if self.config.upper.is_none() {
            self.config.upper = Some(upper.clone());
        }
        self
    }

    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    #[cfg(feature = "compute")]
    pub(crate) async fn apply(&self, store: &DiskStore) -> Result<()> {
        Reconciler::new(self.config.clone())?
            .apply(store, self.config.clone())
            .await?;
        Ok(())
    }
}

/// The regular files at `root`: itself, or every one under it, in path order.
fn files(root: &Path) -> Result<Vec<PathBuf>> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("failed to read {}", root.display()))?;
    if metadata.is_file() {
        return Ok(vec![root.to_owned()]);
    }
    anyhow::ensure!(
        metadata.is_dir(),
        "{} is not a regular file or directory",
        root.display()
    );
    let mut found = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<_>>()?;
    entries.sort();
    for entry in entries {
        let kind = std::fs::symlink_metadata(&entry)?.file_type();
        if kind.is_file() {
            found.push(entry);
        } else if kind.is_dir() {
            found.extend(files(&entry)?);
        }
    }
    Ok(found)
}

fn read(path: Option<&Path>, content: &[Content]) -> Result<Config> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        #[serde(default)]
        content: Config,
    }
    let mut config = match path {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            toml::from_str::<File>(&text)
                .with_context(|| format!("failed to parse {}", path.display()))?
                .content
        }
        None => Config::default(),
    };
    if let Some(parent) = path.and_then(Path::parent) {
        if let Some(upper) = &mut config.upper {
            *upper = parent.join(&*upper);
        }
        for lower in &mut config.lower {
            *lower = parent.join(&*lower);
        }
    }
    use hellas_store::content::config::{Declaration, Object};
    anyhow::ensure!(
        content.is_empty()
            || !config
                .pins
                .keys()
                .any(|name| name.starts_with("config/content-")),
        "config/content-* is reserved for --content"
    );
    let mut index = 0;
    for (root, objects) in content {
        config.lower.push(root.clone());
        for object in objects {
            config.pins.insert(
                format!("config/content-{index:04}"),
                Declaration::Object(Object {
                    url: None,
                    path: None,
                    bytes: Some(object.bytes()),
                    expect: Some(object.id().to_string()),
                    sha256: None,
                    policy: None,
                }),
            );
            index += 1;
        }
    }
    config.validate()?;
    Ok(config)
}
