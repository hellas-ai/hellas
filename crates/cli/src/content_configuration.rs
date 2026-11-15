//! Static content declarations for explicit local store and job commands.
use anyhow::{Context, Result};
use hellas_store::content::config::Config;
#[cfg(feature = "compute")]
use hellas_store::content::{DiskStore, config::Reconciler};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[cfg(feature = "compute")]
/// A file or directory served to jobs, and every object it holds.
type Content = (PathBuf, Vec<hellas_rpc::ContentRef>);

pub(crate) struct ContentConfiguration {
    config: Config,
}

impl ContentConfiguration {
    pub(crate) fn load(path: Option<PathBuf>) -> Result<Self> {
        let path = path.map(std::path::absolute).transpose()?;
        Ok(Self {
            config: read(path.as_deref())?,
        })
    }

    /// Index --content through the execution store, then pin those same references.
    #[cfg(feature = "compute")]
    pub(crate) async fn add_content(
        &mut self,
        store: &DiskStore,
        paths: Vec<PathBuf>,
    ) -> Result<()> {
        let mut content = Vec::new();
        for root in paths {
            let root = std::path::absolute(root)?;
            let objects = store
                .inspect_files(vec![root.clone()])
                .await?
                .into_values()
                .collect();
            content.push((root, objects));
        }
        add_content(&mut self.config, &content)
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

fn read(path: Option<&Path>) -> Result<Config> {
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
    config.validate()?;
    Ok(config)
}

#[cfg(feature = "compute")]
fn add_content(config: &mut Config, content: &[Content]) -> Result<()> {
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
    Ok(())
}
