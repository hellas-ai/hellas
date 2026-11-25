//! Static content declarations for explicit local store and job commands.
use anyhow::{Context, Result};
#[cfg(feature = "compute")]
use hellas_store::content::DiskStore;
use hellas_store::content::config::Config;
use serde::Deserialize;
use std::path::PathBuf;

pub(crate) fn load(path: Option<PathBuf>) -> Result<Config> {
    let Some(path) = path else {
        return Ok(Config::default());
    };
    let path = std::path::absolute(path)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        #[serde(default)]
        content: Config,
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let File { mut content } =
        toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))?;
    if let Some(parent) = path.parent() {
        for dir in content.upper.iter_mut().chain(&mut content.lower) {
            *dir = parent.join(&*dir);
        }
    }
    content.validate()?;
    Ok(content)
}

#[cfg(feature = "compute")]
pub(crate) async fn add_content(
    config: &mut Config,
    store: &DiskStore,
    paths: Vec<PathBuf>,
) -> Result<()> {
    use hellas_store::content::config::{Declaration, Object};
    anyhow::ensure!(
        paths.is_empty()
            || !config
                .pins
                .keys()
                .any(|name| name.starts_with("config/content-")),
        "config/content-* is reserved for --content"
    );
    let mut index = 0;
    for root in paths {
        let objects = store.inspect_files(vec![root.clone()]).await?;
        config.lower.push(root);
        for object in objects.into_values() {
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
