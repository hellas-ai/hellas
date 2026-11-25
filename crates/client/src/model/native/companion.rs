//! Resolve the optional Phonon codec and voice catalog at model build time.
use super::{ModelSpec, Origin, Snapshot, hub, relative};
use anyhow::{Context, Result, ensure};
use catena_models::phonon;
use std::path::{Path, PathBuf};

/// A companion can name the repository/directory or its primary weights or catalog file.
/// Paths inside the model remain the same whichever acquisition source supplied them.
pub(super) struct Companion {
    origin: Origin,
    primary: &'static str,
    selected: String,
}

impl Companion {
    fn open(path: &Path, primary: &'static str) -> Result<Self> {
        let (origin, selected) = if let Some(uri) = crate::model::hf_uri(path) {
            let (repo, key) = hub(uri)?;
            let selected = match key {
                Some(key) if !repo.contains(&key) => format!("{key}/{primary}"),
                Some(key) => key,
                None => primary.to_owned(),
            };
            (Origin::Hub(repo), selected)
        } else if std::fs::metadata(path)?.is_dir() {
            (Origin::Local(path.into()), primary.to_owned())
        } else {
            let name = path
                .file_name()
                .and_then(|f| f.to_str())
                .context("companion filename needs UTF-8")?;
            (
                Origin::Local(path.parent().context("missing companion directory")?.into()),
                name.to_owned(),
            )
        };
        relative(&selected)?;
        ensure!(
            Path::new(&selected).extension() == Path::new(primary).extension(),
            "select a companion directory or its {primary} file"
        );
        Ok(Self {
            origin,
            selected,
            primary,
        })
    }

    pub(super) fn add(&self, snapshot: &mut Snapshot, prefix: &str, key: &str) -> Result<()> {
        let source = match self.selected.rsplit_once('/') {
            _ if key == self.primary => self.selected.clone(),
            Some((dir, _)) => format!("{dir}/{key}"),
            None => key.to_owned(),
        };
        snapshot.add_from(&self.origin, &format!("{prefix}{key}"), &source)
    }
}

pub(super) fn resolve(
    origin: Origin,
    spec: Option<&ModelSpec>,
) -> Result<(Origin, Companion, Companion)> {
    let bundled = match &origin {
        Origin::Local(root) if root.join("model/processor_config.json").try_exists()? => Some(root),
        _ => None,
    };
    let select = |path: Option<&Path>, name, repo, revision, primary| {
        if let Origin::Peer(peer) = &origin {
            return Ok(Companion {
                origin: Origin::Peer(peer.clone()),
                primary,
                selected: primary.into(),
            });
        }
        let default;
        let path = match path {
            Some(path) => path,
            None => {
                default = if let Some(root) = bundled {
                    root.join(name)
                } else if matches!(origin, Origin::Local(_)) {
                    hellas_store::hf::cached_snapshot(repo, revision)
                        .filter(|dir| dir.join(primary).is_file())
                        .with_context(|| format!("local Phonon model needs --{name}: default {repo}@{revision} is absent from the local Hub cache"))?
                } else {
                    PathBuf::from(format!("hf://{repo}@{revision}"))
                };
                &default
            }
        };
        Companion::open(path, primary)
    };
    let codec = select(
        spec.and_then(|s| s.codec.as_deref()),
        "codec",
        phonon::CODEC,
        phonon::CODEC_REVISION,
        "model.safetensors",
    )?;
    let voices = select(
        spec.and_then(|s| s.voices.as_deref()),
        "voices",
        phonon::VOICE_REPO,
        phonon::VOICE_REPO_REVISION,
        phonon::VOICE_CATALOG,
    )?;
    let model = bundled
        .map(|root| Origin::Local(root.join("model")))
        .unwrap_or(origin);
    Ok((model, codec, voices))
}
