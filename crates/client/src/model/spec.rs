//! Acquisition inputs for building a model. The rendered model commits only to content.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct ModelSpec {
    pub model: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voices: Option<PathBuf>,
}

impl<'de> Deserialize<'de> for ModelSpec {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Input {
            Path(PathBuf),
            Parts(#[serde(with = "ModelSpec")] ModelSpec),
        }
        Ok(match Input::deserialize(deserializer)? {
            Input::Path(path) => path.into(),
            Input::Parts(spec) => spec,
        })
    }
}

impl Serialize for ModelSpec {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.has_companions() {
            ModelSpec::serialize(self, serializer)
        } else {
            self.model.serialize(serializer)
        }
    }
}

impl<P: Into<PathBuf>> From<P> for ModelSpec {
    fn from(model: P) -> Self {
        Self {
            model: model.into(),
            codec: None,
            voices: None,
        }
    }
}

impl ModelSpec {
    pub fn paths(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(&self.model)
            .chain(&self.codec)
            .chain(&self.voices)
            .map(PathBuf::as_path)
    }
    pub fn paths_mut(&mut self) -> impl Iterator<Item = &mut PathBuf> {
        std::iter::once(&mut self.model)
            .chain(&mut self.codec)
            .chain(&mut self.voices)
    }
    pub fn has_companions(&self) -> bool {
        self.codec.is_some() || self.voices.is_some()
    }

    pub fn check_locator(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.has_companions() || super::peer_uri(&self.model).is_none(),
            "a hellas:// model already commits to its codec and voices"
        );
        Ok(())
    }
}
