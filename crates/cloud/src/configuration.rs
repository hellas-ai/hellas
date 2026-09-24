//! Private worker settings delivered over the owner's authenticated admin channel.
use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    /// The CLI's fetch route file, including explicit caller grants.
    pub fetch_config: Value,
    /// Provider-local credential environment, never returned by status or inventory.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Private JSON files referenced from fetch_config as @files/NAME.
    #[serde(default)]
    pub files: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn staged_credentials_are_private_and_missing_references_leave_no_files() {
        let parent = tempfile::tempdir().unwrap();
        let mut configuration = Configuration {
            fetch_config: json!({"routes":[{"auth_path":"@files/auth.json"}],"callers":[]}),
            env: BTreeMap::new(),
            files: [("auth.json".into(), json!({"token":"fixture"}))].into(),
        };
        let (staged, installed) = configuration.stage(parent.path()).unwrap();
        let config: Value = crate::config::read_json(&installed.fetch_config).unwrap();
        let auth = Path::new(config["routes"][0]["auth_path"].as_str().unwrap());
        assert!(auth.starts_with(staged.path()));
        assert_eq!(
            crate::config::read_json::<Value>(auth).unwrap(),
            configuration.files["auth.json"]
        );
        for path in [auth, installed.fetch_config.as_path()] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let serialized = serde_json::to_string(&installed).unwrap();
        assert!(!serialized.contains("fixture"));
        drop(staged);
        configuration.files.clear();
        assert!(configuration.stage(parent.path()).is_err());
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

// Keep a pointer to the installed files, not a second copy of their credentials.
// The provider may refresh its auth file; ordinary restarts must preserve that.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledConfiguration {
    pub fetch_config: PathBuf,
    pub env: BTreeMap<String, String>,
}

impl fmt::Debug for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Configuration { contents withheld }")
    }
}

impl Configuration {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.fetch_config.is_object()
                && self.fetch_config.get("routes").is_some_and(Value::is_array)
                && self
                    .fetch_config
                    .get("callers")
                    .is_some_and(Value::is_array),
            "fetch configuration requires routes and callers arrays"
        );
        for (name, value) in &self.env {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                    && !name.as_bytes()[0].is_ascii_digit()
                    && !["HOME", "PATH", "TMPDIR", "TMP", "TEMP"].contains(&name.as_str())
                    && !["HELLAS_", "LD_", "DYLD_", "RUST_", "SSL_", "NIX_"]
                        .iter()
                        .any(|p| name.starts_with(p))
                    && !value.contains('\0'),
                "invalid or reserved credential environment variable"
            );
        }
        for name in self.files.keys() {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && !name.starts_with('.')
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "credential file name must be a simple filename"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 48 * 1024,
            "worker configuration exceeds 48 KiB"
        );
        Ok(())
    }

    pub(crate) fn stage(
        &self,
        parent: &Path,
    ) -> Result<(tempfile::TempDir, InstalledConfiguration), &'static str> {
        self.validate()
            .map_err(|_| "invalid worker configuration")?;
        let stage = tempfile::Builder::new()
            .prefix(".worker-config-")
            .tempdir_in(parent)
            .map_err(|_| "could not create worker configuration directory")?;
        let files = stage.path().join("files");
        crate::management::private_directory(&files)
            .map_err(|_| "worker filesystem could not create an owner-only credential directory")?;
        for (name, value) in &self.files {
            crate::config::save_private(&files.join(name), value, true)
                .map_err(|_| "could not write private worker credential file")?;
        }
        fn resolve(value: &mut Value, files: &Path, names: &BTreeMap<String, Value>) -> Result<()> {
            match value {
                Value::String(text) if text.starts_with("@files/") => {
                    let name = text.strip_prefix("@files/").unwrap();
                    ensure!(
                        names.contains_key(name),
                        "fetch config references a missing credential file"
                    );
                    *text = files.join(name).to_string_lossy().into_owned();
                }
                Value::Array(values) => {
                    for value in values {
                        resolve(value, files, names)?;
                    }
                }
                Value::Object(values) => {
                    for value in values.values_mut() {
                        resolve(value, files, names)?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
        let mut fetch_config = self.fetch_config.clone();
        resolve(&mut fetch_config, &files, &self.files)
            .map_err(|_| "fetch config references a missing credential file")?;
        let path = stage.path().join("fetch.json");
        crate::config::save_private(&path, &fetch_config, true)
            .map_err(|_| "could not write private worker fetch configuration")?;
        Ok((
            stage,
            InstalledConfiguration {
                fetch_config: path,
                env: self.env.clone(),
            },
        ))
    }
}
