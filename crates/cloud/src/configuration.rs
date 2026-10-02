//! Private worker settings delivered over the owner's authenticated admin channel.
use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type Result<T> = std::result::Result<T, ConfigurationError>;

#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("fetch configuration requires routes; legacy callers are unsupported")]
    FetchRoutes,
    #[error(
        "grant configuration requires resources and machine_limits; journal and socket paths are managed"
    )]
    GrantResources,
    #[error("invalid or reserved credential environment variable")]
    Environment,
    #[error("credential file name must be a simple filename")]
    Filename,
    #[error("worker configuration exceeds 48 KiB")]
    SizeBound,
    #[error("fetch config references a missing credential file")]
    MissingFile,
    #[error("worker filesystem does not preserve credential directory ownership")]
    DirectoryOwner,
    #[error("worker filesystem does not preserve private credential directory permissions")]
    DirectoryPermissions,
    #[error("could not create worker configuration directory")]
    CreateDirectory(#[source] std::io::Error),
    #[error("could not write private worker credential file")]
    WriteCredentials(#[source] crate::config::ConfigError),
    #[error("could not write private worker fetch configuration")]
    WriteFetch(#[source] crate::config::ConfigError),
    #[error("could not write private worker grant configuration")]
    WriteGrants(#[source] crate::config::ConfigError),
    #[error("could not open worker credential directory")]
    OpenDirectory(#[source] std::io::Error),
    #[error("could not inspect worker credential directory")]
    InspectDirectory(#[source] std::io::Error),
    #[error("could not restrict worker credential directory permissions")]
    RestrictDirectory(#[source] std::io::Error),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    /// The CLI's Fetch routes. Authority comes exclusively from Work grants.
    pub fetch_config: Value,
    /// Complete Work resources and machine limits; journal/socket paths are managed.
    pub grant_config: Value,
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
    fn staging_restricts_permissions_but_refuses_symlinks() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("fresh");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        restrict_staging_directory(&directory).unwrap();
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert!(restrict_staging_directory(&link).is_err());
    }

    #[test]
    fn staged_credentials_are_private_and_missing_references_leave_no_files() {
        let parent = tempfile::tempdir().unwrap();
        let mut configuration = Configuration {
            fetch_config: json!({"routes":[{"auth_path":"@files/auth.json"}]}),
            grant_config: json!({"resources":[],"machine_limits":[]}),
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
    pub grant_config: PathBuf,
    pub env: BTreeMap<String, String>,
}

impl fmt::Debug for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Configuration { contents withheld }")
    }
}

impl Configuration {
    pub fn validate(&self) -> Result<()> {
        if !(self.fetch_config.is_object()
            && self.fetch_config.get("routes").is_some_and(Value::is_array)
            && self.fetch_config.get("callers").is_none())
        {
            return Err(ConfigurationError::FetchRoutes);
        }
        if !(self.grant_config.is_object()
            && self
                .grant_config
                .get("resources")
                .is_some_and(Value::is_array)
            && self
                .grant_config
                .get("machine_limits")
                .is_some_and(Value::is_array)
            && self.grant_config.get("journal_root").is_none()
            && self.grant_config.get("control_socket").is_none())
        {
            return Err(ConfigurationError::GrantResources);
        }
        for (name, value) in &self.env {
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                || name.as_bytes()[0].is_ascii_digit()
                || ["HOME", "PATH", "TMPDIR", "TMP", "TEMP"].contains(&name.as_str())
                || ["HELLAS_", "LD_", "DYLD_", "RUST_", "SSL_", "NIX_"]
                    .iter()
                    .any(|p| name.starts_with(p))
                || value.contains('\0')
            {
                return Err(ConfigurationError::Environment);
            }
        }
        for name in self.files.keys() {
            if name.is_empty()
                || name.len() > 128
                || name.starts_with('.')
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err(ConfigurationError::Filename);
            }
        }
        if serde_json::to_vec(self)?.len() > 48 * 1024 {
            return Err(ConfigurationError::SizeBound);
        }
        Ok(())
    }

    pub(crate) fn stage(
        &self,
        parent: &Path,
    ) -> Result<(tempfile::TempDir, InstalledConfiguration)> {
        self.validate()?;
        let stage = tempfile::Builder::new()
            .prefix(".worker-config-")
            .tempdir_in(parent)
            .map_err(ConfigurationError::CreateDirectory)?;
        restrict_staging_directory(stage.path())?;
        let files = stage.path().join("files");
        std::fs::create_dir(&files).map_err(ConfigurationError::CreateDirectory)?;
        restrict_staging_directory(&files)?;
        for (name, value) in &self.files {
            crate::config::save_private(&files.join(name), value, true)
                .map_err(ConfigurationError::WriteCredentials)?;
        }
        fn resolve(value: &mut Value, files: &Path, names: &BTreeMap<String, Value>) -> Result<()> {
            match value {
                Value::String(text) if text.starts_with("@files/") => {
                    let name = text.strip_prefix("@files/").unwrap();
                    if !names.contains_key(name) {
                        return Err(ConfigurationError::MissingFile);
                    }
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
        resolve(&mut fetch_config, &files, &self.files)?;
        let path = stage.path().join("fetch.json");
        crate::config::save_private(&path, &fetch_config, true)
            .map_err(ConfigurationError::WriteFetch)?;
        let mut grant_config = self.grant_config.clone();
        grant_config["journal_root"] = serde_json::json!(parent.join("grants"));
        grant_config["control_socket"] = serde_json::json!(parent.join("control.sock"));
        resolve(&mut grant_config, &files, &self.files)?;
        let grant_path = stage.path().join("grant.json");
        crate::config::save_private(&grant_path, &grant_config, true)
            .map_err(ConfigurationError::WriteGrants)?;
        Ok((
            stage,
            InstalledConfiguration {
                fetch_config: path,
                grant_config: grant_path,
                env: self.env.clone(),
            },
        ))
    }
}

// Only for fresh, empty staging directories. Some provider filesystems ignore
// mkdir's mode but support chmod. Verify the result before writing any secrets.
fn restrict_staging_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(ConfigurationError::OpenDirectory)?;
    let metadata = directory
        .metadata()
        .map_err(ConfigurationError::InspectDirectory)?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(ConfigurationError::DirectoryOwner);
    }
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(ConfigurationError::RestrictDirectory)?;
    if directory
        .metadata()
        .map_err(ConfigurationError::InspectDirectory)?
        .permissions()
        .mode()
        & 0o777
        != 0o700
    {
        return Err(ConfigurationError::DirectoryPermissions);
    }
    Ok(())
}
