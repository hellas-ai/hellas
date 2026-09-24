use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub name: String,
    /// The companion image, derived from the CI-built Hellas image.
    pub image: String,
    pub provider: ProviderConfig,
    #[serde(default)]
    pub trust: Trust,
    /// Arguments to the image's original `hellas-cli serve` entrypoint.
    #[serde(default)]
    pub serve_args: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProviderConfig {
    Docker {
        #[serde(default)]
        gpus: bool,
    },
    Runpod {
        /// Named credential profile; omitted for the legacy RUNPOD_API_KEY account.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
        gpu_type: String,
        disk_gb: u32,
        volume_gb: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        container_registry_auth_id: Option<String>,
    },
    Vast {
        offer_id: u64,
        disk_gb: u32,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trust {
    #[default]
    Token,
    MeasuredBoot,
}

impl Spec {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.trust == Trust::Token,
            "measured-boot requires a platform verifier and channel binding; no adapter implements it yet"
        );
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 48
                && self
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "name must contain 1..48 ASCII letters, digits, or hyphens"
        );
        if let (ProviderConfig::Docker { .. }, Some(digest)) =
            (&self.provider, self.image.strip_prefix("sha256:"))
        {
            validate_hex(digest)?;
        } else {
            let (repo, digest) = self
                .image
                .rsplit_once("@sha256:")
                .context("image must be pinned as repository@sha256:<64 lowercase hex digits>")?;
            ensure!(
                !repo.is_empty()
                    && !repo.starts_with('-')
                    && repo
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b)),
                "invalid image repository"
            );
            validate_hex(digest)?;
        }
        validate_serve_args(&self.serve_args)?;
        match &self.provider {
            ProviderConfig::Runpod {
                account,
                gpu_type,
                disk_gb,
                volume_gb,
                ..
            } => {
                if let Some(account) = account {
                    crate::accounts::validate_name(account)?;
                }
                ensure!(
                    !gpu_type.trim().is_empty() && *disk_gb > 0 && *volume_gb > 0,
                    "Runpod requires a GPU type and positive disk/volume sizes"
                );
            }
            ProviderConfig::Vast { offer_id, disk_gb } => ensure!(
                *offer_id > 0 && *disk_gb > 0,
                "Vast requires a positive offer ID and disk size"
            ),
            _ => {}
        }
        Ok(())
    }
}

pub fn validate_serve_args(args: &[String]) -> Result<()> {
    ensure!(
        args.iter().all(|v| !v.contains('\0')),
        "NUL in serve argument"
    );
    for arg in args {
        let key = arg.split('=').next().unwrap_or(arg);
        ensure!(
            ![
                "--identity",
                "--owner",
                "--software-root",
                "--assurance",
                "--artifact-store-path",
                "--help",
                "-h",
                "--version",
                "--check-config",
                "-V"
            ]
            .contains(&key),
            "reserved serve argument: {key}"
        );
    }
    Ok(())
}

pub fn validate_hex(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected 64 lowercase hex digits"
    );
    Ok(())
}

// Deliberately no Debug implementation for credentials or deployment state.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub admin_secret: String,
    pub token: String,
    /// Public transport identity allowed to administer and use this machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

impl Credentials {
    pub fn generate() -> Self {
        Self {
            admin_secret: hex::encode(iroh::SecretKey::generate().to_bytes()),
            token: hex::encode(iroh::SecretKey::generate().to_bytes()),
            owner: None,
        }
    }

    pub fn secret_key(&self) -> Result<iroh::SecretKey> {
        if let Some(owner) = &self.owner {
            validate_hex(owner)?;
            owner.parse::<iroh::EndpointId>()?;
        }
        validate_hex(&self.admin_secret)?;
        validate_hex(&self.token)?;
        Ok(iroh::SecretKey::from_bytes(
            &hex::decode(&self.admin_secret)?.try_into().unwrap(),
        ))
    }

    pub fn env(&self, spec: &Spec) -> Result<BTreeMap<String, String>> {
        self.env_for_args(&spec.serve_args)
    }

    pub fn env_for_args(&self, args: &[String]) -> Result<BTreeMap<String, String>> {
        self.secret_key()?;
        let mut env = BTreeMap::from([
            ("HELLAS_REMOTE_KEY".into(), self.admin_secret.clone()),
            ("HELLAS_REMOTE_TOKEN".into(), self.token.clone()),
            // Hex makes the Vast Docker-flag representation unambiguous.
            (
                "HELLAS_REMOTE_ARGS".into(),
                hex::encode(serde_json::to_vec(args)?),
            ),
        ]);
        if let Some(owner) = &self.owner {
            env.insert("HELLAS_REMOTE_OWNER".into(), owner.clone());
        }
        Ok(env)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub node_id: String,
    pub enrollment_id: String,
}

impl Enrollment {
    pub fn validate(&self) -> Result<()> {
        self.node_id.parse::<iroh::EndpointId>()?;
        validate_hex(&self.enrollment_id)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub spec: Spec,
    pub credentials: Credentials,
    pub resource_id: Option<String>,
    pub enrollment: Option<Enrollment>,
    #[serde(default)]
    pub destroyed: bool,
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .context("invalid JSON file")
}

/// Serialize operations on a receipt, including the API call between reads and
/// writes. Advisory lock files contain no credentials and survive crashes safely.
pub fn lock_state(path: &Path) -> Result<fs::File> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(name)?;
    file.try_lock()
        .context("another command is using this deployment receipt")?;
    Ok(file)
}

/// Atomic, owner-only state; a failed create leaves the original pending record.
pub fn save_state(path: &Path, value: &Deployment, new: bool) -> Result<()> {
    save_private(path, value, new)
}

pub fn save_private<T: Serialize>(path: &Path, value: &T, new: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = hellas_private::private_tempfile(parent, ".cloud-", ".tmp")?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.as_file().sync_all()?;
    if new {
        file.persist_noclobber(path).map_err(|e| e.error)?;
    } else {
        file.persist(path).map_err(|e| e.error)?;
    }
    hellas_private::sync_directory(parent)?;
    Ok(())
}
