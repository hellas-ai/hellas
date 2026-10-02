use std::{collections::BTreeMap, fs, path::Path};

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(transparent)]
    Account(#[from] crate::accounts::AccountError),
    #[error(transparent)]
    ProviderId(#[from] crate::provider::InvalidProviderId),
    #[error(transparent)]
    Grant(#[from] hellas_rpc::protocol::work_grant::records::GrantError),
    #[error(transparent)]
    Key(#[from] iroh::KeyParsingError),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("read {}", path.display())]
    Read {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("invalid JSON file {}", path.display())]
    JsonFile {
        path: std::path::PathBuf,
        source: serde_json::Error,
    },
    #[error("another command is using deployment receipt {}", path.display())]
    Lock {
        path: std::path::PathBuf,
        source: std::fs::TryLockError,
    },
    #[error("reserved serve argument: {0}")]
    ReservedServeArgument(String),
    #[error(
        "measured-boot requires a platform verifier and channel binding; no adapter implements it yet"
    )]
    MeasuredBoot,
    #[error("name must contain 1..48 ASCII letters, digits, or hyphens")]
    Name,
    #[error("invalid image repository")]
    Repository,
    #[error("Runpod requires a GPU type and positive disk/volume sizes")]
    RunpodResources,
    #[error("Vast requires a positive offer ID and disk size")]
    VastResources,
    #[error("NUL in serve argument")]
    ServeNul,
    #[error("expected 64 lowercase hex digits")]
    HexFormat,
    #[error("owner enrollment exceeds its bound")]
    OwnerBound,
    #[error("owner enrollment does not match the authenticated owner transport")]
    OwnerMismatch,
    #[error("owner enrollment required for worker bootstrap")]
    OwnerRequired,
    #[error("worker enrollment exceeds its bound")]
    EnrollmentBound,
    #[error("worker enrollment ID mismatch")]
    EnrollmentId,
    #[error("worker transport differs from its enrollment")]
    EnrollmentTransport,
    #[error("image must be pinned as repository@sha256:<64 lowercase hex digits>")]
    ImagePin,
    #[error("owner enrollment has no transport binding")]
    OwnerBinding,
    #[error("worker enrollment bundle unavailable; upgrade the managed worker")]
    EnrollmentUnavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub name: String,
    /// Digest-pinned image; resolved from the template before Runpod allocation.
    #[serde(default)]
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
        /// None only for receipts from the earlier image-based prototype.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        template_id: Option<String>,
        gpu_type: String,
        #[serde(default)]
        interruptible: bool,
        #[serde(default)]
        disk_gb: u32,
        #[serde(default)]
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
        if self.trust != Trust::Token {
            return Err(ConfigError::MeasuredBoot);
        }
        if self.name.is_empty()
            || self.name.len() > 48
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ConfigError::Name);
        }
        let unresolved_template = self.image.is_empty()
            && matches!(
                &self.provider,
                ProviderConfig::Runpod {
                    template_id: Some(_),
                    ..
                }
            );
        if unresolved_template {
            // A credential-free dry run cannot resolve account template metadata.
        } else if let (ProviderConfig::Docker { .. }, Some(digest)) =
            (&self.provider, self.image.strip_prefix("sha256:"))
        {
            validate_hex(digest)?;
        } else {
            let (repo, digest) = self
                .image
                .rsplit_once("@sha256:")
                .ok_or(ConfigError::ImagePin)?;
            if repo.is_empty()
                || repo.starts_with('-')
                || !repo
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
            {
                return Err(ConfigError::Repository);
            }
            validate_hex(digest)?;
        }
        validate_serve_args(&self.serve_args)?;
        match &self.provider {
            ProviderConfig::Runpod {
                account,
                template_id,
                gpu_type,
                disk_gb,
                volume_gb,
                ..
            } => {
                if let Some(account) = account {
                    crate::accounts::validate_name(account)?;
                }
                if let Some(id) = template_id {
                    crate::provider::validate_id(id)?;
                }
                if gpu_type.trim().is_empty()
                    || (!unresolved_template && (*disk_gb == 0 || *volume_gb == 0))
                {
                    return Err(ConfigError::RunpodResources);
                }
            }
            ProviderConfig::Vast { offer_id, disk_gb } if (*offer_id == 0 || *disk_gb == 0) => {
                return Err(ConfigError::VastResources);
            }
            _ => {}
        }
        Ok(())
    }
}

pub fn validate_serve_args(args: &[String]) -> Result<()> {
    if args.iter().any(|v| v.contains('\0')) {
        return Err(ConfigError::ServeNul);
    }
    for arg in args {
        let key = arg.split('=').next().unwrap_or(arg);
        if [
            "--identity",
            "--owner",
            "--owner-enrollment",
            "--init-owner",
            "--grant-config",
            "--software-root",
            "--assurance",
            "--artifact-store-path",
            "--help",
            "-h",
            "--version",
            "--check-config",
            "-V",
        ]
        .contains(&key)
        {
            return Err(ConfigError::ReservedServeArgument(key.into()));
        }
    }
    Ok(())
}

pub fn validate_hex(value: &str) -> Result<()> {
    if !(value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err(ConfigError::HexFormat);
    }
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
    /// Canonical public owner enrollment, hex encoded for bootstrap transports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_enrollment: Option<String>,
}

impl Credentials {
    pub fn generate() -> Self {
        Self {
            admin_secret: hex::encode(iroh::SecretKey::generate().to_bytes()),
            token: hex::encode(iroh::SecretKey::generate().to_bytes()),
            owner: None,
            owner_enrollment: None,
        }
    }

    pub fn owner_principal(
        &self,
    ) -> Result<Option<hellas_rpc::protocol::work_grant::records::Principal>> {
        use hellas_rpc::protocol::work_grant::records::{MAX_PRINCIPAL_BYTES, Principal};
        let Some(bundle) = &self.owner_enrollment else {
            return Ok(None);
        };
        if bundle.len() > MAX_PRINCIPAL_BYTES * 2 {
            return Err(ConfigError::OwnerBound);
        }
        let principal = Principal::decode(&hex::decode(bundle)?)?;
        let owner = self
            .owner
            .as_deref()
            .ok_or(ConfigError::OwnerBinding)?
            .parse::<iroh::EndpointId>()?;
        if principal.transport() != *owner.as_bytes() {
            return Err(ConfigError::OwnerMismatch);
        }
        Ok(Some(principal))
    }

    pub fn require_owner_enrollment(&self) -> Result<()> {
        if self.owner.is_some() && self.owner_principal()?.is_none() {
            return Err(ConfigError::OwnerRequired);
        }
        Ok(())
    }

    pub fn secret_key(&self) -> Result<iroh::SecretKey> {
        if let Some(owner) = &self.owner {
            validate_hex(owner)?;
            owner.parse::<iroh::EndpointId>()?;
        }
        self.owner_principal()?;
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
        self.require_owner_enrollment()?;
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
        if let Some(bundle) = &self.owner_enrollment {
            env.insert("HELLAS_REMOTE_OWNER_ENROLLMENT".into(), bundle.clone());
        }
        Ok(env)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub node_id: String,
    pub enrollment_id: String,
    /// Absent only in legacy inventory records. Such a record cannot open an owner grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
}

impl Enrollment {
    pub fn validate(&self) -> Result<()> {
        self.node_id.parse::<iroh::EndpointId>()?;
        validate_hex(&self.enrollment_id)?;
        if self.bundle.is_some() {
            self.principal()?;
        }
        Ok(())
    }
    pub fn principal(&self) -> Result<hellas_rpc::protocol::work_grant::records::Principal> {
        use hellas_rpc::protocol::work_grant::records::{MAX_PRINCIPAL_BYTES, Principal};
        let bundle = self
            .bundle
            .as_deref()
            .ok_or(ConfigError::EnrollmentUnavailable)?;
        if bundle.len() > MAX_PRINCIPAL_BYTES * 2 {
            return Err(ConfigError::EnrollmentBound);
        }
        let principal = Principal::decode(&hex::decode(bundle)?)?;
        if principal.id().0.to_string() != self.enrollment_id {
            return Err(ConfigError::EnrollmentId);
        }
        if principal.transport() != *self.node_id.parse::<iroh::EndpointId>()?.as_bytes() {
            return Err(ConfigError::EnrollmentTransport);
        }
        Ok(principal)
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
    let bytes = fs::read(path).map_err(|source| ConfigError::Read {
        path: path.into(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| ConfigError::JsonFile {
        path: path.into(),
        source,
    })
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
    file.try_lock().map_err(|source| ConfigError::Lock {
        path: path.into(),
        source,
    })?;
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
