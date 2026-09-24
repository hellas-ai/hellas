//! Identity-scoped management shared by the CLI and internal RPC.
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use iroh::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    config::{
        Credentials, Deployment, Enrollment, Spec, lock_state, read_json, save_private,
        validate_serve_args,
    },
    wire::{self, Operation, Response},
};

#[derive(Deserialize, Serialize)]
#[serde(tag = "method", content = "params", deny_unknown_fields)]
pub enum Request {
    #[serde(rename = "machines.list")]
    List,
    #[serde(rename = "machines.status")]
    Status { name: String },
    #[serde(rename = "machines.resolve")]
    Resolve { name: String },
    #[serde(rename = "machines.restart")]
    Restart { name: String },
    #[serde(rename = "machines.fetch")]
    Fetch {
        name: String,
        url: String,
        sha256: String,
        bytes: u64,
    },
    #[serde(rename = "machines.prepare")]
    Prepare {
        name: String,
        bootstrap_file: PathBuf,
        #[serde(default)]
        admin_addr: Option<SocketAddr>,
        #[serde(default)]
        serve_args: Vec<String>,
    },
    #[serde(rename = "machines.destroy")]
    Destroy { name: String },
    #[serde(rename = "cloud.runpod")]
    Runpod(crate::cloud::RunpodArgs),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Machine {
    name: String,
    owner: String,
    source: Source,
    enrollment: Option<Enrollment>,
    last_seen_unix: Option<u64>,
    running: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Source {
    Cloud {
        receipt: PathBuf,
    },
    BareMetal {
        credentials: Credentials,
        admin_addr: Option<SocketAddr>,
    },
}

pub struct Service {
    key: SecretKey,
    root: PathBuf,
}

impl Service {
    /// `base` is a trusted local state directory; each identity has its own inventory.
    pub fn new(key: SecretKey, base: &Path) -> Result<Self> {
        let root = base.join(key.public().to_string());
        private_directory(&root)?;
        Ok(Self { key, root })
    }

    pub fn open(key: SecretKey) -> Result<Self> {
        let base = match std::env::var_os("HELLAS_MACHINES_DIR") {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from(std::env::var_os("HOME").context("HOME is unset")?)
                .join(".hellas/machines"),
        };
        Self::new(key, &base)
    }

    pub fn owner(&self) -> String {
        self.key.public().to_string()
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        crate::accounts::validate_name(name)?;
        Ok(self.root.join(format!("{name}.json")))
    }

    fn load(&self, name: &str) -> Result<Machine> {
        let machine: Machine = read_json(&self.path(name)?)?;
        ensure!(
            machine.name == name && machine.owner == self.owner(),
            "machine belongs to another identity"
        );
        Ok(machine)
    }

    fn credentials(&self, machine: &Machine) -> Result<(Credentials, Option<SocketAddr>)> {
        let (credentials, address) = match &machine.source {
            Source::Cloud { receipt } => {
                let state: Deployment = read_json(receipt)?;
                ensure!(!state.destroyed, "machine was destroyed");
                (state.credentials, None)
            }
            Source::BareMetal {
                credentials,
                admin_addr,
            } => (credentials.clone(), *admin_addr),
        };
        ensure!(
            credentials.owner.as_deref() == Some(&self.owner()),
            "machine is not bound to this identity"
        );
        credentials.secret_key()?;
        Ok((credentials, address))
    }

    fn view(&self, machine: &Machine) -> Result<Value> {
        let (location, lifecycle) = match &machine.source {
            Source::Cloud { receipt } if receipt.exists() => {
                let state: Deployment = read_json(receipt)?;
                ensure!(
                    state.credentials.owner.as_deref() == Some(&self.owner()),
                    "receipt owner mismatch"
                );
                (
                    json!({"provider":state.spec.provider, "resource_id":state.resource_id}),
                    if state.destroyed {
                        "destroyed"
                    } else if state.resource_id.is_some() {
                        "allocated"
                    } else {
                        "pending"
                    },
                )
            }
            Source::Cloud { .. } => (json!({}), "pending"),
            Source::BareMetal { .. } => (json!({"provider":{"kind":"bare-metal"}}), "registered"),
        };
        Ok(
            json!({"name":machine.name, "owner":machine.owner, "location":location,
            "lifecycle":lifecycle, "enrollment":machine.enrollment,
            "last_seen_unix":machine.last_seen_unix, "last_observed_running":machine.running}),
        )
    }

    pub fn list(&self) -> Result<Value> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                names.push(
                    path.file_stem()
                        .context("invalid machine filename")?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        names.sort();
        let machines = names
            .iter()
            .map(|name| self.view(&self.load(name)?))
            .collect::<Result<Vec<_>>>()?;
        Ok(json!({"owner":self.owner(), "machines":machines}))
    }

    pub async fn create(&self, spec: Spec, receipt: Option<PathBuf>) -> Result<Value> {
        spec.validate()?;
        let _lock = lock_state(&self.root.join("inventory"))?;
        let path = self.path(&spec.name)?;
        ensure!(!path.exists(), "machine name already exists");
        let receipt = receipt.unwrap_or_else(|| {
            self.root
                .join("receipts")
                .join(format!("{}.json", spec.name))
        });
        let receipt = std::path::absolute(receipt)?;
        ensure!(
            !receipt.exists(),
            "receipt already exists; allocation was not attempted"
        );
        let mut credentials = Credentials::generate();
        credentials.owner = Some(self.owner());
        let machine = Machine {
            name: spec.name.clone(),
            owner: self.owner(),
            source: Source::Cloud {
                receipt: receipt.clone(),
            },
            enrollment: None,
            last_seen_unix: None,
            running: None,
        };
        // Keep the machine visible even if allocation or the final receipt write fails.
        save_private(&path, &machine, true)?;
        let result = crate::deployment::create_with_credentials(spec, &receipt, credentials).await;
        if result.is_err() && !receipt.exists() {
            // No API call can precede the receipt. A local preflight failure is retryable.
            std::fs::remove_file(&path)?;
        }
        let id = result?;
        Ok(json!({"id":id, "state":receipt, "machine":machine.name, "owner":self.owner()}))
    }

    fn prepare(
        &self,
        name: String,
        bootstrap_file: PathBuf,
        admin_addr: Option<SocketAddr>,
        mut serve_args: Vec<String>,
    ) -> Result<Value> {
        let _lock = lock_state(&self.root.join("inventory"))?;
        let path = self.path(&name)?;
        ensure!(!path.exists(), "machine name already exists");
        if serve_args.is_empty() {
            serve_args = vec!["--execute-policy".into(), "none".into()];
        }
        validate_serve_args(&serve_args)?;
        let mut credentials = Credentials::generate();
        credentials.owner = Some(self.owner());
        // JSON avoids executable shell snippets; install this private file on the host.
        let bootstrap = credentials.env_for_args(&serve_args)?;
        save_private(&bootstrap_file, &bootstrap, true)?;
        let machine = Machine {
            name,
            owner: self.owner(),
            source: Source::BareMetal {
                credentials,
                admin_addr,
            },
            enrollment: None,
            last_seen_unix: None,
            running: None,
        };
        save_private(&path, &machine, true)?;
        self.view(&machine)
    }

    async fn admin(&self, name: &str, operation: Operation) -> Result<Value> {
        let path = self.path(name)?;
        let _lock = lock_state(&path)?;
        let mut machine = self.load(name)?;
        let (credentials, address) = self.credentials(&machine)?;
        let response = wire::call_as(&credentials, address, operation, Some(&self.key)).await?;
        match &response {
            Response::Error { message } => bail!("{message}"),
            Response::Status {
                enrollment,
                owner,
                running,
            } => {
                ensure!(
                    *owner == credentials.owner,
                    "agent did not confirm the owner binding; upgrade the companion image"
                );
                enrollment.validate()?;
                if let Some(expected) = &machine.enrollment {
                    ensure!(
                        expected == enrollment,
                        "machine enrollment changed; refusing to replace its trust anchor"
                    );
                } else {
                    ensure!(
                        *running,
                        "Hellas is not running; check the image supports serve --owner"
                    );
                    machine.enrollment = Some(enrollment.clone());
                }
                machine.running = Some(*running);
                machine.last_seen_unix = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs(),
                );
                save_private(&path, &machine, false)?;
            }
            _ => {}
        }
        Ok(serde_json::to_value(response)?)
    }

    /// Live owner authentication plus a stable, enrolled execution route.
    pub async fn resolve(&self, name: &str) -> Result<Enrollment> {
        let response = self.admin(name, Operation::Status).await?;
        ensure!(response["running"] == true, "machine is not running");
        self.load(name)?
            .enrollment
            .context("machine has not enrolled")
    }

    pub async fn execute(&self, request: Request) -> Result<Value> {
        match request {
            Request::List => self.list(),
            Request::Status { name } => self.admin(&name, Operation::Status).await,
            Request::Resolve { name } => Ok(serde_json::to_value(self.resolve(&name).await?)?),
            Request::Restart { name } => {
                self.resolve(&name).await?;
                self.admin(&name, Operation::Restart).await
            }
            Request::Fetch {
                name,
                url,
                sha256,
                bytes,
            } => {
                crate::agent::validate_download(&url, &sha256, bytes)?;
                // Confirm the owner-capable protocol before any mutation.
                self.resolve(&name).await?;
                self.admin(&name, Operation::Fetch { url, sha256, bytes })
                    .await
            }
            Request::Prepare {
                name,
                bootstrap_file,
                admin_addr,
                serve_args,
            } => self.prepare(name, bootstrap_file, admin_addr, serve_args),
            Request::Destroy { name } => {
                let path = self.path(&name)?;
                let _lock = lock_state(&path)?;
                let machine = self.load(&name)?;
                self.credentials(&machine)?;
                let Source::Cloud { receipt } = machine.source else {
                    bail!("bare-metal hosts cannot be destroyed through a cloud adapter")
                };
                let id = crate::deployment::destroy(&receipt, None, None).await?;
                Ok(json!({"id":id,"destroyed":true}))
            }
            Request::Runpod(args) => args.run_managed(Some(self)).await,
        }
    }
}

/// Refuse an existing shared or foreign directory instead of silently changing it.
pub(crate) fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "management directory must be owned by this user with mode 0700"
    );
    Ok(())
}
