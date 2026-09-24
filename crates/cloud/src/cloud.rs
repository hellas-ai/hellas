//! The command subtree embedded directly in the main Hellas CLI.
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    config::{Deployment, ProviderConfig, Spec, Trust, read_json},
    deployment,
    provider::{Cloud, Provider, validate_id},
};

#[derive(Args)]
pub struct CloudArgs {
    /// Use a running private management service for these operations.
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,
    #[command(subcommand)]
    pub provider: CloudCommand,
}

#[derive(Subcommand)]
pub enum CloudCommand {
    /// Manage Runpod GPU pods.
    Runpod(RunpodArgs),
}

#[derive(Args, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunpodArgs {
    /// Named profile in cloud-accounts.json. Omit to use RUNPOD_API_KEY.
    #[arg(long, global = true)]
    #[serde(default)]
    pub account: Option<String>,
    #[command(subcommand)]
    pub command: RunpodCommand,
}

#[derive(Subcommand, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RunpodCommand {
    /// Show one pod's provider metadata (not Hellas readiness).
    Info {
        #[arg(value_parser = parse_id)]
        pod_id: String,
    },
    /// List pods in the selected account, without credentials or environment.
    List,
    /// Create one Hellas pod and save its private administration receipt.
    Create {
        #[arg(long)]
        name: String,
        /// Existing Hellas Runpod template; its image must be digest-pinned.
        #[arg(long, value_parser = parse_id)]
        template: String,
        #[arg(long = "gpu")]
        gpu_type: String,
        /// Request a spot pod that Runpod may interrupt at any time.
        #[arg(long)]
        #[serde(default)]
        interruptible: bool,
        /// Optional receipt path; defaults to the owner machine inventory.
        #[arg(long)]
        state: Option<PathBuf>,
        /// Validate and print the request without reading credentials or allocating.
        #[arg(long)]
        #[serde(default)]
        dry_run: bool,
        /// Arguments for Hellas serve. Execution defaults to disabled.
        #[arg(last = true)]
        #[serde(default)]
        serve_args: Vec<String>,
    },
    /// Delete a pod. With --state, also mark its receipt as destroyed.
    Destroy {
        /// Required unless --state supplies the pod ID and account.
        #[arg(required_unless_present = "state", value_parser = parse_id)]
        pod_id: Option<String>,
        /// Use the saved account; reject conflicting --account or pod ID.
        #[arg(long)]
        state: Option<PathBuf>,
    },
}

fn parse_id(value: &str) -> std::result::Result<String, String> {
    validate_id(value).map_err(|error| error.to_string())?;
    Ok(value.to_owned())
}

impl CloudArgs {
    pub fn needs_identity(&self) -> bool {
        self.socket.is_some()
            || matches!(
                &self.provider,
                CloudCommand::Runpod(RunpodArgs {
                    command: RunpodCommand::Create { dry_run: false, .. }
                        | RunpodCommand::Destroy { state: Some(_), .. },
                    ..
                })
            )
    }

    pub async fn run_owned(self, service: Option<&crate::management::Service>) -> Result<()> {
        ensure!(
            !self.needs_identity() || service.is_some(),
            "an existing Hellas owner identity is required"
        );
        if let Some(socket) = &self.socket {
            let service = service.context("owner identity required")?;
            let inventory =
                crate::internal_rpc::call(socket, crate::management::Request::List).await?;
            ensure!(
                inventory["owner"] == service.owner(),
                "control socket serves another identity"
            );
            let CloudCommand::Runpod(args) = self.provider;
            let result =
                crate::internal_rpc::call(socket, crate::management::Request::Runpod(args)).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        let value = match self.provider {
            CloudCommand::Runpod(args) => args.run_managed(service).await?,
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
        Ok(())
    }
}

impl RunpodArgs {
    pub async fn run(self) -> Result<Value> {
        self.run_managed(None).await
    }

    pub async fn run_managed(self, service: Option<&crate::management::Service>) -> Result<Value> {
        let mut account = self.account;
        let result = match self.command {
            RunpodCommand::List => Cloud::runpod(account.as_deref())?.list().await?,
            RunpodCommand::Info { pod_id } => {
                Cloud::runpod(account.as_deref())?.inspect(&pod_id).await?
            }
            RunpodCommand::Create {
                name,
                template,
                gpu_type,
                interruptible,
                state,
                dry_run,
                mut serve_args,
            } => {
                if serve_args.is_empty() {
                    serve_args = vec!["--execute-policy".into(), "none".into()];
                }
                let spec = Spec {
                    name,
                    image: String::new(),
                    trust: Trust::Token,
                    serve_args,
                    provider: ProviderConfig::Runpod {
                        account: account.clone(),
                        template_id: Some(template),
                        gpu_type,
                        interruptible,
                        disk_gb: 0,
                        volume_gb: 0,
                        container_registry_auth_id: None,
                    },
                };
                spec.validate()?;
                if dry_run {
                    // The payload does not depend on an API credential or profile file.
                    Cloud::new(crate::provider::CloudKind::Runpod)?.plan(&spec)?
                } else if let Some(service) = service {
                    service.create(spec, state).await?
                } else {
                    let state = state.context("create requires --state")?;
                    let id = deployment::create(spec, &state).await?;
                    json!({"id":id, "state":state})
                }
            }
            RunpodCommand::Destroy {
                pod_id,
                state: Some(path),
            } => {
                let state: Deployment = read_json(&path)?;
                if let Some(owner) = &state.credentials.owner {
                    ensure!(
                        service.is_some_and(|service| service.owner() == *owner),
                        "receipt belongs to another identity"
                    );
                }
                let ProviderConfig::Runpod { account: saved, .. } = &state.spec.provider else {
                    bail!("receipt belongs to another cloud provider; refusing termination");
                };
                if let Some(selected) = &account {
                    ensure!(
                        saved.as_ref() == Some(selected),
                        "--account does not match receipt; refusing termination"
                    );
                }
                account = saved.clone();
                let id = deployment::destroy(&path, Some(&state.spec.provider), pod_id.as_deref())
                    .await?;
                json!({"id":id, "destroyed":true, "state":path})
            }
            RunpodCommand::Destroy {
                pod_id,
                state: None,
            } => {
                let id = pod_id.context("destroy requires a pod ID or --state")?;
                Cloud::runpod(account.as_deref())?.destroy(&id).await?;
                json!({"id":id, "destroyed":true})
            }
        };
        Ok(json!({"provider":"runpod", "account":account, "result":result}))
    }
}
