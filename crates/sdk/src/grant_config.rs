//! Local resource configuration shares exactly the paid WorkPolicy parser.
//! Grants and their counters remain runtime state in the provider journal.
use crate::work_config::{ExecutionPolicyFile, FetchPolicyFile, WorkConfigError};
use hellas_rpc::protocol::work_grant::{
    budget::Limit,
    records::{GrantError, GrantPolicy},
    resource::HttpsResource,
};
use serde::Deserialize;
use std::{
    num::NonZeroU64,
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
pub enum GrantConfigError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Policy(#[from] WorkConfigError),
    #[error(transparent)]
    Grant(#[from] GrantError),
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceFile {
    name: String,
    execution: Option<ExecutionPolicyFile>,
    fetch: Option<FetchPolicyFile>,
    https: Option<HttpsResource>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    journal_root: Option<PathBuf>,
    control_socket: Option<PathBuf>,
    machine_limits: Option<Vec<Limit>>,
    max_in_flight: u16,
    max_job_millis: NonZeroU64,
    resources: Vec<ResourceFile>,
}
pub struct GrantConfig {
    pub journal_root: PathBuf,
    pub control_socket: PathBuf,
    pub machine_limits: Option<Vec<Limit>>,
    pub max_in_flight: u16,
    pub max_job_millis: NonZeroU64,
    pub resources: Vec<GrantPolicy>,
}
impl GrantConfig {
    /// Enrollment can precede resource configuration. Existing durable machine
    /// limits remain authoritative when no replacement was explicitly supplied.
    pub fn unconfigured(root: &Path) -> Self {
        Self {
            journal_root: root.join("provider"),
            control_socket: root.join("control.sock"),
            machine_limits: None,
            max_in_flight: 256,
            max_job_millis: NonZeroU64::new(1_800_000).expect("positive"),
            resources: vec![],
        }
    }

    pub fn load(path: &Path, default_root: &Path) -> Result<Self, GrantConfigError> {
        let bytes = hellas_private::read_bounded_regular_file(path, 1 << 20)?;
        let file: ConfigFile = serde_json::from_slice(&bytes)?;
        let journal_root = file
            .journal_root
            .unwrap_or_else(|| default_root.join("provider"));
        let control_socket = file
            .control_socket
            .unwrap_or_else(|| default_root.join("control.sock"));
        if !journal_root.is_absolute()
            || !control_socket.is_absolute()
            || file.max_in_flight == 0
            || file.max_in_flight > 256
            || file.resources.len() > 16
            || (file.machine_limits.is_none() && !file.resources.is_empty())
        {
            return Err(GrantError::Limits.into());
        }
        let resources = file
            .resources
            .into_iter()
            .map(|p| {
                let work = match (p.execution, p.fetch) {
                    (Some(execution), None) => execution.into_policy()?.into(),
                    (None, Some(fetch)) => fetch.into_policy()?,
                    _ => return Err(GrantConfigError::Grant(GrantError::Malformed)),
                };
                let policy = GrantPolicy {
                    name: p.name,
                    work,
                    https: p.https,
                };
                policy.validate()?;
                Ok(policy)
            })
            .collect::<Result<Vec<_>, GrantConfigError>>()?;
        let mut names = std::collections::BTreeSet::new();
        for resource in &resources {
            if !names.insert(&resource.name) {
                return Err(GrantError::Malformed.into());
            }
        }
        Ok(Self {
            journal_root,
            control_socket,
            machine_limits: file.machine_limits,
            max_in_flight: file.max_in_flight,
            max_job_millis: file.max_job_millis,
            resources,
        })
    }
}
