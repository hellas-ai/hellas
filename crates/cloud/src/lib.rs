//! Client-side machine allocation. Created machines are normal Hellas nodes;
//! node bootstrap and administration use their own HostControl service.

use async_trait::async_trait;
use hellas_providers::HttpSecretConfig;
use serde::{Deserialize, Serialize};

pub mod runpod;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid machine request: {0}")]
    Invalid(&'static str),
    #[error("credential source unavailable")]
    Credential,
    #[error("provider request failed")]
    Request(#[source] reqwest::Error),
    #[error(
        "creation of machine {name} could not be confirmed; reconcile by name before retrying: {source}"
    )]
    CreationUnconfirmed {
        name: String,
        #[source]
        source: Box<Self>,
    },
    #[error("provider returned HTTP {0}; response body withheld")]
    HttpStatus(reqwest::StatusCode),
    #[error("provider response exceeds the size limit")]
    ResponseBound,
    #[error("invalid provider response")]
    Response,
    #[error(
        "machine {id} was allocated but verification failed; inspect it before retrying: {reason}"
    )]
    Allocated { id: String, reason: &'static str },
}

/// No owner keys or bootstrap credentials cross this interface. The pinned
/// template explicitly opts into `hellas serve --await-owner`; the machine generates
/// its own node identity.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMachine {
    pub name: String,
    pub image: String,
    pub accelerator: String,
    pub accelerator_count: u32,
    #[serde(default)]
    pub interruptible: bool,
}

/// Public provider metadata only. Environment variables and provider secrets
/// must never be projected into this result.
#[derive(Clone, Debug, Serialize)]
pub struct Machine {
    pub id: String,
    pub name: String,
    pub status: String,
    pub image: String,
    pub public_ip: Option<String>,
    pub console_url: Option<String>,
}

#[async_trait]
pub trait Provider: Send + Sync {
    async fn create(&self, request: &CreateMachine) -> Result<Machine>;
    async fn list(&self) -> Result<Vec<Machine>>;
    async fn destroy(&self, id: &str) -> Result<()>;
}

/// Provider selection and its implementation-specific settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(
    tag = "provider",
    content = "config",
    rename_all = "lowercase",
    deny_unknown_fields
)]
pub enum ProviderConfig {
    RunPod(runpod::Config),
}

pub fn open(credential: HttpSecretConfig, config: ProviderConfig) -> Result<Box<dyn Provider>> {
    match config {
        ProviderConfig::RunPod(config) => runpod::open(credential, config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_config_rejects_unknown_selection_and_fields() {
        for invalid in [
            r#"{"provider":"unknown","config":{}}"#,
            r#"{"provider":"runpod","config":{"unknown":true}}"#,
            r#"{"provider":"runpod","config":{},"unknown":true}"#,
        ] {
            assert!(serde_json::from_str::<ProviderConfig>(invalid).is_err());
        }
        let ProviderConfig::RunPod(config) = serde_json::from_str::<ProviderConfig>(include_str!(
            "../../../docs/machine-provider.json"
        ))
        .unwrap();
        assert_eq!(config.template.as_deref(), Some("your-hellas-template-id"));
    }
}
