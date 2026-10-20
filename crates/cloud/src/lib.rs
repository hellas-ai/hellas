//! Client-side machine allocation. Created machines are normal Hellas nodes;
//! node bootstrap and administration use their own HostControl service.

use async_trait::async_trait;
use hellas_providers::HttpSecretConfig;
use serde::{Deserialize, Serialize};

mod runpod;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported machine provider")]
    UnsupportedProvider,
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
/// image boots `hellas serve --await-owner` and generates its own node identity.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMachine {
    pub name: String,
    pub image: String,
    pub template: String,
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

pub fn open(provider: &str, credential: HttpSecretConfig) -> Result<Box<dyn Provider>> {
    runpod::open(provider, credential)
}
