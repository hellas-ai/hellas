use std::{net::SocketAddr, time::Duration};

use iroh::{Endpoint, EndpointAddr, endpoint::presets};
use serde::{Deserialize, Serialize};

use crate::config::{Credentials, Enrollment};

pub type Result<T> = std::result::Result<T, AdminError>;

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Bind(#[from] iroh::endpoint::BindError),
    #[error(transparent)]
    Connect(#[from] iroh::endpoint::ConnectError),
    #[error(transparent)]
    Connection(#[from] iroh::endpoint::ConnectionError),
    #[error(transparent)]
    Write(#[from] iroh::endpoint::WriteError),
    #[error(transparent)]
    Read(#[from] iroh::endpoint::ReadToEndError),
    #[error(transparent)]
    Closed(#[from] iroh::endpoint::ClosedStream),
    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("machine belongs to another identity; owner key required")]
    OwnerKey,
    #[error("request too large")]
    RequestBound,
}

pub const ALPN: &[u8] = b"hellas-extras/admin/1";
pub const MAX_MESSAGE: usize = 64 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub token: String,
    pub operation: Operation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Operation {
    Status,
    Restart,
    Configure {
        configuration: crate::configuration::Configuration,
    },
    Fetch {
        url: String,
        sha256: String,
        bytes: u64,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    Status {
        enrollment: Enrollment,
        #[serde(default)]
        owner: Option<String>,
        running: bool,
    },
    Fetched {
        sha256: String,
        bytes: u64,
    },
    Error {
        message: String,
    },
}

pub async fn call(
    credentials: &Credentials,
    address: Option<SocketAddr>,
    operation: Operation,
) -> Result<Response> {
    call_as(credentials, address, operation, None).await
}

pub async fn call_as(
    credentials: &Credentials,
    address: Option<SocketAddr>,
    operation: Operation,
    owner_key: Option<&iroh::SecretKey>,
) -> Result<Response> {
    if let Some(owner) = &credentials.owner
        && owner_key.is_none_or(|key| key.public().to_string() != *owner)
    {
        return Err(AdminError::OwnerKey);
    }
    let mut builder = Endpoint::builder(presets::N0);
    if let Some(key) = owner_key {
        builder = builder.secret_key(key.clone());
    }
    let mut addr = EndpointAddr::from(credentials.secret_key()?.public());
    let endpoint = builder.bind().await?;
    if let Some(address) = address {
        addr = addr.with_ip_addr(address);
    }
    let result = tokio::time::timeout(Duration::from_secs(3600), async {
        let connection =
            tokio::time::timeout(Duration::from_secs(30), endpoint.connect(addr, ALPN)).await??;
        let (mut send, mut recv) = connection.open_bi().await?;
        let request = serde_json::to_vec(&Request {
            token: credentials.token.clone(),
            operation,
        })?;
        if request.len() > MAX_MESSAGE {
            return Err(AdminError::RequestBound);
        }
        send.write_all(&request).await?;
        send.finish()?;
        let response = serde_json::from_slice(&recv.read_to_end(MAX_MESSAGE).await?)?;
        connection.close(0u32.into(), b"done");
        Ok::<_, AdminError>(response)
    })
    .await;
    endpoint.close().await;
    result?
}
