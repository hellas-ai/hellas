use std::{net::SocketAddr, time::Duration};

use anyhow::{Result, ensure};
use iroh::{Endpoint, EndpointAddr, endpoint::presets};
use serde::{Deserialize, Serialize};

use crate::config::{Credentials, Enrollment};

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
    if let Some(owner) = &credentials.owner {
        ensure!(
            owner_key.is_some_and(|key| key.public().to_string() == *owner),
            "machine belongs to another identity; owner key required"
        );
    }
    let mut builder = Endpoint::builder(presets::N0);
    if let Some(key) = owner_key {
        builder = builder.secret_key(key.clone());
    }
    let endpoint = builder.bind().await?;
    let mut addr = EndpointAddr::from(credentials.secret_key()?.public());
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
        ensure!(request.len() <= MAX_MESSAGE, "request too large");
        send.write_all(&request).await?;
        send.finish()?;
        let response = serde_json::from_slice(&recv.read_to_end(MAX_MESSAGE).await?)?;
        connection.close(0u32.into(), b"done");
        Ok::<_, anyhow::Error>(response)
    })
    .await;
    endpoint.close().await;
    result?
}
