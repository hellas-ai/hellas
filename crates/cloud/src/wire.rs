use std::{net::SocketAddr, time::Duration};

use hellas_auth::authority::{NodeKey, PrincipalId};
use hellas_auth::{Digest, ProducerSigningKey, hash_tuple};
use iroh::{Endpoint, EndpointAddr, endpoint::Connection, endpoint::presets};
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
    #[error("machine belongs to another owner or administering node")]
    OwnerKey,
    #[error("could not sign the administration session")]
    Sign,
    #[error("could not bind the administration session to its connection")]
    Binding,
    #[error("request too large")]
    RequestBound,
}

pub const ALPN: &[u8] = b"hellas-extras/admin/2";
pub const MAX_MESSAGE: usize = 64 * 1024;
const EXPORTER_LABEL: &[u8] = b"hellas/cloud/admin/v2";

/// The owner as a machine administrator: its principal, and the node whose
/// key proves each administration session. The transport key only dials.
#[derive(Clone)]
pub struct Owner {
    pub principal: PrincipalId,
    pub transport: iroh::SecretKey,
    pub node: ProducerSigningKey,
}

impl Owner {
    pub fn node_key(&self) -> std::result::Result<NodeKey, hellas_auth::authority::AuthorityError> {
        NodeKey::from_public_key(self.node.public_key())
    }
}

/// One administration request. With an owner bound, `proof` is the owner
/// node's signature over [`session_digest`] of this connection, like a daily
/// session: the secret and the bound node key together.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    pub operation: Operation,
}

/// The digest an owner's node key signs: it commits to this exact QUIC
/// connection, so a proof is never valid on another.
pub fn session_digest(connection: &Connection) -> Result<Digest> {
    let mut exporter = [0; 32];
    connection
        .export_keying_material(&mut exporter, EXPORTER_LABEL, ALPN)
        .map_err(|_| AdminError::Binding)?;
    Ok(hash_tuple(
        "hellas.cloud.admin.session.v2",
        &[&exporter, ALPN],
    ))
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
    owner: Option<&Owner>,
) -> Result<Response> {
    let bound = credentials.owner()?;
    if let Some((principal, node)) = bound
        && owner
            .is_none_or(|owner| owner.principal != principal || owner.node_key().ok() != Some(node))
    {
        return Err(AdminError::OwnerKey);
    }
    let owner = owner.filter(|_| bound.is_some());
    let mut builder = Endpoint::builder(presets::N0);
    if let Some(owner) = owner {
        builder = builder.secret_key(owner.transport.clone());
    }
    let mut addr = EndpointAddr::from(credentials.secret_key()?.public());
    let endpoint = builder.bind().await?;
    if let Some(address) = address {
        addr = addr.with_ip_addr(address);
    }
    let result = tokio::time::timeout(Duration::from_secs(3600), async {
        let connection =
            tokio::time::timeout(Duration::from_secs(30), endpoint.connect(addr, ALPN)).await??;
        let proof = owner
            .map(|owner| {
                owner
                    .node
                    .sign_digest(session_digest(&connection)?)
                    .map(|signature| hex::encode(signature.bytes()))
                    .map_err(|_| AdminError::Sign)
            })
            .transpose()?;
        let (mut send, mut recv) = connection.open_bi().await?;
        let request = serde_json::to_vec(&Request {
            token: credentials.token.clone(),
            proof,
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
