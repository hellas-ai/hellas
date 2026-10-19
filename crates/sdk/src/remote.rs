use hellas_auth::ProducerSigningKey;
use iroh::{EndpointId, SecretKey};

/// A node's own machine keys: the iroh transport key for QUIC handshakes and
/// the secp256k1 node key that signs jobs, daily sessions and transcripts.
/// Neither is a principal. Hosts decide where the secret bytes are persisted
/// (for example, the platform credential store); the SDK never writes them
/// implicitly.
#[derive(Clone)]
pub struct NodeIdentity {
    transport_key: SecretKey,
    node_key: ProducerSigningKey,
}

impl NodeIdentity {
    pub fn generate() -> Self {
        Self {
            transport_key: SecretKey::generate(),
            node_key: ProducerSigningKey::generate(),
        }
    }

    pub fn from_secret_bytes(
        transport_key: [u8; 32],
        node_key: [u8; 32],
    ) -> hellas_client::ClientResult<Self> {
        Ok(Self {
            transport_key: SecretKey::from(transport_key),
            node_key: ProducerSigningKey::from_secret_bytes(node_key)
                .map_err(hellas_client::ClientError::external)?,
        })
    }

    pub fn transport_secret_bytes(&self) -> [u8; 32] {
        self.transport_key.to_bytes()
    }

    pub fn node_secret_bytes(&self) -> [u8; 32] {
        self.node_key.to_secret_bytes()
    }

    pub fn node_id(&self) -> EndpointId {
        self.transport_key.public()
    }

    pub fn transport_key(&self) -> SecretKey {
        self.transport_key.clone()
    }

    pub fn node_key(&self) -> &ProducerSigningKey {
        &self.node_key
    }
}
