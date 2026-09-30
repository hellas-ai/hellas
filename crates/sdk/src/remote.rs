use hellas_rpc::ProducerSigningKey;
use iroh::{EndpointId, SecretKey};
/// Stable native caller identity. Hosts decide where these secret bytes are
/// persisted (for example, Gate uses its private application directory or the
/// platform credential store); the SDK never writes them implicitly.
#[derive(Clone)]
pub struct ClientIdentity {
    transport_key: SecretKey,
    caller_key: ProducerSigningKey,
}

impl ClientIdentity {
    pub fn generate() -> Self {
        Self {
            transport_key: SecretKey::generate(),
            caller_key: ProducerSigningKey::generate(),
        }
    }

    pub fn from_secret_bytes(
        transport_key: [u8; 32],
        caller_key: [u8; 32],
    ) -> hellas_client::ClientResult<Self> {
        Ok(Self {
            transport_key: SecretKey::from(transport_key),
            caller_key: ProducerSigningKey::from_secret_bytes(caller_key)
                .map_err(hellas_client::ClientError::external)?,
        })
    }

    pub fn transport_secret_bytes(&self) -> [u8; 32] {
        self.transport_key.to_bytes()
    }

    pub fn caller_secret_bytes(&self) -> [u8; 32] {
        self.caller_key.to_secret_bytes()
    }

    pub fn node_id(&self) -> EndpointId {
        self.transport_key.public()
    }

    pub fn transport_key(&self) -> SecretKey {
        self.transport_key.clone()
    }

    pub fn caller_key(&self) -> &ProducerSigningKey {
        &self.caller_key
    }
}
