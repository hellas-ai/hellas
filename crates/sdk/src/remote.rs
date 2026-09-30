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

    /// Hosts persist `root` separately from the provider's platform enrollment.
    pub fn contact_enrollment(
        &self,
        root: &ProducerSigningKey,
    ) -> hellas_client::ClientResult<hellas_rpc::ProviderEnrollmentBundle> {
        use hellas_rpc::*;
        let statement = ProviderGenesisStatement {
            root_kind: RootKind::Software,
            root_public_key: root.public_key(),
            producer_public_key: self.caller_key.public_key(),
            transport_public_key: PublicKey::Ed25519(*self.node_id().as_bytes()),
            platform_credential: PlatformCredential::Absent,
            installation_nonce: *Digest::hash(root.public_key().bytes()).as_bytes(),
        };
        let root_proof = RootProof::Software(
            root.sign_digest(Digest::hash(&statement.canonical_bytes()))
                .map_err(hellas_client::ClientError::external)?,
        );
        Ok(ProviderEnrollmentBundle {
            genesis: SignedProviderGenesis {
                statement,
                root_proof,
            },
            platform: PlatformEnrollment::Absent,
        })
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
