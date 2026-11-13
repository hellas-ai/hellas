//! SDK transport worlds built on the shared, checked Work fixture.
use crate::{grant_client::*, node_control::profile::ClientProfile};
use hellas_auth::authority::*;
use hellas_authority::model::grant::records::{GrantDef, Offer, SignedOffer};
use hellas_private::StoreLocation;
use hellas_rpc::Assurance;
use std::sync::Arc;
use {
    hellas_authority::test_support as work, hellas_authority::test_support::*,
    hellas_channel::test_support::actors::*,
};

pub(crate) fn provider_enrollment() -> hellas_rpc::ProviderEnrollmentBundle {
    work::enrollment(
        &PROVIDER.node_key(),
        &PROVIDER.node_key(),
        *iroh::SecretKey::from_bytes(&[5; 32]).public().as_bytes(),
        [5; 32],
    )
}

fn transport_enrollment(key: &iroh::SecretKey) -> hellas_rpc::ProviderEnrollmentBundle {
    work::enrollment(
        &PROVIDER.node_key(),
        &PROVIDER.node_key(),
        *key.public().as_bytes(),
        [5; 32],
    )
}

pub(crate) use work::backend::Backend as FakeProvider;
const GATEWAY_ACCESS: GrantId = GrantId([104; 16]);

pub(crate) struct HostBuilder {
    allowance: Allowance,
    capacity: Capacity,
    backend: FakeProvider,
    transport_key: iroh::SecretKey,
}
pub(crate) struct Host {
    pub root: tempfile::TempDir,
    pub world: TestService,
    pub content: hellas_store::content::DiskStore,
    pub backend: FakeProvider,
    pub application: Arc<ClientProfile>,
    pub allowance: GrantDef,
    transport_key: iroh::SecretKey,
}
impl Host {
    pub fn builder() -> HostBuilder {
        HostBuilder {
            allowance: Allowance::responses(ids::ALLOWANCE, FRIEND),
            capacity: Capacity::new(4),
            transport_key: iroh::SecretKey::from_bytes(&[5; 32]),
            backend: FakeProvider {
                signer: Arc::new(PROVIDER.node_key()),
                finish: work::backend::Completion::Immediate,
                ..Default::default()
            },
        }
    }
    fn enrollment(&self) -> hellas_rpc::ProviderEnrollmentBundle {
        transport_enrollment(&self.transport_key)
    }
    pub fn options(&self, addresses: Vec<String>) -> GrantSessionOptions {
        let provider = self.enrollment();
        let signed = SignedOffer::sign(
            Offer {
                network: network(),
                provider: provider.clone(),
                grant: self.allowance.clone(),
                generation: 0,
                sequence: 1,
                valid_until: UnixMillis(u64::MAX),
                addresses,
            },
            &PROVIDER.node_key(),
        )
        .unwrap();
        let target = UnpinnedOffer::decode(&signed.encode().unwrap(), self.world.clock.now())
            .unwrap()
            .pin(&hellas_client::ProviderTrustAnchor {
                expected_genesis: provider.content_id(),
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            })
            .unwrap();
        let location = StoreLocation::for_test(&self.root.path().join("client"));
        GrantSessionOptions {
            target,
            principal: FRIEND.principal(),
            signer: Arc::new(FRIEND.node_key()),
            application: self.application.clone(),
            journal_root: location,
            // Control calls stay bounded independently of the signed job limit.
            control_timeout: std::time::Duration::from_secs(5),
        }
    }
    pub async fn gateway_access(&self) -> hellas_gateway::GatewayAccess {
        let node = self.world.service.node();
        let admin = self.world.administrator(ROOT).await;
        let scope = Rights::new(authority(), ROOT)
            .allow(
                hellas_authority::node::GATEWAY_INVOKE,
                hellas_authority::node::host_resource(authority()),
            )
            .valid_from(self.world.clock.now())
            .valid_until(UnixMillis(u64::MAX))
            .build();
        let [] = credentials::issue(
            credentials::Issuer::Node(&node),
            &admin,
            ids::ROOT_GRANT,
            Some(GATEWAY_ACCESS),
            scope.clone(),
        )
        .await;
        let (_, secret) = hellas_authority::test_support::credentials::issue_one(
            &node,
            &admin,
            ids::ROOT_GRANT,
            scope,
            hellas_auth::authority::CredentialHolder::Bearer,
        )
        .await
        .unwrap();
        hellas_gateway::GatewayAccess::new(node, GATEWAY_ACCESS, secret)
            .await
            .unwrap()
    }
    /// The real provider dispatch loop, with a deterministic backend and pinned proof.
    pub async fn remote(&self) -> RemoteHost {
        self.remote_at("127.0.0.1:0".parse().unwrap()).await
    }
    pub async fn remote_at(&self, address: std::net::SocketAddr) -> RemoteHost {
        use hellas_rpc::services::work::Work;
        use hellas_wire::{ServiceMarker, iroh::IrohTransport};
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(self.transport_key.clone())
            .alpns(vec![Work::ALPN.as_bytes().to_vec()])
            .bind_addr(address)
            .unwrap()
            .bind()
            .await
            .unwrap();
        let listener = endpoint.clone();
        let enrollment = self.enrollment();
        let router = crate::work_router::WorkRouter::grants(self.world.service.clone());
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Some(incoming) = listener.accept().await {
                let router = router.clone();
                let enrollment = enrollment.clone();
                connections.spawn(async move {
                    let transport = Arc::new(IrohTransport::new(incoming.await.unwrap()));
                    if let Ok(server) = router
                        .accept_iroh(
                            &transport,
                            crate::test_identity::OpenProof(enrollment, PROVIDER.node_key()),
                        )
                        .await
                    {
                        let _ = super::super::serve_loop(
                            transport,
                            server,
                            tokio::sync::watch::channel(false).1,
                            crate::provider::RPC_CONNECTION_IDLE_TIMEOUT,
                            tokio::time::Instant::now() + crate::provider::MAX_LIFETIME,
                        )
                        .await;
                    }
                });
            }
            connections.shutdown().await;
        });
        RemoteHost { endpoint, task }
    }
}
impl HostBuilder {
    pub fn with_transport_key(mut self, key: u8) -> Self {
        self.transport_key = iroh::SecretKey::from_bytes(&[key; 32]);
        self
    }
    pub fn with_allowance(mut self, allowance: Allowance) -> Self {
        self.allowance = allowance;
        self
    }
    pub fn with_capacity(mut self, capacity: Capacity) -> Self {
        self.capacity = capacity;
        self
    }
    pub fn with_backend(mut self, mut backend: FakeProvider) -> Self {
        backend.signer = Arc::new(PROVIDER.node_key());
        self.backend = backend;
        self
    }
    pub async fn build(self) -> Host {
        let root = tempfile::tempdir().unwrap();
        hellas_private::restrict_directory(root.path()).unwrap();
        let allowance = self.allowance.definition.clone();
        let clock = TestClock::default();
        let world = Node::bootstrap(&root.path().join("provider"))
            .with_clock(clock.clone())
            .with_provider(transport_enrollment(&self.transport_key))
            .with_capacity(self.capacity)
            .with_allowance(self.allowance)
            .with_grant(
                ids::FRIEND_GRANT,
                Rights::new(authority(), FRIEND)
                    .allow(
                        hellas_authority::grant_service::WORK_EXECUTE,
                        hellas_authority::grant_service::allowance_resource(
                            authority(),
                            allowance.id,
                        ),
                    )
                    .valid_from(clock.now())
                    .valid_until(UnixMillis(u64::MAX))
                    .build(),
            )
            .build()
            .await;
        let content = world.content.clone();
        let world = world.serve(self.backend.clone());
        let secret = world.secret(FRIEND);
        let application = Arc::new(ClientProfile {
            authority: authority(),
            authorization: ids::FRIEND_GRANT,
            credential: CredentialSecret::from_parts(secret.id(), *secret.expose_secret()),
            local: None,
        });
        Host {
            root,
            world,
            content,
            backend: self.backend,
            application,
            allowance,
            transport_key: self.transport_key,
        }
    }
}
pub(crate) struct RemoteHost {
    pub endpoint: iroh::Endpoint,
    task: tokio::task::JoinHandle<()>,
}
impl RemoteHost {
    pub fn addresses(&self) -> Vec<String> {
        self.endpoint
            .bound_sockets()
            .iter()
            .map(ToString::to_string)
            .collect()
    }
    pub async fn shutdown(self) {
        self.endpoint.close().await;
        self.task.await.unwrap();
    }
}
