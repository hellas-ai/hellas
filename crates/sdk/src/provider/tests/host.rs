//! SDK transport worlds built on the shared, checked Work fixture.
use crate::{grant_client::*, node_control::profile::ClientProfile};
use hellas_auth::authority::*;
use hellas_rpc::Assurance;
use hellas_work::model::grant::records::{GrantDef, Offer, SignedOffer};
use hellas_work::test_support::{self as work, actors::*, *};
use std::sync::Arc;

pub(crate) fn provider_enrollment() -> hellas_rpc::ProviderEnrollmentBundle {
    work::enrollment(
        &PROVIDER.node_key(),
        &PROVIDER.node_key(),
        *iroh::SecretKey::from_bytes(&[5; 32]).public().as_bytes(),
        [5; 32],
    )
}

pub(crate) use work::backend::Backend as FakeProvider;
const GATEWAY_ACCESS: GrantId = GrantId([104; 16]);

pub(crate) struct HostBuilder {
    allowance: Allowance,
    capacity: Capacity,
    backend: FakeProvider,
}
pub(crate) struct Host {
    pub root: tempfile::TempDir,
    pub world: TestService,
    pub backend: FakeProvider,
    pub application: Arc<ClientProfile>,
    pub allowance: GrantDef,
}
impl Host {
    pub fn builder() -> HostBuilder {
        HostBuilder {
            allowance: Allowance::responses(ids::ALLOWANCE, FRIEND),
            capacity: Capacity::new(4),
            backend: FakeProvider {
                signer: Arc::new(PROVIDER.node_key()),
                finish: work::backend::Completion::Immediate,
                ..Default::default()
            },
        }
    }
    pub fn options(&self, addresses: Vec<String>) -> GrantSessionOptions {
        let provider = provider_enrollment();
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
                allowed_environments: self
                    .allowance
                    .policies
                    .iter()
                    .map(|p| p.work.allowed_environment())
                    .collect(),
                expected_genesis: provider.content_id(),
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            })
            .unwrap();
        GrantSessionOptions {
            target,
            principal: FRIEND.principal(),
            signer: Arc::new(FRIEND.node_key()),
            application: self.application.clone(),
            journal_root: self.root.path().join("client"),
            // A job deadline below the grant limit leaves room for the client
            // monotonic clock while the injected provider clock stays fixed.
            timeout: std::time::Duration::from_secs(5),
        }
    }
    pub async fn gateway_access(&self) -> hellas_gateway::GatewayAccess {
        let node = self.world.service.node();
        let admin = self.world.administrator(ROOT).await;
        let scope = Rights::new(authority(), ROOT)
            .allow(
                hellas_work::node::GATEWAY_INVOKE,
                hellas_work::node::host_resource(authority()),
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
        let (_, secret) = hellas_work::test_support::credentials::issue_one(
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
    pub async fn responses_options(
        &self,
        addresses: Vec<String>,
    ) -> crate::grant_gateway::responses::FetchGatewayOptions {
        crate::grant_gateway::responses::FetchGatewayOptions {
            access: self.gateway_access().await,
            archive: hellas_gateway::ArchiveOptions {
                directory: self.root.path().join("archive"),
                zdr: true,
            },
            host: "127.0.0.1".into(),
            port: Some(0),
            allow_remote: false,
            wrap: None,
            wrap_args: vec![],
            session: self.options(addresses),
            policy: None,
            request_overrides: Default::default(),
        }
    }
    /// The real provider dispatch loop, with a deterministic backend and pinned proof.
    pub async fn remote(&self) -> RemoteHost {
        use hellas_rpc::services::work::Work;
        use hellas_wire::{ServiceMarker, iroh::IrohTransport};
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[5; 32]))
            .alpns(vec![Work::ALPN.as_bytes().to_vec()])
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let listener = endpoint.clone();
        let router = crate::work_router::WorkRouter::grants(self.world.service.clone());
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Some(incoming) = listener.accept().await {
                let router = router.clone();
                connections.spawn(async move {
                    let transport = Arc::new(IrohTransport::new(incoming.await.unwrap()));
                    if let Ok(server) = router
                        .accept_iroh(
                            &transport,
                            crate::test_identity::OpenProof(
                                provider_enrollment(),
                                PROVIDER.node_key(),
                            ),
                        )
                        .await
                    {
                        super::super::serve_loop(transport, server).await;
                    }
                });
            }
            connections.shutdown().await;
        });
        RemoteHost { endpoint, task }
    }
}
impl HostBuilder {
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
            .with_provider(provider_enrollment())
            .with_capacity(self.capacity)
            .with_allowance(self.allowance)
            .with_grant(
                ids::FRIEND_GRANT,
                Rights::new(authority(), FRIEND)
                    .allow(
                        hellas_work::grant_service::WORK_EXECUTE,
                        hellas_work::grant_service::allowance_resource(authority(), allowance.id),
                    )
                    .valid_from(clock.now())
                    .valid_until(UnixMillis(u64::MAX))
                    .build(),
            )
            .build()
            .await
            .serve(self.backend.clone());
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
            backend: self.backend,
            application,
            allowance,
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
