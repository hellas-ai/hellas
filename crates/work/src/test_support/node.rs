//! Explicit test worlds, provisioned through the same checked APIs as a host.
use super::{common_node, credentials, enrollment, network, signed_caller};
use crate::model::grant::{budget::*, records::*};
use crate::model::work::PrivateRecord;
use crate::work_store::grant::{NodeStore, State};
use hellas_auth::{
    Digest,
    authority::*,
    test_support::{Actor, actors::*, ids},
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub const WAIT: std::time::Duration = std::time::Duration::from_secs(10);
pub async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, future)
        .await
        .expect("test operation exceeded WAIT")
}

#[derive(Clone)]
pub struct TestClock(Arc<AtomicU64>);
impl TestClock {
    pub fn new(now: UnixMillis) -> Self {
        Self(Arc::new(AtomicU64::new(now.0)))
    }
    pub fn now(&self) -> UnixMillis {
        UnixMillis(self.0.load(Ordering::SeqCst))
    }
    pub fn set(&self, now: UnixMillis) {
        self.0.store(now.0, Ordering::SeqCst);
    }
    pub fn source(&self) -> Arc<dyn Fn() -> UnixMillis + Send + Sync> {
        let clock = self.clone();
        Arc::new(move || clock.now())
    }
}
impl Default for TestClock {
    fn default() -> Self {
        Self::new(UnixMillis(1000))
    }
}

pub fn provider_enrollment() -> hellas_rpc::ProviderEnrollmentBundle {
    enrollment(&PROVIDER.key(), &PROVIDER.key(), [5; 32], [5; 32])
}

pub fn authority() -> AuthorityId {
    AuthorityId(Digest::hash(b"test node authority"))
}

pub struct Capacity {
    pub concurrent: u16,
    pub limits: Vec<Limit>,
}
impl Capacity {
    pub fn new(concurrent: u16) -> Self {
        Self {
            concurrent,
            limits: vec![],
        }
    }
    pub fn with_limits(mut self, limits: Vec<Limit>) -> Self {
        self.limits = limits;
        self
    }
}

pub struct Allowance {
    pub definition: GrantDef,
    pub limits: Vec<Limit>,
    pub concurrent: u16,
}
impl Allowance {
    pub fn responses(id: GrantId, actor: Actor) -> Self {
        Self {
            definition: super::definition(id, actor.principal()),
            limits: vec![],
            concurrent: 4,
        }
    }
    pub fn with_limits(mut self, limits: Vec<Limit>) -> Self {
        self.limits = limits;
        self
    }
    pub fn with_concurrency(mut self, concurrent: u16) -> Self {
        self.concurrent = concurrent;
        self
    }
}

pub struct Node {
    network: hellas_kernel::NetworkId,
    path: PathBuf,
    clock: TestClock,
    grants: Vec<(GrantId, GrantSpec)>,
    capacity: Capacity,
    allowances: Vec<Allowance>,
    provider: hellas_rpc::ProviderEnrollmentBundle,
}
impl Node {
    pub fn bootstrap(path: &Path) -> Self {
        Self {
            network: network(),
            path: path.into(),
            clock: TestClock::default(),
            grants: vec![],
            capacity: Capacity::new(4),
            allowances: vec![],
            provider: provider_enrollment(),
        }
    }
    pub fn with_network(mut self, network: hellas_kernel::NetworkId) -> Self {
        self.network = network;
        self
    }
    pub fn with_provider(mut self, provider: hellas_rpc::ProviderEnrollmentBundle) -> Self {
        self.provider = provider;
        self
    }
    pub fn with_clock(mut self, clock: TestClock) -> Self {
        self.clock = clock;
        self
    }
    pub fn with_capacity(mut self, capacity: Capacity) -> Self {
        self.capacity = capacity;
        self
    }
    pub fn with_grant(mut self, id: GrantId, scope: GrantSpec) -> Self {
        self.grants.push((id, scope));
        self
    }
    pub fn with_allowance(mut self, allowance: Allowance) -> Self {
        self.allowances.push(allowance);
        self
    }
    pub async fn build(self) -> TestNode {
        let extra: Vec<_> = crate::operations::OPERATIONS
            .iter()
            .filter(|op| !matches!(op.scope, crate::operations::Scope::Allowance))
            .map(|op| (op.name, op.permission(authority(), None).unwrap().resource))
            .collect();
        let root = common_node::admin_spec(
            authority(),
            ROOT.principal(),
            &extra,
            (self.clock.now(), UnixMillis(u64::MAX)),
            (u64::MAX, MAX_DELEGATION_DEPTH),
            &[crate::grant_service::WORK_EXECUTE],
        );
        let provider = self.provider;
        let (store, secret) = NodeStore::bootstrap(
            &self.path,
            self.network,
            ids::ROOT_GRANT,
            root.clone(),
            root,
            Some(provider.clone()),
            self.clock.now(),
        )
        .await
        .unwrap();
        let policies = self
            .allowances
            .iter()
            .flat_map(|a| a.definition.policies.iter().cloned())
            .fold(Vec::new(), |mut policies, p| {
                if !policies.contains(&p) {
                    policies.push(p);
                }
                policies
            });
        let service = crate::grant_service::GrantService::new(
            store,
            Arc::new(PROVIDER.key()),
            common_node::NoBackend,
            vec![],
            self.clock.source(),
        )
        .unwrap();
        let admin = common_node::WorkAdmin::new(service.clone(), &secret, policies).await;
        admin
            .capacity(self.capacity.concurrent, self.capacity.limits)
            .await;
        for allowance in self.allowances {
            let BudgetNode::Subject { pool, subject } = allowance.definition.budget else {
                panic!("subject budget")
            };
            admin
                .budgets(pool, subject, allowance.limits, allowance.concurrent)
                .await;
            admin.create(allowance.definition).await;
        }
        let mut secrets = vec![(ROOT.principal(), secret)];
        for (id, scope) in self.grants {
            let subject = scope.subject;
            let [credential] = credentials::issue(
                credentials::Issuer::Node(&service.node()),
                &admin.caller,
                ids::ROOT_GRANT,
                Some(id),
                scope,
            )
            .await;
            assert!(
                !secrets.iter().any(|(actor, _)| *actor == subject),
                "one app credential per actor"
            );
            secrets.push((subject, credential));
        }
        service.drain().await.unwrap();
        drop(admin);
        drop(service);
        let store = NodeStore::open(&self.path, self.network, Some(provider), self.clock.now())
            .await
            .unwrap();
        TestNode {
            store,
            path: self.path,
            clock: self.clock,
            secrets,
        }
    }
}

pub struct TestNode {
    pub store: NodeStore,
    pub clock: TestClock,
    path: PathBuf,
    secrets: Vec<(PrincipalId, CredentialSecret)>,
}
pub struct Proposal {
    pub authorization: crate::model::grant::GrantJobAuthorizationV1,
    pub signature: hellas_auth::Signature,
    pub input: crate::model::profile::PreparedWorkInput,
}
impl Proposal {
    fn new(
        store: &NodeStore,
        actor: Actor,
        allowance: GrantId,
        nonce: u64,
        now: UnixMillis,
    ) -> Self {
        let (mut authorization, _, input) =
            super::proposal_for(store, allowance, nonce, actor.key());
        let now = now.0;
        authorization.acceptance_deadline_ms = UnixMillis(now.checked_add(1000).unwrap());
        authorization.terminal_deadline_ms = UnixMillis(now.checked_add(3000).unwrap());
        authorization.delivery_deadline_ms = UnixMillis(now.checked_add(4000).unwrap());
        let signature = actor
            .key()
            .sign_digest(crate::model::grant::grant_work_id(
                network(),
                &authorization,
            ))
            .unwrap();
        Proposal {
            authorization,
            signature,
            input,
        }
    }
    pub fn request(&self) -> hellas_rpc::pb::work::AcceptWorkRequest {
        hellas_rpc::pb::work::AcceptWorkRequest {
            route: Some(hellas_rpc::pb::work::WorkRoute::grant(
                self.authorization.channel_id.0,
            )),
            authorization: self.authorization.encode(),
            client_signature: self.signature.bytes().to_vec(),
            prepared_input: self.input.encode().unwrap(),
        }
    }

    pub fn work(&self) -> Digest {
        crate::model::grant::grant_work_id(network(), &self.authorization)
    }
}
impl TestNode {
    pub fn serve<B: crate::work::WorkBackend + Send + Sync + 'static>(
        self,
        backend: B,
    ) -> TestService {
        let service = crate::grant_service::GrantService::new(
            self.store,
            Arc::new(PROVIDER.key()),
            backend,
            vec![],
            self.clock.source(),
        )
        .unwrap();
        TestService {
            service,
            clock: self.clock,
            secrets: self.secrets,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn secret(&self, actor: Actor) -> &CredentialSecret {
        &self
            .secrets
            .iter()
            .find(|(p, _)| *p == actor.principal())
            .expect("actor is provisioned")
            .1
    }
    pub fn caller(&self, actor: Actor) -> AuthenticatedCaller {
        signed_caller(
            self.store.state().authority(),
            self.secret(actor),
            &actor.key(),
            self.clock.now(),
        )
    }
    pub fn snapshot(&self) -> State {
        self.store.state().clone()
    }
    pub fn used(&self, node: BudgetNode, meter: Meter) -> u64 {
        super::used(&self.store, node, meter)
    }
    pub fn proposal(&self, actor: Actor, allowance: GrantId, nonce: u64) -> Proposal {
        Proposal::new(&self.store, actor, allowance, nonce, self.clock.now())
    }

    pub async fn accept(
        &mut self,
        actor: Actor,
        grant: GrantId,
        request: &Proposal,
    ) -> Result<hellas_auth::Signature, crate::work_store::grant::NodeStoreError> {
        let caller = self.caller(actor);
        self.store
            .accept(
                (&caller, grant),
                request.authorization,
                request.signature,
                &request.input,
                &PROVIDER.key(),
                self.clock.now(),
            )
            .await
    }
    pub async fn dispatch(
        &mut self,
        actor: Actor,
        grant: GrantId,
        request: &Proposal,
    ) -> Result<(), crate::work_store::grant::NodeStoreError> {
        let caller = self.caller(actor);
        self.store
            .dispatch(
                (&caller, grant),
                request.authorization.channel_id,
                request.work(),
                self.clock.now(),
            )
            .await
    }
    pub async fn finish(&mut self, request: &Proposal, usage: Usage) {
        self.store
            .finish(
                request.authorization.channel_id,
                request.work(),
                crate::work_store::grant::GrantOutcome::Failed,
                None,
                usage,
                self.clock.now(),
            )
            .await
            .unwrap();
    }
    pub async fn reopen(self) -> Self {
        let Self {
            store,
            path,
            clock,
            secrets,
        } = self;
        let provider = store.state().provider().unwrap().clone();
        let network = store.state().network();
        drop(store);
        let store = NodeStore::open(&path, network, Some(provider), clock.now())
            .await
            .unwrap();
        Self {
            store,
            path,
            clock,
            secrets,
        }
    }
}

/// The same provisioned world running through the checked service interface.
pub struct TestService {
    pub service: crate::grant_service::GrantService,
    pub clock: TestClock,
    secrets: Vec<(PrincipalId, CredentialSecret)>,
}
impl TestService {
    pub fn secret(&self, actor: Actor) -> &CredentialSecret {
        &self
            .secrets
            .iter()
            .find(|(p, _)| *p == actor.principal())
            .expect("actor is provisioned")
            .1
    }
    pub async fn caller(&self, actor: Actor) -> AuthenticatedCaller {
        self.service
            .node()
            .authenticate_signed(self.secret(actor), &actor.key())
            .await
            .unwrap()
    }
    pub async fn snapshot(&self) -> State {
        self.service.node().writer().await.unwrap().state().clone()
    }
    pub async fn used(&self, node: BudgetNode, meter: Meter) -> u64 {
        super::used(&self.service.node().writer().await.unwrap(), node, meter)
    }
    pub async fn proposal(&self, actor: Actor, allowance: GrantId, nonce: u64) -> Proposal {
        Proposal::new(
            &self.service.node().writer().await.unwrap(),
            actor,
            allowance,
            nonce,
            self.clock.now(),
        )
    }
    pub async fn work(&self, actor: Actor, grant: GrantId) -> crate::grant_service::GrantWork {
        self.service.for_caller(self.caller(actor).await, grant)
    }
}
