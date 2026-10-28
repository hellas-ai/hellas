//! Fresh test stores use explicit offline initialization. Reopens must use `open`.
use crate::model::grant::budget::{BudgetDef, BudgetNode, Limit, PoolId};
use crate::work_store::grant::{NodeStore, NodeStoreError, OwnerApproval};
use hellas_auth::Digest;
use hellas_auth::authority as auth;
use hellas_auth::test_support::actors::ROOT;
use hellas_kernel::NetworkId;
use hellas_rpc::ProviderEnrollmentBundle;

/// Administrative rights with fixture-specific validity, delegation and extra operations.
pub use hellas_auth::test_support::admin_spec;

pub const POOL: PoolId = PoolId([1; 16]);
pub fn budgets(
    pool: PoolId,
    subject: auth::PrincipalId,
    limits: Vec<Limit>,
    concurrent: u16,
) -> [BudgetDef; 3] {
    let account = BudgetNode::Account(auth::ResourceId(Digest::hash(b"test account")));
    let definition = |node, parent, limits, concurrent| BudgetDef {
        node,
        parent,
        revision: auth::Revision(1),
        limits,
        max_in_flight: std::num::NonZeroU16::new(concurrent).unwrap(),
    };
    [
        definition(account, BudgetNode::Machine, vec![], 256),
        definition(BudgetNode::Pool(pool), account, vec![], 256),
        definition(
            BudgetNode::Subject { pool, subject },
            BudgetNode::Pool(pool),
            limits,
            concurrent,
        ),
    ]
}

pub async fn bootstrap_node(
    path: &std::path::Path,
    network: NetworkId,
    provider: Option<ProviderEnrollmentBundle>,
    now: auth::UnixMillis,
) -> Result<NodeStore, NodeStoreError> {
    bootstrap_node_with_credential(path, network, provider, now)
        .await
        .map(|(store, _)| store)
}

pub async fn bootstrap_node_with_credential(
    path: &std::path::Path,
    network: NetworkId,
    provider: Option<ProviderEnrollmentBundle>,
    now: auth::UnixMillis,
) -> Result<(NodeStore, auth::CredentialSecret), NodeStoreError> {
    let provider = provider.expect("provider fixture");
    let authority = auth::AuthorityId(Digest::hash(b"test node authority"));
    let extra: Vec<_> = crate::operations::OPERATIONS
        .iter()
        .filter(|op| !matches!(op.scope, crate::operations::Scope::Allowance))
        .map(|op| (op.name, op.permission(authority, None).unwrap().resource))
        .collect();
    let administrator = admin_spec(
        authority,
        ROOT.principal(),
        &extra,
        (now, auth::UnixMillis(u64::MAX)),
        (u64::MAX, auth::MAX_DELEGATION_DEPTH),
        &[crate::grant_service::WORK_EXECUTE],
    );
    let root = auth::GrantId([0; 16]);
    NodeStore::bootstrap(
        path,
        network,
        root,
        approval(
            auth::Ownership::Bootstrap { root, target: None },
            administrator,
        ),
        Some(provider),
        now,
    )
    .await
}

/// The administrator's own approval, holding the initial credential (of the
/// same scope) on the administrator's device.
pub fn approval(ownership: auth::Ownership, administrator: auth::GrantSpec) -> OwnerApproval {
    approval_for(ownership, administrator.clone(), administrator)
}
pub fn approval_for(
    ownership: auth::Ownership,
    administrator: auth::GrantSpec,
    credential: auth::GrantSpec,
) -> OwnerApproval {
    let holder =
        auth::NodeKey::from_public_key(super::device(administrator.subject).public_key()).unwrap();
    let digest = auth::ownership_digest(ownership, &administrator, &credential, holder);
    OwnerApproval {
        assertion: hellas_auth::test_support::assertion(
            &super::passkey_of(administrator.subject),
            digest,
        ),
        administrator,
        credential,
        holder,
    }
}

pub const EXECUTION_AUTHORIZATION: auth::GrantId = auth::GrantId([238; 16]);

/// Issue an explicit Work grant and app credential through the checked node service.
pub async fn execution(
    service: &crate::grant_service::GrantService,
    administrator: &auth::CredentialSecret,
    identity: &hellas_auth::ProducerSigningKey,
    allowance: auth::GrantId,
) -> (crate::grant_service::GrantWork, auth::CredentialSecret) {
    let node = service.node();
    let subject = super::subject_of(identity);
    let credential = execution_credential(&node, administrator, subject, allowance).await;
    let caller = node
        .authenticate_session(&credential, crate::node::SessionKey::Node(identity))
        .await
        .unwrap();
    (
        service.for_caller(caller, EXECUTION_AUTHORIZATION),
        credential,
    )
}

pub async fn execution_credential(
    node: &crate::node::NodeCoordinator,
    administrator: &auth::CredentialSecret,
    subject: auth::PrincipalId,
    allowance: auth::GrantId,
) -> auth::CredentialSecret {
    let admin = super::session(node, administrator).await;
    let root = auth::GrantId([0; 16]);
    let authority = node.status(&admin, root).await.unwrap().authority;
    let scope = auth::GrantSpec {
        authority,
        subject,
        permissions: [auth::Permission {
            operation: auth::OperationId::new(crate::grant_service::WORK_EXECUTE).unwrap(),
            resource: crate::grant_service::allowance_resource(authority, allowance),
        }]
        .into(),
        not_before: auth::UnixMillis(1000),
        expires: auth::UnixMillis(u64::MAX),
        delegation_depth: 0,
        issuance: None,
    };
    let [credential] = super::credentials::issue(
        super::credentials::Issuer::Node(node),
        &admin,
        root,
        Some(EXECUTION_AUTHORIZATION),
        scope,
    )
    .await;
    credential
}

/// Test hosts keep the provisioned app credential and use the public checked API.
pub struct WorkAdmin {
    root: auth::GrantId,
    pub service: crate::grant_service::WorkAdministration,
    pub caller: auth::AuthenticatedCaller,
}
impl WorkAdmin {
    pub async fn resources(&self, policies: &[crate::model::grant::records::GrantPolicy]) {
        use crate::model::grant::admin::*;
        let WorkControlReply::Catalogue(configured) =
            self.command(WorkControlCommand::Catalogue).await.unwrap()
        else {
            panic!("catalogue reply")
        };
        for policy in policies {
            if !configured.contains(policy) {
                self.command(WorkControlCommand::ConfigureResource {
                    policy: policy.name.clone(),
                })
                .await
                .unwrap();
            }
        }
    }
    pub async fn budgets(
        &self,
        pool: PoolId,
        subject: auth::PrincipalId,
        limits: Vec<Limit>,
        concurrent: u16,
    ) {
        use crate::model::grant::admin::WorkControlCommand;
        for definition in budgets(pool, subject, limits, concurrent) {
            match self
                .command(WorkControlCommand::InspectBudget {
                    node: definition.node,
                })
                .await
            {
                Ok(_) => {}
                Err(NodeStoreError::Grant(
                    crate::model::grant::records::GrantError::OutOfScope,
                )) => {
                    self.command(WorkControlCommand::ConfigureBudget { definition })
                        .await
                        .unwrap();
                }
                Err(error) => panic!("budget inspection failed: {error}"),
            }
        }
    }
    pub async fn capacity(&self, concurrent: u16, limits: Vec<crate::model::grant::budget::Limit>) {
        self.service
            .node()
            .set_machine_capacity(
                &self.caller,
                self.root,
                auth::Revision(0),
                concurrent,
                limits,
            )
            .await
            .unwrap();
    }

    pub async fn create(&self, definition: crate::model::grant::records::GrantDef) {
        use crate::model::grant::admin::*;
        assert_eq!(definition.revision, auth::Revision(1));
        self.resources(&definition.policies).await;
        self.command(WorkControlCommand::Create {
            id: definition.id,
            terms: AllowanceTerms {
                policies: definition.policies.iter().map(|p| p.name.clone()).collect(),
                budget: definition.budget,
                max_job_millis: definition.max_job_millis,
                enabled: definition.enabled,
                allow_account_backed: definition.allow_account_backed,
            },
        })
        .await
        .unwrap();
    }

    pub async fn new(
        service: crate::grant_service::GrantService,
        secret: &auth::CredentialSecret,
        policies: Vec<crate::model::grant::records::GrantPolicy>,
    ) -> Self {
        let node = service.node();
        let root = node
            .writer()
            .await
            .unwrap()
            .state()
            .authority()
            .root_grant();
        let caller = super::session(&node, secret).await;
        Self {
            root,
            service: crate::grant_service::WorkAdministration::new(
                service,
                policies,
                // Longer than one Work session, as deployed allowances may be.
                std::num::NonZeroU64::new(20 * 60_000).unwrap(),
            )
            .unwrap(),
            caller,
        }
    }
    pub async fn command(
        &self,
        command: crate::model::grant::admin::WorkControlCommand,
    ) -> Result<crate::model::grant::admin::WorkControlReply, NodeStoreError> {
        self.service.execute(&self.caller, self.root, command).await
    }
    pub async fn used(
        &self,
        id: auth::GrantId,
        node: crate::model::grant::budget::BudgetNode,
        meter: crate::model::grant::budget::Meter,
    ) -> u64 {
        use crate::model::grant::{admin::*, budget::Window};
        let WorkControlReply::Status { nodes, .. } = self
            .command(WorkControlCommand::Inspect { id })
            .await
            .unwrap()
        else {
            panic!("status reply")
        };
        nodes
            .iter()
            .find(|n| n.node == node)
            .unwrap()
            .counters
            .iter()
            .find(|c| c.meter == meter && c.window == Window::Total)
            .unwrap()
            .used
    }
}

#[derive(Clone, Copy)]
pub struct NoBackend;
pub fn allowance(
    id: auth::GrantId,
    principal: auth::PrincipalId,
    policies: Vec<crate::model::grant::records::GrantPolicy>,
) -> crate::model::grant::records::GrantDef {
    use crate::model::grant::records::*;
    GrantDef {
        id,
        revision: auth::Revision(1),
        policies,
        budget: BudgetNode::Subject {
            pool: POOL,
            subject: principal,
        },
        max_job_millis: std::num::NonZeroU64::new(90_000).unwrap(),
        enabled: true,
        allow_account_backed: true,
    }
}

impl hellas_channel::work::WorkBackend for NoBackend {
    fn try_admit(
        &self,
        domain: hellas_channel::work::admission::CapacityDomain,
    ) -> Result<hellas_channel::work::admission::WorkPermit, hellas_channel::work::BackendFault>
    {
        Err(hellas_channel::work::admission::AdmissionError::Unsupported(domain).into())
    }
}

/// Provision through the native service, then reopen for a fixture that needs raw read access.
pub async fn provision(
    path: &std::path::Path,
    store: NodeStore,
    secret: &auth::CredentialSecret,
    signer: hellas_auth::ProducerSigningKey,
    capacity: (u16, Vec<crate::model::grant::budget::Limit>),
    definition: crate::model::grant::records::GrantDef,
    budget: (Vec<Limit>, u16),
) -> NodeStore {
    let now = store.state().now();
    let network = store.state().network();
    let provider = store.state().provider().unwrap().clone();
    let service = crate::grant_service::GrantService::new(
        store,
        std::sync::Arc::new(signer),
        NoBackend,
        vec![],
        std::sync::Arc::new(move || now),
    )
    .unwrap();
    let admin = WorkAdmin::new(service.clone(), secret, definition.policies.clone()).await;
    admin.capacity(capacity.0, capacity.1).await;
    let BudgetNode::Subject { pool, subject } = definition.budget else {
        panic!("subject budget")
    };
    admin.budgets(pool, subject, budget.0, budget.1).await;
    admin.create(definition).await;
    service.drain().await.unwrap();
    drop(admin);
    drop(service);
    NodeStore::open(path, network, Some(provider), now)
        .await
        .unwrap()
}
