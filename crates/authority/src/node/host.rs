//! Checked host operations and trusted in-process startup configuration.
use super::*;
use crate::model::grant::budget::{BudgetNode, Limit};
use crate::operations::Operation;
use crate::work_store::grant::State;
use hellas_auth::hash_tuple;
use std::num::NonZeroU16;

pub const HOST_STATUS: &str = "host.status";
pub const HOST_CONFIGURE: &str = "host.configure";
pub const HOST_CANCEL_JOB: &str = "host.job.cancel";
pub const HOST_PROVIDER_BIND: &str = "host.provider.bind";
pub use hellas_auth::authority::GATEWAY_INVOKE;

pub fn host_resource(authority: AuthorityId) -> ResourceId {
    ResourceId(hash_tuple(
        "hellas.host.resource.v1",
        &[authority.0.as_bytes()],
    ))
}

pub fn machine_resource(authority: AuthorityId) -> ResourceId {
    ResourceId(hash_tuple(
        "hellas.work.machine.v1",
        &[authority.0.as_bytes()],
    ))
}

/// Persisted machine-wide concurrency and budgets. Changes retain usage and duties.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineCapacity {
    pub revision: Revision,
    pub max_in_flight: NonZeroU16,
    pub limits: Vec<Limit>,
}

/// Private node status; even a providerless node requires an explicit read grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    pub authority: AuthorityId,
    pub authority_revision: Revision,
    pub generation: u64,
    /// The current binding; None until a provider is bootstrapped or bound.
    pub provider: Option<hellas_rpc::ProviderEnrollmentBundle>,
    pub machine: Option<MachineCapacity>,
}

impl NodeCoordinator {
    /// Trusted in-process restart data; the public watch returns its redacted document.
    pub async fn configuration(
        &self,
    ) -> Result<Option<crate::model::grant::configuration::ConfigurationDocument>, NodeStoreError>
    {
        let (store, _) = self.lock().await?;
        Ok(store.state().configuration().cloned())
    }

    /// Trusted restart view of the authority terms already committed with the document.
    pub async fn resource_configuration(
        &self,
    ) -> Result<crate::model::grant::configuration::NodeConfiguration, NodeStoreError> {
        use crate::model::grant::configuration::{ConfiguredBudget, NodeConfiguration};
        let (store, _) = self.lock().await?;
        let state = store.state();
        let budget = |node: BudgetNode| -> Result<Option<ConfiguredBudget>, NodeStoreError> {
            state
                .ledger()
                .node(node.key())
                .map(|node| {
                    let spec = node.spec();
                    Ok(ConfiguredBudget {
                        limits: crate::work_store::grant::ledger::limits(spec).to_vec(),
                        max_in_flight: NonZeroU16::new(
                            crate::work_store::grant::ledger::concurrent(spec),
                        )
                        .ok_or(NodeStoreError::Malformed)?,
                    })
                })
                .transpose()
        };
        let resources: Vec<_> = state.catalogue().cloned().collect();
        let accounts = resources
            .iter()
            .map(|policy| {
                Ok((
                    policy.account,
                    budget(BudgetNode::Account(policy.account))?
                        .ok_or(NodeStoreError::Malformed)?,
                ))
            })
            .collect::<Result<_, NodeStoreError>>()?;
        Ok(NodeConfiguration::new(
            budget(BudgetNode::Machine)?,
            accounts,
            resources,
        )?)
    }

    /// Apply trusted process startup options before exposing control transports.
    /// Remote callers must use `configure`, which requires permission and step-up.
    pub async fn configure_startup(
        &self,
        document: crate::model::grant::configuration::ConfigurationDocument,
        configuration: &crate::model::grant::configuration::NodeConfiguration,
    ) -> Result<(), NodeStoreError> {
        let _changed = ChangeNotification(self.changed.clone());
        let (mut store, now) = self.lock().await?;
        store
            .configure(
                document.revision,
                document.document,
                document.secrets,
                configuration,
                now,
            )
            .await
    }

    /// Reject unauthorized candidates before any runtime preparation.
    pub async fn authorize_configure(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
    ) -> Result<(), NodeStoreError> {
        self.checked(caller, authorization, HOST_CONFIGURE, async |store, now| {
            let authority = store.state().authority();
            authority.authorize_caller(
                caller,
                authorization,
                &Operation::named(HOST_CONFIGURE)?.permission(authority.authority(), None)?,
                now,
            )?;
            caller.session().step_up().map_err(Into::into)
        })
        .await
    }

    /// The whole daemon change has one authority check and one durable frame.
    pub async fn configure(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
        document: crate::model::grant::configuration::ConfigurationDocument,
        configuration: &crate::model::grant::configuration::NodeConfiguration,
    ) -> Result<(), NodeStoreError> {
        let _changed = ChangeNotification(self.changed.clone());
        self.checked(caller, authorization, HOST_CONFIGURE, async |store, now| {
            let authority = store.state().authority();
            authority.authorize_caller(
                caller,
                authorization,
                &Operation::named(HOST_CONFIGURE)?.permission(authority.authority(), None)?,
                now,
            )?;
            caller.session().step_up()?;
            store
                .configure(
                    document.revision,
                    document.document,
                    document.secrets,
                    configuration,
                    now,
                )
                .await
        })
        .await
    }

    /// HTTP admission accepts only a bearer credential restricted to this
    /// operation. An administrator credential must never become an HTTP bearer.
    pub async fn authorize_gateway(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
    ) -> Result<(), NodeStoreError> {
        self.checked(caller, authorization, GATEWAY_INVOKE, async |store, now| {
            let authority = store.state().authority();
            let permission =
                Operation::named(GATEWAY_INVOKE)?.permission(authority.authority(), None)?;
            authority.authorize_caller(caller, authorization, &permission, now)?;
            let credential = authority
                .credential(caller.credential())
                .ok_or(AuthorityError::Denied)?;
            let scope = credential.scope();
            if !credential.bearer()
                || scope.issuance.is_some()
                || scope.delegation_depth != 0
                || scope.permissions.len() != 1
                || !scope.permissions.contains(&permission)
            {
                return Err(AuthorityError::Denied.into());
            }
            Ok(())
        })
        .await
    }

    /// HTTP admission of a bearer credential under its own subject's current
    /// grant of `gateway.invoke` alone, so several principals can share one
    /// gateway. An administrative grant never admits HTTP requests.
    pub async fn authorize_gateway_bearer(
        &self,
        caller: &AuthenticatedCaller,
    ) -> Result<GrantId, NodeStoreError> {
        let grant = {
            let (store, now) = self.lock().await?;
            let authority = store.state().authority();
            let permission =
                Operation::named(GATEWAY_INVOKE)?.permission(authority.authority(), None)?;
            authority
                .grant_for(caller.subject(), &permission, now)
                .ok_or(AuthorityError::Denied)?
        };
        self.authorize_gateway(caller, grant).await?;
        Ok(grant)
    }

    /// Bind the provider of an authority bootstrapped without one. The root proof
    /// is verified offline; an identical retry succeeds without a new record.
    /// Binding a provider is a step-up operation: only a passkey session may.
    pub async fn bind_provider(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
        provider: hellas_rpc::ProviderEnrollmentBundle,
    ) -> Result<hellas_rpc::ContentId, NodeStoreError> {
        let _changed = ChangeNotification(self.changed.clone());
        self.checked(
            caller,
            authorization,
            HOST_PROVIDER_BIND,
            async |store, now| {
                let authority = store.state().authority();
                authority.authorize_caller(
                    caller,
                    authorization,
                    &Operation::named(HOST_PROVIDER_BIND)?
                        .permission(authority.authority(), None)?,
                    now,
                )?;
                crate::model::grant::records::verify_provider(&provider)?;
                let genesis = provider.content_id();
                store
                    .bind_provider(caller, authorization, provider, now)
                    .await?;
                Ok(genesis)
            },
        )
        .await
    }

    pub async fn status(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
    ) -> Result<NodeStatus, NodeStoreError> {
        self.host_action(caller, authorization, HOST_STATUS, |status| status)
            .await
    }

    /// Check the exact host right and perform a synchronous read or enqueue at
    /// the same writer boundary. Network startup and shutdown run outside it.
    pub async fn host_action<T>(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
        operation: &'static str,
        action: impl FnOnce(NodeStatus) -> T,
    ) -> Result<T, NodeStoreError> {
        if !matches!(operation, HOST_STATUS | HOST_CANCEL_JOB) {
            return Err(AuthorityError::Denied.into());
        }
        self.checked(caller, authorization, operation, async |store, now| {
            let state = store.state();
            let authority = state.authority();
            authority.authorize_caller(
                caller,
                authorization,
                &Operation::named(operation)?.permission(authority.authority(), None)?,
                now,
            )?;
            Ok(action(NodeStatus {
                authority: authority.authority(),
                authority_revision: authority.revision(),
                generation: authority.generation(),
                provider: state.provider().ok().cloned(),
                machine: state.machine_capacity()?,
            }))
        })
        .await
    }
}

impl State {
    pub(crate) fn machine_capacity(&self) -> Result<Option<MachineCapacity>, NodeStoreError> {
        let Some(node) = self.ledger().node(BudgetNode::Machine.key()) else {
            return Ok(None);
        };
        let spec = node.spec();
        Ok(Some(MachineCapacity {
            revision: Revision(spec.revision),
            limits: crate::work_store::grant::ledger::limits(spec).to_vec(),
            max_in_flight: NonZeroU16::new(crate::work_store::grant::ledger::concurrent(spec))
                .ok_or(NodeStoreError::Malformed)?,
        }))
    }
}
