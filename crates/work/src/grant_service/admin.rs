use super::*;
use hellas_rpc::protocol::work_grant::admin::*;
use std::num::NonZeroU64;

impl GrantService {
    /// The caller must hold local administrative authority. Remote Work never
    /// calls this entrypoint; HostControl is wrapped by AdminPolicy/Authorized.
    pub fn control(
        &self,
        command: GrantCommand,
        resources: &[GrantPolicy],
        max_job_millis: NonZeroU64,
    ) -> Result<GrantReply, GrantStoreError> {
        self.administer(|store, now| {
            store.tick(now)?;
            let id = match command {
                GrantCommand::Create {
                    id,
                    principal,
                    terms,
                } => {
                    if store.state().grant(id).is_some() {
                        return Err(GrantError::Malformed.into());
                    }
                    let definition = terms.definition(
                        id,
                        Revision(1),
                        GrantKind::Principal(principal),
                        GrantState::Active,
                        resources,
                        max_job_millis,
                        now,
                    )?;
                    store.define(definition, now)?;
                    id
                }
                GrantCommand::Revise {
                    id,
                    expected_revision,
                    terms,
                } => {
                    let previous = existing(store, id, expected_revision)?;
                    let definition = terms.definition(
                        id,
                        next_revision(previous.revision)?,
                        previous.kind,
                        previous.state,
                        resources,
                        max_job_millis,
                        now,
                    )?;
                    store.define(definition, now)?;
                    id
                }
                GrantCommand::SetState {
                    id,
                    expected_revision,
                    state,
                } => {
                    let mut definition = existing(store, id, expected_revision)?;
                    definition.revision = next_revision(definition.revision)?;
                    definition.state = state;
                    store.define(definition, now)?;
                    id
                }
                GrantCommand::InitializeOwner { principal } => {
                    store.initialize_owner(principal, resources.to_vec(), max_job_millis, now)?
                }
                GrantCommand::Inspect { id } => id,
                GrantCommand::NewGeneration {
                    id,
                    expected_revision,
                } => {
                    existing(store, id, expected_revision)?;
                    store.bump_generation(id, now)?;
                    id
                }
                GrantCommand::RepairResource { policy } => {
                    let policy = resources
                        .iter()
                        .find(|p| p.name == policy)
                        .ok_or(GrantError::OutOfScope)?;
                    store.repair_resource(policy.resource_id()?, now)?;
                    return Ok(GrantReply::Repaired);
                }
                GrantCommand::List => {
                    return Ok(GrantReply::Listing(
                        store
                            .state()
                            .grants()
                            .map(|g| GrantSummary {
                                id: g.id,
                                principal: g.kind.principal().id(),
                                owner: matches!(g.kind, GrantKind::Owner(_)),
                                revision: g.revision,
                                state: g.state,
                                policies: g.policies.iter().map(|p| p.name.clone()).collect(),
                                expires: g.expires,
                                generation: store
                                    .state()
                                    .generation(g.id)
                                    .expect("grant has channel"),
                            })
                            .collect(),
                    ));
                }
            };
            Ok(GrantReply::Status {
                offer: Box::new(store.offer(id, &self.signer, self.addresses.as_ref().clone())?),
                now: store.state().now(),
                nodes: store.allowances(id, true)?,
            })
        })
    }
}
fn existing(
    store: &GrantStore,
    id: GrantId,
    expected: Revision,
) -> Result<GrantDef, GrantStoreError> {
    let definition = store.state().grant(id).ok_or(GrantError::Unauthorized)?;
    if definition.revision != expected {
        return Err(GrantError::Revision(definition.revision).into());
    }
    Ok(definition.clone())
}
fn next_revision(revision: Revision) -> Result<Revision, GrantStoreError> {
    Ok(Revision(
        revision.0.checked_add(1).ok_or(GrantError::StateCapacity)?,
    ))
}
trait Definition {
    #[allow(clippy::too_many_arguments)]
    fn definition(
        self,
        id: GrantId,
        revision: Revision,
        kind: GrantKind,
        state: GrantState,
        resources: &[GrantPolicy],
        maximum: NonZeroU64,
        now: UnixMillis,
    ) -> Result<GrantDef, GrantStoreError>;
}
impl Definition for GrantTerms {
    fn definition(
        self,
        id: GrantId,
        revision: Revision,
        kind: GrantKind,
        state: GrantState,
        resources: &[GrantPolicy],
        maximum: NonZeroU64,
        now: UnixMillis,
    ) -> Result<GrantDef, GrantStoreError> {
        if self.policies.len() > 16 || self.max_job_millis > maximum {
            return Err(GrantError::Limits.into());
        }
        let policies = self
            .policies
            .iter()
            .map(|name| {
                resources
                    .iter()
                    .find(|p| &p.name == name)
                    .cloned()
                    .ok_or(GrantError::OutOfScope)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let definition = GrantDef {
            id,
            revision,
            kind,
            state,
            policies,
            limits: self.limits,
            weight: std::num::NonZeroU16::new(1).expect("one"),
            max_job_millis: self.max_job_millis,
            max_in_flight: self.max_in_flight,
            allow_account_backed: self.allow_account_backed,
            expires: self
                .expires_in_millis
                .map(|n| {
                    now.0
                        .checked_add(n.get())
                        .map(UnixMillis)
                        .ok_or(GrantError::Limits)
                })
                .transpose()?,
        };
        definition.validate()?;
        Ok(definition)
    }
}
