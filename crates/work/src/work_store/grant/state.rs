use super::ledger::{Ledger, LedgerError};
use super::{
    ChannelId, Deserialize, GrantChannelState, GrantId, GrantJobAuthorizationV1, GrantOutcome,
    GrantTerminal, NodeStoreError, Serialize, Signature, SignedResult,
};
use crate::model::grant::records::{check_grant_provider, grant_producer};
use crate::model::grant::{
    ChannelClient,
    budget::{BudgetDef, BudgetNode, Charge, Limit, Meter, Usage},
    grant_channel_id, grant_work_id,
    records::{GrantDef, GrantError, GrantPolicy},
};
use crate::model::work::bound_result_digest;
use crate::work_store::channel::funding::GrantFunding;
use crate::work_store::{Applied, Channel, JobBook, JobPhase, JobState, JobTerminal, Role};
use hellas_auth::authority::{AdministrationRecord, AuthoritySnapshot, AuthorityState};
use hellas_auth::authority::{ResourceId, Revision, UnixMillis};
use hellas_auth::{Digest, PublicKey};
use hellas_kernel::NetworkId;
use hellas_rpc::ProviderEnrollmentBundle;
use std::collections::BTreeMap;

const MAX_CHANNELS: usize = 256;
const MAX_ALLOWANCES: usize = 256;
pub(super) const MAX_RESOURCES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub(super) network: NetworkId,
    pub(super) authority: AuthorityState,
    last_administration: Option<AdministrationRecord>,
    pub(crate) last_work_administration: Option<super::WorkRecord>,
    pub(crate) machine_revision: hellas_auth::authority::Revision,
    paid_policy: Option<crate::model::paid_policy::StoredPaidPolicy>,
    pub(super) provider: Option<ProviderEnrollmentBundle>,
    pub(super) grants: BTreeMap<GrantId, GrantDef>,
    generations: BTreeMap<GrantId, u64>,
    pub(super) channels: BTreeMap<Digest, Channel<GrantFunding>>,
    pub(super) admissions: BTreeMap<Digest, super::AdmissionRecord>,
    pub(super) ledger: Ledger,
    pub(super) history: BTreeMap<(GrantId, Revision), GrantDef>,
    pub(super) catalogue: BTreeMap<ResourceId, GrantPolicy>,
    pub(super) resources: BTreeMap<ResourceId, ResourceHealth>,
}
/// Three consecutive unknown accounting results quarantine a route. A verified
/// overrun quarantines immediately; time and grant revisions cannot clear it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceHealth {
    pub revision: u64,
    pub consecutive_faults: u16,
    pub quarantined: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Frame {
    pub namespace: String,
    pub now: UnixMillis,
    pub changes: Vec<Change>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum Change {
    Initialize {
        authority: AuthoritySnapshot,
        #[serde(with = "super::codec::optional_provider")]
        provider: Option<ProviderEnrollmentBundle>,
    },
    Authority(AdministrationRecord),
    Recover(hellas_auth::authority::RecoveryCommand),
    BindProvider(super::BindRecord),
    Machine {
        limits: Vec<Limit>,
        concurrent: u16,
    },
    Define(GrantDef),
    Budget(BudgetDef),
    Resource(GrantPolicy),
    Work(super::WorkRecord),
    Generation {
        grant: GrantId,
        generation: u64,
    },
    Clock,
    RepairResource(ResourceId),
    Accepted {
        #[serde(with = "super::codec::record")]
        authorization: GrantJobAuthorizationV1,
        client_signature: Signature,
        provider_signature: Signature,
        charge: Charge,
        execution: super::ExecutionRecord,
    },
    Dispatched {
        channel: ChannelId,
        work: Digest,
        execution: super::ExecutionRecord,
    },
    Terminal {
        channel: ChannelId,
        work: Digest,
        outcome: GrantOutcome,
        result: Option<SignedResult>,
        usage: Option<Charge>,
    },
}
impl State {
    pub fn paid_policy(&self) -> Option<&crate::model::paid_policy::StoredPaidPolicy> {
        self.paid_policy.as_ref()
    }
    pub fn network(&self) -> NetworkId {
        self.network
    }
    pub fn authority(&self) -> &AuthorityState {
        &self.authority
    }
    /// Latest authenticated authority mutation; older records follow journal retention.
    pub fn last_administration(&self) -> Option<&AdministrationRecord> {
        self.last_administration.as_ref()
    }
    pub fn provider(&self) -> Result<&ProviderEnrollmentBundle, NodeStoreError> {
        self.provider
            .as_ref()
            .ok_or(NodeStoreError::MissingProvider)
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn grants(&self) -> impl Iterator<Item = &GrantDef> {
        self.grants.values()
    }
    pub fn grant(&self, id: GrantId) -> Option<&GrantDef> {
        self.grants.get(&id)
    }
    pub fn channel(&self, id: ChannelId) -> Option<&Channel<GrantFunding>> {
        self.channels.get(&id.0)
    }
    pub fn admission(&self, channel: ChannelId, work: Digest) -> Option<&super::AdmissionRecord> {
        let book = self.channel(channel)?.job_book();
        if book.job_by_id(work).is_none() && book.terminal_by_id(work).is_none() {
            return None;
        }
        self.admissions.get(&work)
    }
    /// The node key whose signature `work` was admitted under, as recorded.
    fn admitted_signer(&self, work: Digest) -> Result<hellas_kernel::Key, NodeStoreError> {
        let record = self
            .admissions
            .get(&work)
            .ok_or(NodeStoreError::Malformed)?;
        Ok(ChannelClient::recorded(record.accepted().caller())?.signer())
    }
    pub fn channel_binding(&self, id: ChannelId) -> Option<&GrantChannelState> {
        self.channels.get(&id.0).map(|c| &c.funding)
    }
    pub fn now(&self) -> UnixMillis {
        self.ledger.high_water()
    }
    pub fn generation(&self, grant: GrantId) -> Option<u64> {
        self.generations.get(&grant).copied()
    }
    pub fn channel_id(&self, grant: GrantId, client: ChannelClient) -> Option<ChannelId> {
        Some(grant_channel_id(
            self.network,
            self.provider.as_ref()?.content_id(),
            grant,
            client,
            self.generation(grant)?,
        ))
    }
    /// Existing channels retain their actor across term and Auth revisions.
    pub(super) fn check_channel(
        &self,
        a: &GrantJobAuthorizationV1,
        client: ChannelClient,
    ) -> Result<(), NodeStoreError> {
        if a.channel_id
            != grant_channel_id(
                self.network,
                self.provider()?.content_id(),
                a.grant_id,
                client,
                a.generation,
            )
        {
            return Err(GrantError::Unauthorized.into());
        }
        Ok(())
    }
    /// A recovered invocation can retain capacity until its enforceable lifetime
    /// ends, even though its quota was already charged at the reserved bound.
    pub fn recovery_holds(
        &self,
        node: BudgetNode,
        now: UnixMillis,
    ) -> Result<usize, NodeStoreError> {
        let mut count = 0;
        for channel in self.channels.values() {
            let grant = self
                .grant(channel.funding.grant)
                .ok_or(GrantError::Unauthorized)?;
            if self.ledger.path(grant.budget)?.contains(&node) {
                count += channel
                    .book
                    .terminals()
                    .filter(|t| {
                        t.outcome.outcome == GrantOutcome::Indeterminate
                            && t.outcome.authorization.terminal_deadline_ms > now
                    })
                    .count();
            }
        }
        Ok(count)
    }
    fn check_budget_meters(
        &self,
        node: BudgetNode,
        limits: &[Limit],
    ) -> Result<(), NodeStoreError> {
        for grant in self.grants.values() {
            if self.ledger.path(grant.budget)?.contains(&node)
                && grant
                    .policies
                    .iter()
                    .any(|p| limits.iter().any(|l| !p.supports(l.meter)))
            {
                return Err(GrantError::Limits.into());
            }
        }
        for channel in self.channels.values() {
            let grant = self
                .grant(channel.funding.grant)
                .ok_or(GrantError::Unauthorized)?;
            if self.ledger.path(grant.budget)?.contains(&node) {
                for job in channel.book.jobs() {
                    let policy = self.policy_for(job.authorization())?;
                    if limits.iter().any(|l| !policy.supports(l.meter)) {
                        return Err(GrantError::Limits.into());
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn initialized(
        network: NetworkId,
        authority: AuthorityState,
        provider: Option<ProviderEnrollmentBundle>,
    ) -> Result<Self, NodeStoreError> {
        if let Some(provider) = &provider {
            check_grant_provider(provider)?;
        }
        let mut ledger = Ledger::default();
        ledger.advance(authority.now());
        Ok(Self {
            network,
            authority,
            last_administration: None,
            last_work_administration: None,
            machine_revision: hellas_auth::authority::Revision(0),
            paid_policy: None,
            provider,
            grants: BTreeMap::new(),
            generations: BTreeMap::new(),
            channels: BTreeMap::new(),
            admissions: BTreeMap::new(),
            ledger,
            history: BTreeMap::new(),
            resources: BTreeMap::new(),
            catalogue: BTreeMap::new(),
        })
    }
    fn mount(&mut self, grant: GrantId, client: ChannelClient) -> Result<(), NodeStoreError> {
        let generation = self.generation(grant).ok_or(GrantError::Unauthorized)?;
        let id = grant_channel_id(
            self.network,
            self.provider()?.content_id(),
            grant,
            client,
            generation,
        );
        if self.channels.contains_key(&id.0) {
            return Ok(());
        }
        if self.channels.len() >= MAX_CHANNELS {
            return Err(GrantError::StateCapacity.into());
        }
        self.channels.insert(
            id.0,
            Channel {
                funding: GrantChannelState {
                    id,
                    grant,
                    generation,
                    client,
                },
                ledger: (),
                role: Role::Provider,
                book: JobBook::default(),
            },
        );
        Ok(())
    }
    pub(super) fn apply(&mut self, frame: &Frame) -> Result<Applied, NodeStoreError> {
        if frame.namespace != "hellas.node.journal.v2"
            || frame.now < self.now()
            || frame.changes.is_empty()
            || frame.changes.len() > 16
        {
            return Err(NodeStoreError::Malformed);
        }
        self.ledger.advance(frame.now);
        let mut applied = Applied::Redundant;
        for change in &frame.changes {
            if self.apply_change(change, frame.now)? == Applied::Changed {
                applied = Applied::Changed;
            }
        }
        Ok(applied)
    }
    fn apply_change(
        &mut self,
        change: &Change,
        now: UnixMillis,
    ) -> Result<Applied, NodeStoreError> {
        match change {
            Change::Initialize { .. } => return Err(NodeStoreError::Malformed),
            Change::Authority(record) => {
                if record.caller().at() != now {
                    return Err(NodeStoreError::Malformed);
                }
                self.authority.apply_administration(record)?;
                self.last_administration = Some(record.clone());
            }
            Change::Recover(command) => self.authority.recover(command, now)?,
            Change::BindProvider(record) => {
                if record.caller.at() != now {
                    return Err(NodeStoreError::Malformed);
                }
                if self.provider.is_some() {
                    return Err(NodeStoreError::ProviderBound);
                }
                record.caller.session().step_up()?;
                self.authority.authorize_recorded(
                    &record.caller,
                    record.authorization,
                    &crate::operations::Operation::named(crate::node::HOST_PROVIDER_BIND)?
                        .permission(self.authority.authority(), None)?,
                )?;
                check_grant_provider(&record.provider)?;
                self.provider = Some(record.provider.clone());
            }
            Change::Work(record) => {
                if record.caller.at() != now || !record.mutation.valid_capacity() {
                    return Err(NodeStoreError::Malformed);
                }
                self.authority.authorize_recorded(
                    &record.caller,
                    record.authorization,
                    &crate::operations::Operation::named(record.mutation.operation())?
                        .permission(self.authority.authority(), None)?,
                )?;
                match &record.mutation {
                    super::WorkMutation::PaidPolicy {
                        expected,
                        policy_salt,
                        policy,
                    } => {
                        record.caller.session().step_up()?;
                        let owner = self
                            .authority
                            .grant(self.authority.root_grant())
                            .ok_or(NodeStoreError::Malformed)?
                            .spec()
                            .subject;
                        if record.caller.actor() != owner {
                            return Err(hellas_auth::authority::AuthorityError::Denied.into());
                        }
                        if self
                            .paid_policy
                            .as_ref()
                            .map_or(Revision(0), |p| p.revision)
                            != *expected
                        {
                            return Err(hellas_auth::authority::AuthorityError::Revision.into());
                        }
                        policy.check()?;
                        self.paid_policy = Some(crate::model::paid_policy::StoredPaidPolicy {
                            revision: expected.next().ok_or(NodeStoreError::Malformed)?,
                            policy_salt: *policy_salt,
                            policy: policy.as_ref().clone(),
                        });
                    }
                    super::WorkMutation::Capacity {
                        expected,
                        max_in_flight,
                        limits,
                    } => {
                        if *expected != self.machine_revision {
                            return Err(hellas_auth::authority::AuthorityError::Revision.into());
                        }
                        if self.provider.is_none()
                            && self.ledger.node(BudgetNode::Machine).is_none()
                        {
                            return Err(NodeStoreError::MissingMachine);
                        }
                        self.apply_change(
                            &Change::Machine {
                                limits: limits.clone(),
                                concurrent: *max_in_flight,
                            },
                            now,
                        )?;
                    }
                    super::WorkMutation::Resource(policy) => {
                        self.apply_change(&Change::Resource(policy.as_ref().clone()), now)?;
                    }
                    super::WorkMutation::Budget(def) => {
                        self.apply_change(&Change::Budget(def.clone()), now)?;
                    }
                    super::WorkMutation::Define(def) => {
                        self.apply_change(&Change::Define(def.as_ref().clone()), now)?;
                    }
                    super::WorkMutation::Generation { id, expected } => {
                        if self.generation(*id) != Some(*expected) {
                            return Err(GrantError::Generation.into());
                        }
                        let generation = expected.checked_add(1).ok_or(GrantError::Generation)?;
                        self.apply_change(
                            &Change::Generation {
                                grant: *id,
                                generation,
                            },
                            now,
                        )?;
                    }
                    super::WorkMutation::Repair { resource, expected } => {
                        if self
                            .resource_health(*resource)
                            .is_none_or(|health| health.revision != *expected)
                        {
                            return Err(hellas_auth::authority::AuthorityError::Revision.into());
                        }
                        self.apply_change(&Change::RepairResource(*resource), now)?;
                    }
                }
                self.last_work_administration = Some(record.clone());
            }
            Change::Clock => {}
            Change::RepairResource(id) => {
                let health = self.resources.get_mut(id).ok_or(GrantError::OutOfScope)?;
                *health = ResourceHealth {
                    revision: health
                        .revision
                        .checked_add(1)
                        .ok_or(NodeStoreError::Malformed)?,
                    ..Default::default()
                };
            }
            Change::Machine { limits, concurrent } => {
                let next_revision = self
                    .machine_revision
                    .next()
                    .ok_or(NodeStoreError::Malformed)?;
                // Configured terms and accepted work must remain measurable.
                self.check_budget_meters(BudgetNode::Machine, limits)?;
                self.ledger.configure_machine(limits.clone(), *concurrent)?;
                self.machine_revision = next_revision;
            }
            Change::Resource(policy) => {
                self.configure_resource(policy.clone())?;
                let queued: Vec<_> = self
                    .channels
                    .iter()
                    .flat_map(|(id, channel)| {
                        channel
                            .book
                            .jobs()
                            .filter(|job| {
                                job.phase() == JobPhase::Accepted
                                    && job.authorization().resource_id == policy.resource
                            })
                            .map(|job| (ChannelId(*id), job.work_id()))
                    })
                    .collect();
                for (channel, work) in queued {
                    self.end(channel, work, GrantOutcome::Released, None, None, now)?;
                }
            }
            Change::Budget(def) => {
                self.check_budget_meters(def.node, &def.limits)?;
                self.ledger.configure_budget(def.clone())?;
            }
            Change::Define(def) => {
                def.validate()?;
                self.check_resources(def, def.enabled)?;
                for id in self.ledger.path(def.budget)? {
                    let node = self.ledger.node(id).ok_or(LedgerError::UnknownNode)?;
                    if def
                        .policies
                        .iter()
                        .any(|p| node.limits().iter().any(|l| !p.supports(l.meter)))
                    {
                        return Err(GrantError::Limits.into());
                    }
                }
                let fresh = !self.grants.contains_key(&def.id);
                if let Some(old) = self.grants.get(&def.id) {
                    if old.budget != def.budget
                        || def.revision != old.revision.next().ok_or(NodeStoreError::Malformed)?
                    {
                        return Err(GrantError::Revision(old.revision).into());
                    }
                } else {
                    if def.revision != Revision(1) {
                        return Err(GrantError::Malformed.into());
                    }
                    if self.grants.len() >= MAX_ALLOWANCES {
                        return Err(GrantError::StateCapacity.into());
                    }
                }
                if let Some(old) = self.grants.insert(def.id, def.clone()) {
                    self.history.insert((old.id, old.revision), old);
                }
                if fresh {
                    self.generations.insert(def.id, 0);
                }
                {
                    let queued: Vec<_> = self
                        .channels
                        .iter()
                        .filter(|(_, c)| c.funding.grant == def.id)
                        .flat_map(|(id, c)| {
                            c.book
                                .jobs()
                                .filter(|j| {
                                    j.phase() == JobPhase::Accepted
                                        && (!def.enabled
                                            || self.check_resource(j.authorization()).is_err())
                                })
                                .map(|j| (ChannelId(*id), j.work_id()))
                        })
                        .collect();
                    for (channel, work) in queued {
                        self.end(channel, work, GrantOutcome::Released, None, None, now)?;
                    }
                }
            }
            Change::Generation { grant, generation } => {
                if self.generation(*grant).and_then(|n| n.checked_add(1)) != Some(*generation) {
                    return Err(GrantError::Generation.into());
                }
                self.generations.insert(*grant, *generation);
            }
            Change::Accepted {
                authorization: a,
                client_signature,
                provider_signature,
                charge,
                execution,
            } => {
                let id = grant_work_id(self.network, a);
                if let Some(job) = self
                    .channels
                    .get(&a.channel_id.0)
                    .and_then(|c| c.book.job_by_id(id))
                {
                    if job.authorization() == a
                        && job.client_signature() == *client_signature
                        && job.provider_signature() == Some(*provider_signature)
                        && self.admissions.get(&id).is_some_and(|record| {
                            record.accepted == *execution && record.reserved == *charge
                        })
                    {
                        return Ok(Applied::Redundant);
                    }
                    return Err(NodeStoreError::Malformed);
                }
                execution.replay(self, a.grant_id, now)?;
                let client = ChannelClient::recorded(execution.caller())?;
                self.check_terms(a, client, now)?;
                self.mount(a.grant_id, client)?;
                verify(client.signer(), *client_signature, id)?;
                verify(grant_producer(self.provider()?)?, *provider_signature, id)?;
                if charge.get(Meter::Requests) != 1
                    || self
                        .policy_for(a)?
                        .pricing
                        .reserve(*charge)
                        .map_err(|_| GrantError::Limits)?
                        != *charge
                {
                    return Err(NodeStoreError::Malformed);
                }
                let budget = self
                    .grant(a.grant_id)
                    .ok_or(GrantError::Unauthorized)?
                    .budget;
                for node in self.ledger.path(budget)? {
                    let holds = self.recovery_holds(node, now)?;
                    let cap = self
                        .ledger
                        .node(node)
                        .ok_or(LedgerError::UnknownNode)?
                        .concurrent();
                    if self.ledger.active_count(node) + holds >= usize::from(cap) {
                        return Err(LedgerError::Concurrent(node).into());
                    }
                }
                let _reservation = self.ledger.reserve(id, budget, *charge, now)?;
                // The only owner of this capability is the candidate journal
                // state; reconstruction on a later durable transition is private.
                let book = &mut self
                    .channels
                    .get_mut(&a.channel_id.0)
                    .ok_or(GrantError::Unauthorized)?
                    .book;
                book.propose(
                    JobState {
                        authorization: *a,
                        work_id: id,
                        prepared_input: vec![],
                        client_signature: *client_signature,
                        provider_signature: None,
                        phase: JobPhase::HalfSigned,
                        result: None,
                        transcript: vec![],
                    },
                    Role::Provider,
                )?;
                book.accept(id, *provider_signature, now, Role::Provider)?;
                if self
                    .admissions
                    .insert(
                        id,
                        super::AdmissionRecord {
                            accepted: execution.clone(),
                            dispatched: None,
                            reserved: *charge,
                        },
                    )
                    .is_some()
                {
                    return Err(NodeStoreError::Malformed);
                }
            }
            Change::Dispatched {
                channel,
                work,
                execution,
            } => {
                let grant = self
                    .channels
                    .get(&channel.0)
                    .ok_or(GrantError::Unauthorized)?
                    .funding
                    .grant;
                let admission = self
                    .admission(*channel, *work)
                    .ok_or(NodeStoreError::Malformed)?;
                if !admission.accepted.same_application(execution) {
                    return Err(NodeStoreError::Malformed);
                }
                if let Some(previous) = &admission.dispatched {
                    return if previous == execution {
                        Ok(Applied::Redundant)
                    } else {
                        Err(NodeStoreError::Malformed)
                    };
                }
                let job = self
                    .channel(*channel)
                    .and_then(|c| c.job_book().job_by_id(*work))
                    .ok_or(GrantError::OutOfScope)?;
                self.check_resource(job.authorization())?;
                execution.replay(self, grant, now)?;
                self.grants
                    .get(&grant)
                    .ok_or(GrantError::Unauthorized)?
                    .admit()?;
                if self
                    .channels
                    .get_mut(&channel.0)
                    .ok_or(GrantError::Unauthorized)?
                    .book
                    .run(*work, now)?
                    == Applied::Redundant
                {
                    return Err(NodeStoreError::Malformed);
                }
                self.admissions
                    .get_mut(work)
                    .ok_or(NodeStoreError::Malformed)?
                    .dispatched = Some(execution.clone());
            }
            Change::Terminal {
                channel,
                work,
                outcome,
                result,
                usage,
            } => {
                self.end(*channel, *work, *outcome, result.clone(), *usage, now)?;
            }
        }
        self.prune();
        Ok(Applied::Changed)
    }
    pub(super) fn check_terms(
        &self,
        a: &GrantJobAuthorizationV1,
        client: ChannelClient,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.check_channel(a, client)?;
        let def = self.grant(a.grant_id).ok_or(GrantError::Unauthorized)?;
        def.admit()?;
        if def.revision != a.grant_revision {
            return Err(GrantError::Revision(def.revision).into());
        }
        if self.generation(a.grant_id) != Some(a.generation) {
            return Err(GrantError::Generation.into());
        }
        if now > a.acceptance_deadline_ms {
            return Err(GrantError::Expired.into());
        }
        if a.resource_revision.0 == 0
            || a.pricing_revision.0 == 0
            || a.proposal_nonce == 0
            || a.acceptance_deadline_ms >= a.terminal_deadline_ms
            || a.terminal_deadline_ms >= a.delivery_deadline_ms
            || a.delivery_deadline_ms.0 - a.terminal_deadline_ms.0 > 300_000
            || a.terminal_deadline_ms.0.saturating_sub(now.0) > def.max_job_millis.get()
        {
            return Err(GrantError::Malformed.into());
        }
        let policy = self.policy_for(a)?;
        if policy.work.allowed_environment() != a.environment_commitment {
            return Err(GrantError::OutOfScope.into());
        }
        self.check_resource(a)?;
        if self
            .resources
            .get(&policy.resource)
            .is_some_and(|r| r.quarantined)
        {
            return Err(GrantError::Quarantined.into());
        }
        Ok(())
    }
    pub fn policy_for(&self, a: &GrantJobAuthorizationV1) -> Result<&GrantPolicy, NodeStoreError> {
        let def = self
            .grant(a.grant_id)
            .filter(|g| g.revision == a.grant_revision)
            .or_else(|| self.history.get(&(a.grant_id, a.grant_revision)))
            .ok_or(GrantError::OutOfScope)?;
        def.policies
            .iter()
            .find(|p| {
                p.resource == a.resource_id
                    && p.revision == a.resource_revision
                    && p.pricing.revision == a.pricing_revision
                    && p.work.digest(self.network, a.channel_id.0) == a.work_policy_digest
            })
            .ok_or_else(|| GrantError::OutOfScope.into())
    }
    pub fn resource_health(&self, id: ResourceId) -> Option<ResourceHealth> {
        self.resources.get(&id).copied()
    }
    fn end(
        &mut self,
        channel: ChannelId,
        work: Digest,
        outcome: GrantOutcome,
        result: Option<SignedResult>,
        usage: Option<Charge>,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        let auth = *self
            .channels
            .get(&channel.0)
            .ok_or(GrantError::Unauthorized)?
            .book
            .job_by_id(work)
            .ok_or(NodeStoreError::Malformed)?
            .authorization();
        let policy = self.policy_for(&auth)?;
        let resource = policy.resource;
        let usage = usage
            .map(|charge| policy.pricing.settle(charge))
            .transpose()
            .map_err(|_| NodeStoreError::Malformed)?;
        let strict_accounting = policy.responses.is_some()
            || policy.https.as_ref().is_some_and(|r| {
                r.accounting != crate::model::grant::resource::AccountingProfile::None
            });
        let provider_key = grant_producer(self.provider()?)?;
        let book = &mut self
            .channels
            .get_mut(&channel.0)
            .ok_or(GrantError::Unauthorized)?
            .book;
        let job = book
            .job_by_id(work)
            .ok_or(NodeStoreError::Malformed)?
            .clone();
        if outcome == GrantOutcome::Released {
            if job.phase() != JobPhase::Accepted || result.is_some() || usage.is_some() {
                return Err(NodeStoreError::Malformed);
            }
        } else if !matches!(job.phase(), JobPhase::Running | JobPhase::Streaming) {
            return Err(NodeStoreError::Malformed);
        }
        if usage.is_some_and(|c| c.get(Meter::Requests) != 1)
            || (outcome == GrantOutcome::Indeterminate && usage.is_some())
        {
            return Err(NodeStoreError::Malformed);
        }
        if let Some(r) = &result {
            if r.result.work_id != work
                || matches!(
                    outcome,
                    GrantOutcome::Released | GrantOutcome::Indeterminate
                )
            {
                return Err(NodeStoreError::Malformed);
            }
            verify(
                provider_key,
                r.signature,
                bound_result_digest(self.network, channel.0, &r.result),
            )?;
        } else if outcome == GrantOutcome::Finished {
            return Err(NodeStoreError::Malformed);
        }
        let reservation = self.ledger.recover(work)?;
        if outcome == GrantOutcome::Released {
            self.ledger.release(reservation)?;
        } else {
            let overrun = self.ledger.settle(
                reservation,
                usage.map_or(Usage::Unknown, Usage::Observed),
                now,
            )?;
            let health = self
                .resources
                .get_mut(&resource)
                .ok_or(NodeStoreError::Malformed)?;
            health.revision = health
                .revision
                .checked_add(1)
                .ok_or(NodeStoreError::Malformed)?;
            if strict_accounting && usage.is_none() {
                health.consecutive_faults = health.consecutive_faults.saturating_add(1);
            } else if usage.is_some() {
                health.consecutive_faults = 0;
            }
            health.quarantined |= overrun || health.consecutive_faults >= 3;
        }
        book.rest_at(JobTerminal {
            work_id: work,
            phase: job.phase(),
            outcome: GrantTerminal {
                outcome,
                authorization: *job.authorization(),
                client_signature: job.client_signature(),
                provider_signature: job.provider_signature().ok_or(NodeStoreError::Malformed)?,
                result,
            },
        });
        Ok(())
    }
}
fn verify(
    key: hellas_kernel::Key,
    signature: Signature,
    digest: Digest,
) -> Result<(), NodeStoreError> {
    hellas_auth::signature::verify_digest_signature(
        &PublicKey::Secp256k1(key.to_bytes()),
        &signature,
        digest,
    )
    .map_err(|_| GrantError::Signature.into())
}

#[derive(Serialize, Deserialize)]
pub(super) struct Snapshot {
    namespace: String,
    #[serde(with = "crate::model::grant::records::network")]
    network: NetworkId,
    authority: AuthoritySnapshot,
    last_administration: Option<AdministrationRecord>,
    last_work_administration: Option<super::WorkRecord>,
    machine_revision: hellas_auth::authority::Revision,
    paid_policy: Option<crate::model::paid_policy::StoredPaidPolicy>,
    #[serde(with = "super::codec::optional_provider")]
    provider: Option<ProviderEnrollmentBundle>,
    grants: Vec<GrantDef>,
    generations: Vec<(GrantId, u64)>,
    ledger: Ledger,
    history: Vec<GrantDef>,
    resources: Vec<(ResourceId, ResourceHealth)>,
    catalogue: Vec<GrantPolicy>,
    channels: Vec<StoredChannel>,
    #[serde(with = "super::codec::entries")]
    admissions: BTreeMap<Digest, super::AdmissionRecord>,
}
#[derive(Serialize, Deserialize)]
struct StoredChannel {
    identity: GrantChannelState,
    nonce: u64,
    jobs: Vec<StoredJob>,
    terminals: Vec<(Digest, u8, GrantTerminal)>,
}
#[derive(Serialize, Deserialize)]
struct StoredJob {
    #[serde(with = "super::codec::record")]
    authorization: GrantJobAuthorizationV1,
    client: Signature,
    provider: Signature,
    phase: u8,
}
impl State {
    pub(super) fn snapshot(&self) -> Result<Snapshot, NodeStoreError> {
        Ok(Snapshot {
            namespace: "hellas.node.checkpoint.v2".into(),
            network: self.network,
            authority: self.authority.snapshot(),
            last_administration: self.last_administration.clone(),
            last_work_administration: self.last_work_administration.clone(),
            machine_revision: self.machine_revision,
            paid_policy: self.paid_policy.clone(),
            provider: self.provider.clone(),
            grants: self.grants.values().cloned().collect(),
            generations: self
                .generations
                .iter()
                .map(|(id, generation)| (*id, *generation))
                .collect(),
            ledger: self.ledger.clone(),
            history: self.history.values().cloned().collect(),
            resources: self.resources.iter().map(|(id, h)| (*id, *h)).collect(),
            catalogue: self.catalogue.values().cloned().collect(),
            admissions: self.admissions.clone(),
            channels: self
                .channels
                .values()
                .map(|c| {
                    Ok(StoredChannel {
                        identity: c.funding.clone(),
                        nonce: c.book.proposal_nonce_high_water(),
                        jobs: c
                            .book
                            .jobs()
                            .map(|j| {
                                Ok(StoredJob {
                                    authorization: *j.authorization(),
                                    client: j.client_signature(),
                                    provider: j
                                        .provider_signature()
                                        .ok_or(NodeStoreError::Malformed)?,
                                    phase: j.phase().code(),
                                })
                            })
                            .collect::<Result<_, NodeStoreError>>()?,
                        terminals: c
                            .book
                            .terminals()
                            .map(|t| (t.work_id, t.phase.code(), t.outcome.clone()))
                            .collect(),
                    })
                })
                .collect::<Result<_, NodeStoreError>>()?,
        })
    }
    pub(super) fn restore(s: Snapshot) -> Result<Self, NodeStoreError> {
        if s.namespace != "hellas.node.checkpoint.v2"
            || s.grants.len() > MAX_ALLOWANCES
            || s.generations.len() != s.grants.len()
            || s.channels.len() > MAX_CHANNELS
            || s.catalogue.len() > MAX_RESOURCES
        {
            return Err(NodeStoreError::Malformed);
        }
        let mut state =
            Self::initialized(s.network, AuthorityState::restore(s.authority)?, s.provider)?;
        if s.last_administration.as_ref().is_some_and(|record| {
            record.caller().authority() != state.authority.authority()
                || record.caller().generation() == 0
                || record.caller().generation() > state.authority.generation()
                || record.caller().before().0 == 0
                || record.caller().before() >= state.authority.revision()
                || record.caller().at() > s.ledger.high_water()
        }) {
            return Err(NodeStoreError::Malformed);
        }
        state.last_administration = s.last_administration;
        if s.last_work_administration.as_ref().is_some_and(|record| {
            record.caller.authority() != state.authority.authority()
                || record.caller.generation() == 0
                || record.caller.generation() > state.authority.generation()
                || record.caller.before().0 == 0
                || record.caller.before() > state.authority.revision()
                || record.caller.at() > s.ledger.high_water()
                || !record.mutation.valid_capacity()
                || match &record.mutation {
                    super::WorkMutation::Capacity {
                        expected,
                        max_in_flight,
                        limits,
                    } => {
                        (expected.0 == 0 && state.provider.is_none())
                            || *expected >= s.machine_revision
                            || Ledger::default()
                                .configure_machine(limits.clone(), *max_in_flight)
                                .is_err()
                    }
                    _ => false,
                }
        }) {
            return Err(NodeStoreError::Malformed);
        }
        state.last_work_administration = s.last_work_administration;
        if (s.machine_revision.0 == 0) != s.ledger.node(BudgetNode::Machine).is_none() {
            return Err(NodeStoreError::Malformed);
        }
        state.machine_revision = s.machine_revision;
        if let Some(policy) = &s.paid_policy {
            if policy.revision.0 == 0 {
                return Err(NodeStoreError::Malformed);
            }
            policy.policy.check()?;
        }
        state.paid_policy = s.paid_policy;
        if s.ledger.high_water() < state.authority.now() {
            return Err(NodeStoreError::Malformed);
        }
        state.ledger = s.ledger;
        state.admissions = s.admissions;
        for def in s.history {
            def.validate()?;
            if state.history.insert((def.id, def.revision), def).is_some() {
                return Err(NodeStoreError::Malformed);
            }
        }
        for (id, health) in s.resources {
            if state.resources.insert(id, health).is_some() {
                return Err(NodeStoreError::Malformed);
            }
        }
        for policy in s.catalogue {
            policy.validate()?;
            if state
                .ledger
                .node(BudgetNode::Account(policy.account))
                .is_none()
                || state.catalogue.values().any(|p| p.name == policy.name)
                || state.catalogue.insert(policy.resource, policy).is_some()
            {
                return Err(NodeStoreError::Malformed);
            }
        }
        if !state.catalogue.keys().eq(state.resources.keys()) {
            return Err(NodeStoreError::Malformed);
        }
        for def in s.grants {
            def.validate()?;
            if state.grants.insert(def.id, def).is_some() {
                return Err(NodeStoreError::Malformed);
            }
        }
        for (grant, generation) in s.generations {
            if !state.grants.contains_key(&grant)
                || state.generations.insert(grant, generation).is_some()
            {
                return Err(NodeStoreError::Malformed);
            }
        }
        for c in s.channels {
            let id = grant_channel_id(
                state.network,
                state.provider()?.content_id(),
                c.identity.grant,
                c.identity.client,
                c.identity.generation,
            );
            if id != c.identity.id
                || state
                    .generation(c.identity.grant)
                    .is_none_or(|g| c.identity.generation > g)
            {
                return Err(NodeStoreError::Malformed);
            }
            let mut book = JobBook::default();
            for j in c.jobs {
                let work = grant_work_id(state.network, &j.authorization);
                if j.authorization.channel_id != id
                    || j.authorization.generation != c.identity.generation
                    || j.authorization.proposal_nonce > c.nonce
                    || j.authorization.grant_id != c.identity.grant
                {
                    return Err(NodeStoreError::Malformed);
                }
                verify(state.admitted_signer(work)?, j.client, work)?;
                verify(grant_producer(state.provider()?)?, j.provider, work)?;
                let phase = JobPhase::from_code(j.phase)?;
                if !matches!(
                    phase,
                    JobPhase::Accepted | JobPhase::Running | JobPhase::Streaming
                ) {
                    return Err(NodeStoreError::Malformed);
                }
                if book
                    .jobs
                    .insert(
                        work,
                        JobState {
                            authorization: j.authorization,
                            work_id: work,
                            prepared_input: vec![],
                            client_signature: j.client,
                            provider_signature: Some(j.provider),
                            phase,
                            result: None,
                            transcript: vec![],
                        },
                    )
                    .is_some()
                {
                    return Err(NodeStoreError::Malformed);
                }
            }
            for (work, phase, terminal) in c.terminals {
                if grant_work_id(state.network, &terminal.authorization) != work
                    || terminal.authorization.channel_id != id
                    || terminal.authorization.generation != c.identity.generation
                    || terminal.authorization.grant_id != c.identity.grant
                    || terminal.authorization.proposal_nonce > c.nonce
                {
                    return Err(NodeStoreError::Malformed);
                }
                verify(
                    state.admitted_signer(work)?,
                    terminal.client_signature,
                    work,
                )?;
                verify(
                    grant_producer(state.provider()?)?,
                    terminal.provider_signature,
                    work,
                )?;
                if let Some(r) = &terminal.result {
                    if r.result.work_id != work {
                        return Err(NodeStoreError::Malformed);
                    }
                    verify(
                        grant_producer(state.provider()?)?,
                        r.signature,
                        bound_result_digest(state.network, id.0, &r.result),
                    )?;
                }
                if book.jobs.contains_key(&work)
                    || book
                        .terminals
                        .insert(
                            work,
                            JobTerminal {
                                work_id: work,
                                phase: JobPhase::from_code(phase)?,
                                outcome: terminal,
                            },
                        )
                        .is_some()
                {
                    return Err(NodeStoreError::Malformed);
                }
            }
            book.proposal_nonce_high_water = c.nonce;
            if state
                .channels
                .insert(
                    id.0,
                    Channel {
                        funding: c.identity,
                        ledger: (),
                        role: Role::Provider,
                        book,
                    },
                )
                .is_some()
            {
                return Err(NodeStoreError::Malformed);
            }
        }
        let mut versions = BTreeMap::new();
        for policy in state.catalogue.values().chain(
            state
                .grants
                .values()
                .chain(state.history.values())
                .flat_map(|g| &g.policies),
        ) {
            if versions
                .insert((policy.resource, policy.revision), policy)
                .is_some_and(|old| old != policy)
            {
                return Err(NodeStoreError::Malformed);
            }
        }
        for def in state.grants.values().chain(state.history.values()) {
            let current = state.grant(def.id).ok_or(NodeStoreError::Malformed)?;
            if current.budget != def.budget || current.revision < def.revision {
                return Err(NodeStoreError::Malformed);
            }
            state.check_resources(def, false)?;
        }
        let mut retained = std::collections::BTreeSet::new();
        for c in state.channels.values() {
            let current = state
                .grant(c.funding.grant)
                .ok_or(NodeStoreError::Malformed)?;
            let mut nonces = std::collections::BTreeSet::new();
            for (a, dispatched, active) in c
                .book
                .jobs()
                .map(|j| (j.authorization(), j.phase() != JobPhase::Accepted, true))
                .chain(c.book.terminals().map(|t| {
                    (
                        &t.outcome.authorization,
                        t.phase != JobPhase::Accepted,
                        false,
                    )
                }))
            {
                let work = grant_work_id(state.network, a);
                if !retained.insert(work) {
                    return Err(NodeStoreError::Malformed);
                }
                let admission = state
                    .admission(c.funding.id, work)
                    .ok_or(NodeStoreError::Malformed)?;
                admission.validate_history(&state, a, dispatched)?;
                if ChannelClient::recorded(admission.accepted().caller())? != c.funding.client {
                    return Err(NodeStoreError::Malformed);
                }
                if active && state.ledger.reservation_bound(work) != Some(admission.reserved) {
                    return Err(NodeStoreError::Malformed);
                }
                if active {
                    let policy = state.policy_for(a)?;
                    for id in state.ledger.path(current.budget)? {
                        let node = state.ledger.node(id).ok_or(LedgerError::UnknownNode)?;
                        if node.limits().iter().any(|l| !policy.supports(l.meter)) {
                            return Err(GrantError::Limits.into());
                        }
                    }
                }
            }
            for a in c
                .book
                .jobs()
                .map(|j| j.authorization())
                .chain(c.book.terminals().map(|t| &t.outcome.authorization))
            {
                if a.proposal_nonce == 0
                    || !nonces.insert(a.proposal_nonce)
                    || a.resource_revision.0 == 0
                    || a.pricing_revision.0 == 0
                    || a.acceptance_deadline_ms >= a.terminal_deadline_ms
                    || a.terminal_deadline_ms >= a.delivery_deadline_ms
                    || a.delivery_deadline_ms.0 - a.terminal_deadline_ms.0 > 300_000
                    || state.policy_for(a)?.work.allowed_environment() != a.environment_commitment
                {
                    return Err(NodeStoreError::Malformed);
                }
            }
            for terminal in c.book.terminals() {
                let t = &terminal.outcome;
                let valid_phase = match t.outcome {
                    GrantOutcome::Released => {
                        terminal.phase == JobPhase::Accepted && t.result.is_none()
                    }
                    GrantOutcome::Indeterminate => {
                        matches!(terminal.phase, JobPhase::Running | JobPhase::Streaming)
                            && t.result.is_none()
                    }
                    GrantOutcome::Finished => {
                        matches!(terminal.phase, JobPhase::Running | JobPhase::Streaming)
                            && t.result.is_some()
                    }
                    GrantOutcome::Failed => {
                        matches!(terminal.phase, JobPhase::Running | JobPhase::Streaming)
                    }
                };
                if !valid_phase {
                    return Err(NodeStoreError::Malformed);
                }
            }
        }
        state.ledger.validate_definitions(state.grants.values())?;
        if retained.len() != state.admissions.len() {
            return Err(NodeStoreError::Malformed);
        }
        let mut reservations = Vec::new();
        for channel in state.channels.values() {
            let grant = state
                .grant(channel.funding.grant)
                .ok_or(GrantError::Unauthorized)?;
            reservations.extend(channel.book.jobs().map(|j| (j.work_id(), grant.budget)));
        }
        state
            .ledger
            .validate_reservations(reservations.into_iter())?;
        Ok(state)
    }
}
