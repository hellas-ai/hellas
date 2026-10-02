use super::ledger::{Ledger, LedgerError};
use super::{
    ChannelId, Deserialize, GrantChannelState, GrantId, GrantJobAuthorizationV1, GrantOutcome,
    GrantStoreError, GrantTerminal, Serialize, Signature, SignedResult,
};
use crate::work_store::channel::funding::GrantFunding;
use crate::work_store::{Applied, Channel, JobBook, JobPhase, JobState, JobTerminal, Role};
use hellas_kernel::NetworkId;
use hellas_rpc::ProviderEnrollmentBundle;
use hellas_rpc::protocol::work::bound_result_digest;
use hellas_rpc::protocol::work_grant::{
    Revision, UnixMillis,
    budget::{BudgetNode, Charge, Limit, Meter, Usage},
    grant_channel_id, grant_work_id, owner_grant_id,
    records::{GrantDef, GrantError, GrantKind, GrantPolicy, GrantState, provider_bytes},
};
use hellas_rpc::{Digest, PublicKey};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub(super) network: NetworkId,
    pub(super) provider: ProviderEnrollmentBundle,
    pub(super) grants: BTreeMap<GrantId, GrantDef>,
    pub(super) channels: BTreeMap<Digest, Channel<GrantFunding>>,
    pub(super) ledger: Ledger,
    pub(super) history: BTreeMap<(GrantId, Revision), GrantDef>,
    pub(super) resources: BTreeMap<Digest, ResourceHealth>,
}
/// Three consecutive unknown accounting results quarantine a route. A verified
/// overrun quarantines immediately; time and grant revisions cannot clear it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceHealth {
    pub consecutive_faults: u16,
    pub quarantined: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Frame {
    pub namespace: String,
    pub now: UnixMillis,
    pub change: Change,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum Change {
    Machine {
        limits: Vec<Limit>,
        concurrent: u16,
    },
    Define(GrantDef),
    Generation {
        grant: GrantId,
        generation: u64,
    },
    Clock,
    RepairResource(Digest),
    Accepted {
        #[serde(with = "super::codec::record")]
        authorization: GrantJobAuthorizationV1,
        client_signature: Signature,
        provider_signature: Signature,
        charge: Charge,
    },
    Dispatched {
        channel: ChannelId,
        work: Digest,
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
    pub fn network(&self) -> NetworkId {
        self.network
    }
    pub fn provider(&self) -> &ProviderEnrollmentBundle {
        &self.provider
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
    pub fn channel_binding(&self, id: ChannelId) -> Option<&GrantChannelState> {
        self.channels.get(&id.0).map(|c| &c.funding)
    }
    pub fn now(&self) -> UnixMillis {
        self.ledger.high_water()
    }
    pub fn generation(&self, grant: GrantId) -> Option<u64> {
        self.channels
            .values()
            .filter(|c| c.funding.grant == grant)
            .map(|c| c.funding.generation)
            .max()
    }
    pub fn channel_id(&self, grant: GrantId) -> Option<ChannelId> {
        let def = self.grant(grant)?;
        Some(grant_channel_id(
            self.network,
            self.provider.content_id(),
            grant,
            def.kind.principal().id(),
            self.generation(grant)?,
        ))
    }
    /// A recovered invocation can retain capacity until its enforceable lifetime
    /// ends, even though its quota was already charged at the reserved bound.
    pub fn recovery_holds(&self, grant: Option<GrantId>, now: UnixMillis) -> usize {
        self.channels
            .values()
            .filter(|c| grant.is_none_or(|id| c.funding.grant == id))
            .flat_map(|c| c.book.terminals())
            .filter(|t| {
                t.outcome.outcome == GrantOutcome::Indeterminate
                    && t.outcome.authorization.terminal_deadline_ms > now
            })
            .count()
    }
    pub(super) fn empty(network: NetworkId, provider: ProviderEnrollmentBundle) -> Self {
        Self {
            network,
            provider,
            grants: BTreeMap::new(),
            channels: BTreeMap::new(),
            ledger: Ledger::default(),
            history: BTreeMap::new(),
            resources: BTreeMap::new(),
        }
    }
    fn mount(&mut self, grant: GrantId, generation: u64) -> Result<(), GrantStoreError> {
        let def = self.grants.get(&grant).ok_or(GrantError::Unauthorized)?;
        let client = def.kind.principal().clone();
        let id = grant_channel_id(
            self.network,
            self.provider.content_id(),
            grant,
            client.id(),
            generation,
        );
        if self.channels.contains_key(&id.0) {
            return Err(GrantError::Generation.into());
        }
        if self.channels.len() >= 256 {
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
    pub(super) fn apply(&mut self, frame: &Frame) -> Result<Applied, GrantStoreError> {
        if frame.namespace != "hellas.work.grant-journal.v1" || frame.now < self.now() {
            return Err(GrantStoreError::Malformed);
        }
        self.ledger.advance(frame.now);
        match &frame.change {
            Change::Clock => {}
            Change::RepairResource(id) => {
                let health = self.resources.get_mut(id).ok_or(GrantError::OutOfScope)?;
                *health = ResourceHealth::default();
            }
            Change::Machine { limits, concurrent } => {
                // Current resumable grants and already accepted work must be
                // measurable under a new machine limit. Revoked, drained grants
                // retain their counters without constraining future policy.
                if self
                    .grants
                    .values()
                    .filter(|g| g.state != GrantState::Revoked)
                    .flat_map(|g| &g.policies)
                    .any(|p| limits.iter().any(|l| !p.supports(l.meter)))
                {
                    return Err(GrantError::Limits.into());
                }
                for job in self.channels.values().flat_map(|c| c.book.jobs()) {
                    let policy = self.policy_for(job.authorization())?;
                    if limits.iter().any(|l| !policy.supports(l.meter)) {
                        return Err(GrantError::Limits.into());
                    }
                }
                self.ledger
                    .configure(BudgetNode::Machine, limits.clone(), *concurrent)?;
            }
            Change::Define(def) => {
                def.validate()?;
                let machine = self
                    .ledger
                    .node(BudgetNode::Machine)
                    .ok_or(LedgerError::UnknownNode)?;
                if def
                    .policies
                    .iter()
                    .any(|p| machine.limits().iter().any(|l| !p.supports(l.meter)))
                {
                    return Err(GrantError::Limits.into());
                }
                let fresh = !self.grants.contains_key(&def.id);
                if let Some(old) = self.grants.get(&def.id) {
                    if old.state == GrantState::Revoked
                        || old.kind != def.kind
                        || def.revision.0
                            != old
                                .revision
                                .0
                                .checked_add(1)
                                .ok_or(GrantStoreError::Malformed)?
                    {
                        return Err(GrantError::Revision(old.revision).into());
                    }
                } else {
                    if def.revision != Revision(1) {
                        return Err(GrantError::Malformed.into());
                    }
                    if self.grants.len() >= 256 {
                        return Err(GrantError::StateCapacity.into());
                    }
                }
                if matches!(def.kind, GrantKind::Owner(_))
                    && def.id
                        != owner_grant_id(
                            self.network,
                            self.provider.content_id(),
                            def.kind.principal().id(),
                        )
                {
                    return Err(GrantError::Malformed.into());
                }
                self.ledger.configure(
                    BudgetNode::Grant(def.id),
                    def.limits.clone(),
                    def.max_in_flight.get(),
                )?;
                for policy in &def.policies {
                    self.resources.entry(policy.resource_id()?).or_default();
                }
                if let Some(old) = self.grants.insert(def.id, def.clone()) {
                    self.history.insert((old.id, old.revision), old);
                }
                if fresh {
                    self.mount(def.id, 0)?;
                }
                if def.state != GrantState::Active {
                    let queued: Vec<_> = self
                        .channels
                        .iter()
                        .filter(|(_, c)| c.funding.grant == def.id)
                        .flat_map(|(id, c)| {
                            c.book
                                .jobs()
                                .filter(|j| j.phase() == JobPhase::Accepted)
                                .map(|j| (ChannelId(*id), j.work_id()))
                        })
                        .collect();
                    for (channel, work) in queued {
                        self.end(channel, work, GrantOutcome::Released, None, None, frame.now)?;
                    }
                }
            }
            Change::Generation { grant, generation } => {
                if self.generation(*grant).and_then(|n| n.checked_add(1)) != Some(*generation) {
                    return Err(GrantError::Generation.into());
                }
                self.mount(*grant, *generation)?;
            }
            Change::Accepted {
                authorization: a,
                client_signature,
                provider_signature,
                charge,
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
                    {
                        return Ok(Applied::Redundant);
                    }
                    return Err(GrantStoreError::Malformed);
                }
                self.check_authority(a, frame.now)?;
                let channel = self
                    .channels
                    .get(&a.channel_id.0)
                    .ok_or(GrantError::Unauthorized)?;
                verify(channel.funding.client.producer(), *client_signature, id)?;
                verify(self.provider.grant_producer()?, *provider_signature, id)?;
                if charge.get(Meter::Requests) != 1 {
                    return Err(GrantStoreError::Malformed);
                }
                for node in [BudgetNode::Machine, BudgetNode::Grant(a.grant_id)] {
                    let holds = self.recovery_holds(
                        if node == BudgetNode::Machine {
                            None
                        } else {
                            Some(a.grant_id)
                        },
                        frame.now,
                    );
                    let cap = self
                        .ledger
                        .node(node)
                        .ok_or(LedgerError::UnknownNode)?
                        .concurrent();
                    if self.ledger.active_count(node) + holds >= usize::from(cap) {
                        return Err(LedgerError::Concurrent(node).into());
                    }
                }
                let _reservation = self.ledger.reserve(
                    id,
                    vec![BudgetNode::Machine, BudgetNode::Grant(a.grant_id)],
                    *charge,
                    frame.now,
                )?;
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
                book.accept(id, *provider_signature, frame.now, Role::Provider)?;
            }
            Change::Dispatched { channel, work } => {
                let grant = self
                    .channels
                    .get(&channel.0)
                    .ok_or(GrantError::Unauthorized)?
                    .funding
                    .grant;
                self.grants
                    .get(&grant)
                    .ok_or(GrantError::Unauthorized)?
                    .admits(frame.now)?;
                if self
                    .channels
                    .get_mut(&channel.0)
                    .ok_or(GrantError::Unauthorized)?
                    .book
                    .run(*work, frame.now)?
                    == Applied::Redundant
                {
                    return Ok(Applied::Redundant);
                }
            }
            Change::Terminal {
                channel,
                work,
                outcome,
                result,
                usage,
            } => {
                self.end(*channel, *work, *outcome, result.clone(), *usage, frame.now)?;
            }
        }
        self.prune();
        Ok(Applied::Changed)
    }
    pub(super) fn check_authority(
        &self,
        a: &GrantJobAuthorizationV1,
        now: UnixMillis,
    ) -> Result<(), GrantStoreError> {
        let def = self.grant(a.grant_id).ok_or(GrantError::Unauthorized)?;
        def.admits(now)?;
        if def.revision != a.grant_revision {
            return Err(GrantError::Revision(def.revision).into());
        }
        if self.channel_id(a.grant_id) != Some(a.channel_id) {
            return Err(GrantError::Generation.into());
        }
        if now > a.acceptance_deadline_ms {
            return Err(GrantError::Expired.into());
        }
        if a.catalogue_revision != Revision(0)
            || a.proposal_nonce == 0
            || a.acceptance_deadline_ms >= a.terminal_deadline_ms
            || a.terminal_deadline_ms >= a.delivery_deadline_ms
            || a.delivery_deadline_ms.0 - a.terminal_deadline_ms.0 > 300_000
            || a.terminal_deadline_ms.0.saturating_sub(now.0) > def.max_job_millis.get()
        {
            return Err(GrantError::Malformed.into());
        }
        if !def.policies.iter().any(|p| {
            p.work.digest(self.network, a.channel_id.0) == a.work_policy_digest
                && p.work.allowed_environment() == a.environment_commitment
        }) {
            return Err(GrantError::OutOfScope.into());
        }
        let policy = self.policy_for(a)?;
        if self
            .resources
            .get(&policy.resource_id()?)
            .is_some_and(|r| r.quarantined)
        {
            return Err(GrantError::Quarantined.into());
        }
        Ok(())
    }
    pub fn policy_for(&self, a: &GrantJobAuthorizationV1) -> Result<&GrantPolicy, GrantStoreError> {
        let def = self
            .grant(a.grant_id)
            .filter(|g| g.revision == a.grant_revision)
            .or_else(|| self.history.get(&(a.grant_id, a.grant_revision)))
            .ok_or(GrantError::OutOfScope)?;
        def.policies
            .iter()
            .find(|p| p.work.digest(self.network, a.channel_id.0) == a.work_policy_digest)
            .ok_or_else(|| GrantError::OutOfScope.into())
    }
    pub fn resource_health(&self, id: Digest) -> Option<ResourceHealth> {
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
    ) -> Result<(), GrantStoreError> {
        let auth = *self
            .channels
            .get(&channel.0)
            .ok_or(GrantError::Unauthorized)?
            .book
            .job_by_id(work)
            .ok_or(GrantStoreError::Malformed)?
            .authorization();
        let policy = self.policy_for(&auth)?;
        let resource = policy.resource_id()?;
        let strict_accounting = policy.https.as_ref().is_some_and(|r| {
            r.accounting != hellas_rpc::protocol::work_grant::resource::AccountingProfile::None
        });
        let book = &mut self
            .channels
            .get_mut(&channel.0)
            .ok_or(GrantError::Unauthorized)?
            .book;
        let job = book
            .job_by_id(work)
            .ok_or(GrantStoreError::Malformed)?
            .clone();
        if outcome == GrantOutcome::Released {
            if job.phase() != JobPhase::Accepted || result.is_some() || usage.is_some() {
                return Err(GrantStoreError::Malformed);
            }
        } else if !matches!(job.phase(), JobPhase::Running | JobPhase::Streaming) {
            return Err(GrantStoreError::Malformed);
        }
        if usage.is_some_and(|c| c.get(Meter::Requests) != 1)
            || (outcome == GrantOutcome::Indeterminate && usage.is_some())
        {
            return Err(GrantStoreError::Malformed);
        }
        if let Some(r) = &result {
            if r.result.work_id != work
                || matches!(
                    outcome,
                    GrantOutcome::Released | GrantOutcome::Indeterminate
                )
            {
                return Err(GrantStoreError::Malformed);
            }
            verify(
                self.provider.grant_producer()?,
                r.signature,
                bound_result_digest(self.network, channel.0, &r.result),
            )?;
        } else if outcome == GrantOutcome::Finished {
            return Err(GrantStoreError::Malformed);
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
                .ok_or(GrantStoreError::Malformed)?;
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
                provider_signature: job.provider_signature().ok_or(GrantStoreError::Malformed)?,
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
) -> Result<(), GrantStoreError> {
    hellas_rpc::signature::verify_digest_signature(
        &PublicKey::Secp256k1(key.to_bytes()),
        &signature,
        digest,
    )
    .map_err(|_| GrantError::Signature.into())
}

#[derive(Serialize, Deserialize)]
pub(super) struct Snapshot {
    namespace: String,
    #[serde(with = "hellas_rpc::protocol::work_grant::records::network")]
    network: NetworkId,
    #[serde(with = "provider_bytes")]
    provider: ProviderEnrollmentBundle,
    grants: Vec<GrantDef>,
    ledger: Ledger,
    history: Vec<GrantDef>,
    resources: Vec<(Digest, ResourceHealth)>,
    channels: Vec<StoredChannel>,
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
    pub(super) fn snapshot(&self) -> Snapshot {
        Snapshot {
            namespace: "hellas.work.grant-checkpoint.v1".into(),
            network: self.network,
            provider: self.provider.clone(),
            grants: self.grants.values().cloned().collect(),
            ledger: self.ledger.clone(),
            history: self.history.values().cloned().collect(),
            resources: self.resources.iter().map(|(id, h)| (*id, *h)).collect(),
            channels: self
                .channels
                .values()
                .map(|c| StoredChannel {
                    identity: c.funding.clone(),
                    nonce: c.book.proposal_nonce_high_water(),
                    jobs: c
                        .book
                        .jobs()
                        .map(|j| StoredJob {
                            authorization: *j.authorization(),
                            client: j.client_signature(),
                            provider: j.provider_signature().expect("accepted journal job"),
                            phase: j.phase().code(),
                        })
                        .collect(),
                    terminals: c
                        .book
                        .terminals()
                        .map(|t| (t.work_id, t.phase.code(), t.outcome.clone()))
                        .collect(),
                })
                .collect(),
        }
    }
    pub(super) fn restore(s: Snapshot) -> Result<Self, GrantStoreError> {
        if s.namespace != "hellas.work.grant-checkpoint.v1"
            || s.grants.len() > 256
            || s.channels.len() > 256
        {
            return Err(GrantStoreError::Malformed);
        }
        s.provider.check_grant_provider()?;
        let mut state = Self::empty(s.network, s.provider);
        state.ledger = s.ledger;
        for def in s.history {
            def.validate()?;
            if state.history.insert((def.id, def.revision), def).is_some() {
                return Err(GrantStoreError::Malformed);
            }
        }
        for (id, health) in s.resources {
            if state.resources.insert(id, health).is_some() {
                return Err(GrantStoreError::Malformed);
            }
        }
        for def in s.grants {
            def.validate()?;
            if state.grants.insert(def.id, def).is_some() {
                return Err(GrantStoreError::Malformed);
            }
        }
        for c in s.channels {
            let id = grant_channel_id(
                state.network,
                state.provider.content_id(),
                c.identity.grant,
                c.identity.client.id(),
                c.identity.generation,
            );
            if id != c.identity.id || !state.grants.contains_key(&c.identity.grant) {
                return Err(GrantStoreError::Malformed);
            }
            let mut book = JobBook::default();
            for j in c.jobs {
                let work = grant_work_id(state.network, &j.authorization);
                if j.authorization.channel_id != id
                    || j.authorization.proposal_nonce > c.nonce
                    || j.authorization.grant_id != c.identity.grant
                {
                    return Err(GrantStoreError::Malformed);
                }
                verify(c.identity.client.producer(), j.client, work)?;
                verify(state.provider.grant_producer()?, j.provider, work)?;
                let phase = JobPhase::from_code(j.phase)?;
                if !matches!(
                    phase,
                    JobPhase::Accepted | JobPhase::Running | JobPhase::Streaming
                ) {
                    return Err(GrantStoreError::Malformed);
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
                    return Err(GrantStoreError::Malformed);
                }
            }
            for (work, phase, terminal) in c.terminals {
                if grant_work_id(state.network, &terminal.authorization) != work
                    || terminal.authorization.channel_id != id
                    || terminal.authorization.grant_id != c.identity.grant
                    || terminal.authorization.proposal_nonce > c.nonce
                {
                    return Err(GrantStoreError::Malformed);
                }
                verify(
                    c.identity.client.producer(),
                    terminal.client_signature,
                    work,
                )?;
                verify(
                    state.provider.grant_producer()?,
                    terminal.provider_signature,
                    work,
                )?;
                if let Some(r) = &terminal.result {
                    if r.result.work_id != work {
                        return Err(GrantStoreError::Malformed);
                    }
                    verify(
                        state.provider.grant_producer()?,
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
                    return Err(GrantStoreError::Malformed);
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
                return Err(GrantStoreError::Malformed);
            }
        }
        for def in state.grants.values().chain(state.history.values()) {
            if matches!(def.kind, GrantKind::Owner(_))
                && def.id
                    != owner_grant_id(
                        state.network,
                        state.provider.content_id(),
                        def.kind.principal().id(),
                    )
            {
                return Err(GrantStoreError::Malformed);
            }
            let current = state.grant(def.id).ok_or(GrantStoreError::Malformed)?;
            if current.kind != def.kind || current.revision < def.revision {
                return Err(GrantStoreError::Malformed);
            }
            for policy in &def.policies {
                if !state.resources.contains_key(&policy.resource_id()?) {
                    return Err(GrantStoreError::Malformed);
                }
            }
        }
        for c in state.channels.values() {
            let current = state
                .grant(c.funding.grant)
                .ok_or(GrantStoreError::Malformed)?;
            if current.kind.principal() != &c.funding.client {
                return Err(GrantStoreError::Malformed);
            }
            let mut nonces = std::collections::BTreeSet::new();
            for a in c
                .book
                .jobs()
                .map(|j| j.authorization())
                .chain(c.book.terminals().map(|t| &t.outcome.authorization))
            {
                if a.proposal_nonce == 0
                    || !nonces.insert(a.proposal_nonce)
                    || a.catalogue_revision != Revision(0)
                    || a.acceptance_deadline_ms >= a.terminal_deadline_ms
                    || a.terminal_deadline_ms >= a.delivery_deadline_ms
                    || a.delivery_deadline_ms.0 - a.terminal_deadline_ms.0 > 300_000
                    || state.policy_for(a)?.work.allowed_environment() != a.environment_commitment
                {
                    return Err(GrantStoreError::Malformed);
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
                    return Err(GrantStoreError::Malformed);
                }
            }
        }
        state.ledger.validate_definitions(state.grants.values())?;
        state.ledger.validate_reservations(
            state
                .channels
                .values()
                .flat_map(|c| c.book.jobs().map(|j| (j.work_id(), c.funding.grant))),
        )?;
        Ok(state)
    }
}
