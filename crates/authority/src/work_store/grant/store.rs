//! Node authority and Work accounting share one durable writer. Every exported
//! acceptance is backed by one fsynced frame covering its entire budget path.
use super::state::{Change, Frame, Snapshot, State};
use super::{
    ChannelId, GrantId, GrantJobAuthorizationV1, GrantOutcome, NodeStoreError, Serialize,
    SignedResult, ledger,
};
use crate::model::grant::records::grant_producer;
use crate::model::grant::standing::{CounterAllowance, NodeAllowance, Standing, StandingLocator};
use crate::model::grant::{
    budget::{BudgetNode, Charge, Meter, Usage, Window},
    grant_work_id,
    records::{GrantError, Offer, SignedOffer},
};
use crate::model::profile::{PreparedWorkInput, WorkContext, WorkPolicy};
use crate::work_store::journal::{
    Journal, JournalId, JournalKind, MAX_CHECKPOINT_BYTES, MAX_RECORD_BYTES,
};
use crate::work_store::{Applied, JobPhase, Role};
use hellas_auth::authority::{Revision, UnixMillis};
use hellas_auth::{Digest, ProducerSigningKey, PublicKey, Signature};
use hellas_kernel::NetworkId;
use hellas_rpc::ProviderEnrollmentBundle;
use hellas_rpc::protocol::value::{decode_canonical_bounded, encode_bounded};
use std::path::Path;
mod bootstrap;
pub use bootstrap::{OwnerApproval, PreparedBootstrap};
#[cfg(test)]
mod tests;

// Includes a maximum-depth dispatch audit record and terminal/accounting growth.
pub(super) const TERMINAL_HEADROOM: usize = 5120;
pub(crate) const MAX_OPEN_JOBS: usize = ledger::MAX_CONCURRENT as usize;
// Every admitted job can still require Dispatch + Terminal, plus the frame
// crossing the soft boundary. These metadata records fit the common byte tail.
const DUTY_FRAMES: u64 = 2 * MAX_OPEN_JOBS as u64 + 1;
/// Both profiles deliberately keep bodies outside this store.
pub struct NodeStore {
    clock: super::clock::ClockBound,
    _identity_lock: bootstrap::IdentityLock,
    journal: Journal,
    pub(super) state: State,
    pub(super) executions: std::collections::BTreeMap<Digest, super::execution::ActiveExecution>,
    pub(super) deliveries: Vec<std::sync::Weak<crate::grant_service::Delivery>>,
}
impl NodeStore {
    pub async fn open(
        directory: &Path,
        network: NetworkId,
        provider: Option<ProviderEnrollmentBundle>,
        now: UnixMillis,
    ) -> Result<Self, NodeStoreError> {
        let mut store = Self::open_initialized(directory, network).await?;
        if provider
            .as_ref()
            .is_some_and(|expected| store.state.provider.as_ref() != Some(expected))
        {
            return Err(GrantError::Audience.into());
        }
        let now = now.max(store.state.now());
        // Never rerun after opening. This also makes reopening idempotent if a
        // process crashed while recording recovery itself.
        let pending: Vec<_> = store
            .state
            .channels
            .iter()
            .flat_map(|(id, c)| {
                c.book
                    .jobs()
                    .map(|j| (ChannelId(*id), j.work_id(), j.phase()))
            })
            .collect();
        for (channel, work, phase) in pending {
            let outcome = if phase == JobPhase::Accepted {
                GrantOutcome::Released
            } else {
                GrantOutcome::Indeterminate
            };
            store
                .commit(
                    now,
                    Change::Terminal {
                        channel,
                        work,
                        outcome,
                        result: None,
                        usage: None,
                    },
                    false,
                )
                .await?;
        }
        store.tick(now).await?;
        Ok(store)
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub(crate) fn time(&self, now: UnixMillis) -> Result<UnixMillis, NodeStoreError> {
        let now = now.max(self.state.now());
        self.clock.check(now)?;
        Ok(now)
    }
    pub(crate) fn check_authority(&self) -> Result<(), NodeStoreError> {
        self.journal.check_authority()?;
        Ok(())
    }
    pub(crate) async fn administer_authority(
        &mut self,
        caller: &hellas_auth::authority::AuthenticatedCaller,
        command: hellas_auth::authority::AdministrationCommand,
        now: UnixMillis,
    ) -> Result<hellas_auth::authority::AdministrationRecord, NodeStoreError> {
        self.check_authority()?;
        let record = self
            .state
            .authority
            .record_administration(caller, command, now)?;
        self.commit(now, Change::Authority(record.clone()), true)
            .await?;
        Ok(record)
    }
    /// Authenticated discovery accepts an existing stale generation without
    /// mutating grant terms, channel identity, allowance or nonce high-water.
    pub(crate) fn standing(
        &self,
        locator: StandingLocator,
        signer: &ProducerSigningKey,
        addresses: Vec<String>,
        now: UnixMillis,
    ) -> Result<Standing, NodeStoreError> {
        if locator.provider != self.state.provider()?.content_id()
            || self
                .state
                .generation(locator.grant)
                .is_none_or(|g| locator.generation > g)
        {
            return Err(GrantError::Unauthorized.into());
        }
        let now = self.time(now)?;
        let offer = self.offer(locator.grant, signer, addresses, now)?;
        let nodes = self.allowances(locator.grant, false, now)?;
        Ok(Standing { offer, now, nodes })
    }
    /// Private projection for authenticated standing or checked Work administration.
    pub(crate) fn offer(
        &self,
        grant: GrantId,
        signer: &ProducerSigningKey,
        addresses: Vec<String>,
        now: UnixMillis,
    ) -> Result<SignedOffer, NodeStoreError> {
        let def = self.state.grant(grant).ok_or(GrantError::Unauthorized)?;
        let generation = self
            .state
            .generation(grant)
            .ok_or(GrantError::Unauthorized)?;
        let offer = SignedOffer::sign(
            Offer {
                network: self.state.network,
                provider: self.state.provider()?.clone(),
                grant: def.clone(),
                generation,
                sequence: def.revision.0,
                valid_until: UnixMillis(now.max(self.state.now()).0.saturating_add(300_000)),
                addresses,
            },
            signer,
        )?;
        Ok(offer)
    }
    pub(crate) fn allowances(
        &self,
        grant: GrantId,
        include_ancestors: bool,
        now: UnixMillis,
    ) -> Result<Vec<NodeAllowance>, NodeStoreError> {
        let def = self.state.grant(grant).ok_or(GrantError::Unauthorized)?;
        let visible = if include_ancestors {
            self.state.ledger().path(def.budget)?
        } else {
            vec![def.budget]
        };
        visible
            .into_iter()
            .map(|id| self.allowance(id, now))
            .collect()
    }
    pub(crate) fn allowance(
        &self,
        id: BudgetNode,
        now: UnixMillis,
    ) -> Result<NodeAllowance, NodeStoreError> {
        let now = now.max(self.state.now());
        let ledger = self.state.ledger();
        let node = ledger.node(id).ok_or(ledger::LedgerError::UnknownNode)?;
        let ancestors = ledger.path(id)?;
        let mut concurrent_remaining = node.concurrent();
        for ancestor in &ancestors {
            let capacity = ledger
                .node(*ancestor)
                .ok_or(ledger::LedgerError::UnknownNode)?
                .concurrent();
            let active =
                ledger.active_count(*ancestor) + self.state.recovery_holds(*ancestor, now)?;
            concurrent_remaining =
                concurrent_remaining.min(usize::from(capacity).saturating_sub(active) as u16);
        }
        let mut counters = Vec::with_capacity(Meter::ALL.len() * Window::ALL.len());
        for meter in Meter::ALL {
            for window in Window::ALL {
                let counter = node.counter_at(meter, window, now);
                let limit = node
                    .limits()
                    .iter()
                    .find(|l| l.meter == meter && l.window == window)
                    .map(|l| l.amount);
                let remaining = ancestors
                    .iter()
                    .filter_map(|id| {
                        let limit = ledger
                            .node(*id)?
                            .limits()
                            .iter()
                            .find(|l| l.meter == meter && l.window == window)?;
                        ledger.remaining_at(*id, *limit, now)
                    })
                    .min();
                counters.push(CounterAllowance {
                    meter,
                    window,
                    window_id: counter.window_id,
                    used: counter.used,
                    reserved: ledger.reserved(id, meter),
                    limit,
                    remaining,
                });
            }
        }
        Ok(NodeAllowance {
            node: id,
            concurrent_limit: node.concurrent(),
            active: (ledger.active_count(id) + self.state.recovery_holds(id, now)?) as u16,
            concurrent_remaining,
            counters,
        })
    }
    pub(crate) async fn tick(&mut self, now: UnixMillis) -> Result<(), NodeStoreError> {
        if now > self.state.now() {
            // Startup and admission clock writes must not spend the emergency
            // tail reserved for dispatch and terminal obligations.
            self.commit(now, Change::Clock, true).await?;
        }
        Ok(())
    }
    /// Verifies the signed request and exact current policy before committing
    /// Accepted plus ancestor reserves. Duplicate retries return the original
    /// signature without extending deadlines or reserving again.
    pub(crate) async fn accept(
        &mut self,
        application: (&hellas_auth::authority::AuthenticatedCaller, GrantId),
        a: GrantJobAuthorizationV1,
        client_signature: Signature,
        input: &PreparedWorkInput,
        signer: &ProducerSigningKey,
        now: UnixMillis,
    ) -> Result<Signature, NodeStoreError> {
        let now = now.max(self.state.now());
        self.check_authority()?;
        let execution = super::ExecutionRecord::capture(&self.state, application, a.grant_id, now)?;
        if signer.public_key()
            != PublicKey::Secp256k1(grant_producer(self.state.provider()?)?.to_bytes())
        {
            return Err(GrantError::Signature.into());
        }
        let client = crate::model::grant::ChannelClient::recorded(execution.caller())?;
        if let Some(signature) = self
            .precheck_acceptance(&a, client, &client_signature, now)
            .await?
        {
            return Ok(signature);
        }
        let id = grant_work_id(self.state.network(), &a);
        let def = self
            .state
            .grant(a.grant_id)
            .ok_or(GrantError::Unauthorized)?;
        let context = WorkContext {
            network: self.state.network(),
            channel: a.channel_id.0,
            client: client.signer(),
            provider: grant_producer(self.state.provider()?)?,
        };
        let policy = self.state.policy_for(&a)?;
        policy
            .work
            .check_bound_input(&context, &(&a).into(), input)?;
        let mut charge = Charge::default();
        charge.set(Meter::Requests, 1);
        match (&policy.work, input) {
            (WorkPolicy::Evaluate(_), PreparedWorkInput::Evaluate(bundle)) => {
                let parts = bundle.parts().map_err(|_| GrantError::Malformed)?;
                charge.set(
                    Meter::InputTokens,
                    parts.prompt_tokens.as_slice().len() as u64,
                );
                charge.set(
                    Meter::OutputTokens,
                    u64::from(parts.text_policy.max_new_tokens()),
                );
                charge.set(Meter::DeviceMillis, def.max_job_millis.get());
            }
            (WorkPolicy::Fetch { .. }, PreparedWorkInput::Fetch(bundle)) => {
                let parts = bundle.parts().map_err(|_| GrantError::Malformed)?;
                let input = hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript)
                    .map_err(|_| GrantError::Malformed)?;
                if let Some(resource) = &policy.responses {
                    charge.set(
                        Meter::OutputTokens,
                        resource.matches(input.body.as_bytes())?,
                    );
                }
                if let Some(resource) = &policy.https {
                    let request =
                        hellas_rpc::http_fetch::HttpFetchRequest::decode(input.body.as_bytes())
                            .map_err(|_| GrantError::Malformed)?;
                    charge.set(Meter::OutputTokens, resource.matches(&request)?);
                }
            }
            _ => return Err(GrantError::OutOfScope.into()),
        }
        let charge = policy
            .pricing
            .reserve(charge)
            .map_err(|_| GrantError::Limits)?;
        let provider_signature = signer.sign_digest(id).map_err(|_| GrantError::Signature)?;
        self.commit(
            now,
            Change::Accepted {
                authorization: a,
                client_signature,
                provider_signature,
                charge,
                execution,
            },
            true,
        )
        .await?;
        Ok(provider_signature)
    }
    /// Probe an uncertain proposal without its body. Authenticate first; known
    /// work returns its original co-signature before current admission checks.
    /// An unknown expired proposal is conclusively refused before input decode.
    /// `client` is the channel's principal and the node key its credential binds.
    pub(crate) async fn precheck_acceptance(
        &mut self,
        a: &GrantJobAuthorizationV1,
        client: crate::model::grant::ChannelClient,
        client_signature: &Signature,
        now: UnixMillis,
    ) -> Result<Option<Signature>, NodeStoreError> {
        let id = grant_work_id(self.state.network(), a);
        self.state.check_channel(a, client)?;
        hellas_auth::signature::verify_digest_signature(
            &client.node.public_key(),
            client_signature,
            id,
        )
        .map_err(|_| GrantError::Signature)?;
        if let Some(channel) = self.state.channel(a.channel_id) {
            if let Some(job) = channel.job_book().job_by_id(id) {
                if job.authorization() == a && job.client_signature() == *client_signature {
                    return Ok(Some(
                        job.provider_signature().ok_or(NodeStoreError::Malformed)?,
                    ));
                }
                return Err(GrantError::Signature.into());
            }
            if let Some(t) = channel.job_book().terminal_by_id(id) {
                if t.outcome.authorization == *a && t.outcome.client_signature == *client_signature
                {
                    return Ok(Some(t.outcome.provider_signature));
                }
                return Err(GrantError::Signature.into());
            }
        }
        let now = now.max(self.state.now());
        self.tick(now).await?;
        self.state.check_terms(a, client, now)?;
        Ok(None)
    }
    pub(crate) async fn dispatch(
        &mut self,
        application: (&hellas_auth::authority::AuthenticatedCaller, GrantId),
        channel: ChannelId,
        work: Digest,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.check_authority()?;
        let now = now.max(self.state.now());
        let allowance = self
            .state
            .channel_binding(channel)
            .ok_or(GrantError::Unauthorized)?
            .grant;
        let execution = super::ExecutionRecord::capture(&self.state, application, allowance, now)?;
        let admission = self
            .state
            .admission(channel, work)
            .ok_or(NodeStoreError::Malformed)?;
        if !admission.accepted.same_application(&execution) {
            return Err(GrantError::Unauthorized.into());
        }
        if admission.dispatched.is_some() {
            return Ok(());
        }
        self.commit(
            now,
            Change::Dispatched {
                channel,
                work,
                execution,
            },
            false,
        )
        .await
    }
    pub(crate) async fn finish(
        &mut self,
        channel: ChannelId,
        work: Digest,
        outcome: GrantOutcome,
        result: Option<SignedResult>,
        usage: Usage,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.commit(
            now,
            Change::Terminal {
                channel,
                work,
                outcome,
                result,
                usage: match usage {
                    Usage::Unknown => None,
                    Usage::Observed(c) => Some(c),
                },
            },
            false,
        )
        .await
    }
    pub(crate) async fn release(
        &mut self,
        channel: ChannelId,
        work: Digest,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.commit(
            now,
            Change::Terminal {
                channel,
                work,
                outcome: GrantOutcome::Released,
                result: None,
                usage: None,
            },
            false,
        )
        .await
    }
    pub(crate) async fn rotate(&mut self) -> Result<(), NodeStoreError> {
        let mut cancellation = self.cancel_on_failure();
        self.journal
            .rotate(&encode(&self.state.snapshot()?)?)
            .await?;
        cancellation.0.clear();
        Ok(())
    }
    pub(super) async fn commit(
        &mut self,
        now: UnixMillis,
        change: Change,
        new_obligation: bool,
    ) -> Result<(), NodeStoreError> {
        self.commit_changes(now, vec![change], new_obligation).await
    }
    pub(super) async fn commit_changes(
        &mut self,
        now: UnixMillis,
        changes: Vec<Change>,
        new_obligation: bool,
    ) -> Result<(), NodeStoreError> {
        let now = self.time(now)?;
        let frame = Frame {
            namespace: "hellas.node.journal.v2".into(),
            now,
            changes,
        };
        let mut candidate = self.state.clone();
        if candidate.apply(&frame)? == Applied::Redundant {
            return Ok(());
        }
        // Terminal pruning is reproducible from the frame cursor. Nonce high
        // water and old generations remain, so pruning cannot permit replay.
        candidate.prune();
        let checkpoint = encode(&candidate.snapshot()?)?;
        let open = candidate
            .channels
            .values()
            .map(|c| c.book.jobs().len())
            .sum::<usize>();
        if open > MAX_OPEN_JOBS
            || checkpoint
                .len()
                .saturating_add(candidate.ledger.clock_headroom())
                .saturating_add(open.saturating_mul(TERMINAL_HEADROOM))
                > MAX_CHECKPOINT_BYTES
        {
            return Err(GrantError::StateCapacity.into());
        }
        // Observe elapsed deadlines against the old state before an extension
        // can make it current again. A new grant cannot revive an old response
        // or execution whose authority already expired.
        self.refresh_executions(frame.now);
        self.refresh_deliveries(frame.now);
        let mut cancellation = self.cancel_on_failure();
        if self.journal.at_soft_limit_with_frames(DUTY_FRAMES) {
            let result = self.rotate().await;
            if new_obligation {
                result?;
            }
            // A rotation refused before writing leaves the reserved tail usable.
            // A failed write poisons the journal, so append still refuses that case.
        }
        self.journal.append(&encode(&frame)?).await?;
        self.state = candidate;
        self.refresh_executions(frame.now);
        self.refresh_deliveries(frame.now);
        cancellation.0.clear();
        Ok(())
    }
}
impl State {
    pub(super) fn prune(&mut self) {
        let now = self.now();
        for c in self.channels.values_mut() {
            c.book
                .terminals
                .retain(|_, t| t.outcome.authorization.delivery_deadline_ms >= now);
        }
        let retained: std::collections::BTreeSet<_> = self
            .channels
            .values()
            .flat_map(|c| {
                c.book
                    .jobs()
                    .map(|j| j.work_id())
                    .chain(c.book.terminals().map(|t| t.work_id))
            })
            .collect();
        self.admissions.retain(|id, _| retained.contains(id));
        let live: std::collections::BTreeSet<_> = self
            .channels
            .values()
            .flat_map(|c| {
                c.book
                    .jobs()
                    .map(|j| (j.authorization().grant_id, j.authorization().grant_revision))
                    .chain(c.book.terminals().map(|t| {
                        (
                            t.outcome.authorization.grant_id,
                            t.outcome.authorization.grant_revision,
                        )
                    }))
            })
            .collect();
        self.history.retain(|key, _| live.contains(key));
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeStoreError> {
    encode_bounded(value, MAX_RECORD_BYTES).map_err(Into::into)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, NodeStoreError> {
    decode_canonical_bounded(bytes, MAX_RECORD_BYTES).map_err(Into::into)
}
