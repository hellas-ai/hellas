//! The single durable writer for provider grant authority. Every exported
//! acceptance is backed by one fsynced frame covering its entire budget path.
use super::state::{Change, Frame, Snapshot, State};
use super::*;
use crate::work_store::journal::{
    Journal, JournalId, JournalKind, MAX_CHECKPOINT_BYTES, MAX_RECORD_BYTES,
};
use crate::work_store::{Applied, JobPhase, Role};
use hellas_kernel::NetworkId;
use hellas_rpc::ProviderEnrollmentBundle;
use hellas_rpc::protocol::value::{canonical_dag_cbor, decode_dag_cbor};
use hellas_rpc::protocol::work_grant::standing::*;
use hellas_rpc::protocol::work_grant::{budget::*, records::*, *};
use hellas_rpc::protocol::work_profile::{PreparedWorkInput, WorkContext, WorkPolicy};
use hellas_rpc::{Digest, ProducerSigningKey, PublicKey, Signature};
use std::path::Path;

const TERMINAL_HEADROOM: usize = 1024;
const MAX_OPEN_JOBS: usize = 256;
// Every admitted job can still require Dispatch + Terminal, plus the frame
// crossing the soft boundary. These metadata records fit the common byte tail.
const DUTY_FRAMES: u64 = 2 * MAX_OPEN_JOBS as u64 + 1;
/// Both profiles deliberately keep bodies outside this store.
pub struct GrantStore {
    journal: Journal,
    state: State,
}
impl GrantStore {
    pub fn open(
        directory: &Path,
        network: NetworkId,
        provider: ProviderEnrollmentBundle,
        now: UnixMillis,
    ) -> Result<Self, GrantStoreError> {
        provider.check_grant_provider()?;
        let key = hellas_rpc::protocol::digest::hash_tuple(
            "hellas.work.grant-journal-key.v1",
            &[network.as_bytes(), provider.content_id().as_bytes()],
        );
        let id = JournalId {
            kind: JournalKind::Grant,
            role: Role::Provider,
            key: *key.as_bytes(),
            generation: 0,
        };
        let (journal, replay) = Journal::open_latest(directory, "grants", id)?;
        let mut state = match replay.checkpoint {
            Some(bytes) => State::restore(decode::<Snapshot>(&bytes)?)?,
            None => State::empty(network, provider.clone()),
        };
        if state.network() != network || state.provider() != &provider {
            return Err(GrantStoreError::Malformed);
        }
        for bytes in replay.records {
            state.apply(&decode::<Frame>(&bytes)?)?;
        }
        let mut store = Self { journal, state };
        let now = now.max(store.state.now());
        if let Ok(owner) = Principal::verify(provider) {
            store.bind_owner(owner, now)?;
        }
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
            store.commit(
                now,
                Change::Terminal {
                    channel,
                    work,
                    outcome,
                    result: None,
                    usage: None,
                },
                false,
            )?;
        }
        store.tick(now)?;
        Ok(store)
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    /// Authenticated discovery accepts an existing stale generation without
    /// mutating grant terms, channel identity, allowance or nonce high-water.
    pub fn standing(
        &mut self,
        query: StandingQuery,
        connection: GrantConnection,
        signer: &ProducerSigningKey,
        addresses: Vec<String>,
        now: UnixMillis,
    ) -> Result<Standing, GrantStoreError> {
        let locator = query.locator;
        let def = self
            .state
            .grant(locator.grant)
            .ok_or(GrantError::Unauthorized)?;
        let principal = def.kind.principal();
        if locator.provider != self.state.provider.content_id()
            || locator.client != principal.id()
            || connection.peer != principal.transport()
            || self
                .state
                .channel(locator.channel(self.state.network))
                .is_none()
        {
            return Err(GrantError::Unauthorized.into());
        }
        hellas_rpc::signature::verify_digest_signature(
            &PublicKey::Secp256k1(principal.producer().to_bytes()),
            &query.signature,
            locator.digest(self.state.network, &connection.exporter),
        )
        .map_err(|_| GrantError::Unauthorized)?;
        self.tick(now)?;
        let def = self
            .state
            .grant(locator.grant)
            .ok_or(GrantError::Unauthorized)?;
        let offer = self.offer(locator.grant, signer, addresses)?;
        let nodes = self.allowances(locator.grant, matches!(def.kind, GrantKind::Owner(_)))?;
        Ok(Standing {
            offer,
            now: self.state.now(),
            nodes,
        })
    }
    /// Private projection for authenticated standing or local owner control.
    pub(crate) fn offer(
        &self,
        grant: GrantId,
        signer: &ProducerSigningKey,
        addresses: Vec<String>,
    ) -> Result<SignedOffer, GrantStoreError> {
        let def = self.state.grant(grant).ok_or(GrantError::Unauthorized)?;
        let generation = self
            .state
            .generation(grant)
            .ok_or(GrantError::Unauthorized)?;
        let offer = SignedOffer::sign(
            Offer {
                network: self.state.network,
                provider: self.state.provider.clone(),
                grant: def.clone(),
                generation,
                sequence: def.revision.0,
                valid_until: UnixMillis(self.state.now().0.saturating_add(300_000)),
                addresses,
            },
            signer,
        )?;
        Ok(offer)
    }
    pub(crate) fn allowances(
        &self,
        grant: GrantId,
        include_machine: bool,
    ) -> Result<Vec<NodeAllowance>, GrantStoreError> {
        let def = self.state.grant(grant).ok_or(GrantError::Unauthorized)?;
        let mut visible = vec![BudgetNode::Grant(def.id)];
        if include_machine {
            visible.push(BudgetNode::Machine);
        }
        let mut nodes = Vec::with_capacity(visible.len());
        for id in visible {
            let ledger = self.state.ledger();
            let node = ledger.node(id).ok_or(ledger::LedgerError::UnknownNode)?;
            let ancestors = match id {
                BudgetNode::Machine => vec![id],
                _ => vec![id, BudgetNode::Machine],
            };
            let active = |id| {
                ledger.active_count(id)
                    + self.state.recovery_holds(
                        match id {
                            BudgetNode::Machine => None,
                            BudgetNode::Grant(grant) => Some(grant),
                        },
                        self.state.now(),
                    )
            };
            let mut counters = Vec::with_capacity(16);
            for meter in Meter::ALL {
                for window in Window::ALL {
                    let counter = node.counter(meter, window);
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
                            ledger.remaining(*id, *limit)
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
            let concurrent_remaining = ancestors
                .iter()
                .filter_map(|id| {
                    ledger
                        .node(*id)
                        .map(|n| usize::from(n.concurrent()).saturating_sub(active(*id)))
                })
                .min()
                .unwrap_or(0) as u16;
            nodes.push(NodeAllowance {
                node: id,
                concurrent_limit: node.concurrent(),
                active: active(id) as u16,
                concurrent_remaining,
                counters,
            });
        }
        Ok(nodes)
    }
    pub fn tick(&mut self, now: UnixMillis) -> Result<(), GrantStoreError> {
        if now > self.state.now() {
            // Dispatch/Terminal already persist their own clock cursor. Queries
            // must not spend the emergency tail reserved for those obligations.
            self.commit(now, Change::Clock, true)?;
        }
        Ok(())
    }
    pub fn configure_machine(
        &mut self,
        limits: Vec<Limit>,
        concurrent: u16,
        now: UnixMillis,
    ) -> Result<(), GrantStoreError> {
        self.commit(now, Change::Machine { limits, concurrent }, true)
    }
    pub fn define(&mut self, definition: GrantDef, now: UnixMillis) -> Result<(), GrantStoreError> {
        self.commit(now, Change::Define(definition), true)
    }
    /// Bootstrap is idempotent even after revision/revocation; it cannot replace
    /// a standing owner grant or reset its counters.
    pub fn initialize_owner(
        &mut self,
        owner: Principal,
        policies: Vec<GrantPolicy>,
        max_job_millis: std::num::NonZeroU64,
        now: UnixMillis,
    ) -> Result<GrantId, GrantStoreError> {
        let id = owner_grant_id(
            self.state.network(),
            self.state.provider().content_id(),
            owner.id(),
        );
        if self.state.grant(id).is_some() {
            return Ok(id);
        }
        self.define(
            GrantDef {
                id,
                revision: Revision(1),
                kind: GrantKind::Owner(owner),
                policies,
                limits: vec![],
                weight: std::num::NonZeroU16::new(1).expect("one"),
                max_job_millis,
                max_in_flight: std::num::NonZeroU16::new(256).expect("positive"),
                expires: None,
                state: GrantState::Active,
                allow_account_backed: true,
            },
            now,
        )?;
        Ok(id)
    }
    pub fn bump_generation(
        &mut self,
        grant: GrantId,
        now: UnixMillis,
    ) -> Result<u64, GrantStoreError> {
        let generation = self
            .state
            .generation(grant)
            .and_then(|n| n.checked_add(1))
            .ok_or(GrantError::Generation)?;
        self.commit(now, Change::Generation { grant, generation }, true)?;
        Ok(generation)
    }
    /// Verifies the signed request and exact current policy before committing
    /// Accepted plus ancestor reserves. Duplicate retries return the original
    /// signature without extending deadlines or reserving again.
    pub fn accept(
        &mut self,
        a: GrantJobAuthorizationV1,
        client_signature: Signature,
        input: &PreparedWorkInput,
        signer: &ProducerSigningKey,
        now: UnixMillis,
    ) -> Result<Signature, GrantStoreError> {
        let now = now.max(self.state.now());
        if signer.public_key()
            != PublicKey::Secp256k1(self.state.provider().grant_producer()?.to_bytes())
        {
            return Err(GrantError::Signature.into());
        }
        if let Some(signature) = self.precheck_acceptance(&a, &client_signature, now)? {
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
            client: def.kind.principal().producer(),
            provider: self.state.provider().grant_producer()?,
        };
        hellas_rpc::signature::verify_digest_signature(
            &PublicKey::Secp256k1(context.client.to_bytes()),
            &client_signature,
            id,
        )
        .map_err(|_| GrantError::Signature)?;
        let policy = def
            .policies
            .iter()
            .find(|p| p.work.digest(context.network, context.channel) == a.work_policy_digest)
            .ok_or(GrantError::OutOfScope)?;
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
                if let Some(resource) = &policy.https {
                    let parts = bundle.parts().map_err(|_| GrantError::Malformed)?;
                    let input =
                        hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript)
                            .map_err(|_| GrantError::Malformed)?;
                    let request =
                        hellas_rpc::http_fetch::HttpFetchRequest::decode(input.body.as_bytes())
                            .map_err(|_| GrantError::Malformed)?;
                    charge.set(Meter::OutputTokens, resource.matches(&request)?);
                }
            }
            _ => return Err(GrantError::OutOfScope.into()),
        }
        let provider_signature = signer.sign_digest(id).map_err(|_| GrantError::Signature)?;
        self.commit(
            now,
            Change::Accepted {
                authorization: a,
                client_signature,
                provider_signature,
                charge,
            },
            true,
        )?;
        Ok(provider_signature)
    }
    /// Probe an uncertain proposal without its body. Authenticate first; known
    /// work returns its original co-signature before current admission checks.
    /// An unknown expired proposal is conclusively refused before input decode.
    pub fn precheck_acceptance(
        &mut self,
        a: &GrantJobAuthorizationV1,
        client_signature: &Signature,
        now: UnixMillis,
    ) -> Result<Option<Signature>, GrantStoreError> {
        let id = grant_work_id(self.state.network(), a);
        let channel = self
            .state
            .channel(a.channel_id)
            .ok_or(GrantError::Unauthorized)?;
        if channel.funding.grant != a.grant_id {
            return Err(GrantError::Unauthorized.into());
        }
        hellas_rpc::signature::verify_digest_signature(
            &PublicKey::Secp256k1(channel.funding.client.producer().to_bytes()),
            client_signature,
            id,
        )
        .map_err(|_| GrantError::Signature)?;
        if let Some(job) = channel.job_book().job_by_id(id) {
            if job.authorization() == a && job.client_signature() == *client_signature {
                return Ok(Some(
                    job.provider_signature().ok_or(GrantStoreError::Malformed)?,
                ));
            }
            return Err(GrantError::Signature.into());
        }
        if let Some(t) = channel.job_book().terminal_by_id(id) {
            if t.outcome.authorization == *a && t.outcome.client_signature == *client_signature {
                return Ok(Some(t.outcome.provider_signature));
            }
            return Err(GrantError::Signature.into());
        }
        let now = now.max(self.state.now());
        self.tick(now)?;
        self.state.check_authority(a, now)?;
        Ok(None)
    }
    pub fn dispatch(
        &mut self,
        channel: ChannelId,
        work: Digest,
        now: UnixMillis,
    ) -> Result<(), GrantStoreError> {
        self.commit(now, Change::Dispatched { channel, work }, false)
    }
    pub fn finish(
        &mut self,
        channel: ChannelId,
        work: Digest,
        outcome: GrantOutcome,
        result: Option<SignedResult>,
        usage: Usage,
        now: UnixMillis,
    ) -> Result<(), GrantStoreError> {
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
    }
    pub fn release(
        &mut self,
        channel: ChannelId,
        work: Digest,
        now: UnixMillis,
    ) -> Result<(), GrantStoreError> {
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
    }
    /// Local administration must explicitly authorize this repair operation.
    pub fn repair_resource(&mut self, id: Digest, now: UnixMillis) -> Result<(), GrantStoreError> {
        self.commit(now, Change::RepairResource(id), true)
    }
    pub fn rotate(&mut self) -> Result<(), GrantStoreError> {
        self.journal.rotate(&encode(&self.state.snapshot())?)?;
        Ok(())
    }
    pub(super) fn commit(
        &mut self,
        now: UnixMillis,
        change: Change,
        new_obligation: bool,
    ) -> Result<(), GrantStoreError> {
        let frame = Frame {
            namespace: "hellas.work.grant-journal.v1".into(),
            now: now.max(self.state.now()),
            change,
        };
        let mut candidate = self.state.clone();
        if candidate.apply(&frame)? == Applied::Redundant {
            return Ok(());
        }
        // Terminal pruning is reproducible from the frame cursor. Nonce high
        // water and old generations remain, so pruning cannot permit replay.
        candidate.prune();
        let checkpoint = encode(&candidate.snapshot())?;
        let open = candidate
            .channels
            .values()
            .map(|c| c.book.jobs().len())
            .sum::<usize>();
        if open > MAX_OPEN_JOBS
            || checkpoint
                .len()
                .saturating_add(open.saturating_mul(TERMINAL_HEADROOM))
                > MAX_CHECKPOINT_BYTES
        {
            return Err(GrantError::StateCapacity.into());
        }
        if self.journal.at_soft_limit_with_frames(DUTY_FRAMES) {
            let result = self.rotate();
            if new_obligation {
                result?;
            }
            // A duty may use the reserved tail if rotation fails. Append errors
            // still poison the journal, and no candidate is published then.
        }
        self.journal.append(&encode(&frame)?)?;
        self.state = candidate;
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
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, GrantStoreError> {
    let bytes = canonical_dag_cbor(value).map_err(|_| GrantStoreError::Malformed)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(GrantError::StateCapacity.into());
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, GrantStoreError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(GrantStoreError::Malformed);
    }
    let value: T = decode_dag_cbor(bytes).map_err(|_| GrantStoreError::Malformed)?;
    if encode(&value)? != bytes {
        return Err(GrantStoreError::Malformed);
    }
    Ok(value)
}
