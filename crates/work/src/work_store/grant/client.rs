//! One proposal writer per grant channel. Bodies are never journaled; an
//! uncertain acceptance survives restart and cannot be replaced by a new nonce.
use super::*;
use crate::work_store::channel::funding::GrantFunding;
use crate::work_store::journal::{Journal, JournalId, JournalKind, MAX_CHECKPOINT_BYTES};
use crate::work_store::{Applied, JobBook, JobPhase, JobState, Role};
use hellas_kernel::NetworkId;
use hellas_rpc::ProviderEnrollmentBundle;
use hellas_rpc::protocol::value::{canonical_dag_cbor, decode_dag_cbor};
use hellas_rpc::protocol::work::bound_result_digest;
use hellas_rpc::protocol::work_grant::{records::*, *};
use hellas_rpc::protocol::work_profile::{PreparedWorkInput, WorkContext, WorkPolicy};
use hellas_rpc::{Digest, OutputEventEnvelope, ProducerSigningKey, PublicKey};
use std::path::Path;

const NAMESPACE: &str = "hellas.work.grant-client.v1";
const MAX_JOBS: usize = 256;

pub struct GrantClientStore {
    journal: Journal,
    context: WorkContext,
    channel: GrantChannelState,
    provider: ProviderEnrollmentBundle,
    state: ClientState,
}
#[derive(Clone, Debug, Default)]
struct ClientState {
    book: JobBook<GrantFunding>,
    now: UnixMillis,
}
#[derive(Serialize, Deserialize)]
struct Frame {
    namespace: String,
    now: UnixMillis,
    change: Change,
}
#[derive(Serialize, Deserialize)]
enum Change {
    Proposed {
        #[serde(with = "super::codec::record")]
        authorization: GrantJobAuthorizationV1,
        signature: Signature,
    },
    Exchange {
        work: Digest,
        pending: bool,
    },
    Accepted {
        work: Digest,
        signature: Signature,
    },
    Result {
        work: Digest,
        signed: SignedResult,
    },
    Clock,
}
#[derive(Serialize, Deserialize)]
struct Snapshot {
    namespace: String,
    now: UnixMillis,
    nonce: u64,
    pending: Option<Digest>,
    jobs: Vec<StoredJob>,
}
#[derive(Serialize, Deserialize)]
struct StoredJob {
    #[serde(with = "super::codec::record")]
    authorization: GrantJobAuthorizationV1,
    client_signature: Signature,
    provider_signature: Option<Signature>,
    result: Option<SignedResult>,
}
impl GrantClientStore {
    pub fn open(
        directory: &Path,
        network: NetworkId,
        provider: ProviderEnrollmentBundle,
        channel: GrantChannelState,
        now: UnixMillis,
    ) -> Result<Self, GrantStoreError> {
        provider.check_grant_provider()?;
        if channel.id
            != grant_channel_id(
                network,
                provider.content_id(),
                channel.grant,
                channel.client.id(),
                channel.generation,
            )
        {
            return Err(GrantError::Generation.into());
        }
        let context = WorkContext {
            network,
            channel: channel.id.0,
            client: channel.client.producer(),
            provider: provider.grant_producer()?,
        };
        let id = JournalId {
            kind: JournalKind::Grant,
            role: Role::Client,
            key: *channel.id.0.as_bytes(),
            generation: 0,
        };
        let (journal, replay) = Journal::open_latest(directory, "grant-client", id)?;
        let mut store = Self {
            journal,
            context,
            channel,
            provider,
            state: ClientState::default(),
        };
        if let Some(bytes) = replay.checkpoint {
            let snapshot: Snapshot = decode(&bytes)?;
            store.state = store.restore(snapshot)?;
        }
        for bytes in replay.records {
            let frame: Frame = decode(&bytes)?;
            let mut candidate = store.state.clone();
            store.apply(&mut candidate, &frame)?;
            store.state = candidate;
        }
        store.tick(now)?;
        Ok(store)
    }
    pub fn context(&self) -> WorkContext {
        self.context
    }
    pub fn channel(&self) -> &GrantChannelState {
        &self.channel
    }
    pub fn book(&self) -> &JobBook<GrantFunding> {
        &self.state.book
    }
    pub fn now(&self) -> UnixMillis {
        self.state.now
    }
    pub fn next_nonce(&self) -> Result<u64, GrantStoreError> {
        if self.book().pending_proposal().is_some() {
            return Err(crate::work_store::ChannelStateError::Conflict {
                what: "unanswered proposal",
            }
            .into());
        }
        self.book()
            .proposal_nonce_high_water()
            .checked_add(1)
            .ok_or_else(|| GrantError::StateCapacity.into())
    }
    /// Validates the current private Offer and the exact input before the
    /// signature becomes durable. Retrying uses `resume`, never this method.
    pub fn propose(
        &mut self,
        offer: &SignedOffer,
        authorization: GrantJobAuthorizationV1,
        input: &PreparedWorkInput,
        signer: &ProducerSigningKey,
        now: UnixMillis,
    ) -> Result<Signature, GrantStoreError> {
        let now = now.max(self.now());
        let verified = SignedOffer::decode(&offer.encode()?, self.channel.client.id(), now)?;
        let offer = verified.offer();
        let a = &authorization;
        if offer.network != self.context.network
            || offer.provider != self.provider
            || offer.channel() != self.channel.id
            || offer.grant.id != a.grant_id
            || offer.grant.revision != a.grant_revision
        {
            return Err(GrantError::Audience.into());
        }
        offer.grant.admits(now)?;
        if now > a.acceptance_deadline_ms
            || a.terminal_deadline_ms.0.saturating_sub(now.0) > offer.grant.max_job_millis.get()
        {
            return Err(GrantError::Expired.into());
        }
        if a.proposal_nonce != self.next_nonce()? {
            return Err(GrantError::Malformed.into());
        }
        let policy = offer
            .grant
            .policies
            .iter()
            .find(|p| {
                p.work.digest(self.context.network, self.context.channel) == a.work_policy_digest
            })
            .ok_or(GrantError::OutOfScope)?;
        policy
            .work
            .check_bound_input(&self.context, &a.into(), input)?;
        if let (Some(resource), PreparedWorkInput::Fetch(bundle)) = (&policy.https, input) {
            let parts = bundle.parts().map_err(|_| GrantError::Malformed)?;
            let input = hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript)
                .map_err(|_| GrantError::Malformed)?;
            let request = hellas_rpc::http_fetch::HttpFetchRequest::decode(input.body.as_bytes())
                .map_err(|_| GrantError::Malformed)?;
            resource.matches(&request)?;
        }
        if signer.public_key() != PublicKey::Secp256k1(self.context.client.to_bytes()) {
            return Err(GrantError::Signature.into());
        }
        let signature = signer
            .sign_digest(grant_work_id(self.context.network, a))
            .map_err(|_| GrantError::Signature)?;
        self.commit(
            now,
            Change::Proposed {
                authorization,
                signature,
            },
            true,
        )?;
        Ok(signature)
    }
    /// An uncertain response remains pending, including after restart. A body
    /// lost at restart can only be probed after the signed acceptance deadline;
    /// the provider then returns its old co-signature or a conclusive refusal.
    pub fn resume(&mut self, work: Digest, now: UnixMillis) -> Result<(), GrantStoreError> {
        self.commit(
            now,
            Change::Exchange {
                work,
                pending: true,
            },
            true,
        )
    }
    /// Call only for a decoded, authenticated refusal. A timeout or transport
    /// error is not a refusal and must leave the pending proposal intact.
    pub fn refused(&mut self, work: Digest, now: UnixMillis) -> Result<(), GrantStoreError> {
        self.commit(
            now,
            Change::Exchange {
                work,
                pending: false,
            },
            false,
        )
    }
    pub fn accepted(
        &mut self,
        work: Digest,
        signature: Signature,
        now: UnixMillis,
    ) -> Result<(), GrantStoreError> {
        self.commit(now, Change::Accepted { work, signature }, false)
    }
    /// Verifies the signed transcript live, then persists only its bound result.
    pub fn complete(
        &mut self,
        work: Digest,
        policy: &WorkPolicy,
        input: &PreparedWorkInput,
        events: &[OutputEventEnvelope],
        signed: SignedResult,
        now: UnixMillis,
    ) -> Result<(), GrantStoreError> {
        let job = self
            .book()
            .job_by_id(work)
            .ok_or(GrantError::Unauthorized)?;
        let a = job.authorization();
        if policy.digest(self.context.network, self.context.channel) != a.work_policy_digest
            || policy.bound_terminal_result(&self.context, work, &a.into(), input, events)?
                != signed.result
        {
            return Err(GrantError::OutOfScope.into());
        }
        self.commit(now, Change::Result { work, signed }, false)
    }
    pub fn tick(&mut self, now: UnixMillis) -> Result<(), GrantStoreError> {
        if now > self.now() {
            self.commit(now, Change::Clock, false)?;
        }
        Ok(())
    }
    pub fn rotate(&mut self) -> Result<(), GrantStoreError> {
        self.journal.rotate(&encode(&self.snapshot(&self.state))?)?;
        Ok(())
    }
    fn check_job(
        &self,
        a: &GrantJobAuthorizationV1,
        signature: &Signature,
    ) -> Result<Digest, GrantStoreError> {
        if a.channel_id != self.channel.id
            || a.grant_id != self.channel.grant
            || a.grant_revision.0 == 0
            || a.catalogue_revision != Revision(0)
            || a.proposal_nonce == 0
            || a.acceptance_deadline_ms >= a.terminal_deadline_ms
            || a.terminal_deadline_ms >= a.delivery_deadline_ms
            || a.delivery_deadline_ms.0 - a.terminal_deadline_ms.0 > 300_000
        {
            return Err(GrantError::Malformed.into());
        }
        let id = grant_work_id(self.context.network, a);
        verify(self.context.client, signature, id)?;
        Ok(id)
    }
    fn apply(&self, state: &mut ClientState, frame: &Frame) -> Result<Applied, GrantStoreError> {
        if frame.namespace != NAMESPACE || frame.now < state.now {
            return Err(GrantStoreError::Malformed);
        }
        state.now = frame.now;
        let changed = match &frame.change {
            Change::Proposed {
                authorization: a,
                signature,
            } => {
                let id = self.check_job(a, signature)?;
                if frame.now > a.acceptance_deadline_ms {
                    return Err(GrantError::Expired.into());
                }
                state.book.propose(
                    JobState {
                        authorization: *a,
                        work_id: id,
                        prepared_input: vec![],
                        client_signature: *signature,
                        provider_signature: None,
                        phase: JobPhase::HalfSigned,
                        result: None,
                        transcript: vec![],
                    },
                    Role::Client,
                )?
            }
            Change::Exchange { work, pending } => state.book.proposal_exchange(*work, *pending)?,
            Change::Accepted { work, signature } => {
                verify(self.context.provider, signature, *work)?;
                state
                    .book
                    .accept(*work, *signature, frame.now, Role::Client)?
            }
            Change::Result { work, signed } => {
                if signed.result.work_id != *work {
                    return Err(GrantError::Malformed.into());
                }
                verify(
                    self.context.provider,
                    &signed.signature,
                    bound_result_digest(self.context.network, self.context.channel, &signed.result),
                )?;
                if let Some(old) = state.book.job_by_id(*work).and_then(|j| j.result()) {
                    if old != &(signed.result, signed.signature) {
                        return Err(GrantError::Signature.into());
                    }
                    Applied::Redundant
                } else {
                    state
                        .book
                        .record_result(*work, signed.result, signed.signature, vec![])?
                }
            }
            Change::Clock => Applied::Changed,
        };
        let pending = state.book.pending_proposal();
        state.book.jobs.retain(|id, j| {
            Some(*id) == pending || j.authorization.delivery_deadline_ms >= state.now
        });
        Ok(changed)
    }
    fn commit(
        &mut self,
        now: UnixMillis,
        change: Change,
        new: bool,
    ) -> Result<(), GrantStoreError> {
        let frame = Frame {
            namespace: NAMESPACE.into(),
            now: now.max(self.now()),
            change,
        };
        let mut candidate = self.state.clone();
        self.apply(&mut candidate, &frame)?;
        // Reserve enough space for a provider signature and result for each
        // exported proposal before admitting it, including unanswered ones.
        if candidate.book.jobs().len() > MAX_JOBS
            || encode(&self.snapshot(&candidate))?
                .len()
                .saturating_add(candidate.book.jobs().len() * 512)
                > MAX_CHECKPOINT_BYTES
        {
            return Err(GrantError::StateCapacity.into());
        }
        if self.journal.at_soft_limit() {
            let rotated = self.rotate();
            if new {
                rotated?;
            }
        }
        self.journal.append(&encode(&frame)?)?;
        self.state = candidate;
        Ok(())
    }
    fn snapshot(&self, state: &ClientState) -> Snapshot {
        Snapshot {
            namespace: NAMESPACE.into(),
            now: state.now,
            nonce: state.book.proposal_nonce_high_water(),
            pending: state.book.pending_proposal(),
            jobs: state
                .book
                .jobs()
                .map(|j| StoredJob {
                    authorization: *j.authorization(),
                    client_signature: j.client_signature(),
                    provider_signature: j.provider_signature(),
                    result: j.result().map(|(result, signature)| SignedResult {
                        result: *result,
                        signature: *signature,
                    }),
                })
                .collect(),
        }
    }
    fn restore(&self, snapshot: Snapshot) -> Result<ClientState, GrantStoreError> {
        if snapshot.namespace != NAMESPACE || snapshot.jobs.len() > MAX_JOBS {
            return Err(GrantStoreError::Malformed);
        }
        let mut state = ClientState {
            now: snapshot.now,
            ..Default::default()
        };
        let mut nonces = std::collections::BTreeSet::new();
        for j in snapshot.jobs {
            let id = self.check_job(&j.authorization, &j.client_signature)?;
            if j.authorization.proposal_nonce > snapshot.nonce
                || !nonces.insert(j.authorization.proposal_nonce)
                || state.book.jobs.contains_key(&id)
            {
                return Err(GrantStoreError::Malformed);
            }
            if let Some(signature) = j.provider_signature {
                verify(self.context.provider, &signature, id)?;
            }
            if let Some(signed) = &j.result {
                if j.provider_signature.is_none() || signed.result.work_id != id {
                    return Err(GrantStoreError::Malformed);
                }
                verify(
                    self.context.provider,
                    &signed.signature,
                    bound_result_digest(self.context.network, self.context.channel, &signed.result),
                )?;
            }
            let phase = if j.result.is_some() {
                JobPhase::Ready
            } else if j.provider_signature.is_some() {
                JobPhase::Accepted
            } else {
                JobPhase::HalfSigned
            };
            state.book.jobs.insert(
                id,
                JobState {
                    authorization: j.authorization,
                    work_id: id,
                    prepared_input: vec![],
                    client_signature: j.client_signature,
                    provider_signature: j.provider_signature,
                    phase,
                    result: j.result.map(|s| (s.result, s.signature)),
                    transcript: vec![],
                },
            );
        }
        state.book.proposal_nonce_high_water = snapshot.nonce;
        state.book.pending_proposal = snapshot.pending;
        state.book.revalidate_exchange(Role::Client)?;
        Ok(state)
    }
}
fn verify(
    key: hellas_kernel::Key,
    signature: &Signature,
    digest: Digest,
) -> Result<(), GrantStoreError> {
    hellas_rpc::signature::verify_digest_signature(
        &PublicKey::Secp256k1(key.to_bytes()),
        signature,
        digest,
    )
    .map_err(|_| GrantError::Signature.into())
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, GrantStoreError> {
    let bytes = canonical_dag_cbor(value).map_err(|_| GrantStoreError::Malformed)?;
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(GrantError::StateCapacity.into());
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, GrantStoreError> {
    let value = decode_dag_cbor(bytes).map_err(|_| GrantStoreError::Malformed)?;
    if encode(&value)? != bytes {
        return Err(GrantStoreError::Malformed);
    }
    Ok(value)
}
