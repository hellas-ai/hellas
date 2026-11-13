//! One proposal writer per grant channel. Bodies are never journaled; an
//! uncertain acceptance survives restart and cannot be replaced by a new nonce.
use super::checkpoint::CheckpointBound;
use super::{Deserialize, GrantChannelState, NodeStoreError, Serialize, Signature, SignedResult};
use crate::model::grant::records::{check_grant_provider, grant_producer};
use crate::model::grant::{
    GrantJobAuthorizationV1, grant_channel_id, grant_work_id,
    records::{GrantError, SignedOffer},
};
use hellas_auth::authority::UnixMillis;
use hellas_auth::{Digest, ProducerSigningKey, PublicKey};
use hellas_channel::job::WorkContext;
use hellas_channel::model::work::bound_result_digest;
use hellas_channel::work_store::channel::funding::GrantFunding;
use hellas_channel::work_store::journal::{
    Journal, JournalId, JournalKind, MAX_CHECKPOINT_BYTES, Replay,
};
use hellas_channel::work_store::{Applied, JobBook, JobPhase, JobState, Role};
use hellas_kernel::NetworkId;
use hellas_private::StoreLocation;
use hellas_rpc::OutputEventEnvelope;
use hellas_rpc::ProviderEnrollmentBundle;
use hellas_rpc::protocol::invocation::{InvocationPolicy, PreparedInvocation};
use hellas_rpc::protocol::value::{decode_canonical_bounded, encode_bounded};

const NAMESPACE: &str = "hellas.work.grant-client.v2";
const MAX_JOBS: usize = 256;
/// Each job's reserve for a provider signature and result. Also covers what a
/// frame adds to the snapshot beyond its own bytes: a new job's field names,
/// the pending work id, and widened clock and nonce integers.
const JOB_HEADROOM: usize = 512;
const JOURNAL_STEM: &str = "grant-client";

pub struct GrantClientStore {
    journal: Journal,
    directory: StoreLocation,
    context: WorkContext,
    channel: GrantChannelState,
    provider: ProviderEnrollmentBundle,
    state: ClientState,
    /// Covers the encoded snapshot of `state`.
    checkpoint_bound: CheckpointBound,
}
#[derive(Clone, Debug, Default, PartialEq)]
struct ClientState {
    book: JobBook<GrantFunding>,
    now: UnixMillis,
}
/// Verified local facts for one grant work ID, read without opening a writer.
pub struct GrantWorkInspection {
    pub phase: JobPhase,
    pub result: Option<SignedResult>,
    pub pending: bool,
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
    /// Release the client writer before this channel is reopened.
    pub async fn close(&mut self) {
        self.journal.close().await;
    }

    fn replayer(&self) -> GrantReplayer {
        GrantReplayer {
            context: self.context,
            channel: self.channel.clone(),
        }
    }

    /// Replay a grant journal read-only with its expected identities. This
    /// does not tick its clock or create a journal.
    pub async fn inspect_work(
        directory: &StoreLocation,
        network: NetworkId,
        provider: ProviderEnrollmentBundle,
        channel: GrantChannelState,
        work: Digest,
    ) -> Result<Option<GrantWorkInspection>, NodeStoreError> {
        check_grant_provider(&provider)?;
        if channel.id
            != grant_channel_id(
                network,
                provider.content_id(),
                channel.grant,
                channel.client,
                channel.generation,
            )
        {
            return Err(GrantError::Generation.into());
        }
        let context = WorkContext {
            network,
            channel: channel.id.0,
            client: channel.client.signer(),
            provider: grant_producer(&provider)?,
        };
        let (id, replay) = Journal::inspect(directory, JOURNAL_STEM).await?;
        if id != journal_id(&channel) {
            return Err(GrantError::Audience.into());
        }
        let state = GrantReplayer { context, channel }.replay(replay)?;
        Ok(state.book.job_by_id(work).map(|job| GrantWorkInspection {
            phase: job.phase(),
            result: job.result().map(|(result, signature)| SignedResult {
                result: *result,
                signature: *signature,
            }),
            pending: state.book.pending_proposal() == Some(work),
        }))
    }
    /// The channel's node key, which this client's credential is bound to,
    /// signs every proposal on behalf of the channel's principal.
    pub async fn open(
        directory: &StoreLocation,
        network: NetworkId,
        provider: ProviderEnrollmentBundle,
        channel: GrantChannelState,
        now: UnixMillis,
    ) -> Result<Self, NodeStoreError> {
        check_grant_provider(&provider)?;
        if channel.id
            != grant_channel_id(
                network,
                provider.content_id(),
                channel.grant,
                channel.client,
                channel.generation,
            )
        {
            return Err(GrantError::Generation.into());
        }
        let context = WorkContext {
            network,
            channel: channel.id.0,
            client: channel.client.signer(),
            provider: grant_producer(&provider)?,
        };
        let (journal, replay) =
            Journal::open_latest(directory, JOURNAL_STEM, journal_id(&channel)).await?;
        let mut store = Self {
            journal,
            directory: directory.clone(),
            context,
            channel,
            provider,
            state: ClientState::default(),
            checkpoint_bound: CheckpointBound::UNMEASURED,
        };
        store.state = store.replayer().replay(replay)?;
        store.tick(now).await?;
        Ok(store)
    }

    /// A failed or cancelled append leaves its outcome unknown. Replay what
    /// committed instead of refusing every later transition until restart.
    async fn reopen_if_poisoned(&mut self) -> Result<(), NodeStoreError> {
        if self.journal.check_authority().is_ok() {
            return Ok(());
        }
        self.journal.close().await;
        let (journal, replay) =
            Journal::open_latest(&self.directory, JOURNAL_STEM, journal_id(&self.channel)).await?;
        self.state = self.replayer().replay(replay)?;
        self.checkpoint_bound = CheckpointBound::UNMEASURED;
        self.journal = journal;
        Ok(())
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
    pub fn next_nonce(&self) -> Result<u64, NodeStoreError> {
        if self.book().pending_proposal().is_some() {
            return Err(hellas_channel::work_store::ChannelStateError::Conflict {
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
    pub async fn propose(
        &mut self,
        offer: &SignedOffer,
        authorization: GrantJobAuthorizationV1,
        input: &PreparedInvocation,
        signer: &ProducerSigningKey,
        now: UnixMillis,
        proposed: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Signature, NodeStoreError> {
        let now = now.max(self.now());
        let verified = SignedOffer::decode(&offer.encode()?, now)?;
        let offer = verified.offer();
        let a = &authorization;
        if offer.network != self.context.network
            || offer.provider != self.provider
            || offer.channel(self.channel.client) != self.channel.id
            || offer.grant.id != a.grant_id
            || offer.grant.revision != a.grant_revision
            || offer.generation != a.generation
        {
            return Err(GrantError::Audience.into());
        }
        offer.grant.admit()?;
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
                p.resource == a.resource_id
                    && p.revision == a.resource_revision
                    && p.pricing.revision == a.pricing_revision
                    && hellas_channel::job::policy_digest(
                        self.context.network,
                        self.context.channel,
                        &p.invocation_policy,
                    )
                    .ok()
                        == Some(a.work_policy_digest)
            })
            .ok_or(GrantError::OutOfScope)?;
        hellas_channel::job::check_input(
            &self.context,
            &a.into(),
            &policy.invocation_policy,
            input,
        )?;
        crate::work_store::grant::store::resource_charge(policy, input)?;
        if signer.public_key() != PublicKey::Secp256k1(self.context.client.to_bytes()) {
            return Err(GrantError::Signature.into());
        }
        let signature = signer
            .sign_digest(grant_work_id(self.context.network, a))
            .map_err(|_| GrantError::Signature)?;
        if let Some(proposed) = proposed {
            proposed.store(true, std::sync::atomic::Ordering::Release);
        }
        self.commit(
            now,
            Change::Proposed {
                authorization,
                signature,
            },
            true,
        )
        .await?;
        Ok(signature)
    }
    /// An uncertain response remains pending, including after restart. A body
    /// lost at restart can only be probed after the signed acceptance deadline;
    /// the provider then returns its old co-signature or a conclusive refusal.
    pub async fn resume(&mut self, work: Digest, now: UnixMillis) -> Result<(), NodeStoreError> {
        self.commit(
            now,
            Change::Exchange {
                work,
                pending: true,
            },
            true,
        )
        .await
    }
    /// Call only for a decoded, authenticated refusal. A timeout or transport
    /// error is not a refusal and must leave the pending proposal intact.
    pub async fn refused(&mut self, work: Digest, now: UnixMillis) -> Result<(), NodeStoreError> {
        self.commit(
            now,
            Change::Exchange {
                work,
                pending: false,
            },
            false,
        )
        .await
    }
    pub async fn accepted(
        &mut self,
        work: Digest,
        signature: Signature,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.commit(now, Change::Accepted { work, signature }, false)
            .await
    }
    /// Verifies the signed transcript live, then persists only its bound result.
    pub async fn complete(
        &mut self,
        work: Digest,
        policy: &InvocationPolicy,
        input: &PreparedInvocation,
        events: &[OutputEventEnvelope],
        signed: SignedResult,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        let job = self
            .book()
            .job_by_id(work)
            .ok_or(GrantError::Unauthorized)?;
        let a = job.authorization();
        if hellas_channel::job::policy_digest(self.context.network, self.context.channel, policy)?
            != a.work_policy_digest
            || hellas_channel::job::terminal_result(
                &self.context,
                work,
                &a.into(),
                policy,
                input,
                events,
            )? != signed.result
        {
            return Err(GrantError::OutOfScope.into());
        }
        self.commit(now, Change::Result { work, signed }, false)
            .await
    }
    pub async fn tick(&mut self, now: UnixMillis) -> Result<(), NodeStoreError> {
        if now > self.now() {
            self.commit(now, Change::Clock, false).await?;
        }
        Ok(())
    }
    pub async fn rotate(&mut self) -> Result<(), NodeStoreError> {
        let checkpoint = encode(&self.snapshot(&self.state))?;
        self.journal.rotate(&checkpoint).await?;
        self.checkpoint_bound.measured(checkpoint.len());
        Ok(())
    }

    async fn commit(
        &mut self,
        now: UnixMillis,
        change: Change,
        new: bool,
    ) -> Result<(), NodeStoreError> {
        self.reopen_if_poisoned().await?;
        let frame = Frame {
            namespace: NAMESPACE.into(),
            now: now.max(self.now()),
            change,
        };
        let mut candidate = self.state.clone();
        self.replayer().apply(&mut candidate, &frame)?;
        let record = encode(&frame);
        let jobs = candidate.book.jobs().len();
        if jobs > MAX_JOBS {
            return Err(GrantError::StateCapacity.into());
        }
        // Reserve enough space for a provider signature and result for each
        // exported proposal before admitting it, including unanswered ones.
        // A frame's values reach the snapshot at most once.
        let len = record.as_ref().map_or(usize::MAX, Vec::len);
        let bound = self.checkpoint_bound.admit(
            len.saturating_add(JOB_HEADROOM),
            jobs * JOB_HEADROOM,
            || Ok(encode(&self.snapshot(&candidate))?.len()),
        )?;
        if self.journal.at_soft_limit() {
            let rotated = self.rotate().await;
            if new {
                rotated?;
            }
        }
        self.journal.append(&record?).await?;
        self.state = candidate;
        self.checkpoint_bound.commit(bound);
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
}
struct GrantReplayer {
    context: WorkContext,
    channel: GrantChannelState,
}
impl GrantReplayer {
    fn replay(&self, replay: Replay) -> Result<ClientState, NodeStoreError> {
        let mut state = match replay.checkpoint {
            Some(bytes) => self.restore(decode(&bytes)?)?,
            None => ClientState::default(),
        };
        for bytes in replay.records {
            let frame: Frame = decode(&bytes)?;
            let mut candidate = state.clone();
            self.apply(&mut candidate, &frame)?;
            state = candidate;
        }
        Ok(state)
    }
    fn check_job(
        &self,
        a: &GrantJobAuthorizationV1,
        signature: &Signature,
    ) -> Result<Digest, NodeStoreError> {
        if a.channel_id != self.channel.id
            || a.generation != self.channel.generation
            || a.grant_id != self.channel.grant
            || a.grant_revision.0 == 0
            || a.resource_revision.0 == 0
            || a.pricing_revision.0 == 0
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
    fn apply(&self, state: &mut ClientState, frame: &Frame) -> Result<Applied, NodeStoreError> {
        if frame.namespace != NAMESPACE || frame.now < state.now {
            return Err(NodeStoreError::Malformed);
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
                        prepared_input: bytes::Bytes::new(),
                        client_signature: *signature,
                        provider_signature: None,
                        phase: JobPhase::HalfSigned,
                        result: None,
                        transcript: bytes::Bytes::new(),
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
                    state.book.record_result(
                        *work,
                        signed.result,
                        signed.signature,
                        bytes::Bytes::new(),
                    )?
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
    fn restore(&self, snapshot: Snapshot) -> Result<ClientState, NodeStoreError> {
        if snapshot.namespace != NAMESPACE || snapshot.jobs.len() > MAX_JOBS {
            return Err(NodeStoreError::Malformed);
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
                return Err(NodeStoreError::Malformed);
            }
            if let Some(signature) = j.provider_signature {
                verify(self.context.provider, &signature, id)?;
            }
            if let Some(signed) = &j.result {
                if j.provider_signature.is_none() || signed.result.work_id != id {
                    return Err(NodeStoreError::Malformed);
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
                    prepared_input: bytes::Bytes::new(),
                    client_signature: j.client_signature,
                    provider_signature: j.provider_signature,
                    phase,
                    result: j.result.map(|s| (s.result, s.signature)),
                    transcript: bytes::Bytes::new(),
                },
            );
        }
        state.book.proposal_nonce_high_water = snapshot.nonce;
        state.book.pending_proposal = snapshot.pending;
        state.book.revalidate_exchange(Role::Client)?;
        Ok(state)
    }
}

fn journal_id(channel: &GrantChannelState) -> JournalId {
    JournalId {
        kind: JournalKind::Grant,
        role: Role::Client,
        key: *channel.id.0.as_bytes(),
    }
}
fn verify(
    key: hellas_kernel::Key,
    signature: &Signature,
    digest: Digest,
) -> Result<(), NodeStoreError> {
    hellas_auth::signature::verify_digest_signature(
        &PublicKey::Secp256k1(key.to_bytes()),
        signature,
        digest,
    )
    .map_err(|_| GrantError::Signature.into())
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeStoreError> {
    encode_bounded(value, MAX_CHECKPOINT_BYTES).map_err(Into::into)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, NodeStoreError> {
    decode_canonical_bounded(bytes, MAX_CHECKPOINT_BYTES).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        channel_client, network, principal, proposal, setup, software_enrollment,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    impl GrantClientStore {
        pub(crate) async fn pause_next_statement(
            &mut self,
        ) -> (
            tokio::sync::oneshot::Receiver<()>,
            std::sync::mpsc::Sender<()>,
        ) {
            self.journal.pause_next_statement().await
        }

        pub(crate) async fn resume_statements(&mut self, release: std::sync::mpsc::Sender<()>) {
            self.journal.resume_statements(release).await;
        }
    }

    static DECODED: AtomicBool = AtomicBool::new(false);
    #[derive(Serialize)]
    struct Probe;
    impl<'de> serde::Deserialize<'de> for Probe {
        fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
            DECODED.store(true, Ordering::SeqCst);
            Err(serde::de::Error::custom("decoder probe"))
        }
    }

    #[test]
    fn oversized_client_records_are_refused_before_deserialization() {
        for (length, called) in [
            (MAX_CHECKPOINT_BYTES + 1, false),
            (MAX_CHECKPOINT_BYTES, true),
        ] {
            DECODED.store(false, Ordering::SeqCst);
            assert!(decode::<Probe>(&vec![0; length]).is_err());
            assert_eq!(DECODED.load(Ordering::SeqCst), called, "{length}");
        }
    }

    async fn open(
        location: &StoreLocation,
        channel: &GrantChannelState,
        now: u64,
    ) -> GrantClientStore {
        let provider = software_enrollment(2, [2; 32]);
        GrantClientStore::open(
            location,
            network(),
            provider,
            channel.clone(),
            UnixMillis(now),
        )
        .await
        .unwrap()
    }

    /// Commits no longer encode the snapshot. The running bound must never
    /// under-count, and replay from any point between appends or around a
    /// rotation must reach exactly the live state.
    #[tokio::test]
    async fn checkpoint_bound_covers_every_client_commit_and_replay_matches_live_state() {
        use hellas_channel::model::work::{PaidJobResultV1, ResultOutcome};
        let directory = tempfile::tempdir().unwrap();
        let (provider, _) = setup(&directory.path().join("provider")).await;
        let (template, _, _) = proposal(&provider, 1);
        let channel = GrantChannelState {
            id: template.channel_id,
            grant: template.grant_id,
            generation: 0,
            client: channel_client(principal(1).0),
        };
        let location = StoreLocation::for_test(&directory.path().join("client"));
        let (mut seed, mut now, mut full) = (0x9e37_79b9_7f4a_7c15_u64, 1_000, 0);
        let mut next = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let mut store = open(&location, &channel, now).await;
        for _ in 0..1500 {
            let step = next(10);
            let pending = store.book().pending_proposal();
            let provider_sign = |digest| principal(2).1.sign_digest(digest).unwrap();
            match (step, pending) {
                (0..=3, None) => {
                    // Deadlines follow the clock so jobs both accumulate and expire.
                    let mut a = template;
                    a.proposal_nonce = store.next_nonce().unwrap();
                    a.acceptance_deadline_ms = UnixMillis(now + 1_000);
                    a.terminal_deadline_ms = UnixMillis(now + 2_000);
                    a.delivery_deadline_ms = UnixMillis(now + 2_000 + next(300_000));
                    let work = grant_work_id(network(), &a);
                    let signature = principal(1).1.sign_digest(work).unwrap();
                    let change = Change::Proposed {
                        authorization: a,
                        signature,
                    };
                    match store.commit(UnixMillis(now), change, true).await {
                        Ok(()) => {}
                        Err(NodeStoreError::Grant(GrantError::StateCapacity)) => {
                            assert_eq!(store.book().jobs().len(), MAX_JOBS);
                            full += 1;
                        }
                        Err(error) => panic!("{error:?}"),
                    }
                }
                (0..=3, Some(work)) => {
                    let signature = provider_sign(work);
                    store
                        .accepted(work, signature, UnixMillis(now))
                        .await
                        .unwrap();
                }
                (4, Some(work)) if next(2) == 0 => {
                    store.refused(work, UnixMillis(now)).await.unwrap()
                }
                (4, Some(work)) => store.resume(work, UnixMillis(now)).await.unwrap(),
                (5 | 6, _) if store.book().jobs().any(|j| j.phase() == JobPhase::Accepted) => {
                    let accepted = store
                        .book()
                        .jobs()
                        .filter(|j| j.phase() == JobPhase::Accepted)
                        .map(|j| j.work_id)
                        .collect::<Vec<_>>();
                    let work = accepted[next(accepted.len() as u64) as usize];
                    let result = PaidJobResultV1 {
                        work_id: work,
                        terminal_transcript_commitment: hellas_rpc::EventCommitment::from_digest(
                            Digest::hash(b"terminal"),
                        ),
                        canonical_output_digest: Digest::hash(b"output"),
                        outcome: ResultOutcome::Finished,
                        transcript_content: hellas_rpc::ContentRef::for_bytes(b"transcript"),
                    };
                    let digest = bound_result_digest(network(), store.context.channel, &result);
                    let signed = SignedResult {
                        result,
                        signature: provider_sign(digest),
                    };
                    let change = Change::Result { work, signed };
                    store.commit(UnixMillis(now), change, false).await.unwrap();
                }
                (7, _) => {
                    now += next(1_000);
                    store.tick(UnixMillis(now)).await.unwrap();
                }
                (8, _) => store.rotate().await.unwrap(),
                _ => {}
            }
            let cost = encode(&store.snapshot(&store.state)).unwrap().len();
            let bound = store.checkpoint_bound.get();
            assert!(cost <= bound, "{cost} > {bound}");
            if step == 8 || next(16) == 0 {
                let live = store.state.clone();
                store.close().await;
                drop(store);
                store = open(&location, &channel, now).await;
                assert_eq!(store.state, live);
            }
        }
        assert!(full > 0, "never reached MAX_JOBS");
    }
}
