//! Running an accepted job: what reaches a backend, what reaches it
//! twice, and what a provider signs about what came back.
//!
//! Every crash here is a real one — the store is dropped and reopened
//! over its own files — and the backend is a double that counts its
//! calls, so "invoked once" is an assertion about a number rather than
//! about a comment.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, Parties, Payout, PendingSlot, Secp256k1Verifier, SigVerifier as _, Terms,
    TermsHash, WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms,
    work_payment_settlement,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PaidWorkError, canonical_output_digest, generation_policy_digest, identity_source_digest,
    private_policy_commitment, propose_authorization, result_digest, signing_hash, terminal_result,
    work_id,
};
use hellas_rpc::protocol::work_setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, WorkSetupError,
    payment_terms_hash,
};
use hellas_rpc::{
    Application, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, ContentId, EvaluateRequest,
    OutputEventEnvelope, ProducerSigningKey, ProgramManifest, PublicKey,
};
use hellas_work::work::{
    BackendFault, PaidWorkBackend, PreparedEvaluateInput, ProviderEndpoint, RunAdmission, RunError,
    RunOutcome, WorkService, run_accepted_work,
};
use hellas_work::work_store::{
    ChannelRecord, ChannelStateError, ChannelStore, JobPhase, JobState, Role, SetupOrigin,
    TerminalOutcome, WorkStoreError,
};

#[path = "work_run/fetch.rs"]
mod fetch;
mod support;
use support::{advance, bond_edge, client, network, payload_at, payment_edge, provider, temp};

// ── Fixture ───────────────────────────────────────────────────────────

const HORIZON: u64 = 500;
const PRICE: u64 = 10;
const CREDIT_LIMIT: u64 = 40;
/// One over half the funding, so the bond exceeds the capacity it
/// leaves behind at zero fees.
const OMISSION_BOND: u64 = 601;
const PAYMENT_VALUE: u64 = 1_000;
const PAYMENT_RESERVE: u64 = 200;
const STAKE: u64 = 64;
const SALT: [u8; 32] = [0x5a; 32];
/// The finalized block a job is accepted at.
const CURSOR: u64 = 10;
/// The prompt this fixture's bundle carries, in tokens.
const PROMPT_TOKENS: u64 = 4;

/// The three heights every job here is bound by.
///
/// `dispatch_margin_blocks + delivery_margin_blocks` is 6, so the last
/// finalized height a dispatch may be marked at is `terminal - 6`.
const fn deadlines() -> JobDeadlines {
    JobDeadlines {
        acceptance: 50,
        terminal: 100,
        payment: 200,
    }
}

/// The last height at which the signed margins still fit before the
/// terminal deadline.
const LAST_DISPATCH: u64 = deadlines().terminal - 6;

fn producer(byte: u8) -> ProducerSigningKey {
    let Ok(key) = ProducerSigningKey::from_secret_bytes([byte; 32]) else {
        panic!("a fixed scalar is a producer key");
    };
    key
}

/// The provider's RPC producer identity: the same scalar its channel
/// party key is.
fn provider_producer() -> ProducerSigningKey {
    producer(0x22)
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: CREDIT_LIMIT,
        delivery_credit_limit: CREDIT_LIMIT,
    }
}

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider().party_key(), client().party_key()),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take(
            [Payout::new(provider().party_key(), STAKE); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 40,
    }
}

fn payment_terms() -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bond_edge(),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: OMISSION_BOND,
    }
}

fn execution_policy() -> PaidExecutionPolicyV1 {
    PaidExecutionPolicyV1 {
        allowed_environment: manifest().content_id(),
        generation_policy_digest: match generation_policy_digest(&text_policy().canonical_bytes()) {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture policy hashes: {error}"),
        },
        identity_source_digest: match identity_source_digest(&identity_artifact().canonical_bytes())
        {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture identity hashes: {error}"),
        },
        max_prompt_tokens: 512,
        max_new_tokens: 128,
        max_stop_token_ids: 4,
        max_spool_bytes: 1_048_576,
        max_encoded_result_frame: 262_144,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
        fixed_price: PRICE,
    }
}

/// A second policy, differing from the first in one measured margin.
fn other_execution_policy() -> PaidExecutionPolicyV1 {
    PaidExecutionPolicyV1 {
        dispatch_margin_blocks: 5,
        ..execution_policy()
    }
}

fn payment_values() -> EdgeValues {
    EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0))
}

fn descriptor_with(
    policy: impl Into<hellas_rpc::protocol::work_profile::PaidWorkPolicy>,
) -> WorkChannelDescriptor {
    let config = WorkChannelConfig {
        network: network(),
        payment_edge: payment_edge(),
        payment_terms: payment_terms(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: policy.into(),
        expected_payment_values: payment_values(),
    };
    match WorkChannelDescriptor::open(config) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

fn descriptor() -> WorkChannelDescriptor {
    descriptor_with(execution_policy())
}

/// One readiness decision, taken at `height` against a healthy channel.
fn ready_at(height: u64) -> ReadyChannel {
    ready_of(descriptor(), height)
}

fn ready_of(descriptor: WorkChannelDescriptor, height: u64) -> ReadyChannel {
    let bond = bond_object();
    let payment = payment_object();
    let observed = ObservedChannel {
        height,
        bond: Some(&bond),
        payment: Some(&payment),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: PendingSlot::Absent,
    };
    match descriptor.check_ready(&observed) {
        Ok(ready) => ready,
        Err(error) => panic!("the fixture channel is ready: {error}"),
    }
}

fn ready() -> ReadyChannel {
    ready_at(CURSOR)
}

fn settlement() -> WorkPaymentSettlement {
    let Some(settlement) = work_payment_settlement(payment_values(), OMISSION_BOND) else {
        panic!("a funded edge prices both exits");
    };
    settlement
}

fn store_at(root: &std::path::Path, height: u64) -> ChannelStore {
    let mut store = match ChannelStore::open(
        root,
        ready().channel().clone(),
        settlement(),
        Role::Provider,
        origin(),
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the fixture store opens: {error}"),
    };
    advance(&mut store, height);
    store
}

/// The fixture channel starts at the synthetic chain genesis.
fn origin() -> SetupOrigin {
    SetupOrigin {
        payment_edge: payment_edge(),
        height: 0,
        payload: payload_at(0),
        parent: [0_u8; 32],
    }
}

/// Runs the production watcher over one empty finalized block per
/// height, up through `height`.
///
/// The same call the settlement loop makes, so a fixture cursor is a
/// cursor this endpoint could have reached.
fn commit(store: &mut ChannelStore, record: ChannelRecord) {
    if let Err(error) = store.commit(record, &Secp256k1Verifier::new()) {
        panic!("the fixture record commits: {error}");
    }
}

fn endpoint(store: ChannelStore) -> ProviderEndpoint {
    match ProviderEndpoint::new(ready(), store, provider()) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the fixture provider endpoint binds: {error}"),
    }
}

fn serving(store: ChannelStore) -> WorkService {
    WorkService::new(endpoint(store))
}

// ── The prepared inputs a job executes from ───────────────────────────

fn manifest() -> ProgramManifest {
    ProgramManifest::new(
        Application::new(CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR).unwrap(),
        ContentId::from_bytes([0x16; 32]),
    )
}

fn prompt_tokens() -> TokenIds {
    TokenIds::from([9, 8, 7, 6])
}

fn text_policy() -> TextPolicy {
    TextPolicy::from_u32_stop_tokens(64, [2, 1])
}

fn identity_artifact() -> TextArtifact {
    TextArtifact::identity(BoundTermId::from_digest(manifest().content_id().digest()))
}

fn text_execution() -> TextExecution {
    TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    )
}

/// One job's request. The nonce byte makes two proposals two different
/// bundles, and therefore two different jobs.
fn evaluate_request(nonce: u8) -> EvaluateRequest {
    EvaluateRequest {
        text_execution: text_execution().input_id().digest(),
        runner_public_key: PublicKey::Secp256k1(client().party_key().to_bytes()),
        execution_environment: manifest().content_id(),
        nonce: [nonce; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

fn bundle(nonce: u8) -> PreparedPaidInputV1 {
    PreparedPaidInputV1::new(
        &evaluate_request(nonce),
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
}

fn bundle_bytes(nonce: u8) -> Vec<u8> {
    match bundle(nonce).encode() {
        Ok(bytes) => bytes,
        Err(error) => panic!("the fixture bundle encodes: {error}"),
    }
}

fn authorization(nonce: u8) -> PaidJobAuthorizationV1 {
    match propose_authorization(
        ready().channel(),
        &execution_policy(),
        &bundle(nonce),
        u64::from(nonce),
        deadlines(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    }
}

/// Puts one accepted job on the disk, and returns its `work_id`.
///
/// The two records the acceptance exchange writes, written directly:
/// these tests are about what happens *after* both signatures exist, and
/// the exchange that produces them has its own file.
fn accept(store: &mut ChannelStore, nonce: u8) -> Digest {
    let authorization = authorization(nonce);
    let id = work_id(ready().channel(), &authorization);
    commit(
        store,
        ChannelRecord::JobProposed {
            authorization,
            client_signature: client().sign(signing_hash(id)),
            prepared_input: bundle_bytes(nonce),
        },
    );
    commit(
        store,
        ChannelRecord::JobAccepted {
            work_id: id,
            provider_signature: provider().sign(signing_hash(id)),
        },
    );
    id
}

// ── Transcripts ───────────────────────────────────────────────────────

/// The tokens every fixture transcript answers with, unless it says
/// otherwise.
const ANSWER: [u32; 5] = [101, 102, 103, 104, 105];

/// Builds one complete signed Evaluate transcript for `request`.
///
/// `chunks` is how the answer is split across signed token-delta events.
/// The answer itself is their concatenation, so two different splits are
/// two transcripts of one answer.
fn transcript_for(
    request: &EvaluateRequest,
    chunks: &[&[u32]],
    key: &ProducerSigningKey,
) -> Vec<OutputEventEnvelope> {
    let mut builder =
        EvaluateOutputTranscriptBuilder::new(input_commitment(request), request.assurance, key);
    let mut generated: Vec<u32> = Vec::new();
    for chunk in chunks {
        if let Err(error) = builder.push_token_delta(chunk.to_vec()) {
            panic!("a non-empty delta pushes: {error}");
        }
        generated.extend_from_slice(chunk);
    }
    let usage = EvaluateUsage {
        input_units: PROMPT_TOKENS,
        output_units: generated.len() as u64,
    };
    let billable_units = match usage.billable_units() {
        Ok(units) => units,
        Err(error) => panic!("the fixture usage sums: {error}"),
    };
    let terminal = EvaluateTerminal {
        final_position: generated.len() as u64,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact: Digest::from_bytes([0x77; 32]),
        usage,
        billable_units,
    };
    match builder.finish(terminal) {
        Ok(events) => events,
        Err(error) => panic!("the fixture transcript finishes: {error}"),
    }
}

fn answer_transcript(request: &EvaluateRequest) -> Vec<OutputEventEnvelope> {
    transcript_for(request, &[&ANSWER[..2], &ANSWER[2..]], &provider_producer())
}

// ── The backend double ────────────────────────────────────────────────

/// What the backend does when it is called.
#[derive(Clone)]
enum Answer {
    /// Sign the answer for whatever request it is handed.
    Transcript,
    /// Sign the answer for a *different* request than the one handed.
    ForAnotherRequest(u8),
    /// Sign the answer under a key this channel does not call the
    /// provider.
    UnderAnotherKey(u8),
    /// Fail.
    Fault(&'static str),
}

/// A backend that counts, and that signs a real transcript when it does
/// not refuse.
///
/// The counter is the whole point: "invoked once" is this number, read
/// after a retry and after a restart.
struct CountingBackend {
    calls: Arc<AtomicUsize>,
    answer: Answer,
}

impl CountingBackend {
    fn new(answer: Answer) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            answer,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl PaidWorkBackend for CountingBackend {
    fn evaluate(
        &self,
        input: PreparedEvaluateInput,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(input.program_manifest(), manifest().canonical_bytes());
        let request = input.evaluate_request();
        let answer = self.answer.clone();
        let produced = match answer {
            Answer::Transcript => Ok(answer_transcript(request)),
            Answer::ForAnotherRequest(nonce) => Ok(answer_transcript(&evaluate_request(nonce))),
            Answer::UnderAnotherKey(byte) => Ok(transcript_for(
                request,
                &[&ANSWER[..2], &ANSWER[2..]],
                &producer(byte),
            )),
            Answer::Fault(reason) => Err(BackendFault::new(reason)),
        };
        async move { produced }
    }
}

// ── Reading answers ───────────────────────────────────────────────────

fn phase_of(service: &WorkService) -> Option<JobPhase> {
    match service.with_state(|state| state.jobs().next().map(JobState::phase)) {
        Ok(phase) => phase,
        Err(error) => panic!("the endpoint is reachable: {error}"),
    }
}

// ── The identity the whole chain rests on ─────────────────────────────

/// The provider's RPC producer key and its channel party key are one
/// scalar.
///
/// Every test below signs a transcript with the first and checks it
/// against the second. If those were two identities, every one of them
/// would pass by construction and prove nothing about a real provider.
#[test]
fn a_providers_producer_key_is_its_party_key() {
    let PublicKey::Secp256k1(compressed) = provider_producer().public_key() else {
        panic!("producer keys are secp256k1");
    };
    assert_eq!(provider().party_key().to_bytes(), compressed);

    // The control: another scalar is another key, so the comparison
    // above is not satisfied by every pair.
    let PublicKey::Secp256k1(other) = producer(0x23).public_key() else {
        panic!("producer keys are secp256k1");
    };
    assert_ne!(provider().party_key().to_bytes(), other);
}

// ── The terminal a result is built from ───────────────────────────────

/// The result summarises the transcript that produced it, and both of
/// its digests come from that transcript.
#[test]
fn a_result_is_derived_from_the_transcript_that_produced_it() {
    let channel = ready().channel().clone();
    let authorization = authorization(1);
    let transcript = answer_transcript(&evaluate_request(1));

    let result = match terminal_result(&channel, &authorization, &transcript) {
        Ok(result) => result,
        Err(error) => panic!("the fixture transcript is a terminal: {error}"),
    };

    assert_eq!(result.work_id, work_id(&channel, &authorization));

    // The terminal commitment is the last signed event's own, taken
    // from the transcript rather than from anything beside it.
    let Some(last) = transcript.last() else {
        panic!("the fixture transcript is not empty");
    };
    assert_eq!(
        result.terminal_transcript_commitment,
        last.event_commitment()
    );
    assert_ne!(
        transcript[0].event_commitment(),
        last.event_commitment(),
        "the events differ, so naming the last one is a choice"
    );

    // And the answer is the flattened token list, recomputed here from
    // the tokens the fixture generated rather than from the result.
    let terminal = EvaluateTerminal {
        final_position: ANSWER.len() as u64,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact: Digest::from_bytes([0x77; 32]),
        usage: EvaluateUsage {
            input_units: PROMPT_TOKENS,
            output_units: ANSWER.len() as u64,
        },
        billable_units: PROMPT_TOKENS + ANSWER.len() as u64,
    };
    let expected = match canonical_output_digest(network(), result.work_id, &ANSWER, &terminal) {
        Ok(digest) => digest,
        Err(error) => panic!("the fixture terminal hashes: {error}"),
    };
    assert_eq!(result.canonical_output_digest, expected);
}

/// Splitting one answer differently changes the transcript and not the
/// answer.
///
/// The two digests in a result say different things, and this is the
/// difference: the client's oracle compares the second, so a provider
/// that batched its tokens differently must still be paid.
#[test]
fn chunking_moves_the_transcript_commitment_and_not_the_answer() {
    let channel = ready().channel().clone();
    let authorization = authorization(1);
    let request = evaluate_request(1);
    let key = provider_producer();

    let one = transcript_for(&request, &[&ANSWER[..]], &key);
    let many = transcript_for(&request, &[&ANSWER[..1], &ANSWER[1..3], &ANSWER[3..]], &key);
    assert_eq!(one.len(), 2, "one delta and a terminal");
    assert_eq!(many.len(), 4, "three deltas and a terminal");

    let (Ok(first), Ok(second)) = (
        terminal_result(&channel, &authorization, &one),
        terminal_result(&channel, &authorization, &many),
    ) else {
        panic!("both fixture transcripts are terminals");
    };
    assert_eq!(
        first.canonical_output_digest,
        second.canonical_output_digest
    );
    assert_ne!(
        first.terminal_transcript_commitment,
        second.terminal_transcript_commitment
    );

    // The control: a different answer is a different answer under both
    // splits.
    let other = transcript_for(&request, &[&[201, 202, 203, 204, 205][..]], &key);
    let Ok(third) = terminal_result(&channel, &authorization, &other) else {
        panic!("the fixture transcript is a terminal");
    };
    assert_ne!(first.canonical_output_digest, third.canonical_output_digest);
}

/// A transcript that is not one verified terminal chain for this
/// authorization is not a result.
///
/// Each case varies exactly one thing about an otherwise valid
/// transcript, and each one is refused for its own reason.
#[test]
fn only_this_jobs_own_terminal_transcript_becomes_a_result() {
    let channel = ready().channel().clone();
    let authorization = authorization(1);
    let request = evaluate_request(1);
    let good = answer_transcript(&request);
    assert!(
        terminal_result(&channel, &authorization, &good).is_ok(),
        "the unvaried transcript is accepted",
    );

    // MUTATION: no events at all.
    let empty = terminal_result(&channel, &authorization, &[]);
    assert!(
        matches!(empty, Err(PaidWorkError::Transcript(_))),
        "unexpected answer: {empty:?}",
    );

    // MUTATION: the terminal event removed, leaving a legal prefix.
    let mut headless = good.clone();
    headless.pop();
    let refused = terminal_result(&channel, &authorization, &headless);
    assert!(
        matches!(refused, Err(PaidWorkError::Transcript(_))),
        "unexpected answer: {refused:?}",
    );

    // MUTATION: a whole, valid transcript — for another request.
    let elsewhere = answer_transcript(&evaluate_request(2));
    let refused = terminal_result(&channel, &authorization, &elsewhere);
    assert!(
        matches!(refused, Err(PaidWorkError::Transcript(_))),
        "unexpected answer: {refused:?}",
    );

    // MUTATION: a whole, valid, correctly self-signed transcript — under
    // a key that is not this channel's provider. Every signature in it
    // verifies, which is why the key has to be checked against the
    // channel and not merely against the transcript.
    let stranger = transcript_for(&request, &[&ANSWER[..2], &ANSWER[2..]], &producer(0x23));
    assert_eq!(
        terminal_result(&channel, &authorization, &stranger),
        Err(PaidWorkError::Mismatch {
            field: "transcript producer key"
        })
    );

    // MUTATION: an event lifted from another transcript into this one,
    // breaking the chain rather than the signatures.
    let mut spliced = good.clone();
    spliced[0] = elsewhere[0].clone();
    let refused = terminal_result(&channel, &authorization, &spliced);
    assert!(
        matches!(refused, Err(PaidWorkError::Transcript(_))),
        "unexpected answer: {refused:?}",
    );
}

// ── One accepted job, one invocation ──────────────────────────────────

/// One accepted job reaches the backend once, across a retry and across
/// a restart.
///
/// Three calls, one invocation. The second is the retry a caller makes
/// when its answer was lost; the third is made by a process that has
/// reopened the journal over the same files and knows nothing else.
#[tokio::test]
async fn one_accepted_job_reaches_the_backend_once() {
    let dir = temp();
    let backend = CountingBackend::new(Answer::Transcript);
    let id = {
        let mut store = store_at(dir.path(), CURSOR);
        let id = accept(&mut store, 1);
        let service = serving(store);

        let outcome = run_accepted_work(&service, &ready(), &backend, id).await;
        let RunOutcome::Completed { result, signature } = expect_outcome(outcome) else {
            panic!("the first run invokes and completes");
        };
        assert_eq!(backend.calls(), 1);
        assert_eq!(result.work_id, id);

        // The retry: the same answer, and no second invocation.
        let again = expect_outcome(run_accepted_work(&service, &ready(), &backend, id).await);
        assert_eq!(
            again,
            RunOutcome::Ready { result, signature },
            "a retry is answered from the disk",
        );
        assert_eq!(backend.calls(), 1, "the retry invoked nothing");
        id
    };

    // The restart: a new process, a new endpoint, the same files.
    let service = serving(store_at(dir.path(), CURSOR));
    let recovered = expect_outcome(run_accepted_work(&service, &ready(), &backend, id).await);
    assert!(
        matches!(recovered, RunOutcome::Ready { .. }),
        "unexpected outcome: {recovered:?}",
    );
    assert_eq!(backend.calls(), 1, "the restart invoked nothing");
}

/// The result the caller is handed is one the disk already holds.
///
/// The ordering rule, checked from the outside: the journal is reopened
/// over its own files by a process that never saw the return value, and
/// what it finds is the same result and the same signature.
#[tokio::test]
async fn a_result_is_on_the_disk_before_its_signature_is_returned() {
    let dir = temp();
    let backend = CountingBackend::new(Answer::Transcript);
    let mut store = store_at(dir.path(), CURSOR);
    let id = accept(&mut store, 1);
    let service = serving(store);

    let RunOutcome::Completed {
        result, signature, ..
    } = expect_outcome(run_accepted_work(&service, &ready(), &backend, id).await)
    else {
        panic!("the run completes");
    };
    drop(service);

    let recovered = store_at(dir.path(), CURSOR);
    let Some(job) = recovered.state().jobs().next() else {
        panic!("the job is still open");
    };
    assert_eq!(job.phase(), JobPhase::Ready);
    assert_eq!(job.result(), Some(&(result, signature)));

    // And the signature is the provider's over this result's digest,
    // checked here against the channel's key rather than trusted.
    let digest = result_digest(ready().channel(), &result);
    assert!(Secp256k1Verifier::new().verify_sig(
        signature,
        provider().party_key(),
        signing_hash(digest)
    ));
}

/// A marker left by a process that did not come back is never resolved
/// by guessing.
///
/// The crash this is about happens between the running marker and the
/// terminal, which is the one window where nothing local can say whether
/// the backend ran. What a recovered endpoint answers is
/// `Indeterminate`, and what it refuses is a result.
#[tokio::test]
async fn a_marker_a_process_did_not_come_back_from_is_indeterminate() {
    let dir = temp();
    let backend = CountingBackend::new(Answer::Transcript);
    let id = {
        let mut store = store_at(dir.path(), CURSOR);
        let id = accept(&mut store, 1);
        // Exactly the state `begin_run` leaves before it returns.
        commit(&mut store, ChannelRecord::JobRunning { work_id: id });
        id
    };

    let service = serving(store_at(dir.path(), CURSOR));
    let outcome = expect_outcome(run_accepted_work(&service, &ready(), &backend, id).await);
    assert_eq!(outcome, RunOutcome::Indeterminate);
    assert_eq!(backend.calls(), 0, "recovery never invokes");
    assert_eq!(
        phase_of(&service),
        Some(JobPhase::Running),
        "and never ends"
    );

    // Nor may a result be recorded for it, however well formed.
    let transcript = answer_transcript(&evaluate_request(1));
    let refused = service.record_result(id, &transcript);
    assert!(
        matches!(
            refused,
            Err(RunError::Store(WorkStoreError::Channel(
                ChannelStateError::Indeterminate
            )))
        ),
        "unexpected answer: {refused:?}",
    );

    // The control: the same transcript on a journal whose marker this
    // process wrote is recorded.
    let other = temp();
    let mut store = store_at(other.path(), CURSOR);
    let id = accept(&mut store, 1);
    let service = serving(store);
    let RunAdmission::Invoke(_) = expect_admission(service.begin_run(id, &ready())) else {
        panic!("an accepted job may run");
    };
    if let Err(error) = service.record_result(id, &transcript) {
        panic!("this process's own invocation records: {error}");
    }
}

/// A second call while the first is running invokes nothing.
#[test]
fn a_job_this_process_is_running_is_not_started_again() {
    let dir = temp();
    let mut store = store_at(dir.path(), CURSOR);
    let id = accept(&mut store, 1);
    let mut endpoint = endpoint(store);

    let RunAdmission::Invoke(input) = expect_admission(endpoint.begin_run(id, &ready())) else {
        panic!("the first call may invoke");
    };
    // Both bodies come out of the journal, not out of a quote: these are
    // the exact canonical values both parties signed the digest of.
    assert_eq!(input.evaluate_request(), &evaluate_request(1));
    assert_eq!(input.program_manifest(), manifest().canonical_bytes());

    assert_eq!(
        expect_admission(endpoint.begin_run(id, &ready())),
        RunAdmission::Running,
        "the second call finds the marker the first wrote",
    );
}

/// A restart executes the job that was accepted, from the bundle the
/// journal kept.
///
/// The transient quote store this bundle came from is gone by
/// construction — this process never had one — so the request handed to
/// the backend can only have come from the disk.
#[tokio::test]
async fn a_restart_runs_the_job_that_was_accepted() {
    let dir = temp();
    let id = {
        let mut store = store_at(dir.path(), CURSOR);
        accept(&mut store, 1)
    };

    let service = serving(store_at(dir.path(), CURSOR));
    let backend = CountingBackend::new(Answer::Transcript);
    let RunOutcome::Completed { result, .. } =
        expect_outcome(run_accepted_work(&service, &ready(), &backend, id).await)
    else {
        panic!("the accepted job runs after a restart");
    };
    assert_eq!(backend.calls(), 1);
    assert_eq!(result.work_id, id);
}

// ── The gate in front of the marker ───────────────────────────────────

/// A run whose margins no longer fit before the terminal deadline marks
/// nothing and invokes nothing.
///
/// One block either side of the boundary the signed policy measures. The
/// late case is the one a client could otherwise force by withholding
/// its accepted job until compute can no longer earn payment.
#[tokio::test]
async fn the_last_height_the_margins_fit_is_the_last_that_may_run() {
    for (height, may_run) in [(LAST_DISPATCH, true), (LAST_DISPATCH + 1, false)] {
        let dir = temp();
        // Acceptance happened at the earlier phase boundary. Only after
        // that durable signature exists does the watcher catch the journal
        // up to the dispatch boundary under test.
        let mut store = store_at(dir.path(), CURSOR);
        let id = accept(&mut store, 1);
        advance(&mut store, height);
        let service = serving(store);
        let backend = CountingBackend::new(Answer::Transcript);
        let outcome = run_accepted_work(&service, &ready_at(height), &backend, id).await;

        if may_run {
            assert!(
                matches!(outcome, Ok(RunOutcome::Completed { .. })),
                "at {height} the margins still fit: {outcome:?}",
            );
            assert_eq!(backend.calls(), 1);
            continue;
        }
        let Err(RunError::Setup(WorkSetupError::TerminalUnreachable { terminal, .. })) = outcome
        else {
            panic!("at {height} the margins do not fit: {outcome:?}");
        };
        assert_eq!(terminal, deadlines().terminal);
        assert_eq!(backend.calls(), 0, "nothing was invoked");
        assert_eq!(
            phase_of(&service),
            Some(JobPhase::Accepted),
            "and nothing was marked",
        );
    }
}

/// A job with no provider co-signature does not run.
#[tokio::test]
async fn a_job_that_was_never_co_signed_does_not_run() {
    let dir = temp();
    let mut store = store_at(dir.path(), CURSOR);
    let authorization = authorization(1);
    let id = work_id(ready().channel(), &authorization);
    commit(
        &mut store,
        ChannelRecord::JobProposed {
            authorization,
            client_signature: client().sign(signing_hash(id)),
            prepared_input: bundle_bytes(1),
        },
    );
    let service = serving(store);
    let backend = CountingBackend::new(Answer::Transcript);

    let outcome = run_accepted_work(&service, &ready(), &backend, id).await;
    assert!(
        matches!(
            outcome,
            Err(RunError::NotAccepted {
                phase: JobPhase::HalfSigned
            })
        ),
        "unexpected outcome: {outcome:?}",
    );
    assert_eq!(backend.calls(), 0);

    // The control: the co-signature is the only thing missing.
    drop(service);
    let mut store = store_at(dir.path(), CURSOR);
    commit(
        &mut store,
        ChannelRecord::JobAccepted {
            work_id: id,
            provider_signature: provider().sign(signing_hash(id)),
        },
    );
    let service = serving(store);
    assert!(
        matches!(
            run_accepted_work(&service, &ready(), &backend, id).await,
            Ok(RunOutcome::Completed { .. })
        ),
        "the same job co-signed runs",
    );
}

/// A run named for another job finds nothing to run.
#[tokio::test]
async fn a_run_named_for_another_job_finds_nothing() {
    let dir = temp();
    let mut store = store_at(dir.path(), CURSOR);
    let id = accept(&mut store, 1);
    let service = serving(store);
    let backend = CountingBackend::new(Answer::Transcript);

    let other = work_id(ready().channel(), &authorization(2));
    assert_ne!(other, id);
    let outcome = run_accepted_work(&service, &ready(), &backend, other).await;
    assert!(
        matches!(outcome, Err(RunError::NoSuchJob)),
        "unexpected outcome: {outcome:?}",
    );
    assert_eq!(backend.calls(), 0);
}

/// A readiness that is not this endpoint's own does not admit a
/// dispatch.
#[test]
fn a_dispatch_is_decided_against_this_endpoints_own_channel() {
    let dir = temp();
    let mut store = store_at(dir.path(), CURSOR);
    let id = accept(&mut store, 1);
    let mut endpoint = endpoint(store);

    // MUTATION: a readiness decided under another execution policy —
    // other measured margins, and therefore another dispatch gate.
    let other = ready_of(descriptor_with(other_execution_policy()), CURSOR);
    let refused = endpoint.begin_run(id, &other);
    assert!(
        matches!(refused, Err(RunError::Policy)),
        "unexpected answer: {refused:?}",
    );

    // The control: the endpoint's own readiness admits it.
    assert!(
        matches!(
            expect_admission(endpoint.begin_run(id, &ready())),
            RunAdmission::Invoke(_)
        ),
        "this endpoint's own readiness admits the dispatch",
    );
}

// ── What a fault costs ────────────────────────────────────────────────

/// A backend fault ends the job and costs this client nothing.
#[tokio::test]
async fn a_backend_fault_is_not_the_clients_debt() {
    let dir = temp();
    let mut store = store_at(dir.path(), CURSOR);
    let id = accept(&mut store, 1);
    let service = serving(store);
    let backend = CountingBackend::new(Answer::Fault("the weights did not load"));

    let outcome = run_accepted_work(&service, &ready(), &backend, id).await;
    let Err(RunError::Backend(fault)) = outcome else {
        panic!("unexpected outcome: {outcome:?}");
    };
    assert!(fault.to_string().contains("the weights did not load"));
    assert_eq!(backend.calls(), 1);

    let (open_job, failed) = service
        .with_state(|state| {
            (
                state.jobs().next().is_some(),
                matches!(
                    state.terminals().next().map(|terminal| &terminal.outcome),
                    Some(TerminalOutcome::Failed { .. })
                ),
            )
        })
        .expect("the endpoint is reachable");
    assert!(!open_job, "the job was ended");
    assert!(
        failed,
        "the job rests at a failed terminal the provider bears itself",
    );
}

/// A transcript that is not this job's is not signed, and ends the job.
#[tokio::test]
async fn a_backend_that_answers_the_wrong_question_signs_nothing() {
    for answer in [Answer::ForAnotherRequest(2), Answer::UnderAnotherKey(0x23)] {
        let dir = temp();
        let mut store = store_at(dir.path(), CURSOR);
        let id = accept(&mut store, 1);
        let service = serving(store);
        let backend = CountingBackend::new(answer);

        let outcome = run_accepted_work(&service, &ready(), &backend, id).await;
        assert!(
            matches!(outcome, Err(RunError::Transcript(_))),
            "unexpected outcome: {outcome:?}",
        );
        assert_eq!(backend.calls(), 1);

        assert!(
            service
                .with_state(|state| state.jobs().next().is_none())
                .expect("the endpoint is reachable"),
            "the job was ended",
        );

        // Nothing was signed: reopening finds no result on the disk.
        drop(service);
        let recovered = store_at(dir.path(), CURSOR);
        assert!(recovered.state().jobs().next().is_none());
    }
}

// ── Fixture plumbing ──────────────────────────────────────────────────

fn expect_outcome(outcome: Result<RunOutcome, RunError>) -> RunOutcome {
    match outcome {
        Ok(outcome) => outcome,
        Err(error) => panic!("the run answers: {error}"),
    }
}

fn expect_admission(admission: Result<RunAdmission, RunError>) -> RunAdmission {
    match admission {
        Ok(admission) => admission,
        Err(error) => panic!("the run is admitted: {error}"),
    }
}

// ── Canonical chain objects, spelled out ──────────────────────────────

const FORMAT_VERSION: u8 = 1;
const TAG_BLOCK_HEIGHT: u8 = 1;
const TAG_FEES: u8 = 2;
const TAG_PARTIES: u8 = 3;
const TAG_EDGE: u8 = 5;
const TAG_BOND_LEASE: u8 = 31;
/// `Freeze | Adjudicated`: close-kind tags 3 and 4.
const WORK_PAYMENT_CLOSES: u8 = 0b0001_1000;
/// `Timeout` alone: close-kind tag 1.
const WORK_STAKE_CLOSES: u8 = 0b0000_0010;

struct EdgeBytes {
    value: u64,
    reserve: u64,
    maker: Key,
    taker: Key,
    terms: TermsHash,
    allowed: u8,
}

impl EdgeBytes {
    fn build(&self) -> Edge {
        let mut out = vec![FORMAT_VERSION, TAG_EDGE];
        out.extend_from_slice(&self.value.to_be_bytes());
        out.extend_from_slice(&self.reserve.to_be_bytes());
        out.extend_from_slice(&[FORMAT_VERSION, TAG_FEES]);
        for _ in 0..4 {
            out.extend_from_slice(&0_u64.to_be_bytes());
        }
        out.extend_from_slice(&[FORMAT_VERSION, TAG_BLOCK_HEIGHT]);
        out.extend_from_slice(&HORIZON.to_be_bytes());
        out.extend_from_slice(&[FORMAT_VERSION, TAG_PARTIES]);
        out.extend_from_slice(&self.maker.to_bytes());
        out.extend_from_slice(&self.taker.to_bytes());
        out.extend_from_slice(self.terms.as_bytes());
        out.push(self.allowed);
        match Edge::decode_exact(&out) {
            Ok(edge) => edge,
            Err(error) => panic!("the hand-written edge is canonical: {error:?}"),
        }
    }
}

fn lease_over(bond: EdgeId, payment: EdgeId) -> LeaseSlots {
    support::lease_over(
        bond,
        payment,
        payment_terms_hash(payment_terms()).as_bytes(),
        &payment_terms().private_policy_commitment,
        HORIZON,
        FORMAT_VERSION,
        TAG_BOND_LEASE,
    )
}

fn bond_object() -> Edge {
    EdgeBytes {
        value: STAKE,
        reserve: 0,
        maker: provider().party_key(),
        taker: client().party_key(),
        terms: Terms::work_stake_bond(bond_terms()).hash(),
        allowed: WORK_STAKE_CLOSES,
    }
    .build()
}

fn payment_object() -> Edge {
    EdgeBytes {
        value: PAYMENT_VALUE,
        reserve: PAYMENT_RESERVE,
        maker: client().party_key(),
        taker: provider().party_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build()
}
