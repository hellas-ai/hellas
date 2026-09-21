//! Delivering one job's answer: what leaves the provider, what it costs
//! the moment it does, and what the client will take.
//!
//! The happy path runs over a real multiplexed transport, so the request
//! is framed, routed by method id, decoded, and answered rather than
//! handed to a function. Every crash is a real one: the store is dropped
//! and reopened over its own files.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use futures::StreamExt as _;
use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, Parties, Payout, PendingSlot, Secp256k1Verifier, Terms, TermsHash,
    WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::pb::work::{
    DeliverResultRequest, DeliverResultResponse, WorkDelivered, WorkRefusalCode,
    deliver_result_response::Outcome,
};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PaidWorkError, PrivateRecord as _, delivery_request_digest, encode_transcript,
    generation_policy_digest, identity_source_digest, private_policy_commitment,
    propose_authorization, signing_hash, terminal_result, work_id,
};
use hellas_rpc::protocol::work_setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, WorkSetupError,
    payment_terms_hash,
};
use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
use hellas_rpc::{
    Application, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, ContentId, EvaluateRequest,
    OutputEventEnvelope, ProducerSigningKey, ProgramManifest, PublicKey,
};
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use hellas_wire::{DefaultClock, Dispatcher, StreamTransport};
use hellas_work::work::{
    BackendFault, ClientEndpoint, CloseEndpoint, DeliverError, PaidEvaluateBackend,
    PreparedEvaluateInput, ProviderEndpoint, RunError, RunOutcome, WorkService, fetch_result,
    run_accepted_work,
};
use hellas_work::work_store::{
    ChannelRecord, ChannelStore, JobPhase, JobState, Role, SetupOrigin, TerminalOutcome,
};
use tokio::sync::mpsc;

mod support;
use support::{advance, bond_edge, client, network, payload_at, payment_edge, provider, temp};

const EXPORTER: [u8; 32] = [0x5e; 32];

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
/// The finalized block both endpoints have processed through.
const CURSOR: u64 = 10;
/// The prompt this fixture's bundle carries, in tokens.
const PROMPT_TOKENS: u64 = 4;
/// A frame bound no legal delivery here comes close to.
const WIDE_FRAME: u32 = 262_144;

const fn deadlines() -> JobDeadlines {
    JobDeadlines {
        acceptance: 50,
        terminal: 100,
        payment: 200,
    }
}

/// The last height at which the signed delivery margin still fits
/// before the terminal deadline.
const LAST_RELEASE: u64 = deadlines().terminal - 2;

fn provider_producer() -> ProducerSigningKey {
    match ProducerSigningKey::from_secret_bytes([0x22; 32]) {
        Ok(key) => key,
        Err(error) => panic!("a fixed scalar is a producer key: {error}"),
    }
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

/// The execution policy, with the one bound a test varies as its
/// argument.
fn policy_with(max_encoded_result_frame: u32) -> PaidExecutionPolicyV1 {
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
        max_encoded_result_frame,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
        fixed_price: PRICE,
    }
}

fn execution_policy() -> PaidExecutionPolicyV1 {
    policy_with(WIDE_FRAME)
}

fn payment_values() -> EdgeValues {
    EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0))
}

fn descriptor_with(policy: PaidExecutionPolicyV1) -> WorkChannelDescriptor {
    let config = WorkChannelConfig {
        network: network(),
        payment_edge: payment_edge(),
        payment_terms: payment_terms(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: policy,
        expected_payment_values: payment_values(),
    };
    match WorkChannelDescriptor::open(config) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

fn ready_of(descriptor: &WorkChannelDescriptor, height: u64) -> ReadyChannel {
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

fn ready_at(height: u64) -> ReadyChannel {
    ready_of(&descriptor_with(execution_policy()), height)
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

fn store_at(root: &std::path::Path, ready: &ReadyChannel, role: Role, height: u64) -> ChannelStore {
    let mut store = match ChannelStore::open(
        root,
        ready.channel().clone(),
        settlement(),
        role,
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

fn authorization(policy: &PaidExecutionPolicyV1, nonce: u8) -> PaidJobAuthorizationV1 {
    match propose_authorization(
        ready_of(&descriptor_with(*policy), CURSOR).channel(),
        policy,
        &bundle(nonce),
        u64::from(nonce),
        deadlines(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    }
}

/// Puts one accepted job on both journals, and returns its `work_id`.
///
/// The acceptance exchange has its own file; these tests are about what
/// happens after both signatures exist.
fn accept(
    policy: &PaidExecutionPolicyV1,
    stores: &mut [&mut ChannelStore],
    nonce: u8,
) -> (Digest, PaidJobAuthorizationV1) {
    let authorization = authorization(policy, nonce);
    let ready = ready_of(&descriptor_with(*policy), CURSOR);
    let id = work_id(ready.channel(), &authorization);
    let Ok(prepared_input) = bundle(nonce).encode() else {
        panic!("the fixture bundle encodes");
    };
    for store in stores {
        commit(
            store,
            ChannelRecord::JobProposed {
                authorization,
                client_signature: client().sign(signing_hash(id)),
                prepared_input: prepared_input.clone(),
            },
        );
        commit(
            store,
            ChannelRecord::JobAccepted {
                work_id: id,
                provider_signature: provider().sign(signing_hash(id)),
            },
        );
    }
    (id, authorization)
}

// ── Transcripts and the backend that produces them ────────────────────

const ANSWER: [u32; 5] = [101, 102, 103, 104, 105];

fn transcript_for(request: &EvaluateRequest, answer: &[u32]) -> Vec<OutputEventEnvelope> {
    let key = provider_producer();
    let mut builder =
        EvaluateOutputTranscriptBuilder::new(input_commitment(request), request.assurance, &key);
    if let Err(error) = builder.push_token_delta(answer.to_vec()) {
        panic!("a non-empty delta pushes: {error}");
    }
    let usage = EvaluateUsage {
        input_units: PROMPT_TOKENS,
        output_units: answer.len() as u64,
    };
    let billable_units = match usage.billable_units() {
        Ok(units) => units,
        Err(error) => panic!("the fixture usage sums: {error}"),
    };
    match builder.finish(EvaluateTerminal {
        final_position: answer.len() as u64,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact: Digest::from_bytes([0x77; 32]),
        usage,
        billable_units,
    }) {
        Ok(events) => events,
        Err(error) => panic!("the fixture transcript finishes: {error}"),
    }
}

/// A backend that counts its calls and signs the fixture answer.
struct AnsweringBackend {
    calls: Arc<AtomicUsize>,
}

impl AnsweringBackend {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl PaidEvaluateBackend for AnsweringBackend {
    fn evaluate(
        &self,
        input: PreparedEvaluateInput,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let produced = transcript_for(input.evaluate_request(), &ANSWER);
        async move { Ok(produced) }
    }
}

/// Runs one accepted job to a signed, durable result.
async fn run_to_result(service: &WorkService, ready: &ReadyChannel, id: Digest) {
    let backend = AnsweringBackend::new();
    let outcome = run_accepted_work(service, ready, &backend, id).await;
    assert!(
        matches!(outcome, Ok(RunOutcome::Completed { .. })),
        "the fixture job completes: {outcome:?}",
    );
}

// ── Transport plumbing ────────────────────────────────────────────────

struct Pipe {
    out: mpsc::UnboundedSender<Bytes>,
    inbox: mpsc::UnboundedReceiver<Bytes>,
}

impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        let _ = self.out.send(bytes);
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.inbox.recv().await)
    }
}

/// The request a client signs on the fixture session for `work_id`.
///
/// A `work_id` is an identifier; this is what makes it an authority,
/// and only on the connection whose exporter it covers.
fn delivery_request(
    channel: &hellas_rpc::protocol::work::PaidChannel,
    work_id: Digest,
) -> DeliverResultRequest {
    DeliverResultRequest {
        work_id: work_id.as_bytes().to_vec(),
        client_signature: client()
            .sign(signing_hash(delivery_request_digest(
                channel, work_id, &EXPORTER,
            )))
            .as_bytes()
            .to_vec(),
    }
}

/// What the two ends of one live session both know.
///
/// A mux over a pair of in-memory pipes has no TLS of its own, so the
/// exporter is supplied here — which is what a QUIC connection does for
/// itself. Both halves are handed the same value, because that is the
/// one property the delivery binding rests on: the number is known to
/// exactly the two ends of one connection.
fn session() -> hellas_wire::TransportContext {
    hellas_wire::TransportContext {
        open_exporter: Some(EXPORTER),
        ..hellas_wire::TransportContext::default()
    }
}

fn transport_pair() -> (MuxTransport, MuxTransport) {
    let (to_server, server_inbox) = mpsc::unbounded_channel();
    let (to_client, client_inbox) = mpsc::unbounded_channel();
    let client = MuxTransport::spawn::<8, _, _>(
        MuxRole::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_server,
            inbox: client_inbox,
        },
        session(),
    );
    let server = MuxTransport::spawn::<8, _, _>(
        MuxRole::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_client,
            inbox: server_inbox,
        },
        session(),
    );
    (client, server)
}

fn serve(transport: MuxTransport, service: WorkService) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = WorkServer(service);
        while let Ok(Some(inbound)) = transport.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&server, inbound).await;
        }
    })
}

fn refusal_code(response: &DeliverResultResponse) -> WorkRefusalCode {
    match &response.outcome {
        Some(Outcome::Refused(refused)) => match WorkRefusalCode::try_from(refused.code) {
            Ok(code) => code,
            Err(error) => panic!("the refusal code is one of the six: {error}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ── One answer, over the wire, debited once ───────────────────────────

/// One job's answer crosses a real transport, lands on the client's
/// disk, and costs the provider exactly one job's delivery credit
/// however many times it is fetched.
#[tokio::test]
async fn one_answer_crosses_the_wire_and_is_debited_once() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, authorization) = accept(
        &execution_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    );

    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    run_to_result(&service, &ready, id).await;

    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };

    let delivered = match fetch_result(transport, &mut endpoint, &ready, id).await {
        Ok(delivery) => delivery,
        Err(error) => panic!("the fixture delivery completes: {error}"),
    };

    // The answer the client holds is the answer the provider computed,
    // rebuilt here from the delivered events rather than trusted.
    let Ok(events) = hellas_rpc::protocol::work::decode_transcript(&delivered.transcript, 1 << 20)
    else {
        panic!("the delivered transcript decodes");
    };
    assert_eq!(
        terminal_result(ready.channel(), &authorization, &events),
        Ok(delivered.result),
    );
    assert_eq!(delivered.result.work_id, id);

    // One debit on the provider's side, and the client is at Ready with
    // no verdict yet.
    {
        assert_eq!(
            service
                .with_state(|state| state.jobs().next().map(JobState::phase))
                .expect("the endpoint is reachable"),
            Some(JobPhase::Delivered)
        );
    }
    assert_eq!(
        endpoint.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Ready)
    );

    // The retry a client makes when its response was lost: the same
    // bytes, and no second debit.
    let (transport, second) = transport_pair();
    let serving_again = serve(second, service.clone());
    let again = match fetch_result(transport, &mut endpoint, &ready, id).await {
        Ok(delivery) => delivery,
        Err(error) => panic!("a replayed delivery completes: {error}"),
    };
    assert_eq!(again, delivered, "the same answer came back");

    assert_eq!(
        endpoint.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Ready),
        "a received result is ready, and a client has no marker past it",
    );

    serving.abort();
    serving_again.abort();
    drop(endpoint);
    drop(service);

    // And it is all on the disk: reopened from the files, the client's
    // journal still holds the result and the transcript it came with.
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let Some(job) = recovered.state().jobs().next() else {
        panic!("the job is still open");
    };
    assert_eq!(job.phase(), JobPhase::Ready);
    assert_eq!(
        job.result().map(|(result, _)| *result),
        Some(delivered.result)
    );
    assert_eq!(job.transcript(), delivered.transcript);
}

// ── The gate in front of the first byte ───────────────────────────────

/// A release whose measured margin no longer fits before the terminal
/// deadline sends nothing and debits nothing.
///
/// One block either side of the boundary the signed policy measures,
/// with the provider's processed height as the only thing varied.
#[tokio::test]
async fn the_last_height_the_delivery_margin_fits_is_the_last_that_may_release() {
    for (height, may_release) in [(LAST_RELEASE, true), (LAST_RELEASE + 1, false)] {
        // The job is accepted and run early, because the dispatch gate
        // has its own margin; only the release height is varied.
        let provider_root = temp();
        let early = ready_at(CURSOR);
        let mut provider_store = store_at(provider_root.path(), &early, Role::Provider, CURSOR);
        let (id, _) = accept(&execution_policy(), &mut [&mut provider_store], 1);
        let Ok(endpoint) = ProviderEndpoint::new(early.clone(), provider_store, provider()) else {
            panic!("the provider endpoint binds");
        };
        let service = WorkService::new(endpoint);
        run_to_result(&service, &early, id).await;
        drop(service);

        let ready = ready_at(height);
        let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, height);
        advance(&mut provider_store, height);
        let Ok(mut endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
        else {
            panic!("the provider endpoint binds at the release height");
        };
        let released = endpoint.deliver(&delivery_request(ready.channel(), id), &ready, &EXPORTER);
        if may_release {
            if let Err(error) = released {
                panic!("at {height} the margin still fits: {error}");
            }
            assert_eq!(
                endpoint.state().jobs().next().map(JobState::phase),
                Some(JobPhase::Delivered),
                "the release marked the job delivered",
            );
            continue;
        }
        let Err(DeliverError::Setup(WorkSetupError::DeliveryUnreachable { terminal, .. })) =
            released
        else {
            panic!("at {height} the margin does not fit: {released:?}");
        };
        assert_eq!(terminal, deadlines().terminal);
        assert_eq!(
            endpoint.state().jobs().next().map(JobState::phase),
            Some(JobPhase::Ready),
            "nothing was marked released",
        );
    }
}

/// A job with no signed result has no answer to release, and says so
/// as a wait rather than a refusal.
///
/// The difference is the whole of how a client learns the answer
/// exists: `NOT_READY` is the provider saying "ask again", and it is
/// what an accepted job in flight answers.
#[tokio::test]
async fn a_job_with_no_result_releases_nothing_yet() {
    let provider_root = temp();
    let ready = ready();
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&execution_policy(), &mut [&mut provider_store], 1);
    let Ok(endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(endpoint);

    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let response = match WorkClientImpl::new(transport)
        .deliver_result(delivery_request(ready.channel(), id))
        .await
    {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    serving.abort();
    assert_eq!(refusal_code(&response), WorkRefusalCode::NotReady);

    // The control: the same request, once the job has a result.
    run_to_result(&service, &ready, id).await;
    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let response = match WorkClientImpl::new(transport)
        .deliver_result(delivery_request(ready.channel(), id))
        .await
    {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    serving.abort();
    assert!(
        matches!(response.outcome, Some(Outcome::Delivered(_))),
        "a finished job delivers: {response:?}",
    );
}

/// An authenticated retry learns the durable failure; an unbound caller
/// cannot distinguish a retained terminal from another channel's work.
#[tokio::test]
async fn a_failed_job_returns_its_terminal_after_authentication() {
    struct FailingBackend;
    impl PaidEvaluateBackend for FailingBackend {
        async fn evaluate(
            &self,
            _input: PreparedEvaluateInput,
        ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
            Err(BackendFault::new("fixture content is unavailable"))
        }
    }

    let provider_root = temp();
    let ready = ready();
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&execution_policy(), &mut [&mut provider_store], 1);
    let endpoint = ProviderEndpoint::new(ready.clone(), provider_store, provider())
        .expect("the provider endpoint binds");
    let service = WorkService::new(endpoint);
    assert!(matches!(
        run_accepted_work(&service, &ready, &FailingBackend, id).await,
        Err(RunError::Backend(_))
    ));

    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let client = WorkClientImpl::new(transport);
    let mut unbound = delivery_request(ready.channel(), id);
    unbound.client_signature = provider()
        .sign(signing_hash(delivery_request_digest(
            ready.channel(),
            id,
            &EXPORTER,
        )))
        .as_bytes()
        .to_vec();
    let response = client
        .deliver_result(unbound)
        .await
        .expect("the call completes");
    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);
    let response = client
        .deliver_result(delivery_request(ready.channel(), id))
        .await
        .expect("the authenticated retry completes");
    assert_eq!(refusal_code(&response), WorkRefusalCode::Declined);
    let Some(Outcome::Refused(refusal)) = response.outcome else {
        panic!("the failed job is refused");
    };
    assert_eq!(refusal.reason, "the job ended permanently as failed");
    serving.abort();
    let _ = serving.await;
    drop(service);

    let recovered = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    assert!(recovered.state().job_by_id(id).is_none());
    assert_eq!(
        recovered
            .state()
            .terminal_by_id(id)
            .map(|terminal| &terminal.outcome),
        Some(&TerminalOutcome::Failed { code: 1 })
    );
    let endpoint = CloseEndpoint::new(recovered, provider())
        .expect("the recovered provider close endpoint binds without admission");
    let service = WorkService::close_only(endpoint);
    let checkpoint = service
        .with_state(|state| state.checkpoint())
        .expect("the restored state is available");
    assert!(matches!(
        service.deliver(&delivery_request(ready.channel(), id), &EXPORTER),
        Err(DeliverError::Terminated { outcome: "failed" })
    ));
    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let client = WorkClientImpl::new(transport);
    for authenticated in [false, true] {
        let mut request = delivery_request(ready.channel(), id);
        if !authenticated {
            request.client_signature = provider()
                .sign(signing_hash(delivery_request_digest(
                    ready.channel(),
                    id,
                    &EXPORTER,
                )))
                .as_bytes()
                .to_vec();
        }
        let expected = if authenticated {
            WorkRefusalCode::Declined
        } else {
            WorkRefusalCode::Invalid
        };
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.deliver_result(request.clone()),
        )
        .await
        .expect("a terminal does not wait for admission readiness")
        .expect("the restored endpoint answers");
        assert_eq!(refusal_code(&response), expected);
        let mut stream = client
            .stream_result(request)
            .await
            .expect("the stream opens");
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .expect("a terminal stream does not wait for admission readiness")
            .expect("the stream carries its refusal")
            .expect("the refusal is an application response");
        let Some(hellas_rpc::pb::work::work_stream_event::Outcome::Refused(refusal)) =
            event.outcome
        else {
            panic!("the restored failed job must not release plaintext");
        };
        assert_eq!(refusal.code, expected as i32);
        if authenticated {
            assert_eq!(refusal.reason, "the job ended permanently as failed");
        }
    }
    assert_eq!(
        service.with_state(|state| state.checkpoint()).unwrap(),
        checkpoint,
        "terminal diagnostics do not change the journal state",
    );
    serving.abort();
    let _ = serving.await;
}

/// A release the deadline has passed is `EXPIRED` on the wire, not a
/// wait.
///
/// The difference is what a client does next. `NOT_READY` says ask
/// again; `EXPIRED` says no later height makes this answer payable, and
/// a client that could not tell them apart would poll a job it can
/// never be paid for until its own deadline ran out too.
#[tokio::test]
async fn a_release_past_the_deadline_is_expired_on_the_wire() {
    let provider_root = temp();
    let early = ready_at(CURSOR);
    let mut provider_store = store_at(provider_root.path(), &early, Role::Provider, CURSOR);
    let (id, _) = accept(&execution_policy(), &mut [&mut provider_store], 1);
    let Ok(endpoint) = ProviderEndpoint::new(early.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(endpoint);
    run_to_result(&service, &early, id).await;
    drop(service);

    let late = LAST_RELEASE + 1;
    let ready = ready_at(late);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, late);
    advance(&mut provider_store, late);
    let Ok(endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds at the late height");
    };
    let service = WorkService::new(endpoint);

    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let response = match WorkClientImpl::new(transport)
        .deliver_result(delivery_request(ready.channel(), id))
        .await
    {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    serving.abort();
    assert_eq!(refusal_code(&response), WorkRefusalCode::Expired);
    assert_eq!(
        service
            .with_state(|state| state.jobs().next().map(JobState::phase))
            .expect("the endpoint is reachable"),
        Some(JobPhase::Ready),
        "nothing was released",
    );
}

/// A `work_id` that is not this channel's open job is refused, and a
/// `work_id` that is not 32 bytes never reaches a journal.
#[tokio::test]
async fn a_delivery_named_for_another_job_finds_nothing() {
    let provider_root = temp();
    let ready = ready();
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&execution_policy(), &mut [&mut provider_store], 1);
    let Ok(endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(endpoint);
    run_to_result(&service, &ready, id).await;

    let other = work_id(ready.channel(), &authorization(&execution_policy(), 2));
    assert_ne!(other, id);
    for (name, work_id) in [
        ("another job", other.as_bytes().to_vec()),
        ("a truncated id", other.as_bytes()[..31].to_vec()),
    ] {
        let (transport, server_transport) = transport_pair();
        let serving = serve(server_transport, service.clone());
        let response = match WorkClientImpl::new(transport)
            .deliver_result(DeliverResultRequest {
                work_id,
                client_signature: client()
                    .sign(signing_hash(delivery_request_digest(
                        ready.channel(),
                        other,
                        &EXPORTER,
                    )))
                    .as_bytes()
                    .to_vec(),
            })
            .await
        {
            Ok(response) => response,
            Err(status) => panic!("the call for {name} completes: {status}"),
        };
        serving.abort();
        assert!(
            matches!(response.outcome, Some(Outcome::Refused(_))),
            "{name} is refused: {response:?}",
        );
    }
    assert_eq!(
        service
            .with_state(|state| state.jobs().next().map(JobState::phase))
            .expect("the endpoint is reachable"),
        Some(JobPhase::Ready),
    );
}

// ── What the client will take ─────────────────────────────────────────

/// A provider signs no result it could not deliver inside the frame.
///
/// The bound is the only thing varied: the same job and the same
/// answer, under two channels that differ in
/// `max_encoded_result_frame` alone. The tight one refuses before the
/// signature exists — which is the point. A signed result the client
/// may not take is a result the client can never record a receipt for,
/// and a job that reaches its payment deadline with one on the
/// provider's disk is a job whose price the ending ledger would charge
/// to a client that was never able to have it.
#[tokio::test]
async fn a_provider_signs_no_result_the_frame_would_not_carry() {
    let generous = delivered_frame_len(WIDE_FRAME).await;
    let tight = u32::try_from(generous - 1).unwrap_or(u32::MAX);

    let provider_root = temp();
    let policy = policy_with(tight);
    let ready = ready_of(&descriptor_with(policy), CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&policy, &mut [&mut provider_store], 1);
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    let backend = AnsweringBackend::new();
    let outcome = run_accepted_work(&service, &ready, &backend, id).await;
    let Err(RunError::Record(PaidWorkError::OverEnvelope {
        field,
        actual,
        limit,
    })) = outcome
    else {
        panic!("an undeliverable result is not signed: {outcome:?}");
    };
    assert_eq!(field, "encoded result frame");
    assert_eq!(actual, generous);
    assert_eq!(limit, u64::from(tight));
    assert_eq!(
        service
            .with_state(|state| state.jobs().next().map(JobState::phase))
            .expect("the endpoint is reachable"),
        None,
        "and the job is over, at the provider's own cost",
    );
}

/// The client refuses a delivery larger than the frame it signed a
/// bound for.
///
/// The other end of the same bound, against a provider that does not
/// apply the one above. It is built by hand for exactly that reason:
/// an honest provider on this channel cannot produce these bytes, so
/// there is no exchange this could be driven through.
#[tokio::test]
async fn a_client_refuses_a_frame_over_the_bound_it_signed() {
    let generous = delivered_frame_len(WIDE_FRAME).await;
    let tight = u32::try_from(generous - 1).unwrap_or(u32::MAX);

    let client_root = temp();
    let provider_root = temp();
    let policy = policy_with(tight);
    let ready = ready_of(&descriptor_with(policy), CURSOR);
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&policy, &mut [&mut client_store, &mut provider_store], 1);

    // The delivery a provider that ignored its own bound would send:
    // the same job, the same answer, signed under the wide channel.
    let wide_policy = policy_with(WIDE_FRAME);
    let wide_ready = ready_of(&descriptor_with(wide_policy), CURSOR);
    let oversized = {
        let wide_root = temp();
        let mut wide_store = store_at(wide_root.path(), &wide_ready, Role::Provider, CURSOR);
        let (wide_id, _) = accept(&wide_policy, &mut [&mut wide_store], 1);
        let Ok(wide_endpoint) = ProviderEndpoint::new(wide_ready.clone(), wide_store, provider())
        else {
            panic!("the provider endpoint binds");
        };
        let wide_service = WorkService::new(wide_endpoint);
        run_to_result(&wide_service, &wide_ready, wide_id).await;
        let Ok(delivery) =
            wide_service.deliver(&delivery_request(wide_ready.channel(), wide_id), &EXPORTER)
        else {
            panic!("the wide delivery is released");
        };
        WorkDelivered {
            result: delivery.result.encode(),
            provider_signature: delivery.signature.as_bytes().to_vec(),
            transcript: delivery.transcript,
        }
    };

    let _ = provider_store;
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let refused = endpoint.receive(id, &ready, &oversized);
    let Err(DeliverError::OverFrame { actual, limit }) = refused else {
        panic!("an oversized frame is refused: {refused:?}");
    };
    assert_eq!(actual, generous);
    assert_eq!(limit, u64::from(tight));
    assert_eq!(
        endpoint.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Accepted),
        "nothing was recorded",
    );
}

/// Returns the encoded length of one legal delivery under `frame`.
async fn delivered_frame_len(frame: u32) -> u64 {
    use prost::Message as _;

    let provider_root = temp();
    let policy = policy_with(frame);
    let ready = ready_of(&descriptor_with(policy), CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&policy, &mut [&mut provider_store], 1);
    let Ok(endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(endpoint);
    run_to_result(&service, &ready, id).await;
    let Ok(delivery) = service.deliver(&delivery_request(ready.channel(), id), &EXPORTER) else {
        panic!("the fixture delivery is released");
    };
    WorkDelivered {
        result: delivery.result.encode(),
        provider_signature: delivery.signature.as_bytes().to_vec(),
        transcript: delivery.transcript,
    }
    .encoded_len() as u64
}

/// A transcript swapped in transit is not recorded, however well the
/// result beside it is signed.
///
/// This is the tamper the client's own rebuild exists for: the provider
/// signed the result honestly, and something between the two endpoints
/// replaced the events it summarises.
#[tokio::test]
async fn a_transcript_swapped_in_transit_is_not_recorded() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(
        &execution_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    );
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    run_to_result(&service, &ready, id).await;
    let Ok(delivery) = service.deliver(&delivery_request(ready.channel(), id), &EXPORTER) else {
        panic!("the fixture delivery is released");
    };

    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let honest = WorkDelivered {
        result: delivery.result.encode(),
        provider_signature: delivery.signature.as_bytes().to_vec(),
        transcript: delivery.transcript.clone(),
    };

    // MUTATION: the same signed result, beside a valid signed transcript
    // of a different answer to the same request.
    let Ok(other) = encode_transcript(&transcript_for(&evaluate_request(1), &[7, 7, 7])) else {
        panic!("the other transcript encodes");
    };
    assert_ne!(other, delivery.transcript);
    let tampered = WorkDelivered {
        transcript: other,
        ..honest.clone()
    };
    let refused = endpoint.receive(id, &ready, &tampered);
    assert!(
        matches!(refused, Err(DeliverError::Store(_))),
        "a swapped transcript is refused: {refused:?}",
    );
    assert_eq!(
        endpoint.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Accepted),
        "nothing was recorded",
    );

    // The control: the untampered delivery is taken.
    if let Err(error) = endpoint.receive(id, &ready, &honest) {
        panic!("the honest delivery records: {error}");
    }
    assert_eq!(
        endpoint.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Ready),
    );
}

/// A client that has not caught up to its own readiness records no
/// receipt.
#[tokio::test]
async fn a_client_behind_its_readiness_records_no_receipt() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(
        &execution_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    );
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    run_to_result(&service, &ready, id).await;
    let Ok(delivery) = service.deliver(&delivery_request(ready.channel(), id), &EXPORTER) else {
        panic!("the fixture delivery is released");
    };

    let delivered = WorkDelivered {
        result: delivery.result.encode(),
        provider_signature: delivery.signature.as_bytes().to_vec(),
        transcript: delivery.transcript,
    };
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };

    // MUTATION: a readiness decided at a later block than this endpoint
    // has processed. The blocks between are where a contest it must not
    // build evidence over would appear.
    let ahead = ready_at(CURSOR + 1);
    let refused = endpoint.receive(id, &ahead, &delivered);
    assert!(
        matches!(
            refused,
            Err(DeliverError::Setup(WorkSetupError::CursorBehind {
                cursor: CURSOR,
                height: 11
            }))
        ),
        "unexpected answer: {refused:?}",
    );

    // The control: the readiness this endpoint has caught up to.
    if let Err(error) = endpoint.receive(id, &ready, &delivered) {
        panic!("a caught-up client records the receipt: {error}");
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

// ── Who may be handed the answer ──────────────────────────────────────

/// A `work_id` is an identifier, and not an authority.
///
/// The exploit it closes: any peer that learned one — off a log, or by
/// having been offered the proposal — called `DeliverResult` and was
/// handed the plaintext, while the debit for it landed on the real
/// client's delivery credit and, at the payment deadline, on that
/// client's identity-wide loss. The request carried nothing else.
///
/// Now it carries a signature over the channel, this job, the action,
/// and the exporter of the connection it arrives on. A stranger has
/// none of the three things that would produce one: not the channel's
/// client key, not a signature for this action, and not one made on
/// this connection.
#[tokio::test]
async fn a_work_id_alone_releases_nothing() {
    let provider_root = temp();
    let ready = ready();
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(&execution_policy(), &mut [&mut provider_store], 1);
    let Ok(endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(endpoint);
    run_to_result(&service, &ready, id).await;

    let signed_with =
        |signer: &hellas_kernel::Secp256k1Signer, exporter: &[u8; 32]| DeliverResultRequest {
            work_id: id.as_bytes().to_vec(),
            client_signature: signer
                .sign(signing_hash(delivery_request_digest(
                    ready.channel(),
                    id,
                    exporter,
                )))
                .as_bytes()
                .to_vec(),
        };
    let cases = vec![
        (
            "a bare work id",
            DeliverResultRequest {
                work_id: id.as_bytes().to_vec(),
                client_signature: Vec::new(),
            },
        ),
        (
            "a signature that is not this channel's client's",
            signed_with(&provider(), &EXPORTER),
        ),
        (
            // The whole point of the exporter: the client's own
            // request, lifted off the connection it was made on.
            "the client's own signature from another connection",
            signed_with(&client(), &[0xa1; 32]),
        ),
    ];

    for (name, request) in cases {
        let (transport, server_transport) = transport_pair();
        let serving = serve(server_transport, service.clone());
        let response = match WorkClientImpl::new(transport).deliver_result(request).await {
            Ok(response) => response,
            Err(status) => panic!("the call for {name} completes: {status}"),
        };
        serving.abort();
        assert_eq!(
            refusal_code(&response),
            WorkRefusalCode::Invalid,
            "{name} releases nothing: {response:?}",
        );
        assert_eq!(
            service
                .with_state(|state| state.jobs().next().map(JobState::phase))
                .expect("the endpoint is reachable"),
            Some(JobPhase::Ready),
            "{name} leaves the answer where it was",
        );
    }

    // The control: the same job, the same connection, the client's own
    // signature over this connection's exporter.
    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let response = match WorkClientImpl::new(transport)
        .deliver_result(delivery_request(ready.channel(), id))
        .await
    {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    serving.abort();
    assert!(
        matches!(response.outcome, Some(Outcome::Delivered(_))),
        "the client is handed its own answer: {response:?}",
    );
}

/// A transport that exports nothing binds nothing, and releases
/// nothing.
///
/// There is no fallback here and there must not be: a connection that
/// cannot export keying material is one on which no signature can be
/// tied to *this* call, so every request over it is a bearer request
/// again.
#[tokio::test]
async fn a_transport_without_an_exporter_delivers_nothing() {
    let provider_root = temp();
    let client_root = temp();
    let ready = ready();
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let (id, _) = accept(
        &execution_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    );
    let Ok(endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider()) else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(endpoint);
    run_to_result(&service, &ready, id).await;

    let (to_server, server_inbox) = mpsc::unbounded_channel();
    let (to_client, client_inbox) = mpsc::unbounded_channel();
    let bare = |out, inbox| {
        MuxTransport::spawn::<8, _, _>(
            MuxRole::Client,
            DefaultClock,
            MuxConfig::default(),
            Pipe { out, inbox },
            hellas_wire::TransportContext::default(),
        )
    };
    let client_transport = bare(to_server, client_inbox);
    let server_transport = MuxTransport::spawn::<8, _, _>(
        MuxRole::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_client,
            inbox: server_inbox,
        },
        hellas_wire::TransportContext::default(),
    );
    let serving = serve(server_transport, service.clone());

    // The client holds the accepted job and still cannot ask for it.
    let Ok(mut client_endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let refused = fetch_result(client_transport, &mut client_endpoint, &ready, id).await;
    serving.abort();
    assert!(
        matches!(refused, Err(DeliverError::Unbindable)),
        "an unbindable connection asks for nothing: {refused:?}",
    );
    assert_eq!(
        service
            .with_state(|state| state.jobs().next().map(JobState::phase))
            .expect("the endpoint is reachable"),
        Some(JobPhase::Ready),
        "nothing was released",
    );
}

/// A real signed prefix reaches the client while computation is blocked;
/// reserving credit precedes that byte, and final delivery remains durable.
#[tokio::test]
async fn live_prefix_precedes_terminal_and_reserves_delivery_credit() {
    use hellas_work::work::{PaidProgress, fetch_result_stream};
    struct PausedBackend {
        release: Arc<tokio::sync::Notify>,
    }
    impl PaidEvaluateBackend for PausedBackend {
        async fn evaluate(
            &self,
            input: PreparedEvaluateInput,
        ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
            Ok(transcript_for(input.evaluate_request(), &ANSWER))
        }
        async fn evaluate_stream(
            &self,
            input: PreparedEvaluateInput,
            progress: PaidProgress,
        ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
            let transcript = transcript_for(input.evaluate_request(), &ANSWER);
            progress(transcript[0].clone())?;
            self.release.notified().await;
            Ok(transcript)
        }
    }
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let (id, _) = accept(
        &execution_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    );
    let service =
        WorkService::new(ProviderEndpoint::new(ready.clone(), provider_store, provider()).unwrap());
    let release = Arc::new(tokio::sync::Notify::new());
    let backend = PausedBackend {
        release: release.clone(),
    };
    let running_service = service.clone();
    let running_ready = ready.clone();
    let computation = tokio::spawn(async move {
        run_accepted_work(&running_service, &running_ready, &backend, id).await
    });
    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let mut endpoint = ClientEndpoint::new(ready.clone(), client_store, client()).unwrap();
    let mut prefixes = 0;
    let delivered = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fetch_result_stream(transport, &mut endpoint, &ready, id, |_| {
            assert!(
                !computation.is_finished(),
                "live tokens must not await completion"
            );
            assert_eq!(
                service
                    .with_state(|state| state.job_by_id(id).map(JobState::phase))
                    .unwrap(),
                Some(JobPhase::Streaming)
            );
            prefixes += 1;
            release.notify_one();
            Ok(())
        }),
    )
    .await
    .expect("stream must make progress")
    .expect("signed delivery succeeds");
    assert_eq!(prefixes, 1);
    assert!(matches!(
        computation.await.unwrap(),
        Ok(RunOutcome::Completed { .. })
    ));
    assert_eq!(
        endpoint.state().job_by_id(id).unwrap().phase(),
        JobPhase::Ready
    );
    assert_eq!(
        service
            .with_state(|state| state.job_by_id(id).map(JobState::phase))
            .unwrap(),
        Some(JobPhase::Delivered)
    );
    serving.abort();
    let _ = serving.await;
    drop(service);
    drop(endpoint);
    let recovered = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let job = recovered.state().job_by_id(id).unwrap();
    assert_eq!(job.phase(), JobPhase::Delivered);
    assert_eq!(job.transcript(), delivered.transcript);
}

#[tokio::test]
async fn paid_stream_checks_status_and_terminal_shape_before_recording_delivery() {
    use hellas_rpc::pb::work::{WorkStreamEvent, work_stream_event};
    use hellas_rpc::services::work::StreamResult;
    use hellas_wire::{WireCode, WireStatus};
    use hellas_work::work::fetch_result_stream;

    for (terminal_count, status) in [
        (0, WireCode::Unavailable),
        (1, WireCode::Unavailable),
        (2, WireCode::Ok),
        (1, WireCode::Ok),
    ] {
        let client_root = temp();
        let provider_root = temp();
        let ready = ready();
        let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
        let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
        let (id, _) = accept(
            &execution_policy(),
            &mut [&mut client_store, &mut provider_store],
            1,
        );
        let service = WorkService::new(
            ProviderEndpoint::new(ready.clone(), provider_store, provider()).unwrap(),
        );
        run_to_result(&service, &ready, id).await;
        let delivered = service
            .deliver(&delivery_request(ready.channel(), id), &EXPORTER)
            .unwrap();
        let event = WorkStreamEvent {
            outcome: Some(work_stream_event::Outcome::Delivered(WorkDelivered {
                result: delivered.result.encode(),
                provider_signature: delivered.signature.as_bytes().to_vec(),
                transcript: delivered.transcript.clone(),
            })),
        };
        let (transport, server_transport) = transport_pair();
        let serving = tokio::spawn(async move {
            let inbound = server_transport.accept().await.unwrap().unwrap();
            hellas_rpc::call::dispatch_server_streaming::<MuxTransport, StreamResult, _, _, _>(
                inbound,
                move |_| async move {
                    if terminal_count == 0 {
                        return Err(WireStatus::new(status, "not ready"));
                    }
                    let mut events = vec![Ok(event); terminal_count];
                    if status != WireCode::Ok {
                        events.push(Err(WireStatus::new(status, "delivery interrupted")));
                    }
                    Ok(futures::stream::iter(events))
                },
            )
            .await
            .unwrap();
        });
        let mut endpoint = ClientEndpoint::new(ready.clone(), client_store, client()).unwrap();
        let mut prefixes = 0;
        let result = fetch_result_stream(transport, &mut endpoint, &ready, id, |_| {
            prefixes += 1;
            Ok(())
        })
        .await;
        serving.await.unwrap();
        if status != WireCode::Ok {
            assert!(matches!(result, Err(DeliverError::Transport(error)) if error.code == status));
        } else if terminal_count != 1 {
            assert!(matches!(
                result,
                Err(DeliverError::Malformed("event after terminal result"))
            ));
        } else {
            assert_eq!(result.unwrap(), delivered);
            assert_eq!(prefixes, 1);
            assert_eq!(
                endpoint.state().job_by_id(id).unwrap().phase(),
                JobPhase::Ready
            );
            continue;
        }
        assert_eq!(prefixes, 0);
        assert_eq!(
            endpoint.state().job_by_id(id).unwrap().phase(),
            JobPhase::Accepted
        );
        let (transport, server_transport) = transport_pair();
        let serving = serve(server_transport, service.clone());
        let recovered = fetch_result_stream(transport, &mut endpoint, &ready, id, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(recovered, delivered);
        serving.abort();
        let _ = serving.await;
    }
}
