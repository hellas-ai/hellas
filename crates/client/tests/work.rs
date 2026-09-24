//! One paid job, end to end, from the client's side: proposed,
//! computed by a real provider endpoint, delivered, checked by an
//! engine that never speaks to the provider, and paid for.
//!
//! Both endpoints are real and hold real journals, and the exchange runs
//! over a real multiplexed transport, framed and routed by method id.
//! The one double is the reexecution engine, because this repository has
//! no second implementation of the model to plug in — so what these
//! tests establish is the orchestration around the check and the
//! consequences of its verdict, not that any particular model
//! reproduces.

#![cfg(feature = "work")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use hellas_client::work::payment::pay_for_result;
use hellas_client::work::reproduce::{ReproduceFault, Reproduced, Reproducer};
use hellas_client::work::{
    CheckedResult, CollectError, CollectOutcome, CollectResultError, CollectResultOutcome,
    collect_checked_result, collect_result,
};
use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, NetworkId, Parties, Payout, PendingSlot, RegistryChunk, RegistryNamespace,
    RegistryRecordTag, Secp256k1Signer, Secp256k1Verifier, Terms, TermsHash, WorkPaymentSettlement,
    WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextExecutionId, TextPolicy, TokenIds, completed_text,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    generation_policy_digest, identity_source_digest, private_policy_commitment,
    propose_authorization, signing_hash, work_id,
};
use hellas_rpc::protocol::work_setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use hellas_rpc::services::work::WorkServer;
use hellas_rpc::{
    Application, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, ContentId, EvaluateRequest,
    OutputEventEnvelope, ProducerSigningKey, ProgramManifest, PublicKey,
};
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use hellas_wire::{DefaultClock, Dispatcher, StreamTransport};
use hellas_work::work::{
    BackendFault, ClientEndpoint, PaidWorkBackend, PreparedEvaluateInput, ProviderEndpoint,
    RunOutcome, WorkService, run_accepted_work,
};
use hellas_work::work_close::{BlockSourceError, FinalizedBlocks, FinalizedWork, observe};
use hellas_work::work_store::{
    ChannelRecord, ChannelStore, JobPhase, JobState, Role, SetupOrigin, TerminalOutcome,
};
use tokio::sync::mpsc;

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

const fn deadlines() -> JobDeadlines {
    JobDeadlines {
        acceptance: 50,
        terminal: 100,
        payment: 200,
    }
}

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-test") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn client() -> Secp256k1Signer {
    signer(0x21)
}

fn provider() -> Secp256k1Signer {
    signer(0x22)
}

fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn provider_producer() -> ProducerSigningKey {
    match ProducerSigningKey::from_secret_bytes([0x22; 32]) {
        Ok(key) => key,
        Err(error) => panic!("a fixed scalar is a producer key: {error}"),
    }
}

fn bond_edge() -> EdgeId {
    EdgeId::from_bytes([0x11; EdgeId::LENGTH])
}

fn payment_edge() -> EdgeId {
    EdgeId::from_bytes([0x22; EdgeId::LENGTH])
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
        execution_policy: policy.into(),
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

fn ready() -> ReadyChannel {
    ready_of(&descriptor_with(execution_policy()), CURSOR)
}

fn settlement() -> WorkPaymentSettlement {
    let Some(settlement) = work_payment_settlement(payment_values(), OMISSION_BOND) else {
        panic!("a funded edge prices both exits");
    };
    settlement
}

fn temp() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("a temporary directory: {error}"),
    }
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

/// The payload digest of the synthetic block at `height`.
///
/// A cursor is contiguous, so a fixture that moves it has to name a
/// chain rather than repeat one digest: each block's parent is the last
/// block's payload, and the watcher refuses anything else.
fn payload_at(height: u64) -> [u8; 32] {
    let mut payload = [0xc0; 32];
    for (slot, byte) in payload.iter_mut().zip(height.to_be_bytes()) {
        *slot = byte;
    }
    payload
}

/// Where the fixture channel was opened: the genesis block of the
/// synthetic chain above, so a store starts with a clock and `advance`
/// reads block one next.
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
fn advance(store: &mut ChannelStore, height: u64) {
    let mut next = store.state().cursor().0.saturating_add(1);
    while next <= height {
        let block = FinalizedWork {
            height: next,
            parent: payload_at(next.saturating_sub(1)),
            payload: payload_at(next),
            txs: Vec::new(),
        };
        if let Err(error) = observe(store, &block, &Secp256k1Verifier::new()) {
            panic!("the fixture block applies: {error}");
        }
        next = next.saturating_add(1);
    }
}

fn commit(store: &mut ChannelStore, record: ChannelRecord) {
    if let Err(error) = store.commit(record, &Secp256k1Verifier::new()) {
        panic!("the fixture record commits: {error}");
    }
}

// ── The prepared inputs a job executes from ───────────────────────────

fn manifest() -> ProgramManifest {
    ProgramManifest::new(
        Application::new(CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR)
            .expect("the causal-LM application identity is valid"),
        ContentId::from_bytes([0x16; 32]),
    )
}

/// The prompt every job here runs on. It is the whole input, because
/// this profile starts from an identity artifact.
const PROMPT: [u32; 4] = [9, 8, 7, 6];

fn prompt_tokens() -> TokenIds {
    TokenIds::from(PROMPT.to_vec())
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
    // The artifact a provider's own store records for this execution.
    // A placeholder would do for the tests that never reexecute; here
    // it would make an honest provider look wrong, because the answer
    // digest binds this field and the re-execution derives it.
    let text_artifact = completed_text(
        TextExecutionId::from_digest(request.text_execution),
        &PROMPT,
        answer,
    )
    .artifact
    .output_id()
    .digest();
    match builder.finish(EvaluateTerminal {
        final_position: answer.len() as u64,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact,
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

impl PaidWorkBackend for AnsweringBackend {
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

/// What the two ends of one live session both know.
///
/// A mux over a pair of in-memory pipes has no TLS of its own, so the
/// exporter is supplied here — which is what a QUIC connection does for
/// itself. Both halves are handed the same value, because that is the
/// one property the delivery binding rests on: the number is known to
/// exactly the two ends of one connection.
fn session() -> hellas_wire::TransportContext {
    hellas_wire::TransportContext {
        open_exporter: Some([0x5e; 32]),
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

// ── The re-execution engine double ────────────────────────────────────

/// An engine that answers with fixed tokens, or refuses.
///
/// It is handed the client's own journal-held bundle and has no other
/// input, which is the property that makes it stand in for a separate
/// implementation at all: nothing it can see comes from the provider's
/// answer.
struct FixedEngine {
    answer: Result<Reproduced, ReproduceFault>,
}

impl FixedEngine {
    fn answering(tokens: &[u32]) -> Self {
        Self {
            answer: Ok(Reproduced {
                output_token_ids: tokens.to_vec(),
                stop_reason: EvaluateStopReason::STOP_TOKEN,
                matched_stop_token_id: Some(1),
            }),
        }
    }

    fn agreeing() -> Self {
        Self::answering(&ANSWER)
    }

    fn failing(reason: &str) -> Self {
        Self {
            answer: Err(ReproduceFault::Engine(reason.to_string())),
        }
    }
}

impl Reproducer for FixedEngine {
    async fn reproduce(&self, _bundle: &PreparedPaidInputV1) -> Result<Reproduced, ReproduceFault> {
        self.answer.clone()
    }
}

/// A finalized-block source over the same synthetic empty chain the
/// fixture's `advance` walks, up to `tip`.
///
/// The client's post-answer catch-up reads this. A `tip` at the fixture
/// cursor makes the catch-up a no-op; a `tip` past a deadline is a
/// reproduction that stalled while the chain moved on.
struct Blocks {
    tip: u64,
}

impl FinalizedBlocks for Blocks {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(Some(self.tip))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        if height == 0 || height > self.tip {
            return Ok(None);
        }
        Ok(Some(FinalizedWork {
            height,
            parent: payload_at(height.saturating_sub(1)),
            payload: payload_at(height),
            txs: Vec::new(),
        }))
    }
}

/// A source that yields no block past the fixture cursor, so the
/// post-answer catch-up moves nothing.
fn still() -> Blocks {
    Blocks { tip: CURSOR }
}

/// The same synthetic chain, with a tip a [`LatchedEngine`] moves while
/// it is being awaited.
///
/// This is what makes the barrier test a test of *order*: the tip is at
/// the fixture cursor until the reproduction actually runs, so a
/// catch-up moved in front of the reproduction reads a chain that has
/// not moved yet.
struct SharedBlocks {
    tip: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl FinalizedBlocks for SharedBlocks {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(Some(self.tip.load(std::sync::atomic::Ordering::SeqCst)))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        if height == 0 || height > self.tip.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(None);
        }
        Ok(Some(FinalizedWork {
            height,
            parent: payload_at(height.saturating_sub(1)),
            payload: payload_at(height),
            txs: Vec::new(),
        }))
    }
}

/// An engine that agrees with the provider's answer — and that is the
/// latch: the moment it runs, the finalized tip it shares with
/// [`SharedBlocks`] jumps to `advance_to`. A reproduction that stalls
/// while the chain moves on, compressed into one call.
struct LatchedEngine {
    tip: std::sync::Arc<std::sync::atomic::AtomicU64>,
    advance_to: u64,
}

impl Reproducer for LatchedEngine {
    async fn reproduce(&self, _bundle: &PreparedPaidInputV1) -> Result<Reproduced, ReproduceFault> {
        self.tip
            .store(self.advance_to, std::sync::atomic::Ordering::SeqCst);
        Ok(Reproduced {
            output_token_ids: ANSWER.to_vec(),
            stop_reason: EvaluateStopReason::STOP_TOKEN,
            matched_stop_token_id: Some(1),
        })
    }
}

// ── The whole path ────────────────────────────────────────────────────

/// One job, proposed and computed and delivered and checked, and a
/// client journal that ends in the phase an invoice may be asked from.
#[tokio::test]
async fn a_checked_answer_is_the_only_thing_that_reaches_the_matched_phase() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let engine = FixedEngine::agreeing();

    // Before the provider has run anything, asking is a wait rather than
    // a failure, and nothing is recorded.
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let waiting =
        collect_checked_result(transport, &mut endpoint, &ready, &still(), &engine, id).await;
    serving.abort();
    assert!(
        matches!(waiting, Ok(CollectOutcome::NotReady { .. })),
        "unexpected outcome: {waiting:?}",
    );
    assert_eq!(
        endpoint.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Accepted),
    );

    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let collected =
        collect_checked_result(transport, &mut endpoint, &ready, &still(), &engine, id).await;
    serving.abort();
    let Ok(CollectOutcome::Checked(CheckedResult { result, transcript })) = collected else {
        panic!("the checked answer is collected: {collected:?}");
    };
    assert_eq!(result.work_id, id);
    assert!(!transcript.is_empty());
    assert_eq!(
        endpoint.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Matched),
    );

    // A second call is the same call: the provider answers from its
    // spool at no second delivery debit, and the verdict is the same
    // verdict.
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let again =
        collect_checked_result(transport, &mut endpoint, &ready, &still(), &engine, id).await;
    serving.abort();
    assert!(
        matches!(again, Ok(CollectOutcome::Checked(_))),
        "unexpected outcome: {again:?}",
    );
    {
        assert_eq!(
            service
                .with_state(|state| state.jobs().next().map(JobState::phase))
                .expect("the endpoint is reachable"),
            Some(JobPhase::Delivered),
            "the provider delivered the plaintext once",
        );
    }

    // And it is on the disk: reopened from the files by a process that
    // saw none of this, the job is still checked.
    drop(endpoint);
    drop(service);
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let Some(job) = recovered.state().jobs().next() else {
        panic!("the job is still open");
    };
    assert_eq!(job.phase(), JobPhase::Matched);
    assert_eq!(job.result().map(|(result, _)| *result), Some(result));
}

/// The whole of the client's side: a checked answer becomes a payment
/// the provider has admitted.
///
/// What each side ends holding is asserted from its own journal, and
/// the client's is asserted from a reopened file — a process that saw
/// none of this and knows only what reached the disk.
#[tokio::test]
async fn a_checked_answer_becomes_a_payment_the_provider_admitted() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let engine = FixedEngine::agreeing();
    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let collected =
        collect_checked_result(transport, &mut endpoint, &ready, &still(), &engine, id).await;
    serving.abort();
    assert!(
        matches!(collected, Ok(CollectOutcome::Checked(_))),
        "the answer is checked: {collected:?}",
    );

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let credited = pay_for_result(transport, &mut endpoint, id).await;
    serving.abort();
    let Ok(credited) = credited else {
        panic!("the checked answer is paid for: {credited:?}");
    };
    assert_eq!(credited, PRICE, "one job at its authorized price");

    // The provider has the certificate and has let the job's credit go,
    // in that order and in one record.
    {
        let state = service
            .with_state(|state| state.clone())
            .expect("the endpoint is reachable");
        assert_eq!(state.ledger().credited_cumulative(), PRICE);
        assert_eq!(state.max_executable_certificate(), PRICE);
        assert!(
            state.jobs().next().is_none(),
            "the job is closed by its payment"
        );
    }

    drop(endpoint);
    drop(service);
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let state = recovered.state();
    assert!(state.jobs().next().is_none());
    assert_eq!(state.ledger().credited_cumulative(), PRICE);
    let Some(payment) = state.last_payment() else {
        panic!("the payment is on the disk");
    };
    assert_eq!(payment.work_id, id);
    assert_eq!(payment.certificate.earned_cumulative(), PRICE);
}

/// The normal paid-work path authenticates and pays a provider result
/// without constructing or invoking a reproduction engine.
#[tokio::test]
async fn an_authenticated_answer_is_paid_without_reexecution() {
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
    let provider_endpoint = ProviderEndpoint::new(ready.clone(), provider_store, provider())
        .expect("the provider endpoint binds");
    let service = WorkService::new(provider_endpoint);
    let mut endpoint = ClientEndpoint::new(ready.clone(), client_store, client())
        .expect("the client endpoint binds");
    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let collected = collect_result(transport, &mut endpoint, &ready, &still(), id).await;
    serving.abort();
    assert!(
        matches!(collected, Ok(CollectResultOutcome::Collected(_))),
        "the authenticated answer is collected: {collected:?}",
    );
    assert_eq!(
        endpoint.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Ready),
        "ordinary collection does not claim an independent match",
    );

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let credited = pay_for_result(transport, &mut endpoint, id).await;
    serving.abort();
    assert_eq!(credited.ok(), Some(PRICE));
    assert_eq!(endpoint.state().ledger().credited_cumulative(), PRICE);
}

/// Ordinary collection uses the same post-delivery finalized-height
/// barrier as the checked path and will not return a stale payable result.
#[tokio::test]
async fn ordinary_collection_refuses_a_stale_payment_boundary() {
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
    let provider_endpoint = ProviderEndpoint::new(ready.clone(), provider_store, provider())
        .expect("the provider endpoint binds");
    let service = WorkService::new(provider_endpoint);
    let mut endpoint = ClientEndpoint::new(ready.clone(), client_store, client())
        .expect("the client endpoint binds");
    run_to_result(&service, &ready, id).await;

    let stale = Blocks {
        tip: authorization.payment_deadline.saturating_add(1),
    };
    let (transport, server) = transport_pair();
    let serving = serve(server, service);
    let collected = collect_result(transport, &mut endpoint, &ready, &stale, id).await;
    serving.abort();
    assert!(
        matches!(collected, Err(CollectResultError::Stale { .. })),
        "the stale result is refused: {collected:?}",
    );
    assert!(endpoint.state().last_payment().is_none());
}

/// A payment signed before a crash is re-sent after it, and credited
/// once.
///
/// The client dies between fsyncing its certificate and sending it —
/// the one window where its journal holds a payment no provider has
/// seen. What comes back is not a second signature: it is the same
/// bytes, off the disk of a process that never made them.
#[tokio::test]
async fn a_payment_signed_before_a_crash_is_re_sent_after_it() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let collected = collect_checked_result(
        transport,
        &mut endpoint,
        &ready,
        &still(),
        &FixedEngine::agreeing(),
        id,
    )
    .await;
    serving.abort();
    assert!(
        matches!(collected, Ok(CollectOutcome::Checked(_))),
        "the answer is checked: {collected:?}",
    );

    // Signed, and then the process is gone before a byte of the
    // certificate leaves it.
    let signed = endpoint.pay(id);
    assert!(signed.is_ok(), "the client signs its payment: {signed:?}");
    drop(endpoint);
    {
        assert_eq!(
            service
                .with_state(|state| state.ledger().credited_cumulative())
                .expect("the endpoint is reachable"),
            0,
            "and the provider has seen nothing",
        );
    }

    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), recovered, client()) else {
        panic!("the client endpoint rebinds");
    };
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let credited = pay_for_result(transport, &mut endpoint, id).await;
    serving.abort();
    assert_eq!(credited.ok(), Some(PRICE));
    assert_eq!(
        service
            .with_state(|state| state.ledger().credited_cumulative())
            .expect("the endpoint is reachable"),
        PRICE,
    );
}

/// A refuted answer closes the job at a permanent refuted terminal and
/// is not paid for.
///
/// The client's own engine ran and disagreed, so this is a refutation
/// rather than a failed check — and the refutation is durable: the one
/// job the channel admits is over, and asking to pay for it signs
/// nothing.
#[tokio::test]
async fn a_refuted_answer_closes_the_job_and_is_not_paid_for() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    run_to_result(&service, &ready, id).await;

    // The result is fetched and journaled, and the client's own engine
    // reproduces a different answer.
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    // One token of the provider's answer, changed: the engine's answer is
    // the only thing this test varies.
    let mut other = ANSWER;
    other[2] = 999;
    let refuted = collect_checked_result(
        transport,
        &mut endpoint,
        &ready,
        &still(),
        &FixedEngine::answering(&other),
        id,
    )
    .await;
    serving.abort();
    assert!(
        matches!(refuted, Err(CollectError::Refuted { .. })),
        "the engine refutes the answer: {refuted:?}",
    );
    // The refutation is durable and permanent: the one job rests at a
    // refuted terminal, so it is closed rather than merely unpaid.
    assert!(
        endpoint.state().jobs().next().is_none(),
        "the refuted job is closed"
    );
    assert!(
        matches!(
            endpoint
                .state()
                .terminals()
                .next()
                .map(|terminal| &terminal.outcome),
            Some(TerminalOutcome::Refuted { .. })
        ),
        "the job rests at a refuted terminal",
    );

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let paid = pay_for_result(transport, &mut endpoint, id).await;
    serving.abort();
    assert!(paid.is_err(), "a refuted answer is not paid for: {paid:?}");
    assert!(
        endpoint.state().last_payment().is_none(),
        "and nothing was signed",
    );
    {
        assert_eq!(
            service
                .with_state(|state| state.ledger().credited_cumulative())
                .expect("the endpoint is reachable"),
            0,
        );
    }
}

/// A refutation stays a refutation across a restart, and no engine that
/// agrees afterwards can reopen it.
///
/// The provider here is honest in every checkable way: its result is
/// signed over its own transcript, its transcript is signed under the
/// channel's provider key, and its delivery is timely. The only thing
/// wrong with it is the answer, and nothing but a re-execution can say
/// so — and once the re-execution has said it, the one job is closed for
/// good.
#[tokio::test]
async fn a_refutation_is_permanent_across_a_restart() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };

    // MUTATION: the engine's answer differs from the provider's in one
    // token. Everything else about the exchange is unchanged.
    let mut other = ANSWER;
    other[2] = 999;
    let engine = FixedEngine::answering(&other);

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let refused =
        collect_checked_result(transport, &mut endpoint, &ready, &still(), &engine, id).await;
    serving.abort();
    assert!(
        matches!(refused, Err(CollectError::Refuted { .. })),
        "unexpected outcome: {refused:?}",
    );
    assert!(
        endpoint.state().jobs().next().is_none(),
        "the refuted job is closed"
    );
    drop(endpoint);

    // Reopened by a process that saw none of this, the job is still
    // refuted: the terminal is on the disk, and it is permanent.
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    assert!(
        matches!(
            recovered
                .state()
                .terminals()
                .next()
                .map(|terminal| &terminal.outcome),
            Some(TerminalOutcome::Refuted { .. })
        ),
        "a restart keeps the refutation",
    );
    assert!(
        recovered.state().jobs().next().is_none(),
        "and does not reopen the job",
    );

    // And an engine that agrees afterwards cannot reopen it: the channel
    // admits one job for its whole life, and that job is over. Collecting
    // again finds no job to collect.
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), recovered, client()) else {
        panic!("the client endpoint binds");
    };
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let again = collect_checked_result(
        transport,
        &mut endpoint,
        &ready,
        &still(),
        &FixedEngine::agreeing(),
        id,
    )
    .await;
    serving.abort();
    assert!(
        again.is_err(),
        "a refuted job cannot be re-collected: {again:?}",
    );
    assert!(
        endpoint.state().last_payment().is_none(),
        "and it is still never paid for",
    );
}

/// An engine that cannot run says so, and its silence is not a verdict
/// either way.
#[tokio::test]
async fn an_engine_that_cannot_run_records_no_verdict() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };

    let engine = FixedEngine::failing("the weights did not load");
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let unchecked =
        collect_checked_result(transport, &mut endpoint, &ready, &still(), &engine, id).await;
    serving.abort();

    let Err(CollectError::Unchecked(ReproduceFault::Engine(reason))) = unchecked else {
        panic!("an engine fault is reported as one: {unchecked:?}");
    };
    assert!(reason.contains("the weights did not load"), "{reason}");
    assert_eq!(
        endpoint.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Ready),
        "a check that did not happen is not a check that passed",
    );
}

/// A reproduction that stalled past the payment deadline refuses to pay
/// at the barrier.
///
/// The post-answer catch-up is the barrier. While the client's own
/// re-execution runs, the finalized tip moves past the height the client
/// signed to pay by; catching up before the durable step makes that the
/// height the payment is judged against, so no certificate is signed.
/// The tip moves *inside* the awaited reproduction — a latch, not a
/// pre-set chain — so this fails against both mutations: remove the
/// catch-up and the stale cursor lets the late payment through, and move
/// the catch-up in front of the reproduction and it reads a chain that
/// has not moved yet, with the same effect.
#[tokio::test]
async fn a_stalled_reproduction_refuses_to_pay_at_the_barrier() {
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
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };

    // The finalized tip is at the fixture cursor until the reproduction
    // is actually awaited; running it moves the tip one block past the
    // payment deadline.
    let tip = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(CURSOR));
    let stalled = SharedBlocks { tip: tip.clone() };
    let engine = LatchedEngine {
        tip,
        advance_to: authorization.payment_deadline.saturating_add(1),
    };
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let collected =
        collect_checked_result(transport, &mut endpoint, &ready, &stalled, &engine, id).await;
    serving.abort();
    assert!(
        matches!(collected, Ok(CollectOutcome::Checked(_))),
        "the answer reproduces and matches: {collected:?}",
    );
    // The barrier ran: the cursor is past the deadline now.
    assert!(
        endpoint.state().cursor().0 > authorization.payment_deadline,
        "the post-answer catch-up advanced the cursor past the deadline",
    );

    // So the payment is refused: a certificate signed now is one this
    // client's own journal is past the height to sign it by.
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let paid = pay_for_result(transport, &mut endpoint, id).await;
    serving.abort();
    assert!(
        paid.is_err(),
        "a payment past its deadline is refused at the barrier: {paid:?}",
    );
    assert!(
        endpoint.state().last_payment().is_none(),
        "and nothing was signed",
    );
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

fn lease_over(bond: EdgeId, payment: EdgeId) -> LeaseSlots {
    let mut value = vec![FORMAT_VERSION, TAG_BOND_LEASE, 2];
    value.extend_from_slice(&bond.to_bytes());
    value.extend_from_slice(&payment.to_bytes());
    value.extend_from_slice(payment_terms_hash(payment_terms()).as_bytes());
    value.extend_from_slice(&payment_terms().private_policy_commitment);
    value.extend_from_slice(&HORIZON.to_be_bytes());

    let slots = [0, 1].map(|index| {
        RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &value,
            index,
        )
    });
    let parsed = hellas_kernel::parse_bond_lease(slots, bond);
    assert!(
        matches!(parsed, LeaseSlots::Present(_)),
        "the hand-written lease is readable, got {parsed:?}",
    );
    parsed
}
