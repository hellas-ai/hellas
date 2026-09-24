//! Spending the certificate: the cursor that makes a deadline mean
//! something, and the close that turns one signed scalar into coins.
//!
//! The job at the top of every fixture here is a real one — proposed,
//! co-signed, computed by a backend, delivered, checked and
//! paid over a live transport — because a close built from a
//! certificate this file invented would prove only that the arithmetic
//! composes. What it settles has to be what the earlier phases produced.
//!
//! What is not re-proved here. That the kernel accepts these bytes and
//! pays out these coins is `hellas-chain`'s
//! `endpoint_built_close_settles_on_a_real_chain`, against real blocks
//! and a real database. These tests are about what the endpoint retains
//! before it sends, what it refuses once it has, and what its watcher
//! does with the blocks that come back.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, Parties, Party, PaymentCloseStart, Payout, PendingSlot, RegistryChunk,
    RegistryNamespace, RegistryRecordTag, Secp256k1Verifier, Terms, TermsHash,
    WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::observe::Samples;
use hellas_rpc::pb::work::{
    AcceptWorkRequest, WorkRefusalCode, accept_work_response::Outcome as AcceptOutcome,
};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PrivateRecord as _, generation_policy_digest, identity_source_digest,
    private_policy_commitment, propose_authorization, signing_hash, work_id,
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
use hellas_wire::mux::MuxTransport;
use hellas_wire::{Dispatcher, StreamTransport};
use hellas_work::work::{
    BackendFault, ClientEndpoint, CloseEndpoint, PaidWorkBackend, PaymentError,
    PreparedEvaluateInput, ProviderEndpoint, RunOutcome, WorkService, admit_payment, fetch_result,
    run_accepted_work,
};
use hellas_work::work_close::{
    BlockSourceError, CatchUpError, CloseError, CloseProgress, FinalizedBlocks, FinalizedWork,
    close_start, response_body_digest, start_body_digest,
};
use hellas_work::work_store::{
    ChannelRecord, ChannelStore, CloseSettlement, JobPhase, JobState, Role, SetupOrigin,
    TerminalOutcome,
};

mod support;
use support::{
    advance, bond_edge, client, network, payload_at, payment_edge, provider, signer, temp,
};

/// The one proposal nonce every job in this file carries.
const NONCE: u8 = 1;

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

/// The execution policy every job here runs under.
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
        max_encoded_result_frame: WIDE_FRAME,
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

fn descriptor() -> WorkChannelDescriptor {
    let config = WorkChannelConfig {
        network: network(),
        payment_edge: payment_edge(),
        payment_terms: payment_terms(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: execution_policy().into(),
        expected_payment_values: payment_values(),
    };
    match WorkChannelDescriptor::open(config) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

/// The channel, ready at the height both endpoints have processed
/// through.
fn ready() -> ReadyChannel {
    let bond = bond_object();
    let payment = payment_object();
    let observed = ObservedChannel {
        height: CURSOR,
        bond: Some(&bond),
        payment: Some(&payment),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: PendingSlot::Absent,
    };
    match descriptor().check_ready(&observed) {
        Ok(ready) => ready,
        Err(error) => panic!("the fixture channel is ready: {error}"),
    }
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

fn authorization() -> PaidJobAuthorizationV1 {
    match propose_authorization(
        ready().channel(),
        &execution_policy(),
        &bundle(NONCE),
        u64::from(NONCE),
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
fn accept(stores: &mut [&mut ChannelStore]) -> Digest {
    let authorization = authorization();
    let ready = ready();
    let id = work_id(ready.channel(), &authorization);
    let Ok(prepared_input) = bundle(NONCE).encode() else {
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
    id
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

#[path = "support/transport.rs"]
mod transport;
use transport::transport_pair;

/// Stops one serving task and waits for it to be gone.
///
/// Awaited rather than merely cancelled: the task holds a handle to the
/// provider's endpoint, and a test that reopens that journal from its
/// files needs the process to have actually let go of it.
async fn stop(serving: tokio::task::JoinHandle<()>) {
    serving.abort();
    let _ = serving.await;
}

fn serve(transport: MuxTransport, service: WorkService) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = WorkServer(service);
        while let Ok(Some(inbound)) = transport.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&server, inbound).await;
        }
    })
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

// ── The state this phase begins from ──────────────────────────────────

/// One job, accepted, computed, delivered and independently checked.
///
/// Everything before the invoice, driven exactly as the earlier phases
/// drive it, because a payment for a job that reached this state any
/// other way would be a payment for something these tests invented.
struct Checked {
    client_root: tempfile::TempDir,
    provider_root: tempfile::TempDir,
    ready: ReadyChannel,
    service: WorkService,
    client: ClientEndpoint,
    id: Digest,
}

async fn checked_job() -> Checked {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let id = accept(&mut [&mut client_store, &mut provider_store]);

    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    let Ok(mut client) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let delivered = fetch_result(transport, &mut client, &ready, id).await;
    stop(serving).await;
    if let Err(error) = delivered {
        panic!("the fixture delivery completes: {error}");
    }
    // The oracle is `hellas-client`'s; what this file needs is the
    // durable verdict it records, which is the only phase an honest
    // client's journal signs a certificate from.
    if let Err(error) = client.matched(id) {
        panic!("the fixture verdict records: {error}");
    }
    Checked {
        client_root,
        provider_root,
        ready,
        service,
        client,
        id,
    }
}

// ── Driving the two calls ─────────────────────────────────────────────

/// One `AdmitCertificate` over a live transport: signed, journaled,
/// sent, and acknowledged.
async fn pay_over_wire(
    service: &WorkService,
    client: &mut ClientEndpoint,
    id: Digest,
) -> Result<u64, PaymentError> {
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let outcome = admit_payment(&WorkClientImpl::new(transport), client, id).await;
    stop(serving).await;
    outcome
}

// ── The state this phase begins from ──────────────────────────────────

/// One job, all the way through: checked and paid for.
///
/// The provider's journal ends holding one client-signed
/// [`EarnedCertificate`] at `PRICE`, and that certificate is the only
/// thing every close below settles.
async fn paid_job() -> Checked {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    if let Err(error) = pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        panic!("the fixture job is paid: {error}");
    }
    fixture
}

/// Applies one finalized block to a service, through the one thing that
/// may apply one.
///
/// The driving authority is taken and given back per block, which is why
/// this reads like the old one-block call and is not one: a loop over it
/// stops where a loop inside the service stops, because the rule is the
/// driver's and not the loop's.
fn observe_one(service: &WorkService, applied: &FinalizedWork) -> Result<(), CatchUpError> {
    match service.drive() {
        Ok(mut driver) => driver.observe_finalized(applied),
        Err(_) => Err(CatchUpError::Busy),
    }
}

/// One `AcceptWorkRequest` for a fresh job at `proposal_nonce`.
fn signed_request(nonce: u8, proposal_nonce: u64) -> AcceptWorkRequest {
    let authorization = match propose_authorization(
        ready().channel(),
        &execution_policy(),
        &bundle(nonce),
        proposal_nonce,
        deadlines(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    };
    let Ok(prepared_input) = bundle(nonce).encode() else {
        panic!("the fixture bundle encodes");
    };
    AcceptWorkRequest {
        authorization: authorization.encode(),
        client_signature: client()
            .sign(signing_hash(work_id(ready().channel(), &authorization)))
            .as_bytes()
            .to_vec(),
        prepared_input,
    }
}

/// One finalized block carrying `txs`, on the chain `payload_at` names.
fn block(height: u64, txs: Vec<hellas_kernel::Tx>) -> FinalizedWork {
    FinalizedWork {
        height,
        parent: payload_at(height.saturating_sub(1)),
        payload: payload_at(height),
        txs,
    }
}

/// The canonical bytes of one pending-close record, spelled out here
/// rather than produced by the kernel's encoder.
///
/// An endpoint reads these bytes out of a registry slot on a wire, not
/// out of a transition it ran, so its side of the agreement is a byte
/// layout. A round trip through `PendingPaymentClose::encode` would
/// pass with any two same-width fields transposed; this does not.
fn pending_bytes(record: &Contest) -> Vec<u8> {
    // envelope: canonical format version 1, type tag 23.
    let mut value = vec![1_u8, 23];
    // body version.
    value.push(2);
    value.extend_from_slice(&payment_edge().to_bytes());
    // opener_role: the taker, which on a payment edge is the provider.
    value.push(1);
    value.extend_from_slice(&record.start_id.to_bytes());
    value.extend_from_slice(&record.deadline.to_be_bytes());
    value.extend_from_slice(&record.start_cumulative.to_be_bytes());
    value.extend_from_slice(&record.final_cumulative.to_be_bytes());
    value.push(u8::from(record.responded));
    value.push(u8::from(record.penalty_due));
    value.extend_from_slice(&OMISSION_BOND.to_be_bytes());
    value
}

/// One contest as the chain would hold it.
struct Contest {
    start_id: hellas_kernel::StartId,
    deadline: u64,
    start_cumulative: u64,
    final_cumulative: u64,
    responded: bool,
    penalty_due: bool,
}

impl Contest {
    /// The record an unanswered provider-opened start at `amount`
    /// leaves.
    fn opened(start_id: hellas_kernel::StartId, deadline: u64, amount: u64) -> Self {
        Self {
            start_id,
            deadline,
            start_cumulative: amount,
            final_cumulative: amount,
            responded: false,
            penalty_due: false,
        }
    }
}

fn pending_slot(record: &Contest) -> PendingSlot {
    let bytes = pending_bytes(record);
    let chunk = RegistryChunk::split(
        RegistryNamespace::PaymentClose,
        RegistryRecordTag::PaymentPending,
        &bytes,
        0,
    );
    let parsed = hellas_kernel::parse_pending_close(chunk, payment_edge());
    assert!(
        matches!(parsed, PendingSlot::Present(_)),
        "the hand-written contest is readable, got {parsed:?}",
    );
    parsed
}

/// The contest identifier the kernel derives for `start` at `height`.
fn contest_id(
    ready: &ReadyChannel,
    start: &PaymentCloseStart,
    height: u64,
) -> hellas_kernel::StartId {
    hellas_kernel::start_id(start_body_digest(ready.channel(), start), height)
}

// ── One paid job, closed on chain ─────────────────────────────────────

/// One certificate becomes one start, one contest, and one payout.
///
/// Every value the close carries is traced back to the job: the amount
/// is the invoice's `cumulative_after`, the signature is the client's
/// own, and the contest identifier is the one the block that accepted
/// the start determines.
#[tokio::test]
async fn a_paid_job_closes_at_exactly_what_it_earned() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();

    let start = {
        let Ok(held) = fixture
            .service
            .with_state(|state| state.max_executable_certificate())
        else {
            panic!("the endpoint is reachable");
        };
        assert_eq!(held, PRICE);
        match fixture.service.prepare_close() {
            Ok(start) => start,
            Err(error) => panic!("a paid channel closes: {error}"),
        }
    };

    // The start is about this channel, claims exactly what was earned,
    // and is includable in the window the terms fix, starting at the
    // block after the one this endpoint has processed.
    assert_eq!(start.payment_edge(), payment_edge());
    assert_eq!(start.terms().hash(), ready.channel().payment_terms_hash());
    assert_eq!(start.opener_role(), hellas_kernel::Party::Taker);
    assert_eq!(start.valid_from_height(), CURSOR + 1);
    assert_eq!(
        start.valid_through_height(),
        CURSOR + payment_terms().start_validity_blocks,
    );
    let Some((certificate, signature)) = start.certificate() else {
        panic!("a paid channel claims what it earned");
    };
    assert_eq!(certificate.earned_cumulative(), PRICE);
    assert_eq!(certificate.payment_edge(), payment_edge());
    let Some(payment) = fixture.client.state().last_payment() else {
        panic!("the client retains what it paid");
    };
    assert_eq!(
        (certificate, signature),
        (&payment.certificate, &payment.certificate_signature),
        "the close carries the client's own certificate, not a copy of the number",
    );

    // Asking again before the window has passed is the resubmission,
    // not a second close: the same bytes, and no second record.
    let (again, before) = {
        let Ok(before) = fixture
            .service
            .with_state(|state| state.close_prepared().cloned())
        else {
            panic!("the endpoint is reachable");
        };
        (fixture.service.prepare_close(), before)
    };
    match again {
        Ok(again) => assert_eq!(Some(&again), before.as_ref()),
        Err(error) => panic!("a retained start is offered again: {error}"),
    }

    // The block that accepts it. The contest identifier is the height's
    // to decide, and nothing the endpoint retained determines it.
    let inclusion = CURSOR + 1;
    let expected = contest_id(&ready, &start, inclusion);
    {
        let accepted = block(
            inclusion,
            vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(start.clone()),
            )],
        );
        if let Err(error) = observe_one(&fixture.service, &accepted) {
            panic!("the block applies: {error}");
        }
        let Ok((opened, cursor)) = fixture
            .service
            .with_state(|state| (state.close_opened(), state.cursor()))
        else {
            panic!("the endpoint is reachable");
        };
        assert_eq!(opened, Some((expected, Party::Taker)));
        assert_eq!(cursor, (inclusion, payload_at(inclusion)));
        assert_ne!(
            expected,
            contest_id(&ready, &start, inclusion + 1),
            "one signed start included at two heights is two contests",
        );
    }

    // The response window runs out with no answer, and the close pays
    // the amount the contest settled at.
    let deadline = inclusion + payment_terms().omit_response_blocks;
    let record = Contest::opened(expected, deadline, PRICE);
    let bond = bond_object();
    let payment_edge_object = payment_object();
    let close = {
        let observed = ObservedChannel {
            height: deadline,
            bond: Some(&bond),
            payment: Some(&payment_edge_object),
            lease: lease_over(bond_edge(), payment_edge()),
            pending: pending_slot(&record),
        };
        match fixture.service.adjudicated_close(&observed) {
            Ok(close) => close,
            Err(error) => panic!("a spent window closes: {error}"),
        }
    };
    let hellas_kernel::Tx::Close { input, outputs, .. } = &close else {
        panic!("an adjudicated close is a close");
    };
    assert_eq!(*input, payment_edge());
    let total = settlement().adjudicated_total();
    assert_eq!(
        outputs.as_slice(),
        [
            Payout::new(provider().party_key(), PRICE),
            Payout::new(client().party_key(), total - PRICE),
        ],
        "the provider is paid the job's price and no omission bond",
    );
}

/// The provider's window does not shut early, and the close does not
/// come late.
///
/// One block either side of the deadline, with the deadline the only
/// thing varied. The kernel's own guard is the complement of this one —
/// a response at the deadline is late and a close at the deadline is
/// not — so an endpoint that built a close one block early would be
/// building a transaction consensus refuses.
#[tokio::test]
async fn a_close_is_built_at_the_deadline_and_not_before_it() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let bond = bond_object();
    let payment_edge_object = payment_object();

    let provider = &fixture.service;
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let id = contest_id(&ready, &start, inclusion);
    if let Err(error) = observe_one(
        provider,
        &block(
            inclusion,
            vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(start),
            )],
        ),
    ) {
        panic!("the block applies: {error}");
    }

    let deadline = inclusion + payment_terms().omit_response_blocks;
    let record = Contest::opened(id, deadline, PRICE);
    for (height, closable) in [(deadline - 1, false), (deadline, true)] {
        let observed = ObservedChannel {
            height,
            bond: Some(&bond),
            payment: Some(&payment_edge_object),
            lease: lease_over(bond_edge(), payment_edge()),
            pending: pending_slot(&record),
        };
        let built = provider.adjudicated_close(&observed);
        if closable {
            if let Err(error) = built {
                panic!("a close at {height} is admissible: {error}");
            }
            continue;
        }
        assert!(
            matches!(
                built,
                Err(CloseError::ResponseWindowOpen {
                    height: found,
                    deadline: owed,
                }) if found == height && owed == deadline
            ),
            "a close at {height} is early: {built:?}",
        );
    }
}

/// A close is built only for the contest this endpoint's own watcher
/// saw.
///
/// Three reads, each differing from the admissible one in exactly one
/// thing: no contest in the slot, another contest's identifier, and a
/// watcher that has not yet read the block that opened this one.
#[tokio::test]
async fn a_close_settles_the_contest_this_endpoint_started() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let deadline = inclusion + payment_terms().omit_response_blocks;
    let bond = bond_object();
    let payment_edge_object = payment_object();

    let provider = &fixture.service;
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let id = contest_id(&ready, &start, inclusion);
    let record = Contest::opened(id, deadline, PRICE);

    // Before the watcher has read the block: the chain says a contest
    // is open and this endpoint cannot yet say it is its own.
    let observed = ObservedChannel {
        height: deadline,
        bond: Some(&bond),
        payment: Some(&payment_edge_object),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: pending_slot(&record),
    };
    assert!(
        matches!(
            provider.adjudicated_close(&observed),
            Err(CloseError::NoContest)
        ),
        "an unread block is not a contest this endpoint holds",
    );

    if let Err(error) = observe_one(
        provider,
        &block(
            inclusion,
            vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(start),
            )],
        ),
    ) {
        panic!("the block applies: {error}");
    }
    if let Err(error) = provider.adjudicated_close(&observed) {
        panic!("the read contest closes: {error}");
    }

    // The same read with an empty slot.
    let absent = ObservedChannel {
        pending: PendingSlot::Absent,
        ..observed
    };
    assert!(
        matches!(
            provider.adjudicated_close(&absent),
            Err(CloseError::NoContest)
        ),
        "an empty slot is no contest",
    );

    // The same read with another contest in the slot. Only the
    // identifier moves.
    let elsewhere = Contest::opened(
        hellas_kernel::StartId::from_bytes([0x77; 32]),
        deadline,
        PRICE,
    );
    let other = ObservedChannel {
        pending: pending_slot(&elsewhere),
        ..observed
    };
    assert!(
        matches!(
            provider.adjudicated_close(&other),
            Err(CloseError::OtherContest)
        ),
        "another contest is not this endpoint's to settle",
    );
}

// ── The cutoff ────────────────────────────────────────────────────────

/// A start that can no longer be included is replaced, and one that
/// can is offered again.
///
/// This is about which bytes `prepare_close` hands back and nothing
/// else — that the same expiry also reopens the channel to work is
/// `a_start_that_never_landed_reopens_the_channel`'s.
///
/// The cursor is the whole proof. It is contiguous, so every block up
/// to it was read: a contest opened by the old start would be on this
/// disk, and it is not. What is left is that the signature's window has
/// passed, and the cursor says exactly that.
#[tokio::test]
async fn a_start_that_can_no_longer_land_is_replaced_and_one_that_can_is_not() {
    let fixture = paid_job().await;
    let provider = &fixture.service;
    let Ok(first) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let through = first.valid_through_height();

    // Every block up to the last one that could have included it.
    for height in (CURSOR + 1)..=through {
        if let Err(error) = observe_one(provider, &block(height, Vec::new())) {
            panic!("the block at {height} applies: {error}");
        }
        match provider.prepare_close() {
            Ok(again) => assert_eq!(
                again, first,
                "a start that can still be included at {height} is the one that is offered",
            ),
            Err(error) => panic!("the retained start is offered: {error}"),
        }
    }

    // One block further, and the old signature can never be included.
    if let Err(error) = observe_one(provider, &block(through + 1, Vec::new())) {
        panic!("the block applies: {error}");
    }
    let Ok(replacement) = provider.prepare_close() else {
        panic!("a spent start is replaced");
    };
    assert_ne!(replacement, first);
    assert_eq!(replacement.valid_from_height(), through + 2);
    assert_eq!(
        provider
            .with_state(|state| state.close_prepared().cloned())
            .ok(),
        Some(Some(replacement)),
        "and the disk holds the one that can land",
    );
}

// ── What the watcher does with the blocks that come back ──────────────

/// A settled close is remembered after its coins are gone.
///
/// The evidence is the block that carried the close and the payout it
/// made, both read out of the transaction consensus accepted. Nothing
/// here looks up a coin, which is the point: a payout may be spent the
/// next block, and its absence would not be evidence that the channel
/// was never settled.
#[tokio::test]
async fn settlement_is_the_block_that_closed_the_edge() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let provider = &fixture.service;
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let id = contest_id(&ready, &start, inclusion);
    if let Err(error) = observe_one(
        provider,
        &block(
            inclusion,
            vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(start),
            )],
        ),
    ) {
        panic!("the block applies: {error}");
    }

    let deadline = inclusion + payment_terms().omit_response_blocks;
    let bond = bond_object();
    let payment_edge_object = payment_object();
    let record = Contest::opened(id, deadline, PRICE);
    let observed = ObservedChannel {
        height: deadline,
        bond: Some(&bond),
        payment: Some(&payment_edge_object),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: pending_slot(&record),
    };
    let Ok(close) = provider.adjudicated_close(&observed) else {
        panic!("a spent window closes");
    };

    for height in (inclusion + 1)..deadline {
        if let Err(error) = observe_one(provider, &block(height, Vec::new())) {
            panic!("the block at {height} applies: {error}");
        }
    }
    if let Err(error) = observe_one(provider, &block(deadline, vec![close])) {
        panic!("the closing block applies: {error}");
    }
    assert_eq!(
        provider.with_state(|state| state.close_settled()).ok(),
        Some(Some(CloseSettlement {
            height: deadline,
            payload: payload_at(deadline),
            provider_payout: PRICE,
        })),
    );
}

/// The watcher applies a block's transactions in the order the
/// validator put them in.
///
/// One block carries the start and the close that ends it. Applied in
/// consensus order both land; applied backwards the start is refused,
/// because a channel whose edge is gone admits no new contest. A
/// scanner that sorted a block's transactions would produce the second
/// history from the first block.
#[tokio::test]
async fn a_blocks_transactions_are_applied_in_consensus_order() {
    // Three fixtures: one to derive the two transactions, and one for
    // each reading order.
    let fixture = paid_job().await;
    let ordered = paid_job().await;
    let reversed = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let provider = &fixture.service;
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let id = contest_id(&ready, &start, inclusion);
    let start_tx =
        hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(start.clone()));

    let deadline = inclusion + payment_terms().omit_response_blocks;
    let record = Contest::opened(id, deadline, PRICE);
    let bond = bond_object();
    let payment_edge_object = payment_object();
    // The close this contest settles, built once and put in the same
    // block as the start it answers. Whether consensus would accept the
    // two together is the kernel's question; what is varied here is
    // only the order the watcher reads them in.
    let close = {
        if let Err(error) = observe_one(provider, &block(inclusion, vec![start_tx.clone()])) {
            panic!("the block applies: {error}");
        }
        let observed = ObservedChannel {
            height: deadline,
            bond: Some(&bond),
            payment: Some(&payment_edge_object),
            lease: lease_over(bond_edge(), payment_edge()),
            pending: pending_slot(&record),
        };
        match provider.adjudicated_close(&observed) {
            Ok(close) => close,
            Err(error) => panic!("a spent window closes: {error}"),
        }
    };
    drop(fixture);

    // A second provider, in the same state, that has read nothing.
    {
        let provider = &ordered.service;
        if let Err(error) = provider.prepare_close() {
            panic!("a paid channel closes: {error}");
        }
        if let Err(error) = observe_one(
            provider,
            &block(inclusion, vec![start_tx.clone(), close.clone()]),
        ) {
            panic!("the block in consensus order applies: {error}");
        }
        let Ok((opened, payout)) = provider.with_state(|state| {
            (
                state.close_opened(),
                state.close_settled().map(|settled| settled.provider_payout),
            )
        }) else {
            panic!("the endpoint is reachable");
        };
        assert_eq!(opened, Some((id, Party::Taker)));
        assert_eq!(payout, Some(PRICE));
    }

    {
        let provider = &reversed.service;
        if let Err(error) = provider.prepare_close() {
            panic!("a paid channel closes: {error}");
        }
        let applied = observe_one(provider, &block(inclusion, vec![close, start_tx]));
        assert!(
            applied.is_err(),
            "a close before the start it answers is not a history this journal takes",
        );
        assert_eq!(
            provider.with_state(|state| state.cursor()).ok(),
            Some((CURSOR, payload_at(CURSOR))),
            "and the cursor stays behind the block it could not apply",
        );
    }
}

// ── Catching up ───────────────────────────────────────────────────────

/// One provider endpoint after a restart, over its own files.
///
/// A watcher owns its endpoint rather than sharing it with a serving
/// task, because a catch-up reads a chain and nothing may hold the
/// endpoint while it waits. Reopening is also what makes each test
/// below a crash: the state the loop runs against is replayed from the
/// disk, and the journal's own lock is what says the serving endpoint
/// is really gone.
struct Watcher {
    provider: ProviderEndpoint,
    _client_root: tempfile::TempDir,
    _provider_root: tempfile::TempDir,
}

fn restarted(fixture: Checked) -> Watcher {
    let Checked {
        client_root,
        provider_root,
        ready,
        service,
        client,
        ..
    } = fixture;
    drop(service);
    drop(client);
    let store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    match ProviderEndpoint::new(ready, store, provider()) {
        Ok(provider) => Watcher {
            provider,
            _client_root: client_root,
            _provider_root: provider_root,
        },
        Err(error) => panic!("the reopened provider endpoint binds: {error}"),
    }
}

/// A finalized history a test writes down.
struct Chain {
    blocks: Vec<FinalizedWork>,
    withheld: Option<u64>,
}

impl FinalizedBlocks for Chain {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(self.blocks.last().map(|block| block.height))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        if self.withheld == Some(height) {
            return Ok(None);
        }
        Ok(self
            .blocks
            .iter()
            .find(|block| block.height == height)
            .cloned())
    }
}

/// The same history, counting every question the source was asked.
///
/// "Before the next block" is a claim about reads, and only a source
/// that counts them can hold a caller to it. Both calls count, because
/// asking for the tip is asking the chain something too: a duty
/// serviced after the tip query but before the fetch would still pass a
/// count that only watched [`FinalizedBlocks::block_at`], and the order
/// this claims is *neither*.
struct CountingChain {
    blocks: Vec<FinalizedWork>,
    reads: AtomicUsize,
}

impl CountingChain {
    fn over(blocks: Vec<FinalizedWork>) -> Self {
        Self {
            blocks,
            reads: AtomicUsize::new(0),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl FinalizedBlocks for CountingChain {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.blocks.last().map(|block| block.height))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .blocks
            .iter()
            .find(|block| block.height == height)
            .cloned())
    }
}

/// Every block is read, and a notification is not a substitute for
/// reading them.
///
/// The start is three blocks in. A watcher that jumped to the tip would
/// report a cursor at the same height and know nothing about the
/// contest — which is the whole difference, because the close is built
/// from what the scan found and not from what the tip says.
#[tokio::test]
async fn a_catch_up_reads_every_block_between() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let mut watcher = restarted(fixture);
    let provider = &mut watcher.provider;
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let inclusion = CURSOR + 3;
    let id = contest_id(&ready, &start, inclusion);
    let start_tx = hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(start));

    // A start and a close on some other channel's payment edge, two
    // blocks before this channel's own. Neither is this channel's
    // business, and a watcher that read them as its own would report a
    // contest it never opened and a settlement that never happened.
    let elsewhere = EdgeId::from_bytes([0x99; EdgeId::LENGTH]);
    let foreign_start = hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(
        PaymentCloseStart::new(
            elsewhere,
            Terms::work_payment(payment_terms()),
            hellas_kernel::Party::Taker,
            (CURSOR + 1, CURSOR + 1),
            None,
            signer(0x22).sign(hellas_kernel::PayloadHash::from_bytes([0x01; 32])),
        ),
    ));
    let foreign_close = hellas_kernel::Tx::close(
        elsewhere,
        hellas_kernel::Proof::adjudicated(hellas_kernel::PaymentContestCommitment::from_bytes(
            [0x02; 32],
        )),
        List::take(
            [Payout::new(signer(0x22).party_key(), 1); MAX_EDGE_OUTPUTS],
            1,
        ),
    );

    let chain = Chain {
        blocks: ((CURSOR + 1)..=(CURSOR + 5))
            .map(|height| {
                let txs = if height == inclusion {
                    vec![start_tx.clone()]
                } else if height == CURSOR + 1 {
                    vec![foreign_start.clone(), foreign_close.clone()]
                } else {
                    Vec::new()
                };
                block(height, txs)
            })
            .collect(),
        withheld: None,
    };
    match provider.catch_up(&chain).await {
        Ok(reached) => assert_eq!(reached, CURSOR + 5),
        Err(error) => panic!("the watcher catches up: {error}"),
    }
    assert_eq!(
        provider.state().close_opened(),
        Some((id, Party::Taker)),
        "the block three heights back is where the contest is",
    );
    assert!(
        provider.state().close_settled().is_none(),
        "another edge's close is not this channel's settlement",
    );

    // Run again with nothing new: a caught-up watcher writes nothing.
    let before = provider.state().cursor();
    match provider.catch_up(&chain).await {
        Ok(reached) => assert_eq!(reached, CURSOR + 5),
        Err(error) => panic!("a caught-up watcher is idle: {error}"),
    }
    assert_eq!(provider.state().cursor(), before);
}

/// A duty found at the front of a restart backlog is surfaced before the
/// watcher asks for the next finalized block.
///
/// The contest is the client's, opened below what this provider holds,
/// because that is what makes it a duty: an answer is owed, and the
/// backlog behind it is what must not get in the way of giving one.
#[tokio::test]
async fn catch_up_services_a_new_close_duty_before_the_next_block() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let understated = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
        .expect("a client opens a close");
    let expected = contest_id(&ready, &understated, inclusion);
    let mut watcher = restarted(fixture);
    let chain = CountingChain::over(vec![
        block(
            inclusion,
            vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(understated),
            )],
        ),
        block(inclusion + 1, Vec::new()),
    ]);
    let sink = Mempool::default();

    match watcher.provider.advance_close(&chain, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the first block's duty is surfaced: {other:?}"),
    }
    assert_eq!(
        chain.reads(),
        2,
        "the tip and the contest block, and not the block after it",
    );
    assert_eq!(watcher.provider.state().cursor().0, inclusion);
    assert_eq!(sink.taken().len(), 1, "and the duty was serviced");
}

/// A restart that reads a journaled contest off its own disk submits the
/// answer, before the deadline, without a fabricated snapshot.
///
/// The client opens a close at nothing while this provider holds a
/// certificate for `PRICE`; the contest is finalized, journaled, and the
/// store is dropped and reopened over its own files. The production
/// `advance_close` — the pure clock wrapper a node runner will call — is
/// the only thing that runs afterwards, and it is what puts the response
/// in the sink. Against the old `return Opened` the sink stays empty, so
/// this is the test that fails before the fix and passes after it.
#[tokio::test]
async fn restart_services_the_response_before_its_deadline() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;

    // The client opens below what it has already signed for: a start of
    // the *client's* (Maker's), claiming nothing.
    let understated = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
        .expect("a client opens a close");
    let expected = contest_id(&ready, &understated, inclusion);

    // The provider journals the contest through real finalization, then
    // the store is dropped and reopened. The response window and the
    // claimed floor must survive that reopen, or the reopened provider
    // could not decide either.
    let watcher = restarted(fixture);
    let Watcher {
        provider: mut endpoint,
        _provider_root,
        _client_root,
    } = watcher;
    endpoint
        .observe_finalized(&block(
            inclusion,
            vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(understated),
            )],
        ))
        .expect("the contest finalizes and journals CloseOpened");
    assert_eq!(
        endpoint.state().close_opened(),
        Some((expected, Party::Maker))
    );
    drop(endpoint);

    let store = store_at(_provider_root.path(), &ready, Role::Provider, CURSOR);
    let mut provider = ProviderEndpoint::new(ready.clone(), store, provider())
        .expect("the reopened provider binds");
    assert_eq!(
        provider.state().close_opened(),
        Some((expected, Party::Maker)),
        "the reopened journal still holds the contest",
    );
    let (cursor_height, _) = provider.state().cursor();
    let deadline = inclusion + payment_terms().omit_response_blocks;
    assert!(
        cursor_height < deadline,
        "the reopened cursor is inside the response window",
    );

    // The whole of what a node runner does: read to the tip, and let the
    // library service whatever duty the read surfaced.
    let chain = Chain {
        blocks: Vec::new(),
        withheld: None,
    };
    let sink = Mempool::default();
    match provider.advance_close(&chain, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the contest is open and its answer in flight: {other:?}"),
    }

    let taken = sink.taken();
    assert_eq!(
        taken.len(),
        1,
        "advance_close itself submitted the response"
    );
    let hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    } = &taken[0]
    else {
        panic!("the submitted transaction is a response move");
    };
    assert_eq!(response.start_id(), expected);
    assert_eq!(response.certificate().earned_cumulative(), PRICE);
}

/// Driven twice: one answer, a cursor that moves past the contest, and
/// the settlement the endpoint goes on to observe for itself.
///
/// One tick cannot see this. A tick that submits an answer and writes
/// nothing about it looks exactly like a tick that discharged a duty —
/// the difference is only visible on the *next* one, where the duty is
/// either gone or still owed. While it was still owed the cursor stopped
/// dead on the block that opened the contest: `advance_close` services a
/// duty before fetching another block, so an undischarged duty is a
/// watcher that never reads again. It would re-sign and re-send the same
/// bytes forever at a frozen height, never see its own answer land,
/// never see the close that ended the contest, and never reach
/// `Settled` — which is what "fanout completion is observation, not
/// acceptance" is about.
#[tokio::test]
async fn a_serviced_contest_advances_the_cursor_and_settles() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;

    // The client opens below what it has already signed for.
    let understated = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
        .expect("a client opens a close");
    let expected = contest_id(&ready, &understated, inclusion);
    let start_tx =
        hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(understated.clone()));

    let mut watcher = restarted(fixture);
    let sink = Mempool::default();

    // Tick one: the contest is read, the answer is journaled, and the
    // answer is submitted.
    let opening = Chain {
        blocks: vec![block(inclusion, vec![start_tx.clone()])],
        withheld: None,
    };
    match watcher.provider.advance_close(&opening, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the contest is read and answered: {other:?}"),
    }
    let submitted = sink.taken();
    assert_eq!(submitted.len(), 1, "one contest, one answer");
    let hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    } = &submitted[0]
    else {
        panic!("the submitted transaction is a response move");
    };
    assert_eq!(response.start_id(), expected);
    assert_eq!(response.certificate().earned_cumulative(), PRICE);

    // The journal says the answer exists, and says it by the digest the
    // signature on the wire covers.
    let responded = watcher
        .provider
        .state()
        .close_responded()
        .expect("the serviced duty is on the disk");
    assert_eq!(responded.start_id, expected);
    assert_eq!(
        responded.response_digest,
        response_body_digest(ready.channel(), expected, response.certificate()),
        "the journaled digest is the one the submitted answer was signed over",
    );
    assert_eq!(
        watcher.provider.state().cursor(),
        (inclusion, payload_at(inclusion)),
        "the cursor stopped on the contest to service it",
    );

    // Tick two: the same endpoint, over the blocks that carry its own
    // answer and then the close that answer settled.
    let payout = Payout::new(ready.channel().provider_key(), PRICE);
    let close_tx = hellas_kernel::Tx::close(
        payment_edge(),
        hellas_kernel::Proof::adjudicated(hellas_kernel::PaymentContestCommitment::from_bytes(
            [0x33; 32],
        )),
        List::take([payout; MAX_EDGE_OUTPUTS], 1),
    );
    let settling = Chain {
        blocks: vec![
            block(inclusion, vec![start_tx]),
            block(inclusion + 1, vec![submitted[0].clone()]),
            block(inclusion + 2, vec![close_tx]),
        ],
        withheld: None,
    };
    match watcher.provider.advance_close(&settling, &sink).await {
        Ok(CloseProgress::Settled { provider_payout }) => assert_eq!(provider_payout, PRICE),
        other => panic!("the answered contest settles: {other:?}"),
    }
    assert_eq!(
        sink.taken().len(),
        1,
        "a discharged duty is not serviced twice",
    );
    assert_eq!(
        watcher.provider.state().cursor(),
        (inclusion + 2, payload_at(inclusion + 2)),
        "and the cursor read every block between",
    );
    assert_eq!(
        watcher
            .provider
            .state()
            .close_settled()
            .map(|settled| settled.provider_payout),
        Some(PRICE),
    );
}

/// A hand-off the sink refused leaves the answer on the disk, and the
/// next pass sends those same bytes.
///
/// The record is written before the transaction leaves, so a failure
/// after it is a journal that says an answer exists when consensus has
/// never seen one. That is the safe half: the answer is fixed by the
/// contest and the certificate, both frozen from the moment the contest
/// was journaled, so re-deriving it produces the same bytes — and the
/// journal refuses any other answer to the same contest, which is what
/// makes the second send the first one rather than a second answer.
#[tokio::test]
async fn a_refused_hand_off_leaves_a_retryable_answer_on_the_disk() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;

    let understated = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
        .expect("a client opens a close");
    let expected = contest_id(&ready, &understated, inclusion);
    let chain = Chain {
        blocks: vec![block(
            inclusion,
            vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(understated),
            )],
        )],
        withheld: None,
    };

    let watcher = restarted(fixture);
    let Watcher {
        provider: mut endpoint,
        _provider_root,
        _client_root,
    } = watcher;
    let refusing = Mempool {
        refuse: true,
        ..Mempool::default()
    };
    let failed = endpoint.advance_close(&chain, &refusing).await;
    assert!(
        failed.is_err(),
        "the sink refused, and the step says so: {failed:?}",
    );
    drop(endpoint);
    let written = journal_bytes(_provider_root.path());

    // The crash: the state the retry runs against is replayed from the
    // file, and it holds the answer the refused hand-off never sent.
    let store = store_at(_provider_root.path(), &ready, Role::Provider, CURSOR);
    let mut endpoint = match ProviderEndpoint::new(ready.clone(), store, provider()) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the reopened provider binds: {error}"),
    };
    let responded = endpoint
        .state()
        .close_responded()
        .expect("the answer survived the crash");
    assert_eq!(responded.start_id, expected);

    let sink = Mempool::default();
    match endpoint.advance_close(&chain, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the unanswered contest is retried: {other:?}"),
    }
    let taken = sink.taken();
    assert_eq!(taken.len(), 1, "the retry sends one answer");
    let hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    } = &taken[0]
    else {
        panic!("the retried transaction is a response move");
    };
    assert_eq!(
        response_body_digest(ready.channel(), expected, response.certificate()),
        responded.response_digest,
        "the retry is the same answer, not a second one",
    );
    assert_eq!(
        endpoint.state().close_responded(),
        Some(responded),
        "and it is not counted twice",
    );
    drop(endpoint);
    assert_eq!(
        journal_bytes(_provider_root.path()),
        written,
        "the retry appended nothing the refused hand-off had not already written",
    );
}

/// The answer a dead process fixed is offered again before one successor
/// block is read, and lands with the window still open.
///
/// This is the crash the durable write exists for, and the reason that
/// write may not double as a completion marker. The record is on the
/// disk and consensus has nothing. If "responded" were read as "done",
/// the restart would fall through to the ordinary backlog scan — and the
/// backlog here runs past the response deadline, so by the time the
/// cursor stopped there would be no answer left to give. Nothing about
/// waiting would help: the contest, the role and the certificate were
/// all frozen at the block that opened it.
#[tokio::test]
async fn a_crashed_answer_is_offered_before_any_successor_block() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let deadline = inclusion + payment_terms().omit_response_blocks;

    let understated = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
        .expect("a client opens a close");
    let expected = contest_id(&ready, &understated, inclusion);
    let opening = Chain {
        blocks: vec![block(
            inclusion,
            vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(understated),
            )],
        )],
        withheld: None,
    };

    // The crash: the answer reaches the disk, the hand-off does not, and
    // the process is gone.
    let Watcher {
        provider: mut dying,
        _provider_root,
        _client_root,
    } = restarted(fixture);
    let refusing = Mempool {
        refuse: true,
        ..Mempool::default()
    };
    assert!(
        dying.advance_close(&opening, &refusing).await.is_err(),
        "the sink refused the answer this process fixed",
    );
    let fixed = dying
        .state()
        .close_responded()
        .expect("the answer is on the disk");
    drop(dying);

    // The restart, against a backlog that runs past the deadline.
    let store = store_at(_provider_root.path(), &ready, Role::Provider, CURSOR);
    let mut provider = match ProviderEndpoint::new(ready.clone(), store, provider()) {
        Ok(provider) => provider,
        Err(error) => panic!("the reopened provider binds: {error}"),
    };
    assert_eq!(provider.state().cursor().0, inclusion);
    let backlog = CountingChain::over(
        ((inclusion + 1)..=(deadline + 1))
            .map(|height| block(height, Vec::new()))
            .collect(),
    );
    let sink = Mempool::default();
    match provider.advance_close(&backlog, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the retained answer is the first thing done: {other:?}"),
    }
    assert_eq!(
        backlog.reads(),
        0,
        "the chain was not asked anything at all ahead of the answer",
    );

    let taken = sink.taken();
    assert_eq!(taken.len(), 1, "the retained answer was sent");
    let hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    } = &taken[0]
    else {
        panic!("the submitted transaction is a response move");
    };
    assert_eq!(
        response_body_digest(ready.channel(), expected, response.certificate()),
        fixed.response_digest,
        "and it is the answer the dead process fixed, not a new one",
    );
    let (height, _) = provider.state().cursor();
    assert!(
        height < deadline,
        "sent at {height}, inside a window that shuts at {deadline}",
    );
}

/// A sink that did not enqueue the answer is asked again; a sink that
/// did is not.
///
/// `Full` and `ValidationRejected` are successful results that mean *not
/// enqueued* — the whole reason the outcome is an enum rather than a
/// unit. Discarding it makes the two indistinguishable from acceptance,
/// and an answer nobody holds is then never sent again. The other half
/// is the same mistake mirrored: an answer a sink *has* taken must not
/// be resent every pass for as long as the contest stays open.
#[tokio::test]
async fn an_unenqueued_answer_is_sent_again_and_an_enqueued_one_is_not() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;

    let understated = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
        .expect("a client opens a close");
    let expected = contest_id(&ready, &understated, inclusion);
    let start_tx =
        hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(understated));
    let chain = Chain {
        blocks: vec![
            block(inclusion, vec![start_tx]),
            block(inclusion + 1, Vec::new()),
        ],
        withheld: None,
    };
    let mut watcher = restarted(fixture);

    // Two passes against a mempool with no room. Each is a send, because
    // neither was an enqueue.
    let full = Mempool::answering(hellas_rpc::SubmitTxOutcome::Full);
    for pass in 1..=2_u32 {
        match watcher.provider.advance_close(&chain, &full).await {
            Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
            other => panic!("pass {pass}: the contest is still open: {other:?}"),
        }
        assert_eq!(full.taken().len(), pass as usize, "pass {pass} sent again");
    }
    assert_eq!(
        watcher.provider.state().cursor().0,
        inclusion + 1,
        "a refused answer does not stop this endpoint reading on",
    );

    // A rejection is the same answer: not enqueued, so ask again.
    let rejected = Mempool::answering(hellas_rpc::SubmitTxOutcome::ValidationRejected);
    match watcher.provider.advance_close(&chain, &rejected).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("a rejected answer is still owed: {other:?}"),
    }
    assert_eq!(rejected.taken().len(), 1);

    // And once a sink takes it, the contest is not answered at again.
    let taking = Mempool::default();
    match watcher.provider.advance_close(&chain, &taking).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the answer is enqueued: {other:?}"),
    }
    assert_eq!(taking.taken().len(), 1);
    match watcher.provider.advance_close(&chain, &taking).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the contest is still open: {other:?}"),
    }
    assert_eq!(
        taking.taken().len(),
        1,
        "an enqueued answer is not sent a second time",
    );
}

/// An answer no sink took buys one successor block and is then owed
/// again, so a backlog longer than the response window cannot swallow
/// it.
///
/// This is the same rule as the crash test one step weaker, and it is
/// the case a bare "already offered" flag gets wrong. `Full` means the
/// answer is still owed, but reading on is exactly what tells this
/// endpoint whether it was owed at all — so the read may not stop dead,
/// and it may not run free either. Against a backlog that outlives the
/// window, running free is the loss: the cursor arrives past the
/// deadline, `answerable_contest` has become `None`, and there is no
/// duty left to retry. The contest still settles — it settles on the
/// understatement, at the claim this provider could have beaten and
/// with the omission penalty unclaimed.
#[tokio::test]
async fn an_unenqueued_answer_outlives_a_backlog_past_the_deadline() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let deadline = inclusion + payment_terms().omit_response_blocks;

    let understated = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
        .expect("a client opens a close");
    let expected = contest_id(&ready, &understated, inclusion);
    let start_tx =
        hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(understated));
    let backlog = Chain {
        blocks: std::iter::once(block(inclusion, vec![start_tx]))
            .chain(((inclusion + 1)..=(deadline + 4)).map(|height| block(height, Vec::new())))
            .collect(),
        withheld: None,
    };
    let mut watcher = restarted(fixture);

    // Tick one: the scan stops on the contest, and the mempool has no
    // room for the answer.
    let full = Mempool::answering(hellas_rpc::SubmitTxOutcome::Full);
    match watcher.provider.advance_close(&backlog, &full).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the contest is read and answered: {other:?}"),
    }
    assert_eq!(full.taken().len(), 1, "the answer was offered once");
    assert_eq!(watcher.provider.state().cursor().0, inclusion);
    let fixed = watcher
        .provider
        .state()
        .close_responded()
        .expect("the answer is on the disk");

    // Tick two: the same backlog, and a mempool that now has room. The
    // unenqueued answer is owed again after one block, not after the
    // ninety-odd this source would happily hand over.
    let taking = Mempool::default();
    match watcher.provider.advance_close(&backlog, &taking).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the unenqueued answer is still owed: {other:?}"),
    }
    let taken = taking.taken();
    assert_eq!(taken.len(), 1, "the answer nobody held was offered again");
    let (height, _) = watcher.provider.state().cursor();
    assert_eq!(
        height,
        inclusion + 1,
        "one successor block was read, not the backlog behind it",
    );
    assert!(
        height < deadline,
        "offered at {height}, inside a window that shuts at {deadline}",
    );
    let hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    } = &taken[0]
    else {
        panic!("the retried transaction is a response move");
    };
    assert_eq!(
        response_body_digest(ready.channel(), expected, response.certificate()),
        fixed.response_digest,
        "and it is the answer already fixed on the disk, not a second one",
    );
    assert_eq!(
        response.certificate().earned_cumulative(),
        PRICE,
        "the answer spends the certificate the contest understated",
    );

    // Tick three: the block after the retry carries it, still inside the
    // window. A sink holds the answer now, so the rest of the backlog is
    // read in one pass and nothing is sent a second time.
    let landing = inclusion + 2;
    assert!(landing < deadline, "the answer had blocks left to land in");
    let landed = Chain {
        blocks: std::iter::once(block(landing, vec![taken[0].clone()]))
            .chain(((landing + 1)..=(deadline + 4)).map(|height| block(height, Vec::new())))
            .collect(),
        withheld: None,
    };
    match watcher.provider.advance_close(&landed, &taking).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the contest runs to the tip: {other:?}"),
    }
    assert_eq!(
        taking.taken().len(),
        1,
        "an answer a sink took is not offered again",
    );
    assert_eq!(
        watcher.provider.state().cursor().0,
        deadline + 4,
        "and an answered contest is not what holds the cursor back",
    );
}

// ── Contests that are nobody's duty ───────────────────────────────────

/// A contest this provider opened itself is not an answer it owes, and
/// the cursor does not wait for one.
///
/// The residual is not deferrable and that is the point: this endpoint
/// answers a *client's* understatement, so a start of its own can never
/// become a duty however long it waits. An endpoint that stopped for one
/// would stop on the block that opened it, never read the close that
/// ended it, and never learn what it was paid.
#[tokio::test]
async fn a_contest_this_provider_opened_does_not_pin_the_cursor() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let mut watcher = restarted(fixture);
    let start = match watcher.provider.prepare_close() {
        Ok(start) => start,
        Err(error) => panic!("a paid channel closes: {error}"),
    };
    assert_eq!(start.opener_role(), Party::Taker);
    let inclusion = CURSOR + 1;
    let expected = contest_id(&ready, &start, inclusion);
    let start_tx = hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(start));
    let sink = Mempool::default();

    // Tick one: the contest is read, and the block after it is too.
    let opening = Chain {
        blocks: vec![
            block(inclusion, vec![start_tx.clone()]),
            block(inclusion + 1, Vec::new()),
        ],
        withheld: None,
    };
    match watcher.provider.advance_close(&opening, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the contest is this endpoint's own: {other:?}"),
    }
    assert_eq!(
        watcher.provider.state().cursor().0,
        inclusion + 1,
        "no answer is owed, so nothing stopped the read",
    );
    assert!(sink.taken().is_empty(), "and nothing was answered");

    // Tick two: the close that ends it, which a stopped cursor could
    // never have reached.
    let settling = Chain {
        blocks: vec![
            block(inclusion, vec![start_tx]),
            block(inclusion + 1, Vec::new()),
            block(inclusion + 2, vec![adjudicated(&ready, PRICE)]),
        ],
        withheld: None,
    };
    match watcher.provider.advance_close(&settling, &sink).await {
        Ok(CloseProgress::Settled { provider_payout }) => assert_eq!(provider_payout, PRICE),
        other => panic!("the contest settles: {other:?}"),
    }
}

/// A client watches its own contest through to settlement.
///
/// There is no client answer at all — only a certificate's beneficiary
/// may spend it — so every contest is one a client can only watch. A
/// duty rule that did not know that would leave the funded party
/// frozen on the block that opened its own close.
#[tokio::test]
async fn a_client_watcher_does_not_stop_on_a_contest() {
    let mut fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let start = match fixture.client.prepare_close() {
        Ok(start) => start,
        Err(error) => panic!("a client closes its own channel: {error}"),
    };
    let inclusion = CURSOR + 1;
    let expected = contest_id(&ready, &start, inclusion);
    let start_tx = hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(start));
    let sink = Mempool::default();

    let opening = Chain {
        blocks: vec![
            block(inclusion, vec![start_tx.clone()]),
            block(inclusion + 1, Vec::new()),
        ],
        withheld: None,
    };
    match fixture.client.advance_close(&opening, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the client's contest is open: {other:?}"),
    }
    assert_eq!(
        fixture.client.state().cursor().0,
        inclusion + 1,
        "a client owes no answer, so nothing stopped the read",
    );

    let settling = Chain {
        blocks: vec![
            block(inclusion, vec![start_tx]),
            block(inclusion + 1, Vec::new()),
            block(inclusion + 2, vec![adjudicated(&ready, PRICE)]),
        ],
        withheld: None,
    };
    match fixture.client.advance_close(&settling, &sink).await {
        Ok(CloseProgress::Settled { provider_payout }) => assert_eq!(provider_payout, PRICE),
        other => panic!("the client sees its own close settle: {other:?}"),
    }
    assert!(sink.taken().is_empty(), "and answered nothing");
}

/// A contest already at this provider's own high-water is not a duty
/// either.
///
/// The client opened at exactly what it signed for, so the one answer
/// the window admits would add nothing — and the certificate that could
/// have beaten it is the one already on this disk, which no later block
/// can improve. Stopping here would be waiting for evidence that cannot
/// arrive.
#[tokio::test]
async fn a_provider_with_nothing_to_add_does_not_pin_the_cursor() {
    let mut fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let start = match fixture.client.prepare_close() {
        Ok(start) => start,
        Err(error) => panic!("a client closes at what it signed for: {error}"),
    };
    assert_eq!(
        start
            .certificate()
            .map(|(certificate, _)| certificate.earned_cumulative()),
        Some(PRICE),
        "the contest already carries this provider's whole high-water",
    );
    let inclusion = CURSOR + 1;
    let expected = contest_id(&ready, &start, inclusion);
    let start_tx = hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(start));
    let mut watcher = restarted(fixture);
    let sink = Mempool::default();

    let opening = Chain {
        blocks: vec![
            block(inclusion, vec![start_tx.clone()]),
            block(inclusion + 1, Vec::new()),
        ],
        withheld: None,
    };
    match watcher.provider.advance_close(&opening, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the levelled contest is open: {other:?}"),
    }
    assert_eq!(
        watcher.provider.state().cursor().0,
        inclusion + 1,
        "nothing to add is not a duty, so nothing stopped the read",
    );
    assert!(sink.taken().is_empty(), "and the window was not spent");
    assert_eq!(
        watcher.provider.state().close_responded(),
        None,
        "no answer was fixed for a contest that has none",
    );

    let settling = Chain {
        blocks: vec![
            block(inclusion, vec![start_tx]),
            block(inclusion + 1, Vec::new()),
            block(inclusion + 2, vec![adjudicated(&ready, PRICE)]),
        ],
        withheld: None,
    };
    match watcher.provider.advance_close(&settling, &sink).await {
        Ok(CloseProgress::Settled { provider_payout }) => assert_eq!(provider_payout, PRICE),
        other => panic!("the levelled contest settles: {other:?}"),
    }
}

/// The finalized close that pays the provider `payout`.
fn adjudicated(ready: &ReadyChannel, payout: u64) -> hellas_kernel::Tx {
    hellas_kernel::Tx::close(
        payment_edge(),
        hellas_kernel::Proof::adjudicated(hellas_kernel::PaymentContestCommitment::from_bytes(
            [0x33; 32],
        )),
        List::take(
            [Payout::new(ready.channel().provider_key(), payout); MAX_EDGE_OUTPUTS],
            1,
        ),
    )
}

/// Bytes the one channel journal under `root` holds.
///
/// A record the state already holds is never appended, so the file is
/// where a second write would have to show up — and the only place it
/// could be counted from.
fn journal_bytes(root: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(root) else {
        panic!("the journal directory reads");
    };
    let Some(path) = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.to_string_lossy().contains("channel-"))
    else {
        panic!("the channel journal exists");
    };
    match std::fs::metadata(&path) {
        Ok(meta) => meta.len(),
        Err(error) => panic!("the journal is measurable: {error}"),
    }
}

/// A block the source cannot supply stops the scan where it is.
///
/// It does not skip ahead, and it does not pretend to be caught up.
/// Every gate in this crate is anchored at the cursor, so a watcher
/// that jumped the gap would make each of them pass on a height at
/// which it does not know what happened.
#[tokio::test]
async fn a_withheld_block_leaves_the_cursor_behind() {
    let fixture = paid_job().await;
    let mut watcher = restarted(fixture);
    let provider = &mut watcher.provider;
    let chain = Chain {
        blocks: ((CURSOR + 1)..=(CURSOR + 5))
            .map(|height| block(height, Vec::new()))
            .collect(),
        withheld: Some(CURSOR + 3),
    };
    let stopped = provider.catch_up(&chain).await;
    assert!(
        matches!(stopped, Err(CatchUpError::Missing { height }) if height == CURSOR + 3),
        "a gap is not a skip: {stopped:?}",
    );
    assert_eq!(
        provider.state().cursor(),
        (CURSOR + 2, payload_at(CURSOR + 2)),
        "the cursor keeps the last block that was read",
    );
}

// ── The deadline the cursor decides ───────────────────────────────────

/// The payment deadline ends the job, once, and lets the channel close.
///
/// Nothing but the watcher moves this. The height that crosses the
/// deadline is a finalized height this endpoint read, and until it does
/// the job is still open — which is the difference this whole phase is
/// about: a provider whose cursor never moved would hold a delivered,
/// unpaid job open forever and never be able to close its channel.
#[tokio::test]
async fn the_watcher_ends_a_job_its_payment_deadline_has_passed() {
    let fixture = checked_job().await;
    let payment_deadline = deadlines().payment;
    let provider = &fixture.service;
    assert_eq!(
        provider
            .with_state(|state| state.jobs().next().map(JobState::phase))
            .expect("the endpoint is reachable"),
        Some(JobPhase::Delivered),
    );

    // A closing provider with a delivered, unpaid job is refused: what
    // the client owes has not been decided yet.
    assert!(
        provider.prepare_close().is_err(),
        "a channel with an open job does not close",
    );

    for height in (CURSOR + 1)..=payment_deadline {
        if let Err(error) = observe_one(provider, &block(height, Vec::new())) {
            panic!("the block at {height} applies: {error}");
        }
    }
    assert!(
        provider
            .with_state(|state| state.jobs().next().is_some())
            .expect("the endpoint is reachable"),
        "the deadline itself is still inside the window the client signed",
    );

    if let Err(error) = observe_one(provider, &block(payment_deadline + 1, Vec::new())) {
        panic!("the block past the deadline applies: {error}");
    }
    assert!(
        provider
            .with_state(|state| state.jobs().next().is_none())
            .expect("the endpoint is reachable"),
        "the job is over",
    );
    assert!(
        provider
            .with_state(|state| matches!(
                state.terminals().next().map(|terminal| &terminal.outcome),
                Some(TerminalOutcome::Expired { .. }),
            ))
            .expect("the endpoint is reachable"),
        "a delivered, unpaid job rests at an expired terminal the provider bears",
    );

    // The next blocks change nothing: the terminal is permanent.
    for height in (payment_deadline + 2)..=(payment_deadline + 4) {
        if let Err(error) = observe_one(provider, &block(height, Vec::new())) {
            panic!("the block at {height} applies: {error}");
        }
    }
    assert!(
        provider
            .with_state(|state| matches!(
                state.terminals().next().map(|terminal| &terminal.outcome),
                Some(TerminalOutcome::Expired { .. }),
            ))
            .expect("the endpoint is reachable"),
        "the expired terminal is permanent",
    );

    // And now the channel can be closed, at nothing: the client never
    // signed a certificate, so there is none to carry.
    match provider.prepare_close() {
        Ok(start) => assert!(
            start.certificate().is_none(),
            "an unpaid channel claims nothing",
        ),
        Err(error) => panic!("a channel whose job is over closes: {error}"),
    }
}

// ── The signed window ─────────────────────────────────────────────────

/// The same channel under another start-validity span.
fn channel_with_span(span: u64) -> hellas_rpc::protocol::work::PaidChannel {
    let mut terms = payment_terms();
    terms.start_validity_blocks = span;
    match hellas_rpc::protocol::work::PaidChannel::new(
        network(),
        payment_edge(),
        terms,
        &SALT,
        channel_policy(),
    ) {
        Ok(channel) => channel,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

/// The signed window starts at the next block and is exactly as wide as
/// the terms say, and at the ceiling it refuses rather than wraps.
///
/// The span is inclusive at both ends, which is the kernel's own
/// reading: a one-block window has span one. An endpoint that read the
/// field as a duration would sign a window one block wider than the
/// terms admit, and every signature it made would be refused for a span
/// that is too wide.
#[test]
fn the_start_window_is_the_next_block_and_the_span_the_terms_fix() {
    for (span, height, expected) in [(8_u64, 10_u64, (11_u64, 18_u64)), (1, 10, (11, 11))] {
        let Ok(start) = close_start(
            &channel_with_span(span),
            hellas_kernel::Party::Taker,
            height,
            None,
            &signer(0x22),
        ) else {
            panic!("a span of {span} at height {height} signs");
        };
        assert_eq!(
            (start.valid_from_height(), start.valid_through_height()),
            expected,
        );
    }

    // A one-block window whose only live block is the last one there
    // is.
    let Ok(edge) = close_start(
        &channel_with_span(1),
        hellas_kernel::Party::Taker,
        u64::MAX - 1,
        None,
        &signer(0x22),
    ) else {
        panic!("the last representable window signs");
    };
    assert_eq!(
        (edge.valid_from_height(), edge.valid_through_height()),
        (u64::MAX, u64::MAX),
    );

    // Past it, nothing is signed. Each of these differs from a case
    // above in exactly one number.
    assert!(
        matches!(
            close_start(
                &channel_with_span(1),
                hellas_kernel::Party::Taker,
                u64::MAX,
                None,
                &signer(0x22),
            ),
            Err(CloseError::WindowOverflow { height }) if height == u64::MAX
        ),
        "there is no block after the last one",
    );
    assert!(
        matches!(
            close_start(
                &channel_with_span(8),
                hellas_kernel::Party::Taker,
                u64::MAX - 1,
                None,
                &signer(0x22),
            ),
            Err(CloseError::WindowOverflow { .. })
        ),
        "an eight-block window does not fit before the ceiling",
    );
    assert!(
        matches!(
            close_start(
                &channel_with_span(0),
                hellas_kernel::Party::Taker,
                10,
                None,
                &signer(0x22),
            ),
            Err(CloseError::NoValidityWindow)
        ),
        "a zero-block window is a signature no block could carry",
    );
}

/// A start signed before a crash is the start that is resubmitted.
///
/// The endpoint is dropped and its journal reopened over its own files,
/// so what comes back is replayed rather than remembered. Signing a
/// second start here would be a second contest for one channel — and
/// the first one may already be in a mempool.
#[tokio::test]
async fn a_start_signed_before_a_crash_is_the_start_that_is_resubmitted() {
    let fixture = paid_job().await;
    let signed = {
        let provider = &fixture.service;
        match provider.prepare_close() {
            Ok(start) => start,
            Err(error) => panic!("a paid channel closes: {error}"),
        }
    };

    let mut watcher = restarted(fixture);
    assert_eq!(
        watcher.provider.state().close_prepared(),
        Some(&signed),
        "the reopened journal holds the exact bytes that were signed",
    );

    // One more finalized block, so a fresh signature would carry a
    // different window. Without it the two are the same bytes — the
    // signing is deterministic — and this would prove nothing.
    if let Err(error) = watcher
        .provider
        .observe_finalized(&block(CURSOR + 1, Vec::new()))
    {
        panic!("the block applies: {error}");
    }
    match watcher.provider.prepare_close() {
        Ok(again) => assert_eq!(
            again, signed,
            "the retained start is resubmitted, not replaced by a fresh one",
        ),
        Err(error) => panic!("the retained start is offered again: {error}"),
    }
    assert_eq!(watcher.provider.state().close_prepared(), Some(&signed));
}

// ── Answering a contest opened below what is held ─────────────────────

/// The provider answers a client that opened below what it has already
/// signed for, and answers exactly once.
///
/// Each refusal below differs from the admissible answer in one thing:
/// the contest is another, the answer already landed, the read is at
/// the deadline rather than a block before it, or the provider holds
/// nothing more than the contest already settles. The last is not a
/// fault — it is the case where the one answer the window admits would
/// buy nothing.
///
/// The endpoint here is the standalone one and not a [`WorkService`],
/// because answering is not a service operation: the service has a
/// journal and no sink, so it has nowhere to put an answer and no
/// hand-off state to record what became of one. `ProviderEndpoint` owns
/// source, sink and hand-off together, and is the only thing that may
/// build these bytes.
#[tokio::test]
async fn the_provider_answers_an_understated_contest_exactly_once() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let bond = bond_object();
    let payment_edge_object = payment_object();

    // The client opens at nothing, having a certificate for PRICE.
    let Ok(understated) = close_start(
        ready.channel(),
        hellas_kernel::Party::Maker,
        CURSOR,
        None,
        &client(),
    ) else {
        panic!("a client opens a close");
    };
    let id = contest_id(&ready, &understated, inclusion);

    let mut watcher = restarted(fixture);
    let provider = &mut watcher.provider;
    if let Err(error) = provider.observe_finalized(&block(
        inclusion,
        vec![hellas_kernel::Tx::move_action(
            hellas_kernel::Move::StartPaymentClose(understated),
        )],
    )) {
        panic!("the block applies: {error}");
    }
    assert_eq!(provider.state().close_opened(), Some((id, Party::Maker)));

    let deadline = inclusion + payment_terms().omit_response_blocks;
    let open = Contest::opened(id, deadline, 0);
    let read_at = |height: u64, record: &Contest| ObservedChannel {
        height,
        bond: Some(&bond),
        payment: Some(&payment_edge_object),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: pending_slot(record),
    };

    // One block before the deadline, the answer is the client's own
    // larger certificate.
    let answered = match provider.respond_to_close(&read_at(deadline - 1, &open)) {
        Ok(answer) => answer,
        Err(error) => panic!("an understated contest is answered: {error}"),
    };
    let hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    } = &answered
    else {
        panic!("an answer is a response move");
    };
    assert_eq!(response.start_id(), id);
    assert_eq!(response.responder_role(), hellas_kernel::Party::Taker);
    assert_eq!(response.certificate().earned_cumulative(), PRICE);

    // The bytes are signed, so the disk holds them before the caller
    // does. A caller handed an answer over a journal that never recorded
    // it could put it on chain behind this endpoint's back, and the
    // endpoint would go on owing — and then refusing — that same answer.
    assert_eq!(
        provider
            .state()
            .close_responded()
            .map(|held| (held.start_id, held.response_digest)),
        Some((
            id,
            response_body_digest(ready.channel(), id, response.certificate())
        )),
        "the answer this endpoint handed out is the answer it recorded",
    );

    // At the deadline the kernel calls it late, and so does this.
    assert!(
        matches!(
            provider.respond_to_close(&read_at(deadline, &open)),
            Err(CloseError::ResponseWindowClosed { height, deadline: owed })
                if height == deadline && owed == deadline
        ),
        "an answer at the deadline is late",
    );

    // The one answer, already landed.
    let mut settled = Contest::opened(id, deadline, 0);
    settled.final_cumulative = PRICE;
    settled.responded = true;
    settled.penalty_due = true;
    assert!(
        matches!(
            provider.respond_to_close(&read_at(deadline - 1, &settled)),
            Err(CloseError::AlreadyResponded)
        ),
        "there is one answer",
    );

    // A contest already at this endpoint's own high-water: nothing to
    // add, and the window is not spent saying so.
    let level = Contest::opened(id, deadline, PRICE);
    assert!(
        matches!(
            provider.respond_to_close(&read_at(deadline - 1, &level)),
            Err(CloseError::NothingToAdd { held, settled }) if held == PRICE && settled == PRICE
        ),
        "an equal high-water has no legal answer",
    );

    // Another contest in the slot.
    let elsewhere = Contest::opened(hellas_kernel::StartId::from_bytes([0x77; 32]), deadline, 0);
    assert!(
        matches!(
            provider.respond_to_close(&read_at(deadline - 1, &elsewhere)),
            Err(CloseError::OtherContest)
        ),
        "another contest is not this endpoint's to answer",
    );
}

/// A block that opens a contest this endpoint may answer.
fn understated_contest(ready: &ReadyChannel, inclusion: u64) -> (FinalizedWork, u64) {
    let Ok(understated) = close_start(
        ready.channel(),
        hellas_kernel::Party::Maker,
        CURSOR,
        None,
        &client(),
    ) else {
        panic!("a client opens a close");
    };
    let opened = block(
        inclusion,
        vec![hellas_kernel::Tx::move_action(
            hellas_kernel::Move::StartPaymentClose(understated),
        )],
    );
    (opened, inclusion + payment_terms().omit_response_blocks)
}

/// A caller stepping the cursor one block at a time is stopped at the
/// duty, exactly where the service's own loop stops.
///
/// This is the composition the sealing is about. A one-block apply
/// decides nothing about how far to read, so a caller that owns the
/// `for` loop owns the reading — and what it can read past is a real
/// deadline: once the cursor is at or beyond the response window,
/// `answerable_contest` deliberately stops returning the duty, and the
/// answer this endpoint could have given is never owed again. The stop
/// belongs to the driver, so every loop over it inherits the stop.
#[tokio::test]
async fn a_loop_of_one_block_calls_cannot_step_past_a_duty() {
    let fixture = paid_job().await;
    let inclusion = CURSOR + 1;
    let (opened, deadline) = understated_contest(&fixture.ready, inclusion);
    let provider = &fixture.service;
    if let Err(error) = observe_one(provider, &opened) {
        panic!("the block that opens the contest applies: {error}");
    }

    // One block at a time, the way a caller holding a loop drives, all
    // the way past the deadline it would otherwise cross.
    for height in (inclusion + 1)..=(deadline + 1) {
        let stepped = observe_one(provider, &block(height, Vec::new()));
        assert!(
            matches!(stepped, Err(CatchUpError::CloseDuty { height: at }) if at == inclusion),
            "block {height} was stepped past the duty: {stepped:?}",
        );
    }
    assert_eq!(
        provider
            .with_state(|state| state.cursor().0)
            .expect("the endpoint is reachable"),
        inclusion,
        "the cursor is still on the block that opened the contest",
    );
    assert!(
        provider
            .with_state(|state| state.answerable_contest().is_some())
            .expect("the endpoint is reachable"),
        "and the answer is still owed rather than late",
    );
}

/// A backlog whose *first* block opens a contest is read no further.
///
/// The restart case §5 names: ten thousand blocks behind, and the duty
/// is in block one. A loop that read its advertised range to completion
/// would discharge nothing until the tip, by which time the response
/// window has shut. The source counts both its questions, so "no
/// successor block is read" is a claim about reads and not about
/// intentions.
#[tokio::test]
async fn a_backlog_stops_on_the_block_that_opened_the_contest() {
    let fixture = paid_job().await;
    let inclusion = CURSOR + 1;
    let (opened, deadline) = understated_contest(&fixture.ready, inclusion);
    let mut blocks = vec![opened];
    blocks.extend(((inclusion + 1)..=(deadline + 5)).map(|height| block(height, Vec::new())));
    let chain = CountingChain::over(blocks);

    let caught = fixture.service.catch_up_job(&chain, fixture.id).await;
    assert!(
        matches!(caught, Err(CatchUpError::CloseDuty { height }) if height == inclusion),
        "the backlog stopped on the duty rather than reading to its tip: {caught:?}",
    );
    assert_eq!(
        chain.reads(),
        2,
        "the tip, then the one block that carried the duty, and nothing after it",
    );
    assert_eq!(
        fixture
            .service
            .with_state(|state| state.cursor().0)
            .expect("the endpoint is reachable"),
        inclusion,
    );
    assert!(
        fixture
            .service
            .with_state(|state| state.answerable_contest().is_some())
            .expect("the endpoint is reachable"),
        "and the duty is owed inside its window, not past it",
    );
}

/// A served channel's close duty is *discharged*: the answer reaches a
/// sink, and the cursor then reads past the contest that stopped it.
///
/// The other half of the no-runner gap. The stop was right and it was
/// permanent: nothing reachable from a `WorkService` could offer the
/// answer, so once a contest opened, every later read of this channel
/// answered `CloseDuty` at the same height for ever. One driver now
/// owns source, sink and hand-off together, and what lets the read
/// through afterwards is that hand-off and not a journal claim of
/// doneness — the contest is still answerable on the disk while the
/// cursor moves past it, which is exactly the state a duty a sink holds
/// is in.
#[tokio::test]
async fn a_driven_close_duty_is_discharged_and_the_cursor_passes() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let (opened, deadline) = understated_contest(&ready, inclusion);
    let chain = Chain {
        blocks: std::iter::once(opened)
            .chain(((inclusion + 1)..=(inclusion + 2)).map(|height| block(height, Vec::new())))
            .collect(),
        withheld: None,
    };
    assert!(
        inclusion + 2 < deadline,
        "the whole of this read is inside the response window",
    );
    let sink = Mempool::default();

    // The drive: read to the contest, fix the answer, offer it, and
    // record what the sink did with it.
    let start_id = match fixture.service.advance_close(&chain, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => start_id,
        other => panic!("the contest is read and answered: {other:?}"),
    };
    assert_eq!(
        fixture
            .service
            .with_state(|state| state.cursor().0)
            .expect("the endpoint is reachable"),
        inclusion,
        "the read stopped on the contest to service it",
    );
    let taken = sink.taken();
    assert_eq!(taken.len(), 1, "one contest, one answer");
    let hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    } = &taken[0]
    else {
        panic!("the submitted transaction is a response move");
    };
    assert_eq!(response.start_id(), start_id);
    assert_eq!(
        response.certificate().earned_cumulative(),
        PRICE,
        "the answer spends the certificate the contest understated",
    );
    let responded = fixture
        .service
        .with_state(|state| state.close_responded())
        .expect("the endpoint is reachable")
        .expect("the serviced duty is on the disk");
    assert_eq!(
        responded.response_digest,
        response_body_digest(ready.channel(), start_id, response.certificate()),
        "the journaled digest is the one the submitted answer was signed over",
    );

    // And the read that was refused for ever now passes the contest —
    // through the ordinary request-path catch-up, which owns no sink and
    // discharged nothing itself.
    let caught = fixture.service.catch_up_job(&chain, fixture.id).await;
    assert!(
        matches!(caught, Ok(height) if height == inclusion + 2),
        "a discharged duty does not stop the read: {caught:?}",
    );
    assert!(
        fixture
            .service
            .with_state(|state| state.answerable_contest().is_some())
            .expect("the endpoint is reachable"),
        "and the contest is still answerable on the disk, so it is the \
         hand-off that let the cursor through and not a record saying done",
    );
}

/// A sink that refuses the answer leaves the duty owed, and the cursor
/// does not run to a tip past the deadline.
///
/// `Full` and `ValidationRejected` are successful results that mean *not
/// enqueued*. Reading the hand-off as "offered, therefore finished"
/// would let every later read run free — and the backlog here outlives
/// the response window, so the cursor would arrive past the deadline
/// with the answer still on the disk and the contest settling on the
/// claim this provider could have beaten.
#[tokio::test]
async fn a_refused_hand_off_leaves_the_duty_owed_short_of_the_deadline() {
    let fixture = paid_job().await;
    let inclusion = CURSOR + 1;
    let (opened, deadline) = understated_contest(&fixture.ready, inclusion);
    let backlog = Chain {
        blocks: std::iter::once(opened)
            .chain(((inclusion + 1)..=(deadline + 4)).map(|height| block(height, Vec::new())))
            .collect(),
        withheld: None,
    };

    for outcome in [
        hellas_rpc::SubmitTxOutcome::Full,
        hellas_rpc::SubmitTxOutcome::ValidationRejected,
    ] {
        let name = format!("{outcome:?}");
        let refusing = Mempool::answering(outcome);
        match fixture.service.advance_close(&backlog, &refusing).await {
            Ok(CloseProgress::Opened { .. }) => {}
            other => panic!("{name}: the contest is still open: {other:?}"),
        }
        assert_eq!(
            refusing.taken().len(),
            1,
            "{name}: the answer was offered once",
        );

        // Owed, so the ordinary read stops at it rather than running the
        // backlog out past the window.
        let caught = fixture.service.catch_up_job(&backlog, fixture.id).await;
        let cursor = fixture
            .service
            .with_state(|state| state.cursor().0)
            .expect("the endpoint is reachable");
        assert!(
            matches!(caught, Err(CatchUpError::CloseDuty { height }) if height == cursor),
            "{name}: an answer nobody took still stops the read: {caught:?}",
        );
        assert!(
            cursor < deadline,
            "{name}: stopped at {cursor}, inside a window that shuts at {deadline}",
        );
        assert!(
            fixture
                .service
                .with_state(|state| state.answerable_contest().is_some())
                .expect("the endpoint is reachable"),
            "{name}: and the answer is still owed rather than late",
        );
    }
}

// ── The cutoff a finalized close is ───────────────────────────────────

/// One job, run to a signed result and not yet released.
async fn ready_job() -> Checked {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let id = accept(&mut [&mut client_store, &mut provider_store]);
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    let Ok(client) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    run_to_result(&service, &ready, id).await;
    Checked {
        client_root,
        provider_root,
        ready,
        service,
        client,
        id,
    }
}

/// A finalized close start takes the answer off the wire.
///
/// The exploit, end to end. The provider has signed a result and not
/// released it. The client opens a close carrying no certificate at
/// all, so the contest settles at nothing and the provider has nothing
/// higher to answer it with. Then the client asks for the plaintext.
///
/// Before this, it got it: the result was on the provider's disk, the
/// job read as ready, and no transition consulted the contest. The
/// compute was spent, the answer was taken, and nothing was signed for
/// it. Now the block that opens the contest is also what ends the job,
/// and the delivery has nothing to release.
#[tokio::test]
async fn a_finalized_close_start_takes_the_answer_off_the_wire() {
    let mut fixture = ready_job().await;
    let ready = fixture.ready.clone();
    let id = fixture.id;

    // The client's own start, carrying nothing.
    let Ok(understated) = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
    else {
        panic!("a client opens a close");
    };
    let inclusion = CURSOR + 1;
    let contest = contest_id(&ready, &understated, inclusion);
    let start_tx =
        hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(understated));

    {
        let provider = &fixture.service;
        assert_eq!(
            provider
                .with_state(|state| state.jobs().next().map(JobState::phase))
                .expect("the endpoint is reachable"),
            Some(JobPhase::Ready),
            "the answer exists and has not left",
        );
        if let Err(error) = observe_one(provider, &block(inclusion, vec![start_tx])) {
            panic!("the block applies: {error}");
        }
        let (opened, open_job, expired) = provider
            .with_state(|state| {
                (
                    state.close_opened(),
                    state.jobs().next().is_some(),
                    matches!(
                        state.terminals().next().map(|terminal| &terminal.outcome),
                        Some(TerminalOutcome::Expired { .. }),
                    ),
                )
            })
            .expect("the endpoint is reachable");
        assert_eq!(opened, Some((contest, Party::Maker)));
        assert!(
            !open_job,
            "a job no payment can reach is not a job that is still open",
        );
        // And it rests at an expired terminal: the provider bears the
        // compute it spent on a job a close cut off.
        assert!(expired, "the cut-off job rests at an expired terminal");
    }

    // The delivery call the exploit ends with.
    let (transport, server) = transport_pair();
    let serving = serve(server, fixture.service.clone());
    let refused = fetch_result(transport, &mut fixture.client, &ready, id).await;
    stop(serving).await;
    let Err(hellas_work::work::DeliverError::Refused { refusal, .. }) = refused else {
        panic!("a closed channel releases nothing: {refused:?}");
    };
    assert_eq!(refusal, hellas_work::work::WorkRefusal::Declined);
    assert_eq!(
        fixture.client.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Accepted),
        "and the client has no answer to check",
    );

    // Nor is there a fresh job to take its place: this channel's one job
    // has reached its permanent terminal.
    let response = {
        let provider = &fixture.service;
        provider.accept(&signed_request(NONCE, 1))
    };
    let Some(AcceptOutcome::Refused(refused)) = response.outcome else {
        panic!("a terminated channel takes no work: {response:?}");
    };
    assert_eq!(refused.code, WorkRefusalCode::Conflict as i32);
}

/// A block out of order writes nothing before it is refused.
///
/// The transitions a block carries move money and shut the channel, so
/// they may not run before the block is one this journal may read. A
/// forged or merely early `h + 2` would otherwise end the job, charge
/// the client, record the contest, and only then be turned away by the
/// cursor — leaving every one of those effects on the disk under a
/// height this endpoint never reached.
#[tokio::test]
async fn a_block_out_of_order_writes_nothing_before_it_is_refused() {
    let fixture = ready_job().await;
    let ready = fixture.ready.clone();
    let provider = &fixture.service;
    let before = provider
        .with_state(|state| state.clone())
        .expect("the endpoint is reachable");

    let Ok(understated) = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
    else {
        panic!("a client opens a close");
    };
    let start_tx =
        hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(understated));
    // Two blocks on, and past the payment deadline as well, so every
    // transition `observe` has would fire if it ran at all.
    let skipped = CURSOR + 2;
    assert!(skipped > deadlines().payment || CURSOR + 2 == skipped);
    let applied = observe_one(provider, &block(skipped, vec![start_tx]));
    assert!(
        matches!(
            applied,
            Err(CatchUpError::Store(
                hellas_work::work_store::WorkStoreError::Channel(
                    hellas_work::work_store::ChannelStateError::CursorNotNext { held, actual }
                )
            )) if held == CURSOR && actual == skipped
        ),
        "a skipped height is not this journal's next block: {applied:?}",
    );
    assert_eq!(
        provider
            .with_state(|state| state.clone())
            .expect("the endpoint is reachable"),
        before,
        "and nothing the block claimed reached the disk",
    );
}

/// The first catch-up cannot skip the channel's own history.
///
/// The exploit it closes: setup finishes at the channel's origin, the
/// client opens and settles a close in the blocks just after it, and
/// the provider starts watching later. A watcher that anchored at the
/// latest finalized block would see neither, report itself caught up,
/// and go on accepting work against an edge that is already gone.
///
/// The store is anchored at the block that opened the channel, so the
/// scan starts one block later whatever the tip says.
#[tokio::test]
async fn a_first_catch_up_cannot_skip_the_channels_own_history() {
    let root = temp();
    let ready = ready();
    // A store that has read nothing since the channel opened, which is
    // what a provider coming up for the first time has.
    let store = store_at(root.path(), &ready, Role::Provider, 0);
    assert_eq!(store.state().cursor(), (0, payload_at(0)));
    let Ok(mut provider) = ProviderEndpoint::new(ready.clone(), store, provider()) else {
        panic!("the provider endpoint binds");
    };

    // The client settles the payment edge in the second block of the
    // channel's life, and twenty more blocks go by.
    let settled_at = 2;
    let close = hellas_kernel::Tx::close(
        payment_edge(),
        hellas_kernel::Proof::adjudicated(hellas_kernel::PaymentContestCommitment::from_bytes(
            [0x02; 32],
        )),
        List::take([Payout::new(client().party_key(), 1); MAX_EDGE_OUTPUTS], 1),
    );
    let chain = Chain {
        blocks: (1..=20)
            .map(|height| {
                let txs = if height == settled_at {
                    vec![close.clone()]
                } else {
                    Vec::new()
                };
                block(height, txs)
            })
            .collect(),
        withheld: None,
    };
    match provider.catch_up(&chain).await {
        Ok(reached) => assert_eq!(reached, 20),
        Err(error) => panic!("the watcher catches up: {error}"),
    }
    let settlement = provider.state().close_settled();
    assert_eq!(
        settlement.map(|settled| settled.height),
        Some(settled_at),
        "the close eighteen blocks back is this channel's",
    );

    // And the channel it found closed admits no work.
    let response = provider.accept(&signed_request(NONCE, 1));
    let Some(AcceptOutcome::Refused(refused)) = response.outcome else {
        panic!("a settled edge takes no work: {response:?}");
    };
    assert_eq!(refused.code, WorkRefusalCode::Declined as i32);
}

// ── Getting the close to a validator ──────────────────────────────────

/// Every transaction one sink was handed, in order.
///
/// `outcome` is what the sink *answers*, which is not the same question
/// as whether the call succeeded: `Full` and `ValidationRejected` are
/// successful results meaning the transaction was not enqueued, and a
/// caller that read them as acceptance would stop sending an answer
/// nobody has.
#[derive(Default)]
struct Mempool {
    submitted: std::sync::Mutex<Vec<hellas_kernel::Tx>>,
    refuse: bool,
    outcome: Option<hellas_rpc::SubmitTxOutcome>,
}

impl Mempool {
    fn answering(outcome: hellas_rpc::SubmitTxOutcome) -> Self {
        Self {
            outcome: Some(outcome),
            ..Self::default()
        }
    }

    fn taken(&self) -> Vec<hellas_kernel::Tx> {
        match self.submitted.lock() {
            Ok(taken) => taken.clone(),
            Err(error) => panic!("the fixture mempool is readable: {error}"),
        }
    }
}

impl hellas_work::work_close::TxSink for Mempool {
    async fn submit(
        &self,
        tx: hellas_kernel::Tx,
    ) -> Result<hellas_rpc::SubmitTxOutcome, BlockSourceError> {
        if self.refuse {
            return Err(BlockSourceError::new("this validator is not taking work"));
        }
        match self.submitted.lock() {
            Ok(mut taken) => taken.push(tx),
            Err(error) => panic!("the fixture mempool is writable: {error}"),
        }
        Ok(self
            .outcome
            .unwrap_or(hellas_rpc::SubmitTxOutcome::Enqueued))
    }
}

/// A retained start is submitted until a block carries it.
///
/// The step before this one built a transaction and handed it back to
/// nobody: `chain::submit_tx` existed and was never called, so a signed
/// close sat on the disk and the channel it was signed to end stayed
/// open for good. What this drives is the whole of the rest — read to
/// the tip, resubmit if no contest is there yet, and stop on the block
/// that says one is.
#[tokio::test]
async fn a_retained_start_is_resubmitted_until_a_block_carries_it() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let mut watcher = restarted(fixture);
    let provider = &mut watcher.provider;
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    let start_tx =
        hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(start.clone()));
    let sink = Mempool::default();

    // Two rounds against a chain that has not carried it. The same
    // bytes each time: a resubmission is the same close.
    let quiet = Chain {
        blocks: ((CURSOR + 1)..=(CURSOR + 2))
            .map(|h| block(h, Vec::new()))
            .collect(),
        withheld: None,
    };
    for round in 0..2 {
        match provider.advance_close(&quiet, &sink).await {
            Ok(CloseProgress::Submitted {
                valid_through,
                outcome,
            }) => {
                assert_eq!(valid_through, start.valid_through_height());
                assert_eq!(outcome, hellas_rpc::SubmitTxOutcome::Enqueued);
            }
            other => panic!("round {round}: the start is submitted: {other:?}"),
        }
    }
    assert_eq!(sink.taken(), vec![start_tx.clone(), start_tx.clone()]);

    // The block that carries it. The contest is finalized, and nothing
    // is submitted again.
    let inclusion = CURSOR + 3;
    let carried = Chain {
        blocks: ((CURSOR + 1)..=(CURSOR + 4))
            .map(|h| {
                if h == inclusion {
                    block(h, vec![start_tx.clone()])
                } else {
                    block(h, Vec::new())
                }
            })
            .collect(),
        withheld: None,
    };
    let expected = contest_id(&ready, &start, inclusion);
    match provider.advance_close(&carried, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the contest is open: {other:?}"),
    }
    assert_eq!(
        sink.taken().len(),
        2,
        "an opened contest is not resubmitted"
    );
    assert_eq!(
        provider.state().close_opened(),
        Some((expected, Party::Taker)),
    );
}

/// A start that can no longer be included leaves the channel open.
///
/// The gate this releases: a signature that reached no block used to
/// shut the channel for good, so an endpoint whose start was never
/// included could take no more work *and* could never close — the
/// close it needed was the one thing it was no longer allowed to sign.
#[tokio::test]
async fn a_start_that_never_landed_reopens_the_channel() {
    let fixture = paid_job().await;
    let mut watcher = restarted(fixture);
    let provider = &mut watcher.provider;
    let Ok(start) = provider.prepare_close() else {
        panic!("a paid channel closes");
    };
    assert!(provider.state().is_closing(), "the window is open");
    let sink = Mempool::default();

    // Every block of the window, and none of them carries it.
    let last = start.valid_through_height();
    let quiet = Chain {
        blocks: ((CURSOR + 1)..=last)
            .map(|h| block(h, Vec::new()))
            .collect(),
        withheld: None,
    };
    match provider.advance_close(&quiet, &sink).await {
        Ok(CloseProgress::Submitted { .. }) => {}
        other => panic!("the last block of the window still admits it: {other:?}"),
    }

    // One block past it.
    let past = Chain {
        blocks: ((CURSOR + 1)..=(last + 1))
            .map(|h| block(h, Vec::new()))
            .collect(),
        withheld: None,
    };
    match provider.advance_close(&past, &sink).await {
        Ok(CloseProgress::Nothing) => {}
        other => panic!("a start that cannot land is nothing: {other:?}"),
    }
    assert!(
        !provider.state().is_closing(),
        "a signature that reached no block does not shut a channel for good",
    );

    // And so it may sign a fresh close: the one thing it needed was no
    // longer forbidden.
    if let Err(error) = provider.prepare_close() {
        panic!("a channel not shut for good may still close: {error}");
    }
}

/// The client closes its own channel, and it is the same step.
///
/// Symmetry is not tidiness here. A provider that stops answering
/// leaves the client's funded payment edge locked up, and the only
/// thing that frees it is a close the client opens itself.
#[tokio::test]
async fn a_client_closes_the_channel_its_provider_stopped_answering() {
    let mut fixture = paid_job().await;
    let start = match fixture.client.prepare_close() {
        Ok(start) => start,
        Err(error) => panic!("a client closes its own channel: {error}"),
    };
    assert_eq!(start.opener_role(), Party::Maker);
    assert_eq!(start.payment_edge(), payment_edge());
    // At what it has already signed for, which is what the omission
    // bond punishes a client for understating.
    let Some(payment) = fixture.client.state().last_payment() else {
        panic!("the client retains what it paid");
    };
    assert_eq!(
        start.certificate().copied(),
        Some((payment.certificate, payment.certificate_signature)),
    );

    // Retained, and offered again rather than signed twice.
    match fixture.client.prepare_close() {
        Ok(again) => assert_eq!(again, start),
        Err(error) => panic!("the retained start is offered again: {error}"),
    }

    // And handed to consensus.
    let sink = Mempool::default();
    let quiet = Chain {
        blocks: vec![block(CURSOR + 1, Vec::new())],
        withheld: None,
    };
    match fixture.client.advance_close(&quiet, &sink).await {
        Ok(CloseProgress::Submitted {
            valid_through,
            outcome,
        }) => {
            assert_eq!(valid_through, start.valid_through_height());
            assert_eq!(outcome, hellas_rpc::SubmitTxOutcome::Enqueued);
        }
        other => panic!("the client's start is submitted: {other:?}"),
    }
    assert_eq!(
        sink.taken(),
        vec![hellas_kernel::Tx::move_action(
            hellas_kernel::Move::StartPaymentClose(start)
        )],
    );
}

// ── Three deadlines, three answers ────────────────────────────────────

/// Each deadline ends the job it is about, at its own height.
///
/// One deadline used to do all three, and it did them at the wrong
/// height: a proposal the provider never co-signed held its reservation
/// until the *payment* deadline, and a job that produced no result in
/// time held it just as long.
///
/// The three cases below are the three phases the height can find a job
/// in, and the only thing varied is which deadline the block has passed.
/// The provider bears whatever it spent — there is no counterparty ledger
/// to move.
#[tokio::test]
async fn each_deadline_ends_its_own_job() {
    // A proposal with no co-signature, past the acceptance deadline.
    // Nobody produced anything, so nobody owes for it.
    {
        let root = temp();
        let ready = ready();
        let mut store = store_at(root.path(), &ready, Role::Provider, CURSOR);
        let authorization = authorization();
        let Ok(prepared_input) = bundle(NONCE).encode() else {
            panic!("the fixture bundle encodes");
        };
        commit(
            &mut store,
            ChannelRecord::JobProposed {
                authorization,
                client_signature: client()
                    .sign(signing_hash(work_id(ready.channel(), &authorization))),
                prepared_input,
            },
        );
        let Ok(mut provider) = ProviderEndpoint::new(ready, store, provider()) else {
            panic!("the provider endpoint binds");
        };

        for height in (CURSOR + 1)..=deadlines().acceptance {
            if let Err(error) = provider.observe_finalized(&block(height, Vec::new())) {
                panic!("the block at {height} applies: {error}");
            }
        }
        assert!(
            provider.state().jobs().next().is_some(),
            "the deadline itself is still a height the co-signature may be made at",
        );
        if let Err(error) =
            provider.observe_finalized(&block(deadlines().acceptance + 1, Vec::new()))
        {
            panic!("the block past acceptance applies: {error}");
        }
        assert!(
            provider.state().jobs().next().is_none(),
            "the proposal is over"
        );
        assert!(
            matches!(
                provider
                    .state()
                    .terminals()
                    .next()
                    .map(|terminal| &terminal.outcome),
                Some(TerminalOutcome::Expired { .. }),
            ),
            "an un-co-signed proposal past acceptance rests at an expired terminal",
        );
    }

    // An accepted job with no result, past the terminal deadline. The
    // provider did not finish, and that is the provider's own loss.
    {
        let root = temp();
        let ready = ready();
        let mut store = store_at(root.path(), &ready, Role::Provider, CURSOR);
        let _ = accept(&mut [&mut store]);
        let Ok(mut provider) = ProviderEndpoint::new(ready, store, provider()) else {
            panic!("the provider endpoint binds");
        };
        for height in (CURSOR + 1)..=deadlines().terminal {
            if let Err(error) = provider.observe_finalized(&block(height, Vec::new())) {
                panic!("the block at {height} applies: {error}");
            }
        }
        assert!(
            provider.state().jobs().next().is_some(),
            "a result at the deadline itself is still owed and still payable",
        );
        if let Err(error) = provider.observe_finalized(&block(deadlines().terminal + 1, Vec::new()))
        {
            panic!("the block past the terminal deadline applies: {error}");
        }
        assert!(provider.state().jobs().next().is_none(), "the job is over");
        assert!(
            matches!(
                provider
                    .state()
                    .terminals()
                    .next()
                    .map(|terminal| &terminal.outcome),
                Some(TerminalOutcome::Expired { .. }),
            ),
            "a provider that did not finish bears it at an expired terminal",
        );
    }

    // A job whose result exists and was in time, past the payment
    // deadline, also rests at an expired terminal. That is
    // `the_watcher_ends_a_job_its_payment_deadline_has_passed`'s.
}

/// A local ending is the provider's own, and rests at a failed terminal.
///
/// The local surface can only end a job as the provider's own fault:
/// `end_run` takes no reason, and the one it records is a failed
/// terminal the provider bears. The ending that charges a client — an
/// expiry decided from finalized heights — is the watcher's alone.
#[tokio::test]
async fn a_local_ending_is_the_providers_own_failed_terminal() {
    let fixture = checked_job().await;
    let id = fixture.id;
    let provider = &fixture.service;
    if let Err(error) = provider.end_run(id) {
        panic!("the local ending records: {error}");
    }
    let (open_job, failed) = provider
        .with_state(|state| {
            (
                state.jobs().next().is_some(),
                matches!(
                    state.terminals().next().map(|terminal| &terminal.outcome),
                    Some(TerminalOutcome::Failed { .. }),
                ),
            )
        })
        .expect("the endpoint is reachable");
    assert!(!open_job, "the job is over");
    assert!(
        failed,
        "a locally ended job rests at a failed terminal the provider bears",
    );
}

// ── Closing what admits no new work ───────────────────────────────────
//
// Three states a close driver exists for, and `check_ready` refuses
// every one of them: an open contest, a bond edge that is gone, and an
// admission horizon that has passed. Each test asks that refusal first,
// against the same descriptor and a coherent read, so the claim these
// mounts rest on is checked rather than asserted — and then builds the
// close capability from the journal and the key alone, which is the
// whole of what a close reads.

/// A provider journal opened without a readiness decision anywhere in
/// sight.
///
/// The channel and the settlement come from the configured descriptor
/// and the funded edge, which is exactly what `work_open::mount` hands a
/// close-only channel. Nothing here calls `check_ready`, and on these
/// channels nothing could.
fn close_only_store(root: &std::path::Path, height: u64) -> ChannelStore {
    let mut store = match ChannelStore::open(
        root,
        descriptor().channel().clone(),
        settlement(),
        Role::Provider,
        origin(),
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the close-only store opens: {error}"),
    };
    advance(&mut store, height);
    store
}

/// The close half of a restarted provider, over the journal a paid job
/// left behind.
struct CloseWatcher {
    provider: CloseEndpoint,
    _client_root: tempfile::TempDir,
    _provider_root: tempfile::TempDir,
}

fn close_only_restart(fixture: Checked, height: u64) -> CloseWatcher {
    let Checked {
        client_root,
        provider_root,
        service,
        client,
        ..
    } = fixture;
    drop(service);
    drop(client);
    let store = close_only_store(provider_root.path(), height);
    match CloseEndpoint::new(store, provider()) {
        Ok(provider) => CloseWatcher {
            provider,
            _client_root: client_root,
            _provider_root: provider_root,
        },
        Err(error) => panic!("the close half binds without a readiness: {error}"),
    }
}

/// One coherent finalized read of the fixture channel.
fn observed<'a>(
    height: u64,
    bond: Option<&'a Edge>,
    payment: Option<&'a Edge>,
    pending: PendingSlot,
) -> ObservedChannel<'a> {
    ObservedChannel {
        height,
        bond,
        payment,
        lease: match bond {
            None => LeaseSlots::Absent,
            Some(_) => lease_over(bond_edge(), payment_edge()),
        },
        pending,
    }
}

/// What this service answers the proposal with.
fn proposal_refusal(service: &WorkService, proposal_nonce: u64) -> i32 {
    match service
        .accept(&signed_request(NONCE, proposal_nonce))
        .outcome
    {
        Some(AcceptOutcome::Refused(refused)) => refused.code,
        other => panic!("a channel that admits no new work refuses: {other:?}"),
    }
}

/// The finalized close that pays this provider `payout`.
fn settling_close(payout: u64) -> hellas_kernel::Tx {
    hellas_kernel::Tx::close(
        payment_edge(),
        hellas_kernel::Proof::adjudicated(hellas_kernel::PaymentContestCommitment::from_bytes(
            [0x44; 32],
        )),
        List::take(
            [Payout::new(provider().party_key(), payout); MAX_EDGE_OUTPUTS],
            1,
        ),
    )
}

/// A channel with an open contest mounts a close-capable service, and
/// that service discharges the duty.
///
/// The contest is the one `check_ready` refuses, asked first and
/// checked: a `PendingClose` is not a readiness decision, so the type
/// the old `ProviderEndpoint::new` demanded could not be built for this
/// channel at all, and the answer this provider owes could not be sent.
/// The journal, meanwhile, holds everything the answer is derived from —
/// the contest the watcher recorded, and the client's own certificate —
/// so the close half needs nothing the readiness carried.
#[tokio::test]
async fn a_contested_channel_mounts_a_close_capable_service() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let understated = close_start(ready.channel(), Party::Maker, CURSOR, None, &client())
        .expect("a client opens a close");
    let expected = contest_id(&ready, &understated, inclusion);
    let deadline = inclusion + payment_terms().omit_response_blocks;

    // The readiness this endpoint would once have needed does not exist.
    let bond = bond_object();
    let payment = payment_object();
    let contested = observed(
        inclusion,
        Some(&bond),
        Some(&payment),
        pending_slot(&Contest::opened(expected, deadline, 0)),
    );
    match descriptor().check_ready(&contested) {
        Err(WorkSetupError::PendingClose { .. }) => {}
        other => panic!("an open contest admits no new work: {other:?}"),
    }

    let watcher = close_only_restart(fixture, CURSOR);
    let service = WorkService::close_only(watcher.provider);
    let chain = Chain {
        blocks: vec![block(
            inclusion,
            vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(understated),
            )],
        )],
        withheld: None,
    };
    let sink = Mempool::default();
    match service.advance_close(&chain, &sink).await {
        Ok(CloseProgress::Opened { start_id }) => assert_eq!(start_id, expected),
        other => panic!("the contest is read and answered: {other:?}"),
    }

    let taken = sink.taken();
    assert_eq!(taken.len(), 1, "the close-only service answered");
    let hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    } = &taken[0]
    else {
        panic!("the submitted transaction is a response move");
    };
    assert_eq!(response.start_id(), expected);
    assert_eq!(response.certificate().earned_cumulative(), PRICE);

    let responded = service
        .with_state(|state| state.close_responded())
        .expect("the endpoint is reachable")
        .expect("the serviced duty is on the disk");
    assert_eq!(responded.start_id, expected);
    assert_eq!(
        responded.response_digest,
        response_body_digest(ready.channel(), expected, response.certificate()),
        "the journaled digest is the one the submitted answer was signed over",
    );
    assert_eq!(
        proposal_refusal(&service, 1),
        WorkRefusalCode::Conflict as i32,
        "retrying the certified job returns its permanent terminal before readiness",
    );
    assert_eq!(
        proposal_refusal(&service, 2),
        WorkRefusalCode::NotReady as i32,
        "and it admits no new work while it has no readiness decision",
    );
}

/// The `(bond absent, payment live)` mount closes its own payment edge.
///
/// This is §7's permissionless leased-bond timeout: the bond is gone,
/// the lease with it, and the payment edge this provider is owed out of
/// is untouched. `check_ready` refuses at the first fact it reads, and
/// the close that recovers the earnings is exactly what must still run.
#[tokio::test]
async fn a_close_only_mount_without_a_bond_closes_its_payment_edge() {
    let fixture = paid_job().await;
    let payment = payment_object();
    match descriptor().check_ready(&observed(CURSOR, None, Some(&payment), PendingSlot::Absent)) {
        Err(WorkSetupError::NotLive { object }) => assert_eq!(object, "the bond edge"),
        other => panic!("a channel whose bond is gone admits no new work: {other:?}"),
    }

    let mut watcher = close_only_restart(fixture, CURSOR);
    let start = watcher
        .provider
        .prepare_close()
        .expect("a paid channel closes without a readiness decision");
    assert_eq!(
        start
            .certificate()
            .map(|(earned, _)| earned.earned_cumulative()),
        Some(PRICE),
        "the start spends the certificate the journal holds",
    );

    let sink = Mempool::default();
    let empty = Chain {
        blocks: Vec::new(),
        withheld: None,
    };
    match watcher.provider.advance_close(&empty, &sink).await {
        Ok(CloseProgress::Submitted { valid_through, .. }) => {
            assert_eq!(
                valid_through,
                CURSOR + payment_terms().start_validity_blocks
            );
        }
        other => panic!("the retained start is handed to consensus: {other:?}"),
    }
    assert_eq!(sink.taken().len(), 1);

    // And the close that lands is observed for itself, which is the
    // terminal answer a close-only mount exists to reach.
    let settling = Chain {
        blocks: vec![block(CURSOR + 1, vec![settling_close(PRICE)])],
        withheld: None,
    };
    match watcher.provider.advance_close(&settling, &sink).await {
        Ok(CloseProgress::Settled { provider_payout }) => assert_eq!(provider_payout, PRICE),
        other => panic!("the close settles this edge: {other:?}"),
    }
}

/// A channel past its admission horizon still closes.
///
/// The horizon is the last height new work may be admitted at, and
/// nothing else: the payment edge outlives it, and so does what this
/// provider has already earned on it.
#[tokio::test]
async fn a_channel_past_its_horizon_still_closes() {
    let fixture = paid_job().await;
    let bond = bond_object();
    let payment = payment_object();
    match descriptor().check_ready(&observed(
        HORIZON,
        Some(&bond),
        Some(&payment),
        PendingSlot::Absent,
    )) {
        Err(WorkSetupError::HorizonPassed { height, horizon }) => {
            assert_eq!((height, horizon), (HORIZON, HORIZON));
        }
        other => panic!("a channel at its horizon admits no new work: {other:?}"),
    }

    let mut watcher = close_only_restart(fixture, HORIZON);
    assert_eq!(watcher.provider.state().cursor().0, HORIZON);
    watcher
        .provider
        .prepare_close()
        .expect("a channel past its horizon still closes");

    let sink = Mempool::default();
    let empty = Chain {
        blocks: Vec::new(),
        withheld: None,
    };
    match watcher.provider.advance_close(&empty, &sink).await {
        Ok(CloseProgress::Submitted { valid_through, .. }) => {
            assert_eq!(
                valid_through,
                HORIZON + payment_terms().start_validity_blocks
            );
        }
        other => panic!("the retained start is handed to consensus: {other:?}"),
    }
    assert_eq!(sink.taken().len(), 1);
}

/// A close-only service admits no new work until a fresh readiness
/// decision arrives, and admits it the moment one does.
///
/// The option is the whole gate, and the value that fills it has one
/// producer: `check_ready`. So "refuses until a fresh readiness
/// succeeds" is not a rule this service applies, it is the only way the
/// value it needs can come into existence.
#[tokio::test]
async fn a_close_only_service_admits_work_only_once_a_readiness_arrives() {
    let root = temp();
    let endpoint = CloseEndpoint::new(close_only_store(root.path(), CURSOR), provider())
        .expect("the close half binds without a readiness");
    let service = WorkService::close_only(endpoint);

    assert_eq!(
        proposal_refusal(&service, 1),
        WorkRefusalCode::NotReady as i32,
        "a channel with no readiness decision admits no work",
    );
    assert!(
        service
            .with_state(|state| state.jobs().next().is_none())
            .expect("the endpoint is reachable"),
        "and the refused proposal reserved nothing",
    );

    service
        .admit_new_work(ready())
        .expect("a fresh readiness for this journal's own channel is taken");

    match service.accept(&signed_request(NONCE, 1)).outcome {
        Some(AcceptOutcome::Accepted(_)) => {}
        other => panic!("the same proposal is now co-signed: {other:?}"),
    }
    assert!(
        service
            .with_state(|state| state.jobs().next().is_some())
            .expect("the endpoint is reachable"),
        "and the accepted job is on the disk",
    );
}

// ── The measurement seams §4's budgets are made of ────────────────────

/// The close path samples the tip it read, each block it fetched, and
/// the fsync that retained its start — one sample per piece of work.
///
/// `Wstart` adds `fresh_tip_ms` to `close_prepared_fsync_ms`; `Wresp`
/// counts `one_block_fetch_ms` once, because §5's loop applies one block
/// before it asks for another. So what a reader must be able to
/// reconstruct is *which* fetch each sample was, and that is what the
/// per-height identity below is for. A seam that summed the backlog
/// would report one number and the deadline would be spent against the
/// wrong one.
#[tokio::test]
async fn a_close_step_samples_its_tip_its_blocks_and_its_prepared_fsync() {
    use tracing::instrument::WithSubscriber as _;

    let fixture = paid_job().await;
    let mut watcher = restarted(fixture);
    let provider = &mut watcher.provider;
    let samples = std::sync::Arc::new(Samples::new());

    let Ok(start) = tracing::subscriber::with_default(samples.clone(), || provider.prepare_close())
    else {
        panic!("a paid channel closes");
    };
    assert_eq!(
        samples.of("close_prepared_fsync_ms").len(),
        1,
        "one start retained, one fsync sampled",
    );
    let prepared = samples.of("close_prepared_fsync_ms");
    assert_eq!(
        prepared[0].field("valid_through"),
        Some(start.valid_through_height().to_string().as_str()),
    );
    assert!(
        !samples.of("fsync_tail_ms").is_empty(),
        "the journal's own append is sampled under it, as its own term",
    );

    // Called again the retained start is handed back, and nothing
    // reaches the disk — so there is no second sample of a fsync that
    // did not happen.
    let _ = tracing::subscriber::with_default(samples.clone(), || provider.prepare_close());
    assert_eq!(
        samples.of("close_prepared_fsync_ms").len(),
        1,
        "a start that is offered again is not retained again",
    );

    let heights: Vec<u64> = ((CURSOR + 1)..=(CURSOR + 3)).collect();
    let quiet = Chain {
        blocks: heights.iter().map(|h| block(*h, Vec::new())).collect(),
        withheld: None,
    };
    let sink = Mempool::default();
    let step = samples.clone();
    let progress = provider
        .advance_close(&quiet, &sink)
        .with_subscriber(step)
        .await;
    assert!(
        matches!(progress, Ok(CloseProgress::Submitted { .. })),
        "the step runs: {progress:?}",
    );

    let tips = samples.of("fresh_tip_ms");
    assert_eq!(tips.len(), 1, "one step asks the tip once");
    assert_eq!(
        tips[0].field("height"),
        Some((CURSOR + 3).to_string().as_str()),
    );

    let fetches = samples.of("one_block_fetch_ms");
    let fetched: Vec<Option<&str>> = fetches
        .iter()
        .map(|sample| sample.field("height"))
        .collect();
    let expected: Vec<String> = heights.iter().map(u64::to_string).collect();
    assert_eq!(
        fetched,
        expected
            .iter()
            .map(String::as_str)
            .map(Some)
            .collect::<Vec<_>>(),
        "three blocks fetched, three samples, each saying which block it was",
    );
}

/// A restart samples the replay it actually ran, with the frames and the
/// bytes it walked.
///
/// §4's `R` divides `restart_replay_ms_at_cap` by a block time, and "at
/// cap" is a property of the file the restart happened to find. The seam
/// cannot know whether the replay it ran was a full one, so it reports
/// what it walked and leaves that judgement to whoever is building the
/// distribution — which is why `frames`, `bytes` and `records` are in
/// the sample and no threshold is.
#[tokio::test]
async fn a_restart_samples_the_replay_it_ran() {
    let fixture = paid_job().await;
    let samples = std::sync::Arc::new(Samples::new());
    let watcher = tracing::subscriber::with_default(samples.clone(), || restarted(fixture));

    let replays = samples.of("restart_replay_ms_at_cap");
    assert_eq!(replays.len(), 1, "one journal reopened, one replay sampled");
    let replay = &replays[0];
    assert_eq!(replay.field("kind"), Some("Channel"));
    assert_eq!(replay.field("role"), Some("Provider"));
    assert_eq!(replay.field("generation"), Some("0"));

    let number = |name: &str| match replay.field(name).map(str::parse::<u64>) {
        Some(Ok(value)) => value,
        other => panic!("{name} is a number: {other:?}"),
    };
    let frames = number("frames");
    assert!(frames > 0, "a paid job leaves records to replay");
    assert_eq!(
        number("records"),
        frames,
        "generation zero holds no checkpoint, so every frame was replayed",
    );
    assert!(
        number("bytes") > frames,
        "the physical size of what was walked, not a frame count again",
    );
    drop(watcher);
}

/// Building an answer is sampled, and refusing to build one is not.
///
/// `response_build_ms` is `Wresp`'s signing term and nothing else: the
/// record that fixes the answer is counted separately, as one of the
/// three fsyncs. A contest this endpoint cannot answer is refused before
/// anything is built, and a term nothing spent time on contributes
/// nothing.
#[tokio::test]
async fn an_answer_that_is_built_is_sampled_and_one_that_is_refused_is_not() {
    let fixture = paid_job().await;
    let ready = fixture.ready.clone();
    let inclusion = CURSOR + 1;
    let bond = bond_object();
    let payment_edge_object = payment_object();

    let Ok(understated) = close_start(
        ready.channel(),
        hellas_kernel::Party::Maker,
        CURSOR,
        None,
        &client(),
    ) else {
        panic!("a client opens a close");
    };
    let id = contest_id(&ready, &understated, inclusion);

    let mut watcher = restarted(fixture);
    let provider = &mut watcher.provider;
    if let Err(error) = provider.observe_finalized(&block(
        inclusion,
        vec![hellas_kernel::Tx::move_action(
            hellas_kernel::Move::StartPaymentClose(understated),
        )],
    )) {
        panic!("the block applies: {error}");
    }

    let deadline = inclusion + payment_terms().omit_response_blocks;
    let open = Contest::opened(id, deadline, 0);
    let read_at = |height: u64, record: &Contest| ObservedChannel {
        height,
        bond: Some(&bond),
        payment: Some(&payment_edge_object),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: pending_slot(record),
    };

    let samples = std::sync::Arc::new(Samples::new());
    if let Err(error) = tracing::subscriber::with_default(samples.clone(), || {
        provider.respond_to_close(&read_at(deadline - 1, &open))
    }) {
        panic!("an understated contest is answered: {error}");
    }
    let built = samples.of("response_build_ms");
    assert_eq!(built.len(), 1, "one answer, one sample");
    assert_eq!(
        built[0].field("start_id"),
        Some(
            id.to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                .as_str()
        ),
        "the sample names the contest it answered",
    );

    // The one answer is already given, so the second call refuses before
    // it builds anything.
    let mut settled = Contest::opened(id, deadline, 0);
    settled.final_cumulative = PRICE;
    settled.responded = true;
    settled.penalty_due = true;
    let refused = tracing::subscriber::with_default(samples.clone(), || {
        provider.respond_to_close(&read_at(deadline - 1, &settled))
    });
    assert!(
        matches!(refused, Err(CloseError::AlreadyResponded)),
        "there is one answer: {refused:?}",
    );
    assert_eq!(
        samples.of("response_build_ms").len(),
        1,
        "an answer that was not built is not an answer that took any time",
    );
}
