//! Paying for one checked job: the amount each endpoint derives for
//! itself, what is on the disk before either of them speaks, and what a
//! certificate the ledger cannot explain does.
//!
//! One call, over a real multiplexed transport, so the request is
//! framed, routed by method id, decoded and answered rather than handed
//! to a function. Every crash is a real one: the endpoints are dropped
//! and their stores reopened over their own files.
//!
//! What is not re-proved here. The transition rules themselves belong to
//! the journal and are pinned in `work_store_channel.rs` — that a
//! payment past its deadline is refused, that a paid job is not paid for
//! again after a restart. The record arithmetic belongs to
//! `paid_work_vectors.rs`. These tests are about the two endpoints and
//! the wire between them.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hellas_kernel::{
    BlockHeight, Decode as _, EarnedCertificate, Edge, EdgeId, EdgeValues, Encode as _, Fees, Key,
    LeaseSlots, List, MAX_EDGE_OUTPUTS, Parties, Payout, PendingSlot, Secp256k1Signer,
    Secp256k1Verifier, Terms, TermsHash, WorkPaymentSettlement, WorkPaymentTerms,
    WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::pb::work::{
    AdmitCertificateRequest, AdmitCertificateResponse, WorkPaid, WorkRefusalCode,
    admit_certificate_response::Outcome as AdmitOutcome,
};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PaymentBindingV1, PrivateRecord as _, generation_policy_digest, identity_source_digest,
    payment_binding_digest, private_policy_commitment, propose_authorization, signing_hash,
    work_id,
};
use hellas_rpc::protocol::work_setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
use hellas_rpc::{
    Application, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, ContentId, EvaluateRequest,
    OutputEventEnvelope, ProducerSigningKey, ProgramManifest, PublicKey,
};
use hellas_wire::mux::MuxTransport;
use hellas_wire::{Dispatcher, StreamTransport};
use hellas_work::work::{
    BackendFault, ClientEndpoint, PaidWorkBackend, PaymentError, PreparedEvaluateInput,
    ProviderEndpoint, RunError, RunOutcome, WorkRefusal, WorkService, admit_payment, fetch_result,
    run_accepted_work,
};
use hellas_work::work_close::FinalizedWork;
use hellas_work::work_store::{ChannelRecord, ChannelStore, JobPhase, JobState, Role, SetupOrigin};

mod support;
use support::{advance, bond_edge, client, network, payload_at, payment_edge, provider, temp};

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
/// Everything before the payment, driven exactly as the earlier phases
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
    // The re-execution is `hellas-client`'s; what this file needs is the
    // durable match it records, which is the only phase an honest
    // client's journal signs a certificate from.
    if let Err(error) = client.matched(id) {
        panic!("the fixture match records: {error}");
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

// ── Driving the call ──────────────────────────────────────────────────

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

/// The provider's answer to one payment, whatever it is.
async fn admit_response(
    service: &WorkService,
    request: AdmitCertificateRequest,
) -> AdmitCertificateResponse {
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let response = WorkClientImpl::new(transport)
        .admit_certificate(request)
        .await;
    stop(serving).await;
    match response {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    }
}

fn refusal_of(response: &AdmitCertificateResponse) -> WorkRefusalCode {
    match &response.outcome {
        Some(AdmitOutcome::Refused(refused)) => match WorkRefusalCode::try_from(refused.code) {
            Ok(code) => code,
            Err(error) => panic!("the refusal code is one of the six: {error}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn signature_over(signer: &Secp256k1Signer, hash: hellas_kernel::PayloadHash) -> Vec<u8> {
    signer.sign(hash).as_bytes().to_vec()
}

fn certificate_bytes(certificate: &EarnedCertificate) -> Vec<u8> {
    let mut buf = vec![0_u8; certificate.encoded_size()];
    let written = certificate.write_to(&mut buf);
    buf.truncate(written);
    buf
}

// ── One job, paid for ─────────────────────────────────────────────────

/// One checked answer becomes one certificate, and both endpoints end
/// at the same number.
///
/// The record counts at the end are what say nothing was written twice:
/// the call was made a second time, and the journals a process that saw
/// none of it reopens are the same length as before.
#[tokio::test]
async fn one_certificate_pays_for_one_job() {
    let mut fixture = checked_job().await;
    let id = fixture.id;

    let credited = match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => credited,
        Err(error) => panic!("the checked job is paid: {error}"),
    };
    assert_eq!(credited, PRICE);

    let state = fixture.client.state();
    assert!(state.jobs().next().is_none(), "the payment closes the job");
    assert_eq!(state.ledger().credited_cumulative(), PRICE);
    let Some(payment) = state.last_payment() else {
        panic!("the payment is retained for re-sending");
    };
    assert_eq!(payment.work_id, id);
    assert_eq!(payment.certificate.earned_cumulative(), PRICE);
    assert_eq!(
        payment.binding.work_id, id,
        "the binding names the job it paid for",
    );
    assert_eq!(
        payment.binding.certificate_digest,
        payment
            .certificate
            .digest(fixture.ready.channel().network()),
        "and the certificate it paid with",
    );

    {
        let state = fixture
            .service
            .with_state(|state| state.clone())
            .expect("the endpoint is reachable");
        assert!(state.jobs().next().is_none());
        assert_eq!(state.ledger().credited_cumulative(), PRICE);
        assert_eq!(state.max_executable_certificate(), PRICE);
        assert!(
            state.terminals().next().is_some(),
            "the admitted certificate is this channel's one terminal",
        );
    }

    // The acknowledgement lost to a crash: the same bytes again, and
    // the same answer.
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(again) => assert_eq!(again, PRICE),
        Err(error) => panic!("a re-sent payment is acknowledged: {error}"),
    }

    // The retained payment answers for the job it paid for and no
    // other: a channel with a payment on its disk has not thereby paid
    // for everything.
    let elsewhere = fixture.client.pay(Digest::from_bytes([0xaa; 32]));
    assert!(
        matches!(elsewhere, Err(PaymentError::NoSuchJob)),
        "another job's payment is not this one's: {elsewhere:?}",
    );

    drop(fixture.client);
    drop(fixture.service);
    let client_store = store_at(
        fixture.client_root.path(),
        &fixture.ready,
        Role::Client,
        CURSOR,
    );
    let provider_store = store_at(
        fixture.provider_root.path(),
        &fixture.ready,
        Role::Provider,
        CURSOR,
    );
    // One cursor record per block read from the channel's origin to
    // `CURSOR`, and then the job's own steps.
    // Client: proposal, acceptance, result, verdict, payment.
    // Provider: proposal, acceptance, running marker, result, release,
    // payment.
    for (store, role, records) in [
        (&client_store, "client", CURSOR + 5),
        (&provider_store, "provider", CURSOR + 6),
    ] {
        assert_eq!(
            store.len(),
            records,
            "the {role} journal wrote each step once",
        );
        let state = store.state();
        assert!(state.jobs().next().is_none(), "the {role} job is closed");
        assert_eq!(state.ledger().credited_cumulative(), PRICE);
        assert_eq!(state.max_executable_certificate(), PRICE);
    }
    assert_eq!(
        client_store.state().last_payment().map(|p| p.work_id),
        Some(id)
    );
}

// ── What the provider will be paid ────────────────────────────────────

/// A provider credits the payment its own ledger arrives at, and no
/// other.
///
/// Each request below moves exactly one field of the honest payment and
/// is re-signed by the client, so what refuses it is the arithmetic and
/// not the signature — and the last two move no field and change only
/// the signer, so both signature rules are shown to be there too.
///
/// Nothing is banked on any of them. A certificate whose binding this
/// ledger cannot explain is not money that was earned and mis-labelled;
/// both halves of an honest payment come out of one derivation.
#[tokio::test]
async fn the_provider_prices_the_payment_itself() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    let channel = fixture.ready.channel().clone();
    let honest = match fixture.client.pay(id) {
        Ok(request) => request,
        Err(error) => panic!("the client signs its payment: {error}"),
    };
    let Ok(binding) = PaymentBindingV1::decode(&honest.binding) else {
        panic!("the client's own binding decodes");
    };
    let Ok(certificate) = EarnedCertificate::decode(&honest.certificate) else {
        panic!("the client's own certificate decodes");
    };
    let certificate = certificate.0;

    let elsewhere = Digest::from_bytes([0x5e; 32]);
    let bindings = [
        (
            "work_id",
            PaymentBindingV1 {
                work_id: elsewhere,
                ..binding
            },
        ),
        (
            "result_digest",
            PaymentBindingV1 {
                result_digest: elsewhere,
                ..binding
            },
        ),
        (
            "certificate_digest",
            PaymentBindingV1 {
                certificate_digest: hellas_kernel::PayloadHash::from_bytes([0x5e; 32]),
                ..binding
            },
        ),
    ];
    for (field, mutated) in bindings {
        assert_ne!(mutated, binding, "{field} is the one thing varied");
        let request = AdmitCertificateRequest {
            binding: mutated.encode(),
            binding_signature: signature_over(
                &client(),
                signing_hash(payment_binding_digest(&channel, &mutated)),
            ),
            ..honest.clone()
        };
        let response = admit_response(&fixture.service, request).await;
        assert_eq!(
            refusal_of(&response),
            WorkRefusalCode::Invalid,
            "a binding whose {field} this provider did not arrive at",
        );
        assert_nothing_credited(&fixture.service, field).await;
    }

    // The certificate's own three fields, each re-signed so the refusal
    // is the ledger's rather than a signature's.
    let other_edge = EdgeId::from_bytes([0x77; EdgeId::LENGTH]);
    let other_terms = TermsHash::from_bytes([0x88; 32]);
    let certificates = [
        (
            "earned_cumulative",
            EarnedCertificate::new(
                channel.payment_edge(),
                channel.payment_terms_hash(),
                PRICE + 1,
            ),
        ),
        (
            "payment_edge",
            EarnedCertificate::new(other_edge, channel.payment_terms_hash(), PRICE),
        ),
        (
            "payment_terms_hash",
            EarnedCertificate::new(channel.payment_edge(), other_terms, PRICE),
        ),
    ];
    for (field, mutated) in certificates {
        assert_ne!(mutated, certificate, "{field} is the one thing varied");
        // The binding is left alone, so the check in front of the
        // certificate passes and the certificate's own field is what
        // refuses each case.
        let request = AdmitCertificateRequest {
            certificate: certificate_bytes(&mutated),
            certificate_signature: signature_over(&client(), mutated.digest(channel.network())),
            ..honest.clone()
        };
        let response = admit_response(&fixture.service, request).await;
        assert_eq!(
            refusal_of(&response),
            WorkRefusalCode::Invalid,
            "a certificate whose {field} this provider did not arrive at",
        );
        assert_nothing_credited(&fixture.service, field).await;
    }

    // The honest bytes, signed by the wrong party — once for each
    // signature the record carries.
    for (slot, request) in [
        (
            "binding",
            AdmitCertificateRequest {
                binding_signature: signature_over(
                    &provider(),
                    signing_hash(payment_binding_digest(&channel, &binding)),
                ),
                ..honest.clone()
            },
        ),
        (
            "certificate",
            AdmitCertificateRequest {
                certificate_signature: signature_over(
                    &provider(),
                    certificate.digest(channel.network()),
                ),
                ..honest.clone()
            },
        ),
    ] {
        let response = admit_response(&fixture.service, request).await;
        assert_eq!(
            refusal_of(&response),
            WorkRefusalCode::Invalid,
            "a {slot} the client did not sign",
        );
        assert_nothing_credited(&fixture.service, slot).await;
    }

    // The control: the client's own bytes, credited.
    let response = admit_response(&fixture.service, honest).await;
    assert!(
        matches!(response.outcome, Some(AdmitOutcome::Paid(_))),
        "the client's own payment is credited: {response:?}",
    );
}

/// Asserts that a refused payment moved no money at all.
async fn assert_nothing_credited(service: &WorkService, what: &str) {
    let state = service
        .with_state(|state| state.clone())
        .expect("the endpoint is reachable");
    assert_eq!(
        state.ledger().credited_cumulative(),
        0,
        "{what} credits nothing",
    );
    assert_eq!(
        state.max_executable_certificate(),
        0,
        "{what} is not banked either",
    );
    assert_eq!(
        state.jobs().next().map(JobState::phase),
        Some(JobPhase::Delivered),
        "{what} leaves the job unpaid",
    );
}

/// An acknowledgement is only this payment's if it names this
/// payment's amount.
///
/// The number is the one thing varied: the same durable certificate,
/// and three answers about what it bought.
#[tokio::test]
async fn an_acknowledgement_must_name_the_amount_that_was_signed() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => assert_eq!(credited, PRICE),
        Err(error) => panic!("the checked job is paid: {error}"),
    }

    for credited_cumulative in [PRICE - 1, PRICE, PRICE + 1] {
        let response = AdmitCertificateResponse {
            outcome: Some(AdmitOutcome::Paid(WorkPaid {
                credited_cumulative,
            })),
        };
        let read = fixture.client.acknowledged(id, &response);
        if credited_cumulative == PRICE {
            assert_eq!(read.ok(), Some(PRICE), "the amount that was signed");
            continue;
        }
        let Err(PaymentError::Acknowledged { signed, credited }) = read else {
            panic!("an acknowledgement of {credited_cumulative}: {read:?}");
        };
        assert_eq!(signed, PRICE);
        assert_eq!(credited, credited_cumulative);
    }
}

/// A job with no result yet has nothing to pay for: the client signs
/// nothing, and the provider credits nothing.
///
/// The control is `one_certificate_pays_for_one_job`: the same call, on
/// the same channel, once a result has been computed and delivered.
#[tokio::test]
async fn an_uncomputed_job_is_not_paid_for() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR);
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR);
    let id = accept(&mut [&mut client_store, &mut provider_store]);
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);

    let paid = endpoint.pay(id);
    let Err(PaymentError::NotPayable { phase }) = paid else {
        panic!("an accepted job with no result: {paid:?}");
    };
    assert_eq!(phase, JobPhase::Accepted);
    assert!(
        endpoint.state().last_payment().is_none(),
        "and nothing was signed",
    );

    // And a well-formed, correctly signed payment for that same job is
    // refused by the provider, whose journal has no result to price
    // either.
    let channel = ready.channel();
    let certificate =
        EarnedCertificate::new(channel.payment_edge(), channel.payment_terms_hash(), PRICE);
    let binding = PaymentBindingV1 {
        work_id: id,
        result_digest: Digest::from_bytes([0x22; 32]),
        certificate_digest: certificate.digest(channel.network()),
    };
    let response = admit_response(
        &service,
        AdmitCertificateRequest {
            certificate: certificate_bytes(&certificate),
            binding: binding.encode(),
            binding_signature: signature_over(
                &client(),
                signing_hash(payment_binding_digest(channel, &binding)),
            ),
            certificate_signature: signature_over(&client(), certificate.digest(channel.network())),
        },
    )
    .await;
    assert_eq!(refusal_of(&response), WorkRefusalCode::Declined);
    let state = service
        .with_state(|state| state.clone())
        .expect("the endpoint is reachable");
    assert_eq!(state.ledger().credited_cumulative(), 0);
    assert_eq!(state.max_executable_certificate(), 0);
    assert_eq!(
        state.jobs().next().map(JobState::phase),
        Some(JobPhase::Accepted),
        "and nothing moved",
    );
}

/// A payment is exactly the bytes the service defines, and no other
/// spelling of them.
///
/// Each request below is the honest one with one field mis-encoded, and
/// none of the three reaches a rule about money: nothing is credited,
/// and nothing is banked either.
#[tokio::test]
async fn a_payment_is_exactly_the_bytes_the_service_defines() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    let honest = match fixture.client.pay(id) {
        Ok(request) => request,
        Err(error) => panic!("the client signs its payment: {error}"),
    };

    let mut trailing = honest.certificate.clone();
    trailing.push(0);
    let mut truncated = honest.binding.clone();
    truncated.pop();
    let mut short = honest.binding_signature.clone();
    short.pop();
    let mutations = [
        (
            "a trailing byte on the certificate",
            AdmitCertificateRequest {
                certificate: trailing,
                ..honest.clone()
            },
        ),
        (
            "a truncated binding",
            AdmitCertificateRequest {
                binding: truncated,
                ..honest.clone()
            },
        ),
        (
            "a 63-byte binding signature",
            AdmitCertificateRequest {
                binding_signature: short,
                ..honest.clone()
            },
        ),
    ];
    for (what, request) in mutations {
        let response = admit_response(&fixture.service, request).await;
        assert_eq!(refusal_of(&response), WorkRefusalCode::Invalid, "{what}");
        assert_nothing_credited(&fixture.service, what).await;
    }

    // The control: the same request, whole.
    let response = admit_response(&fixture.service, honest).await;
    assert!(
        matches!(response.outcome, Some(AdmitOutcome::Paid(_))),
        "the whole request is paid: {response:?}",
    );
}

// ── Payment against default ───────────────────────────────────────────

/// A defaulted job and a paid job are the same job, and exactly one of
/// the two terminals is written.
///
/// Both orders, over the one file that decides them. Expiring first: the
/// provider's watcher reaches finalized blocks past the height this
/// client signed to pay by, and the job rests at a permanent expired
/// terminal — the provider bears whatever it spent, there being no
/// client charge to move. A payment then is refused *and not banked*,
/// because the one job is already over. Paying first: the payment rests
/// the job at a certified terminal, and there is nothing left to expire.
#[tokio::test]
async fn a_defaulted_job_is_not_paid_for_as_well() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    {
        let provider = &fixture.service;
        // The default is the watcher's, reached the only way it can
        // be: finalized blocks past the height this client signed to
        // pay by. No local call can ask for it.
        let Ok(mut driver) = provider.drive() else {
            panic!("this channel's cursor driver is free");
        };
        let mut next = provider
            .with_state(|state| state.cursor().0)
            .expect("the endpoint is reachable")
            .saturating_add(1);
        while next <= deadlines().payment + 1 {
            if let Err(error) = driver.observe_finalized(&FinalizedWork {
                height: next,
                parent: payload_at(next.saturating_sub(1)),
                payload: payload_at(next),
                txs: Vec::new(),
            }) {
                panic!("the fixture block applies: {error}");
            }
            next += 1;
        }
        drop(driver);
        let (open_job, expired) = provider
            .with_state(|state| {
                (
                    state.jobs().next().is_some(),
                    matches!(
                        state.terminals().next().map(|t| &t.outcome),
                        Some(hellas_work::work_store::TerminalOutcome::Expired { .. })
                    ),
                )
            })
            .expect("the endpoint is reachable");
        assert!(!open_job, "the expired job is closed");
        assert!(expired, "and rests at an expired terminal");
    }

    let paid = pay_over_wire(&fixture.service, &mut fixture.client, id).await;
    let Err(PaymentError::Refused { refusal, .. }) = paid else {
        panic!("a defaulted job takes no payment: {paid:?}");
    };
    assert_eq!(refusal, WorkRefusal::Conflict);
    {
        let state = fixture
            .service
            .with_state(|state| state.clone())
            .expect("the endpoint is reachable");
        assert_eq!(state.ledger().credited_cumulative(), 0);
        assert_eq!(
            state.max_executable_certificate(),
            0,
            "a job already expired is not banked as well",
        );
    }
    assert_eq!(
        fixture.client.state().ledger().credited_cumulative(),
        PRICE,
        "the client holds a payment no provider will take",
    );

    // The other order.
    let mut fixture = checked_job().await;
    let id = fixture.id;
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => assert_eq!(credited, PRICE),
        Err(error) => panic!("the checked job is paid: {error}"),
    }
    let provider = &fixture.service;
    let ended = provider.end_run(id);
    assert!(
        matches!(ended, Err(RunError::NoSuchJob)),
        "a paid job is closed: {ended:?}",
    );
    assert_eq!(
        provider
            .with_state(|state| state.ledger().credited_cumulative())
            .expect("the endpoint is reachable"),
        PRICE,
    );
}
