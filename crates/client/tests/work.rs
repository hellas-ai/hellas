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

use hellas_channel::test_support::channel::serve_work as serve;
use hellas_channel::test_support::channel::{
    CURSOR, PRICE, PROMPT_TOKENS, bundle, client, commit, deadlines, descriptor_with, payload_at,
    payment_policy, provider, provider_producer, ready, ready_of, store_at, work_policy,
};

use hellas_auth::Digest;
use hellas_channel::model::prepared_input::PreparedPaidInputV1;
use hellas_channel::model::setup::ReadyChannel;
use hellas_channel::model::work::{
    EvaluatePolicyV2, PaidJobAuthorizationV2, propose_authorization, signing_hash, work_id,
};
use hellas_channel::work::{
    ClientEndpoint, ProviderEndpoint, RunOutcome, WorkService, run_accepted_work,
};
use hellas_channel::work_close::{BlockSourceError, FinalizedBlocks, FinalizedWork};
use hellas_channel::work_store::{
    ChannelRecord, ChannelStore, JobPhase, JobState, Role, TerminalOutcome,
};
use hellas_client::work::payment::pay_for_result;
use hellas_client::work::reproduce::{ReproduceFault, Reproduced, Reproducer};
use hellas_client::work::{
    CheckedResult, CollectError, CollectOutcome, CollectResultError, CollectResultOutcome,
    collect_checked_result, collect_result,
};
use hellas_rpc::evaluate::EvaluateStopReason;
use hellas_rpc::protocol::artifacts::{OutputAddressed as _, TextExecutionId, completed_text};
use hellas_rpc::{EvaluateRequest, OutputEventEnvelope};
use hellas_wire::mux::MuxTransport;

// ── Fixture ───────────────────────────────────────────────────────────

fn temp() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("a temporary directory: {error}"),
    }
}

// ── The prepared inputs a job executes from ───────────────────────────

/// The prompt every job here runs on. It is the whole input, because
/// this profile starts from an identity artifact.
const PROMPT: [u32; 4] = [9, 8, 7, 6];

fn authorization(policy: &EvaluatePolicyV2, nonce: u8) -> PaidJobAuthorizationV2 {
    match propose_authorization(
        ready_of(&descriptor_with(*policy), CURSOR).channel(),
        policy,
        &payment_policy(),
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
async fn accept(
    policy: &EvaluatePolicyV2,
    stores: &mut [&mut ChannelStore],
    nonce: u8,
) -> (Digest, PaidJobAuthorizationV2) {
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
        )
        .await;
        commit(
            store,
            ChannelRecord::JobAccepted {
                work_id: id,
                provider_signature: provider().sign(signing_hash(id)),
            },
        )
        .await;
    }
    (id, authorization)
}

// ── Transcripts and the backend that produces them ────────────────────

const ANSWER: [u32; 5] = [101, 102, 103, 104, 105];

fn transcript_for(request: &EvaluateRequest, answer: &[u32]) -> Vec<OutputEventEnvelope> {
    let text_artifact = completed_text(
        TextExecutionId::from_digest(request.text_execution),
        &PROMPT,
        answer,
    )
    .artifact
    .output_id()
    .digest();
    hellas_channel::test_support::channel::transcript_chunks(
        request,
        &[answer],
        &provider_producer(),
        PROMPT_TOKENS,
        text_artifact,
    )
}

async fn run_to_result(service: &WorkService, ready: &ReadyChannel, id: Digest) {
    let backend =
        hellas_channel::test_support::channel::AnsweringBackend::with_transcript(transcript_for);
    let outcome = run_accepted_work(service, ready, &backend, id).await;
    assert!(
        matches!(outcome, Ok(RunOutcome::Completed { .. })),
        "the fixture job completes: {outcome:?}"
    );
}

// ── Transport plumbing ────────────────────────────────────────────────

fn session() -> hellas_wire::TransportContext {
    hellas_wire::TransportContext {
        open_exporter: Some([0x5e; 32]),
        ..hellas_wire::TransportContext::default()
    }
}

fn transport_pair() -> (MuxTransport, MuxTransport) {
    hellas_channel::test_support::transport::transport_pair_without_write_authority(
        session(),
        session(),
    )
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
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(
        &work_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    )
    .await;
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
                .await
                .expect("the endpoint is reachable"),
            Some(JobPhase::Delivered),
            "the provider delivered the plaintext once",
        );
    }

    // And it is on the disk: reopened from the files by a process that
    // saw none of this, the job is still checked.
    drop(endpoint);
    drop(service);
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
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
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(
        &work_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    )
    .await;
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
            .await
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
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
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
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(
        &work_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    )
    .await;
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
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, authorization) = accept(
        &work_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    )
    .await;
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
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(
        &work_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    )
    .await;
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
    let signed = endpoint.pay(id).await;
    assert!(signed.is_ok(), "the client signs its payment: {signed:?}");
    drop(endpoint);
    {
        assert_eq!(
            service
                .with_state(|state| state.ledger().credited_cumulative())
                .await
                .expect("the endpoint is reachable"),
            0,
            "and the provider has seen nothing",
        );
    }

    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
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
            .await
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
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(
        &work_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    )
    .await;
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
                .await
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
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(
        &work_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    )
    .await;
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
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
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
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(
        &work_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    )
    .await;
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
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, authorization) = accept(
        &work_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    )
    .await;
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
