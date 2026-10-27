//! The bilateral acceptance exchange: what each side has on its disk
//! before it releases a signature, and what it answers when it will not.
//!
//! Every crash here is a real one — the store is dropped and reopened
//! over its own files — and the happy path runs over a real multiplexed
//! transport, so the request is framed, routed by method id, decoded,
//! and answered rather than handed to a function.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use support::temp;

use hellas_auth::Digest;
use hellas_auth::PublicKey;
use hellas_channel::model::prepared_input::PreparedPaidInputV1;
use hellas_channel::model::setup::{ReadyChannel, WorkChannelDescriptor, payment_terms_hash};
use hellas_channel::model::work::{
    JobDeadlines, PaidChannel, PaidJobAuthorizationV2, PrivateRecord as _, prepared_input_digest,
    propose_authorization, signing_hash, work_id, work_policy_digest,
};
use hellas_channel::test_support::channel::{
    CURSOR, OMISSION_BOND, PAYMENT_RESERVE, PAYMENT_VALUE, PRICE, SALT, advance, bond_edge, bundle,
    bundle_bytes, channel_policy, client, deadlines, descriptor,
    descriptor_with as descriptor_with_policy, evaluate_request, identity_artifact, manifest,
    network, origin, payload_at, payment_edge, payment_policy, payment_terms, prompt_tokens,
    provider, settlement, signer, text_execution, text_policy, work_policy,
};
use hellas_channel::test_support::channel::{accept_uploaded, accept_uploaded_service};
use hellas_channel::work::{
    ClientEndpoint, CloseEndpoint, EndpointError, JobProposal, ProposeError, ProviderEndpoint,
    WorkRefusal, WorkService, propose_work,
};
use hellas_channel::work_close::{BlockSourceError, CatchUpError, FinalizedBlocks, FinalizedWork};
use hellas_channel::work_store::{
    Channel, ChannelRecord, ChannelStore, JobPhase, JobState, Role, SetupOrigin, TerminalOutcome,
};
use hellas_kernel::{
    EdgeId, EdgeValues, Fees, PayloadHash, Secp256k1Signer, Secp256k1Verifier, Sig,
    SigVerifier as _, WorkPaymentSettlement, work_payment_settlement,
};
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, WorkAccepted, WorkRefusalCode, WorkRefused,
    accept_work_response::Outcome,
};
use hellas_rpc::protocol::artifacts::{
    InputAddressed as _, OutputAddressed as _, SourceRef, TextExecution, TextPolicy,
};
use hellas_rpc::services::work::{Work, WorkServer};
use hellas_rpc::{ContentId, Evaluate};
use hellas_wire::mux::MuxTransport;
use hellas_wire::{Dispatcher, ServiceMarker, StreamTransport};

mod support;

// ── Fixture ───────────────────────────────────────────────────────────

/// A third party with no role on this channel.
fn stranger() -> Secp256k1Signer {
    signer(0x23)
}

fn ready() -> ReadyChannel {
    ready_with_descriptor(descriptor())
}

fn ready_with_descriptor(descriptor: WorkChannelDescriptor) -> ReadyChannel {
    hellas_channel::test_support::channel::ready_of(&descriptor, CURSOR)
}

async fn store(root: &std::path::Path, role: Role) -> ChannelStore {
    store_with(root, role, settlement()).await
}

async fn store_with(
    root: &std::path::Path,
    role: Role,
    settlement: WorkPaymentSettlement,
) -> ChannelStore {
    match ChannelStore::open(
        root,
        ready().channel().clone(),
        settlement,
        role,
        origin(),
        &Secp256k1Verifier::new(),
    )
    .await
    {
        Ok(store) => store,
        Err(error) => panic!("the fixture store opens: {error}"),
    }
}

/// A store that has processed one finalized block, which is what lets
/// either endpoint measure a deadline.
async fn store_at_cursor(root: &std::path::Path, role: Role) -> ChannelStore {
    at_height(store(root, role).await, CURSOR).await
}

async fn at_height(mut store: ChannelStore, height: u64) -> ChannelStore {
    advance(&mut store, height).await;
    store
}

async fn client_endpoint(root: &std::path::Path) -> ClientEndpoint {
    match ClientEndpoint::new(ready(), store_at_cursor(root, Role::Client).await, client()) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the fixture client endpoint binds: {error}"),
    }
}

async fn provider_endpoint(root: &std::path::Path) -> ProviderEndpoint {
    match ProviderEndpoint::new(
        ready(),
        store_at_cursor(root, Role::Provider).await,
        provider(),
    ) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the fixture provider endpoint binds: {error}"),
    }
}

// ── The prepared inputs a job executes from ───────────────────────────

fn proposal(nonce: u8) -> JobProposal {
    JobProposal {
        prepared_input: bundle(nonce).into(),
        deadlines: deadlines(),
    }
}

/// The authorization the client would build for one proposal at one
/// nonce, computed here rather than taken from the endpoint.
fn authorization(nonce: u8, proposal_nonce: u64) -> PaidJobAuthorizationV2 {
    match propose_authorization(
        ready().channel(),
        &work_policy(),
        &payment_policy(),
        &bundle(nonce),
        proposal_nonce,
        deadlines(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    }
}

/// A request built by hand rather than by the client endpoint, so a
/// provider test can vary exactly one field of it.
fn request(authorization: &PaidJobAuthorizationV2, signature: Sig, nonce: u8) -> AcceptWorkRequest {
    AcceptWorkRequest {
        route: Some(hellas_rpc::pb::work::WorkRoute::payment(
            authorization.channel_id,
        )),
        authorization: authorization.encode(),
        client_signature: signature.as_bytes().to_vec(),
        prepared_input: hellas_rpc::protocol::content_upload::encode_reference(
            hellas_rpc::ContentRef::new(
                ContentId::hash(&bundle_bytes(nonce)),
                bundle_bytes(nonce).len() as u64,
            ),
        ),
    }
}

fn signed_request(nonce: u8, proposal_nonce: u64) -> AcceptWorkRequest {
    signed_request_with(nonce, proposal_nonce, deadlines())
}

fn signed_request_with(
    nonce: u8,
    proposal_nonce: u64,
    deadlines: JobDeadlines,
) -> AcceptWorkRequest {
    let authorization = match propose_authorization(
        ready().channel(),
        &work_policy(),
        &payment_policy(),
        &bundle(nonce),
        proposal_nonce,
        deadlines,
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    };
    let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    request(&authorization, signature, nonce)
}

// ── Canonical chain objects, spelled out ──────────────────────────────

// ── Reading answers ───────────────────────────────────────────────────

fn accepted_signature(response: &AcceptWorkResponse) -> Sig {
    match response.outcome.as_ref() {
        Some(Outcome::Accepted(accepted)) => {
            let Ok(bytes) = <[u8; Sig::LENGTH]>::try_from(&accepted.provider_signature[..]) else {
                panic!("an accepted signature is 64 bytes");
            };
            Sig::from_bytes(bytes)
        }
        other => panic!("expected an acceptance, got {other:?}"),
    }
}

fn refusal_code(response: &AcceptWorkResponse) -> WorkRefusalCode {
    match response.outcome.as_ref() {
        Some(Outcome::Refused(refused)) => match WorkRefusalCode::try_from(refused.code) {
            Ok(code) => code,
            Err(_) => panic!("a refusal names a defined code, got {}", refused.code),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn refusal_text(response: &AcceptWorkResponse) -> String {
    match response.outcome.as_ref() {
        Some(Outcome::Refused(refused)) => refused.reason.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ── An in-memory pipe pair, so the wire is a real wire ────────────────

use hellas_channel::test_support::transport;
use transport::transport_pair;

/// Serves one provider endpoint over one transport until the caller
/// drops the returned handle.
fn serve(transport: MuxTransport, service: WorkService) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = WorkServer(service);
        while let Ok(Some(inbound)) = transport.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&server, inbound).await;
        }
    })
}

// ── The exchange, over a real transport ───────────────────────────────

#[tokio::test]
async fn an_accepted_exchange_leaves_both_signatures_on_both_disks() {
    let client_root = temp();
    let provider_root = temp();
    let service = WorkService::new(provider_endpoint(provider_root.path()).await);
    let (client_transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());

    let mut endpoint = client_endpoint(client_root.path()).await;
    let accepted = propose_work(client_transport, &mut endpoint, &proposal(1)).await;
    let Ok(work_id) = accepted else {
        panic!("the fixture exchange completes: {accepted:?}");
    };

    // Both endpoints let go of their journals before anything reopens
    // them: the exclusive lock is the store's, and a live server still
    // holds one.
    drop(endpoint);
    serving.abort();
    let _ = serving.await;
    drop(service);

    // Reopened from the files, not read from the objects that wrote
    // them: what is on the disk is the only thing a restart has.
    let client_store = store(client_root.path(), Role::Client).await;
    let provider_store = store(provider_root.path(), Role::Provider).await;
    for (side, state) in [
        ("client", client_store.state()),
        ("provider", provider_store.state()),
    ] {
        let Some(job) = state.jobs().next() else {
            panic!("the {side} journal holds the accepted job");
        };
        assert_eq!(job.work_id(), work_id, "{side} names the same job");
        assert_eq!(job.phase(), JobPhase::Accepted, "{side} is accepted");
        assert!(
            job.provider_signature().is_some(),
            "{side} holds the co-signature",
        );
    }
}

#[tokio::test]
async fn the_service_answers_a_refusal_over_the_same_wire() {
    let provider_root = temp();
    // A provider that has processed no block cannot measure a deadline.
    let endpoint = match ProviderEndpoint::new(
        ready(),
        store(provider_root.path(), Role::Provider).await,
        provider(),
    ) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the endpoint binds: {error}"),
    };
    let service = WorkService::new(endpoint);
    let (client_transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service);

    let client = hellas_rpc::services::work::WorkClientImpl::new(client_transport);
    let response = match client.accept_work(signed_request(1, 1)).await {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    serving.abort();
    assert_eq!(refusal_code(&response), WorkRefusalCode::NotReady);
}

/// One channel has one cursor driver, and naming a different job does
/// not buy a second one.
///
/// The authority is the channel's, not a digest's. A guard keyed on
/// what a caller says would hand the second call its own drive of the
/// same cursor, and the two would fetch every block twice and each treat
/// the other's apply as a redundant re-read of its own.
#[tokio::test]
async fn one_channel_has_one_cursor_driver_whatever_a_second_caller_names() {
    let root = temp();
    let service = WorkService::new(provider_endpoint(root.path()).await);
    let held = service.drive().expect("the first driver enters");
    assert!(
        matches!(service.drive(), Err(EndpointError::CatchingUp)),
        "a second driver of this channel is refused",
    );
    assert!(
        service.with_state(|state| state.cursor().0).await.is_ok(),
        "and the one driver does not strand brief journal work",
    );
    drop(held);
    assert!(
        service.drive().is_ok(),
        "the authority comes back when the driver goes",
    );
}

/// A block source that stops inside `block_at` until it is released.
///
/// The wait is the whole fixture. Every claim below is about what a
/// second caller can do while a driver is in there, and a driver that
/// held this channel's journal across the wait would be holding the
/// request path's own lock.
struct HeldChain {
    blocks: Vec<FinalizedWork>,
    fetches: Arc<AtomicUsize>,
    released: Arc<AtomicBool>,
}

impl HeldChain {
    fn over(heights: std::ops::RangeInclusive<u64>, released: &Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            blocks: heights
                .map(|height| FinalizedWork {
                    height,
                    parent: payload_at(height - 1),
                    payload: payload_at(height),
                    txs: Vec::new(),
                })
                .collect(),
            fetches: Arc::new(AtomicUsize::new(0)),
            released: Arc::clone(released),
        })
    }
}

impl FinalizedBlocks for HeldChain {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(self.blocks.last().map(|block| block.height))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        while !self.released.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        Ok(self
            .blocks
            .iter()
            .find(|block| block.height == height)
            .cloned())
    }
}

/// Waits until `count` reaches `wanted`, or gives up rather than hang.
async fn reaches(count: &AtomicUsize, wanted: usize) {
    let waited = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while count.load(Ordering::SeqCst) < wanted {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(waited.is_ok(), "the driver reached the chain wait");
}

/// One job's cursor has one driver, whatever else is running.
///
/// Both drivers here are service calls, because after this slice there
/// is no other kind: the endpoint is not handed out, so a second driver
/// cannot be built out of a raw borrow. The refused one reads no block
/// at all, which is what stops two drivers copying one duty out of the
/// same block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_job_has_one_cursor_driver_while_a_drive_is_in_flight() {
    let root = temp();
    let service = WorkService::new(provider_endpoint(root.path()).await);
    let id = Digest::from_bytes([0x55; 32]);
    let released = Arc::new(AtomicBool::new(false));
    let chain = HeldChain::over((CURSOR + 1)..=(CURSOR + 3), &released);
    let fetches = Arc::clone(&chain.fetches);

    let driving = tokio::spawn({
        let service = service.clone();
        let chain = Arc::clone(&chain);
        async move { service.catch_up_job(chain.as_ref(), id).await }
    });
    reaches(&fetches, 1).await;

    // The second driver of the same job, while the first is stopped at
    // the chain. Bounded, because the failure this is about is a second
    // driver that joins the drive instead of being turned away, and that
    // one would never return.
    let second = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        service.catch_up_job(chain.as_ref(), id),
    )
    .await;
    let Ok(second) = second else {
        panic!("a second driver of one job is turned away, not admitted to the drive");
    };
    assert!(
        matches!(second, Err(CatchUpError::Busy)),
        "a second driver of one job is turned away: {second:?}",
    );
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        1,
        "and it read no block of its own",
    );

    released.store(true, Ordering::SeqCst);
    let Ok(Ok(height)) = driving.await else {
        panic!("the one driver finishes its range");
    };
    assert_eq!(height, CURSOR + 3);
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        3,
        "each block in the range was fetched exactly once",
    );
    assert_eq!(
        service
            .with_state(|state| state.cursor().0)
            .await
            .expect("the endpoint is reachable"),
        CURSOR + 3,
    );
}

/// A second driver naming a *different* job is refused too, and reads
/// nothing.
///
/// This is the forged key. A guard keyed on what the caller says is not
/// a guard: the second call names a digest of its own, gets a slot of
/// its own, and drives the one cursor its counterpart is driving —
/// fetching every block a second time and treating the first driver's
/// applies as its own redundant re-reads. The authority is the
/// channel's, so the name it is asked for buys nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_driver_naming_another_job_is_refused_and_reads_nothing() {
    let root = temp();
    let service = WorkService::new(provider_endpoint(root.path()).await);
    let released = Arc::new(AtomicBool::new(false));
    let chain = HeldChain::over((CURSOR + 1)..=(CURSOR + 3), &released);
    let fetches = Arc::clone(&chain.fetches);

    let driving = tokio::spawn({
        let service = service.clone();
        let chain = Arc::clone(&chain);
        async move {
            service
                .catch_up_job(chain.as_ref(), Digest::from_bytes([0x55; 32]))
                .await
        }
    });
    reaches(&fetches, 1).await;

    let second = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        service.catch_up_job(chain.as_ref(), Digest::from_bytes([0x56; 32])),
    )
    .await;
    let Ok(second) = second else {
        panic!("a driver naming another job is turned away, not admitted to the drive");
    };
    assert!(
        matches!(second, Err(CatchUpError::Busy)),
        "a different name does not buy a second drive of one channel: {second:?}",
    );
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        1,
        "and it read no block of its own",
    );

    released.store(true, Ordering::SeqCst);
    let Ok(Ok(height)) = driving.await else {
        panic!("the one driver finishes its range");
    };
    assert_eq!(height, CURSOR + 3);
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        3,
        "each block in the range was fetched exactly once, not twice",
    );
}

/// A job id is checked against the journal, not taken on trust.
///
/// Nothing else is driving here, so `Busy` is not what refuses this: the
/// channel holds an accepted job, the driver names another, and a
/// cursor advanced for a job this journal has never heard of would be
/// this channel's cursor moved by a stranger.
#[tokio::test]
async fn a_driver_naming_a_job_this_channel_does_not_hold_is_refused() {
    let open = Arc::new(AtomicBool::new(true));

    // Before acceptance there is no job to contradict, which is the
    // phase boundary's own case: the digest is the proposal's, and this
    // journal learns it from the acceptance this read precedes.
    let fresh_root = temp();
    let fresh = WorkService::new(provider_endpoint(fresh_root.path()).await);
    let unread = HeldChain::over((CURSOR + 1)..=(CURSOR + 3), &open);
    let ahead = fresh
        .catch_up_job(unread.as_ref(), Digest::from_bytes([0x55; 32]))
        .await;
    assert!(
        matches!(ahead, Ok(height) if height == CURSOR + 3),
        "a channel holding no job contradicts no name: {ahead:?}",
    );

    let root = temp();
    let service = WorkService::new(provider_endpoint(root.path()).await);
    accepted_signature(&accept_uploaded_service(&service, &signed_request(1, 1)).await);
    let chain = HeldChain::over((CURSOR + 1)..=(CURSOR + 3), &open);
    let fetches = Arc::clone(&chain.fetches);
    let stranger = service
        .catch_up_job(chain.as_ref(), Digest::from_bytes([0x56; 32]))
        .await;
    assert!(
        matches!(stranger, Err(CatchUpError::OtherJob)),
        "the journal's job is what says whose drive this is: {stranger:?}",
    );
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        0,
        "and the refused driver asked the source for nothing",
    );
    assert_eq!(
        service
            .with_state(|state| state.cursor().0)
            .await
            .expect("the endpoint is reachable"),
        CURSOR,
        "so the cursor is where it was",
    );
}

/// A channel whose one job has ended still knows whose drive this is.
///
/// Ending a job clears the *open* job and writes this channel's one
/// permanent terminal, which keeps the real `work_id`. A check that
/// consulted only the open job would therefore find nothing to
/// contradict on every channel that ever finished anything, and the
/// exception meant for "no job yet" would become "no job right now" —
/// any digest a caller offered would drive the cursor.
///
/// All five outcomes rest at the same terminal; the three below are the
/// ones reachable from this fixture's phase without a signed result.
#[tokio::test]
async fn a_driver_naming_another_job_is_refused_after_this_channel_s_job_ended() {
    let open = Arc::new(AtomicBool::new(true));
    for outcome in [
        TerminalOutcome::Failed { code: 1 },
        TerminalOutcome::Expired {
            deadline: deadlines().payment,
            height: CURSOR,
            payload: payload_at(CURSOR),
        },
        TerminalOutcome::Indeterminate,
    ] {
        let name = format!("{outcome:?}");
        let root = temp();
        let (service, held) = terminated_provider(root.path(), outcome).await;
        let chain = HeldChain::over((CURSOR + 1)..=(CURSOR + 3), &open);
        let fetches = Arc::clone(&chain.fetches);

        let stranger = service
            .catch_up_job(chain.as_ref(), Digest::from_bytes([0x56; 32]))
            .await;
        assert!(
            matches!(stranger, Err(CatchUpError::OtherJob)),
            "{name}: the terminal names the job as durably as the open one did: {stranger:?}",
        );
        assert_eq!(
            fetches.load(Ordering::SeqCst),
            0,
            "{name}: and the refused driver asked the source for nothing",
        );
        assert_eq!(
            service
                .with_state(|state| state.cursor().0)
                .await
                .expect("the endpoint is reachable"),
            CURSOR,
            "{name}: so the cursor is where it was",
        );

        // Non-vacuous: the job this channel really ran still drives.
        let owner = service.catch_up_job(chain.as_ref(), held).await;
        assert!(
            matches!(owner, Ok(height) if height == CURSOR + 3),
            "{name}: the job the terminal names is not locked out by it: {owner:?}",
        );
    }
}

/// A reopened provider whose one job has ended at `outcome`, with the
/// `work_id` that terminal holds.
///
/// Journaled the way the endpoint journals it — the proposal, then the
/// terminating record — and reopened, so what the driver reads is what
/// a restart would replay rather than what one run happened to hold.
async fn terminated_provider(
    root: &std::path::Path,
    outcome: TerminalOutcome,
) -> (WorkService, Digest) {
    let authorization = authorization(1, 1);
    let held = work_id(ready().channel(), &authorization);
    let client_signature = client().sign(signing_hash(held));
    let verifier = Secp256k1Verifier::new();
    let mut store = store_at_cursor(root, Role::Provider).await;
    for record in [
        ChannelRecord::JobProposed {
            authorization,
            client_signature,
            prepared_input: bundle_bytes(1),
        },
        ChannelRecord::JobTerminated {
            work_id: held,
            outcome,
        },
    ] {
        if let Err(error) = store.commit(record, &verifier).await {
            panic!("the fixture reaches its terminal: {error}");
        }
    }
    drop(store);

    let service = WorkService::new(provider_endpoint(root).await);
    let ended = service
        .with_state(|state| state.jobs().next().is_none() && state.terminals().next().is_some())
        .await
        .expect("the endpoint is reachable");
    assert!(
        ended,
        "the fixture's job is over and its terminal is on disk"
    );
    (service, held)
}

/// An inbound proposal is answered while a cursor drive waits on a slow
/// chain.
///
/// The drive is mid-flight and stopped at the source for the whole of
/// the request, and the request is answered — co-signature journaled and
/// all — without waiting for it. That is the watcher/runner isolation
/// rule as a test: a driver holds no borrow across a chain wait, so the
/// request path never queues behind one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proposal_is_answered_while_a_drive_waits_on_the_chain() {
    let root = temp();
    let service = WorkService::new(provider_endpoint(root.path()).await);
    let id = Digest::from_bytes([0x55; 32]);
    let released = Arc::new(AtomicBool::new(false));
    let chain = HeldChain::over((CURSOR + 1)..=(CURSOR + 3), &released);
    let fetches = Arc::clone(&chain.fetches);

    let driving = tokio::spawn({
        let service = service.clone();
        let chain = Arc::clone(&chain);
        async move { service.catch_up_job(chain.as_ref(), id).await }
    });
    reaches(&fetches, 1).await;

    let answering = tokio::spawn({
        let service = service.clone();
        async move { accept_uploaded_service(&service, &signed_request(1, 1)).await }
    });
    let answered = tokio::time::timeout(std::time::Duration::from_secs(10), answering).await;
    let Ok(Ok(response)) = answered else {
        panic!("the request path does not queue behind the drive: {answered:?}");
    };
    accepted_signature(&response);
    assert!(
        !driving.is_finished(),
        "the drive was still stopped at the chain while that was answered",
    );

    released.store(true, Ordering::SeqCst);
    assert!(driving.await.is_ok(), "and it finishes afterwards");
}

/// The same, for the drive that owns a sink as well as a source.
///
/// A close drive commits, submits and records a hand-off, so it is the
/// one that would be tempting to run under a single held borrow — and a
/// held borrow here is a provider that stops answering proposals every
/// time the chain is slow. It takes the endpoint per apply and per
/// record and across neither wait, so the request is answered with its
/// co-signature while the drive is stopped at the block source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proposal_is_answered_while_a_close_drive_waits_on_the_chain() {
    let root = temp();
    let service = WorkService::new(provider_endpoint(root.path()).await);
    let released = Arc::new(AtomicBool::new(false));
    let chain = HeldChain::over((CURSOR + 1)..=(CURSOR + 3), &released);
    let fetches = Arc::clone(&chain.fetches);
    let sink = Arc::new(NoSink::default());

    let driving = tokio::spawn({
        let service = service.clone();
        let chain = Arc::clone(&chain);
        let sink = Arc::clone(&sink);
        async move { service.advance_close(chain.as_ref(), sink.as_ref()).await }
    });
    reaches(&fetches, 1).await;

    let answering = tokio::spawn({
        let service = service.clone();
        async move { accept_uploaded_service(&service, &signed_request(1, 1)).await }
    });
    let answered = tokio::time::timeout(std::time::Duration::from_secs(10), answering).await;
    let Ok(Ok(response)) = answered else {
        panic!("the request path does not queue behind the close drive: {answered:?}");
    };
    accepted_signature(&response);
    assert!(
        !driving.is_finished(),
        "the drive was still stopped at the chain while that was answered",
    );

    released.store(true, Ordering::SeqCst);
    let Ok(Ok(progress)) = driving.await else {
        panic!("the close drive finishes its range");
    };
    assert_eq!(
        progress,
        hellas_channel::work_close::CloseProgress::Nothing,
        "this channel has no contest and no retained start, so nothing was sent",
    );
    assert_eq!(
        sink.taken.load(Ordering::SeqCst),
        0,
        "and the sink was never asked to take anything",
    );
    assert_eq!(
        service
            .with_state(|state| state.cursor().0)
            .await
            .expect("the endpoint is reachable"),
        CURSOR + 3,
    );
}

/// A sink that counts what it was asked to take, and takes it.
#[derive(Debug, Default)]
struct NoSink {
    taken: AtomicUsize,
}

impl hellas_channel::work_close::TxSink for NoSink {
    async fn submit(
        &self,
        _tx: hellas_kernel::Tx,
    ) -> Result<hellas_rpc::SubmitTxOutcome, BlockSourceError> {
        self.taken.fetch_add(1, Ordering::SeqCst);
        Ok(hellas_rpc::SubmitTxOutcome::Enqueued)
    }
}

#[test]
fn the_service_catalogue_names_the_work_service_and_nothing_settled() {
    let names: Vec<&str> = hellas_rpc::services::KNOWN_SERVICES
        .iter()
        .map(|service| service.name)
        .collect();
    assert!(
        names.contains(&"hellas.work.v1.Work"),
        "the work service is catalogued, got {names:?}",
    );
    assert_eq!(<Work as ServiceMarker>::ALPN, "/hellas.work.v1.Work/2.0");
    for dead in ["Receipt", "Settle", "JobAcceptance"] {
        assert!(
            !names.iter().any(|name| name.contains(dead)),
            "the single-edge protocol's {dead} is gone, got {names:?}",
        );
    }
}

// ── What the client puts on its disk, and when ────────────────────────

#[tokio::test]
async fn a_client_journals_its_signature_before_the_request_leaves() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(request) = endpoint.propose(&proposal(1)).await else {
        panic!("the fixture proposal is accepted by its own rules");
    };
    drop(endpoint);

    let reopened = store(root.path(), Role::Client).await;
    let Some(job) = reopened.state().jobs().next() else {
        panic!("the journal holds the proposal the caller was handed");
    };
    assert_eq!(job.phase(), JobPhase::HalfSigned);
    assert_eq!(
        job.client_signature().as_bytes().to_vec(),
        request.client_signature,
        "the signature on the disk is the signature on the wire",
    );
    assert_eq!(job.authorization().encode(), request.authorization);
    assert_eq!(
        hellas_rpc::protocol::content_upload::encode_reference(hellas_rpc::ContentRef::new(
            ContentId::hash(job.prepared_input()),
            job.prepared_input().len() as u64
        )),
        request.prepared_input
    );
}

#[tokio::test]
async fn a_proposal_refused_before_signing_leaves_no_job() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    // Terminal deadline inside the measured dispatch and delivery
    // margins: legal, ordered, and unreachable.
    let unreachable = JobProposal {
        prepared_input: bundle(1).into(),
        deadlines: JobDeadlines {
            acceptance: 11,
            terminal: 12,
            payment: 30,
        },
    };
    let refused = endpoint.propose(&unreachable).await;
    assert!(
        matches!(refused, Err(ProposeError::Setup(_))),
        "an unreachable terminal deadline is refused, got {refused:?}",
    );
    assert!(endpoint.state().jobs().next().is_none());
    drop(endpoint);
    assert!(
        store(root.path(), Role::Client)
            .await
            .state()
            .jobs()
            .next()
            .is_none()
    );
}

#[tokio::test]
async fn a_repeat_proposal_returns_the_retained_request() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(first) = endpoint.propose(&proposal(1)).await else {
        panic!("the first proposal is built");
    };
    let Ok(second) = endpoint.propose(&proposal(1)).await else {
        panic!("the same proposal is retained, not rebuilt");
    };
    assert_eq!(first, second, "the retained bytes come back unchanged");
}

#[tokio::test]
async fn a_retained_proposal_survives_restart_expiry_and_policy_change() {
    let root = temp();
    let provider_root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let first = endpoint.propose(&proposal(1)).await.unwrap();
    let work_id = endpoint.state().jobs().next().unwrap().work_id();
    let mut provider_endpoint = provider_endpoint(provider_root.path()).await;
    let response = accept_uploaded(&mut provider_endpoint, &first).await;
    drop(endpoint); // The provider response was lost before journaling.

    let mut policy = work_policy();
    policy.allowed_environment = ContentId::from_bytes([0x99; 32]);
    let changed = ready_with_descriptor(descriptor_with_policy(policy));
    let reopened = at_height(
        store(root.path(), Role::Client).await,
        proposal(1).deadlines.acceptance + 1,
    )
    .await;
    let mut endpoint = ClientEndpoint::new(changed, reopened, client()).unwrap();
    let resumed = endpoint.resume_proposal(work_id).await.unwrap();
    assert_eq!(resumed, first);
    assert_eq!(endpoint.state().proposal_nonce_high_water(), 1);
    assert_eq!(
        accept_uploaded(&mut provider_endpoint, &resumed).await,
        response
    );
    assert_eq!(endpoint.accepted(&response).await.unwrap(), work_id);
}

#[tokio::test]
async fn a_different_proposal_waits_for_the_outstanding_reply() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let first = endpoint.propose(&proposal(1)).await.unwrap();
    assert!(matches!(
        endpoint.propose(&proposal(2)).await,
        Err(ProposeError::Conflict)
    ));
    assert_eq!(endpoint.state().jobs().len(), 1);
    assert_eq!(endpoint.state().proposal_nonce_high_water(), 1);
    assert_eq!(endpoint.propose(&proposal(1)).await.unwrap(), first);
    let provider_root = temp();
    let mut provider_endpoint = provider_endpoint(provider_root.path()).await;
    let response = accept_uploaded(&mut provider_endpoint, &first).await;
    endpoint.accepted(&response).await.unwrap();
    assert!(endpoint.propose(&proposal(2)).await.is_ok());
    assert_eq!(
        endpoint.state().jobs().len(),
        2,
        "accepted executions still overlap"
    );
    assert_eq!(endpoint.state().proposal_nonce_high_water(), 2);
    let pending = endpoint.state().job_book().pending_proposal();
    assert!(matches!(
        endpoint.accepted(&response).await,
        Err(ProposeError::Conflict)
    ));
    assert_eq!(
        endpoint.state().job_book().pending_proposal(),
        pending,
        "a signed reply for another job cannot answer this exchange"
    );
}

#[tokio::test]
async fn a_known_refusal_releases_only_the_proposal_slot_durably() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let first = endpoint.propose(&proposal(1)).await.unwrap();
    let id = endpoint.state().job_book().pending_proposal().unwrap();
    let refused = AcceptWorkResponse {
        outcome: Some(Outcome::Refused(WorkRefused {
            grant: None,
            code: WorkRefusalCode::NotReady as i32,
            reason: String::new(),
        })),
    };
    assert!(matches!(
        endpoint.accepted(&refused).await,
        Err(ProposeError::Refused { .. })
    ));
    assert_eq!(endpoint.state().job_book().pending_proposal(), None);
    assert_eq!(
        endpoint.state().job_by_id(id).unwrap().phase(),
        JobPhase::HalfSigned
    );
    drop(endpoint);
    let mut reopened = client_endpoint(root.path()).await;
    assert_eq!(reopened.state().job_book().pending_proposal(), None);
    assert_eq!(reopened.resume_proposal(id).await.unwrap(), first);
    assert_eq!(reopened.state().job_book().pending_proposal(), Some(id));
    assert!(matches!(
        reopened.propose(&proposal(2)).await,
        Err(ProposeError::Conflict)
    ));
    reopened.accepted(&refused).await.unwrap_err();
    assert!(reopened.propose(&proposal(2)).await.is_ok());
    assert_eq!(reopened.state().jobs().len(), 2);
}

#[tokio::test]
async fn a_lost_reply_blocks_new_nonces_across_restart_and_malformed_replies() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let request = endpoint.propose(&proposal(1)).await.unwrap();
    let id = endpoint.state().job_book().pending_proposal().unwrap();
    drop(endpoint);
    let mut reopened = client_endpoint(root.path()).await;
    assert!(matches!(
        reopened.propose(&proposal(2)).await,
        Err(ProposeError::Conflict)
    ));
    assert!(
        reopened
            .accepted(&AcceptWorkResponse::default())
            .await
            .is_err()
    );
    assert_eq!(reopened.state().job_book().pending_proposal(), Some(id));
    assert_eq!(reopened.resume_proposal(id).await.unwrap(), request);
    assert_eq!(reopened.state().proposal_nonce_high_water(), 1);
}

#[tokio::test]
async fn an_acceptance_with_no_proposal_has_nothing_to_answer() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let authorization = authorization(1, 1);
    let signature = provider().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let response = accepted_response(signature);
    let refused = endpoint.accepted(&response).await;
    assert!(
        matches!(refused, Err(ProposeError::NoOpenJob)),
        "an acceptance answers a proposal or nothing, got {refused:?}",
    );
}

#[tokio::test]
async fn a_co_signature_from_another_key_is_not_an_acceptance() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(_) = endpoint.propose(&proposal(1)).await else {
        panic!("the proposal is built");
    };
    let authorization = authorization(1, 1);
    let forged = stranger().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let refused = endpoint.accepted(&accepted_response(forged)).await;
    assert!(
        matches!(refused, Err(ProposeError::Store(_))),
        "only the provider's key accepts, got {refused:?}",
    );
    assert_eq!(
        phase_of(endpoint.state()),
        Some(JobPhase::HalfSigned),
        "a forged co-signature moves nothing",
    );
}

#[tokio::test]
async fn a_refusal_is_read_back_as_the_refusal_it_names() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(_) = endpoint.propose(&proposal(1)).await else {
        panic!("the proposal is built");
    };
    let response = AcceptWorkResponse {
        outcome: Some(Outcome::Refused(WorkRefused {
            grant: None,
            code: WorkRefusalCode::Declined as i32,
            reason: "no".into(),
        })),
    };
    let refused = endpoint.accepted(&response).await;
    assert!(
        matches!(
            refused,
            Err(ProposeError::Refused {
                refusal: WorkRefusal::Declined,
                ..
            })
        ),
        "the client reads the code the provider sent, got {refused:?}",
    );
}

#[tokio::test]
async fn every_wire_code_reads_back_as_the_refusal_it_names() {
    // A known refusal releases the proposal slot, so each code is read
    // against its own fresh proposal.
    for (code, refusal) in [
        (WorkRefusalCode::NotReady, WorkRefusal::NotReady),
        (WorkRefusalCode::Expired, WorkRefusal::Expired),
        (WorkRefusalCode::Invalid, WorkRefusal::Invalid),
        (WorkRefusalCode::Conflict, WorkRefusal::Conflict),
        (WorkRefusalCode::Declined, WorkRefusal::Declined),
        (WorkRefusalCode::Unavailable, WorkRefusal::Unavailable),
    ] {
        let root = temp();
        let mut endpoint = client_endpoint(root.path()).await;
        let Ok(_) = endpoint.propose(&proposal(1)).await else {
            panic!("the proposal is built");
        };
        let response = AcceptWorkResponse {
            outcome: Some(Outcome::Refused(WorkRefused {
                grant: None,
                code: code as i32,
                reason: "no".into(),
            })),
        };
        let refused = endpoint.accepted(&response).await;
        assert!(
            matches!(refused, Err(ProposeError::Refused { refusal: got, .. }) if got == refusal),
            "{code:?} reads back as {refusal:?}, got {refused:?}",
        );
    }
}

#[tokio::test]
async fn a_response_this_service_does_not_define_is_malformed() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(_) = endpoint.propose(&proposal(1)).await else {
        panic!("the proposal is built");
    };
    for (what, response) in [
        ("no outcome", AcceptWorkResponse { outcome: None }),
        (
            "unspecified refusal",
            AcceptWorkResponse {
                outcome: Some(Outcome::Refused(WorkRefused {
                    grant: None,
                    code: WorkRefusalCode::Unspecified as i32,
                    reason: String::new(),
                })),
            },
        ),
        (
            "unassigned refusal",
            AcceptWorkResponse {
                outcome: Some(Outcome::Refused(WorkRefused {
                    grant: None,
                    code: 99,
                    reason: String::new(),
                })),
            },
        ),
        (
            "short signature",
            AcceptWorkResponse {
                outcome: Some(Outcome::Accepted(WorkAccepted {
                    provider_signature: vec![0; Sig::LENGTH - 1],
                    work_id: vec![0; Digest::LEN],
                })),
            },
        ),
    ] {
        let refused = endpoint.accepted(&response).await;
        assert!(
            matches!(refused, Err(ProposeError::Malformed(_))),
            "{what} is malformed, got {refused:?}",
        );
    }
}

fn accepted_response(signature: Sig) -> AcceptWorkResponse {
    let authorization = authorization(1, 1);
    AcceptWorkResponse {
        outcome: Some(Outcome::Accepted(WorkAccepted {
            provider_signature: signature.as_bytes().to_vec(),
            work_id: work_id(ready().channel(), &authorization)
                .as_bytes()
                .to_vec(),
        })),
    }
}

fn phase_of(state: &Channel) -> Option<JobPhase> {
    state.jobs().next().map(JobState::phase)
}

// ── What the provider puts on its disk, and when ──────────────────────

#[tokio::test]
async fn the_co_signature_is_on_the_disk_before_it_is_answered() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    let response = accept_uploaded(&mut endpoint, &signed_request(1, 1)).await;
    let signature = accepted_signature(&response);
    drop(endpoint);

    let reopened = store(root.path(), Role::Provider).await;
    let Some(job) = reopened.state().jobs().next() else {
        panic!("the journal holds the job it answered for");
    };
    assert_eq!(job.phase(), JobPhase::Accepted);
    assert_eq!(job.provider_signature(), Some(signature));
}

#[tokio::test]
async fn nothing_is_journaled_for_a_proposal_that_is_refused() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    let before = endpoint.state().jobs().next().is_none();
    // Another channel's authorization: the channel id is the first
    // thing `check_authorization` compares.
    let mut foreign = authorization(1, 1);
    foreign.channel_id = Digest::from_bytes([0x00; 32]);
    let signature = client().sign(signing_hash(work_id(ready().channel(), &foreign)));
    let response = accept_uploaded(&mut endpoint, &request(&foreign, signature, 1)).await;

    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);
    assert!(before && endpoint.state().jobs().next().is_none());
    drop(endpoint);
    assert!(
        store(root.path(), Role::Provider)
            .await
            .state()
            .jobs()
            .next()
            .is_none()
    );
}

/// A proposal the journal's own rules would take, refused by the rules
/// that run before it.
///
/// `apply_proposed` checks the channel, the bundle digest, the client
/// signature, and the nonce. It does not check the price, the policy
/// digest, or the deadline order, because nothing in a journal knows
/// what a policy fixed. So this is the case that separates the two: with
/// the acceptance checks removed, these bytes are journaled, credited,
/// and co-signed.
#[tokio::test]
async fn a_price_the_policy_does_not_fix_is_refused_before_anything_is_journaled() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    let mut overpriced = authorization(1, 1);
    overpriced.price = PRICE + 1;
    let signature = client().sign(signing_hash(work_id(ready().channel(), &overpriced)));
    let response = accept_uploaded(&mut endpoint, &request(&overpriced, signature, 1)).await;

    assert_eq!(
        refusal_code(&response),
        WorkRefusalCode::Invalid,
        "{}",
        refusal_text(&response),
    );
    assert!(endpoint.state().jobs().next().is_none());
    drop(endpoint);
    assert!(
        store(root.path(), Role::Provider)
            .await
            .state()
            .jobs()
            .next()
            .is_none()
    );
}

#[tokio::test]
async fn a_retry_returns_the_retained_co_signature() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    let first = accepted_signature(&accept_uploaded(&mut endpoint, &signed_request(1, 1)).await);
    let second = accepted_signature(&accept_uploaded(&mut endpoint, &signed_request(1, 1)).await);
    assert_eq!(first, second);
}

#[tokio::test]
async fn a_retry_after_the_deadline_still_returns_the_retained_signature() {
    let root = temp();
    let client_root = temp();
    let mut caller = client_endpoint(client_root.path()).await;
    let request = caller
        .propose(&proposal(1))
        .await
        .expect("the client journals its proposal");
    let mut endpoint = provider_endpoint(root.path()).await;
    let first = accepted_signature(&accept_uploaded(&mut endpoint, &request).await);
    drop(endpoint);
    drop(caller); // The acceptance acknowledgement never reached the client.

    // Both sides restart. The provider is past acceptance and close-only,
    // while the client still has only its own signature.
    let late = at_height(
        store(root.path(), Role::Provider).await,
        deadlines().acceptance + 1,
    )
    .await;
    let service = WorkService::close_only(CloseEndpoint::new(late, provider()).unwrap());
    let checkpoint = service.with_state(Channel::checkpoint).await.unwrap();
    let mut caller = client_endpoint(client_root.path()).await;
    assert_eq!(phase_of(caller.state()), Some(JobPhase::HalfSigned));
    let id = work_id(ready().channel(), &authorization(1, 1));
    let resumed = caller.resume_proposal(id).await.unwrap();
    let mut forged = resumed.clone();
    forged.client_signature = stranger().sign(signing_hash(id)).as_bytes().to_vec();
    assert_eq!(
        refusal_code(&service.precheck_acceptance(&forged).await.unwrap()),
        WorkRefusalCode::Invalid,
        "a retained signature is returned only to an authenticated proposal",
    );
    let again = service.precheck_acceptance(&resumed).await.unwrap();
    assert_eq!(
        accepted_signature(&again),
        first,
        "an answer already given is not unsaid by a passing height",
    );
    assert_eq!(accept_uploaded_service(&service, &resumed).await, again);
    assert_eq!(
        service.with_state(Channel::checkpoint).await.unwrap(),
        checkpoint
    );
    assert_eq!(caller.accepted(&again).await.unwrap(), id);
    assert_eq!(phase_of(caller.state()), Some(JobPhase::Accepted));

    // A terminal is also an authenticated, permanent answer without readiness.
    drop(service);
    let mut ended = store(root.path(), Role::Provider).await;
    ended
        .commit(
            ChannelRecord::JobTerminated {
                work_id: id,
                outcome: TerminalOutcome::Failed { code: 1 },
            },
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
    let service = WorkService::close_only(CloseEndpoint::new(ended, provider()).unwrap());
    let checkpoint = service.with_state(Channel::checkpoint).await.unwrap();
    assert_eq!(
        refusal_code(&service.precheck_acceptance(&forged).await.unwrap()),
        WorkRefusalCode::Invalid
    );
    assert_eq!(
        refusal_code(&service.precheck_acceptance(&resumed).await.unwrap()),
        WorkRefusalCode::Conflict
    );
    assert_eq!(
        service.with_state(Channel::checkpoint).await.unwrap(),
        checkpoint
    );
}

#[tokio::test]
async fn a_crash_between_the_two_commits_co_signs_on_retry() {
    let root = temp();
    // A provider that journaled the proposal and died before signing.
    let mut store = store_at_cursor(root.path(), Role::Provider).await;
    let authorization = authorization(1, 1);
    let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    if let Err(error) = store
        .commit(
            ChannelRecord::JobProposed {
                authorization,
                client_signature: signature,
                prepared_input: bundle_bytes(1),
            },
            &Secp256k1Verifier::new(),
        )
        .await
    {
        panic!("the proposal is journaled: {error}");
    }
    drop(store);

    let mut endpoint = provider_endpoint(root.path()).await;
    assert_eq!(
        phase_of(endpoint.state()),
        Some(JobPhase::HalfSigned),
        "the reopened provider is half-signed",
    );
    let response = accept_uploaded(&mut endpoint, &request(&authorization, signature, 1)).await;
    assert_eq!(phase_of(endpoint.state()), Some(JobPhase::Accepted),);
    accepted_signature(&response);
}

// ── The six refusals, one at a time ───────────────────────────────────

#[tokio::test]
async fn a_provider_with_no_finalized_block_is_not_ready() {
    let root = temp();
    let Ok(mut endpoint) = ProviderEndpoint::new(
        ready(),
        store(root.path(), Role::Provider).await,
        provider(),
    ) else {
        panic!("the endpoint binds");
    };
    let response = accept_uploaded(&mut endpoint, &signed_request(1, 1)).await;
    assert_eq!(refusal_code(&response), WorkRefusalCode::NotReady);
    assert!(WorkRefusal::NotReady.is_retryable());
}

#[tokio::test]
async fn an_authorization_past_its_acceptance_deadline_expires() {
    let root = temp();
    let late = at_height(
        store(root.path(), Role::Provider).await,
        deadlines().acceptance + 1,
    )
    .await;
    let Ok(mut endpoint) = ProviderEndpoint::new(ready(), late, provider()) else {
        panic!("the endpoint binds");
    };
    let response = accept_uploaded(&mut endpoint, &signed_request(1, 1)).await;
    assert_eq!(refusal_code(&response), WorkRefusalCode::Expired);
    assert!(!WorkRefusal::Expired.is_retryable());
    drop(endpoint);

    let service = WorkService::close_only(
        CloseEndpoint::new(store(root.path(), Role::Provider).await, provider()).unwrap(),
    );
    let checkpoint = service.with_state(Channel::checkpoint).await.unwrap();
    let expired = signed_request(1, 1);
    assert_eq!(
        refusal_code(&service.precheck_acceptance(&expired).await.unwrap()),
        WorkRefusalCode::Expired,
        "the persisted cursor proves expiry without any new readiness",
    );
    assert_eq!(
        refusal_code(&accept_uploaded_service(&service, &expired).await),
        WorkRefusalCode::Expired
    );
    let mut forged = expired;
    forged.client_signature = stranger()
        .sign(signing_hash(work_id(
            ready().channel(),
            &authorization(1, 1),
        )))
        .as_bytes()
        .to_vec();
    assert_eq!(
        refusal_code(&service.precheck_acceptance(&forged).await.unwrap()),
        WorkRefusalCode::Invalid
    );
    let fresh = signed_request_with(
        1,
        1,
        JobDeadlines {
            acceptance: deadlines().acceptance + 1,
            ..deadlines()
        },
    );
    assert!(
        service.precheck_acceptance(&fresh).await.is_none(),
        "the acceptance boundary remains inclusive"
    );
    assert_eq!(
        refusal_code(&accept_uploaded_service(&service, &fresh).await),
        WorkRefusalCode::NotReady
    );
    assert_eq!(
        service.with_state(Channel::checkpoint).await.unwrap(),
        checkpoint
    );
}

#[tokio::test]
async fn a_bundle_that_is_not_the_committed_one_is_invalid() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    // The authorization commits to bundle 1; the request carries 2.
    let authorization = authorization(1, 1);
    let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let response = accept_uploaded(&mut endpoint, &request(&authorization, signature, 2)).await;
    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);
    assert!(endpoint.state().jobs().next().is_none());
}

/// A bundle that hashes to its own authorization and still breaks the
/// policy the channel signed.
///
/// The digest binding is not the same rule as the envelope: a client is
/// free to commit to whatever it likes, and what makes a proposal
/// runnable is that the committed graph fits inside the bounds both
/// parties fixed. Nothing in a journal can see that.
fn overlong_bundle() -> PreparedPaidInputV1 {
    // The channel allows 128 new tokens; this asks for 129.
    let policy = TextPolicy::from_u32_stop_tokens(129, [2, 1]);
    let execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        policy.output_id(),
    );
    let mut request = evaluate_request(1);
    request.text_execution = execution.input_id().digest();
    PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &execution,
        &prompt_tokens(),
        &policy,
        &identity_artifact(),
    )
}

/// A bundle whose runner is not the channel's client, likewise
/// self-consistent and likewise not runnable here.
fn foreign_runner_bundle() -> PreparedPaidInputV1 {
    let mut request = evaluate_request(1);
    request.runner_public_key = PublicKey::Secp256k1(stranger().party_key().to_bytes());
    PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
}

#[tokio::test]
async fn a_bundle_the_policy_does_not_allow_is_refused_though_its_digest_matches() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    for (what, bundle) in [
        ("a generation policy over the envelope", overlong_bundle()),
        ("a runner that is not the client", foreign_runner_bundle()),
    ] {
        let authorization = match propose_authorization(
            ready().channel(),
            &work_policy(),
            &payment_policy(),
            &bundle,
            1,
            deadlines(),
        ) {
            Ok(authorization) => authorization,
            Err(error) => panic!("{what} still builds an authorization: {error}"),
        };
        let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
        let Ok(bytes) = bundle.encode() else {
            panic!("{what} encodes");
        };
        let response = accept_uploaded(
            &mut endpoint,
            &AcceptWorkRequest {
                route: Some(hellas_rpc::pb::work::WorkRoute::payment(
                    authorization.channel_id,
                )),
                authorization: authorization.encode(),
                client_signature: signature.as_bytes().to_vec(),
                prepared_input: bytes,
            },
        )
        .await;

        assert_eq!(
            refusal_code(&response),
            WorkRefusalCode::Invalid,
            "{what}: {}",
            refusal_text(&response),
        );
        assert!(
            endpoint.state().jobs().next().is_none(),
            "{what} reserved nothing"
        );
    }
}

#[tokio::test]
async fn a_forged_client_signature_is_invalid() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    let authorization = authorization(1, 1);
    let forged = stranger().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let response = accept_uploaded(&mut endpoint, &request(&authorization, forged, 1)).await;
    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);
    assert!(
        endpoint.state().jobs().next().is_none(),
        "a proposal nobody signed reserves nothing",
    );
}

/// A signature is exactly 64 bytes, and a longer field is not one.
///
/// The load-bearing case is the last: the real signature with a byte
/// after it. A field of the wrong length full of *garbage* is refused by
/// the verifier however the length is read, so on its own it proves
/// nothing about the length rule — it is here as the neighbour that a
/// reader who truncates would also refuse.
#[tokio::test]
async fn a_signature_of_any_other_length_is_not_a_signature() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    let valid = signed_request(1, 1).client_signature;

    let mut cases: Vec<(String, Vec<u8>)> = [Sig::LENGTH - 1, Sig::LENGTH + 1, 0]
        .into_iter()
        .map(|length| (format!("{length} garbage bytes"), vec![0x11; length]))
        .collect();
    cases.push((
        "the signature with a byte after it".to_owned(),
        valid.iter().copied().chain([0x00]).collect(),
    ));
    cases.push((
        "the signature one byte short".to_owned(),
        valid[..Sig::LENGTH - 1].to_vec(),
    ));

    for (what, client_signature) in cases {
        let mut request = signed_request(1, 1);
        request.client_signature = client_signature;
        let response = accept_uploaded(&mut endpoint, &request).await;
        assert_eq!(
            refusal_code(&response),
            WorkRefusalCode::Invalid,
            "{what} is refused",
        );
        assert!(
            endpoint.state().jobs().next().is_none(),
            "{what} reserved nothing"
        );
    }
}

/// The two refusals the measured margins produce, and the reason they
/// are not the same answer.
///
/// A terminal deadline this height can no longer reach is a fact about
/// the height, and no later one recovers it. A payment deadline too
/// close to its terminal is a fact about two carried numbers and no
/// height at all, so it is wrong rather than late.
#[tokio::test]
async fn the_measured_margins_separate_a_late_job_from_a_malformed_one() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    for (what, deadlines, expected) in [
        (
            "a terminal deadline inside the dispatch and delivery margins",
            JobDeadlines {
                acceptance: 12,
                terminal: 13,
                payment: 100,
            },
            WorkRefusalCode::Expired,
        ),
        (
            "a payment deadline under the measured oracle grace",
            JobDeadlines {
                acceptance: 50,
                terminal: 100,
                payment: 103,
            },
            WorkRefusalCode::Invalid,
        ),
    ] {
        let response = accept_uploaded(&mut endpoint, &signed_request_with(1, 1, deadlines)).await;
        assert_eq!(
            refusal_code(&response),
            expected,
            "{what}: {}",
            refusal_text(&response),
        );
        assert!(
            endpoint.state().jobs().next().is_none(),
            "{what} reserved nothing",
        );
    }
}

#[tokio::test]
async fn bytes_that_are_not_an_authorization_are_invalid() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    let mut truncated = signed_request(1, 1);
    truncated.authorization.pop();
    assert_eq!(
        refusal_code(&accept_uploaded(&mut endpoint, &truncated).await),
        WorkRefusalCode::Invalid,
    );

    let mut retagged = signed_request(1, 1);
    retagged.authorization[1] = 0xfe;
    assert_eq!(
        refusal_code(&accept_uploaded(&mut endpoint, &retagged).await),
        WorkRefusalCode::Invalid,
    );
}

#[tokio::test]
async fn a_job_already_in_flight_does_not_block_the_next_one() {
    let root = temp();
    let mut endpoint = provider_endpoint(root.path()).await;
    accepted_signature(&accept_uploaded(&mut endpoint, &signed_request(1, 1)).await);
    let response = accept_uploaded(&mut endpoint, &signed_request(2, 2)).await;
    accepted_signature(&response);
    assert_eq!(endpoint.state().jobs().len(), 2);
}

#[tokio::test]
async fn a_poisoned_endpoint_is_unavailable() {
    let root = temp();
    let service = WorkService::new(provider_endpoint(root.path()).await);
    // The panic happens inside a service operation, which is the only
    // place the endpoint is borrowed from at all now.
    use futures::FutureExt as _;
    let panicked =
        std::panic::AssertUnwindSafe(service.with_state(|_| panic!("poison the endpoint")))
            .catch_unwind()
            .await;
    assert!(
        panicked.is_err(),
        "the service operation panicked on purpose"
    );
    assert!(matches!(
        service.with_state(|state| state.cursor()).await,
        Err(EndpointError::Poisoned)
    ));
    // And the refusal that answer becomes on the wire is unavailability,
    // not an accusation about the proposal.
    assert_eq!(
        refusal_code(&accept_uploaded_service(&service, &signed_request(1, 1)).await),
        WorkRefusalCode::Unavailable,
    );
}

// ── Binding an endpoint to its own half of its own channel ────────────

#[tokio::test]
async fn an_endpoint_needs_its_own_store_settlement_role_and_key() {
    let root = temp();
    let wrong_role =
        ProviderEndpoint::new(ready(), store(root.path(), Role::Client).await, provider());
    assert!(
        matches!(wrong_role, Err(EndpointError::WrongRole { .. })),
        "a client journal is not a provider endpoint, got {wrong_role:?}",
    );

    let other = temp();
    let wrong_key =
        ProviderEndpoint::new(ready(), store(other.path(), Role::Provider).await, client());
    assert!(
        matches!(wrong_key, Err(EndpointError::WrongKey { .. })),
        "the client's key does not co-sign as the provider, got {wrong_key:?}",
    );

    let third = temp();
    let Some(thin) = work_payment_settlement(
        EdgeValues::new(PAYMENT_VALUE - 1, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0)),
        OMISSION_BOND,
    ) else {
        panic!("a funded edge prices both exits");
    };
    let wrong_settlement = ProviderEndpoint::new(
        ready(),
        store_with(third.path(), Role::Provider, thin).await,
        provider(),
    );
    assert!(
        matches!(wrong_settlement, Err(EndpointError::WrongSettlement)),
        "a store bounded by other funding is not this channel's, got {wrong_settlement:?}",
    );

    let fourth = temp();
    let Ok(elsewhere) = PaidChannel::new(
        network(),
        EdgeId::from_bytes([0x99; EdgeId::LENGTH]),
        payment_terms(),
        &SALT,
        channel_policy(),
    ) else {
        panic!("a second payment edge is a second channel");
    };
    let other_origin = SetupOrigin {
        payment_edge: elsewhere.payment_edge(),
        ..origin()
    };
    let Ok(other_store) = ChannelStore::open(
        fourth.path(),
        elsewhere,
        settlement(),
        Role::Provider,
        other_origin,
        &Secp256k1Verifier::new(),
    )
    .await
    else {
        panic!("the other channel's store opens");
    };
    let wrong_channel = ProviderEndpoint::new(ready(), other_store, provider());
    assert!(
        matches!(wrong_channel, Err(EndpointError::WrongChannel)),
        "another channel's journal is not this channel's, got {wrong_channel:?}",
    );

    let fifth = temp();
    let ok = ClientEndpoint::new(ready(), store(fifth.path(), Role::Client).await, client());
    assert!(ok.is_ok(), "the matching triple binds: {ok:?}");
}

// ── What the authorization derives ────────────────────────────────────

#[test]
fn the_authorization_derives_every_field_it_does_not_choose() {
    let channel = ready().channel().clone();
    let policy = work_policy();
    let built = authorization(7, 3);
    let request = evaluate_request(7);

    // Each field against an independently computed value, not against
    // a second call to the same constructor: a swap of two fields of
    // the same width survives a round trip and does not survive this.
    assert_eq!(built.channel_id, channel.id());
    assert_eq!(built.bond_edge, bond_edge());
    assert_eq!(built.bond_terms_hash, payment_terms().bond_terms_hash());
    assert_eq!(built.payment_edge, payment_edge());
    assert_eq!(
        built.payment_terms_hash,
        payment_terms_hash(payment_terms()),
    );
    assert_eq!(
        built.work_policy_digest,
        work_policy_digest(&channel, &policy),
    );
    assert_eq!(
        built.prepared_input_digest,
        match prepared_input_digest(&channel, &bundle(7)) {
            Ok(digest) => digest,
            Err(error) => panic!("the bundle hashes: {error}"),
        },
    );
    assert_eq!(built.proposal_nonce, 3);
    assert_eq!(built.acceptance_deadline, deadlines().acceptance);
    assert_eq!(built.request_commitment, Evaluate::commit_request(&request));
    assert_eq!(built.environment_commitment, manifest().content_id());
    assert_eq!(built.price, payment_policy().fixed_price);
    assert_eq!(built.terminal_deadline, deadlines().terminal);
    assert_eq!(built.payment_deadline, deadlines().payment);

    // The three deadlines are distinct, so the three assertions above
    // are three assertions and not one repeated.
    assert!(
        deadlines().acceptance != deadlines().terminal
            && deadlines().terminal != deadlines().payment,
    );
}

#[tokio::test]
async fn the_wire_carries_the_authorization_the_signature_covers() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(request) = endpoint.propose(&proposal(1)).await else {
        panic!("the proposal is built");
    };
    let authorization = authorization(1, 1);
    assert_eq!(
        request.authorization,
        authorization.encode(),
        "the wire field is the canonical record, not a re-spelling",
    );
    assert_eq!(
        request.authorization.get(..2),
        Some(&[1_u8, 9_u8][..]),
        "format version 1, private record tag 9",
    );
    assert_eq!(
        request.prepared_input,
        hellas_rpc::protocol::content_upload::encode_reference(hellas_rpc::ContentRef::new(
            ContentId::hash(&bundle_bytes(1)),
            bundle_bytes(1).len() as u64
        ))
    );

    let expected = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    assert_eq!(request.client_signature, expected.as_bytes().to_vec());
    assert!(
        Secp256k1Verifier::new().verify_sig(
            expected,
            client().party_key(),
            PayloadHash::from_bytes(work_id(ready().channel(), &authorization).into_bytes(),),
        ),
        "the signature on the wire verifies over the work id",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_observer_does_not_hold_the_journal_during_chain_io() {
    use hellas_channel::work::{ClientChannel as _, ClientService};
    let root = temp();
    let mut service = ClientService::new(client_endpoint(root.path()).await);
    service
        .observer()
        .observe_ready(
            ready(),
            hellas_channel::work::ObservationTime::now(),
            std::time::Duration::from_secs(30),
        )
        .await
        .unwrap();
    let released = Arc::new(AtomicBool::new(false));
    let source = HeldChain::over(CURSOR + 1..=CURSOR + 1, &released);
    let observer = service.observer();
    let held_source = source.clone();
    let driving =
        tokio::spawn(async move { observer.drive().unwrap().catch_up(&*held_source).await });
    reaches(&source.fetches, 1).await;
    assert!(matches!(
        service.observer().drive(),
        Err(EndpointError::CatchingUp)
    ));
    // The provider exchange can sign and journal while the observer waits.
    let request = service
        .client()
        .await
        .unwrap()
        .propose(&proposal(1))
        .await
        .unwrap();
    assert!(!request.client_signature.is_empty());
    assert_eq!(
        service
            .with_state(|state| state.proposal_nonce_high_water())
            .await
            .unwrap(),
        1
    );
    released.store(true, Ordering::SeqCst);
    assert_eq!(driving.await.unwrap().unwrap(), CURSOR + 1);
    assert!(service.observer().drive().is_ok());
}

#[tokio::test]
async fn shared_client_can_follow_blocks_while_waiting_for_provider_acceptance() {
    use hellas_channel::work::ClientService;
    let client_root = temp();
    let provider_root = temp();
    let mut client = ClientService::new(client_endpoint(client_root.path()).await);
    client
        .observer()
        .observe_ready(
            ready(),
            hellas_channel::work::ObservationTime::now(),
            std::time::Duration::from_secs(30),
        )
        .await
        .unwrap();
    let observer = client.observer();
    let (client_transport, server_transport) = transport_pair();
    let request =
        tokio::spawn(
            async move { propose_work(client_transport, &mut client, &proposal(1)).await },
        );
    // No server is running yet, so the request must wait for its response.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while observer
            .with_state(|state| state.proposal_nonce_high_water())
            .await
            .unwrap()
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    observer
        .drive()
        .unwrap()
        .observe_finalized(&FinalizedWork {
            height: CURSOR + 1,
            parent: payload_at(CURSOR),
            payload: payload_at(CURSOR + 1),
            txs: Vec::new(),
        })
        .await
        .unwrap();
    let serving = serve(
        server_transport,
        WorkService::new(provider_endpoint(provider_root.path()).await),
    );
    request.await.unwrap().unwrap();
    assert_eq!(
        observer.with_state(|state| state.cursor().0).await.unwrap(),
        CURSOR + 1
    );
    serving.abort();
}

#[tokio::test]
async fn managed_observers_start_closed_and_old_tips_cannot_renew_expired_readiness() {
    use hellas_channel::work::{ClientChannel as _, ClientService};
    let client_root = temp();
    let provider_root = temp();
    let mut client = ClientService::new(client_endpoint(client_root.path()).await);
    let provider = WorkService::new(provider_endpoint(provider_root.path()).await);
    provider.require_observer().await.unwrap();
    assert!(matches!(
        client.readiness().await,
        Err(EndpointError::ObservationStale)
    ));
    assert_eq!(
        refusal_code(&accept_uploaded_service(&provider, &signed_request(1, 1)).await),
        WorkRefusalCode::NotReady
    );
    for max_age in [
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(30),
    ] {
        let started = hellas_channel::work::ObservationTime::now();
        client
            .observer()
            .observe_ready(ready(), started, max_age)
            .await
            .unwrap();
        provider
            .observe_ready(ready(), started, max_age)
            .await
            .unwrap();
        assert!(matches!(
            client.client().await.unwrap().propose(&proposal(1)).await,
            Err(ProposeError::Endpoint(EndpointError::ObservationStale))
        ));
        assert_eq!(
            refusal_code(&accept_uploaded_service(&provider, &signed_request(1, 1)).await),
            WorkRefusalCode::NotReady
        );
    }
    assert_eq!(
        client
            .with_state(|state| state.proposal_nonce_high_water())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        provider
            .with_state(|state| state.jobs().len())
            .await
            .unwrap(),
        0
    );
}
