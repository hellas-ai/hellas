//! Spending the certificate from certified reads: the cursor that makes a
//! deadline mean something, the contest a read shows, and the two
//! transactions that turn one signed scalar into coins.
//!
//! The job at the top of every channel fixture here is a real one —
//! proposed, co-signed, computed, delivered, checked and paid over a live
//! transport — so what a close settles is what the earlier phases
//! produced. The chain is a small fake that hands the endpoint the reads a
//! remote light client would: one certified block, its timestamp, the two
//! edges and the pending-close slot.

use std::sync::Mutex;

use hellas_auth::Digest;
use hellas_channel::model::setup::ObservedChannel;
use hellas_channel::test_support::channel::{
    CURSOR, Checked, bond_edge, bond_object, checked_job, client, lease_over, now_ms, payload_at,
    payment_edge, payment_object, serve_work as serve, stop, store_at,
};
use hellas_channel::test_support::transport::transport_pair;
use hellas_channel::work::{
    ClientEndpoint, MAX_CERTIFIED_AGE, POLL, PaymentError, WorkService, admit_payment,
};
use hellas_channel::work_close::{
    BlockSourceError, CloseProgress, TxSink, adjudicated_close, close_start, observe,
};
use hellas_channel::work_store::{
    ChannelStateError, ChannelStore, CloseSettlement, Role, TerminalOutcome, WorkStoreError,
};
use hellas_kernel::{
    Edge, MAX_BLOCK_TIME_LEAD_MS, Move, Party, PendingPaymentClose, PendingSlot,
    RESPONSE_WINDOW_MS, Secp256k1Verifier, Tx,
};
use hellas_rpc::services::work::WorkClientImpl;

mod support;
use support::temp;

const POLL_MS: u64 = POLL.as_millis() as u64;
const MAX_AGE_MS: u64 = MAX_CERTIFIED_AGE.as_millis() as u64;

// ── The chain a watcher reads ─────────────────────────────────────────

/// The two live fixture edges a read reports.
struct Chain {
    bond: Edge,
    payment: Edge,
}

impl Chain {
    fn new() -> Self {
        Self {
            bond: bond_object(),
            payment: payment_object(),
        }
    }

    /// One certified read at `height`, stamped `certified_at_ms`.
    fn read(
        &self,
        height: u64,
        certified_at_ms: u64,
        pending: Option<PendingPaymentClose>,
        payment_live: bool,
    ) -> ObservedChannel<'_> {
        ObservedChannel {
            height,
            payload: payload_at(height),
            certified_at_ms,
            bond: Some(&self.bond),
            payment: payment_live.then_some(&self.payment),
            lease: lease_over(bond_edge(), payment_edge()),
            pending: pending.map_or(PendingSlot::Absent, PendingSlot::Present),
        }
    }
}

/// A sink that keeps what it was handed.
#[derive(Default)]
struct Mempool {
    submitted: Mutex<Vec<Tx>>,
}

impl Mempool {
    fn taken(&self) -> Vec<Tx> {
        std::mem::take(&mut *self.submitted.lock().unwrap())
    }
}

impl TxSink for Mempool {
    async fn submit(&self, tx: Tx) -> Result<hellas_rpc::SubmitTxOutcome, BlockSourceError> {
        self.submitted.lock().unwrap().push(tx);
        Ok(hellas_rpc::SubmitTxOutcome::Enqueued)
    }
}

fn responses(txs: &[Tx]) -> usize {
    txs.iter()
        .filter(|tx| {
            matches!(
                tx,
                Tx::Move {
                    action: Move::RespondPaymentClose(_)
                }
            )
        })
        .count()
}

// ── The state these tests begin from ──────────────────────────────────

/// One `AdmitCertificate` over a live transport.
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

/// One job, all the way through: checked and paid for. The provider's
/// journal holds one client-signed certificate at `PRICE`.
async fn paid_job() -> Checked {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    pay_over_wire(&fixture.service, &mut fixture.client, id)
        .await
        .expect("the fixture job is paid");
    fixture
}

/// The contest a client opens with `start` in a block stamped
/// `block_time_ms`, as consensus records it in the pending slot.
fn contest(
    fixture: &Checked,
    start: &hellas_kernel::PaymentCloseStart,
    height: u64,
    block_time_ms: u64,
) -> PendingPaymentClose {
    PendingPaymentClose::from_accepted_start(
        fixture.ready.channel().network(),
        height,
        block_time_ms,
        start,
    )
    .expect("the fixture contest opens")
}

/// A client start claiming nothing: below the certificate the provider
/// holds, so the provider owes an answer.
fn understated_start(fixture: &Checked) -> hellas_kernel::PaymentCloseStart {
    close_start(
        fixture.ready.channel(),
        Party::Maker,
        CURSOR,
        None,
        &client(),
    )
    .expect("the client signs its start")
}

// ── Close/contest safety ──────────────────────────────────────────────

/// A client's understated close is answered well inside the response
/// window, by a watcher on the derived poll interval reading state up to
/// the certified-age bound old, while proposers stamp blocks up to the
/// skew bound ahead of real time.
///
/// Real time `t0` is when the start is included, in a block stamped `t0`;
/// every later block is stamped `MAX_BLOCK_TIME_LEAD_MS` ahead, the worst
/// case for the deadline `t0 + RESPONSE_WINDOW_MS`. The watcher reads at
/// `t0 + phase + k·POLL`; a read taken at real `r` with lag `lag` reports
/// the state made at real `r − lag`, which shows the contest only from
/// `t0` on. The answer must be offered on the first read that shows the
/// contest, and that read's certified time must still leave half the
/// window — the part sized for submission and inclusion.
#[tokio::test]
async fn a_client_close_below_the_certificate_is_answered_inside_the_window() {
    let chain = Chain::new();
    for lag in [0, MAX_AGE_MS - 1] {
        for lead in [0, MAX_BLOCK_TIME_LEAD_MS] {
            for phase in [0, POLL_MS - 1] {
                let fixture = paid_job().await;
                let sink = Mempool::default();
                // After the fixture's own read, by more than any lag.
                let t0 = fixture
                    .service
                    .with_state(|state| state.certified_at_ms())
                    .await
                    .unwrap()
                    + MAX_AGE_MS;
                let start_height = CURSOR + 1;
                let pending = contest(&fixture, &understated_start(&fixture), start_height, t0);
                let deadline = pending.response_deadline_ms();
                assert_eq!(deadline, t0 + RESPONSE_WINDOW_MS);
                let mut answered_at = None;
                for k in 0.. {
                    let real = t0 + phase + k * POLL_MS;
                    let made = real - lag;
                    let certified = made + lead;
                    let height = start_height + 1 + k;
                    let shown = (made >= t0).then_some(pending);
                    fixture
                        .service
                        .advance_close(&chain.read(height, certified, shown, true), &sink)
                        .await
                        .expect("the read applies");
                    let offered = responses(&sink.taken());
                    if shown.is_none() {
                        assert_eq!(offered, 0, "nothing is answered before it is seen");
                        continue;
                    }
                    assert_eq!(offered, 1, "the first read showing the contest answers it");
                    answered_at = Some((real, certified));
                    break;
                }
                let (real, certified) = answered_at.expect("the contest is answered");
                assert!(
                    real - t0 <= POLL_MS + MAX_AGE_MS,
                    "detected within one poll and one certified age (lag {lag}, phase {phase})",
                );
                assert!(
                    certified < deadline - RESPONSE_WINDOW_MS / 2,
                    "half the window remains for inclusion (lag {lag}, lead {lead}, phase {phase})",
                );
                assert!(
                    real + MAX_BLOCK_TIME_LEAD_MS < deadline - RESPONSE_WINDOW_MS / 2,
                    "even if chain time races ahead by the skew bound",
                );
            }
        }
    }
}

/// The fixed answer is offered on every read until a read shows it
/// landed; then the answered contest is adjudicated.
#[tokio::test]
async fn the_answer_is_offered_on_every_read_until_it_lands() {
    let chain = Chain::new();
    let fixture = paid_job().await;
    let sink = Mempool::default();
    let t0 = now_ms();
    let pending = contest(&fixture, &understated_start(&fixture), CURSOR + 1, t0);

    for k in 0..3 {
        let progress = fixture
            .service
            .advance_close(
                &chain.read(CURSOR + 2 + k, t0 + k * POLL_MS, Some(pending), true),
                &sink,
            )
            .await
            .expect("the read applies");
        assert!(matches!(progress, CloseProgress::Opened { .. }));
        let offered = sink.taken();
        assert_eq!(responses(&offered), 1, "read {k} offers the answer again");
    }

    // A read shows the answer accepted: nothing more is answered, and the
    // contest the answer settled is adjudicated from that read's slot.
    let certificate = fixture
        .client
        .state()
        .executable_certificate()
        .expect("the client holds the certificate it signed");
    let response = hellas_channel::work_close::close_response(
        fixture.ready.channel(),
        pending.start_id(),
        certificate,
        &hellas_channel::test_support::channel::provider(),
    )
    .expect("the provider's answer");
    let answered = pending.with_accepted_response(&response);
    let progress = fixture
        .service
        .advance_close(
            &chain.read(CURSOR + 10, t0 + 4 * POLL_MS, Some(answered), true),
            &sink,
        )
        .await
        .expect("the read applies");
    assert!(matches!(
        progress,
        CloseProgress::AdjudicationSubmitted { .. }
    ));
    let submitted = sink.taken();
    assert_eq!(
        responses(&submitted),
        0,
        "an answer that landed is not resent"
    );
    let settlement = fixture
        .service
        .with_state(|state| state.settlement())
        .await
        .unwrap();
    assert_eq!(
        submitted,
        vec![adjudicated_close(fixture.ready.channel(), settlement, &answered).unwrap()],
        "the close is built from the read's own slot",
    );
}

/// A contest the provider owes nothing on is adjudicated only once the
/// read's block time reaches the deadline, and from that read's slot.
#[tokio::test]
async fn adjudication_waits_for_the_window_in_block_time() {
    let chain = Chain::new();
    let mut fixture = paid_job().await;
    let sink = Mempool::default();
    // The client claims exactly what it signed: nothing to add.
    let start = fixture.client.prepare_close().await.unwrap();
    let t0 = now_ms();
    let pending = contest(&fixture, &start, CURSOR + 1, t0);
    let deadline = pending.response_deadline_ms();

    for (height, certified) in [(CURSOR + 2, t0), (CURSOR + 500, deadline - 1)] {
        let progress = fixture
            .service
            .advance_close(&chain.read(height, certified, Some(pending), true), &sink)
            .await
            .expect("the read applies");
        assert!(matches!(progress, CloseProgress::Opened { .. }));
        assert!(
            sink.taken().is_empty(),
            "nothing is due before the deadline"
        );
    }
    let progress = fixture
        .service
        .advance_close(
            &chain.read(CURSOR + 501, deadline, Some(pending), true),
            &sink,
        )
        .await
        .expect("the read applies");
    assert!(matches!(
        progress,
        CloseProgress::AdjudicationSubmitted { .. }
    ));
    let settlement = fixture
        .service
        .with_state(|state| state.settlement())
        .await
        .unwrap();
    assert_eq!(
        sink.taken(),
        vec![adjudicated_close(fixture.ready.channel(), settlement, &pending).unwrap()],
    );

    // The edge gone at a later read is the close, recorded where it was seen.
    let progress = fixture
        .service
        .advance_close(&chain.read(CURSOR + 503, deadline + 1, None, false), &sink)
        .await
        .expect("the read applies");
    assert_eq!(progress, CloseProgress::Settled);
    assert_eq!(
        fixture
            .service
            .with_state(|state| state.close_settled())
            .await
            .unwrap(),
        Some(CloseSettlement {
            height: CURSOR + 503,
            payload: payload_at(CURSOR + 503),
        }),
    );
}

// ── Re-anchoring ──────────────────────────────────────────────────────

async fn provider_store(root: &std::path::Path) -> ChannelStore {
    store_at(
        root,
        &hellas_channel::test_support::channel::ready(),
        Role::Provider,
        CURSOR,
    )
    .await
}

/// The cursor moves forward to any later certified read — however far,
/// and a gap past the window is a warning, not a refusal — and never back.
#[tokio::test]
async fn the_cursor_reanchors_forward_and_refuses_older_reads() {
    let root = temp();
    let chain = Chain::new();
    let verifier = Secp256k1Verifier::new();
    let mut store = provider_store(root.path()).await;
    let t0 = store.state().certified_at_ms();

    let far = CURSOR + 1_000_000;
    observe(
        &mut store,
        &chain.read(far, t0 + 10 * RESPONSE_WINDOW_MS, None, true),
        &verifier,
    )
    .await
    .expect("a jump past the window still applies");
    assert_eq!(store.state().cursor(), (far, payload_at(far)));

    let behind = observe(&mut store, &chain.read(far - 1, t0, None, true), &verifier).await;
    assert!(matches!(
        behind,
        Err(WorkStoreError::Channel(
            ChannelStateError::CursorBehind { .. }
        ))
    ));
    let mut other = chain.read(far, t0 + 10 * RESPONSE_WINDOW_MS, None, true);
    other.payload = [0x99; 32];
    let forked = observe(&mut store, &other, &verifier).await;
    assert!(matches!(
        forked,
        Err(WorkStoreError::Channel(
            ChannelStateError::CursorNotContiguous { .. }
        ))
    ));
    assert_eq!(store.state().cursor(), (far, payload_at(far)));
}

/// A jump past a job's deadlines ends it exactly as walking every block
/// would have, at the read that crossed them.
#[tokio::test]
async fn a_jump_expires_the_jobs_whose_deadlines_it_crossed() {
    let fixture = checked_job().await;
    let chain = Chain::new();
    let deadlines = hellas_channel::test_support::channel::deadlines();
    let past = deadlines.payment + 100;
    fixture
        .service
        .advance_close(&chain.read(past, now_ms(), None, true), &Mempool::default())
        .await
        .expect("the read applies");
    let (open, terminal) = fixture
        .service
        .with_state(|state| {
            (
                state.jobs().len(),
                state.terminal_by_id(fixture.id).map(|t| t.outcome.clone()),
            )
        })
        .await
        .unwrap();
    assert_eq!(open, 0);
    assert!(matches!(
        terminal,
        Some(TerminalOutcome::Expired { height, .. }) if height == past
    ));
}

/// A contest open at the channel's first sighting is seen there: the
/// origin read's own slot.
#[tokio::test]
async fn a_contest_at_the_first_sighting_is_recorded() {
    let root = temp();
    let chain = Chain::new();
    let verifier = Secp256k1Verifier::new();
    let fixture = paid_job().await;
    let content = hellas_channel::test_support::channel::content_store(root.path()).await;
    let origin = hellas_channel::test_support::channel::origin();
    let mut store = ChannelStore::open(
        &hellas_private::StoreLocation::for_test(root.path()),
        fixture.ready.channel().clone(),
        hellas_channel::test_support::channel::settlement(),
        Role::Client,
        origin,
        content.clone(),
        &verifier,
    )
    .await
    .expect("the store opens");
    content.finish_recovery().await.unwrap();
    let pending = contest(
        &fixture,
        &understated_start(&fixture),
        origin.height,
        now_ms(),
    );
    observe(
        &mut store,
        &chain.read(origin.height, now_ms(), Some(pending), true),
        &verifier,
    )
    .await
    .expect("the origin read applies");
    assert_eq!(
        store.state().close_opened(),
        Some((pending.start_id(), Party::Maker))
    );
    assert_eq!(store.state().pending(), Some(pending));
}
