//! One paid job, end to end, from the client's side: proposed,
//! computed by a real provider endpoint, delivered, authenticated, and
//! paid for.
//!
//! Both endpoints are real and hold real journals, and the exchange runs
//! over a real multiplexed transport, framed and routed by method id.

#![cfg(feature = "work")]

use hellas_channel::test_support::channel::serve_work as serve;
use hellas_channel::test_support::channel::{
    CURSOR, PRICE, accept, authorization, client, payload_at, provider, ready, run_to_result,
    store_at,
};

use hellas_channel::work::{ClientEndpoint, ProviderEndpoint, WorkService};
use hellas_channel::work_close::{BlockSourceError, FinalizedBlocks, FinalizedWork};
use hellas_channel::work_store::{JobPhase, JobState, Role};
use hellas_client::work::payment::pay_for_result;
use hellas_client::work::{CollectResultError, CollectResultOutcome, collect_result};
use hellas_wire::mux::MuxTransport;

// ── Fixture ───────────────────────────────────────────────────────────

fn temp() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("a temporary directory: {error}"),
    }
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

// ── The whole path ────────────────────────────────────────────────────

/// The normal paid-work path authenticates and pays a provider result
/// without constructing or invoking a reproduction engine.
#[tokio::test]
async fn an_authenticated_answer_is_paid_without_reexecution() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let id = accept(&mut [&mut client_store, &mut provider_store]).await;
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
    endpoint
        .verified(id)
        .await
        .expect("the client records its result check");

    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let credited = pay_for_result(transport, &mut endpoint, id).await;
    serving.abort();
    assert_eq!(credited.ok(), Some(PRICE));
    assert_eq!(endpoint.state().ledger().credited_cumulative(), PRICE);
}

/// Ordinary collection uses a post-delivery finalized-height
/// barrier and will not return a stale payable result.
#[tokio::test]
async fn ordinary_collection_refuses_a_stale_payment_boundary() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let id = accept(&mut [&mut client_store, &mut provider_store]).await;
    let authorization = authorization();
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
    let id = accept(&mut [&mut client_store, &mut provider_store]).await;
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
    let collected = collect_result(transport, &mut endpoint, &ready, &still(), id).await;
    serving.abort();
    assert!(
        matches!(collected, Ok(CollectResultOutcome::Collected(_))),
        "the answer is collected: {collected:?}",
    );
    endpoint
        .verified(id)
        .await
        .expect("the client records its result check");

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
