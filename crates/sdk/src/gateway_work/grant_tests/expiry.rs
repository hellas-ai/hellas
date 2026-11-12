//! Delay real journal commits before acknowledgement, on every host platform.
use super::*;
use hellas_channel::work_store::journal::test_support::AppendHook;
use std::sync::atomic::AtomicUsize;

#[tokio::test]
async fn a_durable_proposal_is_not_replaced_when_admission_expires() {
    let fixture = Fixture::builder().with_max_job_millis(10_000).build().await;
    let ticking = follow_clock(&fixture);
    let (hook, delayed) = delay_transition(
        &fixture.host.root.path().join("client"),
        "Proposed",
        1,
        Duration::from_millis(6_000),
    );
    assert!(matches!(
        fixture.result(None).await,
        Err(WorkGatewayError::Timeout(_))
    ));
    assert_eq!(delayed.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 0);
    let session = fixture.session().await;
    assert_eq!(session.store().next_nonce().unwrap(), 2);
    assert!(session.store().book().pending_proposal().is_none());
    drop(session);
    drop(hook);
    fixture.shutdown().await;
    ticking.abort();
}

#[tokio::test]
async fn ambiguous_acceptance_recovers_original_work_without_replacement() {
    let fixture = Fixture::builder().with_max_job_millis(30_000).build().await;
    let ticking = follow_clock(&fixture);
    // The actual Accepted INSERT commits, but its acknowledgement misses the
    // control timeout. The provider continues independently of the client RPC.
    let (hook, delayed) = delay_transition(
        &fixture.host.root.path().join("provider"),
        "Accepted",
        1,
        Duration::from_secs(6),
    );
    assert!(matches!(
        fixture.result(None).await,
        Err(WorkGatewayError::Timeout(_))
    ));
    assert_eq!(delayed.load(Ordering::SeqCst), 1);
    // A failed session closes with the original proposal still journaled.
    // Actual demand reopens and recovers it before signing the next request.
    drop(hook);
    assert!(fixture.gateway.backends()[0].down);
    ticking.abort();
    let session = fixture.session().await;
    let pending = session.store().book().pending_proposal().unwrap();
    let deadline = session
        .store()
        .book()
        .job_by_id(pending)
        .unwrap()
        .authorization()
        .acceptance_deadline_ms;
    drop(session);
    fixture.gateway.backends["test"]
        .grant
        .lock()
        .await
        .take()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    fixture
        .host
        .world
        .clock
        .set(hellas_auth::authority::UnixMillis(deadline.0 + 1));
    fixture.result(None).await.unwrap();
    assert!(!fixture.gateway.backends()[0].down);
    let session = fixture.session().await;
    assert!(session.store().book().pending_proposal().is_none());
    assert_eq!(session.store().next_nonce().unwrap(), 3);
    drop(session);
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
    ticking.abort();
}

#[tokio::test]
async fn journal_open_time_counts_from_standing_response_arrival() {
    crate::grant_client::tests::delayed_open_keeps_response_arrival_clock(|path| {
        delay_transition(path, "Clock", 1, Duration::from_millis(600)).0
    })
    .await;
}

fn delay_transition(
    directory: &std::path::Path,
    kind: &'static str,
    limit: usize,
    delay: Duration,
) -> (AppendHook, Arc<AtomicUsize>) {
    let delayed = Arc::new(AtomicUsize::new(0));
    let count = delayed.clone();
    let hook = AppendHook::new(directory, move |payload| {
        let selected = has_change(payload, kind)
            && count
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    (n < limit).then_some(n + 1)
                })
                .is_ok();
        Box::pin(async move {
            if selected {
                tokio::time::sleep(delay).await;
            }
        })
    });
    (hook, delayed)
}

// Read only the transition tags, ignoring signatures and record bodies.
fn has_change(payload: &[u8], kind: &str) -> bool {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Change {
        Unit(String),
        Record(std::collections::BTreeMap<String, serde::de::IgnoredAny>),
    }
    impl Change {
        fn is(&self, kind: &str) -> bool {
            match self {
                Self::Unit(name) => name == kind,
                Self::Record(fields) => fields.contains_key(kind),
            }
        }
    }
    #[derive(serde::Deserialize)]
    struct Frame {
        change: Option<Change>,
        #[serde(default)]
        changes: Vec<Change>,
    }
    let frame: Frame = hellas_rpc::protocol::value::decode_dag_cbor(payload).unwrap();
    frame
        .change
        .iter()
        .chain(&frame.changes)
        .any(|change| change.is(kind))
}

fn follow_clock(fixture: &Fixture) -> tokio::task::JoinHandle<()> {
    let clock = fixture.host.world.clock.clone();
    let start = std::time::Instant::now();
    let base = clock.now().0;
    tokio::spawn(async move {
        loop {
            clock.set(hellas_auth::authority::UnixMillis(
                base + start.elapsed().as_millis() as u64,
            ));
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
}
