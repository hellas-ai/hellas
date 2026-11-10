//! Delay real journal commits before acknowledgement, on every host platform.
use super::*;
use hellas_channel::work_store::journal::test_support::AppendHook;
use std::sync::atomic::AtomicUsize;

#[tokio::test]
async fn slow_durable_admission_retries_once() {
    for (persistent, provider_write) in [(false, false), (true, false), (false, true)] {
        let fixture = Fixture::builder()
            .with_max_job_millis(if provider_write { 5_000 } else { 10_000 })
            .build()
            .await;
        let ticking = follow_clock(&fixture);
        let (hook, delayed) = delay_transition(
            &fixture
                .host
                .root
                .path()
                .join(if provider_write { "provider" } else { "client" }),
            if provider_write { "Clock" } else { "Proposed" },
            if persistent { 2 } else { 1 },
            Duration::from_millis(if provider_write { 3_000 } else { 6_000 }),
        );
        let result = fixture.result(None).await;
        assert_eq!(
            delayed.load(Ordering::SeqCst),
            if persistent { 2 } else { 1 }
        );
        if persistent {
            assert!(
                matches!(result, Err(WorkGatewayError::Timeout(_))),
                "{result:?}"
            );
        } else {
            result.unwrap();
        }
        assert_eq!(
            fixture.host.backend.calls.load(Ordering::SeqCst),
            usize::from(!persistent)
        );
        let session = fixture.session().await;
        assert_eq!(session.store().next_nonce().unwrap(), 3);
        assert!(session.store().book().pending_proposal().is_none());
        drop(session);
        drop(hook);
        fixture.shutdown().await;
        ticking.abort();
    }
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
    // The timed-out request's session recovered the proposal it retained
    // before closing: the original work stands and nothing replaced it.
    drop(hook);
    let session = fixture.session().await;
    assert!(session.store().book().pending_proposal().is_none());
    assert_eq!(session.store().next_nonce().unwrap(), 2);
    drop(session);
    within(fixture.host.backend.started.notified()).await;
    assert_eq!(fixture.host.backend.calls.load(Ordering::SeqCst), 1);
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
