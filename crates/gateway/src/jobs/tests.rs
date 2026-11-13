use super::*;
use tokio::sync::oneshot;

fn request() -> Request {
    Request {
        origin: Origin::Local,
        method: "POST".into(),
        path: "/v1/responses".into(),
    }
}

#[tokio::test]
async fn cancel_before_execution_never_starts_and_releases_once() {
    let limit = Arc::new(RequestLimit::default());
    limit.configure(std::num::NonZeroU64::new(1));
    let jobs = Arc::new(Jobs::new(limit));
    let job = jobs.admit(&request()).unwrap();
    let id = job.id();
    assert!(jobs.cancel(id));
    assert!(
        job.spawn("backend", async { panic!("cancelled admission ran") })
            .is_err()
    );
    drop(job);
    assert!(!jobs.cancel(id));
    jobs.admit(&request())
        .expect("cancelled work returns its quota");
    jobs.drain().await.unwrap();
}

#[tokio::test]
async fn watch_observes_admission_backend_acceptance_cancel_and_settlement_in_order() {
    let jobs = Arc::new(Jobs::default());
    let (initial, mut events) = jobs.watch(|jobs| jobs);
    assert!(initial.is_empty());
    let job = jobs.admit(&request()).unwrap();
    let (release, released) = oneshot::channel();
    let running = job.clone();
    job.spawn("chosen", async move {
        released.await.unwrap();
        running.finish(Outcome::Completed);
    })
    .unwrap();
    job.accepted();
    assert!(jobs.cancel(job.id()));
    job.cancelled().await;
    assert_eq!(jobs.watch(|jobs| jobs).0[0].state, State::Cancelling);
    release.send(()).unwrap();
    jobs.drain().await.unwrap();
    assert!(jobs.watch(|jobs| jobs).0.is_empty());
    let mut states = vec![];
    while let Ok(Event::Job { job }) = events.try_recv() {
        states.push((job.state, job.outcome));
    }
    assert_eq!(
        states,
        [
            (State::Admitted, None),
            (State::Running, None),
            (State::Accepted, None),
            (State::Cancelling, None),
            (State::Finished, Some(Outcome::Completed)),
        ]
    );
}

#[tokio::test]
async fn exhausted_quota_prevents_routing() {
    struct Unreachable;
    impl crate::WorkExecutionBackend for Unreachable {
        fn backends(&self) -> Vec<crate::BackendInfo> {
            vec![]
        }
        fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), WorkShutdownError>> {
            Box::pin(async { Ok(()) })
        }
    }
    let limit = Arc::new(RequestLimit::default());
    limit.configure(std::num::NonZeroU64::new(1));
    let jobs = Arc::new(Jobs::new(limit));
    let first = jobs.admit(&request()).unwrap();
    let router = crate::router::router(
        vec![],
        Arc::new(Unreachable),
        jobs.clone(),
        Default::default(),
    )
    .await
    .unwrap();
    use tower::ServiceExt;
    let response = router
        .oneshot(
            axum::http::Request::post("/v1/responses")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(jobs.watch(|jobs| jobs).0.len(), 1);
    drop(first);
}

#[tokio::test]
async fn cancelled_drain_keeps_work_even_when_the_table_is_poisoned() {
    for poison in [false, true] {
        let jobs = Arc::new(Jobs::default());
        let job = jobs.admit(&request()).unwrap();
        let (release, released) = oneshot::channel();
        let running = job.clone();
        job.spawn("backend", async move {
            released.await.unwrap();
            running.finish(Outcome::Completed);
        })
        .unwrap();
        if poison {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _state = jobs.state.lock().unwrap();
                    panic!("inject poisoned job table");
                }))
                .is_err()
            );
        }
        {
            let mut first = std::pin::pin!(jobs.drain());
            assert!(futures::poll!(&mut first).is_pending());
        }
        assert!(jobs.admit(&request()).is_err());
        let mut second = std::pin::pin!(jobs.drain());
        assert!(futures::poll!(&mut second).is_pending());
        release.send(()).unwrap();
        let result = second.await;
        if poison {
            assert!(matches!(result, Err(WorkShutdownError::Poisoned)));
        } else {
            result.unwrap();
        }
    }
}

#[tokio::test]
async fn task_panic_is_reported_after_other_work_finishes() {
    let jobs = Arc::new(Jobs::default());
    let first = jobs.admit(&request()).unwrap();
    first
        .spawn("first", async {
            panic!("injected task panic");
        })
        .unwrap();
    let second = jobs.admit(&request()).unwrap();
    let (release, released) = oneshot::channel();
    second
        .spawn("second", async {
            released.await.unwrap();
        })
        .unwrap();
    let mut draining = std::pin::pin!(jobs.drain());
    assert!(futures::poll!(&mut draining).is_pending());
    tokio::task::yield_now().await;
    assert!(futures::poll!(&mut draining).is_pending());
    release.send(()).unwrap();
    assert!(matches!(draining.await, Err(WorkShutdownError::Task(error)) if error.is_panic()));
}

#[tokio::test]
async fn recovered_acceptances_do_not_consume_the_request_quota() {
    let limit = Arc::new(RequestLimit::default());
    limit.configure(std::num::NonZeroU64::new(1));
    let jobs = Arc::new(Jobs::new(limit));
    let first = jobs.admit(&request()).unwrap();
    first.accepted();
    first.finish(Outcome::Completed);
    assert!(jobs.admit(&request()).is_err());
    let recovered: Vec<_> = (0..3).map(|_| jobs.recover(&request()).unwrap()).collect();
    assert_eq!(jobs.watch(|jobs| jobs).0.len(), 3);
    for job in recovered {
        job.accepted();
        job.finish(Outcome::Completed);
    }
    assert!(jobs.admit(&request()).is_err());
    jobs.close();
    assert!(jobs.recover(&request()).is_err());
    jobs.drain().await.unwrap();
}
