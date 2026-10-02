use super::*;
use crate::work_store::journal::JournalError;
use tokio::sync::Semaphore;

#[path = "../../tests/common_grant/mod.rs"]
mod common;

#[derive(Clone)]
struct Backend {
    slots: Arc<Semaphore>,
    started: Arc<Notify>,
    finish: Arc<Notify>,
    panic: bool,
}
impl Backend {
    fn new(panic: bool) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(1)),
            started: Arc::new(Notify::new()),
            finish: Arc::new(Notify::new()),
            panic,
        }
    }
}
impl WorkBackend for Backend {
    fn try_admit(&self, domain: CapacityDomain) -> Result<WorkPermit, BackendFault> {
        Ok(WorkPermit::new(
            domain,
            self.slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| crate::work::admission::AdmissionError::Capacity)?,
        ))
    }
    async fn fetch_stream(
        &self,
        input: PreparedFetchInput,
        _: PaidProgress,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        let input = input
            .reserve(async { self.try_admit(CapacityDomain::Fetch) })
            .await?;
        let (_, admission) = input.into_parts_and_admission();
        let _running = admission.dispatch()?;
        self.started.notify_one();
        self.finish.notified().await;
        assert!(!self.panic, "backend fixture panic");
        Err(BackendFault::caused_by(std::io::Error::other(
            "backend fixture stopped",
        )))
    }
}
fn start(directory: &std::path::Path, backend: Backend) -> (GrantService, ChannelId, Digest) {
    let store = common::setup(directory);
    let (mut authorization, _, input) = common::proposal(&store, 1);
    // These tests coordinate shutdown explicitly; allow journal I/O and other
    // parallel fixtures to run without accidentally testing deadline expiry.
    authorization.terminal_deadline_ms = UnixMillis(11_000);
    authorization.delivery_deadline_ms = UnixMillis(12_000);
    let id = grant_work_id(common::network(), &authorization);
    let signature = common::principal(1).1.sign_digest(id).unwrap();
    let service = GrantService::new(
        store,
        Arc::new(common::principal(2).1),
        backend,
        vec![],
        Arc::new(|| UnixMillis(1000)),
    )
    .unwrap();
    let response = service.accept(
        &AcceptWorkRequest {
            route: Some(WorkRoute::grant(authorization.channel_id)),
            authorization: authorization.encode(),
            client_signature: signature.bytes().to_vec(),
            prepared_input: input.encode().unwrap(),
        },
        &TransportContext {
            peer: Some(hellas_wire::PeerIdentity([1; 32])),
            auth_level: hellas_wire::AuthLevel::Vouched,
            open_exporter: Some([7; 32]),
            rtt_ms: None,
        },
    );
    assert!(matches!(
        response.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ));
    (service, authorization.channel_id, id)
}

#[tokio::test]
async fn backend_panic_finishes_the_job_and_does_not_strand_shutdown() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let directory = tempfile::tempdir().unwrap();
        let backend = Backend::new(true);
        let (service, channel, id) = start(directory.path(), backend.clone());
        backend.started.notified().await;
        backend.finish.notify_one();
        service.drain().await.unwrap();
        assert_eq!(backend.slots.available_permits(), 1);
        service
            .administer(|store, _| {
                let terminal = store
                    .state()
                    .channel(channel)
                    .unwrap()
                    .job_book()
                    .terminal_by_id(id)
                    .unwrap();
                assert_eq!(terminal.outcome.outcome, GrantOutcome::Failed);
                Ok(())
            })
            .unwrap();
        drop(service);
        let reopened = GrantStore::open(
            directory.path(),
            common::network(),
            common::principal(2).0.bundle().clone(),
            UnixMillis(1000),
        )
        .unwrap();
        assert_eq!(
            reopened
                .state()
                .channel(channel)
                .unwrap()
                .job_book()
                .terminal_by_id(id)
                .unwrap()
                .outcome
                .outcome,
            GrantOutcome::Failed
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn failed_writer_waits_for_physical_completion_before_returning_the_error() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for poison in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let backend = Backend::new(false);
            let (service, _, _) = start(directory.path(), backend.clone());
            backend.started.notified().await;
            if poison {
                let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _held = service.inner.lock().unwrap();
                    panic!("writer fixture panic");
                }));
                assert!(panic.is_err());
            } else {
                // An administrative write can fail while another execution
                // still owns capacity. Its typed failure must survive drain.
                let failure = service.administer::<()>(|_, _| {
                    Err(JournalError::Io(std::io::Error::other("fsync fixture failure")).into())
                });
                assert!(matches!(failure, Err(GrantStoreError::Completion(_))));
            }
            let mut draining = std::pin::pin!(service.drain());
            assert!(futures::poll!(&mut draining).is_pending());
            assert_eq!(backend.slots.available_permits(), 0);
            backend.finish.notify_one();
            let GrantStoreError::Completion(source) = draining.await.unwrap_err() else {
                panic!("shutdown lost its durable failure");
            };
            if poison {
                assert!(matches!(source.as_ref(), GrantStoreError::WriterPoisoned));
            } else {
                assert!(matches!(
                    source.as_ref(),
                    GrantStoreError::Journal(JournalError::Io(_))
                ));
            }
            assert_eq!(backend.slots.available_permits(), 1);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_shutdown_keeps_ownership_for_the_next_drain() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let directory = tempfile::tempdir().unwrap();
        let backend = Backend::new(false);
        let (service, _, _) = start(directory.path(), backend.clone());
        backend.started.notified().await;
        {
            let mut first = std::pin::pin!(service.drain());
            assert!(futures::poll!(&mut first).is_pending());
        }
        let mut second = std::pin::pin!(service.drain());
        assert!(futures::poll!(&mut second).is_pending());
        assert_eq!(backend.slots.available_permits(), 0);
        backend.finish.notify_one();
        second.await.unwrap();
        assert_eq!(backend.slots.available_permits(), 1);
    })
    .await
    .unwrap();
}
