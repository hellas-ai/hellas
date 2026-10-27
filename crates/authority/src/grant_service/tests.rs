mod protocol;
mod uploads;
use super::*;
use hellas_channel::work_store::journal::JournalError;

use crate::test_support as common;
use {crate::test_support::within, hellas_channel::test_support::assert_err};

use hellas_channel::test_support::backend::{Backend, Reply};
async fn start(directory: &std::path::Path, backend: Backend) -> (GrantService, ChannelId, Digest) {
    let (store, secret) = common::setup_with_credential(directory).await;
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
    let (work_service, _) = common::common_node::execution(
        &service,
        &secret,
        &common::principal(1).1,
        authorization.grant_id,
    )
    .await;
    let response = crate::test_support::accept_grant(
        &work_service,
        &AcceptWorkRequest {
            route: Some(WorkRoute::grant(authorization.channel_id.0)),
            authorization: authorization.encode(),
            client_signature: signature.bytes().to_vec(),
            prepared_input: input.encode().unwrap(),
        },
        &common::principal(1).1,
    )
    .await;
    assert!(matches!(
        response.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ));
    (service, authorization.channel_id, id)
}

#[tokio::test]
async fn backend_panic_finishes_the_job_and_does_not_strand_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let backend = Backend {
        reply: Reply::Failure { panic: true },
        ..Backend::default()
    };
    let (service, channel, id) = start(directory.path(), backend.clone()).await;
    within(backend.started.notified()).await;
    backend.finish.release();
    within(service.drain()).await.unwrap();
    assert_eq!(backend.slots.available_permits(), 1);
    service
        .administer(async |store, _| {
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
        .await
        .unwrap();
    drop(service);
    let reopened = NodeStore::open(
        directory.path(),
        common::network(),
        Some(hellas_channel::test_support::software_enrollment(
            2, [2; 32],
        )),
        UnixMillis(1000),
    )
    .await
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
}

#[tokio::test]
async fn failed_writer_waits_for_physical_completion_before_returning_the_error() {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Failure {
        Write,
        RuntimePanic,
        StorePanic,
    }
    for failure_kind in [Failure::Write, Failure::RuntimePanic, Failure::StorePanic] {
        let directory = tempfile::tempdir().unwrap();
        let backend = Backend {
            reply: Reply::Failure { panic: false },
            ..Backend::default()
        };
        let (service, _, _) = start(directory.path(), backend.clone()).await;
        within(backend.started.notified()).await;
        if failure_kind == Failure::RuntimePanic {
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = service.inner.lock().unwrap();
                panic!("writer fixture panic");
            }));
            panic.unwrap_err();
        } else if failure_kind == Failure::StorePanic {
            let panic = std::panic::AssertUnwindSafe(async {
                let _held = service.node.store.lock().await.unwrap();
                panic!("store fixture panic");
            })
            .catch_unwind()
            .await;
            panic.unwrap_err();
            assert_err!(
                service.administer(async |_, _| Ok(())).await,
                NodeStoreError::WriterPoisoned
            );
            assert_err!(
                service
                    .node()
                    .begin_authentication(Digest::hash(b"failed writer"))
                    .await,
                NodeStoreError::WriterPoisoned
            );
        } else {
            // An administrative write can fail while another execution
            // still owns capacity. Its typed failure must survive drain.
            let failure = service.administer::<()>(async |_, _| {
                Err(JournalError::Io(std::io::Error::other("fsync fixture failure")).into())
            });
            assert_err!(failure.await, NodeStoreError::Completion(_));
        }
        let mut draining = std::pin::pin!(service.drain());
        assert!(futures::poll!(&mut draining).is_pending());
        assert_eq!(backend.slots.available_permits(), 0);
        backend.finish.release();
        let NodeStoreError::Completion(source) = within(draining).await.unwrap_err() else {
            panic!("shutdown lost its durable failure");
        };
        if failure_kind != Failure::Write {
            assert!(matches!(source.as_ref(), NodeStoreError::WriterPoisoned));
        } else {
            assert!(matches!(
                source.as_ref(),
                NodeStoreError::Journal(JournalError::Io(_))
            ));
        }
        assert_eq!(backend.slots.available_permits(), 1);
    }
}

#[tokio::test]
async fn cancelled_shutdown_keeps_ownership_for_the_next_drain() {
    let directory = tempfile::tempdir().unwrap();
    let backend = Backend {
        reply: Reply::Failure { panic: false },
        ..Backend::default()
    };
    let (service, _, _) = start(directory.path(), backend.clone()).await;
    within(backend.started.notified()).await;
    let writer = service.node.store.lock().await.unwrap();
    {
        let mut blocked = std::pin::pin!(service.drain());
        assert!(futures::poll!(&mut blocked).is_pending());
    }
    assert_eq!(backend.slots.available_permits(), 0);
    drop(writer);
    {
        let mut first = std::pin::pin!(service.drain());
        assert!(futures::poll!(&mut first).is_pending());
    }
    let mut second = std::pin::pin!(service.drain());
    assert!(futures::poll!(&mut second).is_pending());
    assert_eq!(backend.slots.available_permits(), 0);
    backend.finish.release();
    within(second).await.unwrap();
    assert_eq!(backend.slots.available_permits(), 1);
}
