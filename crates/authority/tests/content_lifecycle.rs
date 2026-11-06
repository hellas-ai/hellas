#![cfg(feature = "test-support")]
use futures::StreamExt;
use hellas_auth::Digest;
use hellas_authority::{
    grant_service::{GrantService, GrantWork},
    model::grant::{ChannelId, GrantJobAuthorizationV1},
    test_support as common,
};
use hellas_channel::{
    model::work::PrivateRecord,
    test_support::{backend::Backend, drive_upload},
    work::admission::Cancellation,
};
use hellas_rpc::{
    pb::{content as pb, work::*},
    services::content::Upload,
};
use hellas_store::content::{ContentStore, DiskStore, Error, PinName, Scope};
use hellas_wire::{MethodMarker, StreamTransport, TransportContext, mux::MuxTransport};
use std::sync::Arc;

struct Fixture {
    root: tempfile::TempDir,
    service: GrantService,
    work: GrantWork,
    backend: Backend,
    node: DiskStore,
    clock: common::TestClock,
    wire: AcceptWorkRequest,
    frames: Vec<pb::UploadRequest>,
    authorization: GrantJobAuthorizationV1,
    id: Digest,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let (store, secret) = common::setup_with_credential(root.path()).await;
        let (authorization, signature, input) = common::proposal(&store, 1);
        let request = AcceptWorkRequest {
            route: Some(WorkRoute::grant(authorization.channel_id.0)),
            authorization: authorization.encode(),
            client_signature: signature.bytes().to_vec(),
            prepared_input: input.canonical_bytes().unwrap(),
        };
        let (wire, frames) = common::grant_upload_requests(
            &request,
            &common::principal(1).1,
            common::network(),
            [7; 32],
        );
        let node = common::content_store(root.path()).await;
        let clock = common::TestClock::default();
        let backend = Backend::default();
        let service = GrantService::new(
            store,
            Arc::new(common::principal(2).1),
            backend.clone(),
            vec![],
            clock.source(),
            node.clone(),
        )
        .unwrap();
        let (work, _) = common::common_node::execution(
            &service,
            &secret,
            &common::principal(1).1,
            authorization.grant_id,
        )
        .await;
        let id = hellas_authority::model::grant::grant_work_id(common::network(), &authorization);
        Self {
            root,
            service,
            work,
            backend,
            node,
            clock,
            wire,
            frames,
            authorization,
            id,
        }
    }
    async fn upload(&self, connection: Cancellation) -> Result<(), hellas_wire::WireStatus> {
        drive_upload(
            self.work
                .upload_stream(
                    Box::pin(futures::stream::iter(
                        self.frames.clone().into_iter().map(Ok),
                    )),
                    context(),
                    connection,
                )
                .await,
        )
        .await
    }
    async fn clean(&self) {
        common::within(async {
            loop {
                if self.node.ram_pool().stats().unwrap().outstanding == 0 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
    }
}
fn context() -> TransportContext {
    TransportContext {
        open_exporter: Some([7; 32]),
        ..Default::default()
    }
}

#[tokio::test]
async fn signed_generic_opening_checks_connection_before_reserving_and_cleans_incomplete_uploads() {
    let f = Fixture::new().await;
    let mut wrong = context();
    wrong.open_exporter = Some([8; 32]);
    assert!(
        f.work
            .upload_stream(
                Box::pin(futures::stream::iter(f.frames.clone().into_iter().map(Ok))),
                wrong,
                Cancellation::new()
            )
            .await
            .is_err()
    );
    assert_eq!(f.node.ram_pool().held(), 0);
    let mut reply = f
        .work
        .upload_stream(
            Box::pin(futures::stream::iter(
                std::iter::once(f.frames[0].clone()).map(Ok),
            )),
            context(),
            Cancellation::new(),
        )
        .await
        .unwrap();
    assert!(reply.next().await.unwrap().unwrap().missing);
    assert!(f.node.ram_pool().held() > 0);
    drop(reply);
    f.clean().await;
    assert_eq!(f.node.stats().unwrap().used, 0);
}

#[tokio::test]
async fn completed_unaccepted_content_is_released_on_connection_loss_or_deadline() {
    for expire in [false, true] {
        let f = Fixture::new().await;
        let connection = Cancellation::new();
        f.upload(connection.clone()).await.unwrap();
        assert!(f.node.ram_pool().held() > 0);
        if expire {
            f.clock.set(f.authorization.acceptance_deadline_ms);
        } else {
            connection.cancel();
        }
        f.clean().await;
        assert_eq!(f.node.stats().unwrap().used, 0);
    }
}

#[tokio::test]
async fn accepted_ram_content_ends_at_physical_completion_and_result_delivery_survives() {
    let f = Fixture::new().await;
    let connection = Cancellation::new();
    f.upload(connection.clone()).await.unwrap();
    let response = f.work.accept(&f.wire).await;
    assert!(
        matches!(
            response.outcome,
            Some(accept_work_response::Outcome::Accepted(_))
        ),
        "{response:?}"
    );
    common::within(f.backend.started.notified()).await;
    assert_eq!(
        f.node.ram_pool().held(),
        0,
        "staging moves into live job accounting"
    );
    connection.cancel();
    assert_eq!(f.backend.slots.available_permits(), 0);
    f.backend.finish.release();
    common::within(f.service.drain()).await.unwrap();
    let events: Vec<_> = f
        .work
        .stream(StreamResultRequest {
            route: Some(WorkRoute::grant(f.authorization.channel_id.0)),
            work_id: f.id.as_bytes().to_vec(),
            client_signature: vec![],
        })
        .collect()
        .await;
    assert!(
        events.iter().any(|event| matches!(
            event,
            Ok(WorkStreamEvent {
                outcome: Some(work_stream_event::Outcome::Terminal(_))
            })
        )),
        "{events:?}"
    );
    for path in common::all_files(f.root.path()) {
        let bytes = std::fs::read(path).unwrap();
        assert!(
            !bytes
                .windows(b"never-journal-this-body".len())
                .any(|window| window == b"never-journal-this-body")
        );
        assert!(
            !bytes
                .windows(b"private-grant-result".len())
                .any(|window| window == b"private-grant-result")
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_acceptance_response_finishes_ram_transfer_and_installs_execution() {
    let f = Fixture::new().await;
    f.upload(Cancellation::new()).await.unwrap();
    let job = common::pending_content(&f.service, ChannelId(f.authorization.channel_id.0), f.id);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let work = f.work.clone();
    let wire = f.wire.clone();
    let caller = tokio::spawn(
        common::GRANT_CONTENT_TRANSFER_PAUSE
            .scope((entered.clone(), release.clone()), async move {
                work.accept(&wire).await
            }),
    );
    common::within(entered.notified()).await;
    let (at_gate, gate_entered) = tokio::sync::oneshot::channel();
    let at_gate = Arc::new(std::sync::Mutex::new(Some(at_gate)));
    let (unblock, blocked) = std::sync::mpsc::channel();
    let blocked = Arc::new(std::sync::Mutex::new(blocked));
    let scope = Scope::Owner.bind(
        move || {
            let (at_gate, blocked) = (at_gate.clone(), blocked.clone());
            async move {
                Ok(move || {
                    if let Some(at_gate) = at_gate.lock().unwrap().take() {
                        let _ = at_gate.send(());
                    }
                    blocked.lock().unwrap().recv().map_err(|_| Error::Denied)?;
                    Ok(())
                })
            }
        },
        std::future::pending(),
    );
    let upper = job.store().clone();
    let blocker = tokio::spawn(async move {
        upper
            .set_pin(&scope, &PinName::new("gate".into()).unwrap(), None, None)
            .await
    });
    common::within(gate_entered).await.unwrap();
    release.notify_one();
    caller.abort();
    let _ = caller.await;
    unblock.send(()).unwrap();
    common::within(blocker).await.unwrap().unwrap();
    common::within(f.backend.started.notified()).await;
    assert_eq!(f.node.ram_pool().held(), 0);
    let retry = f.work.accept(&f.wire).await;
    assert!(matches!(
        retry.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ));
    f.backend.finish.release();
    common::within(f.service.drain()).await.unwrap();
    assert_eq!(f.backend.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn blocked_generic_upload_progress_retains_live_authority_at_the_carrier() {
    use hellas_channel::test_support::transport::{CarrierGate, transport_pair_with_server_gate};
    use hellas_rpc::services::content::ContentClientImpl;
    use std::sync::atomic::{AtomicUsize, Ordering};
    for expire in [false, true] {
        let f = Fixture::new().await;
        let gate = Arc::new(CarrierGate {
            remaining: AtomicUsize::new(0),
            sent: AtomicUsize::new(0),
            blocked: Default::default(),
            ready: Default::default(),
        });
        let (client, server) = transport_pair_with_server_gate(context(), gate.clone());
        let connection = Cancellation::new();
        let cancelled = connection.clone();
        let work = f.work.clone();
        let serving = tokio::spawn(async move {
            let inbound = server.accept().await.unwrap().unwrap();
            assert_eq!(inbound.method_id, Upload::METHOD_ID);
            let context = inbound.context.clone();
            hellas_rpc::call::dispatch_bidi_streaming::<MuxTransport, Upload, _, _, _>(
                inbound,
                |requests| async move {
                    work.upload_stream(Box::pin(requests), context, cancelled)
                        .await
                },
            )
            .await
        });
        let mut call = ContentClientImpl::new(client).upload().await.unwrap();
        call.send(f.frames[0].clone()).await.unwrap();
        common::within(gate.blocked.notified()).await;
        if expire {
            f.clock.set(f.authorization.acceptance_deadline_ms);
        } else {
            connection.cancel();
        }
        assert!(!matches!(common::within(call.next()).await, Some(Ok(_))));
        assert_eq!(gate.sent.load(Ordering::SeqCst), 0);
        let _ = common::within(serving).await.unwrap();
        f.clean().await;
    }
}

#[tokio::test]
async fn an_opening_on_another_connection_cannot_share_a_pending_upload_owner() {
    let f = Fixture::new().await;
    let connection_a = Cancellation::new();
    let mut a = f
        .work
        .upload_stream(
            Box::pin(futures::stream::iter(f.frames.clone().into_iter().map(Ok))),
            context(),
            connection_a.clone(),
        )
        .await
        .unwrap();
    a.next().await.unwrap().unwrap();
    let held = f.node.ram_pool().held();
    let mut frames_b = f.frames.clone();
    let Some(pb::upload_request::Part::Open(open)) = &mut frames_b[0].part else {
        panic!()
    };
    let opening = open.work.as_mut().unwrap();
    opening.binding_signature = common::principal(1)
        .1
        .sign_digest(hellas_channel::job::opening_digest(opening, &[8; 32]))
        .unwrap()
        .bytes()
        .to_vec();
    let context_b = TransportContext {
        open_exporter: Some([8; 32]),
        ..Default::default()
    };
    let connection_b = Cancellation::new();
    assert!(
        f.work
            .upload_stream(
                Box::pin(futures::stream::iter(frames_b.clone().into_iter().map(Ok))),
                context_b.clone(),
                connection_b.clone()
            )
            .await
            .is_err()
    );
    assert_eq!(f.node.ram_pool().held(), held);
    drop(a);
    f.clean().await;
    drive_upload(
        f.work
            .upload_stream(
                Box::pin(futures::stream::iter(frames_b.into_iter().map(Ok))),
                context_b,
                connection_b.clone(),
            )
            .await,
    )
    .await
    .unwrap();
    // The old connection's late monitor cannot remove the new generation.
    connection_a.cancel();
    let accepted = f.work.accept(&f.wire).await;
    assert!(
        matches!(
            accepted.outcome,
            Some(accept_work_response::Outcome::Accepted(_))
        ),
        "{accepted:?}"
    );
    common::within(f.backend.started.notified()).await;
    f.backend.finish.release();
    common::within(f.service.drain()).await.unwrap();
}

#[tokio::test]
async fn owner_content_authority_does_not_require_a_provider_service() {
    use hellas_auth::authority::{GrantId, UnixMillis};
    use hellas_authority::{content, node::NodeCoordinator};
    let root = tempfile::tempdir().unwrap();
    let (store, secret) = common::common_node::bootstrap_node_with_credential(
        root.path(),
        common::network(),
        None,
        UnixMillis(1000),
    )
    .await
    .unwrap();
    let node = NodeCoordinator::new(store, Arc::new(|| UnixMillis(1000)));
    assert!(node.provider().await.unwrap().is_none());
    let caller = common::session(&node, &secret).await;
    let (scope, _) = node
        .content_owner_for_caller(caller, GrantId([0; 16]), content::UPLOAD)
        .await
        .unwrap();
    let memory =
        hellas_store::content::MemoryStore::new(hellas_store::content::Reservations::ram(4096));
    let object = hellas_rpc::ContentRef::for_bytes(b"owner without provider");
    hellas_channel::content::upload_bytes(
        &memory,
        &scope,
        b"owner without provider",
        Some(hellas_channel::content::object_pin(object).unwrap()),
    )
    .await
    .unwrap();
    let pins = memory
        .pins(&Scope::Owner, "", Default::default())
        .await
        .unwrap();
    assert_eq!(pins.pins.len(), 1);
    assert_eq!(pins.pins[0].1.target.object(), object);
}

#[tokio::test]
async fn grant_root_completion_consults_the_policy_with_full_reference_and_requesting_scope() {
    use common::{actors::*, ids};
    use hellas_store::content::{Miss, MissDecision, OnMiss, ScopeKind, StoreStats};
    struct Recording(Arc<std::sync::Mutex<Vec<(hellas_rpc::ContentRef, ScopeKind)>>>);
    impl OnMiss for Recording {
        fn decide(&self, miss: &Miss, _: &StoreStats) -> MissDecision {
            self.0
                .lock()
                .unwrap()
                .push((miss.object, miss.scope.kind.clone()));
            MissDecision::Refuse
        }
    }
    let root = tempfile::tempdir().unwrap();
    let compute = common::compute::Compute;
    let node = common::Node::bootstrap(root.path())
        .with_allowance(compute.allowance(ids::ALLOWANCE, FRIEND))
        .with_grant(
            ids::FRIEND_GRANT,
            common::Rights::new(common::authority(), FRIEND)
                .allow(
                    hellas_authority::grant_service::WORK_EXECUTE,
                    hellas_authority::grant_service::allowance_resource(
                        common::authority(),
                        ids::ALLOWANCE,
                    ),
                )
                .valid_until(hellas_auth::authority::UnixMillis(100_000))
                .build(),
        )
        .build()
        .await;
    let proposal = compute.proposal(&node, FRIEND, ids::ALLOWANCE, 1);
    let content = node.content.clone();
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    content
        .set_on_miss(Arc::new(Recording(observed.clone())))
        .unwrap();
    let world = node.serve(Backend::default());
    let work = world.work(FRIEND, ids::FRIEND_GRANT).await;
    let (_, frames) = common::grant_upload_requests(
        &proposal.request(),
        &FRIEND.node_key(),
        common::network(),
        [7; 32],
    );
    let connection = Cancellation::new();
    drive_upload(
        work.upload_stream(
            Box::pin(futures::stream::iter(frames.into_iter().map(Ok))),
            context(),
            connection.clone(),
        )
        .await,
    )
    .await
    .unwrap();
    assert!(observed.lock().unwrap().iter().any(|(object,scope)| *object==proposal.authorization.input_content && matches!(scope,ScopeKind::Work {job,reservation,..} if job.id==proposal.work() && *reservation!=0)));
    connection.cancel();
    common::within(async {
        while content.ram_pool().held() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    world.service.drain().await.unwrap();
}
