use super::*;
use crate::{grant_service::GrantService, test_support as common};
use futures::StreamExt;
use hellas_auth::authority::*;
use hellas_channel::model::work::PrivateRecord;
use hellas_channel::test_support::{
    backend::Backend,
    transport::{CarrierGate, transport_pair_with_server_gate},
};
use hellas_rpc::{
    ContentRef,
    pb::content as pb,
    services::content::{ContentClientImpl, ContentServer},
};
use hellas_store::content::{
    ContentService, ContentStore, MemoryStore, Path, PinPolicy, PinTarget, PinValue, Reservations,
};
use hellas_wire::{Dispatcher, StreamTransport, TransportContext, mux::MuxTransport};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Fixture {
    _directory: tempfile::TempDir,
    service: GrantService,
    backend: Backend,
    clock: common::TestClock,
    admin: AuthenticatedCaller,
    secret: CredentialSecret,
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let (store, secret) = common::setup_with_credential(directory.path()).await;
        let clock = common::TestClock::default();
        let backend = Backend::default();
        let service = GrantService::new(
            store,
            Arc::new(common::principal(2).1),
            backend.clone(),
            vec![],
            clock.source(),
            crate::test_support::content_store(directory.path()).await,
        )
        .unwrap();
        let admin = common::session(&service.node(), &secret).await;
        Self {
            _directory: directory,
            service,
            backend,
            clock,
            admin,
            secret,
        }
    }
    async fn reader(&self, pin: &PinName, expires: UnixMillis) -> GrantWork {
        let node = self.service.node();
        let authority = node
            .status(&self.admin, GrantId([0; 16]))
            .await
            .unwrap()
            .authority;
        let scope = GrantSpec {
            authority,
            subject: common::principal(1).0,
            permissions: [Permission {
                operation: OperationId::new(READ).unwrap(),
                resource: pin_resource(authority, pin),
            }]
            .into(),
            not_before: UnixMillis(1000),
            expires,
            delegation_depth: 0,
            issuance: None,
        };
        let [secret] = common::credentials::issue(
            common::credentials::Issuer::Node(&node),
            &self.admin,
            GrantId([0; 16]),
            Some(GrantId([9; 16])),
            scope,
        )
        .await;
        self.service
            .for_caller(common::session(&node, &secret).await, GrantId([9; 16]))
    }
    async fn revoke(&self) {
        let node = self.service.node();
        let expected = {
            let (store, _) = node.lock().await.unwrap();
            store
                .state()
                .authority()
                .grant(GrantId([9; 16]))
                .unwrap()
                .revision()
        };
        node.grant(
            &self.admin,
            GrantCommand::Revoke {
                authorization: GrantId([0; 16]),
                id: GrantId([9; 16]),
                expected,
            },
        )
        .await
        .unwrap();
    }
}
fn name(s: &str) -> PinName {
    PinName::new(s.into()).unwrap()
}
fn at(s: &str) -> Path {
    Path::new(name(s), String::new()).unwrap()
}
async fn put(store: &MemoryStore, key: &str, bytes: &[u8], policy: PinPolicy) -> PinValue {
    let object = ContentRef::for_bytes(bytes);
    let mut upload = store
        .upload(
            &Scope::Owner,
            object,
            Some(PinTarget {
                name: name(key),
                policy,
            }),
        )
        .await
        .unwrap();
    if !upload.complete() {
        let chunks = hellas_xet::chunk(bytes);
        upload.declare(&chunks, true).await.unwrap();
        let mut offset = 0;
        for chunk in chunks {
            let end = offset + chunk.data_len as usize;
            upload.accept_chunk(&bytes[offset..end]).await.unwrap();
            offset = end;
        }
    }
    store
        .pins(&Scope::Owner, key, Default::default())
        .await
        .unwrap()
        .pins
        .into_iter()
        .find(|(pin, _)| pin.as_str() == key)
        .unwrap()
        .1
}

#[tokio::test]
async fn exact_pin_grant_follows_cas_and_recreation_but_respects_current_policy() {
    let f = Fixture::new().await;
    let store = MemoryStore::new(Reservations::ram(1 << 20));
    let a = put(&store, "selected", b"first", PinPolicy::Granted).await;
    let b = put(&store, "another", b"second", PinPolicy::Granted).await;
    let reader = f.reader(&name("selected"), UnixMillis(2000)).await;
    let (scope, _) = reader.content_read(name("selected")).await.unwrap();
    assert!(store.stat(&scope, &at("another")).await.unwrap().is_none());
    assert_eq!(
        store
            .pins(&scope, "", Default::default())
            .await
            .unwrap()
            .pins
            .len(),
        1
    );
    store
        .set_pin(&Scope::Owner, &name("selected"), Some(&a), Some(b.clone()))
        .await
        .unwrap();
    assert_eq!(
        store
            .stat(&scope, &at("selected"))
            .await
            .unwrap()
            .unwrap()
            .target,
        b.target
    );
    let owner = PinValue {
        policy: PinPolicy::Owner,
        ..b.clone()
    };
    store
        .set_pin(
            &Scope::Owner,
            &name("selected"),
            Some(&b),
            Some(owner.clone()),
        )
        .await
        .unwrap();
    assert!(store.stat(&scope, &at("selected")).await.unwrap().is_none());
    store
        .set_pin(&Scope::Owner, &name("selected"), Some(&owner), None)
        .await
        .unwrap();
    assert!(store.stat(&scope, &at("selected")).await.unwrap().is_none());
    store
        .set_pin(&Scope::Owner, &name("selected"), None, Some(a))
        .await
        .unwrap();
    assert!(store.stat(&scope, &at("selected")).await.unwrap().is_some());
    assert!(store.collect(&scope).await.is_err());
    assert!(
        store
            .upload(&scope, ContentRef::for_bytes(b"x"), None)
            .await
            .is_err()
    );
    assert!(
        reader
            .bind_content(Scope::Owner, ACQUIRE, Cancellation::new(), None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn revocation_between_read_chunks_checks_the_existing_authority() {
    let f = Fixture::new().await;
    let store = MemoryStore::new(Reservations::ram((hellas_xet::MAX_CHUNK_SIZE * 3) as u64));
    let data = vec![17; hellas_xet::MAX_CHUNK_SIZE * 2];
    put(&store, "selected", &data, PinPolicy::Granted).await;
    let reader = f.reader(&name("selected"), UnixMillis(2000)).await;
    let (scope, _) = reader.content_read(name("selected")).await.unwrap();
    let mut read = store
        .read(&scope, &at("selected"), 0..data.len() as u64)
        .await
        .unwrap();
    assert_eq!(
        read.bytes.next().await.unwrap().unwrap().as_ref(),
        &data[..hellas_xet::MAX_CHUNK_SIZE]
    );
    f.revoke().await;
    assert!(read.bytes.next().await.unwrap().is_err());
    assert!(store.stat(&scope, &at("selected")).await.is_err());
}

#[tokio::test]
async fn cancelling_a_content_monitor_releases_its_queued_authority_writer() {
    let f = Fixture::new().await;
    let reader = f.reader(&name("selected"), UnixMillis(2000)).await;
    let (scope, carrier) = reader.content_read(name("selected")).await.unwrap();
    let node = f.service.node();
    let held = node.writer().await.unwrap();
    let mut ended = Box::pin(scope.ended());
    assert!(futures::poll!(ended.as_mut()).is_pending());
    drop(ended);
    drop(held);
    assert_eq!(
        common::within(futures::future::poll_fn(|cx| {
            carrier.poll_write(cx, &mut |_| std::task::Poll::Ready(Ok(1)))
        }))
        .await
        .unwrap(),
        1
    );
    f.revoke().await;
    common::within(scope.ended()).await;
    assert!(
        futures::future::poll_fn(|cx| {
            carrier.poll_write(cx, &mut |_| std::task::Poll::Ready(Ok(1)))
        })
        .await
        .is_err()
    );
}

#[tokio::test]
async fn owner_upload_rechecks_after_declaration_and_rejects_revoked_payload() {
    let f = Fixture::new().await;
    let node = f.service.node();
    let authority = node
        .status(&f.admin, GrantId([0; 16]))
        .await
        .unwrap()
        .authority;
    let spec = GrantSpec {
        authority,
        subject: f.admin.subject(),
        permissions: [Operation::named(UPLOAD)
            .unwrap()
            .permission(authority, None)
            .unwrap()]
        .into(),
        not_before: UnixMillis(1000),
        expires: UnixMillis(2000),
        delegation_depth: 0,
        issuance: None,
    };
    let [secret] = common::credentials::issue(
        common::credentials::Issuer::Node(&node),
        &f.admin,
        GrantId([0; 16]),
        None,
        spec,
    )
    .await;
    let owner = f
        .service
        .for_caller(common::session(&node, &secret).await, GrantId([0; 16]));
    let (scope, _) = owner
        .bind_content(Scope::Owner, UPLOAD, Cancellation::new(), None)
        .await
        .unwrap();
    let pool = Reservations::ram(100);
    let store = MemoryStore::new(pool.clone());
    let bytes = b"private owner upload";
    let mut upload = store
        .upload(
            &scope,
            ContentRef::for_bytes(bytes),
            Some(PinTarget {
                name: name("owner"),
                policy: PinPolicy::Owner,
            }),
        )
        .await
        .unwrap();
    upload
        .declare(&hellas_xet::chunk(bytes), true)
        .await
        .unwrap();
    node.revoke_credential(&f.admin, GrantId([0; 16]), secret.id(), Revision(1))
        .await
        .unwrap();
    assert!(upload.accept_chunk(bytes).await.is_err());
    assert!(!upload.complete());
    drop(upload);
    assert!(
        store
            .stat(&Scope::Owner, &at("owner"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(pool.stats().unwrap().outstanding, 0);
}

#[tokio::test]
async fn blocked_rpc_carrier_stops_on_revocation_or_expiry_without_another_write() {
    for expire in [false, true] {
        let f = Fixture::new().await;
        let store = Arc::new(MemoryStore::new(Reservations::ram(1 << 20)));
        put(&store, "selected", b"private metadata", PinPolicy::Granted).await;
        let reader = f.reader(&name("selected"), UnixMillis(1050)).await;
        let (scope, writer) = reader.content_read(name("selected")).await.unwrap();
        let gate = Arc::new(CarrierGate {
            remaining: AtomicUsize::new(0),
            sent: AtomicUsize::new(0),
            blocked: Default::default(),
            ready: Default::default(),
        });
        let (client, server) =
            transport_pair_with_server_gate(TransportContext::default(), gate.clone());
        let service = ContentService::new(store, scope).with_write_authority(writer);
        let serving = tokio::spawn(async move {
            while let Ok(Some(inbound)) = server.accept().await {
                let service = service.clone();
                tokio::spawn(async move {
                    let _ = <ContentServer<ContentService<MemoryStore>> as Dispatcher<
                        MuxTransport,
                    >>::dispatch(&ContentServer(service), inbound)
                    .await;
                });
            }
        });
        let request = tokio::spawn(async move {
            ContentClientImpl::new(client)
                .stat(pb::StatRequest {
                    at: Some(pb::Path {
                        pin: "selected".into(),
                        path: String::new(),
                    }),
                })
                .await
        });
        common::within(gate.blocked.notified()).await;
        if expire {
            f.clock.set(UnixMillis(1050));
        } else {
            f.revoke().await;
        }
        assert!(common::within(request).await.unwrap().is_err());
        assert_eq!(gate.sent.load(Ordering::SeqCst), 0);
        serving.abort();
    }
}

#[tokio::test]
async fn idle_work_upload_ends_on_its_proposal_cancellation_or_deadline() {
    for expire in [false, true] {
        let f = Fixture::new().await;
        let node = f.service.node();
        let authorization = {
            let (store, _) = node.lock().await.unwrap();
            common::proposal(&store, 1).0
        };
        let (work, _) = common::common_node::execution(
            &f.service,
            &f.secret,
            &common::principal(1).1,
            authorization.grant_id,
        )
        .await;
        let store = Arc::new(MemoryStore::new(Reservations::ram(1 << 20)));
        let object = ContentRef::for_bytes(b"idle unaccepted bytes");
        let job = hellas_store::content::JobId {
            channel: authorization.channel_id.0,
            id: crate::model::grant::grant_work_id(common::network(), &authorization),
        };
        let local = store
            .open_work(job, vec![object], object.bytes())
            .await
            .unwrap();
        let cancellation = Cancellation::new();
        let (scope, writer) = work
            .bind_content(
                local.clone(),
                crate::grant_service::WORK_EXECUTE,
                cancellation.clone(),
                Some(authorization),
            )
            .await
            .unwrap();
        let service = ContentService::new(store.clone(), scope).with_write_authority(writer);
        let (client, server) = common::transport::transport_pair();
        let serving = tokio::spawn(async move {
            let inbound = server.accept().await.unwrap().unwrap();
            let _ =
                <ContentServer<ContentService<MemoryStore>> as Dispatcher<MuxTransport>>::dispatch(
                    &ContentServer(service),
                    inbound,
                )
                .await;
        });
        let mut call = ContentClientImpl::new(client).upload().await.unwrap();
        call.send(pb::UploadRequest {
            part: Some(pb::upload_request::Part::Open(pb::UploadOpen {
                object: Some(pb::ContentRef {
                    id: object.id().as_bytes().to_vec(),
                    bytes: object.bytes(),
                }),
                pin: None,
                work: None,
            })),
        })
        .await
        .unwrap();
        assert!(!common::within(call.next()).await.unwrap().unwrap().complete);
        if expire {
            f.clock.set(authorization.acceptance_deadline_ms);
        } else {
            cancellation.cancel();
        }
        assert!(!matches!(common::within(call.next()).await, Some(Ok(_))));
        assert!(call.finish().is_err());
        common::within(serving).await.unwrap();
        store.end_work(&local).await.unwrap();
    }
}

#[tokio::test]
async fn idle_watch_ends_on_revocation_without_a_pin_event() {
    let f = Fixture::new().await;
    let store = Arc::new(MemoryStore::new(Reservations::ram(1 << 20)));
    put(&store, "selected", b"held bytes", PinPolicy::Granted).await;
    let reader = f.reader(&name("selected"), UnixMillis(2000)).await;
    let (scope, writer) = reader.content_read(name("selected")).await.unwrap();
    let cursor = store
        .pins(&scope, "", Default::default())
        .await
        .unwrap()
        .cursor;
    let service = ContentService::new(store, scope).with_write_authority(writer);
    let (client, server) = common::transport::transport_pair();
    let serving = tokio::spawn(async move {
        let inbound = server.accept().await.unwrap().unwrap();
        let _ = <ContentServer<ContentService<MemoryStore>> as Dispatcher<MuxTransport>>::dispatch(
            &ContentServer(service),
            inbound,
        )
        .await;
    });
    let mut call = ContentClientImpl::new(client)
        .watch_pins(pb::WatchPinsRequest {
            prefix: String::new(),
            from: Some(pb::Cursor {
                offset: 0,
                object: None,
                generation: cursor.generation,
                after: String::new(),
            }),
        })
        .await
        .unwrap();
    assert!(futures::poll!(call.next()).is_pending());
    f.revoke().await;
    assert!(!matches!(common::within(call.next()).await, Some(Ok(_))));
    assert!(call.finish().is_err());
    common::within(serving).await.unwrap();
}

#[derive(Clone, Default)]
struct SourceGate {
    open: Arc<std::sync::atomic::AtomicBool>,
    blocked: Arc<tokio::sync::Notify>,
    ready: Arc<futures::task::AtomicWaker>,
}
impl hellas_wire::WriteAuthorization for SourceGate {
    fn poll_write(
        &mut self,
        cx: &mut std::task::Context<'_>,
        write: &mut dyn FnMut(
            &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<usize>>,
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.ready.register(cx.waker());
        if self.open.load(Ordering::SeqCst) {
            write(cx)
        } else {
            self.blocked.notify_one();
            std::task::Poll::Pending
        }
    }
}
#[tokio::test]
async fn revoked_owner_cannot_publish_an_acquisition_that_finishes_after_revocation() {
    use hellas_rpc::services::content::Content;
    use hellas_store::content::{DiskStore, IndexMode, Source};
    use hellas_wire::ServiceMarker;
    let f = Fixture::new().await;
    let owner = f.service.for_caller(
        common::session(&f.service.node(), &f.secret).await,
        GrantId([0; 16]),
    );
    let (scope, _) = owner
        .bind_content(Scope::Owner, ACQUIRE, Cancellation::new(), None)
        .await
        .unwrap();
    let source = Arc::new(MemoryStore::new(Reservations::ram(1 << 20)));
    let value = put(
        &source,
        "source",
        b"download finishing after revocation",
        PinPolicy::Public,
    )
    .await;
    let server = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .relay_mode(iroh::RelayMode::Disabled)
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .alpns(vec![Content::ALPN.as_bytes().to_vec()])
        .bind()
        .await
        .unwrap();
    let gate = SourceGate::default();
    let endpoint = server.clone();
    let outgoing = gate.clone();
    let serving = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let source = source.clone();
            let outgoing = outgoing.clone();
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let transport = hellas_wire::iroh::IrohTransport::new(connection);
                while let Ok(Some(inbound)) = transport.accept().await {
                    let service = ContentService::new(source.clone(), Scope::Public)
                        .with_write_authority(hellas_wire::WriteAuthority::new(outgoing.clone()));
                    tokio::spawn(async move {
                        let _ = <ContentServer<ContentService<MemoryStore>> as Dispatcher<
                            hellas_wire::iroh::IrohTransport,
                        >>::dispatch(
                            &ContentServer(service), inbound
                        )
                        .await;
                    });
                }
            });
        }
    });
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let peers =
        hellas_wire::iroh::Pool::for_service::<Content>(endpoint.clone(), Default::default());
    peers.connection(server.addr()).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = DiskStore::open(
        directory.path().into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
        Default::default(),
    )
    .await
    .unwrap()
    .with_peers(peers);
    store.finish_recovery().await.unwrap();
    let acquiring = store.clone();
    let source_node = *server.id().as_bytes();
    let task = tokio::spawn(async move {
        acquiring
            .acquire(
                &scope,
                Source::Peer {
                    node: source_node,
                    at: at("source"),
                },
                Some(value.target.object()),
                PinTarget {
                    name: name("acquired"),
                    policy: PinPolicy::Owner,
                },
            )
            .await
    });
    common::within(gate.blocked.notified()).await;
    let node = f.service.node();
    let revision = {
        let (store, _) = node.lock().await.unwrap();
        store
            .state()
            .authority()
            .credential(f.secret.id())
            .unwrap()
            .revision()
    };
    // This must complete while the network is blocked: staging holds no writer.
    common::within(node.revoke_credential(&f.admin, GrantId([0; 16]), f.secret.id(), revision))
        .await
        .unwrap();
    gate.open.store(true, Ordering::SeqCst);
    gate.ready.wake();
    assert!(common::within(task).await.unwrap().is_err());
    assert!(
        store
            .stat(&Scope::Owner, &at("acquired"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.stats().unwrap().used, 0);
    assert_eq!(store.stats().unwrap().outstanding, 0);
    store.close().await;
    endpoint.close().await;
    server.close().await;
    serving.abort();
}

#[tokio::test]
async fn accepted_work_reads_past_the_proposal_deadline_and_stops_at_terminal() {
    use hellas_rpc::pb::work::{AcceptWorkRequest, WorkRoute, accept_work_response};
    let f = Fixture::new().await;
    let node = f.service.node();
    let (authorization, signature, input) = {
        let (store, _) = node.lock().await.unwrap();
        common::proposal(&store, 1)
    };
    let (work, _) = common::common_node::execution(
        &f.service,
        &f.secret,
        &common::principal(1).1,
        authorization.grant_id,
    )
    .await;
    let store = MemoryStore::new(Reservations::ram(1 << 20));
    let input_bytes = input.canonical_bytes().unwrap();
    let value = put(&store, "input", &input_bytes, PinPolicy::Jobs).await;
    assert_eq!(value.target.object(), authorization.input_content);
    let local = store
        .open_work(
            hellas_store::content::JobId {
                channel: authorization.channel_id.0,
                id: crate::model::grant::grant_work_id(common::network(), &authorization),
            },
            vec![authorization.input_content],
            authorization.input_content.bytes(),
        )
        .await
        .unwrap();
    let (scope, _) = work
        .bind_content(
            local.clone(),
            crate::grant_service::WORK_EXECUTE,
            Cancellation::new(),
            Some(authorization),
        )
        .await
        .unwrap();
    let accepted = common::accept_grant(
        &work,
        &AcceptWorkRequest {
            route: Some(WorkRoute::grant(authorization.channel_id.0)),
            authorization: authorization.encode(),
            client_signature: signature.bytes().to_vec(),
            prepared_input: input_bytes.clone(),
        },
        &common::principal(1).1,
    )
    .await;
    assert!(matches!(
        accepted.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ));
    common::within(f.backend.started.notified()).await;
    f.clock
        .set(UnixMillis(authorization.acceptance_deadline_ms.0 + 1));
    assert!(store.stat(&scope, &at("input")).await.unwrap().is_some());
    let mut read = store
        .read(&scope, &at("input"), 0..input_bytes.len() as u64)
        .await
        .unwrap();
    assert_eq!(
        read.bytes.next().await.unwrap().unwrap().as_ref(),
        input_bytes
    );
    f.backend.finish.release();
    common::within(f.service.drain()).await.unwrap();
    assert!(store.stat(&scope, &at("input")).await.is_err());
    store.end_work(&local).await.unwrap();
}
