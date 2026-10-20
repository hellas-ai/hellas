use super::*;
use crate::test_support::transport::{CarrierGate, transport_pair_with_server_gate};
use std::{future::Future, io, task::Poll, time::Duration};

pub(super) fn delivery_request(a: &GrantJobAuthorizationV1, id: Digest) -> DeliverResultRequest {
    DeliverResultRequest {
        route: Some(WorkRoute::grant(a.channel_id.0)),
        work_id: id.as_bytes().to_vec(),
        client_signature: Vec::new(),
    }
}

async fn revise_and_restore(
    service: &GrantService,
    secret: &hellas_auth::authority::CredentialSecret,
    remove_right: bool,
) {
    use hellas_auth::authority::{AdministrationCommand, GrantCommand, OperationId, Permission};
    let admin = crate::test_support::session(&service.node(), secret).await;
    // Keep the writer across both distinct commits. Delivery can never observe
    // the intermediate state by polling; the writer must invalidate it itself.
    service
        .administer(async |store, now| {
            let grant = store
                .state()
                .authority()
                .grant(common_node::EXECUTION_AUTHORIZATION)
                .unwrap();
            let original = grant.spec().clone();
            let mut interim = original.clone();
            if remove_right {
                interim.permissions = [Permission {
                    operation: OperationId::new(hellas_work::node::HOST_STATUS).unwrap(),
                    resource: hellas_work::node::host_resource(interim.authority),
                }]
                .into();
            } else {
                interim.expires.0 -= 1;
            }
            for spec in [interim, original] {
                store
                    .administer_authority(
                        &admin,
                        AdministrationCommand::Grant(GrantCommand::Revise {
                            authorization: GrantId([0; 16]),
                            id: common_node::EXECUTION_AUTHORIZATION,
                            expected: store
                                .state()
                                .authority()
                                .grant(common_node::EXECUTION_AUTHORIZATION)
                                .unwrap()
                                .revision(),
                            spec,
                        }),
                        now,
                    )
                    .await?;
            }
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn committed_loss_cannot_revive_a_native_stream_or_an_unpolled_carrier_binding() {
    for remove_right in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (store, secret) = setup_with_credential(dir.path()).await;
        let request = request(&store, 1);
        let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
        let backend = Backend {
            reply: Reply::text("private-grant-result", 2),
            ..Backend::default()
        };
        let (service, work, _) = service(store, backend.clone(), &secret).await;
        let id = accepted_id(work.accept(&request).await);
        within(backend.started.notified()).await;
        backend.finish.release();
        within(service.drain()).await.unwrap();
        let request = delivery_request(&a, id);
        let mut stream = work.stream(request.clone());
        assert!(matches!(
            stream.next().await.unwrap().unwrap().outcome,
            Some(work_stream_event::Outcome::Prefix(_))
        ));
        let binding = service.bind_delivery(&work.access, &request).await.unwrap();
        let writer = service.delivery_authority(binding.clone());
        revise_and_restore(&service, &secret, remove_right).await;
        service
            .administer(async |store, now| {
                work.access.authorize(store, a.grant_id, now).unwrap();
                assert_eq!(binding.cancellation().is_cancelled(), remove_right);
                Ok(())
            })
            .await
            .unwrap();
        let mut handed_off = false;
        let result = futures::future::poll_fn(|cx| {
            writer.poll_write(cx, &mut |_| {
                handed_off = true;
                Poll::Ready(Ok(7))
            })
        })
        .await;
        assert_eq!(handed_off, !remove_right);
        let event = stream.next().await.unwrap().unwrap();
        if remove_right {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            let Some(work_stream_event::Outcome::Refused(refusal)) = event.outcome else {
                panic!("stale generation delivered");
            };
            assert_eq!(
                refusal.grant.unwrap().code,
                GrantRefusalCode::Revoked as i32
            );
            assert!(stream.next().await.is_none());
        } else {
            assert_eq!(result.unwrap(), 7);
            assert!(matches!(
                event.outcome,
                Some(work_stream_event::Outcome::Prefix(_))
            ));
        }
    }
}

#[tokio::test]
async fn response_registry_is_bounded_and_does_not_retain_abandoned_responses() {
    let dir = tempfile::tempdir().unwrap();
    let (store, secret) = setup_with_credential(dir.path()).await;
    let request = request(&store, 1);
    let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
    let backend = Backend::default();
    let clock = TestClock::default();
    let service = GrantService::new(
        store,
        Arc::new(principal(2).1),
        backend.clone(),
        vec![],
        clock.source(),
    )
    .unwrap();
    let (work, _) = common_node::execution(&service, &secret, &principal(1).1, a.grant_id).await;
    let id = accepted_id(work.accept(&request).await);
    within(backend.started.notified()).await;
    backend.finish.release();
    within(service.drain()).await.unwrap();
    let node = service.node();
    let admin = crate::test_support::session(&node, &secret).await;
    let mut scope = snapshot(&service)
        .await
        .authority()
        .grant(common_node::EXECUTION_AUTHORIZATION)
        .unwrap()
        .spec()
        .clone();
    scope.expires = UnixMillis(1100);
    let (_, short) = crate::test_support::credentials::issue_one(
        &node,
        &admin,
        GrantId([0; 16]),
        scope,
        crate::test_support::holder(principal(1).0),
    )
    .await
    .unwrap();
    let expiring = service.for_caller(
        node.authenticate_session(&short, crate::node::SessionKey::Node(&principal(1).1))
            .await
            .unwrap(),
        common_node::EXECUTION_AUTHORIZATION,
    );
    let request = delivery_request(&a, id);
    let mut responses = Vec::new();
    for _ in 0..1024 {
        responses.push(
            service
                .bind_delivery(&expiring.access, &request)
                .await
                .unwrap(),
        );
    }
    let refused = match service.bind_delivery(&work.access, &request).await {
        Ok(_) => panic!("response registry exceeded its bound"),
        Err(refused) => refused,
    };
    assert_eq!(
        refused.grant.unwrap().code,
        GrantRefusalCode::StateCapacity as i32
    );
    // No response poll or authority mutation occurs as these credentials expire.
    // A fresh valid request must reclaim their registry slots on admission.
    clock.set(UnixMillis(1100));
    let replacement = service.bind_delivery(&work.access, &request).await.unwrap();
    assert!(
        responses
            .iter()
            .all(|response| response.cancellation().is_cancelled())
    );
    drop(replacement);
    let abandoned = Arc::downgrade(responses.last().unwrap());
    drop(responses);
    assert!(abandoned.upgrade().is_none());
    service.bind_delivery(&work.access, &request).await.unwrap();
}

#[tokio::test]
async fn extending_expired_authority_does_not_revive_an_unpolled_response() {
    for completed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (store, secret) = setup_with_credential(dir.path()).await;
        let request = request(&store, 1);
        let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
        let backend = Backend::default();
        let clock = TestClock::default();
        let service = GrantService::new(
            store,
            Arc::new(principal(2).1),
            backend.clone(),
            vec![],
            clock.source(),
        )
        .unwrap();
        let (work, _) =
            common_node::execution(&service, &secret, &principal(1).1, a.grant_id).await;
        set_execution_expiry(&service, &secret, UnixMillis(1100)).await;
        let id = accepted_id(work.accept(&request).await);
        within(backend.started.notified()).await;
        if completed {
            backend.finish.release();
            within(service.drain()).await.unwrap();
        }
        let binding = service
            .bind_delivery(&work.access, &delivery_request(&a, id))
            .await
            .unwrap();
        let writer = service.delivery_authority(binding.clone());
        clock.set(UnixMillis(1100));
        set_execution_expiry(&service, &secret, UnixMillis(2200)).await;
        assert!(
            binding.cancellation().is_cancelled(),
            "expiry must be observed before replacing the old state"
        );
        let error = futures::future::poll_fn(|cx| {
            writer.poll_write(cx, &mut |_| panic!("expired response cannot revive"))
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        service
            .bind_delivery(&work.access, &delivery_request(&a, id))
            .await
            .unwrap();
        if !completed {
            tokio::time::timeout(WAIT, backend.cancelled.notified())
                .await
                .expect("the expired execution cannot revive after extension");
            assert_eq!(backend.slots.available_permits(), 0);
            backend.finish.release();
            within(service.drain()).await.unwrap();
            assert_eq!(backend.slots.available_permits(), 1);
        }
    }
}

#[tokio::test]
async fn delivery_write_rechecks_under_writer_and_releases_it_on_backpressure() {
    for target in [AccessTarget::Credential, AccessTarget::Grant] {
        let dir = tempfile::tempdir().unwrap();
        let (store, secret) = setup_with_credential(dir.path()).await;
        let request = request(&store, 1);
        let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
        let backend = Backend::default();
        let (service, work, credential) = service(store, backend.clone(), &secret).await;
        let id = accepted_id(work.accept(&request).await);
        within(backend.started.notified()).await;
        let delivery = service
            .bind_delivery(&work.access, &delivery_request(&a, id))
            .await
            .unwrap();
        let authority = service.delivery_authority(delivery);
        let attempted = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let waiting = tokio::spawn({
            let service = service.clone();
            let authority = authority.clone();
            let attempted = attempted.clone();
            let calls = calls.clone();
            async move {
                futures::future::poll_fn(|cx| {
                    authority.poll_write(cx, &mut |cx| {
                        let mut writer = Box::pin(service.node.store.lock());
                        assert!(
                            writer.as_mut().poll(cx).is_pending(),
                            "handoff owns the policy writer"
                        );
                        calls.fetch_add(1, Ordering::SeqCst);
                        attempted.notify_one();
                        Poll::Pending
                    })
                })
                .await
            }
        });
        attempted.notified().await;
        // This must commit while the carrier is blocked, and wake that carrier
        // without another producer event or transport-ready notification.
        tokio::time::timeout(
            Duration::from_secs(3),
            revoke_access(&service, &secret, &credential, target),
        )
        .await
        .unwrap();
        let count = calls.load(Ordering::SeqCst);
        let error = tokio::time::timeout(WAIT, waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls.load(Ordering::SeqCst), count);
        let error = futures::future::poll_fn(|cx| {
            authority.poll_write(cx, &mut |_| panic!("denied response cannot revive"))
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        backend.finish.release();
        within(service.drain()).await.unwrap();
    }
}

#[tokio::test]
async fn rpc_revocation_blocks_encoded_unary_stream_body_and_end_at_the_carrier() {
    use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
    for target in [AccessTarget::Credential, AccessTarget::Grant] {
        for (streaming, allowed, recovered) in
            [(false, 0, false), (true, 1, false), (true, 0, true)]
        {
            tokio::time::timeout(Duration::from_secs(30), async {
                let dir = tempfile::tempdir().unwrap();
                let (store, secret) = setup_with_credential(dir.path()).await;
                let request = request(&store, 1);
                let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
                let backend = Backend::default();
                let (service, work, credential) = service(store, backend.clone(), &secret).await;
                let id = accepted_id(work.accept(&request).await);
                within(backend.started.notified()).await;
                backend.finish.release();
                within(service.drain()).await.unwrap();
                let (service, work) = if recovered {
                    drop(work);
                    drop(service);
                    let store = NodeStore::open(
                        dir.path(),
                        network(),
                        Some(crate::test_support::software_enrollment(2, [2; 32])),
                        UnixMillis(1000),
                    )
                    .await
                    .unwrap();
                    let service = GrantService::new(
                        store,
                        Arc::new(principal(2).1),
                        backend.clone(),
                        vec![],
                        Arc::new(|| UnixMillis(1000)),
                    )
                    .unwrap();
                    let caller = service
                        .node()
                        .authenticate_session(
                            &credential,
                            crate::node::SessionKey::Node(&principal(1).1),
                        )
                        .await
                        .unwrap();
                    let work = service.for_caller(caller, common_node::EXECUTION_AUTHORIZATION);
                    let mut stream = work.stream(delivery_request(&a, id));
                    let Some(work_stream_event::Outcome::Refused(refusal)) =
                        stream.next().await.unwrap().unwrap().outcome
                    else {
                        panic!("recovered results have durable metadata but no RAM body");
                    };
                    assert!(refusal.grant.unwrap().terminal.is_some());
                    (service, work)
                } else {
                    (service, work)
                };
                let gate = Arc::new(CarrierGate {
                    remaining: AtomicUsize::new(allowed),
                    sent: AtomicUsize::new(0),
                    blocked: Notify::new(),
                    ready: Default::default(),
                });
                let (client, server) = transport_pair_with_server_gate(context(), gate.clone());
                let serving = tokio::spawn(async move {
                    let inbound = server.accept().await.unwrap().unwrap();
                    Dispatcher::<MuxTransport>::dispatch(&WorkServer(work), inbound).await
                });
                let reading = tokio::spawn(async move {
                    let rpc = WorkClientImpl::new(client);
                    let request = delivery_request(&a, id);
                    if streaming {
                        let mut stream = rpc.stream_result(request).await?;
                        while let Some(event) = stream.next().await {
                            event?;
                        }
                        stream.finish().map(|_| ())
                    } else {
                        rpc.deliver_result(request).await.map(|_| ())
                    }
                });
                gate.blocked.notified().await;
                assert_eq!(gate.sent.load(Ordering::SeqCst), allowed);
                revoke_access(&service, &secret, &credential, target).await;
                assert_err!(within(reading).await.unwrap(),
                    error if error.code == hellas_wire::WireCode::Internal);
                let _ = serving.await.unwrap();
                assert_eq!(
                    gate.sent.load(Ordering::SeqCst),
                    allowed,
                    "revocation cannot release another frame"
                );
            })
            .await
            .unwrap();
        }
    }
}
