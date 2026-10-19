use super::*;

#[tokio::test]
async fn authority_expiry_wakes_delivery_and_rejects_buffered_output() {
    for expires in [AccessTarget::Credential, AccessTarget::Grant] {
        for (prefixes, completed) in [(1, false), (2, false), (1, true), (2, true)] {
            let dir = tempfile::tempdir().unwrap();
            let (mut store, secret) = setup_with_credential(dir.path()).await;
            let mut def = store.state().grant(GrantId([1; 16])).unwrap().clone();
            def.revision.0 += 1;
            def.policies[0].revision.0 += 1;
            store
                .configure_resource(def.policies[0].clone(), UnixMillis(1000))
                .await
                .unwrap();
            store.define(def, UnixMillis(1000)).await.unwrap();
            let request = request(&store, 1);
            let auth = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
            let backend = Backend {
                reply: Reply::text("private-grant-result", prefixes),
                ..Backend::default()
            };
            let clock = TestClock::default();

            let service = GrantService::new(
                store,
                Arc::new(principal(2).1),
                backend.clone(),
                vec![],
                clock.source(),
            )
            .unwrap();
            let (work_service, _) =
                common_node::execution(&service, &secret, &principal(1).1, GrantId([1; 16])).await;
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
            let work_service = match expires {
                AccessTarget::Credential => {
                    let (_, credential) = node
                        .issue_credential(
                            &admin,
                            GrantId([0; 16]),
                            scope,
                            crate::test_support::holder(principal(1).0),
                        )
                        .await
                        .unwrap();
                    service.for_caller(
                        node.authenticate_session(
                            &credential,
                            crate::node::SessionKey::Node(&principal(1).1),
                        )
                        .await
                        .unwrap(),
                        common_node::EXECUTION_AUTHORIZATION,
                    )
                }
                AccessTarget::Grant => {
                    node.grant(
                        &admin,
                        hellas_auth::authority::GrantCommand::Revise {
                            authorization: GrantId([0; 16]),
                            id: common_node::EXECUTION_AUTHORIZATION,
                            expected: execution_revision(&service).await,
                            spec: scope,
                        },
                    )
                    .await
                    .unwrap();
                    work_service
                }
            };
            let id = accepted_id(work_service.accept(&request).await);
            within(backend.started.notified()).await;
            let cache = cache::cached(&service, id);
            if completed {
                backend.finish.release();
                within(service.drain()).await.unwrap();
            }
            let other_writer = if expires == AccessTarget::Credential {
                let reader = cache::another_application(&service, &secret).await;
                let binding = service
                    .bind_delivery(&reader.access, &delivery::delivery_request(&auth, id))
                    .await
                    .unwrap();
                Some(service.delivery_authority(binding))
            } else {
                None
            };
            let mut stream = work_service.stream(delivery::delivery_request(&auth, id));
            assert!(matches!(
                stream.next().await.unwrap().unwrap().outcome,
                Some(work_stream_event::Outcome::Prefix(_))
            ));
            let next = stream.next();
            tokio::pin!(next);
            if prefixes == 1 && !completed {
                // Register the timer with no producer/administration notification.
                // It must wake at allowance expiry, before the delivery deadline.
                assert!(futures::poll!(&mut next).is_pending());
            }
            clock.set(UnixMillis(1100));
            if let Some(writer) = other_writer {
                // Poll synchronously before the cache timer gets another turn.
                // This reader's credential is live; the original job's is expired.
                let mut write = Box::pin(futures::future::poll_fn(|cx| {
                    writer.poll_write(cx, &mut |_| {
                        panic!("expired original credential allowed a cached body")
                    })
                }));
                assert!(
                    matches!(futures::poll!(&mut write), std::task::Poll::Ready(Err(error))
                    if error.kind() == std::io::ErrorKind::PermissionDenied)
                );
                cache::discarded(&cache);
            }
            let Some(work_stream_event::Outcome::Refused(refusal)) =
                tokio::time::timeout(WAIT, next)
                    .await
                    .expect("allowance expiry must wake an idle stream")
                    .unwrap()
                    .unwrap()
                    .outcome
            else {
                panic!("expired delivery must refuse buffered output and terminal");
            };
            assert_eq!(
                refusal.grant.unwrap().code,
                if expires == AccessTarget::Credential {
                    GrantRefusalCode::Unauthorized
                } else {
                    GrantRefusalCode::Expired
                } as i32,
                "{expires:?}"
            );
            assert!(stream.next().await.is_none());
            tokio::time::timeout(WAIT, cache.cancellation().cancelled())
                .await
                .unwrap();
            cache::discarded(&cache);
            if !completed {
                tokio::time::timeout(WAIT, backend.cancelled.notified())
                    .await
                    .expect("expiry wakes the execution without a mutation or output");
            }
            backend.finish.release();
            within(service.drain()).await.unwrap();
            let state = snapshot(&service).await;
            assert_eq!(state.ledger().active_count(BudgetNode::Machine), 0);
            assert_eq!(
                state
                    .ledger()
                    .node(budget())
                    .unwrap()
                    .counter(Meter::Requests, Window::Total)
                    .used,
                1
            );
            assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        }
    }
}
