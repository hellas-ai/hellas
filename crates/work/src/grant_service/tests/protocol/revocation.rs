use super::*;

#[tokio::test]
async fn revoked_queued_grant_never_dispatches_and_wrong_application_never_reserves() {
    for target in [AccessTarget::Credential, AccessTarget::Grant] {
        let dir = tempfile::tempdir().unwrap();
        let (store, secret) = setup_with_credential(dir.path()).await;
        let request = request(&store, 1);
        let backend = Backend {
            queued: Some(Arc::new(Notify::new())),
            ..Backend::default()
        };
        let (service, work_service, _credential) = service(store, backend.clone(), &secret).await;
        let wrong = service.for_caller(
            service.node().authenticate(&secret).await.unwrap(),
            common_node::EXECUTION_AUTHORIZATION,
        );
        assert_eq!(
            refusal(wrong.accept(&request).await),
            GrantRefusalCode::Unauthorized
        );
        accepted_id(work_service.accept(&request).await);
        revoke_access(&service, &secret, &_credential, target).await;
        backend.queued.as_ref().unwrap().notify_one();
        within(service.drain()).await.unwrap();
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.slots.available_permits(), 1);
        let state = snapshot(&service).await;
        assert_eq!(
            state
                .ledger()
                .node(BudgetNode::Machine)
                .unwrap()
                .counter(Meter::Requests, Window::Total)
                .used,
            0
        );
    }
}

#[tokio::test]
async fn committed_revocation_cancels_execution_but_retains_physical_ownership_and_charge() {
    for target in [AccessTarget::Credential, AccessTarget::Grant] {
        let dir = tempfile::tempdir().unwrap();
        let (store, secret) = setup_with_credential(dir.path()).await;
        let request = request(&store, 1);
        let authorization = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
        let backend = Backend {
            stop_on_cancel: true,
            ..Backend::default()
        };
        let (service, work, credential) = service(store, backend.clone(), &secret).await;
        let id = accepted_id(work.accept(&request).await);
        within(backend.started.notified()).await;
        let reserved = snapshot(&service)
            .await
            .admission(authorization.channel_id, id)
            .unwrap()
            .reserved();
        if target == AccessTarget::Grant {
            let node = service.node();
            let admin = node.authenticate(&secret).await.unwrap();
            let mut scope = snapshot(&service)
                .await
                .authority()
                .grant(common_node::EXECUTION_AUTHORIZATION)
                .unwrap()
                .spec()
                .clone();
            scope.expires.0 -= 1;
            let stale = execution_revision(&service).await;
            node.grant(
                &admin,
                hellas_auth::authority::GrantCommand::Revise {
                    authorization: GrantId([0; 16]),
                    id: common_node::EXECUTION_AUTHORIZATION,
                    expected: stale,
                    spec: scope,
                },
            )
            .await
            .unwrap();
            assert_err!(
                node.grant(
                    &admin,
                    hellas_auth::authority::GrantCommand::Revoke {
                        authorization: GrantId([0; 16]),
                        id: common_node::EXECUTION_AUTHORIZATION,
                        expected: stale,
                    }
                )
                .await,
                NodeStoreError::Authority(hellas_auth::authority::AuthorityError::Revision)
            );
            service
                .administer(async |store, now| {
                    assert!(
                        store.refresh_execution(id, now).is_some(),
                        "retained rights and a rejected mutation do not cancel work"
                    );
                    Ok(())
                })
                .await
                .unwrap();
            node.grant(
                &admin,
                hellas_auth::authority::GrantCommand::Revoke {
                    authorization: GrantId([0; 16]),
                    id: common_node::EXECUTION_AUTHORIZATION,
                    expected: execution_revision(&service).await,
                },
            )
            .await
            .unwrap();
        } else {
            revoke_access(&service, &secret, &credential, target).await;
        }
        tokio::time::timeout(WAIT, backend.cancelled.notified())
            .await
            .expect("revocation must signal idle execution without delivery polling");
        assert_eq!(backend.slots.available_permits(), 0);
        let state = snapshot(&service).await;
        assert_eq!(state.ledger().active_count(BudgetNode::Machine), 1);
        assert_eq!(
            state
                .channel(authorization.channel_id)
                .unwrap()
                .job_book()
                .job_by_id(id)
                .unwrap()
                .phase(),
            crate::work_store::JobPhase::Running
        );
        let mut drain = Box::pin(service.drain());
        assert!(futures::poll!(&mut drain).is_pending());
        backend.finish.release();
        drain.await.unwrap();
        assert_eq!(backend.slots.available_permits(), 1);
        let state = snapshot(&service).await;
        assert_eq!(state.ledger().active_count(BudgetNode::Machine), 0);
        assert_eq!(
            state
                .channel(authorization.channel_id)
                .unwrap()
                .job_book()
                .terminal_by_id(id)
                .unwrap()
                .outcome
                .outcome,
            GrantOutcome::Failed
        );
        for meter in Meter::ALL {
            assert_eq!(
                state
                    .ledger()
                    .node(budget())
                    .unwrap()
                    .counter(meter, Window::Total)
                    .used,
                reserved.get(meter)
            );
        }
    }
}

#[test]
fn interrupted_authority_append_cancels_execution_and_recovery_keeps_the_charge() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
        .block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (store, secret) = setup_with_credential(dir.path()).await;
            let request = request(&store, 1);
            let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
            let backend = Backend {
                stop_on_cancel: true,
                ..Backend::default()
            };
            let (service, work, credential) = service(store, backend.clone(), &secret).await;
            let id = accepted_id(work.accept(&request).await);
            within(backend.started.notified()).await;
            let cache = cache::cached(&service, id);
            let node = service.node();
            let delivery = service
                .bind_delivery(&work.access, &delivery::delivery_request(&a, id))
                .await
                .unwrap();
            let admin = node.authenticate(&secret).await.unwrap();
            let (entered, started) = tokio::sync::oneshot::channel();
            let (release, blocked) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                blocked.recv().unwrap();
            });
            started.await.unwrap();
            let mut revoke = Box::pin(node.revoke_credential(
                &admin,
                GrantId([0; 16]),
                credential.id(),
                Revision(1),
            ));
            assert!(futures::poll!(&mut revoke).is_pending());
            drop(revoke);
            cache::discarded(&cache);
            assert!(
                delivery.cancellation().is_cancelled(),
                "interrupted persistence invalidates delivery before another poll"
            );
            tokio::time::timeout(WAIT, backend.cancelled.notified())
                .await
                .expect("an uncertain append must invalidate execution");
            assert_eq!(backend.slots.available_permits(), 0);
            backend.finish.release();
            assert_err!(service.drain().await, NodeStoreError::Completion(source) if matches!(source.as_ref(), NodeStoreError::Journal(crate::work_store::journal::JournalError::Poisoned)));
            assert_eq!(backend.slots.available_permits(), 1);
            release.send(()).unwrap();
            blocker.await.unwrap();
            tokio::task::spawn_blocking(|| {}).await.unwrap();
            drop(work);
            drop(node);
            drop(service);
            let reopened = NodeStore::open(
                dir.path(),
                network(),
                Some(crate::test_support::software_enrollment(2, [2; 32])),
                UnixMillis(1000),
            )
            .await
            .unwrap();
            assert_eq!(
                reopened
                    .state()
                    .channel(a.channel_id)
                    .unwrap()
                    .job_book()
                    .terminal_by_id(id)
                    .unwrap()
                    .outcome
                    .outcome,
                GrantOutcome::Indeterminate
            );
            assert_eq!(
                reopened
                    .state()
                    .ledger()
                    .node(budget())
                    .unwrap()
                    .counter(Meter::Requests, Window::Total)
                    .used,
                1
            );
        });
}

#[tokio::test]
async fn auth_revocation_stops_open_result_delivery_without_dropping_running_accounting() {
    for (target, prefixes) in [(AccessTarget::Credential, 2), (AccessTarget::Grant, 1)] {
        let dir = tempfile::tempdir().unwrap();
        let (store, secret) = setup_with_credential(dir.path()).await;
        let request = request(&store, 1);
        let auth = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
        let backend = Backend {
            reply: Reply::text("private-grant-result", prefixes),
            ..Backend::default()
        };
        let (service, work_service, _credential) = service(store, backend.clone(), &secret).await;
        let id = accepted_id(work_service.accept(&request).await);
        within(backend.started.notified()).await;
        let mut stream = work_service.stream(delivery::delivery_request(&auth, id));
        assert!(matches!(
            stream.next().await.unwrap().unwrap().outcome,
            Some(work_stream_event::Outcome::Prefix(_))
        ));
        let next = stream.next();
        tokio::pin!(next);
        if prefixes == 1 {
            assert!(futures::poll!(&mut next).is_pending());
        }
        revoke_access(&service, &secret, &_credential, target).await;
        let Some(work_stream_event::Outcome::Refused(refusal)) = tokio::time::timeout(WAIT, next)
            .await
            .expect("committed revocation wakes delivery")
            .unwrap()
            .unwrap()
            .outcome
        else {
            panic!("revoked stream must refuse");
        };
        assert_eq!(
            refusal.grant.unwrap().code,
            if target == AccessTarget::Credential {
                GrantRefusalCode::Unauthorized
            } else {
                GrantRefusalCode::Revoked
            } as i32
        );
        assert!(stream.next().await.is_none());
        assert!(matches!(
            work_service.accept(&request).await.outcome,
            Some(accept_work_response::Outcome::Refused(_))
        ));
        backend.finish.release();
        tokio::time::timeout(std::time::Duration::from_secs(3), service.drain())
            .await
            .unwrap()
            .unwrap();
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
    }
}
