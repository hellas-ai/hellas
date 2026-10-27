use super::*;
use crate::grant_service::ResultCache;

pub(super) fn cached(service: &GrantService, id: Digest) -> Arc<ResultCache> {
    service
        .inner
        .lock()
        .unwrap()
        .live
        .get(&id)
        .unwrap()
        .cache
        .clone()
}
pub(super) fn discarded(cache: &ResultCache) {
    let body = cache.lock().unwrap();
    assert!(!body.retained);
    assert!(body.events.is_empty());
    assert_eq!(
        body.events.capacity(),
        0,
        "drop the body allocation, not only its length"
    );
    assert_eq!(body.bytes, 0);
}

pub(super) async fn another_application(
    service: &GrantService,
    secret: &hellas_auth::authority::CredentialSecret,
) -> hellas_authority::grant_service::GrantWork {
    let node = service.node();
    let admin = crate::test_support::session(&node, secret).await;
    let scope = snapshot(service)
        .await
        .authority()
        .grant(common_node::EXECUTION_AUTHORIZATION)
        .unwrap()
        .spec()
        .clone();
    let (_, credential) = crate::test_support::credentials::issue_one(
        &node,
        &admin,
        GrantId([0; 16]),
        scope,
        hellas_channel::test_support::holder(principal(1).0),
    )
    .await
    .unwrap();
    service.for_caller(
        node.authenticate_session(&credential, crate::node::SessionKey::Node(&principal(1).1))
            .await
            .unwrap(),
        common_node::EXECUTION_AUTHORIZATION,
    )
}

#[tokio::test]
async fn revoke_discards_active_and_completed_bodies_without_delivery_polling() {
    for target in [AccessTarget::Credential, AccessTarget::Grant] {
        for completed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (store, secret) = setup_with_credential(dir.path()).await;
            let request = request(&store, 1);
            let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
            let backend = Backend::default();
            let (service, work, credential) = service(store, backend.clone(), &secret).await;
            let id = accepted_id(
                crate::test_support::accept_grant(
                    &work,
                    &request,
                    &hellas_channel::test_support::principal(1).1,
                )
                .await,
            );
            within(backend.started.notified()).await;
            if completed {
                backend.finish.release();
                within(service.drain()).await.unwrap();
            }
            let cache = cached(&service, id);
            assert!(cache.bytes() > 0);
            let late = cache.lock().unwrap().events[0].clone();
            revoke_access(&service, &secret, &credential, target).await;
            discarded(&cache);
            let error = service.progress(id, late).unwrap_err();
            let cause = std::error::Error::source(&error).unwrap();
            if completed {
                assert!(
                    matches!(
                        cause.downcast_ref::<crate::grant_service::ExecutionError>(),
                        Some(crate::grant_service::ExecutionError::NotDispatched)
                    ),
                    "{error:?}"
                );
            } else {
                assert!(
                    matches!(
                        cause.downcast_ref::<hellas_channel::work::admission::AdmissionError>(),
                        Some(hellas_channel::work::admission::AdmissionError::Cancelled)
                    ),
                    "{error:?}"
                );
            }
            discarded(&cache);
            if !completed {
                tokio::time::timeout(WAIT, backend.cancelled.notified())
                    .await
                    .unwrap();
                assert_eq!(backend.slots.available_permits(), 0);
                backend.finish.release();
                within(service.drain()).await.unwrap();
            }
            discarded(&cache);
            if target == AccessTarget::Credential {
                let reader = another_application(&service, &secret).await;
                let mut stream = reader.stream(delivery::delivery_request(&a, id));
                let Some(work_stream_event::Outcome::Refused(refusal)) =
                    stream.next().await.unwrap().unwrap().outcome
                else {
                    panic!("discarded output must not return to a new application");
                };
                let detail = refusal.grant.unwrap();
                assert_eq!(detail.code, GrantRefusalCode::OutputUnavailable as i32);
                assert!(!detail.terminal.unwrap().provider_signature.is_empty());
            }
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
            let terminal = state
                .channel(a.channel_id)
                .unwrap()
                .job_book()
                .terminal_by_id(id)
                .unwrap();
            assert_eq!(terminal.outcome.outcome, GrantOutcome::Finished);
            assert!(
                terminal.outcome.result.is_some(),
                "settlement metadata survives discarded delivery bodies"
            );
            assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn completed_cache_expires_without_a_delivery_or_mutation_and_never_owns_the_writer() {
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
    set_execution_expiry(&service, &secret, UnixMillis(1100)).await;
    let id = accepted_id(
        crate::test_support::accept_grant(
            &work,
            &request,
            &hellas_channel::test_support::principal(1).1,
        )
        .await,
    );
    within(backend.started.notified()).await;
    backend.finish.release();
    within(service.drain()).await.unwrap();
    let cache = cached(&service, id);
    assert!(cache.bytes() > 0);
    clock.set(UnixMillis(1100));
    tokio::time::timeout(WAIT, cache.cancellation().cancelled())
        .await
        .unwrap();
    discarded(&cache);
    drop(work);
    drop(service);
    // Keep the cache handle alive: neither it nor its timer may retain the writer.
    let reopened = NodeStore::open(
        dir.path(),
        network(),
        Some(hellas_channel::test_support::software_enrollment(
            2, [2; 32],
        )),
        UnixMillis(1100),
    )
    .await
    .unwrap();
    assert!(
        reopened
            .state()
            .channel(a.channel_id)
            .unwrap()
            .job_book()
            .terminal_by_id(id)
            .unwrap()
            .outcome
            .result
            .is_some()
    );
    discarded(&cache);
}

#[tokio::test]
async fn discarded_prefix_still_verifies_usage_and_rejects_a_different_signed_completion() {
    for rewrite_prefix in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, secret) = setup_with_credential(dir.path()).await;
        let mut def = store.state().grant(GrantId([1; 16])).unwrap().clone();
        def.revision.0 += 1;

        use_https(&mut def.policies[0], chat_resource("https://glm.test", 8));
        def.policies[0].revision.0 += 1;
        store
            .configure_resource(def.policies[0].clone(), UnixMillis(1000))
            .await
            .unwrap();
        store.define(def, UnixMillis(1000)).await.unwrap();
        let request = request(&store, 1);
        let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
        let backend = Backend {
            reply: Reply::usage(200, rewrite_prefix),
            ..Backend::default()
        };
        let (service, work, credential) = service(store, backend.clone(), &secret).await;
        let id = accepted_id(
            crate::test_support::accept_grant(
                &work,
                &request,
                &hellas_channel::test_support::principal(1).1,
            )
            .await,
        );
        within(backend.started.notified()).await;
        let cache = cached(&service, id);
        assert!(cache.bytes() > 0);
        revoke_access(&service, &secret, &credential, AccessTarget::Credential).await;
        discarded(&cache);
        tokio::time::timeout(WAIT, backend.cancelled.notified())
            .await
            .unwrap();
        assert_eq!(backend.slots.available_permits(), 0);
        backend.finish.release();
        within(service.drain()).await.unwrap();
        discarded(&cache);
        let state = snapshot(&service).await;
        let used = state
            .ledger()
            .node(BudgetNode::Machine)
            .unwrap()
            .counter(Meter::OutputTokens, Window::Total)
            .used;
        assert_eq!(used, if rewrite_prefix { 8 } else { 2 });
        let terminal = state
            .channel(a.channel_id)
            .unwrap()
            .job_book()
            .terminal_by_id(id)
            .unwrap();
        assert_eq!(
            terminal.outcome.outcome,
            if rewrite_prefix {
                GrantOutcome::Failed
            } else {
                GrantOutcome::Finished
            }
        );
        assert_eq!(terminal.outcome.result.is_some(), !rewrite_prefix);
    }
}

#[tokio::test]
async fn catalogue_change_discards_bodies_and_cancels_bound_responses_before_late_settlement() {
    use crate::model::grant::admin::WorkControlCommand;
    for (completed, remove_from_allowance) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let directory = tempfile::tempdir().unwrap();
        let (store, secret) = setup_with_credential(directory.path()).await;
        let request = request(&store, 1);
        let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
        let backend = Backend::default();
        let (service, work, _) = service(store, backend.clone(), &secret).await;
        let id = accepted_id(
            crate::test_support::accept_grant(
                &work,
                &request,
                &hellas_channel::test_support::principal(1).1,
            )
            .await,
        );
        within(backend.started.notified()).await;
        if completed {
            backend.finish.release();
            within(service.drain()).await.unwrap();
        }
        let cache = cached(&service, id);
        assert!(cache.bytes() > 0);
        let response = service
            .bind_delivery(&work.access, &delivery::delivery_request(&a, id))
            .await
            .unwrap();
        let writer = service.delivery_authority(response.clone());
        let mut changed = policy();
        if remove_from_allowance {
            changed.resource =
                hellas_auth::authority::ResourceId(Digest::hash(b"replacement resource"));
            changed.name = "replacement".into();
        } else {
            changed.revision.0 += 1;
        }
        let admin =
            common_node::WorkAdmin::new(service.clone(), &secret, vec![changed.clone()]).await;
        admin
            .command(WorkControlCommand::ConfigureResource {
                policy: changed.name.clone(),
            })
            .await
            .unwrap();
        if remove_from_allowance {
            use crate::model::grant::admin::AllowanceTerms;
            assert!(
                cache.bytes() > 0,
                "adding another resource does not revoke this one"
            );
            admin
                .command(WorkControlCommand::Revise {
                    id: a.grant_id,
                    expected_revision: a.grant_revision,
                    terms: AllowanceTerms {
                        policies: vec![changed.name],
                        budget: budget(),
                        max_job_millis: std::num::NonZeroU64::new(10000).unwrap(),
                        enabled: true,
                        allow_account_backed: true,
                    },
                })
                .await
                .unwrap();
        }
        discarded(&cache);
        assert!(response.cancellation().is_cancelled());
        let error = futures::future::poll_fn(|cx| {
            writer.poll_write(cx, &mut |_| panic!("old policy reached a carrier"))
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_err!(service.bind_delivery(&work.access, &delivery::delivery_request(&a, id)).await,
            refusal if refusal.grant.as_ref().unwrap().code == GrantRefusalCode::OutOfScope as i32);
        if !completed {
            tokio::time::timeout(WAIT, backend.cancelled.notified())
                .await
                .unwrap();
            assert_eq!(backend.slots.available_permits(), 0);
            backend.finish.release();
            within(service.drain()).await.unwrap();
        }
        discarded(&cache);
        let state = snapshot(&service).await;
        let terminal = state
            .channel(a.channel_id)
            .unwrap()
            .job_book()
            .terminal_by_id(id)
            .unwrap();
        assert_eq!(terminal.outcome.outcome, GrantOutcome::Finished);
        assert!(terminal.outcome.result.is_some());
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
