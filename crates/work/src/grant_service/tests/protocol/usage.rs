use super::*;

#[tokio::test]
async fn verified_usage_survives_error_status_and_late_settlement_without_faulting_the_route() {
    for (status, late) in [(200, true), (500, false), (500, true)] {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, secret) = setup_with_credential(dir.path()).await;
        let id = GrantId([1; 16]);
        let mut def = store.state().grant(id).unwrap().clone();
        def.revision = Revision(2);

        use_https(&mut def.policies[0], chat_resource("https://glm.test", 8));
        let resource = def.policies[0].resource;
        def.policies[0].revision.0 += 1;
        store
            .configure_resource(def.policies[0].clone(), UnixMillis(1000))
            .await
            .unwrap();
        store.define(def, UnixMillis(1000)).await.unwrap();
        let request = request(&store, 1);
        let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
        let backend = Backend {
            reply: Reply::usage(status, false),
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
        let work = accepted_id(
            crate::test_support::accept_grant(
                &work_service,
                &request,
                &crate::test_support::principal(1).1,
            )
            .await,
        );
        within(backend.started.notified()).await;
        if late {
            clock.set(UnixMillis(a.terminal_deadline_ms.0 + 1));
        }
        backend.finish.release();
        within(service.drain()).await.unwrap();
        let state = snapshot(&service).await;
        assert_eq!(
            state
                .ledger()
                .node(BudgetNode::Machine)
                .unwrap()
                .counter(Meter::OutputTokens, Window::Total)
                .used,
            2
        );
        let health = state.resource_health(resource).unwrap();
        assert!(!health.quarantined);
        assert_eq!(health.consecutive_faults, 0);
        assert_eq!(
            state
                .channel(a.channel_id)
                .unwrap()
                .job_book()
                .terminal_by_id(work)
                .unwrap()
                .outcome
                .outcome,
            if late {
                GrantOutcome::Failed
            } else {
                GrantOutcome::Finished
            }
        );
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }
}
