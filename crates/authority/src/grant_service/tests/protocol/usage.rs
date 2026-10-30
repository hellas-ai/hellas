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
                &hellas_channel::test_support::principal(1).1,
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

#[tokio::test]
async fn metered_https_health_requests_do_not_quarantine_generation() {
    use crate::test_support::ids;
    use hellas_channel::test_support::actors::*;
    use hellas_channel::test_support::backend::Completion;
    let dir = tempfile::tempdir().unwrap();
    let mut https = chat_resource("https://glm.test", 8);
    https.paths.push("/health".into());
    https.methods.push("GET".into());
    let mut allowance = Allowance::responses(ids::ALLOWANCE, FRIEND);
    use_https(&mut allowance.definition.policies[0], https.clone());
    let resource = allowance.definition.policies[0].resource;
    let node = Node::bootstrap(dir.path())
        .with_allowance(allowance)
        .with_grant(
            ids::FRIEND_GRANT,
            Rights::new(authority(), FRIEND)
                .allow(
                    crate::grant_service::WORK_EXECUTE,
                    crate::grant_service::allowance_resource(authority(), ids::ALLOWANCE),
                )
                .valid_until(UnixMillis(100_000))
                .build(),
        )
        .build()
        .await;
    #[derive(Clone)]
    struct BackendByRequest {
        health: Backend,
        generation: Backend,
        calls: Arc<AtomicUsize>,
    }
    impl hellas_channel::work::WorkBackend for BackendByRequest {
        fn try_admit(
            &self,
            domain: hellas_channel::work::admission::CapacityDomain,
        ) -> Result<hellas_channel::work::admission::WorkPermit, hellas_channel::work::BackendFault>
        {
            hellas_channel::work::WorkBackend::try_admit(&self.health, domain)
        }
        async fn execute_stream(
            &self,
            input: hellas_channel::work::Admitted,
            progress: hellas_channel::work::PaidProgress,
        ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, hellas_channel::work::BackendFault>
        {
            let backend = if self.calls.fetch_add(1, Ordering::SeqCst) < 3 {
                &self.health
            } else {
                &self.generation
            };
            hellas_channel::work::WorkBackend::execute_stream(backend, input, progress).await
        }
    }
    let backend = Backend {
        reply: Reply::events(Reply::http(200, "application/json", r#"{"ok":true}"#)),
        finish: Completion::Immediate,
        signer: Arc::new(PROVIDER.node_key()),
        ..Backend::default()
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let generation = Backend {
        reply: Reply::usage(200, false),
        ..backend.clone()
    };
    let world = node.serve(BackendByRequest {
        health: backend,
        generation,
        calls: calls.clone(),
    });
    let work = world.work(FRIEND, ids::FRIEND_GRANT).await;
    for nonce in 1..=4 {
        let mut proposal = world.proposal(FRIEND, ids::ALLOWANCE, nonce).await;
        if nonce <= 3 {
            let request = hellas_rpc::http_fetch::HttpFetchRequest {
                url: "https://glm.test/health".into(),
                method: "GET".into(),
                headers: vec![],
                body_base64: String::new(),
                tls: https.tls.clone(),
                credential: None,
                max_response_bytes: https.max_response_bytes,
            };
            let contract = hellas_rpc::FetchContract::http().unwrap();
            let events = hellas_rpc::fetch::build_input_events_with_retention(
                "openai",
                "responses",
                &serde_json::to_vec(&request).unwrap(),
                contract.manifest_id(),
                Assurance::ProducerSigned,
                &FRIEND.node_key(),
                Retention::Ephemeral,
            )
            .unwrap();
            proposal.input = hellas_rpc::protocol::invocation::fetch::prepare(
                &events,
                &contract,
                PROVIDER.node_key().public_key(),
                proposal.input.application_policy.0.clone(),
                [nonce as u8; 32],
            )
            .unwrap();
            proposal.authorization.input_content =
                hellas_rpc::ContentRef::for_bytes(&proposal.input.canonical_bytes().unwrap());
            proposal.authorization.prepared_input_digest =
                hellas_channel::job::bound_prepared_input_digest(
                    network(),
                    proposal.authorization.channel_id.0,
                    &proposal.input,
                )
                .unwrap();
            proposal.authorization.request_commitment =
                proposal.input.request.commitment().unwrap();
            proposal.signature = FRIEND.node_key().sign_digest(proposal.work()).unwrap();
        }
        let id = accepted_id(
            crate::test_support::accept_grant(&work, &proposal.request(), &FRIEND.node_key()).await,
        );
        within(async {
            loop {
                let state = world.snapshot().await;
                if state
                    .channel(proposal.authorization.channel_id)
                    .and_then(|c| c.job_book().terminal_by_id(id))
                    .is_some()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        {
            let health = world.snapshot().await.resource_health(resource).unwrap();
            assert!(
                !health.quarantined,
                "health request {nonce} quarantined the resource"
            );
            assert_eq!(health.consecutive_faults, 0);
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        world.used(BudgetNode::Machine, Meter::OutputTokens).await,
        2
    );
    world.service.drain().await.unwrap();
}
