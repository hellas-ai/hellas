use super::*;
use crate::test_support::{BODY, PRICE, PaidFixture};
use hellas_channel::work::{Admitted, BackendFault, WorkBackend, admission::WorkPermit};
use hellas_channel::work_close::CloseChannel as _;
use hellas_rpc::output::OutputEvent;
use hellas_rpc::services::work::Work;
use tokio::sync::{Mutex, Semaphore, mpsc};

struct Controlled {
    backend: hellas_channel::test_support::backend::Backend,
    started: mpsc::UnboundedSender<usize>,
    sequence: std::sync::atomic::AtomicUsize,
    gates: [Arc<Semaphore>; 3],
}
impl WorkBackend for Controlled {
    fn try_admit(
        &self,
        backend: &hellas_channel::work::admission::BackendKey,
        _caller: hellas_auth::PublicKey,
    ) -> std::result::Result<WorkPermit, BackendFault> {
        self.backend.try_admit(backend, _caller)
    }
    async fn execute(
        &self,
        input: Admitted,
    ) -> std::result::Result<Vec<hellas_rpc::OutputEventEnvelope>, BackendFault> {
        let index = self.sequence.fetch_add(1, Ordering::SeqCst);
        self.started.send(index).unwrap();
        self.gates[index].acquire().await.unwrap().forget();
        if index == 2 {
            use hellas_rpc::protocol::invocation::output::{FailureReason, OutputStream};
            let backend = hellas_channel::work::admission::BackendKey::of(input.invocation())?;
            let caller = input.invocation().request.runner_public_key;
            let (prepared, _, _, admission) = input
                .reserve(async { self.try_admit(&backend, caller) })
                .await?
                .into_parts_and_admission();
            let _running = admission.dispatch().await?;
            return Ok(
                OutputStream::new(&prepared.request, &self.backend.signer, 65536)
                    .unwrap()
                    .fail(FailureReason::Execution)
                    .unwrap()
                    .1,
            );
        }
        self.backend.execute(input).await
    }
}

#[tokio::test]
async fn paid_jobs_collect_concurrently_and_pay_in_completion_order() {
    paid_concurrency(false).await;
    paid_concurrency(true).await;
}

async fn paid_concurrency(cancel: bool) {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = PaidFixture::new();
        let provider = fixture.provider().await;
        let (started, mut starts) = mpsc::unbounded_channel();
        let gates = std::array::from_fn(|_| Arc::new(Semaphore::new(0)));
        let mount = crate::paid_provider::MountedWork::with_backend(Controlled {
            backend: hellas_channel::test_support::backend::Backend {
                slots: Arc::new(Semaphore::new(2)),
                finish: hellas_channel::test_support::backend::Completion::Immediate,
                ..Default::default()
            },
            started,
            sequence: Default::default(),
            gates: gates.clone(),
        });
        let server = Endpoint::builder(presets::Minimal)
            .alpns(vec![Work::ALPN.as_bytes().to_vec()])
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let endpoint = bind_paid_endpoint(SecretKey::from_bytes(&[1; 32]))
            .await
            .unwrap();
        mount
            .mount(
                hellas_wire::peers::PeerId::from_bytes(*endpoint.id().as_bytes()),
                &provider,
            )
            .await
            .unwrap();
        let mount = crate::work_router::WorkRouter::payment(mount);
        let (bundle, producer) = enrollment(server.id());
        let trust = hellas_client::ProviderTrustAnchor {
            expected_genesis: bundle.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        };
        let serving = tokio::spawn({
            let server = server.clone();
            async move {
                let transport = IrohTransport::new(server.accept().await.unwrap().await.unwrap());
                let handler = Arc::new(
                    mount
                        .accept_iroh(
                            &transport,
                            crate::test_identity::OpenProof(bundle, producer),
                        )
                        .await
                        .unwrap(),
                );
                let mut calls = tokio::task::JoinSet::new();
                while let Ok(Some(inbound)) = transport.accept().await {
                    let handler = handler.clone();
                    calls.spawn(async move {
                        let _ =
                            hellas_wire::Dispatcher::<IrohTransport>::dispatch(&*handler, inbound)
                                .await;
                    });
                }
                while calls.join_next().await.is_some() {}
            }
        });
        let mut client = fixture.client().await;
        let content = client
            .client()
            .await
            .unwrap()
            .store()
            .await
            .unwrap()
            .content_store();
        let session = Arc::new(Mutex::new(PaidWorkSession {
            args: PaidWorkOptions {
                content,
                config: fixture.config.clone(),
                provider: crate::test_support::address(server.id()),
                provider_addrs: server.bound_sockets(),
                apple_trust: None,
                assurance: Assurance::ProducerSigned,
                expected_price: PRICE,
                acceptance_blocks: 49,
                terminal_blocks: 99,
                payment_blocks: 199,
                timeout: None,
            },
            descriptor: fixture.descriptor.clone(),
            policy: fixture.policy.clone(),
            dialer: Arc::new(ProviderDialer::new(
                server.id(),
                server.bound_sockets(),
                endpoint.clone(),
                trust,
            )),
            client,
            observer: None,
            needs_recovery: false,
        }));
        let job = crate::job::Job::fetch(
            PRICE,
            hellas_channel::test_support::test_responses_contract(),
            "openai".into(),
            "responses".into(),
            BODY.to_vec(),
            Assurance::ProducerSigned,
        )
        .unwrap();
        let key = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let jobs = Arc::new(hellas_gateway::jobs::Jobs::default());
        let mut request_jobs = Vec::new();
        let mut tasks = Vec::new();
        let mut streams = Vec::new();
        for index in 0..2 {
            let proposed = Arc::new(AtomicBool::new(false));
            let delivery = session
                .lock()
                .await
                .propose_job(&job, &key, &proposed)
                .await
                .unwrap();
            assert!(proposed.load(Ordering::Acquire));
            let request_job = crate::test_support::request_job(&jobs);
            request_jobs.push(request_job.clone());
            let (requester, mut stream) = crate::gateway_work::Requester::<
                OutputEvent,
                hellas_gateway::WorkGatewayError,
            >::new(request_job);
            tasks.push(tokio::spawn({
                let session = session.clone();
                async move {
                    let result = delivery
                        .collect(
                            Some(&requester.progress()),
                            Some(&requester.accepted()),
                            None,
                        )
                        .await
                        .unwrap();
                    session.lock().await.pay(result).await.unwrap()
                }
            }));
            assert!(matches!(
                stream.next().await.unwrap().unwrap(),
                hellas_gateway::WorkEvent::Accepted(_)
            ));
            streams.push(stream);
            assert_eq!(starts.recv().await.unwrap(), index);
        }
        session
            .lock()
            .await
            .with_state(|state| {
                assert_eq!(state.proposal_nonce_high_water(), 2);
                let mut nonces = state
                    .jobs()
                    .map(|j| j.authorization().proposal_nonce)
                    .collect::<Vec<_>>();
                nonces.sort_unstable();
                assert_eq!(nonces, [1, 2]);
                assert_eq!(state.ledger().credited_cumulative(), 0);
                assert_eq!(
                    state.jobs().map(|j| j.authorization().price).sum::<u64>(),
                    2 * PRICE
                );
            })
            .await
            .unwrap();
        // Cancellation and disconnect both leave collection and settlement owned.
        let mut first_stream = streams.remove(0);
        if cancel {
            assert!(jobs.cancel(request_jobs[0].id()));
            assert!(first_stream.next().await.is_none());
        }
        drop(first_stream);
        gates[1].add_permits(1);
        let second = tasks.pop().unwrap().await.unwrap();
        assert_eq!(second.credited_cumulative, PRICE);
        provider
            .with_state(|state| {
                assert_eq!(state.ledger().credited_cumulative(), PRICE);
                assert_eq!(state.jobs().count(), 1);
            })
            .await
            .unwrap();
        // A signed execution failure terminates its own job without payment.
        let delivery = session
            .lock()
            .await
            .propose_job(&job, &key, &Arc::new(AtomicBool::new(false)))
            .await
            .unwrap();
        assert_eq!(starts.recv().await.unwrap(), 2);
        gates[2].add_permits(1);
        assert!(matches!(
            delivery.collect(None, None, None).await,
            Err(PaidClientError::InvocationFailed { .. })
        ));
        session
            .lock()
            .await
            .with_state(|state| {
                assert_eq!(state.proposal_nonce_high_water(), 3);
                assert_eq!(state.ledger().credited_cumulative(), PRICE);
                assert_eq!(state.jobs().count(), 1);
                assert_eq!(state.terminals().count(), 2);
            })
            .await
            .unwrap();
        gates[0].add_permits(1);
        let first = tasks.pop().unwrap().await.unwrap();
        assert_ne!(first.work_id, second.work_id);
        assert_eq!(first.credited_cumulative, 2 * PRICE);
        provider
            .with_state(|state| {
                assert_eq!(state.ledger().credited_cumulative(), 2 * PRICE);
                assert_eq!(state.jobs().count(), 0);
                assert_eq!(state.terminals().count(), 3);
            })
            .await
            .unwrap();
        session.lock().await.shutdown().await;
        drop(session);
        endpoint.close().await;
        server.close().await;
        serving.abort();
        let _ = serving.await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn funded_capacity_refuses_before_signing_or_consuming_a_nonce() {
    use hellas_channel::model::work::signing_hash;
    use hellas_rpc::pb::work::{AcceptWorkResponse, WorkAccepted, accept_work_response};
    let fixture = PaidFixture::new();
    let mut client = fixture.client().await;
    let limit = client
        .with_state(|state| state.settlement().capacity() / PRICE)
        .await
        .unwrap();
    let content = empty_content();
    for nonce in 1..=limit {
        let proposed = Arc::new(AtomicBool::new(false));
        client
            .propose(&fixture.proposal(), &content, Some(proposed.clone()))
            .await
            .unwrap();
        assert!(proposed.load(Ordering::Acquire));
        let id = client
            .with_state(|state| {
                assert_eq!(state.proposal_nonce_high_water(), nonce);
                state.job_book().pending_proposal().unwrap()
            })
            .await
            .unwrap();
        // Co-sign without executing: every open job must keep its reservation.
        let signature = crate::test_support::signer(2).sign(signing_hash(id));
        client
            .client()
            .await
            .unwrap()
            .accepted(&AcceptWorkResponse {
                outcome: Some(accept_work_response::Outcome::Accepted(WorkAccepted {
                    work_id: id.as_bytes().to_vec(),
                    provider_signature: signature.as_bytes().to_vec(),
                })),
            })
            .await
            .unwrap();
    }
    let proposed = Arc::new(AtomicBool::new(false));
    let error = client
        .propose(&fixture.proposal(), &content, Some(proposed.clone()))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        hellas_channel::work::ProposeError::Store(
            hellas_channel::work_store::WorkStoreError::Channel(
                hellas_channel::work_store::ChannelStateError::OverCredit { .. }
            )
        )
    ));
    assert!(!proposed.load(Ordering::Acquire));
    client
        .with_state(|state| {
            assert_eq!(state.proposal_nonce_high_water(), limit);
            assert!(state.job_book().pending_proposal().is_none());
            assert_eq!(state.jobs().count() as u64, limit);
            assert_eq!(state.ledger().credited_cumulative(), 0);
        })
        .await
        .unwrap();
    client.close().await.unwrap();
    drop(client);
    let reopened = fixture
        .store(hellas_channel::work_store::Role::Client)
        .await;
    assert_eq!(reopened.state().proposal_nonce_high_water(), limit);
    assert_eq!(reopened.state().jobs().count() as u64, limit);
}
