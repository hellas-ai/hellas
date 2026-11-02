use super::*;
use hellas_chain::test_support::devnet::{Devnet, DevnetConfig, run};
use hellas_rpc::pb::work::{
    OfferRefusalCode, OfferRefused, RequestOfferResponse, request_offer_response::Outcome,
};
use hellas_rpc::services::work_setup::{Open, RequestOffer, WorkSetup};
use hellas_wire::{ServiceMarker as _, StreamTransport as _, iroh::IrohTransport};

struct QuoteServer {
    endpoint: Endpoint,
    serving: tokio::task::JoinHandle<()>,
    reached: Arc<Mutex<Option<tokio::time::Instant>>>,
}

#[derive(Default)]
struct Approvals(AtomicUsize);
#[async_trait::async_trait]
impl hellas_authority::authenticator::Authenticator for Approvals {
    fn public_key(
        &self,
    ) -> std::result::Result<
        hellas_authority::authenticator::PublicKey,
        hellas_auth::authority::AuthorityError,
    > {
        hellas_authority::authenticator::Authenticator::public_key(
            &hellas_auth::test_support::actors::FRIEND.passkey(),
        )
    }
    async fn assert(
        &self,
        challenge: hellas_auth::Digest,
    ) -> std::result::Result<
        hellas_auth::authority::PasskeyAssertion,
        hellas_auth::authority::AuthorityError,
    > {
        self.0.fetch_add(1, Ordering::SeqCst);
        hellas_authority::authenticator::Authenticator::assert(
            &hellas_auth::test_support::actors::FRIEND.passkey(),
            challenge,
        )
        .await
    }
}

/// Authenticate normally, then either withhold the quote or refuse it. Both
/// exercise the real transport and candidate-routing path without funding.
async fn quote_server(stall: bool) -> QuoteServer {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .alpns(vec![WorkSetup::ALPN.as_bytes().to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let server = endpoint.clone();
    let reached = Arc::new(Mutex::new(None));
    let observed = reached.clone();
    let serving = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let transport = IrohTransport::new(connection);
        let (enrollment, signer) = crate::test_identity::enrollment(server.id());
        let proof = crate::test_identity::OpenProof(enrollment, signer);
        let inbound = transport.accept().await.unwrap().unwrap();
        hellas_rpc::call::dispatch_unary_with_context::<IrohTransport, Open, _, _, _>(
            inbound,
            |request, context| async move {
                hellas_rpc::open::OpenHandler::open(
                    &proof,
                    request,
                    context,
                    WorkSetup::ALPN.as_bytes(),
                )
                .await
            },
        )
        .await
        .unwrap();
        let inbound = transport.accept().await.unwrap().unwrap();
        hellas_rpc::call::dispatch_unary_with_context::<IrohTransport, RequestOffer, _, _, _>(
            inbound,
            move |request, _context| async move {
                assert!(
                    request.funding_coins.is_empty(),
                    "only a quote can precede funding"
                );
                *observed.lock().unwrap() = Some(tokio::time::Instant::now());
                if stall {
                    std::future::pending::<()>().await;
                }
                Ok(RequestOfferResponse {
                    outcome: Some(Outcome::Refused(OfferRefused {
                        code: OfferRefusalCode::NoPolicy as i32,
                        ..Default::default()
                    })),
                })
            },
        )
        .await
        .unwrap();
        transport.connection().closed().await;
    });
    QuoteServer {
        endpoint,
        serving,
        reached,
    }
}

#[test]
fn an_unresponsive_paid_quote_yields_to_the_next_provider_within_the_connection_bound() {
    run(|runtime| {
        Box::pin(async move {
            let mut devnet = Devnet::start(
                runtime,
                DevnetConfig {
                    name: "gateway_connection_fallback",
                    owners: vec![],
                    full_nodes: 1,
                },
            )
            .await;
            devnet.seal().await;
            let fixture = crate::test_support::PaidFixture::on_network(devnet.network());
            let mut pool = super::tests::test_pool(&fixture, fixture.policy.clone()).await;
            let approvals = Arc::new(Approvals::default());
            pool.owner = Arc::new(
                crate::client_owner::ClientOwner::new(
                    approvals.clone(),
                    pool.settlement_key.party_key(),
                    &fixture.root.path().join("counted-funding"),
                )
                .unwrap(),
            );
            let first = quote_server(true).await;
            let second = quote_server(false).await;
            let config = crate::work_config::WorkConfig {
                chain: crate::work_config::ChainCrossCheck {
                    network: devnet.network(),
                    genesis_payload_digest: devnet.genesis_payload().0.into(),
                    threshold_identity: devnet.consensus_info().threshold_identity.clone(),
                    genesis: Some(devnet.genesis().clone()),
                },
                validators: devnet.light_client_urls(),
                journal_root: fixture.root.path().join("provider"),
                poll: Duration::from_millis(20),
                max_observation_age: Duration::from_secs(30),
            };
            // A peer that accepts TCP but never completes WebSocket setup must
            // not hold up another peer's already verified snapshot.
            let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut with_stalled = config.clone();
            with_stalled.validators[0] = format!("ws://{}", stalled.local_addr().unwrap());
            tokio::time::timeout(
                Duration::from_secs(2),
                crate::client_chain::connect(&with_stalled, Duration::from_secs(30)),
            )
            .await
            .expect("verified peers must not wait for the stalled peer's 5s timeout")
            .unwrap();
            drop(stalled);
            let original = pool.providers.remove(0);
            for (index, endpoint) in [&first.endpoint, &second.endpoint].into_iter().enumerate() {
                let mut args = original.args.clone();
                args.config = config.clone();
                args.journal_root = fixture.root.path().join(format!("client-{index}"));
                args.provider = crate::test_identity::address(endpoint.id());
                args.provider_addrs = endpoint.bound_sockets();
                args.timeout = Some(Duration::from_secs(60));
                pool.providers.push(Arc::new(Provider {
                    args,
                    policy: fixture.policy.clone(),
                    serial: AsyncMutex::new(None),
                    pending: AtomicUsize::new(0),
                    unavailable_until: Mutex::new(None),
                }));
            }
            let input = JobInput::Fetch {
                contract: test_responses_contract(),
                service: "openai".into(),
                method: "responses".into(),
                request: crate::test_support::BODY.to_vec(),
                assurance: hellas_rpc::Assurance::ProducerSigned,
            };
            let request = pool.request(WorkRequest::Compute(input)).unwrap();
            let pool = Arc::new(pool);
            let (requester, _receiver) = Requester::<FetchEvent, PoolError>::new();
            let result = pool.clone().run(request, requester).await;
            let first_contact = *first.reached.lock().unwrap();
            let second_contact = *second.reached.lock().unwrap();
            for provider in &pool.providers {
                let found = hellas_channel::work_store::discover_setups(
                    &provider.args.journal_root,
                    devnet.network(),
                )
                .await
                .unwrap();
                assert!(found.setups.is_empty());
                assert!(found.unidentified.is_empty());
            }
            pool.shutdown().await.unwrap();
            first.endpoint.close().await;
            second.endpoint.close().await;
            first.serving.abort();
            second.serving.abort();
            let _ = first.serving.await;
            let _ = second.serving.await;
            devnet.shutdown().await;
            let Err(PoolError::ProvidersUnavailable(errors)) = result else {
                panic!("both candidates must have been attempted");
            };
            assert_eq!(approvals.0.load(Ordering::SeqCst), 0);
            assert_eq!(errors.len(), 2, "{errors:?}");
            assert!(errors[0].contains("paid provider connection"), "{errors:?}");
            assert!(
                errors[1].contains(&format!(
                    "provider refused offer request ({})",
                    OfferRefusalCode::NoPolicy as i32
                )),
                "{errors:?}"
            );
            let elapsed = second_contact
                .expect("fallback provider receives a quote request")
                .duration_since(first_contact.expect("first provider receives a quote request"));
            assert!(
                elapsed >= Duration::from_secs(9),
                "first provider must consume its connection allowance: {elapsed:?}"
            );
            assert!(
                elapsed < Duration::from_secs(15),
                "fallback must use the 10s allowance, not the 60s request budget: {elapsed:?}"
            );
        })
    });
}
