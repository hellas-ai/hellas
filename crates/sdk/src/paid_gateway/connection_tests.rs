use super::*;
use hellas_chain::test_support::devnet::{Devnet, DevnetConfig, run};
use hellas_rpc::pb::work::{
    OfferRefusalCode, OfferRefused, RequestOfferResponse, request_offer_response::Outcome,
};
use hellas_rpc::services::work_setup::{Open, RequestOffer, WorkSetup};
use hellas_wire::{ServiceMarker as _, StreamTransport as _, iroh::IrohTransport};

#[tokio::test]
async fn gateway_refuses_funding_owner_from_another_genesis() {
    let fixture = crate::test_support::PaidFixture::new();
    let owner = Arc::new(
        crate::client_owner::ClientOwner::new(
            Arc::new(hellas_auth::test_support::actors::FRIEND.passkey()),
            crate::test_support::signer(7).party_key(),
            &fixture.config.chain,
        )
        .unwrap(),
    );
    let original_network = fixture.config.chain.network_id().to_owned();
    let mut config = fixture.config;
    config.chain =
        crate::test_support::chain_dir_with_digest(fixture.root.path(), config.network(), [2; 32]);
    assert_eq!(original_network, config.chain.network_id());
    assert_ne!(owner.chain_root(), config.chain.as_path());
    let provider = crate::test_support::address(iroh::SecretKey::generate().public());
    let options = crate::paid_gateway::PaidGatewayOptions {
        config,
        max_pending_requests: 1,
        providers: vec![crate::paid_gateway::GatewayProviderOptions {
            provider,
            provider_addrs: vec![],
            apple_trust: None,
            assurance: hellas_rpc::Assurance::ProducerSigned,
            expected_price: 1,
            acceptance_blocks: 1,
            terminal_blocks: 1,
            payment_blocks: 1,
            timeout: Some(std::time::Duration::from_secs(30)),
        }],
    };
    let identity =
        crate::NodeIdentity::from_secret_bytes(iroh::SecretKey::generate().to_bytes(), [0x21; 32])
            .unwrap();
    let error = crate::paid_gateway::PaidGateway::open(options, identity, owner)
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error,
        crate::paid_gateway::PoolError::Invalid("funding owner belongs to another chain directory")
    ));
}

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
                    &fixture.config.chain,
                )
                .unwrap(),
            );
            let first = quote_server(true).await;
            let second = quote_server(false).await;
            use commonware_cryptography::{Hasher as _, Sha256};
            use hellas_chain::genesis::{Chain, ChainProfile, CustomChainFile};
            let genesis_json = serde_json::to_string(devnet.genesis()).unwrap();
            let mut trust = ChainProfile::known(Chain::Devnet).trust().clone();
            trust.network_id = devnet.network().as_str().into();
            trust.genesis_sha256 = hex::encode(Sha256::hash(genesis_json.as_bytes()));
            trust.epochs[0].threshold_identity =
                hex::encode(&devnet.consensus_info().threshold_identity);
            let config = crate::work_config::WorkConfig {
                chain: hellas_chain::genesis::ChainDir::open(
                    fixture.root.path(),
                    &ChainProfile::custom(CustomChainFile {
                        consensus_digest: hex::encode(
                            hellas_chain::genesis_digest(devnet.genesis()).0,
                        ),
                        trust,
                        validators: devnet.light_client_urls(),
                        genesis_json: Some(genesis_json),
                        genesis_payload: Some(hex::encode(devnet.genesis_payload().0)),
                    })
                    .unwrap(),
                )
                .unwrap(),
                poll: Duration::from_millis(20),
                max_observation_age: Duration::from_secs(30),
            };
            // A peer that accepts TCP but never completes WebSocket setup must
            // not hold up another peer's already verified snapshot.
            let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut with_stalled = config.clone();
            let mut routes = with_stalled.chain.validators().to_vec();
            routes[0] = format!("ws://{}", stalled.local_addr().unwrap());
            with_stalled.chain = with_stalled.chain.with_validators(routes).unwrap();
            tokio::time::timeout(
                Duration::from_secs(2),
                crate::client_chain::connect(&with_stalled, Duration::from_secs(30)),
            )
            .await
            .expect("verified peers must not wait for the stalled peer's 5s timeout")
            .unwrap();
            drop(stalled);
            let original = pool.providers.remove(0);
            for endpoint in [&first.endpoint, &second.endpoint] {
                let mut args = original.args.clone();
                args.config = config.clone();
                args.provider = crate::test_identity::address(endpoint.id());
                args.journal_root =
                    crate::paid_client::PaidJournalDir::gateway(&config.chain, args.provider);
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
