use super::*;
use hellas_auth::test_support::{
    Actor,
    actors::{AGENT, OPERATOR, STRANGER},
};
use hellas_rpc::pb::work::{
    ExchangeSetupRequest, OfferRefusalCode, RequestOfferRequest, RequestOfferResponse,
    exchange_setup_response, request_offer_response::Outcome,
};
use hellas_rpc::services::work_setup::{WorkSetup, WorkSetupServer};
use hellas_sdk::paid_provider::{
    MountedSetup, MountedWork, WorkRunner, WorkRunnerConfig, WorkWatcher,
};
use hellas_sdk::work_router::WorkRouter;
use hellas_wire::{
    Dispatcher, Metadata, ServiceMarker, StreamTransport, WireStatus, iroh::IrohTransport,
};
use hellas_work::model::offer::{SignedPaidOffer, request_digest};
use hellas_work::work::{
    BackendFault, WorkBackend,
    admission::{CapacityDomain, WorkPermit},
};
use hellas_work::work_store::{Role, SetupAbort, SetupEnd, SetupStore};
use iroh::{Endpoint, EndpointAddr, TransportAddr, endpoint::presets};

const JOB_PRICE: u64 = 20;
const FUNDING: u64 = 401;

struct CpuEvaluate(
    Arc<tokio::sync::Semaphore>,
    Arc<std::sync::atomic::AtomicUsize>,
);
impl WorkBackend for CpuEvaluate {
    fn try_admit(&self, domain: CapacityDomain) -> Result<WorkPermit, BackendFault> {
        if domain != CapacityDomain::Gpu {
            return Err(hellas_work::work::admission::AdmissionError::Unsupported(domain).into());
        }
        Ok(WorkPermit::new(
            domain,
            self.0.clone().try_acquire_owned().map_err(|_| {
                BackendFault::from(hellas_work::work::admission::AdmissionError::Capacity)
            })?,
        ))
    }
    async fn execute(
        &self,
        input: hellas_work::work::PreparedWorkInput,
    ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, BackendFault> {
        let hellas_work::work::PreparedWorkInput::Evaluate(input) = input else {
            return Err(BackendFault::caused_by(std::io::Error::other(
                "Evaluate fixture",
            )));
        };
        let (parts, admission) = input.into_parts_and_admission();
        let _running = admission
            .reserve(CapacityDomain::Gpu, async {
                self.try_admit(CapacityDomain::Gpu)
            })
            .await?
            .dispatch()
            .await?;
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let key = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let mut output = hellas_rpc::evaluate::EvaluateOutputTranscriptBuilder::new(
            hellas_rpc::evaluate::input_commitment(&parts.evaluate_request),
            parts.evaluate_request.assurance,
            &key,
        );
        output.push_token_delta(vec![1]).unwrap();
        let usage = hellas_rpc::evaluate::EvaluateUsage {
            input_units: parts.prompt_tokens.as_slice().len() as u64,
            output_units: 1,
        };
        Ok(output
            .finish(hellas_rpc::evaluate::EvaluateTerminal {
                final_position: 1,
                stop_reason: hellas_rpc::evaluate::EvaluateStopReason::STOP_TOKEN,
                matched_stop_token_id: Some(1),
                text_artifact: Digest::hash(b"cpu-evaluate-fixture"),
                usage,
                billable_units: usage.billable_units().unwrap(),
            })
            .unwrap())
    }
}

/// Only arithmetic execution is a double. Setup, Work, journals, clocks and
/// owner signatures use the native services and the six-validator chain.
struct Provider {
    endpoint: Endpoint,
    clock: WorkWatcher,
    serving: tokio::task::JoinHandle<()>,
    admin: hellas_work::grant_service::WorkAdministration,
}
impl Provider {
    fn start<'a>(
        root: &'a std::path::Path,
        config: WorkConfig,
        node: hellas_sdk::FullNode,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    ) -> impl std::future::Future<Output = Self> + 'a {
        Box::pin(Self::start_inner(root, config, node, calls))
    }

    async fn start_inner(
        root: &std::path::Path,
        config: WorkConfig,
        node: hellas_sdk::FullNode,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        let store = NodeStore::open(
            &root.join("authority"),
            hellas_work::model::grant::grant_network(),
            Some(provider_enrollment()),
            UnixMillis(1),
        )
        .await
        .unwrap();
        let authority = NodeCoordinator::new(store, Arc::new(|| UnixMillis(1)));
        let key = Arc::new(ProducerSigningKey::from_secret_bytes([2; 32]).unwrap());
        let grants = hellas_work::grant_service::GrantService::from_node(
            authority.clone(),
            &provider_enrollment(),
            key.clone(),
            hellas_work::test_support::common_node::NoBackend,
            vec![],
        )
        .await
        .unwrap();
        let admin = hellas_work::grant_service::WorkAdministration::new(
            grants,
            vec![],
            std::num::NonZeroU64::new(5000).unwrap(),
        )
        .unwrap();
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(provider_identity().transport_key())
            .alpns(vec![
                WorkSetup::ALPN.as_bytes().to_vec(),
                hellas_rpc::services::work::Work::ALPN.as_bytes().to_vec(),
            ])
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let setup = MountedSetup::default();
        let work =
            MountedWork::with_backend(CpuEvaluate(Arc::new(tokio::sync::Semaphore::new(1)), calls));
        let runner = WorkRunner::discover(
            WorkRunnerConfig {
                network: config.chain.network,
                journal_root: config.journal_root,
                poll: config.poll,
                max_observation_age: config.max_observation_age,
                settlement_key: provider_settlement(),
            },
            work.clone(),
            setup.clone(),
        )
        .await
        .unwrap()
        .on_node(
            node,
            authority,
            provider_enrollment(),
            endpoint
                .bound_sockets()
                .iter()
                .map(ToString::to_string)
                .collect(),
        );
        let clock = WorkWatcher::spawn(runner);
        let router = WorkRouter::payment(work);
        let open = Arc::new(
            hellas_sdk::ProviderOpen::<ProducerSigningKey>::new(key, provider_enrollment(), None)
                .unwrap(),
        );
        let server = endpoint.clone();
        let serving = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Some(incoming) = server.accept().await {
                let setup = setup.clone();
                let router = router.clone();
                let open = open.clone();
                connections.spawn(async move {
                    let connection = incoming.await.unwrap();
                    let is_setup = connection.alpn() == WorkSetup::ALPN.as_bytes();
                    let transport = IrohTransport::new(connection);
                    if is_setup {
                        let dispatcher =
                            hellas_rpc::open::OpenDispatcher::<
                                _,
                                _,
                                hellas_rpc::services::work_setup::Open,
                            >::new(WorkSetupServer(setup), open);
                        while let Ok(Some(inbound)) = transport.accept().await {
                            if Dispatcher::<IrohTransport>::dispatch(&dispatcher, inbound)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    } else {
                        let Ok(dispatcher) = router.accept_iroh(&transport, open).await else {
                            return;
                        };
                        while let Ok(Some(inbound)) = transport.accept().await {
                            if dispatcher.dispatch(inbound).await.is_err() {
                                break;
                            }
                        }
                    }
                });
            }
            while let Some(result) = connections.join_next().await {
                result.unwrap();
            }
        });
        Self {
            endpoint,
            clock,
            serving,
            admin,
        }
    }
    async fn policy(
        &self,
        secret: &auth::CredentialSecret,
        revision: u64,
        policy: hellas_work::model::paid_policy::PaidPolicy,
    ) {
        let node = self.admin.node();
        let caller = hellas_work::test_support::session(&node, secret).await;
        self.admin
            .execute(
                &caller,
                auth::GrantId([0; 16]),
                hellas_work::model::grant::admin::WorkControlCommand::SetPaidPolicy {
                    expected_revision: auth::Revision(revision),
                    policy: Box::new(policy),
                },
            )
            .await
            .unwrap();
    }
    fn addr(&self) -> EndpointAddr {
        EndpointAddr::from_parts(
            self.endpoint.id(),
            self.endpoint
                .bound_sockets()
                .into_iter()
                .map(TransportAddr::Ip),
        )
    }
    async fn shutdown(mut self) {
        self.endpoint.close().await;
        tokio::time::timeout(Duration::from_secs(30), self.clock.shutdown())
            .await
            .unwrap()
            .unwrap();
        self.serving.await.unwrap();
    }
}

async fn connect_offer(client: &Endpoint, provider: &Provider) -> IrohTransport {
    let connection = client
        .connect(provider.addr(), WorkSetup::ALPN.as_bytes())
        .await
        .unwrap();
    let transport = IrohTransport::new(connection);
    hellas_client::confidential_open_selected::<hellas_rpc::services::work_setup::Open>(
        &transport,
        Assurance::ProducerSigned,
        None,
    )
    .await
    .unwrap();
    transport
}

async fn request(
    client: &Endpoint,
    provider: &Provider,
    network: hellas_kernel::NetworkId,
    owner: Actor,
    key: &Secp256k1Signer,
    coins: &[CoinId],
    mutation: Option<&str>,
) -> Result<RequestOfferResponse, WireStatus> {
    let transport = connect_offer(client, provider).await;
    let mut request = RequestOfferRequest {
        client_principal: owner.principal().as_bytes().to_vec(),
        client_key: key.party_key().to_bytes().to_vec(),
        funding_coins: coins.iter().map(|c| c.to_bytes().to_vec()).collect(),
        signature: vec![],
    };
    let mut exporter = transport.context().open_exporter.unwrap();
    if mutation == Some("exporter") {
        exporter[0] ^= 1;
    }
    let signed_network = if mutation == Some("network") {
        hellas_kernel::NetworkId::new("wrong-network").unwrap()
    } else {
        network
    };
    let genesis = if mutation == Some("provider") {
        ContentId::from_bytes([7; 32])
    } else {
        provider_enrollment().content_id()
    };
    let hash = request_digest(signed_network, genesis, &request, &exporter);
    request.signature = key
        .sign(hellas_kernel::PayloadHash::from_bytes(*hash.as_bytes()))
        .as_bytes()
        .to_vec();
    match mutation {
        Some("principal") => request.client_principal = ROOT.principal().as_bytes().to_vec(),
        Some("key") => request.client_key = provider_settlement().party_key().to_bytes().to_vec(),
        Some("coin") => request.funding_coins[0][0] ^= 1,
        Some("signature") => request.signature[0] ^= 1,
        _ => {}
    }
    hellas_rpc::call::unary::<_, hellas_rpc::services::work_setup::RequestOffer>(
        &transport,
        request,
        Metadata::new(),
    )
    .await
}
fn granted(response: RequestOfferResponse) -> SignedPaidOffer {
    let Some(Outcome::Granted(granted)) = response.outcome else {
        panic!("expected offer, got {response:?}")
    };
    SignedPaidOffer::decode(&granted.offer).unwrap()
}
fn refused(response: RequestOfferResponse, code: OfferRefusalCode) {
    let Some(Outcome::Refused(refused)) = response.outcome else {
        panic!("expected refusal, got {response:?}")
    };
    assert_eq!(refused.code, code as i32);
}
fn files(root: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    entries
        .map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() { files(&path) } else { 1 }
        })
        .sum()
}
fn revision_two(
    offer: &SignedPaidOffer,
    key: &Secp256k1Signer,
    funding: Funding,
    omission: u64,
) -> hellas_work::model::bundle::WorkChannelSetupBundleV2 {
    let one = &offer.offer().proposal;
    let policy = &offer.offer().policy;
    let terms = hellas_kernel::WorkPaymentTerms {
        bond_edge: one.bond_edge(),
        bond_terms: one.bond_terms().clone(),
        omission_bond: omission,
        private_policy_commitment: hellas_work::model::work::private_policy_commitment(
            policy.network,
            &policy.policy_salt,
            &policy.channel_policy,
        ),
        omit_response_blocks: policy.min_omit_response_blocks,
        start_validity_blocks: hellas_kernel::MAX_START_VALIDITY_BLOCKS,
    };
    let payment = hellas_kernel::Tx::open_hash(
        policy.network,
        &funding,
        &hellas_kernel::Terms::work_payment(terms.clone()),
    );
    one.clone()
        .countersign_bond_and_propose_payment(
            hellas_kernel::PartyAuth::signer(key.sign(one.bond_open_hash())),
            funding,
            terms,
            hellas_kernel::PartyAuth::signer(key.sign(payment)),
        )
        .unwrap()
}

async fn evaluate_and_settle(
    devnet: &mut Devnet,
    options: PaidWorkOptions,
    endpoint: &Endpoint,
    key: &Secp256k1Signer,
    root: &std::path::Path,
    provider: &Provider,
    original: &SignedPaidOffer,
) {
    let authority = client_authority(&root.join("client-authority"), UnixMillis(1)).await;
    let client_node = devnet.full_node(1).clone();
    let coin = original
        .offer()
        .payment_funding
        .maker()
        .iter()
        .next()
        .copied()
        .unwrap();
    let mut session = sealing_while(
        devnet,
        Duration::from_millis(100),
        PaidWorkSession::open(
            options,
            endpoint.clone(),
            key.clone(),
            client_node,
            authority,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        session.descriptor().bond_edge(),
        original.offer().proposal.bond_edge()
    );
    // Idempotence survives consumption of the originally proven payment coins.
    assert_eq!(
        granted(
            request(
                endpoint,
                provider,
                devnet.network(),
                FRIEND,
                key,
                &[coin],
                None
            )
            .await
            .unwrap()
        )
        .encode()
        .unwrap(),
        original.encode().unwrap()
    );
    eprintln!("automatic: opened; evaluating");
    let result = session
        .run(
            Some(hellas_work::test_support::paid::bundle(7).into()),
            false,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    eprintln!("automatic: evaluated; settling");
    assert_eq!(result.job_price, JOB_PRICE);
    assert_eq!(result.credited_cumulative, JOB_PRICE);
    assert_eq!(
        sealing_while(devnet, Duration::from_millis(100), session.settle())
            .await
            .unwrap(),
        JOB_PRICE
    );
    eprintln!("automatic: settled");
    session.shutdown().await;
    drop(session);
}

pub(super) fn frame_size() -> usize {
    fn bytes<A, F: std::future::Future>(_: impl FnOnce(A) -> F) -> usize {
        std::mem::size_of::<F>()
    }
    bytes(exercise_inner)
}

pub(super) fn exercise(
    runtime: commonware_runtime::tokio::Context,
) -> impl std::future::Future<Output = ()> {
    eprintln!("automatic future bytes {}", frame_size());
    Box::pin(exercise_inner(runtime))
}

async fn exercise_inner(runtime: commonware_runtime::tokio::Context) {
    eprintln!("automatic: begin");
    let root = tempfile::tempdir().unwrap();
    let owners = [
        GenesisOwner {
            kind: OwnerKind::Passkey,
            seed: 0x11,
            balance: 39,
        },
        GenesisOwner {
            kind: OwnerKind::Passkey,
            seed: 0x13,
            balance: FUNDING,
        },
        GenesisOwner {
            kind: OwnerKind::Passkey,
            seed: 0x12,
            balance: FUNDING,
        },
        GenesisOwner {
            kind: OwnerKind::Passkey,
            seed: 0x14,
            balance: FUNDING,
        },
        GenesisOwner {
            kind: OwnerKind::Passkey,
            seed: 0x16,
            balance: FUNDING,
        },
    ];
    let actors = [ROOT, FRIEND, OPERATOR, AGENT, STRANGER];
    let keys: Vec<_> = [2, 0x21, 0x23, 0x24, 0x25]
        .into_iter()
        .map(|n| Secp256k1Signer::from_secret_scalar([n; 32]).unwrap())
        .collect();
    let mut devnet = Devnet::start(
        runtime,
        DevnetConfig {
            name: "sdk_automatic_offers",
            owners: owners.to_vec(),
            full_nodes: 2,
        },
    )
    .await;
    devnet.seal().await;
    let chain = RemoteLightClient::connect(devnet.light_client_url(0))
        .await
        .unwrap();
    let mut payment_coins = Vec::new();
    for index in 0..owners.len() {
        assert_eq!(
            owners[index].key().into_kernel().to_bytes(),
            *actors[index].principal().as_bytes()
        );
        let (tx, coin) = delegate_allocation(
            devnet.allocations(),
            &owners[index],
            keys[index].party_key().into(),
        );
        if index == 0 {
            let hellas_chain::domain::Transaction::Kernel(hellas_kernel::Tx::Owner(reshape)) = tx
            else {
                panic!("owner delegation")
            };
            let selected: Vec<_> = reshape.inputs().iter().copied().collect();
            let plan = hellas_sdk::coin_owner::OwnerReshape::prepare(
                &chain,
                devnet.network(),
                owners[0].key().into_kernel(),
                &selected,
                Some(keys[0].party_key()),
                Some(12),
            )
            .await
            .unwrap();
            assert_eq!(plan.outputs().len(), 4);
            let outputs: Vec<_> = plan.outputs().iter().cloned().collect();
            assert_eq!(
                outputs.iter().map(|p| p.value()).collect::<Vec<_>>(),
                vec![12, 12, 12, 3]
            );
            assert_eq!(
                outputs[3],
                hellas_kernel::Payout::new(owners[0].key().into_kernel(), 3)
            );
            assert!(
                plan.clone()
                    .authorize(hellas_kernel::Auth::native(
                        keys[0].sign(plan.payload_hash())
                    ))
                    .is_err(),
                "node delegation never grants reshape authority"
            );
            let tx = plan
                .clone()
                .authorize(owners[0].authorize(plan.payload_hash()))
                .unwrap();
            chain
                .submit_tx(hellas_chain::domain::Transaction::Kernel(tx))
                .await
                .unwrap();
        } else {
            chain.submit_tx(tx).await.unwrap();
        }
        payment_coins.push(coin);
    }
    devnet.seal().await;
    let (store, secret) = hellas_work::test_support::common_node::bootstrap_node_with_credential(
        &root.path().join("authority"),
        hellas_work::model::grant::grant_network(),
        Some(provider_enrollment()),
        UnixMillis(1),
    )
    .await
    .unwrap();
    drop(store);
    let config = work_config(&devnet, root.path().join("paid"));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut provider = Provider::start(
        root.path(),
        config.clone(),
        devnet.full_node(0).clone(),
        calls.clone(),
    )
    .await;
    let endpoint = bind_paid_endpoint(iroh::SecretKey::from_bytes(&[0x43; 32]))
        .await
        .unwrap();
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[1],
            &[],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NoPolicy,
    );
    assert_eq!(files(&config.journal_root), 0);
    let mut policy = paid_policy();
    policy.work_policy = hellas_work::test_support::paid::work_policy().into();
    policy.payment_policy.fixed_price = JOB_PRICE;
    policy.expected_payment_values = EdgeValues::new(FUNDING, 0, Fees::ZERO);
    policy.offers.omission_bond = 201;
    policy.offers.max_open_offers = 2;
    provider.policy(&secret, 0, policy.clone()).await;
    for field in [
        "principal",
        "key",
        "coin",
        "signature",
        "network",
        "provider",
        "exporter",
    ] {
        assert!(
            request(
                &endpoint,
                &provider,
                devnet.network(),
                FRIEND,
                &keys[1],
                &[payment_coins[1]],
                Some(field)
            )
            .await
            .is_err(),
            "signed {field}"
        );
    }
    assert_eq!(files(&config.journal_root), 0);
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            ROOT,
            &keys[1],
            &[payment_coins[1]],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NeedsFunding,
    );
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[2],
            &[payment_coins[1]],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NeedsFunding,
    );
    let stake = devnet
        .light_client(0)
        .get_coins_by_delegate(keys[0].party_key().into())
        .await
        .unwrap()
        .unwrap()
        .coins[0]
        .0;
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            ROOT,
            &keys[0],
            &[CoinId::from_bytes(stake.0)],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NeedsFunding,
    );
    let quote = request(
        &endpoint,
        &provider,
        devnet.network(),
        FRIEND,
        &keys[1],
        &[],
        None,
    )
    .await
    .unwrap();
    let Some(Outcome::Quote(quote)) = quote.outcome else {
        panic!("quote")
    };
    assert_eq!(quote.funding_value, FUNDING);
    assert_eq!(files(&config.journal_root), 0);
    std::fs::write(&config.journal_root, b"blocked journal root").unwrap();
    assert!(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[1],
            &[payment_coins[1]],
            None
        )
        .await
        .is_err()
    );
    std::fs::remove_file(&config.journal_root).unwrap();
    assert!(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[1],
            &[payment_coins[1]],
            None
        )
        .await
        .is_err(),
        "an ambiguous durable failure cannot be followed by another allocation"
    );
    provider.shutdown().await;
    provider = Provider::start(
        root.path(),
        config.clone(),
        devnet.full_node(0).clone(),
        calls.clone(),
    )
    .await;
    let first = granted(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[1],
            &[payment_coins[1]],
            None,
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        quote.provider_channel_policy,
        hellas_rpc::protocol::value::encode_bounded(
            &first.offer().policy,
            hellas_work::model::grant::records::MAX_OFFER_BYTES
        )
        .unwrap()
    );
    let before = files(&config.journal_root);
    assert!(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[2],
            &[payment_coins[1]],
            None
        )
        .await
        .is_err(),
        "one live offer per principal"
    );
    assert!(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            OPERATOR,
            &keys[1],
            &[payment_coins[2]],
            None
        )
        .await
        .is_err(),
        "one live offer per key"
    );
    assert_eq!(
        granted(
            request(
                &endpoint,
                &provider,
                devnet.network(),
                FRIEND,
                &keys[1],
                &[payment_coins[1]],
                None
            )
            .await
            .unwrap()
        )
        .encode()
        .unwrap(),
        first.encode().unwrap()
    );
    assert_eq!(files(&config.journal_root), before);
    let other_peer = bind_paid_endpoint(iroh::SecretKey::from_bytes(&[0x44; 32]))
        .await
        .unwrap();
    assert_eq!(
        granted(
            request(
                &other_peer,
                &provider,
                devnet.network(),
                FRIEND,
                &keys[1],
                &[payment_coins[1]],
                None
            )
            .await
            .unwrap()
        )
        .encode()
        .unwrap(),
        first.encode().unwrap()
    );
    let transport = connect_offer(&other_peer, &provider).await;
    let denied = hellas_rpc::call::unary::<_, hellas_rpc::services::work_setup::ExchangeSetup>(
        &transport,
        ExchangeSetupRequest {
            bond_edge: first.offer().proposal.bond_edge().to_bytes().to_vec(),
            bundle: vec![],
        },
        Metadata::new(),
    )
    .await
    .unwrap();
    assert!(matches!(
        denied.outcome,
        Some(exchange_setup_response::Outcome::Refused(_))
    ));
    other_peer.close().await;
    for change in ["omission", "funding"] {
        let mut funding = first.offer().payment_funding.clone();
        if change == "funding" {
            funding = Funding::new(
                List::take([CoinId::from_bytes([0xee; 32]); 4], 1),
                List::empty(CoinId::from_bytes([0; 32])),
            );
        }
        let proposal = revision_two(
            &first,
            &keys[1],
            funding,
            if change == "omission" { 300 } else { 201 },
        );
        let transport = connect_offer(&endpoint, &provider).await;
        let refused =
            hellas_rpc::call::unary::<_, hellas_rpc::services::work_setup::ExchangeSetup>(
                &transport,
                ExchangeSetupRequest {
                    bond_edge: first.offer().proposal.bond_edge().to_bytes().to_vec(),
                    bundle: proposal.encode(),
                },
                Metadata::new(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                refused.outcome,
                Some(exchange_setup_response::Outcome::Refused(_))
            ),
            "changed {change} cannot get a provider payment signature"
        );
    }
    let second = granted(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            OPERATOR,
            &keys[2],
            &[payment_coins[2]],
            None,
        )
        .await
        .unwrap(),
    );
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            AGENT,
            &keys[3],
            &[payment_coins[3]],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::OfferLimit,
    );
    policy.offers.max_open_offers = 3;
    provider.policy(&secret, 1, policy.clone()).await;
    let third = granted(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            AGENT,
            &keys[3],
            &[payment_coins[3]],
            None,
        )
        .await
        .unwrap(),
    );
    // Simulate a client interrupted after accepting revision one. Its funding
    // stays live; recovery after the horizon must ask for a fresh offer.
    let interrupted_root = root.path().join("interrupted-client");
    let mut interrupted = SetupStore::open(
        &interrupted_root,
        devnet.network(),
        third.offer().proposal.bond_edge(),
        Role::Client,
        &hellas_kernel::Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    interrupted
        .commit(
            hellas_work::work_store::SetupRecord::Offer {
                peer: *provider.endpoint.id().as_bytes(),
                floor: None,
                offer: Box::new(third.clone()),
            },
            &hellas_kernel::Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
    drop(interrupted);
    policy.offers.max_open_offers = 4;
    provider.policy(&secret, 2, policy.clone()).await;
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            STRANGER,
            &keys[4],
            &[payment_coins[4]],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NoStakeAvailable,
    );
    let reserved: std::collections::BTreeSet<_> = [&first, &second, &third]
        .into_iter()
        .flat_map(|o| o.offer().proposal.bond_funding().maker().iter().copied())
        .collect();
    assert_eq!(
        reserved.len(),
        3,
        "automatic offers use disjoint owner-delegated stake"
    );
    for offer in [&first, &second, &third] {
        assert_eq!(offer.offer().proposal.bond_funding().maker().len(), 1);
        assert_eq!(
            offer
                .offer()
                .proposal
                .bond_terms()
                .timeout_outputs
                .iter()
                .map(|p| p.value())
                .sum::<u64>(),
            12
        );
    }
    // A restart reads both standing terms and original offers from their journals.
    provider.shutdown().await;
    provider = Provider::start(
        root.path(),
        config.clone(),
        devnet.full_node(0).clone(),
        calls.clone(),
    )
    .await;
    assert_eq!(
        provider
            .admin
            .node()
            .paid_policy()
            .await
            .unwrap()
            .unwrap()
            .revision,
        auth::Revision(3)
    );
    assert_eq!(
        granted(
            request(
                &endpoint,
                &provider,
                devnet.network(),
                FRIEND,
                &keys[1],
                &[payment_coins[1]],
                None
            )
            .await
            .unwrap()
        )
        .encode()
        .unwrap(),
        first.encode().unwrap()
    );
    let options = PaidWorkOptions {
        config: config.clone(),
        journal_root: root.path().join("client"),
        provider: provider.endpoint.id(),
        provider_addrs: provider.endpoint.bound_sockets(),
        assurance: Assurance::ProducerSigned,
        apple_trust: None,
        expected_price: JOB_PRICE,
        payment_funding: first.offer().payment_funding.clone(),
        acceptance_blocks: 16,
        terminal_blocks: 64,
        payment_blocks: 32,
        timeout: Duration::from_secs(120),
    };
    Box::pin(evaluate_and_settle(
        &mut devnet,
        options.clone(),
        &endpoint,
        &keys[1],
        root.path(),
        &provider,
        &first,
    ))
    .await;
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        holdings(&devnet, owners[1].key())
            .await
            .iter()
            .map(|(_, v)| *v)
            .sum::<u64>(),
        FUNDING - JOB_PRICE
    );
    // A malicious no-show can post its countersigned bond alone. The same
    // production clock reclaims it without waiting for a payment proposal.
    let partial = revision_two(
        &second,
        &keys[2],
        second.offer().payment_funding.clone(),
        201,
    );
    chain
        .submit_tx(hellas_chain::domain::Transaction::Kernel(
            partial.bond_open().unwrap(),
        ))
        .await
        .unwrap();
    devnet.seal().await;
    let unposted: std::collections::BTreeSet<_> = [&second, &third]
        .into_iter()
        .flat_map(|o| o.offer().proposal.bond_funding().maker().iter().copied())
        .collect();
    for _ in 0..20 {
        if holdings(&devnet, owners[0].key())
            .await
            .iter()
            .any(|(id, v)| *v == 12 && !unposted.contains(id))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        devnet.seal().await;
    }
    assert!(
        holdings(&devnet, owners[0].key())
            .await
            .iter()
            .any(|(id, v)| *v == 12 && !unposted.contains(id)),
        "partial bond reclaimed by runner"
    );
    assert!(
        chain.get_latest_block().await.unwrap().unwrap().height
            < second.offer().proposal.bond_terms().timeout.get()
    );
    eprintln!("automatic: expiry");
    let expiry = [&first, &second, &third]
        .into_iter()
        .map(|o| o.offer().proposal.bond_terms().timeout.get())
        .max()
        .unwrap();
    devnet.seal_through(expiry).await;
    for _ in 0..200 {
        if holdings(&devnet, owners[0].key())
            .await
            .iter()
            .map(|(_, v)| *v)
            .sum::<u64>()
            == 39 + JOB_PRICE
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        devnet.seal().await;
    }
    let held = holdings(&devnet, owners[0].key()).await;
    assert_eq!(held.iter().map(|(_, v)| *v).sum::<u64>(), 39 + JOB_PRICE);
    assert_eq!(held.iter().filter(|(_, v)| *v == 12).count(), 3);
    assert_eq!(held.iter().filter(|(_, v)| *v == JOB_PRICE).count(), 1);
    let transport = connect_offer(&endpoint, &provider).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = hellas_rpc::call::unary::<_,hellas_rpc::services::work_setup::ExchangeSetup>(
                &transport, ExchangeSetupRequest { bond_edge: third.offer().proposal.bond_edge().to_bytes().to_vec(), bundle: vec![] }, Metadata::new(),
            ).await.unwrap();
            if matches!(response.outcome, Some(exchange_setup_response::Outcome::Refused(ref r)) if r.code == hellas_work::work::WorkRefusal::Expired.code() as i32) { break; }
            tokio::time::sleep(config.poll).await;
        }
    }).await.expect("the unanswered offer durably expires at its horizon");
    drop(transport);
    provider.shutdown().await;
    let store = SetupStore::open(
        &config.journal_root,
        devnet.network(),
        third.offer().proposal.bond_edge(),
        Role::Provider,
        &hellas_kernel::Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        store.state().end(),
        Some(SetupEnd::Aborted(SetupAbort::BondOpenExpired))
    );
    drop(store);
    provider = Provider::start(
        root.path(),
        config.clone(),
        devnet.full_node(0).clone(),
        calls.clone(),
    )
    .await;
    policy.offers.max_stake_per_client = 11;
    provider.policy(&secret, 3, policy.clone()).await;
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            STRANGER,
            &keys[4],
            &[payment_coins[4]],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NoStakeAvailable,
    );
    policy.offers.max_stake_per_client = 12;
    provider.policy(&secret, 4, policy).await;
    eprintln!("automatic: fresh after expiry");
    let mut fresh_args = options;
    fresh_args.journal_root = interrupted_root;
    fresh_args.provider_addrs = provider.endpoint.bound_sockets();
    fresh_args.payment_funding = third.offer().payment_funding.clone();
    let agent_authority =
        client_authority_for(&root.path().join("agent-authority"), UnixMillis(1), AGENT).await;
    let client_node = devnet.full_node(1).clone();
    let mut fresh = sealing_while(
        &mut devnet,
        Duration::from_millis(100),
        PaidWorkSession::open(
            fresh_args,
            endpoint.clone(),
            keys[3].clone(),
            client_node,
            agent_authority,
        ),
    )
    .await
    .unwrap();
    assert_ne!(
        fresh.descriptor().bond_edge(),
        third.offer().proposal.bond_edge(),
        "expired client revision one cannot pin recovery to a dead offer"
    );
    assert_eq!(
        sealing_while(&mut devnet, Duration::from_millis(100), fresh.settle())
            .await
            .unwrap(),
        0
    );
    fresh.shutdown().await;
    drop(fresh);
    provider.shutdown().await;
    endpoint.close().await;
    devnet.shutdown().await;
}
