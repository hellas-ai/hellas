//! One paid Fetch job through the SDK, against the six-validator devnet.
//!
//! The provider is provisioned with `provision_offer` and served by
//! `start_fetch_provider`; the client runs `run_paid_work`, then settles
//! through a recovered `PaidWorkSession`.
//! Both parties hold genesis allocations owned by software passkeys and
//! read the chain through their own full node. Only block ordering (the
//! devnet's proposer) and the upstream HTTP response are fixtures; the
//! money is read back out of the validators' finalized state.

use std::sync::Arc;
use std::time::Duration;

use hellas_auth::authority::{self as auth, ContactCard, UnixMillis};
use hellas_auth::test_support::actors::{FRIEND, ROOT};
use hellas_auth::{Digest, ProducerSigningKey};
use hellas_chain::LightClient as _;
use hellas_chain::client::RemoteLightClient;
use hellas_chain::domain::SettlementKey;
use hellas_chain::test_support::devnet::{
    Devnet, DevnetConfig, GenesisOwner, OwnerKind, delegate_allocation, run,
};
use hellas_executor::{
    FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchCall, FetchProjector,
    FetchRequestView, MockFetchProvider, PreparedFetchRequest, ProjectedFetch,
};
use hellas_kernel::{CoinId, EdgeValues, Fees, Funding, Key, List, Secp256k1Signer};
use hellas_rpc::output::{OutputEvent, StopReason, TextChannel};
use hellas_rpc::{Assurance, ContentId, Retention, RootProof};
use hellas_sdk::paid_client::{
    PaidWorkOptions, PaidWorkRun, PaidWorkSession, bind_paid_endpoint, run_paid_work,
};
use hellas_sdk::work_config::{ChainCrossCheck, WorkConfig, WorkRoute, WorkRoutes};
use hellas_sdk::work_provision::{ProvisionOptions, preview_bond, provision_offer};
use hellas_sdk::{
    FetchProviderOptions, FetchRoute, FetchRouteEntry, FetchRoutePolicy, FetchRouteRegistry,
    NodeIdentity, PaidProviderOptions, RootProver, start_fetch_provider,
};
use hellas_work::model::fetch::{
    FetchPolicyV2, FetchRoutePolicy as PaidRoute, PreparedPaidFetchInputV1, fetch_route_commitment,
};
use hellas_work::model::profile::WorkPolicy;
use hellas_work::model::work::{JobPaymentPolicyV2, PaidChannelPolicyV1};
use hellas_work::node::NodeCoordinator;
use hellas_work::test_support::common_node::{admin_spec, approval, bootstrap_node};
use hellas_work::test_support::{enrollment, test_responses_contract};
use hellas_work::work_store::grant::NodeStore;

/// The job's flat price.
const PRICE: u64 = 10;
/// The client's genesis allocation, all of which funds the payment edge.
const CLIENT_FUNDING: u64 = 100;
/// The provider's genesis allocation, all of which it stakes. Not equal
/// to [`PRICE`], so returned principal and earnings are told apart.
const PROVIDER_STAKE: u64 = 12;
/// One over half the funding.
const OMISSION_BOND: u64 = 51;
/// The height the bond times out at.
const BOND_TIMEOUT: u64 = 200;
const BODY: &[u8] = br#"{"model":"fixture","input":"sdk-paid-e2e","max_output_tokens":8}"#;

/// The provider's genesis owner: the `ROOT` actor's passkey, which owns
/// its node authority.
const PROVIDER_OWNER: GenesisOwner = GenesisOwner {
    kind: OwnerKind::Passkey,
    seed: 0x11,
    balance: PROVIDER_STAKE,
};
/// The client's genesis owner: the `FRIEND` actor's passkey.
const CLIENT_OWNER: GenesisOwner = GenesisOwner {
    kind: OwnerKind::Passkey,
    seed: 0x13,
    balance: CLIENT_FUNDING,
};

fn client_settlement() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([0x21; 32]).unwrap()
}

fn provider_identity() -> NodeIdentity {
    NodeIdentity::from_secret_bytes([4; 32], [2; 32]).unwrap()
}

fn provider_settlement() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar(provider_identity().node_secret_bytes()).unwrap()
}

fn provider_enrollment() -> hellas_rpc::ProviderEnrollmentBundle {
    enrollment(
        &ProducerSigningKey::from_secret_bytes([1; 32]).unwrap(),
        &ProducerSigningKey::from_secret_bytes([2; 32]).unwrap(),
        *provider_identity().transport_key().public().as_bytes(),
        [3; 32],
    )
}

fn work_policy() -> WorkPolicy {
    let route = PaidRoute::sealed_route("openai", "responses").unwrap();
    WorkPolicy::Fetch {
        contract: test_responses_contract(),
        policy: FetchPolicyV2 {
            allowed_environment: test_responses_contract().manifest_id(),
            route_commitment: fetch_route_commitment(&route.canonical_body_bytes()).unwrap(),
            max_request_body_bytes: 4096,
            max_output_events: 64,
            max_output_bytes: 16384,
            max_spool_bytes: 65536,
            max_encoded_result_frame: 65536,
            max_encoded_prepared_input: 65536,
        },
        route,
    }
}

fn work_config(devnet: &Devnet, journal_root: std::path::PathBuf) -> WorkConfig {
    WorkConfig {
        chain: ChainCrossCheck {
            network: devnet.network(),
            genesis_payload_digest: devnet.genesis_payload().0.into(),
            threshold_identity: devnet.consensus_info().threshold_identity.clone(),
            genesis: Some(devnet.genesis().clone()),
        },
        validators: devnet.light_client_urls(),
        journal_root,
        routes: WorkRoutes::default(),
        policy_salt: [9; 32],
        channel_policy: PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        },
        work_policy: work_policy(),
        payment_policy: JobPaymentPolicyV2 {
            fixed_price: PRICE,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
        },
        poll: Duration::from_millis(20),
        max_observation_age: Duration::from_secs(60),
        expected_payment_values: EdgeValues::new(CLIENT_FUNDING, 0, Fees::ZERO),
        min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
    }
}

/// A node authority owned by `FRIEND`, the client's genesis owner.
async fn client_authority(root: &std::path::Path, now: UnixMillis) -> NodeCoordinator {
    let authority = auth::AuthorityId(Digest::hash(b"paid e2e client authority"));
    let administrator = admin_spec(
        authority,
        FRIEND.principal(),
        &[],
        (now, UnixMillis(u64::MAX)),
        (u64::MAX, auth::MAX_DELEGATION_DEPTH),
        &[],
    );
    let grant = auth::GrantId([0; 16]);
    let (store, _) = NodeStore::bootstrap(
        root,
        hellas_work::model::grant::grant_network(),
        grant,
        approval(
            auth::Ownership::Bootstrap {
                root: grant,
                target: None,
            },
            administrator,
        ),
        None,
        now,
    )
    .await
    .unwrap();
    NodeCoordinator::new(store, Arc::new(move || now))
}

/// The upstream: one programmed response, projected as one text delta and
/// a finished terminal.
fn routes() -> (FetchRouteRegistry, MockFetchProvider) {
    let environment = test_responses_contract().manifest_id();
    let upstream = MockFetchProvider::new(environment);
    upstream.insert("openai", "responses", BODY, [b"upstream".to_vec()]);
    let mut routes = FetchRouteRegistry::new();
    routes
        .register(
            FetchRoute::new("openai", "responses"),
            FetchRouteEntry::new(
                Arc::new(upstream.clone()),
                Arc::new(Adaptor(environment)),
                FetchRoutePolicy::default(),
            )
            .unwrap(),
        )
        .unwrap();
    (routes, upstream)
}

struct Adaptor(ContentId);
impl FetchAdaptorFactory for Adaptor {
    fn execution_environment(&self) -> ContentId {
        self.0
    }
    fn create(&self, call: &FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError> {
        Ok(FetchAdaptorSession {
            request_view: FetchRequestView::from_call(call),
            provider_request: PreparedFetchRequest::new(call, call.body.clone()),
            projector: Box::new(Projector(false)),
        })
    }
}

struct Projector(bool);
impl FetchProjector for Projector {
    fn project(&mut self, _: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if std::mem::replace(&mut self.0, true) {
            return Ok(Vec::new());
        }
        let event = hellas_rpc::fetch::encode_fetch_event_payload(&OutputEvent::TextDelta {
            index: 0,
            delta: "paid-output".into(),
            channel: TextChannel::Output,
        })
        .map_err(|_| FetchAdaptorError::failed("event encodes"))?;
        let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(&OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        })
        .map_err(|_| FetchAdaptorError::failed("terminal encodes"))?;
        Ok(vec![
            ProjectedFetch::Event(event),
            ProjectedFetch::Terminal(terminal),
        ])
    }
    fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        Ok(Vec::new())
    }
}

struct SoftwareRoot;
impl RootProver for SoftwareRoot {
    async fn prove_statement(&self, _: &[u8]) -> Result<RootProof, hellas_sdk::AttestationError> {
        panic!("the software enrollment is already signed")
    }
    async fn prove_open_binding(
        &self,
        _: Digest,
    ) -> Result<RootProof, hellas_sdk::AttestationError> {
        panic!("a software Open is signed by the producer key")
    }
}

/// Drives `work` to completion while sealing a block every `period`, as
/// a live proposer would.
async fn sealing_while<T>(
    devnet: &mut Devnet,
    period: Duration,
    work: impl std::future::Future<Output = T>,
) -> T {
    tokio::time::timeout(Duration::from_secs(120), async {
        let proposer = async {
            loop {
                tokio::time::sleep(period).await;
                devnet.seal().await;
            }
        };
        tokio::pin!(proposer);
        tokio::select! {
            output = work => output,
            () = &mut proposer => unreachable!(),
        }
    })
    .await
    .expect("the SDK phase completes within its deadline")
}

/// The coins `owner` holds at the tip, by value, as validator 0 and the
/// first full node agree they are.
async fn holdings(devnet: &Devnet, owner: SettlementKey) -> Vec<(CoinId, u64)> {
    devnet
        .coins(0, owner, [])
        .await
        .into_iter()
        .map(|(id, coin)| (id, coin.value))
        .collect()
}

/// The provider earns exactly the price from the payment close, and its
/// stake comes back separately, as a different coin, at the bond's
/// timeout.
#[test]
fn a_paid_fetch_job_through_the_sdk_earns_the_price_and_returns_the_stake_separately() {
    run(|runtime| async move {
        let root = tempfile::tempdir().unwrap();
        let now = UnixMillis(1);
        // The genesis owners are the actors whose passkeys own the two
        // node authorities.
        for (owner, actor) in [(PROVIDER_OWNER, ROOT), (CLIENT_OWNER, FRIEND)] {
            assert_eq!(
                owner.key().into_kernel(),
                Key::from_bytes(*actor.principal().as_bytes())
            );
        }
        let mut devnet = Devnet::start(
            runtime,
            DevnetConfig {
                name: "sdk_paid_e2e",
                owners: vec![PROVIDER_OWNER, CLIENT_OWNER],
                full_nodes: 2,
            },
        )
        .await;
        let provider_node = devnet.full_node(0).clone();
        let client_node = devnet.full_node(1).clone();

        // Each owner delegates its allocation to its node's settlement key,
        // submitted through a validator URL by a client with no node.
        devnet.seal().await;
        let (provider_funding, stake_coin) = delegate_allocation(
            devnet.allocations(),
            &PROVIDER_OWNER,
            provider_settlement().party_key().into(),
        );
        let (client_funding, payment_coin) = delegate_allocation(
            devnet.allocations(),
            &CLIENT_OWNER,
            client_settlement().party_key().into(),
        );
        let submitter = RemoteLightClient::connect(devnet.light_client_url(2))
            .await
            .unwrap();
        for tx in [provider_funding, client_funding] {
            assert_eq!(
                submitter.submit_tx(tx).await.unwrap(),
                hellas_chain::SubmitTxOutcome::Enqueued
            );
        }
        devnet.seal().await;

        // The provider: authority, offer, then the served endpoint.
        let provider_authority = NodeCoordinator::new(
            bootstrap_node(
                &root.path().join("provider-authority"),
                hellas_work::model::grant::grant_network(),
                Some(provider_enrollment()),
                now,
            )
            .await
            .unwrap(),
            Arc::new(move || now),
        );
        let client_transport = iroh::SecretKey::from_bytes(&[0x41; 32]);
        let mut options = ProvisionOptions {
            work_config: work_config(&devnet, root.path().join("provider-journal")),
            settlement_key: provider_settlement(),
            provider: provider_enrollment(),
            addresses: vec![],
            client: ContactCard::new(
                FRIEND.principal(),
                "client".into(),
                FRIEND.assert(ContactCard::digest(FRIEND.principal(), "client")),
            )
            .unwrap(),
            client_node: client_settlement().party_key(),
            redelegate_payout: true,
            stake_coins: vec![stake_coin],
            bond_timeout: BOND_TIMEOUT,
            timeout_payout: PROVIDER_STAKE,
            max_job_price: 40,
        };
        let bond = preview_bond(&options, &provider_authority).await.unwrap();
        options.work_config.routes = WorkRoutes::try_from_iter([WorkRoute {
            peer: hellas_sdk::wire::peers::PeerId::from_bytes(
                *client_transport.public().as_bytes(),
            ),
            bond,
            client: client_settlement().party_key(),
        }])
        .unwrap();
        let config = options.work_config.clone();
        let provisioned = provision_offer(options, &provider_node, &provider_authority)
            .await
            .unwrap();
        assert_eq!(provisioned.bond_edge, bond);
        drop(provider_authority);

        let (routes, upstream) = routes();
        let provider = start_fetch_provider(
            FetchProviderOptions {
                port: Some(0),
                identity: provider_identity(),
                enrollment: provider_enrollment(),
                root: Arc::new(SoftwareRoot),
                state_directory: root.path().join("provider-state"),
                grants: None,
                routes,
                fetch_max_in_flight: 1,
                fetch_queue_capacity: 1,
                paid_work: Some(
                    PaidProviderOptions::new(config.clone(), provider_node.clone()).unwrap(),
                ),
            }
            .prepare()
            .await
            .unwrap(),
        )
        .await
        .unwrap();
        let provider_addrs = provider
            .bound_sockets()
            .into_iter()
            .filter(std::net::SocketAddr::is_ipv4)
            .map(|mut addr| {
                addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
                addr
            })
            .collect();

        // The client: one job, paid, then settled.
        let client_producer = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
        let events = hellas_rpc::fetch::build_input_events_with_retention(
            "openai",
            "responses",
            BODY,
            test_responses_contract().manifest_id(),
            Assurance::ProducerSigned,
            &client_producer,
            Retention::Ephemeral,
        )
        .unwrap();
        let prepared_input =
            PreparedPaidFetchInputV1::new(&events, &test_responses_contract()).unwrap();
        let options = PaidWorkOptions {
            config,
            journal_root: root.path().join("client-journal"),
            provider: provider.node_id(),
            provider_addrs,
            provider_trust: hellas_client::ProviderTrustAnchor {
                allowed_environments: vec![test_responses_contract().manifest_id()],
                expected_genesis: provider_enrollment().content_id(),
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            },
            bond,
            payment_funding: Funding::new(
                List::take([payment_coin; hellas_kernel::MAX_PARTY_INPUTS], 1),
                List::empty(CoinId::from_bytes([0; 32])),
            ),
            omission_bond: OMISSION_BOND,
            acceptance_blocks: 16,
            terminal_blocks: 64,
            payment_blocks: 32,
            timeout: Duration::from_secs(120),
        };
        let client_authority = client_authority(&root.path().join("client-authority"), now).await;
        // Setup runs concurrently with node execution. Keep the job on a
        // stable tip because payment readiness expires while its independent
        // observer catches up; setup read recovery is exercised separately.
        let endpoint = bind_paid_endpoint(client_transport.clone()).await.unwrap();
        let open = PaidWorkSession::open(
            options.clone(),
            endpoint.clone(),
            client_settlement(),
            client_node.clone(),
            client_authority.clone(),
        );
        tokio::pin!(open);
        // Let initial readiness succeed, then force the retained source behind
        // while its first setup exchange is in flight.
        tokio::select! {
            result = &mut open => panic!("setup ended before any Open finalized: {}", result.err().map_or_else(|| "unexpected success".into(), |error| error.to_string())),
            () = async {
                while !options.journal_root.exists() {
                    tokio::task::yield_now().await;
                }
            } => {},
        }
        client_node.require_finalized_height_for_test(devnet.height() + 1);
        assert!(client_node.view().is_err());
        assert!(
            tokio::time::timeout(options.config.poll, &mut open)
                .await
                .is_err()
        );
        let mut session = sealing_while(&mut devnet, Duration::from_millis(100), open)
            .await
            .unwrap();
        session.shutdown().await;
        drop(session);
        endpoint.close().await;

        let result = run_paid_work(
            PaidWorkRun {
                options: options.clone(),
                prepared_input: prepared_input.into(),
                settle: false,
            },
            client_transport.clone(),
            client_settlement(),
            client_node.clone(),
            client_authority.clone(),
        )
        .await
        .unwrap();
        let endpoint = bind_paid_endpoint(client_transport).await.unwrap();
        let mut session = tokio::time::timeout(
            options.timeout,
            PaidWorkSession::open(
                options,
                endpoint.clone(),
                client_settlement(),
                client_node,
                client_authority,
            ),
        )
        .await
        .expect("the settled session opens within its deadline")
        .unwrap();
        let settled_provider_payout =
            sealing_while(&mut devnet, Duration::from_millis(100), session.settle())
                .await
                .unwrap();
        session.shutdown().await;
        drop(session);
        endpoint.close().await;

        assert_eq!(result.bond_edge, bond);
        assert_eq!(result.job_price, PRICE);
        assert_eq!(result.credited_cumulative, PRICE, "one job at its price");
        assert_eq!(
            settled_provider_payout, PRICE,
            "the settled close paid the provider the price",
        );
        assert_eq!(upstream.calls("openai", "responses", BODY), 1);

        // Earnings: while the stake is still bonded, the price is the whole
        // of what the provider owner holds.
        let earnings = holdings(&devnet, PROVIDER_OWNER.key()).await;
        assert_eq!(
            earnings.iter().map(|(_, value)| *value).collect::<Vec<_>>(),
            vec![PRICE],
            "EARNINGS: exactly the price, and no principal yet",
        );
        assert_eq!(
            holdings(&devnet, CLIENT_OWNER.key())
                .await
                .iter()
                .map(|(_, value)| *value)
                .collect::<Vec<_>>(),
            vec![CLIENT_FUNDING - PRICE],
            "the client got back its funding less exactly the price",
        );

        // Principal: the provider's own clock times the bond out.
        devnet.seal_through(BOND_TIMEOUT).await;
        let mut held = Vec::new();
        for _ in 0..200 {
            held = holdings(&devnet, PROVIDER_OWNER.key()).await;
            if held.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            devnet.seal().await;
        }
        assert_eq!(
            held.len(),
            2,
            "the bond timeout returned the stake: {held:?}"
        );
        assert_eq!(
            held,
            vec![earnings[0], (held[1].0, PROVIDER_STAKE)],
            "RETURNED PRINCIPAL: the stake, unchanged, beside the unchanged earnings",
        );
        assert_ne!(
            held[1].0, earnings[0].0,
            "principal and earnings are different coins"
        );

        provider.shutdown().await.unwrap();
        devnet.shutdown().await;
    });
}

#[test]
fn setup_reads_recover_after_execution_and_expire_with_a_typed_error() {
    use hellas_chain::WorkBlocks;
    use hellas_work::work_close::{BlockSourceError, FinalizedBlocks as _};
    use hellas_work::work_open::{SetupQuery, SetupView as _};

    run(|runtime| async move {
        let mut devnet = Devnet::start(
            runtime,
            DevnetConfig {
                name: "sdk_setup_reads",
                owners: vec![CLIENT_OWNER],
                full_nodes: 1,
            },
        )
        .await;
        devnet.seal().await;
        let node = devnet.full_node(0).clone();
        let client = node.view().unwrap().client();
        let timeout = hellas_chain::node::RECOVERY_TIMEOUT;
        let poll = work_config(&devnet, std::path::PathBuf::new()).poll;
        let source = WorkBlocks::new(client.clone()).with_read_retry(poll, timeout);
        let query = SetupQuery {
            bond_edge: hellas_kernel::EdgeId::from_bytes([0; 32]),
            payment_edge: hellas_kernel::EdgeId::from_bytes([1; 32]),
            funding: Default::default(),
        };
        let next = devnet.height() + 1;
        node.require_finalized_height_for_test(next);
        assert!(matches!(
            client.get_latest_block().await,
            Err(hellas_chain::QueryError::StateUnavailable(_))
        ));
        let read = source.finalized_setup(query.clone());
        tokio::pin!(read);
        assert!(tokio::time::timeout(poll, &mut read).await.is_err());
        let (snapshot, block) = tokio::join!(read, devnet.seal());
        assert_eq!(snapshot.unwrap().unwrap().height, next);
        assert_eq!(source.latest_height().await.unwrap(), Some(next));
        assert_eq!(
            source.block_at(next).await.unwrap().unwrap().payload,
            hellas_chain::FinalizedBlockView::decode(
                &client
                    .get_finalized_block(hellas_chain::FinalizedBlockQuery::Height(next))
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
            .payload()
            .0
        );
        drop(block);

        node.require_finalized_height_for_test(next + 1);
        let started = tokio::time::Instant::now();
        let error = source.finalized_setup(query).await.unwrap_err();
        assert!(
            matches!(error, BlockSourceError::ReadUnavailableTimeout { timeout: elapsed, .. }
            if elapsed == timeout)
        );
        assert!(started.elapsed() >= timeout);
        // A failed read never advances a journal or makes the stale node usable.
        assert!(node.view().is_err());
        devnet.shutdown().await;
    });
}
