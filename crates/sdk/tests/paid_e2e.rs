//! One paid Fetch job through the SDK, against the six-validator devnet.
//!
//! The provider creates its offer over RPC under its owner-approved policy; the client runs `transact`, then settles
//! through a recovered `PaidWorkSession`.
//! Both parties hold genesis allocations owned by software passkeys and
//! authenticate remote reads; only the provider runs a full node. Only block ordering (the
//! devnet's proposer) and the upstream HTTP response are fixtures; the
//! money is read back out of the validators' finalized state.

// The executor re-executes this binary as its Catena compile child.
#[ctor::ctor(unsafe)]
fn catena_child() {
    if hellas_executor::child_main().unwrap() {
        std::process::exit(0);
    }
}

#[path = "paid_e2e/automatic.rs"]
mod automatic;
#[path = "paid_e2e/gateway.rs"]
mod gateway;
#[path = "paid_e2e/remote.rs"]
mod remote;

use std::sync::Arc;
use std::time::Duration;

use hellas_auth::authority::{self as auth, UnixMillis};
use hellas_auth::test_support::actors::{FRIEND, ROOT};
use hellas_auth::{Digest, ProducerSigningKey};
use hellas_authority::node::NodeCoordinator;
use hellas_authority::work_store::grant::NodeStore;
use hellas_chain::client::RemoteLightClient;
use hellas_chain::domain::SettlementKey;
use hellas_chain::test_support::devnet::{
    Devnet, DevnetConfig, GenesisOwner, OwnerKind, delegate_allocation, run,
};
use hellas_chain::{FinalizedWorkView as _, LightClient as _};
use hellas_channel::content::InvocationContent;
use hellas_channel::model::work::{JobPaymentPolicyV2, PaidChannelPolicyV1};
use hellas_channel::test_support::{enrollment, test_responses_contract};
use hellas_executor::{
    FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchCall, FetchProjector,
    FetchRequestView, MockFetchProvider, PreparedFetchRequest, ProjectedFetch,
};
use hellas_kernel::{CoinId, EdgeValues, Fees, Funding, Key, List, Secp256k1Signer};
use hellas_rpc::output::{OutputEvent, StopReason, TextChannel};
use hellas_rpc::protocol::invocation::{
    self as invocation, Admission, InvocationPolicy, Limits, PreparedInvocation,
};
use hellas_rpc::{Assurance, ContentId, Retention, RootProof};
use hellas_sdk::paid_client::{PaidWorkOptions, PaidWorkSession, bind_paid_endpoint};
use hellas_sdk::work_config::{ChainCrossCheck, WorkConfig};
use hellas_sdk::{
    FetchProviderOptions, FetchRoute, FetchRouteEntry, FetchRoutePolicy, FetchRouteRegistry,
    NodeIdentity, PaidProviderOptions, RootProver, start_fetch_provider,
};
use invocation::fetch::{FetchAdmission, FetchLimits, FetchRoutePolicy as PaidRoute};

/// The job's flat price.
const PRICE: u64 = 10;
/// The client's genesis allocation, all of which funds the payment edge.
const CLIENT_FUNDING: u64 = 201;
/// The provider's genesis allocation, all of which it stakes. Not equal
/// to [`PRICE`], so returned principal and earnings are told apart.
const PROVIDER_STAKE: u64 = 12;
/// One over half the funding.
const OMISSION_BOND: u64 = 101;
/// The height the bond times out at.
const BOND_TIMEOUT: u64 = 200;
const OFFLINE_OWNER: GenesisOwner = GenesisOwner {
    kind: OwnerKind::Native,
    secret_scalar: [0x18; 32],
    balance: 1,
};
const BODY: &[u8] = br#"{"model":"fixture","input":"sdk-paid-e2e","max_output_tokens":8}"#;

/// The provider's genesis owner: the `ROOT` actor's passkey, which owns
/// its node authority.
const PROVIDER_OWNER: GenesisOwner = GenesisOwner {
    kind: OwnerKind::Passkey,
    secret_scalar: [0x11; 32],
    balance: PROVIDER_STAKE,
};
/// The client's genesis owner: the `FRIEND` actor's passkey.
const CLIENT_OWNER: GenesisOwner = GenesisOwner {
    kind: OwnerKind::Passkey,
    secret_scalar: [0x13; 32],
    balance: 3 * CLIENT_FUNDING,
};

fn client_settlement() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([0x21; 32]).unwrap()
}

fn provider_identity() -> NodeIdentity {
    NodeIdentity::from_secret_bytes(iroh::SecretKey::generate().to_bytes(), [2; 32]).unwrap()
}

fn provider_settlement() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([2; 32]).unwrap()
}

fn provider_enrollment(identity: &NodeIdentity) -> hellas_rpc::ProviderEnrollmentBundle {
    enrollment(
        &ProducerSigningKey::from_secret_bytes([1; 32]).unwrap(),
        &ProducerSigningKey::from_secret_bytes([2; 32]).unwrap(),
        *identity.transport_key().public().as_bytes(),
        [3; 32],
    )
}

/// A valid, root-signed enrollment of the same node that the provider does not present.
fn other_provider(options: &PaidWorkOptions) -> PaidWorkOptions {
    let other = enrollment(
        &ProducerSigningKey::from_secret_bytes([7; 32]).unwrap(),
        &ProducerSigningKey::from_secret_bytes([8; 32]).unwrap(),
        *options.provider.node.as_bytes(),
        [3; 32],
    );
    let address = hellas_sdk::client::ProviderAddress::of(&other).unwrap();
    assert_eq!(address.node, options.provider.node);
    assert_ne!(address.enrollment, options.provider.enrollment);
    PaidWorkOptions {
        provider: address,
        ..options.clone()
    }
}

/// A buyer addressing another enrollment of this node is refused before it
/// signs a request, approves funding or writes a channel journal.
async fn check_other_enrollment_refused(
    options: &PaidWorkOptions,
    endpoint: &iroh::Endpoint,
    owner: Arc<hellas_sdk::client_owner::ClientOwner>,
    approvals: &Approvals,
) {
    let mut elsewhere = other_provider(options);
    elsewhere.journal_root = options.journal_root.with_file_name("elsewhere-journal");
    let refused = |error: String| {
        assert!(error.contains("genesis pin mismatch"), "{error}");
    };
    refused(
        hellas_sdk::paid_client::request_paid_quote(
            &elsewhere,
            endpoint,
            &client_settlement(),
            FRIEND.principal(),
        )
        .await
        .expect_err("quote from another enrollment")
        .to_string(),
    );
    refused(
        PaidWorkSession::open(
            elsewhere.clone(),
            endpoint.clone(),
            client_settlement(),
            owner.clone(),
        )
        .await
        .err()
        .expect("channel with another enrollment")
        .to_string(),
    );
    let mut gateway = elsewhere.clone();
    gateway.journal_root = options.journal_root.with_file_name("elsewhere-gateway");
    let error = hellas_sdk::paid_gateway::PaidGateway::open(
        hellas_sdk::paid_gateway::PaidGatewayOptions {
            providers: vec![gateway],
            max_pending_requests: 1,
        },
        NodeIdentity::from_secret_bytes(iroh::SecretKey::generate().to_bytes(), [0x21; 32])
            .unwrap(),
        owner,
    )
    .await
    .err()
    .expect("pool with another enrollment");
    refused(format!("{error:#}"));
    assert!(
        approvals.0.lock().unwrap().is_empty(),
        "another enrollment never reaches funding"
    );
    assert!(
        hellas_channel::work_store::discover_setups(
            &elsewhere.journal_root,
            elsewhere.config.chain.network
        )
        .await
        .unwrap()
        .setups
        .is_empty()
    );
}

/// A job naming a contract the provider's policy does not admit: the
/// provider's own contract under another driver.
fn other_contract_job() -> hellas_sdk::job::Job {
    let admitted = test_responses_contract();
    let other = hellas_rpc::FetchContract::new(
        admitted.adaptor(),
        admitted.schema(),
        "openai-responses-driver-9.9.9",
        admitted.egress().clone(),
    )
    .unwrap();
    assert_ne!(other, admitted);
    hellas_sdk::job::Job::fetch(
        PRICE,
        other,
        "openai".into(),
        "responses".into(),
        BODY.to_vec(),
        Assurance::ProducerSigned,
    )
    .unwrap()
}

/// The buyer's named contract is checked against the quoted, retained and
/// recovered policy before any funding approval.
async fn check_other_contract_refused(
    options: &PaidWorkOptions,
    endpoint: &iroh::Endpoint,
    owner: Arc<hellas_sdk::client_owner::ClientOwner>,
    approvals: &Approvals,
) {
    let funded = approvals.0.lock().unwrap().len();
    let error = PaidWorkSession::open_for_job(
        options.clone(),
        endpoint.clone(),
        client_settlement(),
        owner,
        &other_contract_job(),
    )
    .await
    .err()
    .expect("a job under a contract the policy does not admit");
    assert!(
        matches!(error, hellas_sdk::paid_client::PaidClientError::Job(_)),
        "{error}"
    );
    assert_eq!(approvals.0.lock().unwrap().len(), funded);
}

fn work_policy() -> InvocationPolicy {
    InvocationPolicy {
        admissions: vec![Admission::Fetch {
            admission: FetchAdmission {
                contract: test_responses_contract(),
                route: PaidRoute::sealed_route("openai", "responses").unwrap(),
                limits: FetchLimits {
                    max_request_body_bytes: 4096,
                    max_output_events: 64,
                    max_spool_bytes: 65536,
                    max_encoded_result_frame: 65536,
                    max_encoded_prepared_input: 65536,
                },
            },
        }],
        limits: Limits {
            max_upload_bytes: 65536,
            max_output_bytes: 16384,
            max_steps: 1,
            execution_timeout_ms: 5000,
        },
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
        poll: Duration::from_millis(20),
        max_observation_age: Duration::from_secs(60),
    }
}

fn paid_policy() -> hellas_channel::model::paid_policy::PaidPolicy {
    hellas_channel::model::paid_policy::PaidPolicy {
        channel_policy: PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        },
        invocation_policy: work_policy(),
        payment_policy: JobPaymentPolicyV2 {
            fixed_price: PRICE,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
        },
        expected_payment_values: EdgeValues::new(CLIENT_FUNDING, 0, Fees::ZERO),
        min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        jobs_per_channel: 10,
        offers: hellas_channel::model::paid_policy::OfferPolicy {
            max_stake_per_client: PROVIDER_STAKE,
            bond_lifetime_blocks: BOND_TIMEOUT,
            max_open_offers: 2,
            omission_bond: OMISSION_BOND,
            redelegate_payout: true,
        },
    }
}

async fn start_provider(
    root: &std::path::Path,
    config: WorkConfig,
    node: hellas_sdk::FullNode,
    identity: &NodeIdentity,
) -> (hellas_sdk::ProviderHandle, PausedFetch) {
    let (routes, upstream) = routes();
    let provider = start_fetch_provider(
        FetchProviderOptions {
            port: Some(0),
            identity: identity.clone(),
            enrollment: provider_enrollment(identity),
            root: Arc::new(SoftwareRoot),
            state_directory: root.join("provider-state"),
            grants: Some(hellas_sdk::GrantProviderOptions {
                policies: vec![],
                max_job_millis: std::num::NonZeroU64::new(5000).unwrap(),
            }),
            routes,
            fetch_max_in_flight: 1,
            fetch_queue_capacity: 1,
            paid_work: Some(PaidProviderOptions::new(config, node).unwrap()),
        }
        .prepare()
        .await
        .unwrap(),
    )
    .await
    .unwrap();
    (provider, upstream)
}

fn addresses(provider: &hellas_sdk::ProviderHandle) -> Vec<std::net::SocketAddr> {
    provider
        .bound_sockets()
        .into_iter()
        .filter(std::net::SocketAddr::is_ipv4)
        .map(|mut a| {
            a.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
            a
        })
        .collect()
}

#[derive(Default)]
struct Approvals(std::sync::Mutex<Vec<Digest>>, tokio::sync::Notify);
#[async_trait::async_trait]
impl hellas_authority::authenticator::Authenticator for Approvals {
    fn public_key(
        &self,
    ) -> Result<hellas_authority::authenticator::PublicKey, auth::AuthorityError> {
        hellas_authority::authenticator::Authenticator::public_key(&FRIEND.passkey())
    }
    async fn assert(
        &self,
        challenge: Digest,
    ) -> Result<auth::PasskeyAssertion, auth::AuthorityError> {
        self.0.lock().unwrap().push(challenge);
        self.1.notify_one();
        hellas_authority::authenticator::Authenticator::assert(&FRIEND.passkey(), challenge).await
    }
}

/// The upstream: one programmed response, projected as one text delta and
/// a finished terminal.
#[derive(Clone)]
struct PausedFetch {
    inner: MockFetchProvider,
    pause: Arc<std::sync::atomic::AtomicBool>,
    fail: Arc<std::sync::atomic::AtomicBool>,
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
impl hellas_executor::FetchProvider for PausedFetch {
    fn execution_environment(&self) -> ContentId {
        hellas_executor::FetchProvider::execution_environment(&self.inner)
    }
    fn run(&self, request: PreparedFetchRequest) -> hellas_executor::FetchProviderFuture<'_> {
        Box::pin(async move {
            if self.fail.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(hellas_executor::FetchProviderError::failed(
                    "upstream unavailable",
                ));
            }
            let response = hellas_executor::FetchProvider::run(&self.inner, request).await?;
            if self.pause.load(std::sync::atomic::Ordering::SeqCst) {
                self.started.notify_one();
                self.release.notified().await;
                eprintln!("h6: gated upstream released");
            }
            Ok(response)
        })
    }
}
impl PausedFetch {
    fn calls(&self, service: &str, method: &str, body: &[u8]) -> usize {
        self.inner.calls(service, method, body)
    }
}
fn routes() -> (FetchRouteRegistry, PausedFetch) {
    let environment = test_responses_contract().manifest_id();
    let upstream = MockFetchProvider::new(environment);
    upstream.insert("openai", "responses", BODY, [b"upstream".to_vec()]);
    let upstream = PausedFetch {
        inner: upstream,
        pause: Arc::default(),
        fail: Arc::default(),
        started: Arc::default(),
        release: Arc::default(),
    };
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
        tokio::pin!(work);
        loop {
            tokio::select! {
                output = &mut work => return output,
                () = tokio::time::sleep(period) => {},
            }
            let seal = devnet.seal();
            tokio::pin!(seal);
            tokio::select! {
                output = &mut work => {
                    // Sealing mutates the validators across awaits. Finish its
                    // commit before handing the caller a stable finalized tip.
                    seal.await;
                    return output;
                },
                _ = &mut seal => {},
            }
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

async fn client_reshapes(devnet: &Devnet) -> Vec<hellas_kernel::Reshape> {
    let mut found = Vec::new();
    let chain = devnet.validator_light_client(0);
    for height in 1..=devnet.height() {
        let block = chain
            .get_finalized_block(hellas_chain::FinalizedBlockQuery::Height(height))
            .await
            .unwrap()
            .unwrap();
        for tx in hellas_chain::FinalizedBlockView::decode(&block)
            .unwrap()
            .txs()
        {
            if let hellas_chain::domain::Transaction::Kernel(hellas_kernel::Tx::Owner(reshape)) = tx
                && reshape.outputs().as_slice()[0].owner() == CLIENT_OWNER.key().into_kernel()
            {
                found.push(reshape.clone());
            }
        }
    }
    found
}

async fn check_client_funding(devnet: &Devnet, approvals: &Approvals, expected: usize) {
    let reshapes = Box::pin(client_reshapes(devnet)).await;
    assert_eq!(
        reshapes.len(),
        expected,
        "exactly one chain reshape per new channel"
    );
    let challenges = approvals.0.lock().unwrap();
    assert_eq!(challenges.len(), expected);
    for (reshape, challenge) in reshapes.iter().zip(challenges.iter()) {
        assert_eq!(
            reshape.outputs().as_slice()[0],
            hellas_kernel::Payout::delegated(
                CLIENT_OWNER.key().into_kernel(),
                Some(client_settlement().party_key()),
                CLIENT_FUNDING
            )
        );
        let change = reshape.outputs().as_slice()[1];
        assert_eq!(change.owner(), CLIENT_OWNER.key().into_kernel());
        assert_eq!(change.delegate(), None);
        assert!(change.value() > 0);
        assert_eq!(reshape.inputs().len(), 1, "fewest available inputs");
        assert_eq!(
            *challenge,
            Digest::from(
                *hellas_kernel::Reshape::payload_hash(
                    devnet.network(),
                    reshape.inputs(),
                    reshape.outputs()
                )
                .as_bytes()
            )
        );
    }
}

async fn advance_offline(devnet: &mut Devnet, relays: &remote::Relays) {
    let (tx, _) = delegate_allocation(
        devnet.allocations(),
        &OFFLINE_OWNER,
        client_settlement().party_key().into(),
    );
    relays.source.local.submit_tx(tx).await.unwrap();
    let block = devnet.seal().await;
    assert!(
        !block.txs().is_empty(),
        "offline interval includes a real state-changing block"
    );
    devnet.seal().await;
    devnet.seal().await;
}

async fn check_gateway_quote(
    options: &PaidWorkOptions,
    owner: Arc<hellas_sdk::client_owner::ClientOwner>,
) {
    use hellas_gateway::WorkExecutionBackend as _;
    let mut args = options.clone();
    args.journal_root = options.journal_root.with_file_name("gateway-client");
    let journal = args.journal_root.clone();
    let gateway = hellas_sdk::paid_gateway::PaidGateway::open(
        hellas_sdk::paid_gateway::PaidGatewayOptions {
            providers: vec![args],
            max_pending_requests: 1,
        },
        NodeIdentity::from_secret_bytes(iroh::SecretKey::generate().to_bytes(), [0x21; 32])
            .unwrap(),
        owner,
    )
    .await
    .unwrap();
    assert!(!journal.exists(), "gateway discovery only requests a quote");
    assert!(
        !options.config.journal_root.exists(),
        "gateway quotes never stake"
    );
    assert!(
        gateway
            .fetch(hellas_gateway::WorkFetchRequest {
                provider: options.provider.node,
                service: "openai".into(),
                method: "wrong-route".into(),
                body: BODY.to_vec(),
            })
            .is_err(),
        "gateway checks the quoted route before requesting funding"
    );
    let oversized = format!(
        "{{\"input\":\"{}\"}}",
        "x".repeat(4096) // Over the quoted admission's request body limit.
    );
    assert!(
        gateway
            .fetch(hellas_gateway::WorkFetchRequest {
                provider: options.provider.node,
                service: "openai".into(),
                method: "responses".into(),
                body: oversized.into_bytes(),
            })
            .is_err(),
        "gateway admits the whole request before requesting funding"
    );
    gateway.drain().await.unwrap();
    assert!(!journal.exists());
    assert!(!options.config.journal_root.exists());
}

/// The provider earns exactly the price from the payment close, and its
/// stake comes back separately, as a different coin, at the bond's
/// timeout.
#[test]
fn a_paid_fetch_job_through_the_sdk_earns_the_price_and_returns_the_stake_separately() {
    run(|runtime| paid_scenario(runtime, false));
}

#[test]
fn setup_reports_a_typed_error_if_remote_proofs_stay_unavailable() {
    run(|runtime| paid_scenario(runtime, true));
}

struct PaidScenario<S = PaidWorkSession> {
    identity: NodeIdentity,
    root: tempfile::TempDir,
    devnet: Devnet,
    provider_node: hellas_sdk::FullNode,
    provider: hellas_sdk::ProviderHandle,
    relays: remote::Relays,
    approvals: Arc<Approvals>,
    owner: Arc<hellas_sdk::client_owner::ClientOwner>,
    client_home: std::path::PathBuf,
    client_transport: iroh::SecretKey,
    endpoint: iroh::Endpoint,
    options: PaidWorkOptions,
    prepared_input: PreparedInvocation,
    quote: hellas_sdk::paid_client::PaidQuote,
    session: S,
}

fn paid_scenario(
    runtime: commonware_runtime::tokio::Context,
    never_catches_up: bool,
) -> impl std::future::Future<Output = ()> {
    Box::pin(async move {
        if let Some(case) = Box::pin(paid_setup(runtime, never_catches_up)).await {
            Box::pin(paid_finish(case)).await;
        }
    })
}

async fn paid_fixture(runtime: commonware_runtime::tokio::Context) -> PaidScenario<()> {
    let root = tempfile::tempdir().unwrap();
    let identity = provider_identity();
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
            owners: vec![PROVIDER_OWNER, CLIENT_OWNER, OFFLINE_OWNER],
            full_nodes: 1,
        },
    )
    .await;
    let provider_node = devnet.full_node(0).clone();

    // Each owner delegates its allocation to its node's settlement key,
    // submitted through a validator URL by a client with no node.
    devnet.seal().await;
    let (provider_funding, _stake_coin) = delegate_allocation(
        devnet.allocations(),
        &PROVIDER_OWNER,
        provider_settlement().party_key().into(),
    );
    let submitter = RemoteLightClient::connect(devnet.light_client_url(2))
        .await
        .unwrap();
    for tx in [provider_funding] {
        assert_eq!(
            submitter.submit_tx(tx).await.unwrap(),
            hellas_chain::SubmitTxOutcome::Enqueued
        );
    }
    devnet.seal().await;

    // The owner stores standing policy once; no client route or bond exists.
    let (store, secret) =
        hellas_authority::test_support::common_node::bootstrap_node_with_credential(
            &root.path().join("provider-state/grants"),
            hellas_authority::model::grant::grant_network(),
            Some(provider_enrollment(&identity)),
            now,
        )
        .await
        .unwrap();
    drop(store);
    let config = work_config(&devnet, root.path().join("provider-journal"));
    let relays = remote::Relays::start(&devnet).await;
    let (provider, _) = start_provider(
        root.path(),
        config.clone(),
        provider_node.clone(),
        &identity,
    )
    .await;
    let authority = provider.administration().unwrap().node();
    let caller = hellas_authority::test_support::session(&authority, &secret).await;
    let command = || hellas_authority::model::grant::admin::WorkControlCommand::SetPaidPolicy {
        expected_revision: auth::Revision(0),
        policy: Box::new(paid_policy()),
    };
    provider
        .administration()
        .unwrap()
        .execute(&caller, auth::GrantId([0; 16]), command())
        .await
        .unwrap();
    assert_eq!(
        authority.paid_policy().await.unwrap().unwrap().policy,
        paid_policy()
    );
    assert!(matches!(
        provider
            .administration()
            .unwrap()
            .execute(&caller, auth::GrantId([0; 16]), command())
            .await,
        Err(
            hellas_authority::work_store::grant::NodeStoreError::Authority(
                auth::AuthorityError::Revision
            )
        )
    ));
    let daily = authority
        .authenticate_session(
            &secret,
            hellas_authority::node::SessionKey::Node(&ROOT.node_key()),
        )
        .await
        .unwrap();
    assert!(matches!(
        provider
            .administration()
            .unwrap()
            .execute(
                &daily,
                auth::GrantId([0; 16]),
                hellas_authority::model::grant::admin::WorkControlCommand::SetPaidPolicy {
                    expected_revision: auth::Revision(1),
                    policy: Box::new(paid_policy())
                }
            )
            .await,
        Err(
            hellas_authority::work_store::grant::NodeStoreError::Authority(
                auth::AuthorityError::StepUp
            )
        )
    ));
    drop(authority);
    let client_transport = iroh::SecretKey::generate();
    let provider_addrs = addresses(&provider);

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
    let prepared_input = invocation::fetch::prepare(
        &events,
        &test_responses_contract(),
        ProducerSigningKey::from_secret_bytes([2; 32])
            .unwrap()
            .public_key(),
        work_policy().canonical_bytes().unwrap(),
        [0; 32],
    )
    .unwrap();
    let mut client_config = config;
    client_config.validators = relays.urls.clone();
    let options = PaidWorkOptions {
        config: client_config,
        journal_root: root.path().join("client-journal"),
        provider: hellas_sdk::client::ProviderAddress::of(&provider_enrollment(&identity)).unwrap(),
        provider_addrs,
        assurance: Assurance::ProducerSigned,
        apple_trust: None,
        expected_price: PRICE,
        acceptance_blocks: 16,
        terminal_blocks: 64,
        payment_blocks: 32,
        timeout: Some(Duration::from_secs(120)),
    };
    let approvals = Arc::new(Approvals::default());
    let client_home = root.path().join("requester");
    let owner = Arc::new(
        hellas_sdk::client_owner::ClientOwner::new(
            approvals.clone(),
            client_settlement().party_key(),
            &client_home.join("funding"),
        )
        .unwrap(),
    );
    let endpoint = bind_paid_endpoint(client_transport.clone()).await.unwrap();
    assert!(!options.config.journal_root.exists());
    Box::pin(check_other_enrollment_refused(
        &options,
        &endpoint,
        owner.clone(),
        &approvals,
    ))
    .await;
    let mut fresh = options.clone();
    fresh.journal_root = options
        .journal_root
        .with_file_name("other-contract-journal");
    Box::pin(check_other_contract_refused(
        &fresh,
        &endpoint,
        owner.clone(),
        &approvals,
    ))
    .await;
    let quote = hellas_sdk::paid_client::request_paid_quote(
        &options,
        &endpoint,
        &client_settlement(),
        FRIEND.principal(),
    )
    .await
    .unwrap();
    assert_eq!(quote.funding_value, CLIENT_FUNDING);
    assert_eq!(
        hellas_kernel::work_payment_settlement(
            quote.policy.expected_payment_values,
            quote.omission_bond
        )
        .unwrap()
        .capacity(),
        PRICE * 10
    );
    assert!(
        !options.config.journal_root.exists(),
        "a quote creates no paid journal"
    );
    Box::pin(check_gateway_quote(&options, owner.clone())).await;
    assert!(
        approvals.0.lock().unwrap().is_empty(),
        "discovery never approves money"
    );
    PaidScenario {
        identity,
        root,
        devnet,
        provider_node,
        provider,
        relays,
        approvals,
        owner,
        client_home,
        client_transport,
        endpoint,
        options,
        prepared_input,
        quote,
        session: (),
    }
}

async fn paid_setup(
    runtime: commonware_runtime::tokio::Context,
    never_catches_up: bool,
) -> Option<PaidScenario> {
    let PaidScenario {
        identity,
        root,
        mut devnet,
        provider_node,
        provider,
        mut relays,
        approvals,
        owner,
        client_home,
        client_transport,
        endpoint,
        options,
        prepared_input,
        quote,
        session: (),
    } = paid_fixture(runtime).await;
    let mut options = options;
    if never_catches_up {
        options.timeout = Some(Duration::from_millis(250));
    }
    relays
        .source
        .unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let attempts = relays
        .source
        .attempts
        .load(std::sync::atomic::Ordering::SeqCst);
    let open = PaidWorkSession::open(
        options.clone(),
        endpoint.clone(),
        client_settlement(),
        owner.clone(),
    );
    tokio::pin!(open);
    // A completed typed timeout is the expected result in the outage case;
    // it need not lose a scheduling race to the proof-attempt observer.
    if never_catches_up {
        let error = tokio::time::timeout(Duration::from_secs(5), &mut open)
            .await
            .unwrap()
            .err()
            .expect("proof reads remain bounded");
        assert!(
            matches!(error, hellas_sdk::paid_client::PaidClientError::Owner(hellas_sdk::client_owner::ClientOwnerError::Timeout(timeout)) if Some(timeout) == options.timeout),
            "typed proof read expiry: {error}"
        );
        assert!(
            approvals.0.lock().unwrap().is_empty(),
            "unverified money cannot reach the passkey"
        );
        endpoint.close().await;
        provider.shutdown().await.unwrap();
        relays.shutdown().await;
        devnet.shutdown().await;
        return None;
    }
    tokio::select! {
        result = &mut open => panic!("setup ended before its proof read: {}", result.err().map_or_else(|| "unexpected success".into(), |error| error.to_string())),
        () = async { while relays.source.attempts.load(std::sync::atomic::Ordering::SeqCst) < attempts + 2 { tokio::task::yield_now().await; } } => {},
    }
    assert!(
        approvals.0.lock().unwrap().is_empty(),
        "unverified money cannot reach the passkey"
    );
    relays
        .source
        .unavailable
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let session = sealing_while(&mut devnet, Duration::from_millis(100), &mut open)
        .await
        .unwrap();
    assert_eq!(
        approvals.0.lock().unwrap().len(),
        1,
        "one exact owner act opens the channel"
    );
    Box::pin(check_client_funding(&devnet, &approvals, 1)).await;
    assert!(!client_home.join("chain").exists());
    assert!(!root.path().join("client-authority").exists());
    Some(PaidScenario {
        identity,
        root,
        devnet,
        provider_node,
        provider,
        relays,
        approvals,
        owner,
        client_home,
        client_transport,
        endpoint,
        options,
        prepared_input,
        quote,
        session,
    })
}

async fn paid_finish(case: PaidScenario) {
    eprintln!("H4 setup complete; checking transport recovery");
    let PaidScenario {
        identity,
        root,
        mut devnet,
        provider_node,
        provider,
        mut relays,
        approvals,
        owner,
        client_home,
        client_transport,
        endpoint,
        options,
        prepared_input,
        quote,
        mut session,
    } = case;
    let bond = session.descriptor().bond_edge();
    let bond_timeout = session
        .descriptor()
        .channel()
        .payment_terms()
        .bond_terms
        .timeout
        .get();
    assert_eq!(
        session.descriptor().invocation_policy(),
        &quote.policy.invocation_policy
    );
    assert_eq!(
        session.descriptor().channel().payment_terms().omission_bond,
        OMISSION_BOND
    );
    let before = session.with_state(|state| state.cursor().0).await.unwrap();
    let connections = relays
        .source
        .connections
        .load(std::sync::atomic::Ordering::SeqCst);
    relays.disconnect();
    devnet.seal().await;
    devnet.seal().await;
    let resumed_height = devnet.height();
    tokio::time::timeout(options.timeout.unwrap(), async {
        loop {
            if session.with_state(|state| state.cursor().0).await.unwrap() == resumed_height {
                break;
            }
            tokio::time::sleep(options.config.poll).await;
        }
    })
    .await
    .expect("a dropped remote transport reconnects and catches up");
    assert!(resumed_height > before);
    assert!(
        relays
            .source
            .connections
            .load(std::sync::atomic::Ordering::SeqCst)
            > connections
    );
    session.shutdown().await;
    drop(session);
    endpoint.close().await;

    provider.shutdown().await.unwrap();
    let (provider, upstream) = start_provider(
        root.path(),
        options.config.clone(),
        provider_node,
        &identity,
    )
    .await;
    assert_eq!(
        provider
            .administration()
            .unwrap()
            .node()
            .paid_policy()
            .await
            .unwrap()
            .unwrap()
            .policy,
        paid_policy()
    );
    let mut options = options;
    options.provider_addrs = addresses(&provider);
    let endpoint = bind_paid_endpoint(client_transport.clone()).await.unwrap();
    eprintln!("H4 transport recovered; testing offline/stale-root recovery");
    let old_cursor = resumed_height;
    Box::pin(advance_offline(&mut devnet, &relays)).await;
    let offline_tip = devnet.height();
    assert_eq!(offline_tip - old_cursor, 3);
    relays
        .source
        .replay
        .store(2, std::sync::atomic::Ordering::SeqCst);
    let attempts = relays
        .source
        .attempts
        .load(std::sync::atomic::Ordering::SeqCst);
    let reopening = PaidWorkSession::open(
        options.clone(),
        endpoint.clone(),
        client_settlement(),
        owner.clone(),
    );
    tokio::pin!(reopening);
    tokio::select! {
        result = &mut reopening => panic!("certified pre-open replay ended recovery: {}", result.err().map_or_else(|| "unexpected success".into(), |error| error.to_string())),
        () = async { while relays.source.attempts.load(std::sync::atomic::Ordering::SeqCst) < attempts + 2 { tokio::task::yield_now().await; } } => {},
    }
    assert_eq!(approvals.0.lock().unwrap().len(), 1);
    relays
        .source
        .replay
        .store(0, std::sync::atomic::Ordering::SeqCst);
    let mut recovered = reopening.await.unwrap();
    assert_eq!(
        recovered
            .with_state(|state| state.cursor().0)
            .await
            .unwrap(),
        offline_tip,
        "offline catch-up visits every missing height"
    );
    recovered.shutdown().await;
    drop(recovered);
    // Restart recovery re-verifies the retained offer against the address.
    let error = PaidWorkSession::open_retained(
        other_provider(&options),
        endpoint.clone(),
        client_settlement(),
        owner.clone(),
    )
    .await
    .err()
    .expect("retained channel under another enrollment");
    assert!(
        matches!(
            error,
            hellas_sdk::paid_client::PaidClientError::RetainedEnrollment(address)
                if address == other_provider(&options).provider
        ),
        "{error}"
    );
    assert_eq!(approvals.0.lock().unwrap().len(), 1);
    Box::pin(check_other_contract_refused(
        &options,
        &endpoint,
        owner.clone(),
        &approvals,
    ))
    .await;
    endpoint.close().await;
    eprintln!("H4 offline recovery complete; running paid job");
    let client_producer = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
    let job = hellas_sdk::job::Job::fetch(
        PRICE,
        test_responses_contract(),
        "openai".into(),
        "responses".into(),
        BODY.to_vec(),
        Assurance::ProducerSigned,
    )
    .unwrap();
    let job_folder = root.path().join("job");
    job.save(&job_folder).unwrap();
    let purchase_path = root.path().join("purchases/job.json");
    let mut purchase = hellas_sdk::transact::Purchase::open(&purchase_path, &job, false).unwrap();
    let endpoint = bind_paid_endpoint(client_transport).await.unwrap();
    let mut session = PaidWorkSession::open(
        options.clone(),
        endpoint.clone(),
        client_settlement(),
        owner.clone(),
    )
    .await
    .unwrap();
    session
        .run(
            None,
            &InvocationContent::Ephemeral(Default::default()),
            true,
            None,
        )
        .await
        .unwrap();
    assert!(
        !session.needs_recovery(),
        "initial recovery has completed before this request"
    );
    // A signed failure retires unpaid, including the caller's purchase marker.
    upstream
        .fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let failed = hellas_sdk::transact::transact(
        &mut session,
        &job,
        &client_producer,
        hellas_sdk::transact::TransactionOptions {
            purchase: Some(&mut purchase),
            ..Default::default()
        },
    )
    .await
    .err()
    .expect("signed failure is reported without payment");
    let hellas_sdk::transact::TransactError::Client(
        hellas_sdk::paid_client::PaidClientError::InvocationFailed { work_id, .. },
    ) = failed
    else {
        panic!("unexpected failure: {failed}");
    };
    session
        .with_state(|state| {
            assert_eq!(state.ledger().credited_cumulative(), 0);
            assert!(state.last_payment().is_none());
            assert!(matches!(
                state.terminal_by_id(work_id).unwrap().outcome,
                hellas_channel::work_store::TerminalOutcome::Rejected { .. }
            ));
        })
        .await
        .unwrap();
    assert!(!purchase.is_pending());
    assert!(!purchase_path.exists());
    assert!(!session.needs_recovery());
    session.shutdown().await;
    drop(session);
    drop(purchase);
    let mut purchase = hellas_sdk::transact::Purchase::open(&purchase_path, &job, false).unwrap();
    purchase.reconcile(&options).await.unwrap();
    let mut session = PaidWorkSession::open(
        options.clone(),
        endpoint.clone(),
        client_settlement(),
        owner.clone(),
    )
    .await
    .unwrap();
    session
        .run(
            None,
            &InvocationContent::Ephemeral(Default::default()),
            true,
            None,
        )
        .await
        .unwrap();
    upstream
        .pause
        .store(true, std::sync::atomic::Ordering::SeqCst);
    {
        let first = hellas_sdk::transact::transact(
            &mut session,
            &job,
            &client_producer,
            hellas_sdk::transact::TransactionOptions {
                purchase: Some(&mut purchase),
                ..Default::default()
            },
        );
        tokio::pin!(first);
        tokio::select! {
            result = &mut first => panic!("job completed before interruption: {:?}", result.err()),
            () = upstream.started.notified() => {},
        }
        // The provider has accepted and dispatched, but has exposed no output.
    }
    assert!(
        session.needs_recovery(),
        "cancellation keeps recovery armed for the next request"
    );
    eprintln!("h6: first attempt interrupted after backend dispatch");
    let interrupted = session
        .with_state(|state| {
            let jobs = state.jobs().collect::<Vec<_>>();
            assert_eq!(jobs.len(), 1);
            eprintln!("h6: interrupted client phase {:?}", jobs[0].phase());
            (jobs[0].work_id(), jobs[0].authorization().proposal_nonce)
        })
        .await
        .unwrap();
    session.shutdown().await;
    drop(session);
    drop(purchase);
    let mut purchase = hellas_sdk::transact::Purchase::open(&purchase_path, &job, false).unwrap();
    purchase.reconcile(&options).await.unwrap();
    let mut session = PaidWorkSession::open(
        options.clone(),
        endpoint.clone(),
        client_settlement(),
        owner.clone(),
    )
    .await
    .unwrap();
    session
        .with_state(|state| {
            assert!(
                state.jobs().all(|job| job.prepared_input().is_empty()),
                "reopened Fetch journals retain metadata only"
            );
        })
        .await
        .unwrap();
    eprintln!("h6: reopened metadata-only client; releasing backend");
    upstream
        .pause
        .store(false, std::sync::atomic::Ordering::SeqCst);
    upstream.release.notify_one();
    let loaded = hellas_sdk::job::Job::load(&job_folder).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        hellas_sdk::transact::transact(
            &mut session,
            &loaded,
            &client_producer,
            hellas_sdk::transact::TransactionOptions {
                purchase: Some(&mut purchase),
                ..Default::default()
            },
        ),
    )
    .await
    .expect("accepted retry completes within its test deadline")
    .unwrap();
    eprintln!("h6: accepted retry paid once");
    assert!(
        !session.needs_recovery(),
        "the completed payment clears recovery"
    );
    assert_eq!(
        result.work_id, interrupted.0,
        "the original accepted work resumes"
    );
    assert_eq!(
        session
            .with_state(|state| state.proposal_nonce_high_water())
            .await
            .unwrap(),
        interrupted.1,
        "retry creates no second proposal"
    );
    eprintln!("H4 paid job complete; settling");
    let settled_provider_payout =
        sealing_while(&mut devnet, Duration::from_millis(100), session.settle())
            .await
            .unwrap();
    session.shutdown().await;
    drop(session);

    assert_eq!(result.bond_edge, bond);
    assert_eq!(result.job_price, PRICE);
    assert_eq!(result.credited_cumulative, PRICE, "one job at its price");
    assert_eq!(
        settled_provider_payout, PRICE,
        "the settled close paid the provider the price",
    );
    assert_eq!(upstream.calls("openai", "responses", BODY), 1);
    let marker = std::fs::read(&purchase_path).unwrap();
    assert!(
        !marker.windows(BODY.len()).any(|bytes| bytes == BODY),
        "purchase state contains no request bytes"
    );
    purchase.reported().unwrap();
    drop(purchase);

    assert_eq!(
        approvals.0.lock().unwrap().len(),
        1,
        "a reopened channel never prompts again"
    );

    // Earnings and returned principal are distinct finalized coins.
    let earnings = holdings(&devnet, PROVIDER_OWNER.key()).await;
    assert_eq!(
        earnings
            .iter()
            .filter(|(_, value)| *value == PRICE)
            .map(|(_, value)| *value)
            .collect::<Vec<_>>(),
        vec![PRICE],
        "EARNINGS: exactly the job price",
    );
    assert_eq!(
        holdings(&devnet, CLIENT_OWNER.key())
            .await
            .iter()
            .map(|(_, value)| *value)
            .collect::<Vec<_>>(),
        vec![CLIENT_FUNDING - PRICE, 2 * CLIENT_FUNDING],
        "the client got back its funding less exactly the price",
    );

    eprintln!("H4 settlement complete; awaiting early stake reclaim");
    let mut held = Vec::new();
    for _ in 0..200 {
        held = holdings(&devnet, PROVIDER_OWNER.key()).await;
        if held.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        devnet.seal().await;
    }
    assert!(
        devnet.height() < bond_timeout,
        "payment closure releases stake before the horizon"
    );
    assert_eq!(
        held.len(),
        2,
        "the closed payment's bond returned its stake: {held:?}"
    );
    assert_eq!(
        held,
        vec![
            *earnings.iter().find(|(_, value)| *value == PRICE).unwrap(),
            (held[1].0, PROVIDER_STAKE)
        ],
        "RETURNED PRINCIPAL: the stake, unchanged, beside the unchanged earnings",
    );
    assert_ne!(
        held[1].0,
        earnings
            .iter()
            .find(|(_, value)| *value == PRICE)
            .unwrap()
            .0,
        "principal and earnings are different coins"
    );

    eprintln!("H4 stake returned; opening second channel");
    let mut second = sealing_while(
        &mut devnet,
        Duration::from_millis(100),
        PaidWorkSession::open(
            options.clone(),
            endpoint.clone(),
            client_settlement(),
            owner.clone(),
        ),
    )
    .await
    .unwrap();
    Box::pin(check_client_funding(&devnet, &approvals, 2)).await;
    assert_ne!(second.descriptor().bond_edge(), bond);
    second.shutdown().await;
    drop(second);
    let second = PaidWorkSession::open(
        options.clone(),
        endpoint.clone(),
        client_settlement(),
        owner.clone(),
    )
    .await
    .unwrap();
    Box::pin(provider_close_offline(&mut devnet, second, prepared_input)).await;
    assert_eq!(
        approvals.0.lock().unwrap().len(),
        2,
        "the offline close releases no new client signature"
    );
    endpoint.close().await;
    assert!(!client_home.join("chain").exists());
    provider.shutdown().await.unwrap();
    relays.shutdown().await;
    devnet.shutdown().await;
}

async fn provider_close_offline(
    devnet: &mut Devnet,
    mut session: PaidWorkSession,
    input: PreparedInvocation,
) {
    use hellas_chain::{WorkBlocks, work_view::WorkChannelQuery};
    let result = session
        .run(
            Some(input),
            &InvocationContent::Ephemeral(Default::default()),
            false,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.credited_cumulative, PRICE);
    let certificate = session
        .with_state(|state| state.executable_certificate())
        .await
        .unwrap()
        .unwrap();
    let channel = session.descriptor().channel().clone();
    session.shutdown().await;
    drop(session);
    let provider_before = holdings(devnet, PROVIDER_OWNER.key()).await;
    let start = hellas_channel::work_close::close_start(
        &channel,
        hellas_kernel::Party::Taker,
        devnet.height(),
        Some(certificate),
        &provider_settlement(),
    )
    .unwrap();
    let local = devnet.validator_light_client(0);
    local
        .submit_tx(hellas_chain::domain::Transaction::Kernel(
            hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(start)),
        ))
        .await
        .unwrap();
    devnet.seal().await;
    let source = WorkBlocks::new(local);
    let query = WorkChannelQuery {
        bond_edge: channel.payment_terms().bond_edge,
        payment_edge: Some(channel.payment_edge()),
        funding: Default::default(),
    };
    let snapshot = source
        .work_channel_snapshot(query.clone())
        .await
        .unwrap()
        .unwrap();
    let hellas_kernel::PendingSlot::Present(pending) = snapshot.pending() else {
        panic!("provider start opens an actual contest")
    };
    assert_eq!(
        pending.final_cumulative(),
        PRICE,
        "A can settle only B's certified cumulative while B is absent"
    );
    devnet.seal_through(pending.response_deadline()).await;
    for _ in 0..32 {
        devnet.seal().await;
        if source
            .work_channel_snapshot(query.clone())
            .await
            .unwrap()
            .unwrap()
            .payment()
            .is_none()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        source
            .work_channel_snapshot(query)
            .await
            .unwrap()
            .unwrap()
            .payment()
            .is_none()
    );
    assert_eq!(
        holdings(devnet, CLIENT_OWNER.key())
            .await
            .iter()
            .map(|(_, value)| value)
            .sum::<u64>(),
        CLIENT_OWNER.balance - 2 * PRICE
    );
    let provider_after = holdings(devnet, PROVIDER_OWNER.key()).await;
    let earnings = hellas_kernel::Payout::delegated(
        PROVIDER_OWNER.key().into_kernel(),
        Some(provider_settlement().party_key()),
        0,
    )
    .id(channel.payment_edge(), 0);
    assert_eq!(
        provider_after
            .iter()
            .find(|(id, _)| *id == earnings)
            .map(|(_, value)| *value),
        Some(PRICE),
        "this payment close pays the exact price; reclaimed stake is separate"
    );
    for coin in provider_before {
        assert!(
            provider_after.contains(&coin),
            "unspent coins survive settlement"
        );
    }
}

/// Plan-v4 §6, CI variant: B, with no node, buys one run of a program A has
/// never seen through an automatic offer, and pays for it exactly once.
#[test]
fn unseen_program_pays_exactly_once() {
    run(automatic::exercise);
}

#[test]
fn setup_reads_recover_after_execution_and_expire_with_a_typed_error() {
    use hellas_chain::WorkBlocks;
    use hellas_channel::work_close::{BlockSourceError, FinalizedBlocks as _};
    use hellas_channel::work_open::{SetupQuery, SetupView as _};

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
            payment_edge: Some(hellas_kernel::EdgeId::from_bytes([1; 32])),
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
        let error = tokio::time::timeout(timeout.saturating_mul(2), source.finalized_setup(query))
            .await
            .expect("unavailable setup reads stay bounded")
            .unwrap_err();
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

#[test]
fn remote_object_reads_verify_current_state_and_reject_forged_witnesses() {
    run(remote::proofs);
}
