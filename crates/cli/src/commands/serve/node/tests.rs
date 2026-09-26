use futures::StreamExt;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use hellas_chain::{LatestBlock, QueryError, WorkChannelQuery, WorkChannelSnapshot};
use hellas_kernel::{
    Auth, BlockHeight, BufferWriter, CoinId, Decode as _, Edge, EdgeValues, Encode as _, Fees,
    Funding, Key, LeaseSlots, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, MAX_START_VALIDITY_BLOCKS,
    MIN_OMIT_RESPONSE_BLOCKS, Move, Parties, Party, Payout, PendingPaymentClose, Proof,
    RegistryChunk, RegistryNamespace, RegistryRecordTag, StartId, Terms, Tx, WorkPaymentSettlement,
    WorkPaymentTerms, WorkStakeBondTerms, Writer as _,
};
use hellas_rpc::call::WithTrailer;
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PrivateRecord as _, decode_transcript, delivery_request_digest, encode_transcript,
    generation_policy_digest, identity_source_digest, next_payment, payment_binding_digest,
    private_policy_commitment, propose_authorization, result_digest, signing_hash, terminal_result,
    work_id,
};
use hellas_rpc::protocol::work_bundle::WorkChannelSetupBundleV1;
use hellas_rpc::protocol::work_setup::ProviderChannelPolicy;
use hellas_rpc::services::execute::ExecuteClientImpl;
use hellas_rpc::services::work::WorkClientImpl;
use hellas_rpc::services::work_setup::WorkSetupClientImpl;
use hellas_rpc::{
    Application, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, ContentId, EvaluateRequest,
    OutputEventEnvelope, ProducerSigningKey, ProgramManifest, PublicKey, SubmitTxOutcome,
};
use hellas_wire::{AuthLevel, PeerIdentity};
use hellas_work::work::{BackendFault, PreparedEvaluateInput, WorkRefusal};
use hellas_work::work_close::{BlockSourceError, FinalizedWork};
use hellas_work::work_handshake::{apply_setup_exchange, prepare_setup_exchange};
use hellas_work::work_open::{FinalizedSetup, SetupQuery};
use hellas_work::work_store::{
    ChannelRecord, ChannelState, SetupEnd, SetupOrigin, SetupRecord, SetupScan, TerminalOutcome,
};
use iroh::{EndpointAddr, TransportAddr};
use tokio::sync::{Notify, Semaphore};

use super::super::work_config::{WorkRoutes, load_work_config};
use super::*;

fn assert_retryable_not_ready(refusal: WorkRefused) {
    assert_eq!(refusal.code, WorkRefusalCode::NotReady as i32);
    assert!(WorkRefusal::NotReady.is_retryable());
    assert!(refusal.reason.len() <= 64);
}

#[derive(Clone, Debug)]
struct ContextWitness(Arc<Mutex<Option<TransportContext>>>);

impl WorkSetupHandler for ContextWitness {
    fn exchange_setup(
        &self,
        _request: ExchangeSetupRequest,
        context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<ExchangeSetupResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        if let Ok(mut observed) = self.0.lock() {
            *observed = Some(context);
        }
        core::future::ready(Ok(ExchangeSetupResponse::default()))
    }
}

#[derive(Clone)]
struct ConcurrentDispatchWitness {
    calls: Arc<AtomicUsize>,
    first_entered: Arc<Notify>,
    second_entered: Arc<Notify>,
    release_first: Arc<Notify>,
}

impl WorkSetupHandler for ConcurrentDispatchWitness {
    fn exchange_setup(
        &self,
        _request: ExchangeSetupRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<ExchangeSetupResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let first_entered = self.first_entered.clone();
        let second_entered = self.second_entered.clone();
        let release_first = self.release_first.clone();
        async move {
            if call == 0 {
                first_entered.notify_one();
                release_first.notified().await;
            } else {
                second_entered.notify_one();
            }
            Ok(ExchangeSetupResponse::default())
        }
    }
}

/// The route identity is the peer iroh authenticated on this exact
/// connection, not a field a caller supplied in the request. Keeping the
/// raw context beside the derived route makes the authentication level an
/// assertion of its own rather than an inference from a populated peer.
#[tokio::test]
async fn work_setup_routes_only_the_vouched_dialling_peer() {
    let observed = Arc::new(Mutex::new(None));
    let witness = ContextWitness(Arc::clone(&observed));
    let alpn = <WorkSetup as ServiceMarker>::ALPN.as_bytes();
    let server = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[0x63; 32]))
        .alpns(vec![alpn.to_vec()])
        .bind_addr(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("a loopback socket"),
        )
        .expect("the server has a valid bind address")
        .bind()
        .await
        .expect("the server binds");
    let target = EndpointAddr::from_parts(
        server.id(),
        server.bound_sockets().into_iter().map(TransportAddr::Ip),
    );
    let client = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[0x64; 32]))
        .bind_addr(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("a loopback socket"),
        )
        .expect("the client has a valid bind address")
        .bind()
        .await
        .expect("the client binds");
    let expected = PeerIdentity(*client.id().as_bytes());

    let accepting_server = server.clone();
    let (release_connection, released) = oneshot::channel();
    let serving = tokio::spawn(async move {
        let incoming = accepting_server
            .accept()
            .await
            .expect("the server receives a dial");
        let accepting = incoming.accept().expect("the server accepts the dial");
        let connection = accepting.await.expect("the iroh handshake completes");
        let transport = IrohTransport::new(connection);
        let inbound = transport
            .accept()
            .await
            .expect("the transport accepts the call")
            .expect("the call has one inbound stream");
        Dispatcher::<IrohTransport>::dispatch(&WorkSetupServer(witness), inbound)
            .await
            .expect("WorkSetup dispatches");
        let _ = released.await;
    });

    let connection = client
        .connect(target, alpn)
        .await
        .expect("the client dials the WorkSetup ALPN");
    WorkSetupClientImpl::new(IrohTransport::new(connection))
        .exchange_setup(ExchangeSetupRequest::default())
        .await
        .expect("the genuine WorkSetup call completes");
    let _ = release_connection.send(());
    serving.await.expect("the server task completes");

    let context = observed
        .lock()
        .expect("the witness lock remains usable")
        .clone()
        .expect("the handler receives a transport context");
    assert_eq!(context.peer, Some(expected));
    assert_eq!(context.auth_level, AuthLevel::Vouched);
    assert_eq!(context.vouched_peer(), Some(expected));

    assert_eq!(
        None::<&TransportContext>.and_then(TransportContext::vouched_peer),
        None,
        "an absent context has no route",
    );
    assert_eq!(
        TransportContext::default().vouched_peer(),
        None,
        "a default context has no route",
    );
    assert_eq!(
        TransportContext {
            peer: Some(expected),
            ..TransportContext::default()
        }
        .vouched_peer(),
        None,
        "a populated peer the transport does not vouch for has no route",
    );
    client.close().await;
    server.close().await;
}

#[tokio::test]
async fn one_slow_rpc_does_not_serialize_its_connection() {
    let alpn = <WorkSetup as ServiceMarker>::ALPN.as_bytes();
    let server = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[0x67; 32]))
        .alpns(vec![alpn.to_vec()])
        .bind_addr(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("a loopback socket"),
        )
        .expect("the server has a valid bind address")
        .bind()
        .await
        .expect("the server binds");
    let target = EndpointAddr::from_parts(
        server.id(),
        server.bound_sockets().into_iter().map(TransportAddr::Ip),
    );
    let client = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[0x68; 32]))
        .bind_addr(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("a loopback socket"),
        )
        .expect("the client has a valid bind address")
        .bind()
        .await
        .expect("the client binds");

    let first_entered = Arc::new(Notify::new());
    let second_entered = Arc::new(Notify::new());
    let release_first = Arc::new(Notify::new());
    let witness = ConcurrentDispatchWitness {
        calls: Arc::new(AtomicUsize::new(0)),
        first_entered: first_entered.clone(),
        second_entered: second_entered.clone(),
        release_first: release_first.clone(),
    };
    let accepting = server.clone();
    let serving = tokio::spawn(async move {
        let incoming = accepting
            .accept()
            .await
            .expect("the server receives a dial");
        let connection = incoming
            .accept()
            .expect("the server accepts the dial")
            .await
            .expect("the handshake completes");
        serve_loop(
            Arc::new(IrohTransport::new(connection)),
            WorkSetupServer(witness),
        )
        .await
    });

    let connection = client
        .connect(target, alpn)
        .await
        .expect("the client dials WorkSetup");
    let first_transport = IrohTransport::new(connection.clone());
    let first = tokio::spawn(async move {
        WorkSetupClientImpl::new(first_transport)
            .exchange_setup(ExchangeSetupRequest::default())
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), first_entered.notified())
        .await
        .expect("the first handler starts");

    let second_transport = IrohTransport::new(connection.clone());
    let second = tokio::spawn(async move {
        WorkSetupClientImpl::new(second_transport)
            .exchange_setup(ExchangeSetupRequest::default())
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), second_entered.notified())
        .await
        .expect("the second handler starts while the first is blocked");
    release_first.notify_one();
    first
        .await
        .expect("the first client task completes")
        .expect("the first RPC succeeds");
    second
        .await
        .expect("the second client task completes")
        .expect("the second RPC succeeds");

    connection.close(0_u32.into(), b"concurrency test complete");
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("the server observes connection close")
        .expect("the server task does not panic")
        .expect("the serve loop exits cleanly");
    client.close().await;
    server.close().await;
}

#[tokio::test]
async fn remote_cache_cli_uses_the_nodes_existing_dispatch_and_admin_grant() {
    use clap::Parser;
    use hellas_rpc::cache::{
        CacheKey, CacheKind, CacheOptions, CachePolicy, CacheStore, MemoryCacheStore,
    };

    let temporary = temp();
    let identity_path = temporary.path().join("admin.identity");
    let admin = crate::identity::load_or_create(Some(&identity_path)).unwrap();
    let server = Endpoint::builder(presets::Minimal)
        .alpns(vec![CacheControl::ALPN.as_bytes().to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let directory = Arc::new(PeerDirectory::with_config(
        PeerId::from_bytes(*server.id().as_bytes()),
        hellas_rpc::peer_directory_config(),
    ));
    let store = Arc::new(MemoryCacheStore::default());
    store
        .insert(&CacheKey::hash(CacheKind::Proxy, &[b"cli"]), b"output", 0)
        .unwrap();
    for granted in [false, true] {
        let mut execution = test_remote_execution();
        execution.control = CacheController::new(&CacheOptions {
            policy: CachePolicy::Record,
            store: Some(store.clone()),
        });
        if granted {
            execution
                .admin_policy
                .peers
                .push(PeerIdentity(*admin.transport_key.public().as_bytes()));
        }
        let handler = NodeHandlerImpl::new(
            server.id(),
            "admin-test".into(),
            Vec::new(),
            directory.clone(),
        );
        let manager = directory.manager();
        let accepting = server.clone();
        let task = tokio::spawn(async move {
            let connection = accepting.accept().await.unwrap().await.unwrap();
            serve_connection(
                connection.alpn().to_vec(),
                connection,
                execution,
                handler,
                manager,
                None,
                None,
            )
            .await
        });
        let cli = crate::Cli::try_parse_from([
            "hellas",
            "--identity",
            identity_path.to_str().unwrap(),
            "output-cache",
            "--node-id",
            &server.id().to_string(),
            "--node-addr",
            &server.bound_sockets()[0].to_string(),
            "clear",
        ])
        .unwrap();
        let crate::Commands::OutputCache(args) = cli.command else {
            panic!()
        };
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            crate::commands::output_cache::run(args, None, cli.identity.as_deref()),
        )
        .await
        .unwrap();
        if granted {
            result.unwrap();
            assert!(store.list().unwrap().is_empty());
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("administrative access")
            );
            assert_eq!(store.list().unwrap().len(), 1);
        }
        task.abort();
    }
    server.close().await;
}

#[tokio::test]
async fn production_fetch_alpn_dispatches_run_ticket_on_its_connection() {
    let alpn = <Fetch as ServiceMarker>::ALPN.as_bytes();
    assert!(served_alpns(false).contains(&alpn.to_vec()));
    let server = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[0x65; 32]))
        .alpns(vec![alpn.to_vec()])
        .bind_addr(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("a loopback socket"),
        )
        .expect("the server has a valid bind address")
        .bind()
        .await
        .expect("the server binds");
    let target = EndpointAddr::from_parts(
        server.id(),
        server.bound_sockets().into_iter().map(TransportAddr::Ip),
    );
    let client = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[0x66; 32]))
        .bind_addr(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("a loopback socket"),
        )
        .expect("the client has a valid bind address")
        .bind()
        .await
        .expect("the client binds");

    let local_peer = PeerId::from_bytes(*server.id().as_bytes());
    let directory = Arc::new(PeerDirectory::with_config(
        local_peer,
        hellas_rpc::peer_directory_config(),
    ));
    let node_handler = NodeHandlerImpl::new(
        server.id(),
        "fetch-dispatch-test".to_string(),
        Vec::new(),
        directory.clone(),
    );
    let accepting_server = server.clone();
    let serving = tokio::spawn(async move {
        let incoming = accepting_server
            .accept()
            .await
            .expect("the server receives the Fetch dial");
        let connection = incoming
            .accept()
            .expect("the server accepts the Fetch dial")
            .await
            .expect("the Fetch handshake completes");
        serve_connection(
            connection.alpn().to_vec(),
            connection,
            test_remote_execution(),
            node_handler,
            directory.manager(),
            None,
            None,
        )
        .await
    });

    let connection = client
        .connect(target, alpn)
        .await
        .expect("the client dials the advertised Fetch ALPN");
    let closing = connection.clone();
    let mut response = match ExecuteClientImpl::new(IrohTransport::new(connection))
        .run_ticket(hellas_rpc::pb::execute::RunTicketRequest::default())
        .await
    {
        Ok(response) => response,
        Err(error) => panic!("RunTicket method did not reach its server stream: {error}"),
    };
    let error = match response.next().await {
        Some(Err(error)) => error,
        Some(Ok(_)) => panic!("an empty ticket cannot produce work events"),
        None => match response.finish() {
            Ok(_) => panic!("an empty ticket must end with an error trailer"),
            Err(error) => error,
        },
    };
    assert_ne!(
        error.code(),
        hellas_wire::WireCode::Unimplemented,
        "Fetch ALPN must route RunTicket to Execute, not its Fetch fallback",
    );
    closing.close(0_u32.into(), b"test complete");
    let _ = tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("the Fetch serve loop observes connection close")
        .expect("the Fetch server task does not panic");
    server.close().await;
    client.close().await;
}

async fn exchange_routed_setup(
    server: &Endpoint,
    target: &EndpointAddr,
    setup: &MountedSetup,
    client_secret: u8,
) -> ExchangeSetupResponse {
    let local_peer = PeerId::from_bytes(*server.id().as_bytes());
    let directory = Arc::new(PeerDirectory::with_config(
        local_peer,
        hellas_rpc::peer_directory_config(),
    ));
    let handler = NodeHandlerImpl::new(
        server.id(),
        "peer-routed-setup-test".to_string(),
        Vec::new(),
        directory.clone(),
    );
    let accepting = server.clone();
    let setup = setup.clone();
    let serving = tokio::spawn(async move {
        let incoming = accepting
            .accept()
            .await
            .expect("the routed setup server receives a connection");
        let connection = incoming
            .accept()
            .expect("the routed setup connection starts")
            .await
            .expect("the routed setup handshake completes");
        serve_connection(
            connection.alpn().to_vec(),
            connection,
            test_remote_execution(),
            handler,
            directory.manager(),
            Some(setup),
            None,
        )
        .await
        .expect("the routed setup connection is served");
    });

    let client = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[client_secret; 32]))
        .bind_addr(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("a loopback socket"),
        )
        .expect("the routed setup client has a valid bind address")
        .bind()
        .await
        .expect("the routed setup client binds");
    let connection = client
        .connect(
            target.clone(),
            <WorkSetup as ServiceMarker>::ALPN.as_bytes(),
        )
        .await
        .expect("the routed setup client dials");
    let response = WorkSetupClientImpl::new(IrohTransport::new(connection.clone()))
        .exchange_setup(ExchangeSetupRequest::default())
        .await
        .expect("the routed setup request completes");
    connection.close(0_u32.into(), b"routed setup complete");
    serving.await.expect("the routed setup server task joins");
    client.close().await;
    response
}

fn advanced_setup_bundle(response: ExchangeSetupResponse) -> WorkChannelSetupBundleV1 {
    let Some(exchange_setup_response::Outcome::Advanced(advanced)) = response.outcome else {
        panic!("a configured peer receives its setup proposal")
    };
    match WorkChannelSetupBundleV1::decode(&advanced.bundle) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the routed setup proposal decodes: {error}"),
    }
}

/// Two empty first requests carry no selector at all. The authenticated
/// dialling peers are therefore the only route identities, and each must
/// reach the exact setup service that owns its configured journal.
#[tokio::test]
async fn two_vouched_peers_receive_their_distinct_configured_offers() {
    let dir = temp();
    let first = OfferFixture::first();
    let second = OfferFixture::second();
    first.seed_provider_offer(dir.path(), admits());
    second.seed_provider_offer(dir.path(), admits());

    let first_secret = 0x71;
    let second_secret = 0x72;
    let first_peer = PeerId::from_bytes(
        *SecretKey::from_bytes(&[first_secret; 32])
            .public()
            .as_bytes(),
    );
    let second_peer = PeerId::from_bytes(
        *SecretKey::from_bytes(&[second_secret; 32])
            .public()
            .as_bytes(),
    );
    let setup_mount = MountedSetup::default();
    let runner = WorkRunner::discover(
        WorkRunnerConfig {
            network: network(),
            threshold_identity: threshold_identity(),
            journal_root: dir.path().to_path_buf(),
            routes: configured_routes(&[
                (first_peer, first.bond_edge(), first.client().party_key()),
                (second_peer, second.bond_edge(), second.client().party_key()),
            ]),
            validators: Vec::new(),
            poll: Duration::from_millis(1),
            max_observation_age: Duration::from_secs(5),
            settlement_key: provider(),
            policy: provider_policy(),
        },
        MountedWork::default(),
        setup_mount.clone(),
    )
    .expect("both owned provider journals are discovered");
    assert_eq!(runner.journal_count(), 2, "both journals keep a clock");

    let alpn = <WorkSetup as ServiceMarker>::ALPN.as_bytes();
    let server = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[0x70; 32]))
        .alpns(vec![alpn.to_vec()])
        .bind_addr(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("a loopback socket"),
        )
        .expect("the routed setup server has a valid bind address")
        .bind()
        .await
        .expect("the routed setup server binds");
    let target = EndpointAddr::from_parts(
        server.id(),
        server.bound_sockets().into_iter().map(TransportAddr::Ip),
    );

    let first_bundle = advanced_setup_bundle(
        exchange_routed_setup(&server, &target, &setup_mount, first_secret).await,
    );
    let second_bundle = advanced_setup_bundle(
        exchange_routed_setup(&server, &target, &setup_mount, second_secret).await,
    );
    assert_eq!(first_bundle.revision(), 1);
    assert_eq!(second_bundle.revision(), 1);
    assert_ne!(
        first_bundle, second_bundle,
        "the two peers do not receive one global first mount",
    );
    assert_eq!(
        first_bundle.bond_terms().parties.taker(),
        first.client().party_key(),
        "the first peer reaches the journal configured for its client",
    );
    assert_eq!(
        second_bundle.bond_terms().parties.taker(),
        second.client().party_key(),
        "the second peer reaches the journal configured for its client",
    );

    assert!(
        setup_mount.service(&TransportContext::default()).is_none(),
        "an absent identity has no route",
    );
    assert!(
        setup_mount
            .service(&TransportContext {
                peer: Some(PeerIdentity(first_peer.into_bytes())),
                ..TransportContext::default()
            })
            .is_none(),
        "an unvouched identity has no route",
    );
    assert!(
        setup_mount
            .service(&vouched_context(PeerId::from_bytes([0xff; 32])))
            .is_none(),
        "an unknown vouched peer has no route",
    );
    let exact_first = setup_mount
        .service(&vouched_context(first_peer))
        .expect("the first route owns one exact setup service");
    assert!(
        !setup_mount.mount(first_peer, first.bond_edge(), &exact_first),
        "a second candidate makes the peer ambiguous",
    );
    assert!(
        setup_mount.service(&vouched_context(first_peer)).is_none(),
        "an ambiguous peer fails closed",
    );

    drop(runner);
    server.close().await;
}

fn discover_two_route_runner(
    root: &Path,
    work_mount: &MountedWork,
    setup_mount: &MountedSetup,
) -> WorkRunner {
    let first = OfferFixture::first();
    let second = OfferFixture::second();
    match WorkRunner::discover(
        WorkRunnerConfig {
            network: network(),
            threshold_identity: threshold_identity(),
            journal_root: root.to_path_buf(),
            routes: configured_routes(&[
                (
                    first_route_peer(),
                    first.bond_edge(),
                    first.client().party_key(),
                ),
                (
                    second_route_peer(),
                    second.bond_edge(),
                    second.client().party_key(),
                ),
            ]),
            validators: Vec::new(),
            poll: Duration::from_millis(1),
            max_observation_age: Duration::from_secs(5),
            settlement_key: provider(),
            policy: provider_policy(),
        },
        work_mount.clone(),
        setup_mount.clone(),
    ) {
        Ok(runner) => runner,
        Err(error) => panic!("both configured routes are discovered: {error}"),
    }
}

async fn accept_mounted_route(
    mount: &MountedWork,
    peer: PeerId,
    request: AcceptWorkRequest,
) -> AcceptWorkResponse {
    let context = vouched_context(peer);
    let handler = mount
        .handler(&context)
        .expect("the configured peer has one mounted channel");
    let response: WithTrailer<AcceptWorkResponse> = handler
        .accept_work(request, context)
        .await
        .unwrap_or_else(|error| panic!("the mounted Work handler answers: {error}"))
        .into();
    response.response
}

/// Completing one setup moves only that route from WorkSetup to Work.
/// The other peer keeps its revision-one offer and cannot see the new
/// channel through either a global mount or the completing peer's key.
#[tokio::test]
async fn completion_clears_and_mounts_only_the_completing_route() {
    let dir = temp();
    let first = OfferFixture::first();
    let second = OfferFixture::second();
    first.write_completed_setup(dir.path());
    second.seed_provider_offer(dir.path(), admits());
    let source = RoutedChain::new([first.bond_edge()], [first.ready_snapshot(ORIGIN, None)]);
    let work_mount = MountedWork::default();
    let setup_mount = MountedSetup::default();
    let mut runner = discover_two_route_runner(dir.path(), &work_mount, &setup_mount);

    assert!(
        runner.tick(&source).await,
        "both journal steps are answered"
    );
    assert!(
        setup_mount
            .service(&vouched_context(first_route_peer()))
            .is_none(),
        "the completing setup route is cleared",
    );
    assert!(
        work_mount
            .handler(&vouched_context(second_route_peer()))
            .is_none(),
        "the waiting peer cannot reach the completing peer's channel",
    );

    let wrong = accept_mounted_route(
        &work_mount,
        first_route_peer(),
        second.signed_accept_request(),
    )
    .await;
    assert!(
        !matches!(
            wrong.outcome,
            Some(accept_work_response::Outcome::Accepted(_))
        ),
        "A's route accepts no authorization for B's channel",
    );
    let accepted = accept_mounted_route(
        &work_mount,
        first_route_peer(),
        first.signed_accept_request(),
    )
    .await;
    assert!(
        matches!(
            accepted.outcome,
            Some(accept_work_response::Outcome::Accepted(_))
        ),
        "A's route accepts A's authorization",
    );

    let second_setup = setup_mount
        .service(&vouched_context(second_route_peer()))
        .expect("B's setup route remains mounted");
    let response: WithTrailer<ExchangeSetupResponse> = second_setup
        .exchange_setup(
            ExchangeSetupRequest::default(),
            vouched_context(second_route_peer()),
        )
        .await
        .unwrap_or_else(|error| panic!("B's setup route answers: {error}"))
        .into();
    let proposal = advanced_setup_bundle(response.response);
    assert_eq!(proposal.revision(), 1, "B remains at revision one");
    assert_eq!(
        proposal.bond_terms().parties.taker(),
        second.client().party_key(),
        "B still receives B's configured proposal",
    );
}

/// Readiness is recomputed from the selected route's fresh coherent
/// snapshot before every new signature. A contest on A invalidates only A;
/// B's independent snapshot and service remain ready. Retained answers and
/// already-expired proposals do not wait for another admission decision.
#[tokio::test]
async fn requests_use_local_observation_and_one_contested_route_does_not_disable_another() {
    let dir = temp();
    let first = OfferFixture::first();
    let second = OfferFixture::second();
    first.write_completed_setup(dir.path());
    second.write_completed_setup(dir.path());
    let source = RoutedChain::new(
        [first.bond_edge(), second.bond_edge()],
        [
            first.ready_snapshot(ORIGIN, None),
            second.ready_snapshot(ORIGIN, None),
        ],
    );
    let work_mount = MountedWork::default();
    let setup_mount = MountedSetup::default();
    let mut runner = discover_two_route_runner(dir.path(), &work_mount, &setup_mount);

    assert!(runner.tick(&source).await, "both completed routes mount");
    let first_request = first.signed_accept_request();
    let reads_before_request = source.0.lock().unwrap().snapshot_reads;
    let accepted =
        accept_mounted_route(&work_mount, first_route_peer(), first_request.clone()).await;
    assert!(
        matches!(
            accepted.outcome.as_ref(),
            Some(accept_work_response::Outcome::Accepted(_))
        ),
        "A's first fresh snapshot permits its signature",
    );

    assert_eq!(
        source.0.lock().unwrap().snapshot_reads,
        reads_before_request,
        "acceptance performs no validator reads"
    );

    source.set_snapshot(first.ready_snapshot(ORIGIN, Some(pending_contest(false))));
    let service = work_mount
        .service(&vouched_context(first_route_peer()))
        .unwrap();
    let checkpoint = service.with_state(ChannelState::checkpoint).unwrap();
    // Block the observer's read, not a request. Existing local evidence still
    // permits replies, and those replies cannot initiate validator I/O.
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    source.0.lock().unwrap().next_read = Some((entered.clone(), release.clone()));
    let observer_source = source.clone();
    let observing = tokio::spawn(async move { runner.tick(&observer_source).await });
    entered.acquire().await.unwrap().forget();
    let repeated = tokio::time::timeout(
        Duration::from_secs(1),
        accept_mounted_route(&work_mount, first_route_peer(), first_request.clone()),
    )
    .await
    .expect("a lost acknowledgement does not wait for admission");
    assert_eq!(
        repeated, accepted,
        "only the existing co-signature is returned"
    );

    let mut expired_authorization = first.authorization();
    expired_authorization.proposal_nonce = 2;
    expired_authorization.acceptance_deadline = ORIGIN - 1;
    let expired_id = work_id(first.descriptor().channel(), &expired_authorization);
    let expired = AcceptWorkRequest {
        authorization: expired_authorization.encode(),
        client_signature: first
            .client()
            .sign(signing_hash(expired_id))
            .as_bytes()
            .to_vec(),
        prepared_input: first_request.prepared_input.clone(),
    };
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        accept_mounted_route(&work_mount, first_route_peer(), expired),
    )
    .await
    .expect("known expiry does not wait for admission");
    assert!(matches!(response.outcome,
        Some(accept_work_response::Outcome::Refused(refusal))
            if refusal.code == WorkRefusalCode::Expired as i32));
    assert_eq!(
        service.with_state(ChannelState::checkpoint).unwrap(),
        checkpoint
    );
    release.add_permits(1);
    assert!(observing.await.unwrap());

    let mut fresh_authorization = first.authorization();
    fresh_authorization.proposal_nonce = 2;
    let fresh_id = work_id(first.descriptor().channel(), &fresh_authorization);
    let fresh = AcceptWorkRequest {
        authorization: fresh_authorization.encode(),
        client_signature: first
            .client()
            .sign(signing_hash(fresh_id))
            .as_bytes()
            .to_vec(),
        prepared_input: first_request.prepared_input,
    };
    let refused = accept_mounted_route(&work_mount, first_route_peer(), fresh).await;
    let Some(accept_work_response::Outcome::Refused(refusal)) = refused.outcome else {
        panic!("A's finalized contest prevents another provider signature")
    };
    assert_retryable_not_ready(refusal);

    let second_response = accept_mounted_route(
        &work_mount,
        second_route_peer(),
        second.signed_accept_request(),
    )
    .await;
    assert!(
        matches!(
            second_response.outcome,
            Some(accept_work_response::Outcome::Accepted(_))
        ),
        "B remains ready from B's own fresh snapshot",
    );
}

/// Connections are irrelevant to close duty. With neither peer dialled,
/// one tick still advances every owned journal and submits both unrelated
/// permissionless closes that their coherent snapshots make due.
#[tokio::test]
async fn one_tick_drives_every_owned_journal_without_connected_clients() {
    let dir = temp();
    let first = OfferFixture::first();
    let second = OfferFixture::second();
    first.write_completed_setup(dir.path());
    second.write_completed_setup(dir.path());
    let start_id = write_contested_channel(dir.path());
    let source = RoutedChain::new(
        [first.bond_edge(), second.bond_edge()],
        [
            first.channel_snapshot(ORIGIN, None, Some(pending_contest(true))),
            second.channel_snapshot(
                second.bond_terms().timeout.get(),
                Some(second.live_bond()),
                None,
            ),
        ],
    );
    let work_mount = MountedWork::default();
    let setup_mount = MountedSetup::default();
    let mut runner = discover_two_route_runner(dir.path(), &work_mount, &setup_mount);

    assert!(
        runner.tick(&source).await,
        "the one source answers both clocks"
    );
    let submitted = source.submitted();
    let adjudications = submitted
        .iter()
        .filter(|tx| {
            matches!(
                tx,
                Tx::Close {
                    input,
                    proof: Proof::Adjudicated { .. },
                    ..
                } if *input == first.payment_edge()
            )
        })
        .count();
    let timeouts = submitted
        .iter()
        .filter(|tx| {
            matches!(
                tx,
                Tx::Close {
                    input,
                    proof: Proof::Timeout { .. },
                    ..
                } if *input == second.bond_edge()
            )
        })
        .count();
    let responses = submitted
        .iter()
        .filter(|tx| {
            matches!(
                tx,
                Tx::Move {
                    action: Move::RespondPaymentClose(response),
                } if response.start_id() == start_id
            )
        })
        .count();
    assert_eq!(responses, 1, "A's retained response is resubmitted");
    assert_eq!(adjudications, 1, "A's adjudication is submitted");
    assert_eq!(timeouts, 1, "B's bond timeout is submitted");
    assert_eq!(
        submitted.len(),
        3,
        "one tick submits all three exact duties"
    );
    assert_eq!(
        runner.journal_count(),
        2,
        "both journals remain on the clock without a client",
    );
}

#[tokio::test]
async fn unmounted_work_refuses_every_method_as_bounded_retryable_not_ready() {
    let setup: WithTrailer<ExchangeSetupResponse> = UnmountedWork
        .exchange_setup(ExchangeSetupRequest::default(), TransportContext::default())
        .await
        .unwrap()
        .into();
    let Some(exchange_setup_response::Outcome::Refused(refusal)) = setup.response.outcome else {
        panic!("unmounted WorkSetup must refuse")
    };
    assert_retryable_not_ready(refusal);

    let accept: WithTrailer<AcceptWorkResponse> = UnmountedWork
        .accept_work(AcceptWorkRequest::default(), TransportContext::default())
        .await
        .unwrap()
        .into();
    let Some(accept_work_response::Outcome::Refused(refusal)) = accept.response.outcome else {
        panic!("unmounted Work must refuse acceptance")
    };
    assert_retryable_not_ready(refusal);

    let delivery: WithTrailer<DeliverResultResponse> = UnmountedWork
        .deliver_result(DeliverResultRequest::default(), TransportContext::default())
        .await
        .unwrap()
        .into();
    let Some(deliver_result_response::Outcome::Refused(refusal)) = delivery.response.outcome else {
        panic!("unmounted Work must refuse delivery")
    };
    assert_retryable_not_ready(refusal);

    let payment: WithTrailer<AdmitCertificateResponse> = UnmountedWork
        .admit_certificate(
            AdmitCertificateRequest::default(),
            TransportContext::default(),
        )
        .await
        .unwrap()
        .into();
    let Some(admit_certificate_response::Outcome::Refused(refusal)) = payment.response.outcome
    else {
        panic!("unmounted Work must refuse payment")
    };
    assert_retryable_not_ready(refusal);
}

// ── The clock's fixture ───────────────────────────────────────────
//
// Real journals under a real root, replayed by their own stores, and
// a chain a test writes down. Nothing here is a double for a journal
// or for the kernel: what is stood in for is consensus, which is one
// finalized read and one sink that keeps what it was handed.

const SALT: [u8; 32] = [0x5a; 32];
/// One over half the funding, so the bond exceeds the capacity it
/// leaves behind at zero fees.
const OMISSION_BOND: u64 = 601;
const PAYMENT_VALUE: u64 = 1_000;
const PAYMENT_RESERVE: u64 = 200;
/// The finalized block this channel's payment Open landed in, and so
/// the cursor every mount of it starts at.
const ORIGIN: u64 = 44;
/// Height at which the fixture contest's response window shuts. Above
/// the origin, which is what makes the answer below a timely one.
const RESPONSE_DEADLINE: u64 = 60;
/// The immutable history floor both journals are armed at.
const FLOOR: u64 = 7;

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-devnet") else {
        panic!("a short ascii id is a network id");
    };
    network
}

/// A threshold identity consensus accepts: the compressed BLS12-381 G1
/// generator used by the configuration loader's fixture too.
fn threshold_identity() -> Vec<u8> {
    vec![
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac,
        0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b,
        0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb,
        0x22, 0xc6, 0xbb,
    ]
}

fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn client() -> Secp256k1Signer {
    signer(0x21)
}

fn provider() -> Secp256k1Signer {
    signer(0x22)
}

/// The provider's RPC producer identity: the same scalar its channel
/// party key is.
fn provider_producer() -> ProducerSigningKey {
    let Ok(key) = ProducerSigningKey::from_secret_bytes([0x22; 32]) else {
        panic!("a fixed scalar is a producer key");
    };
    key
}

fn temp() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/hellas-cli-tests");
    if let Err(error) = std::fs::create_dir_all(&root) {
        panic!("the persistent test-artifact directory exists: {error}");
    }
    match tempfile::Builder::new()
        .prefix("paid-node-")
        .tempdir_in(root)
    {
        Ok(dir) => dir,
        Err(error) => panic!("a temporary directory: {error}"),
    }
}

fn test_remote_execution() -> RemoteExecutionServices {
    let directory = temp();
    let identity_path = directory.path().join("identity");
    let identity = crate::identity::load_or_create(Some(&identity_path))
        .expect("the test remote-execution identity is created");
    let executor = Executor::spawn_with_producer_key(
        ExecutePolicy::Deny,
        hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY,
        identity.producer_key.clone(),
        identity.enrollment.canonical_bytes(),
        Assurance::ProducerSigned,
    )
    .expect("the test remote-execution actor starts");
    RemoteExecutionServices {
        control: CacheController::new(&Default::default()),
        admin_policy: AdminPolicy::default(),
        executor,
        open_identity: identity.open_identity(),
    }
}

fn default_route_peer() -> PeerId {
    PeerId::from_bytes([0x31; 32])
}

fn first_route_peer() -> PeerId {
    PeerId::from_bytes([0x41; 32])
}

fn second_route_peer() -> PeerId {
    PeerId::from_bytes([0x42; 32])
}

fn vouched_context(peer: PeerId) -> TransportContext {
    TransportContext {
        peer: Some(PeerIdentity(peer.into_bytes())),
        auth_level: AuthLevel::Vouched,
        ..TransportContext::default()
    }
}

/// Builds routes through the production loader, the only constructor
/// that can establish their duplicate-peer and duplicate-bond invariants.
fn configured_routes(routes: &[(PeerId, EdgeId, Key)]) -> WorkRoutes {
    let route_values: Vec<_> = routes
        .iter()
        .map(|(peer, bond, client)| {
            serde_json::json!({
                "peer": hex::encode(peer.as_bytes()),
                "bond": hex::encode(bond.to_bytes()),
                "client": hex::encode(client.to_bytes()),
            })
        })
        .collect();
    let value = serde_json::json!({
        "chain": {
            "network_id": network().as_str(),
            "genesis_payload_digest": hex::encode([0x01; 32]),
            "threshold_identity": hex::encode(threshold_identity()),
        },
        "validators": (1..=6)
            .map(|index| format!("http://127.0.0.1:900{index}"))
            .collect::<Vec<_>>(),
        "journal": { "root": "/var/lib/hellas/work" },
        "routes": route_values,
        "policies": {
            "policy_salt": hex::encode(SALT),
            "channel": {
                "compute_credit_limit": 40,
                "delivery_credit_limit": 40,
            },
            "execution": {
                "allowed_environment": hex::encode([0x11; 32]),
                "generation_policy_digest": hex::encode([0x12; 32]),
                "identity_source_digest": hex::encode([0x13; 32]),
                "max_prompt_tokens": 512,
                "max_new_tokens": 128,
                "max_stop_token_ids": 4,
                "max_spool_bytes": 1_048_576_u64,
                "max_encoded_result_frame": 262_144,
                "max_encoded_quote_response": 1_048_576_u64,
                "dispatch_margin_blocks": 4,
                "delivery_margin_blocks": 2,
                "oracle_grace_blocks": 6,
                "fixed_price": 10,
            },
        },
        "poll_ms": 1,
        "expected_payment_values": {
            "value": PAYMENT_VALUE,
            "reserve": PAYMENT_RESERVE,
            "close_fees": { "base": 0, "slot": 0, "proof": 0, "lifetime": 0 },
        },
        "min_omit_response_blocks": MIN_OMIT_RESPONSE_BLOCKS,
    });
    let dir = temp();
    let path = dir.path().join("routes.json");
    if let Err(error) = std::fs::write(&path, value.to_string()) {
        panic!("the route fixture is written: {error}");
    }
    match load_work_config(&path) {
        Ok(config) => config.routes,
        Err(error) => panic!("the route fixture passes the production loader: {error}"),
    }
}

fn coins(ids: &[u8]) -> List<CoinId, MAX_PARTY_INPUTS> {
    let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
    for (slot, id) in slots.iter_mut().zip(ids) {
        *slot = CoinId::from_bytes([*id; CoinId::LENGTH]);
    }
    List::take(slots, ids.len())
}

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider().party_key(), client().party_key()),
        timeout: BlockHeight::new(500),
        timeout_outputs: List::take(
            [Payout::new(provider().party_key(), 64); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 40,
    }
}

fn bond_funding() -> Funding {
    Funding::new(coins(&[0xa1]), coins(&[]))
}

fn payment_funding() -> Funding {
    Funding::new(coins(&[0xb1]), coins(&[]))
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: 40,
        delivery_credit_limit: 40,
    }
}

fn execution_policy() -> PaidExecutionPolicyV1 {
    PaidExecutionPolicyV1 {
        allowed_environment: manifest().content_id(),
        generation_policy_digest: match generation_policy_digest(&text_policy().canonical_bytes()) {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture generation policy hashes: {error}"),
        },
        identity_source_digest: match identity_source_digest(&identity_artifact().canonical_bytes())
        {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture identity source hashes: {error}"),
        },
        max_prompt_tokens: 512,
        max_new_tokens: 128,
        max_stop_token_ids: 4,
        max_spool_bytes: 1_048_576,
        max_encoded_result_frame: 262_144,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
        fixed_price: 10,
    }
}

fn payment_terms() -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bond_edge(),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: MAX_START_VALIDITY_BLOCKS,
        omission_bond: OMISSION_BOND,
    }
}

fn provider_policy() -> ProviderChannelPolicy {
    ProviderChannelPolicy {
        network: network(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: execution_policy().into(),
        expected_payment_values: EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::ZERO),
        min_omit_response_blocks: MIN_OMIT_RESPONSE_BLOCKS,
    }
}

fn admits() -> PaymentAdmission {
    PaymentAdmission::Admits(Box::new(provider_policy()))
}

// ── The handshake this journal retains ────────────────────────────

fn proposed() -> WorkChannelSetupBundleV1 {
    let hash = Tx::open_hash(
        network(),
        &bond_funding(),
        &Terms::work_stake_bond(bond_terms()),
    );
    match WorkChannelSetupBundleV1::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        Auth::native(provider().sign(hash)),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture bond proposes: {error}"),
    }
}

fn countersigned(bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
    let bond_hash = bundle.bond_open_hash();
    let payment_hash = Tx::open_hash(
        network(),
        &payment_funding(),
        &Terms::work_payment(payment_terms()),
    );
    match bundle.countersign_bond_and_propose_payment(
        Auth::native(client().sign(bond_hash)),
        payment_funding(),
        payment_terms(),
        Auth::native(client().sign(payment_hash)),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment proposes: {error}"),
    }
}

fn completed(bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
    let Some(hash) = bundle.payment_open_hash() else {
        panic!("a proposed payment has an open hash");
    };
    match bundle.countersign_payment(Auth::native(provider().sign(hash))) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment countersigns: {error}"),
    }
}

fn bond_edge() -> EdgeId {
    Tx::edge_id_of(&bond_funding(), &Terms::work_stake_bond(bond_terms()))
}

fn payment_edge() -> EdgeId {
    Tx::edge_id_of(&payment_funding(), &Terms::work_payment(payment_terms()))
}

/// The channel the retained descriptor names, which is the one the
/// runner's mount must open.
fn descriptor() -> hellas_rpc::protocol::work_setup::CloseDescriptor {
    match provider_policy().describe_close(payment_edge(), payment_terms()) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the fixture close descriptor opens: {error}"),
    }
}

fn settlement() -> WorkPaymentSettlement {
    match descriptor().expected_settlement() {
        Ok(settlement) => settlement,
        Err(error) => panic!("the fixture edge prices both exits: {error}"),
    }
}

/// The payload digest of the synthetic block at `height`.
fn payload_at(height: u64) -> [u8; 32] {
    let mut payload = [0xc0; 32];
    for (slot, byte) in payload.iter_mut().zip(height.to_be_bytes()) {
        *slot = byte;
    }
    payload
}

fn origin() -> SetupOrigin {
    SetupOrigin {
        payment_edge: payment_edge(),
        height: ORIGIN,
        payload: payload_at(ORIGIN),
        parent: payload_at(ORIGIN - 1),
    }
}

/// A provider's setup journal, complete and recording where its
/// channel begins — which is exactly what a restarting node finds.
fn write_setup_journal(root: &Path) {
    let verifier = Secp256k1Verifier::new();
    let mut store = match SetupStore::open(root, network(), bond_edge(), Role::Provider, &verifier)
    {
        Ok(store) => store,
        Err(error) => panic!("the fixture setup journal opens: {error}"),
    };
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());
    let Some(terms) = three.payment_terms().cloned() else {
        panic!("a countersigned payment has terms");
    };
    let Some(edge) = three.payment_edge() else {
        panic!("a countersigned payment has an edge");
    };
    let close_descriptor = match provider_policy().describe_close(edge, terms) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the fixture close descriptor opens: {error}"),
    };
    for record in [
        SetupRecord::ScanArmed {
            height: FLOOR,
            payload: payload_at(FLOOR),
        },
        SetupRecord::Bundle {
            bundle: one.encode(),
        },
        SetupRecord::Bundle {
            bundle: two.encode(),
        },
        SetupRecord::ArmedBundle {
            bundle: three.encode(),
            close_descriptor: Box::new(close_descriptor),
        },
        SetupRecord::Complete {
            payment_edge: edge,
            origin_height: ORIGIN,
            origin_payload: payload_at(ORIGIN),
            origin_parent: payload_at(ORIGIN - 1),
        },
    ] {
        if let Err(error) = store.commit(record, &verifier) {
            panic!("the fixture setup record commits: {error}");
        }
    }
}

/// Reopens the channel journal the mount opens, under exactly the
/// channel, settlement, role and origin the descriptor fixes.
fn open_channel(root: &Path) -> ChannelStore {
    match ChannelStore::open(
        root,
        descriptor().channel().clone(),
        settlement(),
        Role::Provider,
        origin(),
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the fixture channel journal opens: {error}"),
    }
}

// ── One job, paid for, and then contested ─────────────────────────

fn manifest() -> ProgramManifest {
    ProgramManifest::new(
        Application::new(CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR)
            .expect("the causal-LM application identity is valid"),
        ContentId::from_bytes([0x16; 32]),
    )
}

fn prompt_tokens() -> TokenIds {
    TokenIds::from([9, 8, 7, 6])
}

fn text_policy() -> TextPolicy {
    TextPolicy::from_u32_stop_tokens(64, [2, 1])
}

fn identity_artifact() -> TextArtifact {
    TextArtifact::identity(BoundTermId::from_digest(manifest().content_id().digest()))
}

fn text_execution() -> TextExecution {
    TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    )
}

fn evaluate_request() -> EvaluateRequest {
    EvaluateRequest {
        text_execution: text_execution().input_id().digest(),
        runner_public_key: PublicKey::Secp256k1(client().party_key().to_bytes()),
        execution_environment: manifest().content_id(),
        nonce: [0x9e; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

fn bundle() -> PreparedPaidInputV1 {
    PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
}

fn deadlines() -> JobDeadlines {
    JobDeadlines {
        acceptance: 50,
        terminal: 100,
        payment: 200,
    }
}

fn authorization() -> PaidJobAuthorizationV1 {
    match propose_authorization(
        descriptor().channel(),
        &execution_policy(),
        &bundle(),
        1,
        deadlines(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    }
}

/// One complete signed transcript for the fixture request.
fn answer_transcript() -> Vec<OutputEventEnvelope> {
    let request = evaluate_request();
    let producer = provider_producer();
    let mut builder = EvaluateOutputTranscriptBuilder::new(
        input_commitment(&request),
        request.assurance,
        &producer,
    );
    let answer = vec![101_u32, 102, 103, 104, 105];
    if let Err(error) = builder.push_token_delta(answer.clone()) {
        panic!("a non-empty delta pushes: {error}");
    }
    let usage = EvaluateUsage {
        input_units: 4,
        output_units: answer.len() as u64,
    };
    let billable_units = match usage.billable_units() {
        Ok(units) => units,
        Err(error) => panic!("the fixture usage sums: {error}"),
    };
    match builder.finish(EvaluateTerminal {
        final_position: answer.len() as u64,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact: Digest::from_bytes([0x77; 32]),
        usage,
        billable_units,
    }) {
        Ok(events) => events,
        Err(error) => panic!("the fixture transcript finishes: {error}"),
    }
}

/// The executor-side seam in the node proof. The paid gate still
/// rebuilds the request from its journal; this backend supplies only
/// the terminal that a real executor would stream back.
#[derive(Clone)]
struct AnsweringPaidBackend {
    calls: Arc<AtomicUsize>,
}

impl PaidWorkBackend for AnsweringPaidBackend {
    async fn evaluate(
        &self,
        input: PreparedEvaluateInput,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        assert_eq!(
            input.evaluate_request().text_execution,
            evaluate_request().text_execution,
            "the paid gate dispatches the request retained in the accepted bundle",
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(answer_transcript())
    }
}

/// A paid backend whose call outlives the request-path assertion.
#[derive(Clone)]
struct BlockingPaidBackend {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl BlockingPaidBackend {
    fn new() -> Self {
        Self {
            entered: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }

    async fn wait_for_call(&self) {
        match self.entered.acquire().await {
            Ok(permit) => permit.forget(),
            Err(error) => panic!("the blocking backend stays open: {error}"),
        }
    }

    fn finish(&self) {
        self.release.add_permits(1);
    }
}

impl PaidWorkBackend for BlockingPaidBackend {
    async fn evaluate_stream(
        &self,
        input: PreparedEvaluateInput,
        progress: hellas_work::work::PaidProgress,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        for event in answer_transcript() {
            if event.event().body().kind() == hellas_rpc::evaluate::TOKEN_DELTA_EVENT_KIND {
                progress(event)?;
            }
        }
        self.evaluate(input).await
    }

    async fn evaluate(
        &self,
        _input: PreparedEvaluateInput,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        self.entered.add_permits(1);
        match self.release.acquire().await {
            Ok(permit) => permit.forget(),
            Err(error) => return Err(BackendFault::new(error.to_string())),
        }
        Ok(answer_transcript())
    }
}

fn commit(store: &mut ChannelStore, record: ChannelRecord) {
    if let Err(error) = store.commit(record, &Secp256k1Verifier::new()) {
        panic!("the fixture channel record commits: {error}");
    }
}

/// The provider journal a process can find after crashing between its
/// durable acceptance and the detached backend task's first poll.
fn write_accepted_channel(root: &Path) -> Digest {
    let channel = descriptor().channel().clone();
    let mut store = open_channel(root);
    let job = authorization();
    let id = work_id(&channel, &job);
    commit(
        &mut store,
        ChannelRecord::JobProposed {
            authorization: job,
            client_signature: client().sign(signing_hash(id)),
            prepared_input: match bundle().encode() {
                Ok(bytes) => bytes,
                Err(error) => panic!("the fixture bundle encodes: {error}"),
            },
        },
    );
    commit(
        &mut store,
        ChannelRecord::JobAccepted {
            work_id: id,
            provider_signature: provider().sign(signing_hash(id)),
        },
    );
    id
}

/// The channel journal a restarted provider finds: one job it
/// delivered and holds a signed certificate for, and a finalized
/// contest opened below that certificate.
///
/// It is written and closed here, so the runner opens it exactly as
/// a restart does — through the mount the setup driver hands back.
fn write_contested_channel(root: &Path) -> StartId {
    let channel = descriptor().channel().clone();
    let mut store = open_channel(root);
    let job = authorization();
    let id = work_id(&channel, &job);
    commit(
        &mut store,
        ChannelRecord::JobProposed {
            authorization: job,
            client_signature: client().sign(signing_hash(id)),
            prepared_input: match bundle().encode() {
                Ok(bytes) => bytes,
                Err(error) => panic!("the fixture bundle encodes: {error}"),
            },
        },
    );
    commit(
        &mut store,
        ChannelRecord::JobAccepted {
            work_id: id,
            provider_signature: provider().sign(signing_hash(id)),
        },
    );
    commit(&mut store, ChannelRecord::JobRunning { work_id: id });
    let transcript = answer_transcript();
    let result = match terminal_result(&channel, &job, &transcript) {
        Ok(result) => result,
        Err(error) => panic!("the fixture result derives: {error}"),
    };
    commit(
        &mut store,
        ChannelRecord::JobResult {
            work_id: id,
            result,
            provider_signature: provider().sign(signing_hash(result_digest(&channel, &result))),
            transcript: match encode_transcript(&transcript) {
                Ok(bytes) => bytes,
                Err(error) => panic!("the fixture transcript encodes: {error}"),
            },
        },
    );
    commit(&mut store, ChannelRecord::PlaintextReleased { work_id: id });
    let (certificate, binding) = match next_payment(&channel, &job, &result, 0, settlement()) {
        Ok(paid) => paid,
        Err(error) => panic!("the fixture payment builds: {error}"),
    };
    commit(
        &mut store,
        ChannelRecord::JobTerminated {
            work_id: id,
            outcome: TerminalOutcome::Certified {
                certificate,
                binding: Box::new(binding),
                binding_signature: client()
                    .sign(signing_hash(payment_binding_digest(&channel, &binding))),
                certificate_signature: client().sign(certificate.digest(network())),
            },
        },
    );
    let start_id = StartId::from_bytes([0x7c; 32]);
    commit(
        &mut store,
        ChannelRecord::CloseOpened {
            start_id,
            opener: Party::Maker,
            response_deadline: RESPONSE_DEADLINE,
            claimed: 0,
        },
    );
    start_id
}

/// The coherent finalized view the clock asks this fixture chain for.
fn channel_snapshot(
    height: u64,
    bond: Option<Edge>,
    pending: Option<RegistryChunk>,
) -> WorkChannelSnapshot {
    WorkChannelSnapshot::new(
        WorkChannelQuery {
            bond_edge: bond_edge(),
            payment_edge: payment_edge(),
            funding: BTreeSet::new(),
        },
        LatestBlock {
            height,
            payload: hellas_chain::domain::Digest::from(payload_at(height)),
            state_root: hellas_chain::domain::Digest::from([0xd0; 32]),
            finalization: Vec::new(),
        },
        bond,
        None,
        [None, None],
        pending,
        BTreeSet::new(),
    )
}

/// Canonical pending-close bytes for the fixture contest.
///
/// Written field by field because the kernel deliberately exposes the
/// consensus record for reading, not for callers to manufacture. The
/// decode at the end proves this literal is its canonical shape.
fn pending_contest(responded: bool) -> RegistryChunk {
    let mut value = Vec::with_capacity(PendingPaymentClose::ENCODED_SIZE);
    value.extend_from_slice(&[1, 23, 2]); // envelope and work-close version
    value.extend_from_slice(payment_edge().as_bytes());
    value.push(Party::Maker.tag());
    value.extend_from_slice(&[0x7c; StartId::LENGTH]);
    value.extend_from_slice(&RESPONSE_DEADLINE.to_be_bytes());
    value.extend_from_slice(&0_u64.to_be_bytes());
    let final_cumulative = if responded {
        execution_policy().fixed_price
    } else {
        0
    };
    value.extend_from_slice(&final_cumulative.to_be_bytes());
    value.push(u8::from(responded));
    value.push(u8::from(responded));
    value.extend_from_slice(&OMISSION_BOND.to_be_bytes());
    assert_eq!(value.len(), PendingPaymentClose::ENCODED_SIZE);
    let record = match PendingPaymentClose::decode_exact(&value) {
        Ok(record) => record,
        Err(error) => panic!("the fixture pending-close bytes decode: {error:?}"),
    };
    assert_eq!(record.responded(), responded);
    match RegistryChunk::split(
        RegistryNamespace::PaymentClose,
        RegistryRecordTag::PaymentPending,
        &value,
        0,
    ) {
        Some(chunk) => chunk,
        None => panic!("one pending close fits one registry chunk"),
    }
}

/// One readable live edge under the fixture bond's committed terms.
fn live_bond() -> Edge {
    let terms = Terms::work_stake_bond(bond_terms());
    let mut encoded = vec![0_u8; Edge::MAX_ENCODED_SIZE];
    let written = {
        let mut writer = BufferWriter::new(&mut encoded);
        writer.write(&[1, 5]); // canonical Edge envelope
        64_u64.encode_to(&mut writer);
        0_u64.encode_to(&mut writer);
        Fees::ZERO.encode_to(&mut writer);
        terms.timeout().encode_to(&mut writer);
        terms.parties().encode_to(&mut writer);
        terms.hash().encode_to(&mut writer);
        terms.allowed_closes().encode_to(&mut writer);
        writer.position()
    };
    match Edge::decode_exact(&encoded[..written]) {
        Ok(edge) => edge,
        Err(error) => panic!("the fixture live bond decodes: {error:?}"),
    }
}

/// The live payment edge at the values the measured artifact admitted.
fn live_payment() -> Edge {
    let terms = Terms::work_payment(payment_terms());
    let mut encoded = vec![0_u8; Edge::MAX_ENCODED_SIZE];
    let written = {
        let mut writer = BufferWriter::new(&mut encoded);
        writer.write(&[1, 5]); // canonical Edge envelope
        PAYMENT_VALUE.encode_to(&mut writer);
        PAYMENT_RESERVE.encode_to(&mut writer);
        Fees::ZERO.encode_to(&mut writer);
        terms.timeout().encode_to(&mut writer);
        terms.parties().encode_to(&mut writer);
        terms.hash().encode_to(&mut writer);
        terms.allowed_closes().encode_to(&mut writer);
        writer.position()
    };
    match Edge::decode_exact(&encoded[..written]) {
        Ok(edge) => edge,
        Err(error) => panic!("the fixture live payment decodes: {error:?}"),
    }
}

/// Canonical registry chunks for this payment channel's bond lease.
fn live_lease_slots() -> [Option<RegistryChunk>; 2] {
    let terms = payment_terms();
    let mut value = vec![1, 31, 2]; // envelope, BondLease tag, body version
    value.extend_from_slice(&bond_edge().to_bytes());
    value.extend_from_slice(&payment_edge().to_bytes());
    value.extend_from_slice(Terms::work_payment(terms.clone()).hash().as_bytes());
    value.extend_from_slice(&terms.private_policy_commitment);
    value.extend_from_slice(&terms.admission_horizon().get().to_be_bytes());
    let slots = [0, 1].map(|index| {
        RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &value,
            index,
        )
    });
    assert!(
        matches!(
            hellas_kernel::parse_bond_lease(slots, bond_edge()),
            LeaseSlots::Present(_)
        ),
        "the fixture lease is canonical",
    );
    slots
}

/// A coherent readable channel, optionally with a contest opened after
/// it was mounted.
fn ready_channel_snapshot(height: u64, pending: Option<RegistryChunk>) -> WorkChannelSnapshot {
    WorkChannelSnapshot::new(
        WorkChannelQuery {
            bond_edge: bond_edge(),
            payment_edge: payment_edge(),
            funding: BTreeSet::new(),
        },
        LatestBlock {
            height,
            payload: hellas_chain::domain::Digest::from(payload_at(height)),
            state_root: hellas_chain::domain::Digest::from([0xd1; 32]),
            finalization: Vec::new(),
        },
        Some(live_bond()),
        Some(live_payment()),
        live_lease_slots(),
        pending,
        BTreeSet::new(),
    )
}

// ── The chain a test writes down ──────────────────────────────────

/// One coherent finalized read, a tip that never moves, and a sink
/// that keeps what it was handed.
#[derive(Clone)]
struct TestChain(Arc<ChainState>);

struct ChainState {
    /// Everything a driver submitted, in the order it did.
    submitted: Mutex<Vec<Tx>>,
    /// The one coherent finalized channel read this chain answers with.
    snapshot: Mutex<WorkChannelSnapshot>,
    /// One permit added as `latest_height` is entered.
    entered: Semaphore,
    /// One permit the test adds to let `latest_height` out again.
    release: Semaphore,
    /// Whether `latest_height` waits at all.
    slow: bool,
}

impl TestChain {
    fn new() -> Self {
        Self::with(false)
    }

    /// A chain whose block read blocks until the test releases it.
    fn slow() -> Self {
        Self::with(true)
    }

    fn with(slow: bool) -> Self {
        Self(Arc::new(ChainState {
            submitted: Mutex::new(Vec::new()),
            snapshot: Mutex::new(channel_snapshot(ORIGIN, None, None)),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            slow,
        }))
    }

    fn submitted(&self) -> Vec<Tx> {
        match self.0.submitted.lock() {
            Ok(held) => held.clone(),
            Err(error) => panic!("the fixture sink is reachable: {error}"),
        }
    }

    fn set_snapshot(&self, snapshot: WorkChannelSnapshot) {
        match self.0.snapshot.lock() {
            Ok(mut held) => *held = snapshot,
            Err(error) => panic!("the fixture snapshot is reachable: {error}"),
        }
    }

    /// Waits until a caller is inside the block read.
    async fn wait_for_read(&self) {
        match self.0.entered.acquire().await {
            Ok(permit) => permit.forget(),
            Err(error) => panic!("the fixture chain is open: {error}"),
        }
    }

    fn release(&self) {
        self.0.release.add_permits(1);
    }
}

impl SetupView for TestChain {
    async fn finalized_setup(
        &self,
        _query: SetupQuery,
    ) -> Result<Option<FinalizedSetup>, BlockSourceError> {
        // Both edges consumed and no funding left live. A completed
        // setup reads its edge only to price the settlement, and an
        // absent one is what makes the mount fall back to the
        // descriptor's expectation — the same one this fixture's
        // journal was written under.
        Ok(Some(FinalizedSetup {
            height: ORIGIN,
            bond: None,
            payment: None,
            lease: LeaseSlots::Absent,
            live_funding: BTreeSet::new(),
        }))
    }
}

impl FinalizedWorkView for TestChain {
    async fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
        let snapshot = match self.0.snapshot.lock() {
            Ok(held) => held.clone(),
            Err(error) => {
                return Err(QueryError::StateUnavailable(format!(
                    "the fixture snapshot lock failed: {error}",
                )));
            }
        };
        if snapshot.query() != &query {
            return Err(QueryError::StateUnavailable(
                "the fixture was asked for another work channel".to_string(),
            ));
        }
        Ok(Some(snapshot))
    }
}

impl FinalizedBlocks for TestChain {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        if self.0.slow {
            self.0.entered.add_permits(1);
            match self.0.release.acquire().await {
                Ok(permit) => permit.forget(),
                Err(error) => panic!("the fixture chain is open: {error}"),
            }
        }
        Ok(Some(ORIGIN))
    }

    async fn block_at(&self, _height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        Ok(None)
    }
}

impl TxSink for TestChain {
    async fn submit(&self, tx: Tx) -> Result<SubmitTxOutcome, BlockSourceError> {
        match self.0.submitted.lock() {
            Ok(mut held) => held.push(tx),
            Err(error) => panic!("the fixture sink is reachable: {error}"),
        }
        Ok(SubmitTxOutcome::Enqueued)
    }
}

/// One finalized source with independent coherent snapshots for several
/// channels. It has no clients and no routing opinion: queries select only
/// by their signed channel identity, while every submission is retained so
/// one runner tick can be inspected as a whole.
#[derive(Clone)]
struct RoutedChain(Arc<Mutex<RoutedChainState>>);

struct RoutedChainState {
    snapshot_reads: usize,
    next_read: Option<(Arc<Semaphore>, Arc<Semaphore>)>,
    completed_setups: Vec<EdgeId>,
    snapshots: Vec<WorkChannelSnapshot>,
    submitted: Vec<Tx>,
}

impl RoutedChain {
    fn new(
        completed_setups: impl IntoIterator<Item = EdgeId>,
        snapshots: impl IntoIterator<Item = WorkChannelSnapshot>,
    ) -> Self {
        Self(Arc::new(Mutex::new(RoutedChainState {
            snapshot_reads: 0,
            next_read: None,
            completed_setups: completed_setups.into_iter().collect(),
            snapshots: snapshots.into_iter().collect(),
            submitted: Vec::new(),
        })))
    }

    fn set_snapshot(&self, snapshot: WorkChannelSnapshot) {
        match self.0.lock() {
            Ok(mut held) => {
                let query = snapshot.query().clone();
                if let Some(existing) = held
                    .snapshots
                    .iter_mut()
                    .find(|existing| existing.query() == &query)
                {
                    *existing = snapshot;
                } else {
                    held.snapshots.push(snapshot);
                }
            }
            Err(error) => panic!("the routed source is reachable: {error}"),
        }
    }

    fn submitted(&self) -> Vec<Tx> {
        match self.0.lock() {
            Ok(held) => held.submitted.clone(),
            Err(error) => panic!("the routed sink is reachable: {error}"),
        }
    }
}

impl SetupView for RoutedChain {
    async fn finalized_setup(
        &self,
        query: SetupQuery,
    ) -> Result<Option<FinalizedSetup>, BlockSourceError> {
        let known = self
            .0
            .lock()
            .map_err(|error| BlockSourceError::new(format!("the setup lock failed: {error}")))?
            .completed_setups
            .contains(&query.bond_edge);
        if !known {
            return Err(BlockSourceError::new(
                "the routed source was asked for an unconfigured setup",
            ));
        }
        Ok(Some(FinalizedSetup {
            height: ORIGIN,
            bond: None,
            payment: None,
            lease: LeaseSlots::Absent,
            live_funding: BTreeSet::new(),
        }))
    }
}

impl FinalizedWorkView for RoutedChain {
    async fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
        let gate = {
            let mut state = self.0.lock().unwrap();
            state.snapshot_reads += 1;
            state.next_read.take()
        };
        if let Some((entered, release)) = gate {
            entered.add_permits(1);
            release.acquire().await.unwrap().forget();
        }
        match self.0.lock() {
            Ok(held) => held
                .snapshots
                .iter()
                .find(|snapshot| snapshot.query() == &query)
                .cloned()
                .map(Some)
                .ok_or_else(|| {
                    QueryError::StateUnavailable(
                        "the routed source was asked for another channel".to_string(),
                    )
                }),
            Err(error) => Err(QueryError::StateUnavailable(format!(
                "the routed snapshot lock failed: {error}",
            ))),
        }
    }
}

impl FinalizedBlocks for RoutedChain {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(Some(ORIGIN))
    }

    async fn block_at(&self, _height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        Ok(None)
    }
}

impl TxSink for RoutedChain {
    async fn submit(&self, tx: Tx) -> Result<SubmitTxOutcome, BlockSourceError> {
        self.0
            .lock()
            .map_err(|error| BlockSourceError::new(format!("the sink lock failed: {error}")))?
            .submitted
            .push(tx);
        Ok(SubmitTxOutcome::Enqueued)
    }
}

/// The injectable finalized source used by the ALPN proof. It starts
/// at the scan floor, finalizes each setup Open handed to its sink in
/// the next block, and exposes the resulting channel through the same
/// coherent snapshot interface production uses.
#[derive(Clone)]
struct NodeChain(Arc<Mutex<NodeChainState>>);

struct NodeChainState {
    setup: FinalizedSetup,
    snapshot: WorkChannelSnapshot,
    blocks: Vec<FinalizedWork>,
    submitted: Vec<Tx>,
}

impl NodeChain {
    fn new() -> Self {
        let live_funding = [
            CoinId::from_bytes([0xa1; CoinId::LENGTH]),
            CoinId::from_bytes([0xb1; CoinId::LENGTH]),
        ]
        .into_iter()
        .collect();
        Self(Arc::new(Mutex::new(NodeChainState {
            setup: FinalizedSetup {
                height: FLOOR,
                bond: None,
                payment: None,
                lease: LeaseSlots::Absent,
                live_funding,
            },
            snapshot: WorkChannelSnapshot::new(
                WorkChannelQuery {
                    bond_edge: bond_edge(),
                    payment_edge: payment_edge(),
                    funding: BTreeSet::new(),
                },
                LatestBlock {
                    height: FLOOR,
                    payload: hellas_chain::domain::Digest::from(payload_at(FLOOR)),
                    state_root: hellas_chain::domain::Digest::from([0xd1; 32]),
                    finalization: Vec::new(),
                },
                None,
                None,
                [None, None],
                None,
                BTreeSet::new(),
            ),
            blocks: Vec::new(),
            submitted: Vec::new(),
        })))
    }

    fn latest(&self) -> u64 {
        match self.0.lock() {
            Ok(held) => held.blocks.last().map_or(FLOOR, |block| block.height),
            Err(error) => panic!("the node-chain fixture is reachable: {error}"),
        }
    }

    fn submitted(&self) -> Vec<Tx> {
        match self.0.lock() {
            Ok(held) => held.submitted.clone(),
            Err(error) => panic!("the node-chain fixture is reachable: {error}"),
        }
    }

    /// Exposes a pending client contest one finalized height after
    /// mount. The otherwise empty block is deliberate: it proves that
    /// cursor catch-up alone cannot substitute for the coherent state
    /// predicate, without letting the raw journal's own close refusal
    /// mask a stale-readiness mutation.
    fn open_contest(&self) -> u64 {
        let current = self.latest();
        let height = current + 1;
        let block = FinalizedWork {
            height,
            parent: payload_at(current),
            payload: payload_at(height),
            txs: Vec::new(),
        };
        match self.0.lock() {
            Ok(mut held) => {
                held.blocks.push(block);
                held.snapshot = ready_channel_snapshot(height, Some(pending_contest(false)));
            }
            Err(error) => panic!("the node-chain fixture is reachable: {error}"),
        }
        height
    }
}

impl SetupView for NodeChain {
    async fn finalized_setup(
        &self,
        query: SetupQuery,
    ) -> Result<Option<FinalizedSetup>, BlockSourceError> {
        let expected_funding = [
            CoinId::from_bytes([0xa1; CoinId::LENGTH]),
            CoinId::from_bytes([0xb1; CoinId::LENGTH]),
        ]
        .into_iter()
        .collect();
        if query.bond_edge != bond_edge()
            || query.payment_edge != payment_edge()
            || query.funding != expected_funding
        {
            return Err(BlockSourceError::new(
                "the fixture was asked for another setup",
            ));
        }
        match self.0.lock() {
            Ok(held) => Ok(Some(held.setup.clone())),
            Err(error) => Err(BlockSourceError::new(format!(
                "the node-chain setup lock failed: {error}",
            ))),
        }
    }
}

impl FinalizedWorkView for NodeChain {
    async fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
        match self.0.lock() {
            Ok(held) if held.snapshot.query() == &query => Ok(Some(held.snapshot.clone())),
            Ok(_) => Err(QueryError::StateUnavailable(
                "the fixture was asked for another work channel".to_string(),
            )),
            Err(error) => Err(QueryError::StateUnavailable(format!(
                "the node-chain snapshot lock failed: {error}",
            ))),
        }
    }
}

impl FinalizedBlocks for NodeChain {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(Some(self.latest()))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        match self.0.lock() {
            Ok(held) => Ok(held
                .blocks
                .iter()
                .find(|block| block.height == height)
                .cloned()),
            Err(error) => Err(BlockSourceError::new(format!(
                "the node-chain block lock failed: {error}",
            ))),
        }
    }
}

impl TxSink for NodeChain {
    async fn submit(&self, tx: Tx) -> Result<SubmitTxOutcome, BlockSourceError> {
        let mut held = self
            .0
            .lock()
            .map_err(|error| BlockSourceError::new(format!("the sink lock failed: {error}")))?;
        held.submitted.push(tx.clone());
        let open_number = held
            .blocks
            .iter()
            .flat_map(|block| &block.txs)
            .filter(|tx| matches!(tx, Tx::Open { .. }))
            .count();
        if !matches!(tx, Tx::Open { .. }) {
            return Ok(SubmitTxOutcome::Enqueued);
        }
        let height = held
            .blocks
            .last()
            .map_or(FLOOR + 1, |block| block.height + 1);
        held.blocks.push(FinalizedWork {
            height,
            parent: payload_at(height - 1),
            payload: payload_at(height),
            txs: vec![tx],
        });
        match open_number {
            0 => {
                held.setup = FinalizedSetup {
                    height,
                    bond: Some(live_bond()),
                    payment: None,
                    lease: LeaseSlots::Absent,
                    live_funding: [CoinId::from_bytes([0xb1; CoinId::LENGTH])]
                        .into_iter()
                        .collect(),
                };
            }
            1 => {
                let lease = hellas_kernel::parse_bond_lease(live_lease_slots(), bond_edge());
                held.setup = FinalizedSetup {
                    height,
                    bond: Some(live_bond()),
                    payment: Some(live_payment()),
                    lease,
                    live_funding: BTreeSet::new(),
                };
                held.snapshot = ready_channel_snapshot(height, None);
            }
            other => {
                return Err(BlockSourceError::new(format!(
                    "the fixture received unexpected setup Open {}",
                    other + 1,
                )));
            }
        }
        Ok(SubmitTxOutcome::Enqueued)
    }
}

/// The runner a node starts with: the configured root, the stored
/// identity, and the policy it was configured with.
fn runner(root: &Path, policy: ProviderChannelPolicy, mount: &MountedWork) -> WorkRunner {
    match WorkRunner::discover(
        WorkRunnerConfig {
            network: network(),
            threshold_identity: threshold_identity(),
            journal_root: root.to_path_buf(),
            routes: configured_routes(&[(default_route_peer(), bond_edge(), client().party_key())]),
            validators: Vec::new(),
            poll: Duration::from_millis(1),
            max_observation_age: Duration::from_secs(5),
            settlement_key: provider(),
            policy,
        },
        mount.clone(),
        MountedSetup::default(),
    ) {
        Ok(runner) => runner,
        Err(error) => panic!("the configured root enumerates: {error}"),
    }
}

/// The one contest this fixture's sink was handed an answer to.
fn responded(chain: &TestChain) -> StartId {
    let submitted = chain.submitted();
    let [
        Tx::Move {
            action: Move::RespondPaymentClose(response),
        },
    ] = submitted.as_slice()
    else {
        panic!("the clock submits exactly one contest answer: {submitted:?}");
    };
    response.start_id()
}

fn adjudicated_payment_closes(chain: &TestChain) -> usize {
    chain
        .submitted()
        .iter()
        .filter(|tx| {
            matches!(
                tx,
                Tx::Close {
                    input,
                    proof: Proof::Adjudicated { .. },
                    ..
                } if *input == payment_edge()
            )
        })
        .count()
}

fn seed_provider_offer(root: &Path, admission: PaymentAdmission) {
    let store = match SetupStore::open(
        root,
        network(),
        bond_edge(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the empty provider root opens its first setup: {error}"),
    };
    let mut endpoint = SetupEndpoint::new(store, provider(), admission);
    if let Err(error) = endpoint.arm_scan(SetupScan {
        height: FLOOR,
        payload: payload_at(FLOOR),
    }) {
        panic!("the provider arms its finalized floor: {error}");
    }
    if let Err(error) = endpoint.propose_bond(network(), bond_funding(), bond_terms()) {
        panic!("the provider journals its offer: {error}");
    }
}

#[derive(Clone, Copy)]
struct OfferFixture {
    client_seed: u8,
    bond_coin: u8,
    payment_coin: u8,
}

impl OfferFixture {
    const fn first() -> Self {
        Self {
            client_seed: 0x21,
            bond_coin: 0xa1,
            payment_coin: 0xb1,
        }
    }

    const fn second() -> Self {
        Self {
            client_seed: 0x23,
            bond_coin: 0xa2,
            payment_coin: 0xb2,
        }
    }

    fn client(self) -> Secp256k1Signer {
        signer(self.client_seed)
    }

    fn bond_funding(self) -> Funding {
        Funding::new(coins(&[self.bond_coin]), coins(&[]))
    }

    fn bond_terms(self) -> WorkStakeBondTerms {
        WorkStakeBondTerms {
            parties: Parties::new(provider().party_key(), self.client().party_key()),
            timeout: BlockHeight::new(500),
            timeout_outputs: List::take(
                [Payout::new(provider().party_key(), 64); MAX_EDGE_OUTPUTS],
                1,
            ),
            max_job_price: 40,
        }
    }

    fn bond_edge(self) -> EdgeId {
        Tx::edge_id_of(
            &self.bond_funding(),
            &Terms::work_stake_bond(self.bond_terms()),
        )
    }

    fn payment_funding(self) -> Funding {
        Funding::new(coins(&[self.payment_coin]), coins(&[]))
    }

    fn payment_terms(self) -> WorkPaymentTerms {
        WorkPaymentTerms {
            bond_edge: self.bond_edge(),
            bond_terms: self.bond_terms(),
            private_policy_commitment: private_policy_commitment(
                network(),
                &SALT,
                &channel_policy(),
            ),
            omit_response_blocks: MIN_OMIT_RESPONSE_BLOCKS,
            start_validity_blocks: MAX_START_VALIDITY_BLOCKS,
            omission_bond: OMISSION_BOND,
        }
    }

    fn payment_edge(self) -> EdgeId {
        Tx::edge_id_of(
            &self.payment_funding(),
            &Terms::work_payment(self.payment_terms()),
        )
    }

    fn proposed(self) -> WorkChannelSetupBundleV1 {
        let hash = Tx::open_hash(
            network(),
            &self.bond_funding(),
            &Terms::work_stake_bond(self.bond_terms()),
        );
        match WorkChannelSetupBundleV1::propose_bond(
            network(),
            self.bond_funding(),
            self.bond_terms(),
            Auth::native(provider().sign(hash)),
        ) {
            Ok(bundle) => bundle,
            Err(error) => panic!("the routed bond proposes: {error}"),
        }
    }

    fn countersigned(self, bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
        let bond_hash = bundle.bond_open_hash();
        let payment_hash = Tx::open_hash(
            network(),
            &self.payment_funding(),
            &Terms::work_payment(self.payment_terms()),
        );
        match bundle.countersign_bond_and_propose_payment(
            Auth::native(self.client().sign(bond_hash)),
            self.payment_funding(),
            self.payment_terms(),
            Auth::native(self.client().sign(payment_hash)),
        ) {
            Ok(bundle) => bundle,
            Err(error) => panic!("the routed payment proposes: {error}"),
        }
    }

    fn completed(self, bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
        let Some(hash) = bundle.payment_open_hash() else {
            panic!("the routed payment has an open hash");
        };
        match bundle.countersign_payment(Auth::native(provider().sign(hash))) {
            Ok(bundle) => bundle,
            Err(error) => panic!("the routed payment countersigns: {error}"),
        }
    }

    fn descriptor(self) -> hellas_rpc::protocol::work_setup::CloseDescriptor {
        match provider_policy().describe_close(self.payment_edge(), self.payment_terms()) {
            Ok(descriptor) => descriptor,
            Err(error) => panic!("the routed close descriptor opens: {error}"),
        }
    }

    fn write_completed_setup(self, root: &Path) {
        let verifier = Secp256k1Verifier::new();
        let mut store =
            match SetupStore::open(root, network(), self.bond_edge(), Role::Provider, &verifier) {
                Ok(store) => store,
                Err(error) => panic!("the routed setup journal opens: {error}"),
            };
        let one = self.proposed();
        let two = self.countersigned(one.clone());
        let three = self.completed(two.clone());
        let close_descriptor = self.descriptor();
        for record in [
            SetupRecord::ScanArmed {
                height: FLOOR,
                payload: payload_at(FLOOR),
            },
            SetupRecord::Bundle {
                bundle: one.encode(),
            },
            SetupRecord::Bundle {
                bundle: two.encode(),
            },
            SetupRecord::ArmedBundle {
                bundle: three.encode(),
                close_descriptor: Box::new(close_descriptor),
            },
            SetupRecord::Complete {
                payment_edge: self.payment_edge(),
                origin_height: ORIGIN,
                origin_payload: payload_at(ORIGIN),
                origin_parent: payload_at(ORIGIN - 1),
            },
        ] {
            if let Err(error) = store.commit(record, &verifier) {
                panic!("the routed setup record commits: {error}");
            }
        }
    }

    fn evaluate_request(self) -> EvaluateRequest {
        EvaluateRequest {
            text_execution: text_execution().input_id().digest(),
            runner_public_key: PublicKey::Secp256k1(self.client().party_key().to_bytes()),
            execution_environment: manifest().content_id(),
            nonce: [self.client_seed; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        }
    }

    fn prepared_bundle(self) -> PreparedPaidInputV1 {
        PreparedPaidInputV1::new(
            &self.evaluate_request(),
            &manifest(),
            &text_execution(),
            &prompt_tokens(),
            &text_policy(),
            &identity_artifact(),
        )
    }

    fn authorization(self) -> PaidJobAuthorizationV1 {
        match propose_authorization(
            self.descriptor().channel(),
            &execution_policy(),
            &self.prepared_bundle(),
            1,
            deadlines(),
        ) {
            Ok(authorization) => authorization,
            Err(error) => panic!("the routed authorization builds: {error}"),
        }
    }

    fn signed_accept_request(self) -> AcceptWorkRequest {
        let authorization = self.authorization();
        let id = work_id(self.descriptor().channel(), &authorization);
        AcceptWorkRequest {
            authorization: authorization.encode(),
            client_signature: self.client().sign(signing_hash(id)).as_bytes().to_vec(),
            prepared_input: match self.prepared_bundle().encode() {
                Ok(bytes) => bytes,
                Err(error) => panic!("the routed prepared input encodes: {error}"),
            },
        }
    }

    fn live_bond(self) -> Edge {
        let terms = Terms::work_stake_bond(self.bond_terms());
        let mut encoded = vec![0_u8; Edge::MAX_ENCODED_SIZE];
        let written = {
            let mut writer = BufferWriter::new(&mut encoded);
            writer.write(&[1, 5]);
            64_u64.encode_to(&mut writer);
            0_u64.encode_to(&mut writer);
            Fees::ZERO.encode_to(&mut writer);
            terms.timeout().encode_to(&mut writer);
            terms.parties().encode_to(&mut writer);
            terms.hash().encode_to(&mut writer);
            terms.allowed_closes().encode_to(&mut writer);
            writer.position()
        };
        match Edge::decode_exact(&encoded[..written]) {
            Ok(edge) => edge,
            Err(error) => panic!("the routed live bond decodes: {error:?}"),
        }
    }

    fn live_payment(self) -> Edge {
        let terms = Terms::work_payment(self.payment_terms());
        let mut encoded = vec![0_u8; Edge::MAX_ENCODED_SIZE];
        let written = {
            let mut writer = BufferWriter::new(&mut encoded);
            writer.write(&[1, 5]);
            PAYMENT_VALUE.encode_to(&mut writer);
            PAYMENT_RESERVE.encode_to(&mut writer);
            Fees::ZERO.encode_to(&mut writer);
            terms.timeout().encode_to(&mut writer);
            terms.parties().encode_to(&mut writer);
            terms.hash().encode_to(&mut writer);
            terms.allowed_closes().encode_to(&mut writer);
            writer.position()
        };
        match Edge::decode_exact(&encoded[..written]) {
            Ok(edge) => edge,
            Err(error) => panic!("the routed live payment decodes: {error:?}"),
        }
    }

    fn live_lease_slots(self) -> [Option<RegistryChunk>; 2] {
        let terms = self.payment_terms();
        let mut value = vec![1, 31, 2];
        value.extend_from_slice(&self.bond_edge().to_bytes());
        value.extend_from_slice(&self.payment_edge().to_bytes());
        value.extend_from_slice(Terms::work_payment(terms.clone()).hash().as_bytes());
        value.extend_from_slice(&terms.private_policy_commitment);
        value.extend_from_slice(&terms.admission_horizon().get().to_be_bytes());
        let slots = [0, 1].map(|index| {
            RegistryChunk::split(
                RegistryNamespace::BondLease,
                RegistryRecordTag::BondLease,
                &value,
                index,
            )
        });
        assert!(
            matches!(
                hellas_kernel::parse_bond_lease(slots, self.bond_edge()),
                LeaseSlots::Present(_)
            ),
            "the routed lease is canonical",
        );
        slots
    }

    fn channel_snapshot(
        self,
        height: u64,
        bond: Option<Edge>,
        pending: Option<RegistryChunk>,
    ) -> WorkChannelSnapshot {
        WorkChannelSnapshot::new(
            WorkChannelQuery {
                bond_edge: self.bond_edge(),
                payment_edge: self.payment_edge(),
                funding: BTreeSet::new(),
            },
            LatestBlock {
                height,
                payload: hellas_chain::domain::Digest::from(payload_at(height)),
                state_root: hellas_chain::domain::Digest::from([0xd2; 32]),
                finalization: Vec::new(),
            },
            bond,
            None,
            [None, None],
            pending,
            BTreeSet::new(),
        )
    }

    fn ready_snapshot(self, height: u64, pending: Option<RegistryChunk>) -> WorkChannelSnapshot {
        WorkChannelSnapshot::new(
            WorkChannelQuery {
                bond_edge: self.bond_edge(),
                payment_edge: self.payment_edge(),
                funding: BTreeSet::new(),
            },
            LatestBlock {
                height,
                payload: hellas_chain::domain::Digest::from(payload_at(height)),
                state_root: hellas_chain::domain::Digest::from([0xd3; 32]),
                finalization: Vec::new(),
            },
            Some(self.live_bond()),
            Some(self.live_payment()),
            self.live_lease_slots(),
            pending,
            BTreeSet::new(),
        )
    }

    fn seed_provider_offer(self, root: &Path, admission: PaymentAdmission) {
        let store = match SetupStore::open(
            root,
            network(),
            self.bond_edge(),
            Role::Provider,
            &Secp256k1Verifier::new(),
        ) {
            Ok(store) => store,
            Err(error) => panic!("the provider route opens its setup: {error}"),
        };
        let mut endpoint = SetupEndpoint::new(store, provider(), admission);
        if let Err(error) = endpoint.arm_scan(SetupScan {
            height: FLOOR,
            payload: payload_at(FLOOR),
        }) {
            panic!("the provider route arms its finalized floor: {error}");
        }
        if let Err(error) = endpoint.propose_bond(network(), self.bond_funding(), self.bond_terms())
        {
            panic!("the provider route journals its offer: {error}");
        }
    }
}

fn client_setup(root: &Path, policy: ProviderChannelPolicy) -> SetupEndpoint {
    let store = match SetupStore::open(
        root,
        network(),
        bond_edge(),
        Role::Client,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the empty client root opens its first setup: {error}"),
    };
    SetupEndpoint::new(
        store,
        client(),
        PaymentAdmission::Proposes(Box::new(policy)),
    )
}

fn signed_accept_request() -> AcceptWorkRequest {
    let authorization = authorization();
    let id = work_id(descriptor().channel(), &authorization);
    AcceptWorkRequest {
        authorization: authorization.encode(),
        client_signature: client().sign(signing_hash(id)).as_bytes().to_vec(),
        prepared_input: match bundle().encode() {
            Ok(bytes) => bytes,
            Err(error) => panic!("the prepared fixture input encodes: {error}"),
        },
    }
}

/// A node endpoint with the production ALPN dispatcher and production
/// runner loop, parameterized only at the existing finalized-source
/// seam.
struct RunningPaidNode {
    endpoint: Endpoint,
    client: Endpoint,
    target: EndpointAddr,
    accept_task: JoinHandle<()>,
    runner_task: JoinHandle<()>,
    stop: Option<oneshot::Sender<()>>,
    setup_mount: MountedSetup,
    work_mount: MountedWork,
    execution_calls: Arc<AtomicUsize>,
    peer: PeerId,
}

impl RunningPaidNode {
    async fn start(root: &Path, policy: ProviderChannelPolicy, source: NodeChain) -> Self {
        let setup_mount = MountedSetup::default();
        let execution_calls = Arc::new(AtomicUsize::new(0));
        let peer = PeerId::from_bytes(*SecretKey::from_bytes(&[0x62; 32]).public().as_bytes());
        let work_mount = MountedWork::with_backend(AnsweringPaidBackend {
            calls: Arc::clone(&execution_calls),
        });
        let runner = match WorkRunner::discover(
            WorkRunnerConfig {
                network: network(),
                threshold_identity: threshold_identity(),
                journal_root: root.to_path_buf(),
                routes: configured_routes(&[(peer, bond_edge(), client().party_key())]),
                validators: Vec::new(),
                poll: Duration::from_millis(1),
                max_observation_age: Duration::from_secs(5),
                settlement_key: provider(),
                policy,
            },
            work_mount.clone(),
            setup_mount.clone(),
        ) {
            Ok(runner) => runner,
            Err(error) => panic!("the node discovers its provider offer: {error}"),
        };

        let alpns = served_alpns(true);
        assert!(
            alpns.contains(&<WorkSetup as ServiceMarker>::ALPN.as_bytes().to_vec())
                && alpns.contains(&<Work as ServiceMarker>::ALPN.as_bytes().to_vec()),
            "the started node advertises both paid-work ALPNs",
        );
        let endpoint = match Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[0x61; 32]))
            .alpns(alpns)
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("a loopback socket"),
            ) {
            Ok(builder) => match builder.bind().await {
                Ok(endpoint) => endpoint,
                Err(error) => panic!("the test node binds: {error}"),
            },
            Err(error) => panic!("the test node has a valid bind address: {error}"),
        };
        let target = EndpointAddr::from_parts(
            endpoint.id(),
            endpoint.bound_sockets().into_iter().map(TransportAddr::Ip),
        );
        let client = match Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[0x62; 32]))
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("a loopback socket"),
            ) {
            Ok(builder) => match builder.bind().await {
                Ok(endpoint) => endpoint,
                Err(error) => panic!("the test client binds: {error}"),
            },
            Err(error) => panic!("the test client has a valid bind address: {error}"),
        };

        let local_peer = PeerId::from_bytes(*endpoint.id().as_bytes());
        let directory = Arc::new(PeerDirectory::with_config(
            local_peer,
            hellas_rpc::peer_directory_config(),
        ));
        let node_handler = NodeHandlerImpl::new(
            endpoint.id(),
            "paid-node-e2e".to_string(),
            Vec::new(),
            directory.clone(),
        );
        let accepting_endpoint = endpoint.clone();
        let setup_for_accept = setup_mount.clone();
        let work_for_accept = work_mount.clone();
        let execution_for_accept = test_remote_execution();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = accepting_endpoint.accept().await {
                let accepting = match incoming.accept() {
                    Ok(accepting) => accepting,
                    Err(error) => panic!("the test node accepts an incoming: {error}"),
                };
                let node_handler = node_handler.clone();
                let manager = directory.manager();
                let setup = setup_for_accept.clone();
                let work = work_for_accept.clone();
                let execution = execution_for_accept.clone();
                tokio::spawn(async move {
                    let connection = match accepting.await {
                        Ok(connection) => connection,
                        Err(error) => panic!("the test node negotiates a connection: {error}"),
                    };
                    let alpn = connection.alpn().to_vec();
                    if let Err(error) = serve_connection(
                        alpn,
                        connection,
                        execution,
                        node_handler,
                        manager,
                        Some(setup),
                        Some(work),
                    )
                    .await
                    {
                        panic!("the test node serves its connection: {error}");
                    }
                });
            }
        });

        let (stop, stopped) = oneshot::channel();
        let runner_task = tokio::spawn(async move {
            runner
                .run_over(stopped, move || {
                    let source = source.clone();
                    async move { Some(source) }
                })
                .await;
        });

        Self {
            endpoint,
            client,
            target,
            accept_task,
            runner_task,
            stop: Some(stop),
            setup_mount,
            work_mount,
            execution_calls,
            peer,
        }
    }

    fn context(&self) -> TransportContext {
        vouched_context(self.peer)
    }

    async fn connect(&self, alpn: &[u8]) -> (IrohTransport, Connection) {
        let connecting = self.client.connect(self.target.clone(), alpn);
        let connection = match tokio::time::timeout(Duration::from_secs(5), connecting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => panic!("the advertised ALPN is dialable: {error}"),
            Err(_) => panic!("the advertised ALPN dial timed out"),
        };
        let closing = connection.clone();
        (IrohTransport::new(connection), closing)
    }

    async fn exchange_setup(&self, request: ExchangeSetupRequest) -> ExchangeSetupResponse {
        let (transport, connection) = self
            .connect(<WorkSetup as ServiceMarker>::ALPN.as_bytes())
            .await;
        let client = WorkSetupClientImpl::new(transport);
        let response = match client.exchange_setup(request).await {
            Ok(response) => response,
            Err(error) => panic!("WorkSetup exchange reaches the node: {error}"),
        };
        drop(client);
        connection.close(0_u32.into(), b"setup round complete");
        response
    }

    async fn accept_work(&self, request: AcceptWorkRequest) -> AcceptWorkResponse {
        let (transport, connection) = self.connect(<Work as ServiceMarker>::ALPN.as_bytes()).await;
        let client = WorkClientImpl::new(transport);
        let response = match client.accept_work(request).await {
            Ok(response) => response,
            Err(error) => panic!("Work acceptance reaches the node: {error}"),
        };
        drop(client);
        connection.close(0_u32.into(), b"work request complete");
        response
    }

    async fn deliver_result(&self, work_id: Digest) -> DeliverResultResponse {
        let (transport, connection) = self.connect(<Work as ServiceMarker>::ALPN.as_bytes()).await;
        let exporter = match transport.open_exporter() {
            Ok(exporter) => exporter,
            Err(error) => panic!("the client derives this Work connection's exporter: {error}"),
        };
        let request = DeliverResultRequest {
            work_id: work_id.as_bytes().to_vec(),
            client_signature: client()
                .sign(signing_hash(delivery_request_digest(
                    descriptor().channel(),
                    work_id,
                    &exporter,
                )))
                .as_bytes()
                .to_vec(),
        };
        let client = WorkClientImpl::new(transport);
        let response = match client.deliver_result(request).await {
            Ok(response) => response,
            Err(error) => panic!("Work delivery reaches the node: {error}"),
        };
        drop(client);
        connection.close(0_u32.into(), b"work delivery complete");
        response
    }

    /// Polls through the wire's retryable `NotReady` until the detached
    /// invocation has made its signed terminal durable.
    async fn wait_for_result(&self, work_id: Digest) -> Vec<OutputEventEnvelope> {
        let delivered = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let response = self.deliver_result(work_id).await;
                match response.outcome {
                    Some(deliver_result_response::Outcome::Delivered(delivered)) => {
                        break delivered;
                    }
                    Some(deliver_result_response::Outcome::Refused(refusal))
                        if refusal.code == WorkRefusalCode::NotReady as i32 =>
                    {
                        tokio::task::yield_now().await;
                    }
                    outcome => panic!(
                        "the accepted job remains retryable until its result is ready, got {outcome:?}",
                    ),
                }
            }
        })
        .await;
        let delivered = match delivered {
            Ok(delivered) => delivered,
            Err(_) => panic!("the accepted job's result reaches the client"),
        };
        let expected = match terminal_result(
            descriptor().channel(),
            &authorization(),
            &answer_transcript(),
        ) {
            Ok(result) => result,
            Err(error) => panic!("the expected terminal result derives: {error}"),
        };
        assert_eq!(
            delivered.result,
            expected.encode(),
            "the client receives the result the retained invocation produced",
        );
        assert_eq!(
            delivered.provider_signature,
            provider()
                .sign(signing_hash(result_digest(
                    descriptor().channel(),
                    &expected,
                )))
                .as_bytes(),
            "the result reaches the client with this provider's signature",
        );
        let budget = usize::try_from(execution_policy().max_spool_bytes).unwrap_or(usize::MAX);
        match decode_transcript(&delivered.transcript, budget) {
            Ok(transcript) => transcript,
            Err(error) => panic!("the delivered transcript decodes: {error}"),
        }
    }

    async fn wait_for_mount(&self) {
        let mounted = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if self.work_mount.service(&self.context()).is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(mounted.is_ok(), "the production clock mounts the channel");
        assert!(
            self.setup_mount.service(&self.context()).is_none(),
            "the matching setup is cleared when its channel mounts",
        );
    }

    async fn wait_for_cursor(&self, height: u64) {
        let caught_up = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let cursor = self
                    .work_mount
                    .service(&self.context())
                    .and_then(|service| service.with_state(|state| state.cursor().0).ok());
                if cursor.is_some_and(|cursor| cursor >= height) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            caught_up.is_ok(),
            "the driven journal catches up to the contest snapshot",
        );
    }

    async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = self.runner_task.await;
        self.accept_task.abort();
        let _ = self.accept_task.await;
        self.client.close().await;
        self.endpoint.close().await;
    }
}

async fn run_advertised_paid_exchange(
    root: &Path,
    client_root: &Path,
    policy: ProviderChannelPolicy,
    contested: bool,
) {
    seed_provider_offer(root, PaymentAdmission::Admits(Box::new(policy.clone())));
    let source = NodeChain::new();
    let node = RunningPaidNode::start(root, policy.clone(), source.clone()).await;
    assert!(
        node.setup_mount.service(&node.context()).is_some(),
        "the runner mounts the exact setup it drives before the first dial",
    );

    let mut caller = client_setup(client_root, policy);
    let first = node.exchange_setup(ExchangeSetupRequest::default()).await;
    if let Err(error) = apply_setup_exchange(&mut caller, first) {
        panic!("WorkSetup round 1 imports the driven provider offer: {error}");
    }
    if let Err(error) = caller.arm_scan(SetupScan {
        height: FLOOR,
        payload: payload_at(FLOOR),
    }) {
        panic!("the client arms the same finalized floor: {error}");
    }
    if let Err(error) = caller.propose_payment(payment_funding(), payment_terms()) {
        panic!("the client journals its payment proposal: {error}");
    }
    let second = node.exchange_setup(prepare_setup_exchange(&caller)).await;
    if let Err(error) = apply_setup_exchange(&mut caller, second) {
        panic!("WorkSetup round 2 imports the provider countersignature: {error}");
    }
    assert_eq!(
        caller.state().revision(),
        Some(3),
        "both ALPN rounds complete the three-revision setup",
    );
    drop(caller);

    node.wait_for_mount().await;
    let setup_opens = source
        .submitted()
        .into_iter()
        .filter(|tx| matches!(tx, Tx::Open { .. }))
        .count();
    assert_eq!(
        setup_opens, 2,
        "the production clock submits and finalizes both setup Opens",
    );

    // The observer must publish readiness before the first request. Request
    // handling itself has no validator connection and cannot refresh it.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if node
                .work_mount
                .service(&node.context())
                .is_some_and(|service| service.readiness().is_ok())
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the channel observer publishes readiness");

    if contested {
        let contest_height = source.open_contest();
        node.wait_for_cursor(contest_height).await;
    }
    let response = node.accept_work(signed_accept_request()).await;
    if contested {
        let Some(accept_work_response::Outcome::Refused(refusal)) = response.outcome else {
            panic!(
                "fresh readiness must refuse a pending contest, got {:?}",
                response.outcome,
            );
        };
        assert_retryable_not_ready(refusal);
    } else if !matches!(
        response.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ) {
        panic!(
            "the valid proposal must reach the freshly admitted driven service, got {:?}",
            response.outcome,
        );
    } else {
        let id = work_id(descriptor().channel(), &authorization());
        assert_eq!(
            node.wait_for_result(id).await,
            answer_transcript(),
            "the real delivery seam returns the executed transcript",
        );
        assert_eq!(
            node.execution_calls.load(Ordering::SeqCst),
            1,
            "the node invokes its retained executor exactly once",
        );
    }
    node.shutdown().await;
}

/// An empty-root offer traverses the two ALPN setup rounds, the
/// production runner finalizes and mounts it, and a valid paid proposal
/// reaches that exact service. A second independent offer opens a
/// contest after mount and proves readiness is re-read per request.
#[tokio::test(flavor = "multi_thread")]
async fn paid_setup_and_accept_reach_the_mounted_services_over_the_advertised_alpns() {
    let fixture = temp();
    let policy = provider_policy();
    for (name, contested) in [("ready", false), ("contested", true)] {
        let root = fixture.path().join(format!("provider-{name}"));
        let client_root = fixture.path().join(format!("client-{name}"));
        if let Err(error) = std::fs::create_dir(&root) {
            panic!("the empty provider root is created: {error}");
        }
        if let Err(error) = std::fs::create_dir(&client_root) {
            panic!("the empty client root is created: {error}");
        }
        let mut entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) => panic!("the provider root is readable: {error}"),
        };
        assert!(
            entries.next().is_none(),
            "each provider fixture starts from an empty root",
        );
        run_advertised_paid_exchange(&root, &client_root, policy.clone(), contested).await;
    }
}

/// A restart with an open contest is answered by the clock, before
/// the deadline, without a single library call from this file.
///
/// Nothing in the runner names a contest, builds a response, or reads
/// a deadline: the journal on the disk holds the contest and the
/// certificate, and one tick is the whole of what this file adds.
#[tokio::test]
async fn a_restart_with_an_open_contest_is_answered_on_the_clock() {
    let dir = temp();
    write_setup_journal(dir.path());
    let start_id = write_contested_channel(dir.path());
    let mount = MountedWork::default();
    let mut runner = runner(dir.path(), provider_policy(), &mount);
    let chain = TestChain::new();

    assert!(
        mount
            .service(&vouched_context(default_route_peer()))
            .is_none(),
        "nothing is mounted before the first tick",
    );
    assert!(chain.submitted().is_empty(), "and nothing is submitted");

    assert!(runner.tick(&chain).await, "the fixture chain answers");

    assert_eq!(responded(&chain), start_id);
    let Some(service) = mount.service(&vouched_context(default_route_peer())) else {
        panic!("the tick that answered the contest mounted its channel")
    };
    let cursor = match service.with_state(|state| state.cursor().0) {
        Ok(cursor) => cursor,
        Err(error) => panic!("the mounted channel is readable: {error}"),
    };
    assert!(
        cursor < RESPONSE_DEADLINE,
        "the answer was submitted at {cursor}, past the deadline {RESPONSE_DEADLINE}",
    );
    let responded = match service.with_state(|state| state.close_responded()) {
        Ok(responded) => responded,
        Err(error) => panic!("the mounted channel is readable: {error}"),
    };
    assert_eq!(
        responded.map(|contest| contest.start_id),
        Some(start_id),
        "the answer is on the disk before it reaches a sink",
    );
}

#[tokio::test]
async fn the_paid_work_clock_submits_adjudication_when_consensus_makes_it_due_and_not_before() {
    let dir = temp();
    write_setup_journal(dir.path());
    let start_id = write_contested_channel(dir.path());
    let mount = MountedWork::default();
    let mut runner = runner(dir.path(), provider_policy(), &mount);
    let chain = TestChain::new();
    chain.set_snapshot(channel_snapshot(ORIGIN, None, Some(pending_contest(false))));

    assert!(runner.tick(&chain).await, "the first coherent read answers");
    assert_eq!(
        adjudicated_payment_closes(&chain),
        0,
        "an unresponded contest below its deadline is not final",
    );
    let Some(service) = mount.service(&vouched_context(default_route_peer())) else {
        panic!("the first tick mounts the contested channel")
    };
    assert_eq!(
        service
            .with_state(|state| state.close_responded().map(|held| held.start_id))
            .unwrap_or_else(|error| panic!("the mounted channel is readable: {error}")),
        Some(start_id),
        "the response is chosen and fsynced locally",
    );

    assert!(
        runner.tick(&chain).await,
        "the second coherent read answers"
    );
    assert_eq!(
        adjudicated_payment_closes(&chain),
        0,
        "a local CloseResponded is not consensus response evidence",
    );

    chain.set_snapshot(channel_snapshot(ORIGIN, None, Some(pending_contest(true))));
    assert!(runner.tick(&chain).await, "the responded read answers");
    assert_eq!(
        adjudicated_payment_closes(&chain),
        1,
        "consensus response makes exactly one adjudicated payment close due",
    );
}

#[tokio::test]
async fn the_paid_work_clock_returns_the_completed_bond_at_its_horizon() {
    let dir = temp();
    write_setup_journal(dir.path());
    let mount = MountedWork::default();
    let mut runner = runner(dir.path(), provider_policy(), &mount);
    let chain = TestChain::new();
    chain.set_snapshot(channel_snapshot(
        bond_terms().timeout.get(),
        Some(live_bond()),
        None,
    ));

    assert!(runner.tick(&chain).await, "the horizon read answers");
    let submitted = chain.submitted();
    let timeouts = submitted
        .iter()
        .filter(|tx| {
            matches!(
                tx,
                Tx::Close {
                    input,
                    proof: Proof::Timeout { .. },
                    ..
                } if *input == bond_edge()
            )
        })
        .count();
    assert_eq!(
        timeouts, 1,
        "the live completed bond is returned by one deterministic timeout",
    );
    assert_eq!(submitted.len(), 1, "no other transaction is submitted");
}

/// The runner mounts what it is handed, and `Work` answers from it.
///
/// The discriminator is deliberately not the refusal code of
/// `accept_work`, which a close-only mount also refuses as
/// `NotReady`: it is `admit_certificate`, which the mounted service
/// answers from its own channel's state and the unmounted one cannot
/// answer at all.
#[tokio::test]
async fn the_clock_serves_work_from_the_channel_it_was_handed() {
    let dir = temp();
    write_setup_journal(dir.path());
    let mount = MountedWork::default();
    let mut runner = runner(dir.path(), provider_policy(), &mount);
    let chain = TestChain::new();

    let unmounted: WithTrailer<AdmitCertificateResponse> = UnmountedWork
        .admit_certificate(
            AdmitCertificateRequest::default(),
            TransportContext::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("the unmounted handler answers: {error}"))
        .into();
    let Some(admit_certificate_response::Outcome::Refused(before)) = unmounted.response.outcome
    else {
        panic!("an unmounted Work refuses payment")
    };
    assert_eq!(before.code, WorkRefusalCode::NotReady as i32);

    assert!(runner.tick(&chain).await, "the fixture chain answers");

    let Some(service) = mount.service(&vouched_context(default_route_peer())) else {
        panic!("the driver handed back a channel and the runner published it")
    };
    let edge = match service.with_state(|state| state.channel().payment_edge()) {
        Ok(edge) => edge,
        Err(error) => panic!("the mounted channel is readable: {error}"),
    };
    assert_eq!(
        edge,
        payment_edge(),
        "the mount is the channel the setup journal names",
    );
    let mounted: WithTrailer<AdmitCertificateResponse> = service
        .admit_certificate(
            AdmitCertificateRequest::default(),
            TransportContext::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("the mounted handler answers: {error}"))
        .into();
    let Some(admit_certificate_response::Outcome::Refused(after)) = mounted.response.outcome else {
        panic!("a mounted Work refuses a payment naming no job of its own")
    };
    assert_ne!(
        after.code,
        WorkRefusalCode::NotReady as i32,
        "a mounted channel answers from its own state, not from `NotReady`: {}",
        after.reason,
    );

    // And the setup is not driven again, so no second journal is
    // opened on the file the first mount holds.
    assert_eq!(runner.channel_count(), 1);
    assert!(
        runner.tick(&chain).await,
        "a second tick drives the channel"
    );
    assert!(chain.submitted().is_empty(), "and it has nothing to submit");
}

/// Discovery must resume the obligation already recorded by an Accepted
/// journal; no client retries a request and no transient Courtesy state is
/// present after this simulated process restart.
#[test]
fn the_clock_resumes_an_accepted_job_after_restart() {
    let dir = temp();
    write_setup_journal(dir.path());
    let work_id = write_accepted_channel(dir.path());
    let calls = Arc::new(AtomicUsize::new(0));
    let chain = TestChain::new();
    chain.set_snapshot(ready_channel_snapshot(ORIGIN, None));
    let runtime = || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the process runtime starts")
    };
    let first_process = runtime();
    first_process.block_on(async {
        let mount = MountedWork::with_backend(AnsweringPaidBackend {
            calls: Arc::clone(&calls),
        });
        let mut runner = runner(dir.path(), provider_policy(), &mount);

        assert!(runner.tick(&chain).await, "the recovery read answers");

        let finished = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let phase = mount
                    .service(&vouched_context(default_route_peer()))
                    .and_then(|service| {
                        service
                            .with_state(|state| {
                                state
                                    .jobs()
                                    .next()
                                    .filter(|job| job.work_id() == work_id)
                                    .map(|job| job.phase())
                            })
                            .ok()
                            .flatten()
                    });
                if calls.load(Ordering::SeqCst) == 1 && phase == Some(JobPhase::Ready) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            finished.is_ok(),
            "the recovered accepted job reaches one durable result"
        );

        assert!(runner.tick(&chain).await, "the next recovery read answers");
        tokio::task::yield_now().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a ready journal is never invoked again"
        );

        // Deterministically retain a channel handle in an unfinished task, as the
        // detached execution task may still do just after publishing Ready.
        let retained = mount
            .service(&vouched_context(default_route_peer()))
            .unwrap();
        tokio::spawn(async move {
            std::future::pending::<()>().await;
            drop(retained);
        });
        drop(runner);
        drop(mount);
    });
    // Ready is durable before the detached execution future necessarily drops
    // its channel handle. End the old process's tasks and file locks before
    // discovering journals again, as a real process restart would.
    drop(first_process);

    // A second restart finds a result, not an Accepted job to resume. It must
    // deliver that result without a new AcceptWork priming its readiness.
    let restarted_process = runtime();
    restarted_process.block_on(async {
        let mount = MountedWork::default();
        let mut restarted = self::runner(dir.path(), provider_policy(), &mount);
        assert!(restarted.tick(&chain).await);
        let exporter = [0x5b; 32];
        let mut context = vouched_context(default_route_peer());
        context.open_exporter = Some(exporter);
        let request = DeliverResultRequest {
            work_id: work_id.as_bytes().to_vec(),
            client_signature: client()
                .sign(signing_hash(delivery_request_digest(
                    descriptor().channel(),
                    work_id,
                    &exporter,
                )))
                .as_bytes()
                .to_vec(),
        };
        let handler = mount
            .handler(&context)
            .expect("restarted channel is mounted");
        let response: WithTrailer<DeliverResultResponse> = tokio::time::timeout(
            Duration::from_secs(5),
            handler.deliver_result(request.clone(), context.clone()),
        )
        .await
        .expect("retained result is immediately collectable")
        .expect("delivery succeeds")
        .into();
        assert!(matches!(
            response.response.outcome,
            Some(deliver_result_response::Outcome::Delivered(_))
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "delivery never reruns the model"
        );

        chain.set_snapshot(ready_channel_snapshot(ORIGIN, Some(pending_contest(false))));
        assert!(restarted.tick(&chain).await);
        let response: WithTrailer<DeliverResultResponse> = handler
            .deliver_result(request, context)
            .await
            .expect("refusal is answered")
            .into();
        let Some(deliver_result_response::Outcome::Refused(refusal)) = response.response.outcome
        else {
            panic!("cached readiness must not release data after a finalized contest");
        };
        assert_retryable_not_ready(refusal);
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn open_result_stream_stops_when_a_contest_finalizes() {
    let dir = temp();
    write_setup_journal(dir.path());
    let work_id = write_accepted_channel(dir.path());
    let backend = BlockingPaidBackend::new();
    let mount = MountedWork::with_backend(backend.clone());
    let mut runner = runner(dir.path(), provider_policy(), &mount);
    let chain = TestChain::new();
    chain.set_snapshot(ready_channel_snapshot(ORIGIN, None));
    assert!(runner.tick(&chain).await);
    backend.wait_for_call().await;

    let exporter = [0x5b; 32];
    let mut context = vouched_context(default_route_peer());
    context.open_exporter = Some(exporter);
    let request = DeliverResultRequest {
        work_id: work_id.as_bytes().to_vec(),
        client_signature: client()
            .sign(signing_hash(delivery_request_digest(
                descriptor().channel(),
                work_id,
                &exporter,
            )))
            .as_bytes()
            .to_vec(),
    };
    let handler = mount.handler(&context).unwrap();
    let mut stream = handler.stream_result(request, context).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        first.outcome,
        Some(hellas_rpc::pb::work::work_stream_event::Outcome::Prefix(_))
    ));

    chain.set_snapshot(ready_channel_snapshot(ORIGIN, Some(pending_contest(false))));
    assert!(runner.tick(&chain).await);
    backend.finish();
    let next = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .expect("the open stream terminates with a refusal");
    assert!(
        match next {
            Err(status) => status.code == hellas_wire::WireCode::Unavailable,
            Ok(event) => matches!(event.outcome,
            Some(hellas_rpc::pb::work::work_stream_event::Outcome::Refused(refusal))
                if refusal.code == WorkRefusalCode::NotReady as i32 || refusal.code == WorkRefusalCode::Unavailable as i32),
        },
        "no payload is released after the observer revokes readiness"
    );
    assert!(stream.next().await.is_none());
}

/// A request is answered while the clock waits on a slow chain.
///
/// The mutation this fails against is the one §5 names: a driver
/// that held the endpoint across the source's wait. It would not
/// compile in a spawned task if it held a `MutexGuard`, and it
/// would deadlock here if it held anything else.
#[tokio::test(flavor = "multi_thread")]
async fn the_clock_does_not_starve_the_request_path() {
    let dir = temp();
    write_setup_journal(dir.path());
    let backend = BlockingPaidBackend::new();
    let mount = MountedWork::with_backend(backend.clone());
    let mut runner = runner(dir.path(), provider_policy(), &mount);
    let initial = TestChain::new();
    initial.set_snapshot(ready_channel_snapshot(ORIGIN, None));
    assert!(runner.tick(&initial).await);
    let chain = TestChain::slow();
    chain.set_snapshot(ready_channel_snapshot(ORIGIN, None));

    let ticking = {
        let chain = chain.clone();
        tokio::spawn(async move { runner.tick(&chain).await })
    };
    chain.wait_for_read().await;

    // The dispatch path's own two steps, both taken while the clock
    // is inside the chain read: resolve the handler for this ALPN,
    // and answer with it.
    let Some(dispatch) = mount.handler(&vouched_context(default_route_peer())) else {
        panic!("the channel is mounted before the chain is read")
    };
    let answered = tokio::time::timeout(Duration::from_secs(5), async move {
        let response = dispatch
            .accept_work(signed_accept_request(), TransportContext::default())
            .await?;
        Ok::<WithTrailer<AcceptWorkResponse>, WireStatus>(response.into())
    })
    .await;
    match answered {
        Ok(Ok(response)) => {
            assert!(
                matches!(
                    response.response.outcome,
                    Some(accept_work_response::Outcome::Accepted(_))
                ),
                "the request is accepted while the close clock is waiting",
            );
        }
        Ok(Err(error)) => panic!("the request path is reachable: {error}"),
        Err(_) => panic!("an inbound request waited on the clock's chain read"),
    }
    let entered = tokio::time::timeout(Duration::from_secs(5), backend.wait_for_call()).await;
    assert!(
        entered.is_ok(),
        "the accepted job reaches its executor without joining the close clock",
    );

    backend.finish();
    chain.release();
    if let Err(error) = ticking.await {
        panic!("the tick finishes once the chain answers: {error}");
    }
}

/// Told to stop, the clock stops between two steps and leaves both
/// journals openable and replayable.
#[tokio::test]
async fn a_clean_shutdown_leaves_a_replayable_journal() {
    let dir = temp();
    write_setup_journal(dir.path());
    let start_id = write_contested_channel(dir.path());
    let mount = MountedWork::default();
    let runner = runner(dir.path(), provider_policy(), &mount);
    let chain = TestChain::new();
    let (stop, stopped) = oneshot::channel();
    let task = {
        let chain = chain.clone();
        tokio::spawn(async move {
            runner
                .run_over(stopped, move || {
                    let chain = chain.clone();
                    async move { Some(chain) }
                })
                .await;
        })
    };

    // The loop is running and has answered the contest at least
    // once, so both journals are open and held.
    for _ in 0..2_000_u32 {
        if !chain.submitted().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(responded(&chain), start_id, "the loop answered the contest");

    if stop.send(()).is_err() {
        panic!("the runner is still listening for its stop signal");
    }
    if let Err(error) = task.await {
        panic!("the runner stops when it is told to: {error}");
    }

    // A channel nobody advances is a channel this node no longer
    // answers from, and the files go with it.
    assert!(
        mount
            .service(&vouched_context(default_route_peer()))
            .is_none(),
        "a stopped clock serves no channel",
    );

    // Both files are released, and both replay to what the clock
    // left in them.
    let setup = match SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the setup journal reopens after a clean stop: {error}"),
    };
    assert_eq!(setup.state().end(), Some(SetupEnd::Complete));
    assert!(!setup.recovered_torn_tail(), "the setup journal is whole");

    let channel = open_channel(dir.path());
    assert!(
        !channel.recovered_torn_tail(),
        "the channel journal is whole"
    );
    assert_eq!(
        channel.state().close_responded().map(|held| held.start_id),
        Some(start_id),
        "the answer the clock fixed replays",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_channel_observer_does_not_stop_other_channels_or_shutdown() {
    let dir = temp();
    let first = OfferFixture::first();
    let second = OfferFixture::second();
    first.write_completed_setup(dir.path());
    second.write_completed_setup(dir.path());
    let source = RoutedChain::new(
        [first.bond_edge(), second.bond_edge()],
        [
            first.ready_snapshot(ORIGIN, None),
            second.ready_snapshot(ORIGIN, None),
        ],
    );
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    source.0.lock().unwrap().next_read = Some((entered.clone(), release));
    let mount = MountedWork::default();
    let setups = MountedSetup::default();
    let runner = discover_two_route_runner(dir.path(), &mount, &setups);
    let (stop, stopped) = oneshot::channel();
    let observing = tokio::spawn(async move {
        runner
            .run_over(stopped, move || {
                let source = source.clone();
                async move { Some(source) }
            })
            .await;
    });
    tokio::time::timeout(Duration::from_secs(2), entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if mount
                .service(&vouched_context(second_route_peer()))
                .is_some_and(|service| service.readiness().is_ok())
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the second channel advances while the first source is blocked");
    let response =
        accept_mounted_route(&mount, second_route_peer(), second.signed_accept_request()).await;
    assert!(matches!(
        response.outcome,
        Some(accept_work_response::Outcome::Accepted(_))
    ));
    let held = mount
        .service(&vouched_context(second_route_peer()))
        .unwrap();
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), observing)
        .await
        .expect("shutdown cancels the blocked read")
        .unwrap();
    assert!(
        held.readiness().is_err(),
        "already-held handlers cannot admit after shutdown"
    );
    assert!(
        mount
            .service(&vouched_context(second_route_peer()))
            .is_none()
    );
}
