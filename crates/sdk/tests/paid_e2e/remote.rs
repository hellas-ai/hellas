//! Untrusted WebSocket transport around the harness's real finalized state.
use super::*;
use hellas_chain::domain::{Coin, ObjectId, Transaction};
use hellas_chain::{
    CoinListing, ConsensusInfo, EdgeLookup, FinalizedBlock, FinalizedBlockQuery, LatestBlock,
    OwnerEdges, QueryError,
};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

#[derive(Clone)]
pub(super) struct Source {
    pub local: hellas_chain::rpc::LocalLightClient,
    pub unavailable: Arc<AtomicBool>,
    pub tips_unavailable: Arc<AtomicBool>,
    tip_refusals: Arc<tokio::sync::Semaphore>,
    pub listing_padding: Arc<AtomicBool>,
    pub attempts: Arc<AtomicUsize>,
    pub replay: Arc<AtomicU64>,
    pub corrupt: Arc<AtomicUsize>,
    pub forged: Arc<AtomicBool>,
    pub stale: Arc<std::sync::Mutex<Option<hellas_rpc::pb::chain::GetOperationsResponse>>>,
    pub connections: Arc<AtomicUsize>,
    /// Latency injected into source selection only.
    pub delay: std::time::Duration,
    observation_gate: Arc<std::sync::Mutex<Option<ObservationGate>>>,
}

// The retained, single-source opener reads applied Latest for selection,
// setup, mounted floor, readiness, catch-up, then initial observation.
#[derive(Clone)]
struct ObservationGate {
    reads: Arc<AtomicUsize>,
    first_blocked: Arc<AtomicUsize>,
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
    delay: Duration,
}

macro_rules! forward {
    ($name:ident($($arg:ident: $ty:ty),*) -> $out:ty) => {
        async fn $name(&self, $($arg: $ty),*) -> Result<$out, QueryError> { self.local.$name($($arg),*).await }
    };
}
impl hellas_chain::LightClient for Source {
    forward!(get_state_root() -> Option<hellas_chain::domain::Digest>);
    forward!(get_proof(object_id: ObjectId) -> Option<Vec<u8>>);
    forward!(get_coin(payload: hellas_chain::domain::Digest, object_id: ObjectId) -> Option<Coin>);
    forward!(
        get_edge(payload: hellas_chain::domain::Digest, object_id: ObjectId) -> Option<EdgeLookup>
    );
    forward!(get_finalization(payload: hellas_chain::domain::Digest) -> Option<Vec<u8>>);
    forward!(submit_tx(tx: Transaction) -> hellas_chain::SubmitTxOutcome);
    forward!(get_validators() -> Vec<String>);
    async fn get_consensus_info(&self) -> Result<ConsensusInfo, QueryError> {
        tokio::time::sleep(self.delay).await;
        self.local.get_consensus_info().await
    }
    async fn get_coins_by_owner(
        &self,
        owner: SettlementKey,
    ) -> Result<Option<CoinListing>, QueryError> {
        let mut listing = self.local.get_coins_by_owner(owner).await?;
        if self.listing_padding.load(Ordering::SeqCst)
            && let Some(listing) = &mut listing
        {
            listing
                .coins
                .extend((1..=32).map(|n| (ObjectId::from([n; 32]), u64::MAX)));
        }
        Ok(listing)
    }
    forward!(get_coins_by_delegate(delegate: SettlementKey) -> Option<CoinListing>);
    forward!(get_edges_by_owner(owner: SettlementKey) -> Option<OwnerEdges>);
    async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        Ok(self
            .get_finalized_block(FinalizedBlockQuery::Latest)
            .await?
            .map(|block| block.snapshot))
    }
    async fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        if self.tips_unavailable.load(Ordering::SeqCst) {
            self.tip_refusals.add_permits(1);
            return Err(QueryError::Remote("injected RPC Unavailable".into()));
        }
        let height = self.replay.load(Ordering::SeqCst);
        let query = if height > 0 && query == FinalizedBlockQuery::Latest {
            FinalizedBlockQuery::Height(height)
        } else {
            query
        };
        let mut block = self.local.get_finalized_block(query).await?;
        if self.forged.load(Ordering::SeqCst)
            && let Some(block) = &mut block
        {
            block.snapshot.finalization[0] ^= 1;
        }
        Ok(block)
    }
    async fn get_applied_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        let gate = self.observation_gate.lock().unwrap().clone();
        if query == FinalizedBlockQuery::Latest
            && let Some(gate) = gate
        {
            let read = gate.reads.fetch_add(1, Ordering::SeqCst) + 1;
            if read == 5 {
                tokio::time::sleep(gate.delay).await;
            }
            if read >= 6 {
                let _ = gate.first_blocked.compare_exchange(
                    0,
                    read,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                gate.entered.add_permits(1);
                let _ = gate.release.acquire().await;
            }
        }
        if self.tips_unavailable.load(Ordering::SeqCst) {
            self.tip_refusals.add_permits(1);
            return Err(QueryError::Remote("injected RPC Unavailable".into()));
        }
        let height = self.replay.load(Ordering::SeqCst);
        let query = if height > 0 && query == FinalizedBlockQuery::Latest {
            FinalizedBlockQuery::Height(height)
        } else {
            query
        };
        let mut block = self.local.get_applied_finalized_block(query).await?;
        if self.forged.load(Ordering::SeqCst)
            && let Some(block) = &mut block
        {
            block.snapshot.finalization[0] ^= 1;
        }
        Ok(block)
    }
    async fn get_operations(
        &self,
        request: hellas_rpc::pb::chain::GetOperationsRequest,
    ) -> Result<hellas_rpc::pb::chain::GetOperationsResponse, QueryError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(QueryError::StateUnavailable(
                "injected transient proof read".into(),
            ));
        }
        if let Some(stale) = self.stale.lock().unwrap().clone() {
            return Ok(stale);
        }
        let mut response = self.local.get_operations(request).await?;
        match self.corrupt.load(Ordering::SeqCst) {
            1 => {
                // Change a key in a canonical Any-QMDB Update, preserving the
                // operation tag, value and terminal commit-floor encoding.
                if let Some(update) = response
                    .operations
                    .iter_mut()
                    .find(|operation| operation[0] == 0xd2)
                {
                    update[20] ^= 1;
                }
            }
            2 => {
                response.operations.pop();
            }
            3 => response.operations.reverse(),
            _ => {}
        }
        Ok(response)
    }
}

pub(super) struct Relays {
    pub source: Source,
    pub urls: Vec<String>,
    disconnect: tokio::sync::watch::Sender<u64>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Relays {
    pub async fn start(devnet: &Devnet) -> Self {
        Self::start_at(devnet, 0, std::time::Duration::ZERO).await
    }

    /// A relay group that answers `Latest` at `replay` and takes `delay`
    /// before reporting its consensus identity, so a test can put a fast
    /// stale group beside a slower current one.
    pub async fn start_at(devnet: &Devnet, replay: u64, delay: std::time::Duration) -> Self {
        let source = Source {
            local: devnet.validator_light_client(0),
            unavailable: Arc::new(AtomicBool::new(false)),
            tips_unavailable: Arc::new(AtomicBool::new(false)),
            tip_refusals: Arc::new(tokio::sync::Semaphore::new(0)),
            listing_padding: Arc::new(AtomicBool::new(false)),
            attempts: Arc::new(AtomicUsize::new(0)),
            replay: Arc::new(AtomicU64::new(replay)),
            corrupt: Arc::new(AtomicUsize::new(0)),
            forged: Arc::new(AtomicBool::new(false)),
            stale: Arc::new(std::sync::Mutex::new(None)),
            connections: Arc::new(AtomicUsize::new(0)),
            delay,
            observation_gate: Default::default(),
        };
        let (disconnect, _) = tokio::sync::watch::channel(0);
        let mut urls = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            urls.push(format!("ws://{}", listener.local_addr().unwrap()));
            let (activity, _) = tokio::sync::broadcast::channel(16);
            let service = hellas_chain::LightClientRpc::new(source.clone(), activity);
            let source = source.clone();
            let disconnect = disconnect.clone();
            let mut stop = disconnect.subscribe();
            tasks.push(tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        _ = stop.changed() => {
                            if *stop.borrow() == u64::MAX { connections.shutdown().await; break; }
                        }
                        accepted = listener.accept() => {
                            let (stream, _) = accepted.unwrap();
                            source.connections.fetch_add(1, Ordering::SeqCst);
                            let service = service.clone();
                            let mut disconnect = disconnect.subscribe();
                            connections.spawn(async move {
                                let serve = async {
                                    let ws = tokio_tungstenite::accept_async_with_config(stream, Some(hellas_wire::ws::websocket_config())).await.unwrap();
                                    let transport = hellas_wire::ws::accept_upgraded(ws, None).unwrap();
                                    let _ = hellas_chain::serve_light_client_transport(transport, service).await;
                                };
                                tokio::select! { () = serve => {}, _ = disconnect.changed() => {} }
                            });
                        }
                        _ = connections.join_next(), if !connections.is_empty() => {},
                    }
                }
            }));
        }
        Self {
            source,
            urls,
            disconnect,
            tasks,
        }
    }
    pub async fn shutdown(&mut self) {
        self.disconnect.send_replace(u64::MAX);
        for task in self.tasks.drain(..) {
            task.await.unwrap();
        }
    }
    pub fn disconnect(&self) {
        self.disconnect.send_modify(|generation| *generation += 1);
    }
}
impl Drop for Relays {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Source selection must agree with the caller's own height guard.
///
/// A peer that authenticates promptly but is behind the retained journal is
/// refused, because the caller's guard would reject its state anyway and a
/// reconnect policy that keeps choosing it never recovers while healthy peers
/// sit configured beside it. The same peers are selected once they can serve
/// the floor.
pub(super) async fn stale_source_selection(runtime: commonware_runtime::tokio::Context) {
    let root = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::start(
        runtime,
        DevnetConfig {
            name: "sdk_source_floor",
            owners: vec![CLIENT_OWNER],
            full_nodes: 0,
        },
    )
    .await;
    devnet.seal().await;
    devnet.seal().await;
    let mut relays = Relays::start(&devnet).await;
    let mut config = work_config(&devnet, root.path().join("journal"));
    config.validators = relays.urls.clone();
    let tip = devnet.height();
    assert!(tip > 1, "the fixture finalizes more than one block");
    let behind = tip - 1;
    // Every responsive relay now answers Latest with an older finalized block.
    relays.source.replay.store(behind, Ordering::SeqCst);
    assert!(
        matches!(
            hellas_sdk::client_chain::connect_at(&config, Duration::from_millis(300), tip).await,
            Err(QueryError::ReadUnavailableTimeout { .. })
        ),
        "a responsive source below the journal height is not selected"
    );
    let selected = hellas_sdk::client_chain::connect_at(&config, Duration::from_secs(5), behind)
        .await
        .expect("a source that serves the journal height is selected");
    assert_eq!(
        selected.get_latest_block().await.unwrap().unwrap().height,
        behind
    );
    relays.source.replay.store(0, Ordering::SeqCst);
    let current = hellas_sdk::client_chain::connect_at(&config, Duration::from_secs(5), tip)
        .await
        .expect("the same sources serve the current tip");
    assert_eq!(
        current.get_latest_block().await.unwrap().unwrap().height,
        tip
    );
    relays.shutdown().await;
    devnet.shutdown().await;
}

/// Paid startup establishes the retained journal's height floor before it
/// selects a source. A fast validator below that floor is skipped in favour
/// of a slower configured validator that is current, because recovery's own
/// reads would refuse the stale one anyway.
///
/// The setup journal is not the only retained floor: a completed setup
/// stops advancing while the channel journal it mounted keeps observing.
/// A source that satisfies the setup floor can therefore be behind the
/// channel cursor by the time the channel is mounted, and startup must
/// reselect at that cursor rather than keep the fast stale source.
pub(super) async fn paid_startup_uses_the_retained_floor(
    runtime: commonware_runtime::tokio::Context,
) {
    let mut case = paid_fixture(runtime).await;
    // Retain a complete channel journal through the real opening path.
    let mut session = sealing_while(
        &mut case.devnet,
        Duration::from_millis(100),
        PaidWorkSession::open(
            case.options.clone(),
            case.endpoint.clone(),
            client_settlement(),
            case.owner.clone(),
            SessionOpenMode::Any,
            SessionFundingOptions::default(),
        ),
    )
    .await
    .unwrap();
    let bond = session.descriptor().bond_edge();
    // The setup journal stops at the height that completed the handshake;
    // the channel journal continues to observe. Seal well past that setup
    // floor so the two retained cursors separate before the restart.
    let setup_height = case.devnet.height();
    assert!(
        setup_height < 50,
        "the setup floor stays below the stale relay's replay height",
    );
    case.devnet.seal_through(100).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let cursor = session
            .with_state(|state| state.cursor().0)
            .await
            .expect("the session journal is readable");
        if cursor >= 80 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the retained channel journal observes the sealed blocks",
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    session.shutdown().await;
    drop(session);

    // The fast relays are above the setup floor but below the channel
    // cursor; the current relays take longer to report their identity, so
    // selection must reject the fast ones on height, first at the setup
    // floor and then again at the mounted channel's cursor.
    let mut stale = Relays::start_at(&case.devnet, 50, Duration::ZERO).await;
    let mut current = Relays::start_at(&case.devnet, 0, Duration::from_millis(200)).await;
    let mut options = case.options.clone();
    // The configured committee is six validators: three fast stale ones
    // beside three slower current ones.
    options.config.validators = stale
        .urls
        .iter()
        .take(3)
        .chain(current.urls.iter().take(3))
        .cloned()
        .collect();
    options.timeout = Some(Duration::from_secs(30));
    let mut session = sealing_while(
        &mut case.devnet,
        Duration::from_millis(100),
        PaidWorkSession::open(
            options,
            case.endpoint.clone(),
            client_settlement(),
            case.owner.clone(),
            SessionOpenMode::Retained,
            SessionFundingOptions::default(),
        ),
    )
    .await
    .expect("startup selects a source that serves the retained journal");
    assert_eq!(session.descriptor().bond_edge(), bond);
    session.shutdown().await;
    drop(session);

    stale.shutdown().await;
    current.shutdown().await;
    case.endpoint.close().await;
    case.relays.shutdown().await;
    case.devnet.shutdown().await;
}

pub(super) async fn proofs(runtime: commonware_runtime::tokio::Context) {
    use commonware_codec::DecodeExt as _;
    use hellas_chain::{FinalizedBlockView, domain::coin_object_id};
    let root = tempfile::tempdir().unwrap();
    let foreign_runtime = commonware_runtime::Supervisor::child(&runtime, "foreign");
    let mut devnet = Devnet::start(
        runtime,
        DevnetConfig {
            name: "requester_proofs",
            owners: vec![CLIENT_OWNER],
            full_nodes: 0,
        },
    )
    .await;
    devnet.seal().await;
    let mut relays = Relays::start(&devnet).await;
    let mut config = work_config(&devnet, root.path().join("journal"));
    config.validators = relays.urls.clone();
    let client = hellas_sdk::client_chain::connect(&config, Duration::from_secs(5))
        .await
        .unwrap();
    let genesis =
        hellas_chain::test_support::devnet::genesis_coin(devnet.allocations(), CLIENT_OWNER.key());
    let missing = CoinId::from_bytes([0x65; 32]);
    let keys = vec![coin_object_id(genesis), coin_object_id(missing)];
    let first = client.get_objects(keys.clone()).await.unwrap().unwrap();
    assert!(first.objects.contains_key(&coin_object_id(genesis)));
    assert!(!first.objects.contains_key(&coin_object_id(missing)));
    let old = relays
        .source
        .local
        .get_finalized_block(FinalizedBlockQuery::Latest)
        .await
        .unwrap()
        .unwrap();
    let old_block = hellas_chain::HellasBlock::decode(old.block.as_slice()).unwrap();
    let old_target = old_block.sync_target();
    let stale = relays
        .source
        .local
        .get_operations(hellas_rpc::pb::chain::GetOperationsRequest {
            op_count: *old_target.range.end(),
            start: *old_target.range.start(),
            max_ops: (*old_target.range.end() - *old_target.range.start()).min(64),
            include_pinned_nodes: false,
        })
        .await
        .unwrap();
    relays.source.listing_padding.store(true, Ordering::SeqCst);
    let plan = hellas_sdk::coin_owner::OwnerReshape::split(
        &client,
        devnet.network(),
        CLIENT_OWNER.key().into_kernel(),
        201,
        client_settlement().party_key(),
    )
    .await
    .unwrap();
    relays.source.listing_padding.store(false, Ordering::SeqCst);
    assert_eq!(
        plan.inputs().as_slice(),
        &[genesis],
        "scan beyond 32 ineligible, untrusted listing hints"
    );
    assert_eq!(
        plan.outputs().as_slice()[1].value(),
        CLIENT_OWNER.balance - 201
    );
    let outputs = plan.output_ids();
    client
        .submit_tx(Transaction::Kernel(
            plan.clone()
                .authorize(CLIENT_OWNER.authorize(plan.payload_hash()))
                .unwrap(),
        ))
        .await
        .unwrap();
    devnet.seal().await;
    devnet.seal().await;
    let keys = vec![
        coin_object_id(genesis),
        coin_object_id(outputs.as_slice()[0]),
        coin_object_id(missing),
    ];
    let current = client.get_objects(keys.clone()).await.unwrap().unwrap();
    assert!(
        !current.objects.contains_key(&coin_object_id(genesis)),
        "deleted input cannot be proved live by its old update"
    );
    assert!(
        current
            .objects
            .contains_key(&coin_object_id(outputs.as_slice()[0]))
    );
    assert!(!current.objects.contains_key(&coin_object_id(missing)));
    let latest = relays
        .source
        .local
        .get_finalized_block(FinalizedBlockQuery::Latest)
        .await
        .unwrap()
        .unwrap();
    let block = hellas_chain::HellasBlock::decode(latest.block.as_slice()).unwrap();
    assert!(
        *block.sync_target().range.start() > 0,
        "exercise a real nonzero inactivity floor"
    );
    for mode in 1..=3 {
        relays.source.corrupt.store(0, Ordering::SeqCst);
        // Each corruption must be read from the transport rather than a
        // previously verified in-memory object view.
        let fresh = hellas_sdk::client_chain::connect(&config, Duration::from_secs(5))
            .await
            .unwrap();
        relays.source.corrupt.store(mode, Ordering::SeqCst);
        let error = fresh.get_objects(keys.clone()).await.unwrap_err();
        assert!(
            matches!(error, QueryError::Remote(_)),
            "corrupt, missing or reordered operation witness {mode}: {error}"
        );
        if mode == 1 {
            assert!(
                error.to_string().contains("range proof"),
                "canonical update tampering must fail cryptographic verification: {error}"
            );
        }
    }
    relays.source.corrupt.store(0, Ordering::SeqCst);
    let fresh = hellas_sdk::client_chain::connect(&config, Duration::from_secs(5))
        .await
        .unwrap();
    *relays.source.stale.lock().unwrap() = Some(stale);
    assert!(
        matches!(
            fresh.get_objects(keys.clone()).await,
            Err(QueryError::Remote(_))
        ),
        "a genuine old range proof cannot establish current state"
    );
    *relays.source.stale.lock().unwrap() = None;
    relays.source.forged.store(true, Ordering::SeqCst);
    assert!(
        matches!(
            client.get_objects(keys.clone()).await,
            Err(QueryError::Remote(_))
        ),
        "a transport cannot forge finalization"
    );
    relays.source.forged.store(false, Ordering::SeqCst);
    assert!(client.get_objects(keys.clone()).await.unwrap().is_some());
    let unpinned = RemoteLightClient::connect(&relays.urls[0]).await.unwrap();
    assert!(matches!(
        unpinned.get_objects(keys.clone()).await,
        Err(QueryError::Remote(_))
    ));
    assert!(matches!(
        client.get_objects(vec![coin_object_id(missing); 33]).await,
        Err(QueryError::Remote(_))
    ));
    let mut foreign = Devnet::start(
        foreign_runtime,
        DevnetConfig {
            name: "foreign_committee",
            owners: vec![CLIENT_OWNER],
            full_nodes: 0,
        },
    )
    .await;
    foreign.seal().await;
    assert_ne!(
        foreign.consensus_info().threshold_identity,
        devnet.consensus_info().threshold_identity
    );
    let foreign_block = foreign
        .validator_light_client(0)
        .get_finalized_block(FinalizedBlockQuery::Latest)
        .await
        .unwrap()
        .unwrap();
    assert!(
        foreign
            .consensus_verifier()
            .verify_snapshot(&foreign_block.snapshot, &foreign_block.block)
            .is_ok()
    );
    assert!(
        devnet
            .consensus_verifier()
            .verify_snapshot(&foreign_block.snapshot, &foreign_block.block)
            .is_err(),
        "a genuinely signed non-genesis committee block is refused"
    );
    foreign.shutdown().await;
    assert!(FinalizedBlockView::decode(&latest).is_ok());
    use hellas_channel::work_open::SetupView as _;
    let query = hellas_channel::work_open::SetupQuery {
        bond_edge: hellas_kernel::EdgeId::from_bytes([0; 32]),
        payment_edge: None,
        funding: Default::default(),
    };
    let unfloored = hellas_chain::WorkBlocks::new(client.clone())
        .finalized_setup(query.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        unfloored.height, latest.snapshot.height,
        "the live certified root really proves absence before applying the journal floor"
    );
    let floor = hellas_chain::WorkBlocks::new(client.clone())
        .with_min_height(latest.snapshot.height + 1)
        .with_read_retry(Duration::from_millis(10), Duration::from_secs(2));
    let behind = floor.finalized_setup(query).await;
    assert!(
        matches!(
            behind,
            Err(hellas_channel::work_close::BlockSourceError::ReadUnavailableTimeout { .. })
        ),
        "a valid state below persisted progress cannot establish channel absence"
    );
    // One hanging relay must not discard an already verified healthy answer.
    let hanging = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.validators[0] = format!("ws://{}", hanging.local_addr().unwrap());
    assert!(
        hellas_sdk::client_chain::connect(&config, Duration::from_millis(500))
            .await
            .is_ok()
    );
    drop(hanging);
    // One source makes two refusals evidence of a retry, rather than two
    // concurrent source-selection requests. Observe requests, not elapsed time.
    config.validators = vec![relays.urls[0].clone()];
    relays.source.tips_unavailable.store(true, Ordering::SeqCst);
    let connecting = hellas_sdk::client_chain::connect(&config, Duration::from_secs(2));
    tokio::pin!(connecting);
    tokio::select! {
        result = &mut connecting => panic!("source selection ended before retrying unavailable tips: {}", result.err().map_or_else(|| "unexpected success".into(), |error| error.to_string())),
        permits = relays.source.tip_refusals.acquire_many(2) => permits.unwrap().forget(),
    }
    relays
        .source
        .tips_unavailable
        .store(false, Ordering::SeqCst);
    assert!(connecting.await.is_ok());
    relays.source.tips_unavailable.store(true, Ordering::SeqCst);
    assert!(matches!(
        hellas_sdk::client_chain::connect(&config, Duration::from_millis(100)).await,
        Err(QueryError::ReadUnavailableTimeout { .. })
    ));
    relays
        .source
        .tips_unavailable
        .store(false, Ordering::SeqCst);
    let split = hellas_sdk::coin_owner::OwnerReshape::prepare(
        &client,
        devnet.network(),
        CLIENT_OWNER.key().into_kernel(),
        &outputs.as_slice()[1..2],
        Some(client_settlement().party_key()),
        Some(100),
    )
    .await
    .unwrap();
    client
        .submit_tx(Transaction::Kernel(
            split
                .clone()
                .authorize(CLIENT_OWNER.authorize(split.payload_hash()))
                .unwrap(),
        ))
        .await
        .unwrap();
    devnet.seal().await;
    assert!(
        matches!(
            hellas_sdk::coin_owner::OwnerReshape::split(
                &client,
                devnet.network(),
                CLIENT_OWNER.key().into_kernel(),
                504,
                client_settlement().party_key()
            )
            .await,
            Err(hellas_sdk::coin_owner::CoinOwnerError::Insufficient {
                required: 504,
                available: 503
            })
        ),
        "five otherwise eligible inputs cannot fund a four-input channel reshape"
    );
    relays.shutdown().await;
    devnet.shutdown().await;
}

pub(super) async fn opening_cancellation_releases_the_mounted_client_journal(
    runtime: commonware_runtime::tokio::Context,
) {
    use hellas_channel::work_store::{ChannelStore, Role, WorkStoreError, journal::JournalError};
    let mut case = paid_fixture(runtime).await;
    let mut session = sealing_while(
        &mut case.devnet,
        Duration::from_millis(100),
        PaidWorkSession::open(
            case.options.clone(),
            case.endpoint.clone(),
            client_settlement(),
            case.owner.clone(),
            SessionOpenMode::Any,
            SessionFundingOptions::default(),
        ),
    )
    .await
    .unwrap();
    let descriptor = session.descriptor().clone();
    let height = case.devnet.height();
    tokio::time::timeout(Duration::from_secs(60), async {
        while session.with_state(|state| state.cursor().0).await.unwrap() < height {
            tokio::time::sleep(case.options.config.poll).await;
        }
    })
    .await
    .unwrap();
    let expected = session
        .with_state(|state| state.checkpoint())
        .await
        .unwrap();
    session.shutdown().await;
    drop(session);
    case.relays.source.replay.store(height, Ordering::SeqCst);
    for expires in [false, true] {
        let mut options = case.options.clone();
        options.config.max_observation_age = options.config.poll * 2;
        options.timeout = case.options.timeout;
        let gate = ObservationGate {
            reads: Arc::new(AtomicUsize::new(0)),
            first_blocked: Arc::new(AtomicUsize::new(0)),
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
            delay: options.config.max_observation_age + options.config.poll,
        };
        *case.relays.source.observation_gate.lock().unwrap() = Some(gate.clone());
        let mut opening = Box::pin(PaidWorkSession::open(
            options,
            case.endpoint.clone(),
            client_settlement(),
            case.owner.clone(),
            SessionOpenMode::Retained,
            SessionFundingOptions::default(),
        ));
        tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                result = &mut opening => panic!("opening ended before initial observation: {:?}; applied reads {}, first blocked {}", result.err(), gate.reads.load(Ordering::SeqCst), gate.first_blocked.load(Ordering::SeqCst)),
                permit = gate.entered.acquire() => permit.unwrap().forget(),
            }
        }).await.unwrap();
        assert_eq!(
            gate.first_blocked.load(Ordering::SeqCst),
            6,
            "the controlled sixth applied read is initial observation"
        );
        assert!(matches!(
            ChannelStore::recover(
                &case.options.journal_root,
                descriptor.channel().clone(),
                Role::Client,
                case.options.content.clone(),
                &hellas_kernel::Secp256k1Verifier::new()
            )
            .await,
            Err(WorkStoreError::Journal(JournalError::Locked { .. }))
        ));
        if expires {
            let error = opening
                .await
                .err()
                .expect("the configured opening deadline expires");
            assert!(
                matches!(
                    error,
                    hellas_sdk::paid_client::PaidClientError::Timeout { .. }
                ),
                "{error}"
            );
        } else {
            drop(opening);
        }
        let mut recovered = ChannelStore::recover(
            &case.options.journal_root,
            descriptor.channel().clone(),
            Role::Client,
            case.options.content.clone(),
            &hellas_kernel::Secp256k1Verifier::new(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(recovered.state().checkpoint(), expected);
        assert_eq!(
            gate.release.available_permits(),
            0,
            "the network gate is still blocked during canonical reopen"
        );
        recovered.close().await.unwrap();
        drop(recovered);
        *case.relays.source.observation_gate.lock().unwrap() = None;
        gate.release.close();
        let mut reopened = PaidWorkSession::open(
            case.options.clone(),
            case.endpoint.clone(),
            client_settlement(),
            case.owner.clone(),
            SessionOpenMode::Retained,
            SessionFundingOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            reopened.descriptor().channel().id(),
            descriptor.channel().id()
        );
        reopened.shutdown().await;
        drop(reopened);
    }
    case.endpoint.close().await;
    case.provider.shutdown().await.unwrap();
    case.provider_content.close().await;
    case.relays.shutdown().await;
    case.devnet.shutdown().await;
}
