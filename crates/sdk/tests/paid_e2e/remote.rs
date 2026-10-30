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
    pub listing_padding: Arc<AtomicBool>,
    pub attempts: Arc<AtomicUsize>,
    pub replay: Arc<AtomicU64>,
    pub corrupt: Arc<AtomicUsize>,
    pub forged: Arc<AtomicBool>,
    pub stale: Arc<std::sync::Mutex<Option<hellas_rpc::pb::chain::GetOperationsResponse>>>,
    pub connections: Arc<AtomicUsize>,
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
    forward!(get_consensus_info() -> ConsensusInfo);
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
        if self.tips_unavailable.load(Ordering::SeqCst) {
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
        let source = Source {
            local: devnet.validator_light_client(0),
            unavailable: Arc::new(AtomicBool::new(false)),
            tips_unavailable: Arc::new(AtomicBool::new(false)),
            listing_padding: Arc::new(AtomicBool::new(false)),
            attempts: Arc::new(AtomicUsize::new(0)),
            replay: Arc::new(AtomicU64::new(0)),
            corrupt: Arc::new(AtomicUsize::new(0)),
            forged: Arc::new(AtomicBool::new(false)),
            stale: Arc::new(std::sync::Mutex::new(None)),
            connections: Arc::new(AtomicUsize::new(0)),
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
    config.validators = relays.urls.clone();
    relays.source.tips_unavailable.store(true, Ordering::SeqCst);
    let connecting = hellas_sdk::client_chain::connect(&config, Duration::from_secs(2));
    tokio::pin!(connecting);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut connecting)
            .await
            .is_err(),
        "RPC Unavailable waits on the same connection future"
    );
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
