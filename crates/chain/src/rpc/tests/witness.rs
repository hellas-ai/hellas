use super::*;
use crate::{HellasBlock, client::RemoteLightClient};
use commonware_codec::Encode as _;
use commonware_consensus::{
    CertifiableBlock as _, Heightable as _,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_storage::mmr::Location;
use commonware_utils::non_empty_range;
use hellas_rpc::pb::chain::{GetOperationsRequest, GetOperationsResponse};
use std::sync::{Arc, Mutex};

type Pending = crate::execution::finalized::Executed<commonware_runtime::tokio::Context>;

#[derive(Default)]
struct Operations {
    requests: Vec<GetOperationsRequest>,
    corrupt: bool,
}

#[derive(Clone)]
struct ObservedClient {
    local: LocalLightClient,
    operations: Arc<Mutex<Operations>>,
}

// Forward the real fixture, intercepting only operation proofs for assertions
// and fault injection at the wire boundary.
macro_rules! forward {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {$ (
        async fn $name(&self, $($arg: $ty),*) -> Result<$out, QueryError> {
            self.local.$name($($arg),*).await
        }
    )*};
}

impl LightClient for ObservedClient {
    async fn get_operations(
        &self,
        request: GetOperationsRequest,
    ) -> Result<GetOperationsResponse, QueryError> {
        let corrupt = {
            let mut operations = self.operations.lock().unwrap();
            operations.requests.push(request);
            operations.corrupt
        };
        let mut response = self.local.get_operations(request).await?;
        if corrupt {
            response.operations[0][1] ^= 1;
        }
        Ok(response)
    }

    forward! {
        get_state_root() -> Option<Digest>;
        get_proof(object_id: ObjectId) -> Option<Vec<u8>>;
        get_coin(payload: Digest, object_id: ObjectId) -> Option<crate::domain::Coin>;
        get_edge(payload: Digest, object_id: ObjectId) -> Option<crate::EdgeLookup>;
        get_finalization(payload: Digest) -> Option<Vec<u8>>;
        get_latest_block() -> Option<LatestBlock>;
        get_finalized_block(query: FinalizedBlockQuery) -> Option<FinalizedBlock>;
        get_applied_finalized_block(query: FinalizedBlockQuery) -> Option<FinalizedBlock>;
        submit_tx(tx: Transaction) -> hellas_rpc::SubmitTxOutcome;
        get_validators() -> Vec<String>;
        get_consensus_info() -> ConsensusInfo;
        get_coins_by_owner(owner: SettlementKey) -> Option<crate::CoinListing>;
        get_coins_by_delegate(delegate: SettlementKey) -> Option<crate::CoinListing>;
        get_edges_by_owner(owner: SettlementKey) -> Option<crate::OwnerEdges>;
    }
}

struct Fixture {
    database: UtxoDatabase<commonware_runtime::tokio::Context>,
    owners: OwnerIndex,
    remote: RemoteLightClient,
    applied: HellasBlock,
    archived: HellasBlock,
    pending: Option<Pending>,
    old_coin: ObjectId,
    new_coin: ObjectId,
    server: tokio::task::JoinHandle<()>,
    archive: Handle<()>,
    chain_indexer: ChainIndexer,
    operations: Arc<Mutex<Operations>>,
}

async fn prepare(
    database: &UtxoDatabase<commonware_runtime::tokio::Context>,
    allocations: &[(SettlementKey, u64)],
    parent: &HellasBlock,
    committee: &crate::execution::test_support::ConsensusFixture,
    txs: Vec<Transaction>,
) -> (HellasBlock, Pending) {
    let height = parent.height().get() + 1;
    let batch = execute_all(
        KernelContext::with_fees(
            crate::domain::TEST_NETWORK,
            BlockHeight::new(height),
            BlockHash::from_bytes(parent.digest().0),
            KERNEL_FEES,
        ),
        &ChainVerifier::new(),
        &txs,
        allocations,
        database.new_batches().await,
    )
    .await
    .unwrap();
    let owner_root = crate::execution::owner_tree::root(&batch).await.unwrap();
    let pending = batch.merkleize().await.unwrap();
    let bounds = pending.bounds();
    let block = HellasBlock::new(
        Context {
            round: Round::new(Epoch::zero(), View::new(height)),
            leader: committee.leaders[0].clone(),
            parent: (parent.context().round.view(), parent.digest()),
        },
        parent.digest(),
        Height::new(height),
        height,
        pending.root(),
        crate::UtxoSyncTarget::new(
            pending.root(),
            non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size)),
        ),
        txs,
    )
    .with_owner_root(owner_root);
    (block, pending)
}

async fn fixture(runtime: commonware_runtime::tokio::Context) -> Fixture {
    let committee = consensus_fixture(91);
    let owner = owner_key(41);
    let allocations = vec![(owner, 100)];
    let (root, target) =
        crate::execution::store::empty_state(runtime.child("genesis"), "witness", 1024, 8).await;
    let genesis = HellasBlock::genesis(committee.leaders[0].clone(), root, target, [0; 32].into());
    let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(
        runtime.child("database"),
        utxo_db_config(&runtime, "witness", 1024, 8),
    )
    .await;
    let (archive, archive_task) = spawn_archive(
        runtime.child("archive"),
        "witness",
        Config::default(),
        committee.verifier.clone(),
        genesis.clone(),
    )
    .await
    .unwrap();
    let owners = OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, allocations.clone());
    let (applied, batch) = prepare(&database, &allocations, &genesis, &committee, vec![]).await;
    database.finalize(batch).await;
    archive
        .ingest_finalized(applied.clone(), finalization(&committee, &applied))
        .await
        .unwrap();
    owners.apply_finalized(&applied).unwrap();
    let old_coin = genesis_object_id(0);
    let (reshape, ids) = crate::execution::test_support::reshape(
        41,
        &[old_coin],
        &[(owner, Some(owner_key(42)), 100)],
    );
    let (archived, pending) =
        prepare(&database, &allocations, &applied, &committee, vec![reshape]).await;
    // Marshal has the real certificate, but Stateful has not committed this batch.
    archive
        .ingest_finalized(archived.clone(), finalization(&committee, &archived))
        .await
        .unwrap();
    let local = LocalLightClient::new(
        database.clone(),
        owners.clone(),
        Mempool::default(),
        archive.clone(),
        ConsensusInfo {
            validators: vec![],
            threshold_identity: committee.assembler.identity().encode().to_vec(),
            network_id: crate::domain::TEST_NETWORK.as_str().into(),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let (activity, _) = tokio::sync::broadcast::channel(8);
    let operations = Arc::new(Mutex::new(Operations::default()));
    let server = crate::server::spawn_light_client_server(
        address,
        ObservedClient {
            local,
            operations: operations.clone(),
        },
        activity,
        crate::server::LightClientRpcState::default(),
    )
    .await
    .unwrap();
    let remote = RemoteLightClient::connect(format!("ws://{address}"))
        .await
        .unwrap()
        .with_consensus_verifier(committee.verifier);
    Fixture {
        database,
        owners,
        remote,
        applied,
        archived,
        pending: Some(pending),
        old_coin,
        new_coin: ids[0],
        server,
        archive: archive_task,
        chain_indexer: archive,
        operations,
    }
}

impl Fixture {
    fn assert_reads(&self, range: std::ops::Range<u64>) {
        let mut requests = std::mem::take(&mut self.operations.lock().unwrap().requests);
        requests.sort_by_key(|request| request.start);
        for request in &requests {
            assert_eq!(request.op_count, range.end);
        }
        assert_eq!(
            requests
                .into_iter()
                .flat_map(|r| r.start..r.start + r.max_ops)
                .collect::<Vec<_>>(),
            range.collect::<Vec<_>>(),
            "verified reads must cover only the missing operation range",
        );
    }
}

#[test]
fn object_witness_reuses_verified_state_and_rejects_corrupt_updates() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        // Bootstrap without requesting the coin, then read it through a clone.
        fixture.remote.get_objects(vec![]).await.unwrap().unwrap();
        assert!(!fixture.operations.lock().unwrap().requests.is_empty());
        fixture.operations.lock().unwrap().requests.clear();
        let clone = fixture.remote.clone();
        let snapshot = clone
            .get_objects(vec![fixture.old_coin])
            .await
            .unwrap()
            .unwrap();
        assert!(snapshot.objects.contains_key(&fixture.old_coin));
        assert!(
            fixture.operations.lock().unwrap().requests.is_empty(),
            "a verified checkpoint must not be downloaded again"
        );

        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        fixture.operations.lock().unwrap().corrupt = true;
        let keys = vec![fixture.old_coin, fixture.new_coin];
        assert!(fixture.remote.get_objects(keys.clone()).await.is_err());
        fixture.operations.lock().unwrap().corrupt = false;
        fixture.operations.lock().unwrap().requests.clear();
        let snapshot = clone.get_objects(keys).await.unwrap().unwrap();
        assert_eq!(snapshot.block.payload, fixture.archived.digest());
        assert!(!snapshot.objects.contains_key(&fixture.old_coin));
        assert!(
            matches!(snapshot.objects.get(&fixture.new_coin), Some(Object::Coin(coin)) if coin.value == 100)
        );
        let mut requests = fixture.operations.lock().unwrap().requests.clone();
        requests.sort_by_key(|request| request.start);
        let target = fixture.archived.sync_target();
        let start = (*fixture.applied.sync_target().range.end()).max(*target.range.start());
        assert_eq!(
            requests
                .iter()
                .map(|request| request.start)
                .collect::<Vec<_>>(),
            (start..*target.range.end()).step_by(64).collect::<Vec<_>>(),
            "failed update must be fetched again in full"
        );
        for request in requests {
            assert_eq!(
                request.op_count,
                *fixture.archived.sync_target().range.end()
            );
        }
        fixture.operations.lock().unwrap().requests.clear();
        fixture.owners.apply_finalized(&fixture.archived).unwrap();
        let committee = consensus_fixture(91);
        let (block, batch) = prepare(
            &fixture.database,
            &[(owner_key(41), 100)],
            &fixture.archived,
            &committee,
            vec![],
        )
        .await;
        fixture.database.finalize(batch).await;
        fixture
            .chain_indexer
            .ingest_finalized(block.clone(), finalization(&committee, &block))
            .await
            .unwrap();
        fixture.owners.apply_finalized(&block).unwrap();
        assert!(block.sync_target().range.start() < target.range.end());
        let snapshot = clone
            .get_objects(vec![fixture.new_coin])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.block.payload, block.digest());
        assert!(snapshot.objects.contains_key(&fixture.new_coin));
        assert_eq!(
            fixture.operations.lock().unwrap().requests[0].start,
            *target.range.end(),
            "incremental reads begin at the cached cursor"
        );
        fixture.server.abort();
        let _ = fixture.server.await;
        fixture.archive.abort();
        let _ = fixture.archive.await;
    });
}

#[test]
fn object_witness_bootstraps_again_after_pruning_overtakes_its_cursor() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        let keys = vec![fixture.old_coin, fixture.new_coin];
        fixture
            .remote
            .get_objects(keys.clone())
            .await
            .unwrap()
            .unwrap();
        fixture.operations.lock().unwrap().requests.clear();
        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        let committee = consensus_fixture(91);
        let mut parent = fixture.archived.clone();
        fixture.owners.apply_finalized(&parent).unwrap();
        for _ in 0..8 {
            let (block, batch) = prepare(
                &fixture.database,
                &[(owner_key(41), 100)],
                &parent,
                &committee,
                vec![],
            )
            .await;
            fixture.database.finalize(batch).await;
            fixture
                .chain_indexer
                .ingest_finalized(block.clone(), finalization(&committee, &block))
                .await
                .unwrap();
            fixture.owners.apply_finalized(&block).unwrap();
            parent = block;
        }
        let target = parent.sync_target();
        assert!(target.range.start() > fixture.applied.sync_target().range.end());
        fixture.database.prune(&target).await;
        let snapshot = fixture.remote.get_objects(keys).await.unwrap().unwrap();
        assert_eq!(snapshot.block.payload, parent.digest());
        assert!(!snapshot.objects.contains_key(&fixture.old_coin));
        assert!(snapshot.objects.contains_key(&fixture.new_coin));
        assert_eq!(
            fixture
                .operations
                .lock()
                .unwrap()
                .requests
                .iter()
                .map(|request| request.start)
                .min(),
            Some(*target.range.start())
        );
        fixture.server.abort();
        let _ = fixture.server.await;
        fixture.archive.abort();
        let _ = fixture.archive.await;
    });
}

#[test]
fn object_witness_uses_a_certified_applied_checkpoint() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        let applied = fixture.applied.sync_target();
        assert_eq!(
            fixture.database.read().await.bounds().end,
            applied.range.end()
        );
        assert!(fixture.archived.sync_target().range.end() > applied.range.end());
        // Observing archive progress must not reject the older applied checkpoint.
        let latest = fixture
            .remote
            .get_finalized_block(FinalizedBlockQuery::Latest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.snapshot.payload, fixture.archived.digest());
        // Bootstrap without the coin, then request it through a clone of the client.
        fixture.remote.get_objects(vec![]).await.unwrap().unwrap();
        fixture.assert_reads(*applied.range.start()..*applied.range.end());
        let remote = fixture.remote.clone();
        let keys = vec![fixture.old_coin, fixture.new_coin];
        let snapshot = remote.get_objects(keys.clone()).await.unwrap().unwrap();
        assert_eq!(snapshot.block.height, fixture.applied.height().get());
        assert_eq!(snapshot.block.payload, fixture.applied.digest());
        assert_eq!(snapshot.block.state_root, fixture.applied.state_root());
        assert!(
            matches!(snapshot.objects.get(&fixture.old_coin), Some(Object::Coin(coin)) if coin.value == 100)
        );
        assert!(!snapshot.objects.contains_key(&fixture.new_coin));
        fixture.assert_reads(*applied.range.end()..*applied.range.end());

        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        assert_eq!(fixture.owners.cursor().payload, fixture.applied.digest());
        // A corrupt suffix must not advance the shared cache or publish partial changes.
        fixture.operations.lock().unwrap().corrupt = true;
        assert!(fixture.remote.get_objects(keys.clone()).await.is_err());
        fixture.operations.lock().unwrap().corrupt = false;
        fixture.operations.lock().unwrap().requests.clear();
        // Also cover the commit-before-owner-publication window without any sleeps.
        let snapshot = remote.get_objects(keys.clone()).await.unwrap().unwrap();
        let target = fixture.archived.sync_target();
        fixture
            .assert_reads((*applied.range.end()).max(*target.range.start())..*target.range.end());
        assert_eq!(snapshot.block.payload, fixture.archived.digest());
        assert_eq!(snapshot.block.state_root, fixture.archived.state_root());
        assert!(!snapshot.objects.contains_key(&fixture.old_coin));
        assert!(
            matches!(snapshot.objects.get(&fixture.new_coin), Some(Object::Coin(coin)) if coin.value == 100)
        );
        fixture.owners.apply_finalized(&fixture.archived).unwrap();
        let published = remote.get_objects(keys.clone()).await.unwrap().unwrap();
        assert_eq!(published.block.payload, snapshot.block.payload);
        assert_eq!(published.block.state_root, snapshot.block.state_root);
        fixture.assert_reads(*target.range.end()..*target.range.end());

        let committee = consensus_fixture(91);
        let mut parent = fixture.archived.clone();
        let mut cursor = *target.range.end();
        for step in 0..8 {
            // Spend the cached coin so pruning can retire its original operation.
            let txs = if step == 1 {
                let (tx, ids) = crate::execution::test_support::reshape(
                    41,
                    &[fixture.new_coin],
                    &[(owner_key(41), Some(owner_key(42)), 100)],
                );
                fixture.new_coin = ids[0];
                vec![tx]
            } else {
                vec![]
            };
            let (block, batch) = prepare(
                &fixture.database,
                &[(owner_key(41), 100)],
                &parent,
                &committee,
                txs,
            )
            .await;
            fixture.database.finalize(batch).await;
            fixture
                .chain_indexer
                .ingest_finalized(block.clone(), finalization(&committee, &block))
                .await
                .unwrap();
            fixture.owners.apply_finalized(&block).unwrap();
            parent = block;
            if step == 0 {
                assert!(*parent.sync_target().range.start() < cursor);
                let snapshot = remote.get_objects(keys.clone()).await.unwrap().unwrap();
                assert_eq!(snapshot.block.payload, parent.digest());
                assert!(snapshot.objects.contains_key(&fixture.new_coin));
                fixture.assert_reads(cursor..*parent.sync_target().range.end());
                cursor = *parent.sync_target().range.end();
            }
        }
        // Once pruning overtakes the cached cursor, recover from the retained interval.
        let target = parent.sync_target();
        assert!(*target.range.start() > cursor);
        fixture.database.prune(&target).await;
        let snapshot = remote
            .get_objects(vec![fixture.old_coin, keys[1], fixture.new_coin])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.block.payload, parent.digest());
        assert_eq!(snapshot.objects.len(), 1);
        assert!(snapshot.objects.contains_key(&fixture.new_coin));
        fixture.assert_reads(*target.range.start()..*target.range.end());
        fixture.server.abort();
        let _ = fixture.server.await;
        fixture.archive.abort();
        let _ = fixture.archive.await;
    });
}

#[test]
fn unapplied_checkpoint_and_operation_requests_return_a_typed_wire_status() {
    run_qmdb(|runtime| async move {
        let fixture = fixture(runtime).await;
        for query in [
            FinalizedBlockQuery::Height(fixture.archived.height().get()),
            FinalizedBlockQuery::Payload(fixture.archived.digest()),
        ] {
            assert!(matches!(
                fixture.remote.get_applied_finalized_block(query).await,
                Err(QueryError::NotYetApplied),
            ));
        }
        assert!(matches!(
            fixture
                .remote
                .get_operations(hellas_rpc::pb::chain::GetOperationsRequest {
                    op_count: *fixture.archived.sync_target().range.end(),
                    start: *fixture.archived.sync_target().range.start(),
                    max_ops: 1,
                    include_pinned_nodes: false,
                })
                .await,
            Err(QueryError::NotYetApplied),
        ));
        fixture.server.abort();
        let _ = fixture.server.await;
        fixture.archive.abort();
        let _ = fixture.archive.await;
    });
}

#[cfg(feature = "work-watcher")]
#[test]
fn work_freshness_reference_uses_the_applied_witness_checkpoint() {
    use crate::{FinalizedWorkView as _, WorkBlocks, WorkChannelQuery};
    use hellas_channel::work_close::FinalizedBlocks as _;

    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        let witness = fixture
            .remote
            .get_objects(vec![fixture.old_coin])
            .await
            .unwrap()
            .unwrap();
        let source = WorkBlocks::new(fixture.remote.clone());
        let height = source.latest_height().await.unwrap().unwrap();
        eprintln!(
            "work freshness reference={height}; applied witness={}",
            witness.block.height
        );
        let query = WorkChannelQuery {
            bond_edge: hellas_kernel::EdgeId::from_bytes([0x31; 32]),
            payment_edge: None,
            funding: Default::default(),
        };
        let observed = source
            .with_min_height(height)
            .work_channel_snapshot(query.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed.block().height, witness.block.height);
        assert_eq!(height, witness.block.height);
        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        let source = WorkBlocks::new(fixture.remote.clone());
        let height = source.latest_height().await.unwrap().unwrap();
        assert_eq!(height, fixture.archived.height().get());
        let observed = source
            .with_min_height(height)
            .work_channel_snapshot(query)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed.block().height, height);
        fixture.server.abort();
        let _ = fixture.server.await;
        fixture.archive.abort();
        let _ = fixture.archive.await;
    });
}
