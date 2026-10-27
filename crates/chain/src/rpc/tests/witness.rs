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

type Pending = crate::execution::finalized::Executed<commonware_runtime::tokio::Context>;

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
        archive,
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
    let server = crate::server::spawn_light_client_server(
        address,
        local,
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
    }
}

#[test]
fn object_witness_uses_a_certified_applied_checkpoint() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        let count = fixture.database.read().await.bounds().end;
        assert_eq!(count, fixture.applied.sync_target().range.end());
        assert!(fixture.archived.sync_target().range.end() > count);
        eprintln!(
            "archive height={} root={} count={}; committed height={} root={} count={}",
            fixture.archived.height(),
            fixture.archived.state_root(),
            fixture.archived.sync_target().range.end(),
            fixture.applied.height(),
            fixture.applied.state_root(),
            count,
        );
        // Observing archive progress must not reject the older applied checkpoint.
        let latest = fixture
            .remote
            .get_finalized_block(FinalizedBlockQuery::Latest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.snapshot.payload, fixture.archived.digest());
        let keys = vec![fixture.old_coin, fixture.new_coin];
        let snapshot = fixture
            .remote
            .get_objects(keys.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.block.height, fixture.applied.height().get());
        assert_eq!(snapshot.block.payload, fixture.applied.digest());
        assert_eq!(snapshot.block.state_root, fixture.applied.state_root());
        assert!(
            matches!(snapshot.objects.get(&fixture.old_coin), Some(Object::Coin(coin)) if coin.value == 100)
        );
        assert!(!snapshot.objects.contains_key(&fixture.new_coin));

        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        assert_eq!(fixture.owners.cursor().payload, fixture.applied.digest());
        // Also cover the commit-before-owner-publication window without any sleeps.
        let snapshot = fixture
            .remote
            .get_objects(keys.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.block.payload, fixture.archived.digest());
        assert_eq!(snapshot.block.state_root, fixture.archived.state_root());
        assert!(!snapshot.objects.contains_key(&fixture.old_coin));
        assert!(
            matches!(snapshot.objects.get(&fixture.new_coin), Some(Object::Coin(coin)) if coin.value == 100)
        );
        fixture.owners.apply_finalized(&fixture.archived).unwrap();
        let published = fixture.remote.get_objects(keys).await.unwrap().unwrap();
        assert_eq!(published.block.payload, snapshot.block.payload);
        assert_eq!(published.block.state_root, snapshot.block.state_root);
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
    use hellas_work::work_close::FinalizedBlocks as _;

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
