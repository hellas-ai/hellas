use super::*;
use crate::LightClient as _;
use crate::execution::{
    ChainVerifier,
    store::{empty_state, utxo_db_config},
};
use crate::{
    domain,
    execution::test_support::{ConsensusFixture, consensus_fixture, finalization, run_qmdb},
};
use commonware_codec::Decode as _;
use commonware_consensus::{Block as _, Heightable as _, Reporter};
use commonware_consensus::{
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_glue::stateful::db::DatabaseSet;
use commonware_glue::stateful::db::{Merkleized as _, Unmerkleized as _};
use commonware_storage::{mmr::Location, qmdb::sync::Target};
use commonware_utils::non_empty_range;
use std::time::Duration;

struct Fixture {
    committee: ConsensusFixture,
    database: UtxoDatabase<runtime::Context>,
    head: HellasBlock,
    config: Config,
    allocations: Vec<(SettlementKey, u64)>,
}
impl Fixture {
    async fn new(runtime: runtime::Context, directory: &std::path::Path) -> Self {
        let committee = consensus_fixture(97521);
        let signer = hellas_kernel::Secp256k1Signer::from_secret_scalar([17; 32]).unwrap();
        let allocations = vec![(SettlementKey::from(signer.party_key()), 5000)];
        let genesis = hellas_genesis::Genesis {
            schema_version: 1,
            network_id: domain::TEST_NETWORK.as_str().into(),
            validators: committee
                .leaders
                .iter()
                .rev()
                .enumerate()
                .map(|(i, key)| hellas_genesis::GenesisValidator {
                    public_key: hex::encode(key.encode()),
                    label: format!("validator-{i}"),
                })
                .collect(),
            allocations: allocations
                .iter()
                .map(|(key, balance)| hellas_genesis::GenesisAllocation {
                    address: key.to_string(),
                    balance: *balance,
                })
                .collect(),
        };
        let (root, target) =
            empty_state(runtime.child("producer_genesis"), "producer", 4096, 128).await;
        let head = HellasBlock::genesis(
            committee.leaders.iter().min().unwrap().clone(),
            root,
            target,
        );
        let config = Config {
            genesis,
            threshold_identity: committee.assembler.identity().encode().to_vec(),
            genesis_payload: head.digest(),
            storage_dir: directory.to_path_buf(),
            validators: vec![],
            peers: vec![],
            archive_blocks: None,
        };
        let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(
            runtime.child("producer"),
            utxo_db_config(&runtime, "producer", 4096, 128),
        )
        .await;
        Self {
            committee,
            database,
            head,
            config,
            allocations,
        }
    }
    async fn next(&mut self) -> FinalizedBlock {
        let height = self.head.height().get() + 1;
        let batch = crate::execution::execute_all(
            hellas_kernel::Context::with_fees(
                crate::domain::network_id(&self.config.genesis).unwrap(),
                hellas_kernel::BlockHeight::new(height),
                hellas_kernel::BlockHash::from_bytes(self.head.digest().0),
                domain::KERNEL_FEES,
            ),
            &ChainVerifier::new(),
            &[],
            &self.allocations,
            self.database.new_batches().await,
        )
        .await
        .unwrap();
        let owner_root = crate::execution::owner_tree::root(&batch).await.unwrap();
        let executed = batch.merkleize().await.unwrap();
        let bounds = executed.bounds();
        let block = HellasBlock::new(
            Context {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: self.committee.leaders[0].clone(),
                parent: (self.head.context().round.view(), self.head.digest()),
            },
            self.head.digest(),
            Height::new(height),
            height,
            executed.root(),
            Target {
                root: executed.root(),
                range: non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size)),
            },
            vec![],
        )
        .with_owner_root(owner_root);
        self.database.finalize(executed).await;
        self.head = block.clone();
        self.certify(block)
    }
    fn certify(&self, block: HellasBlock) -> FinalizedBlock {
        FinalizedBlock {
            snapshot: crate::LatestBlock {
                height: block.height().get(),
                payload: block.digest(),
                state_root: block.state_root(),
                finalization: finalization(&self.committee, &block).encode().to_vec(),
            },
            block: block.encode().to_vec(),
        }
    }
}

#[test]
fn full_nodes_exchange_executed_state_without_a_validator() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, &directory.path().join("a")).await;
        let seed = FullNode::start(fixture.config.clone()).await.unwrap();
        let block = fixture.next().await;
        seed.0.core.apply(block.clone()).await.unwrap();
        let block2 = fixture.next().await;
        let mut config = fixture.config.clone();
        config.storage_dir = directory.path().join("relay");
        config.peers = vec![seed.endpoint_addr()];
        let a = FullNode::start(config).await.unwrap();
        tokio::time::timeout(Duration::from_secs(20), a.wait_ready())
            .await
            .unwrap()
            .unwrap();
        seed.0.core.apply(block2.clone()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            while a.0.core.applied() != 2 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        seed.shutdown().await.unwrap();
        let mut config = fixture.config.clone();
        config.storage_dir = directory.path().join("b");
        config.peers = vec![a.endpoint_addr()];
        config.archive_blocks = NonZeroU64::new(1);
        let b = FullNode::start(config).await.unwrap();
        let view = tokio::time::timeout(Duration::from_secs(20), b.wait_ready())
            .await
            .unwrap()
            .unwrap();
        let coins = view
            .client()
            .get_coins_by_owner(fixture.allocations[0].0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(coins.coins.len(), 1);
        assert_eq!(coins.coins[0].1, 5000);
        assert_eq!(coins.snapshot.payload, block2.snapshot.payload);
        let mut progress = b.finalized();
        tokio::time::timeout(Duration::from_secs(20), async {
            while *progress.borrow_and_update() < 2 {
                progress.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(
            b.view().unwrap().client().get_state_root().await.unwrap(),
            Some(block2.snapshot.state_root)
        );
        assert!(
            b.0.core
                .indexer
                .get_finalized_block(FinalizedBlockQuery::Height(1))
                .await
                .unwrap()
                .is_none()
        );
        let local = b.view().unwrap().client();
        let historical = tokio::time::timeout(
            Duration::from_secs(15),
            local.get_finalized_block(FinalizedBlockQuery::Height(1)),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(historical, block);
        // The public read subset does not trigger private recovery fetching.
        use hellas_rpc::{pb::chain as pb, services::chain_sync::ChainSyncHandler as _};
        let public = b
            .get_finalized_block(pb::GetFinalizedBlockRequest {
                query: Some(pb::get_finalized_block_request::Query::Height(1)),
            })
            .await
            .unwrap();
        assert!(public.block.is_none());
        a.shutdown().await.unwrap();
        assert!(
            local
                .get_finalized_block(FinalizedBlockQuery::Height(1))
                .await
                .is_err()
        );
        assert!(
            local
                .get_finalized_block(FinalizedBlockQuery::Height(999))
                .await
                .is_err()
        );
        b.shutdown().await.unwrap();
    });
}

#[test]
fn corrupt_proofs_cannot_raise_readiness_and_certified_root_failure_halts() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, directory.path()).await;
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        let first = fixture.next().await;
        let mut corrupt = first.clone();
        corrupt.block[0] ^= 1;
        assert!(matches!(
            node.0.core.apply(corrupt).await,
            Err(Error::InvalidBlock(_))
        ));
        let mut corrupt = first.clone();
        corrupt.snapshot.finalization[0] ^= 1;
        assert!(matches!(
            node.0.core.apply(corrupt).await,
            Err(Error::InvalidBlock(_))
        ));
        assert_eq!(node.0.core.readiness.seen.load(Ordering::Acquire), 0);
        assert_eq!(node.0.core.applied(), 0);
        node.0.core.apply(first).await.unwrap();
        let retained = node.view().unwrap();
        let second = fixture.next().await;
        node.0.core.observe(&second).unwrap();
        assert!(node.view().is_err());
        assert!(retained.client().get_state_root().await.is_err());
        let block = HellasBlock::decode(second.block.as_slice()).unwrap();
        let bad = HellasBlock::new(
            block.context().clone(),
            block.parent(),
            block.height(),
            block.timestamp(),
            Digest::from([99; 32]),
            block.sync_target(),
            block.txs().to_vec(),
        )
        .with_owner_root(block.owner_root());
        assert!(matches!(
            node.0.core.apply(fixture.certify(bad)).await,
            Err(Error::Execution(_))
        ));
        assert_eq!(node.0.core.applied(), 1);
        assert!(node.view().is_err());
        assert!(node.0.core.apply(second).await.is_err());
        assert!(node.shutdown().await.is_err());
    });
}

#[test]
fn pruned_archive_restarts_with_live_owner_state() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, directory.path()).await;
        fixture.config.archive_blocks = NonZeroU64::new(2);
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        let mut last = fixture.next().await;
        node.0.core.apply(last.clone()).await.unwrap();
        for _ in 1..260 {
            last = fixture.next().await;
            node.0.core.apply(last.clone()).await.unwrap();
        }
        // Marshal's pruning request is processed asynchronously.
        tokio::time::timeout(Duration::from_secs(5), async {
            while node
                .0
                .core
                .indexer
                .get_finalized_block(FinalizedBlockQuery::Height(1))
                .await
                .unwrap()
                .is_some()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        node.shutdown().await.unwrap();
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        assert!(
            node.view().is_err(),
            "restart needs a freshly verified head observation"
        );
        node.0.core.observe(&last).unwrap();
        assert_eq!(node.0.core.applied(), 260);
        let coins = node
            .view()
            .unwrap()
            .client()
            .get_coins_by_owner(fixture.allocations[0].0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(coins.coins[0].1, 5000);
        assert_eq!(coins.snapshot.payload, last.snapshot.payload);
        node.0.core.apply(fixture.next().await).await.unwrap();
        assert_eq!(node.0.core.applied(), 261);
        node.shutdown().await.unwrap();
    });
}

#[test]
fn a_state_directory_has_one_writer_and_retained_views_stop_on_shutdown() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, directory.path()).await;
        let mut wrong_genesis = fixture.config.clone();
        wrong_genesis.genesis_payload = [0xff; 32].into();
        assert!(matches!(
            FullNode::start(wrong_genesis).await,
            Err(Error::Config(_))
        ));
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        assert!(matches!(
            FullNode::start(fixture.config.clone()).await,
            Err(Error::Storage(_))
        ));
        node.0.core.apply(fixture.next().await).await.unwrap();
        let view = node.view().unwrap();
        node.shutdown().await.unwrap();
        assert!(view.client().get_state_root().await.is_err());
        drop(view);
        let node = FullNode::start(fixture.config).await.unwrap();
        node.shutdown().await.unwrap();
    });
}

struct StateRequests {
    old_count: u64,
    requested: tokio::sync::Notify,
    advanced: tokio::sync::watch::Sender<bool>,
}
#[derive(Clone)]
struct CorruptSource(
    hellas_rpc::pb::chain::GetFinalizedBlockResponse,
    Option<(FullNode, bool)>,
    Option<Arc<StateRequests>>,
);
#[allow(refining_impl_trait)]
impl hellas_rpc::services::chain_sync::ChainSyncHandler for CorruptSource {
    async fn get_latest_block(
        &self,
        _: hellas_rpc::pb::chain::GetLatestBlockRequest,
    ) -> Result<hellas_rpc::pb::chain::GetFinalizedBlockResponse, hellas_wire::WireStatus> {
        Ok(self.0.clone())
    }
    async fn get_finalized_block(
        &self,
        request: hellas_rpc::pb::chain::GetFinalizedBlockRequest,
    ) -> Result<hellas_rpc::pb::chain::GetFinalizedBlockResponse, hellas_wire::WireStatus> {
        if let Some((node, _)) = &self.1 {
            return hellas_rpc::services::chain_sync::ChainSyncHandler::get_finalized_block(
                node, request,
            )
            .await;
        }
        Ok(self.0.clone())
    }
    async fn get_finalization(
        &self,
        _: hellas_rpc::pb::chain::GetFinalizationRequest,
    ) -> Result<hellas_rpc::pb::chain::GetFinalizationResponse, hellas_wire::WireStatus> {
        Ok(hellas_rpc::pb::chain::GetFinalizationResponse { certificate: None })
    }
    async fn get_operations(
        &self,
        request: hellas_rpc::pb::chain::GetOperationsRequest,
    ) -> Result<hellas_rpc::pb::chain::GetOperationsResponse, hellas_wire::WireStatus> {
        if let Some(state) = &self.2 {
            state.requested.notify_one();
        }
        let Some((node, corrupt)) = &self.1 else {
            return Err(hellas_wire::WireStatus::unimplemented(
                "fixture has no state",
            ));
        };
        if let Some(state) = &self.2 {
            if *corrupt {
                state.requested.notify_one();
            } else if request.op_count == state.old_count {
                // Bootstrap must receive a newer live target before any good
                // operations for the initial target are allowed to complete.
                if tokio::time::timeout(
                    Duration::from_millis(200),
                    state.advanced.subscribe().wait_for(|advanced| *advanced),
                )
                .await
                .is_err()
                {
                    return Err(hellas_wire::WireStatus::new(
                        hellas_wire::WireCode::Unavailable,
                        "state source busy",
                    ));
                }
            } else {
                state.advanced.send_replace(true);
            }
        }
        let mut response =
            hellas_rpc::services::chain_sync::ChainSyncHandler::get_operations(node, request)
                .await?;
        if *corrupt {
            let mut proof = commonware_storage::merkle::Proof::<
                commonware_storage::mmr::Family,
                Digest,
            >::decode_cfg(response.proof.as_slice(), &128)
            .unwrap();
            if let Some(digest) = proof.digests.first_mut() {
                *digest = Digest::from([99; 32]);
            } else {
                proof.digests.push(Digest::from([99; 32]));
            }
            response.proof = proof.encode().to_vec();
        }
        Ok(response)
    }
    async fn subscribe_finalized(
        &self,
        _: hellas_rpc::pb::chain::GetLatestBlockRequest,
    ) -> Result<
        futures_util::stream::BoxStream<
            'static,
            Result<hellas_rpc::pb::chain::GetFinalizedBlockResponse, hellas_wire::WireStatus>,
        >,
        hellas_wire::WireStatus,
    > {
        if let Some((node, false)) = &self.1 {
            return hellas_rpc::services::chain_sync::ChainSyncHandler::subscribe_finalized(
                node,
                hellas_rpc::pb::chain::GetLatestBlockRequest {},
            )
            .await;
        }
        Ok(Box::pin(futures_util::stream::pending()))
    }
}

#[test]
fn corrupt_peer_is_dropped_and_marked_failed_in_the_registry() {
    use hellas_rpc::peers::{PeerId, ServiceStatus};
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, directory.path()).await;
        let good = fixture.next().await;
        for corrupt_certificate in [false, true] {
            let mut block = good.clone();
            if corrupt_certificate {
                block.snapshot.finalization[0] ^= 1;
            } else {
                block.block[0] ^= 1;
            }
            let server = CorruptSource(
                crate::server::finalized_block_response(Some(block)),
                None,
                None,
            );
            let (endpoint, serving) = serve_source(server).await;
            fixture.config.storage_dir = directory.path().join(if corrupt_certificate {
                "bad-certificate"
            } else {
                "bad-block"
            });
            fixture.config.peers = vec![endpoint.addr()];
            let node = FullNode::start(fixture.config.clone()).await.unwrap();
            tokio::time::timeout(Duration::from_secs(15), async {
                while node.peer_ids().contains(&endpoint.id()) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            assert!(node.view().is_err());
            assert_eq!(node.0.core.applied(), 0);
            assert_eq!(node.0.core.readiness.seen.load(Ordering::Acquire), 0);
            let registry = node.peer_registry().unwrap();
            let entry = registry
                .get(PeerId::from_bytes(*endpoint.id().as_bytes()))
                .unwrap();
            assert!(
                node.0
                    .manager
                    .is_blocked(PeerId::from_bytes(*endpoint.id().as_bytes()))
            );
            assert!(
                entry
                    .services
                    .values()
                    .any(|service| service.status == ServiceStatus::Failed)
            );
            node.shutdown().await.unwrap();
            serving.abort();
            let _ = serving.await;
            endpoint.close().await;
        }
    });
}

#[cfg(feature = "indexer-api")]
#[test]
fn indexed_node_publishes_from_its_execution_database_and_reopens_pruned_state() {
    use commonware_cryptography::{Hasher as _, Sha256};
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, directory.path()).await;
        fixture.config.genesis.network_id = hellas_genesis::HELLAS_DEVNET_1_ID.into();
        fixture.config.archive_blocks = NonZeroU64::new(1);
        let json = serde_json::to_vec(&fixture.config.genesis).unwrap();
        let trust = hellas_genesis::TrustDocument {
            schema_version: 1,
            network_id: fixture.config.genesis.network_id.clone(),
            genesis_sha256: hex::encode(Sha256::hash(&json)),
            epochs: vec![hellas_genesis::TrustEpoch {
                epoch: 0,
                start_height: 0,
                end_height: None,
                threshold_identity: hex::encode(&fixture.config.threshold_identity),
            }],
        };
        let node = FullNode::start_indexed(
            fixture.config.clone(),
            trust.clone(),
            json.clone(),
            "read".into(),
        )
        .await
        .unwrap();
        let mut last = fixture.next().await;
        node.0.core.apply(last.clone()).await.unwrap();
        for _ in 1..3 {
            last = fixture.next().await;
            node.0.core.apply(last.clone()).await.unwrap();
        }
        let owner = fixture.allocations[0].0;
        let proof = node.owner_proof(owner, 0, 32, None).await.unwrap().unwrap();
        assert_eq!(proof.block().view().payload(), last.snapshot.payload);
        let coins = node
            .view()
            .unwrap()
            .client()
            .get_coins_by_owner(owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(coins.snapshot.payload, proof.block().view().payload());
        assert_eq!(coins.coins.len(), 1);
        assert!(
            node.archive()
                .get_finalized_block(FinalizedBlockQuery::Height(1))
                .await
                .unwrap()
                .is_none()
        );
        node.shutdown().await.unwrap();
        let node = FullNode::start_indexed(fixture.config.clone(), trust, json, "read".into())
            .await
            .unwrap();
        assert!(node.view().is_err());
        let recovered = node.owner_proof(owner, 0, 32, None).await.unwrap().unwrap();
        assert_eq!(recovered.page(), proof.page());
        assert_eq!(recovered.block().view().payload(), last.snapshot.payload);
        node.0.core.apply(fixture.next().await).await.unwrap();
        assert_eq!(
            node.owner_proof(owner, 0, 32, None)
                .await
                .unwrap()
                .unwrap()
                .block()
                .view()
                .height(),
            4
        );
        node.shutdown().await.unwrap();
    });
}

#[cfg(feature = "validator")]
#[test]
fn validator_archive_seeds_execution_over_iroh() {
    use commonware_cryptography::{Signer as _, ed25519};
    use hellas_rpc::services::{chain_sync::ChainSync, node::Node};
    use hellas_wire::ServiceMarker as _;
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime.child("producer"), directory.path()).await;
        let (archive, handle) = crate::indexer::spawn_archive(
            runtime.child("seed"),
            "seed",
            ArchiveConfig::default(),
            fixture.committee.verifier.clone(),
            fixture.head.clone(),
        )
        .await
        .unwrap();
        let key = ed25519::PrivateKey::from_seed(97521).encode();
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(
                key.as_ref().try_into().unwrap(),
            ))
            .alpns(vec![
                ChainSync::ALPN.as_bytes().to_vec(),
                Node::ALPN.as_bytes().to_vec(),
            ])
            .bind()
            .await
            .unwrap();
        assert_eq!(
            endpoint.id().as_bytes().as_slice(),
            fixture.committee.leaders[0].encode().as_ref()
        );
        fixture.config.peers = vec![endpoint.addr()];
        let (activity, _) = tokio::sync::broadcast::channel(4);
        let serving = tokio::spawn(super::transport::serve_validator_endpoint(
            archive.clone(),
            activity,
            endpoint.clone(),
            fixture.database.clone(),
            fixture.committee.verifier.clone(),
        ));
        let block = fixture.next().await;
        archive
            .ingest_finalized_proof(
                HellasBlock::decode(block.block.as_slice()).unwrap(),
                &block.snapshot.finalization,
            )
            .await
            .unwrap();
        let node = FullNode::start(fixture.config).await.unwrap();
        let view = tokio::time::timeout(Duration::from_secs(20), node.wait_ready())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            view.client().get_state_root().await.unwrap(),
            Some(block.snapshot.state_root)
        );
        assert!(node.peer_ids().contains(&endpoint.id()));
        node.shutdown().await.unwrap();
        serving.abort();
        let _ = serving.await;
        endpoint.close().await;
        handle.abort();
        let _ = handle.await;
    });
}

// Test producers submit certificates through marshal; production sources do the
// same after transport verification. Stateful owns every database mutation.
impl Core {
    async fn apply(&self, incoming: FinalizedBlock) -> Result<(), Error> {
        use commonware_consensus::simplex::types::Activity;
        self.readiness.running()?;
        let block = self.observe(&incoming)?;
        let height = incoming.snapshot.height;
        let proof = crate::finality_proof::FinalityProof::decode(&incoming.snapshot.finalization)
            .map_err(invalid)?;
        for candidate in std::iter::once(block).chain(proof.descendants) {
            if !self
                .indexer
                .marshal
                .verified(candidate.context().round, candidate)
                .await
            {
                return Err(storage("marshal closed"));
            }
        }
        self.indexer
            .marshal
            .clone()
            .report(Activity::Finalization(proof.certificate));
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.applied() < height {
                if self.readiness.running().is_err() {
                    return Err(Error::Execution("node halted".into()));
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Ok(())
        })
        .await
        .map_err(storage)?
    }
}

#[test]
fn state_sync_blocks_bad_proofs_and_advances_its_floor_from_the_live_feed() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, &directory.path().join("seed")).await;
        let seed = FullNode::start(fixture.config.clone()).await.unwrap();
        let block = fixture.next().await;
        seed.0.core.apply(block.clone()).await.unwrap();
        let mut endpoints = Vec::new();
        let old_count = *HellasBlock::decode(block.block.as_slice())
            .unwrap()
            .sync_target()
            .range
            .end();
        let requested = Arc::new(StateRequests {
            old_count,
            requested: Default::default(),
            advanced: tokio::sync::watch::channel(false).0,
        });
        let mut tasks = Vec::new();
        for corrupt in [true, false] {
            let server = CorruptSource(
                crate::server::finalized_block_response(Some(block.clone())),
                Some((seed.clone(), corrupt)),
                Some(requested.clone()),
            );
            let (endpoint, task) = serve_source(server).await;
            tasks.push(task);
            endpoints.push(endpoint);
        }
        let mut config = fixture.config.clone();
        config.storage_dir = directory.path().join("replica");
        config.peers = endpoints.iter().map(|e| e.addr()).collect();
        let starting = tokio::spawn(FullNode::start(config));
        tokio::time::timeout(Duration::from_secs(20), requested.requested.notified())
            .await
            .unwrap();
        let block = fixture.next().await;
        seed.0.core.apply(block.clone()).await.unwrap();
        let node = tokio::time::timeout(Duration::from_secs(30), starting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(node.0.core.applied(), 2);
        assert_eq!(
            node.0.core.database.read().await.root(),
            block.snapshot.state_root
        );
        assert!(
            node.0
                .manager
                .is_blocked(replication::peer(endpoints[0].id()))
        );
        assert!(
            !node
                .0
                .manager
                .is_blocked(replication::peer(endpoints[1].id()))
        );
        assert!(
            hellas_rpc::services::chain_sync::ChainSyncHandler::get_operations(
                &node,
                hellas_rpc::pb::chain::GetOperationsRequest {
                    op_count: u64::MAX,
                    start: 0,
                    max_ops: 64,
                    include_pinned_nodes: false,
                }
            )
            .await
            .is_err()
        );
        node.shutdown().await.unwrap();
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        for endpoint in endpoints {
            endpoint.close().await;
        }
        seed.shutdown().await.unwrap();
    });
}

#[test]
fn provisioned_anchor_and_directory_identity_cannot_be_replaced_by_a_peer() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let fixture = Fixture::new(runtime, directory.path()).await;
        let mut wrong = fixture.config.clone();
        wrong.genesis_payload = Digest::from([99; 32]);
        assert!(matches!(
            FullNode::start(wrong).await,
            Err(Error::Config(_))
        ));
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        node.shutdown().await.unwrap();
        let mut wrong = fixture.config;
        wrong.threshold_identity = consensus_fixture(100)
            .assembler
            .identity()
            .encode()
            .to_vec();
        assert!(matches!(
            FullNode::start(wrong).await,
            Err(Error::Storage(_))
        ));
    });
}

#[cfg(feature = "validator")]
#[test]
fn full_node_and_validator_execution_roles_share_the_same_directory() {
    use crate::execution::pipeline;
    use commonware_consensus::{
        marshal::{resolver::handler, standard::Standard},
        types::FixedEpocher,
    };
    use commonware_glue::stateful::SyncPlan;
    use commonware_runtime::Runner as _;
    use commonware_utils::NZUsize;
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, directory.path()).await;
        let first = fixture.next().await;
        let second = fixture.next().await;
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        node.0.core.apply(first.clone()).await.unwrap();
        node.shutdown().await.unwrap();
        let config = fixture.config.clone();
        let signer = fixture.committee.schemes[0].clone();
        let verifier = fixture.committee.verifier.clone();
        let next = second.clone();
        // Start the validator's signer, mempool and shared execution wiring on
        // the full node's directory. Feed a committee certificate without
        // starting a second consensus network inside this storage-role test.
        tokio::task::spawn_blocking(move || {
            let _lock = pipeline::lock(&config.storage_dir).unwrap();
            runtime::Runner::new(
                runtime::Config::new().with_storage_directory(&config.storage_dir),
            )
            .start(move |context| async move {
                let settings = ArchiveConfig::default();
                let mut app = crate::Application::new(
                    context.child("app"),
                    domain::network_id(&config.genesis).unwrap(),
                    signer.participants().iter().min().unwrap().clone(),
                    genesis_allocations(&config.genesis).unwrap(),
                    "chain",
                    crate::ApplicationConfig::default(),
                )
                .await;
                assert!(app.mempool.is_none());
                let mempool = app.mempool();
                let owner = app.owner_index();
                let genesis = app.genesis_block();
                pipeline::pin(
                    &config.storage_dir,
                    &config.genesis,
                    &config.threshold_identity,
                    genesis.digest(),
                )
                .unwrap();
                let plan = SyncPlan::<_, domain::Scheme, Standard<HellasBlock>>::init(
                    &context.child("startup"),
                    "chain",
                )
                .await;
                let provider = Trust::Genesis(Arc::new(verifier.clone()));
                pipeline::verify_floor(&plan, &provider).unwrap();
                let startup = plan.sync_height();
                let (archive, indexer, processed) = crate::indexer::init(
                    context.child("archive"),
                    "chain",
                    &settings,
                    plan.marshal_start(genesis),
                    provider,
                    FixedEpocher::new(NonZeroU64::new(u64::MAX).unwrap()),
                )
                .await;
                let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                    .bind()
                    .await
                    .unwrap();
                let network =
                    replication::Network::new(endpoint.clone(), Trust::Genesis(Arc::new(verifier)));
                let (execution, mailbox) = pipeline::init(
                    context.child("execution"),
                    app,
                    &settings,
                    indexer.marshal.clone(),
                    plan,
                    network.clone(),
                    None,
                );
                let (receiver, handler) = handler::init(context.child("handler"), NZUsize!(256));
                let resolver = commonware_resolver::opaque::init::<_, _, _, PublicKey>(
                    context.child("resolver"),
                    network,
                    handler,
                    NZUsize!(256),
                    Duration::from_millis(500),
                );
                let archive = archive.start_unbuffered(mailbox.clone(), (receiver, resolver));
                let execution = execution.start();
                let database = mailbox.subscribe_databases().await;
                assert_eq!(
                    pipeline::restore(
                        &indexer,
                        &database,
                        &owner,
                        startup.into_iter().chain(processed).max()
                    )
                    .await
                    .unwrap(),
                    1
                );
                assert_eq!(database.read().await.root(), first.snapshot.state_root);
                let client = LocalLightClient::new(
                    database.clone(),
                    owner.clone(),
                    mempool,
                    indexer.clone(),
                    config.info().unwrap(),
                );
                assert_eq!(
                    client
                        .get_coins_by_owner(genesis_allocations(&config.genesis).unwrap()[0].0)
                        .await
                        .unwrap()
                        .unwrap()
                        .coins[0]
                        .1,
                    5000
                );
                let block = HellasBlock::decode(next.block.as_slice()).unwrap();
                assert!(indexer.marshal.verified(block.context().round, block).await);
                indexer.marshal.clone().report(
                    commonware_consensus::simplex::types::Activity::Finalization(
                        crate::finality_proof::FinalityProof::decode(&next.snapshot.finalization)
                            .unwrap()
                            .certificate,
                    ),
                );
                tokio::time::timeout(Duration::from_secs(10), async {
                    while owner.cursor().height < 2 {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(
                    client.get_state_root().await.unwrap(),
                    Some(next.snapshot.state_root)
                );
                archive.abort();
                execution.abort();
                let _ = archive.await;
                let _ = execution.await;
                endpoint.close().await;
            });
        })
        .await
        .unwrap();
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        node.0.core.observe(&second).unwrap();
        assert_eq!(
            node.view()
                .unwrap()
                .client()
                .get_state_root()
                .await
                .unwrap(),
            Some(second.snapshot.state_root)
        );
        node.0.core.apply(fixture.next().await).await.unwrap();
        node.shutdown().await.unwrap();
    });
}

async fn serve_source(server: CorruptSource) -> (iroh::Endpoint, tokio::task::JoinHandle<()>) {
    use hellas_rpc::services::chain_sync::{ChainSync, ChainSyncServer};
    use hellas_wire::{ServiceMarker as _, iroh::IrohTransport};
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .alpns(vec![ChainSync::ALPN.as_bytes().to_vec()])
        .bind()
        .await
        .unwrap();
    let accept = endpoint.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        while let Some(incoming) = accept.accept().await {
            let server = server.clone();
            connections.spawn(async move {
                if let Ok(connection) = incoming.await {
                    super::transport::dispatch(
                        Arc::new(IrohTransport::new(connection)),
                        ChainSyncServer(server),
                    )
                    .await;
                }
            });
        }
    });
    (endpoint, task)
}

#[test]
fn cancelled_bootstrap_releases_its_writer_and_resumes_the_certified_floor() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, &directory.path().join("seed")).await;
        let seed = FullNode::start(fixture.config.clone()).await.unwrap();
        let block = fixture.next().await;
        seed.0.core.apply(block.clone()).await.unwrap();
        let requested = Arc::new(StateRequests {
            old_count: 0,
            requested: Default::default(),
            advanced: tokio::sync::watch::channel(false).0,
        });
        let (endpoint, serving) = serve_source(CorruptSource(
            crate::server::finalized_block_response(Some(block.clone())),
            None,
            Some(requested.clone()),
        ))
        .await;
        let mut config = fixture.config.clone();
        config.storage_dir = directory.path().join("replica");
        config.peers = vec![endpoint.addr()];
        let starting = tokio::spawn(FullNode::start(config.clone()));
        tokio::time::timeout(Duration::from_secs(20), requested.requested.notified())
            .await
            .unwrap();
        assert!(crate::execution::pipeline::lock(&config.storage_dir).is_err());
        starting.abort();
        let _ = starting.await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while crate::execution::pipeline::lock(&config.storage_dir).is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        config.peers = vec![seed.endpoint_addr()];
        let node = tokio::time::timeout(Duration::from_secs(20), FullNode::start(config))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.0.core.applied(), 1);
        assert_eq!(
            node.0.core.database.read().await.root(),
            block.snapshot.state_root
        );
        node.shutdown().await.unwrap();
        serving.abort();
        let _ = serving.await;
        endpoint.close().await;
        seed.shutdown().await.unwrap();
    });
}
