use super::*;
use crate::LightClient as _;
use crate::execution::{
    ChainVerifier,
    store::{UtxoDatabase, empty_state, utxo_db_config},
};
use crate::{
    domain::{self, SettlementKey},
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
use hellas_private::Durability::Crash;
use std::time::Duration;

struct Fixture {
    committee: ConsensusFixture,
    database: UtxoDatabase<runtime::Context>,
    head: HellasBlock,
    config: Config,
    allocations: Vec<(SettlementKey, u64)>,
}

#[test]
fn compiled_devnet_profile_starts_on_clean_home_with_pinned_hls3_genesis() {
    use commonware_runtime::Supervisor as _;
    run_qmdb(|runtime| async move {
        let profile = hellas_genesis::ChainProfile::known(hellas_genesis::Chain::Devnet);
        let genesis = profile.genesis();
        let leader = genesis
            .validators
            .iter()
            .map(|validator| {
                PublicKey::decode(hex::decode(&validator.public_key).unwrap().as_slice()).unwrap()
            })
            .min()
            .unwrap();
        let application = crate::Application::new(
            runtime.child("known_genesis"),
            crate::domain::network_id(genesis).unwrap(),
            crate::genesis_digest(genesis),
            leader,
            genesis_allocations(genesis).unwrap(),
            "known_genesis",
            crate::ApplicationConfig::default(),
        )
        .await;
        assert_eq!(
            application.genesis_block().digest().0,
            profile.known_genesis_payload_pin().unwrap()
        );
        let home = tempfile::tempdir().unwrap();
        let chain = crate::chain_dir::ChainDir::open(home.path(), &profile, Crash).unwrap();
        let mut config = Config::for_profile(chain, vec![], None).unwrap();
        config.validators.clear();
        let node = FullNode::start(config).await.unwrap();
        node.shutdown().await.unwrap();
    });
}
impl Fixture {
    async fn new(runtime: runtime::Context, directory: &std::path::Path) -> Self {
        Self::new_in(runtime, directory, domain::TEST_NETWORK, 5000).await
    }
    async fn new_in(
        runtime: runtime::Context,
        directory: &std::path::Path,
        network: hellas_kernel::NetworkId,
        balance: u64,
    ) -> Self {
        let committee = consensus_fixture(97521);
        let signer = hellas_kernel::Secp256k1Signer::from_secret_scalar([17; 32]).unwrap();
        let allocations = vec![(SettlementKey::from(signer.party_key()), balance)];
        let genesis = hellas_genesis::Genesis {
            schema_version: 1,
            network_id: network.as_str().into(),
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
        let committee = crate::execution::test_support::consensus_fixture_in(
            97521,
            4,
            network,
            crate::genesis_digest(&genesis),
        );
        let (root, target) =
            empty_state(runtime.child("producer_genesis"), "producer", 4096, 128).await;
        let head = HellasBlock::genesis(
            committee.leaders.iter().min().unwrap().clone(),
            root,
            target,
            crate::genesis_digest(&genesis),
        );
        use commonware_cryptography::{Hasher as _, Sha256};
        let genesis_json = serde_json::to_string(&genesis).unwrap();
        let mut trust = hellas_genesis::ChainProfile::known(hellas_genesis::Chain::Devnet)
            .trust()
            .clone();
        trust.network_id = genesis.network_id.clone();
        trust.genesis_sha256 = hex::encode(Sha256::hash(genesis_json.as_bytes()));
        trust.epochs[0].threshold_identity = hex::encode(committee.assembler.identity().encode());
        let profile = hellas_genesis::ChainProfile::custom(hellas_genesis::CustomChainFile {
            trust,
            validators: vec!["ws://unused.invalid".into()],
            genesis_json,
        })
        .unwrap();
        let mut config = Config::for_profile(
            crate::chain_dir::ChainDir::open(directory, &profile, Crash).unwrap(),
            vec![],
            None,
        )
        .unwrap();
        config.validators.clear();
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
                crate::domain::network_id(self.config.genesis()).unwrap(),
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
                root: executed.ops_root(),
                range: non_empty_range!(
                    executed.sync_boundary(),
                    Location::new(executed.bounds().total_size)
                ),
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
                finalization: crate::finality_proof::encode(
                    &finalization(&self.committee, &block).encode(),
                    &[],
                )
                .unwrap(),
            },
            block: block.encode().to_vec(),
        }
    }
}

#[test]
fn recovery_finds_the_first_committed_block_before_its_archive_acknowledgment() {
    use commonware_actor::Feedback;
    use commonware_consensus::{
        marshal::{Start, Update, resolver::handler},
        types::FixedEpocher,
    };
    use commonware_utils::NZUsize;
    #[derive(Clone)]
    struct HoldAcknowledgment(tokio::sync::mpsc::UnboundedSender<Update<HellasBlock>>);
    impl Reporter for HoldAcknowledgment {
        type Activity = Update<HellasBlock>;
        fn report(&mut self, update: Self::Activity) -> Feedback {
            self.0.send(update).unwrap();
            Feedback::Ok
        }
    }
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime.child("producer"), directory.path()).await;
        let genesis = fixture.head.clone();
        let owner = crate::owner_index::OwnerIndex::new(
            domain::TEST_NETWORK,
            &genesis,
            fixture.allocations.clone(),
        );
        let trust = Trust::Genesis(Arc::new(fixture.committee.verifier.clone()));
        let (actor, archive, _) = crate::indexer::init(
            runtime.child("archive"),
            "unacknowledged",
            &ArchiveConfig::default(),
            Start::Genesis(genesis.clone()),
            trust.clone(),
            FixedEpocher::new(NonZeroU64::new(u64::MAX).unwrap()),
        )
        .await;
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let network = replication::Network::new(endpoint.clone(), trust.clone());
        let (receiver, handler) = handler::init(runtime.child("handler"), NZUsize!(256));
        let resolver = commonware_resolver::opaque::init::<_, _, _, PublicKey>(
            runtime.child("resolver"),
            network,
            handler,
            NZUsize!(256),
            Duration::from_millis(500),
        );
        let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
        let task = actor.start_unbuffered(HoldAcknowledgment(send), (receiver, resolver));
        let block = fixture.next().await;
        let input = input::FinalizedInput::new(archive.clone(), Arc::default(), trust);
        input.accept(&block).await.unwrap();
        let acknowledgment = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let update = receive.recv().await.expect("archive remained open");
                if matches!(update, Update::Block(..)) {
                    break update;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            archive
                .marshal
                .get_processed_height()
                .await
                .map_or(0, |h| h.get()),
            0
        );
        assert_eq!(owner.cursor().height, 0);
        assert_eq!(
            crate::execution::pipeline::restore(
                &archive,
                &fixture.database,
                &owner,
                None,
                &genesis
            )
            .await
            .unwrap(),
            1
        );
        assert_eq!(owner.cursor().payload, block.snapshot.payload);
        // Stop the source without releasing its durable acknowledgment.
        task.abort();
        let _ = task.await;
        drop(acknowledgment);
        endpoint.close().await;
    });
}

#[test]
fn certified_future_history_suspends_retained_reads_until_ancestry_executes() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, directory.path()).await;
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        apply(&node, fixture.next().await).await.unwrap();
        let retained = node.view().unwrap().client();
        let parent = fixture.next().await;
        let tip = fixture.next().await;
        node.accept_finalized(&tip).await.unwrap();
        assert_eq!(
            node.status(),
            NodeStatus::CatchingUp {
                observed: Some(3),
                executed: 1
            }
        );
        assert!(matches!(
            retained.get_latest_block().await,
            Err(QueryError::StateUnavailable(_))
        ));
        node.accept_finalized(&parent).await.unwrap();
        apply(&node, tip.clone()).await.unwrap();
        assert_eq!(
            retained.get_latest_block().await.unwrap().unwrap().payload,
            tip.snapshot.payload
        );
        node.shutdown().await.unwrap();
    });
}

#[test]
fn full_nodes_exchange_executed_state_without_a_validator() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, &directory.path().join("a")).await;
        let seed = FullNode::start(fixture.config.clone()).await.unwrap();
        let block = fixture.next().await;
        apply(&seed, block.clone()).await.unwrap();
        let block2 = fixture.next().await;
        let mut config = fixture.config.clone();
        config.chain = crate::chain_dir::ChainDir::open(
            &directory.path().join("relay"),
            config.chain.profile(),
            Crash,
        )
        .unwrap();
        config.peers = vec![seed.endpoint_addr()];
        let a = FullNode::start(config).await.unwrap();
        tokio::time::timeout(Duration::from_secs(20), a.wait_ready())
            .await
            .unwrap()
            .unwrap();
        apply(&seed, block2.clone()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            while a.status().executed_height() != 2 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        seed.shutdown().await.unwrap();
        let mut config = fixture.config.clone();
        config.chain = crate::chain_dir::ChainDir::open(
            &directory.path().join("b"),
            config.chain.profile(),
            Crash,
        )
        .unwrap();
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
        assert!(!archived(&b, 1).await);
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
            apply(&node, corrupt).await,
            Err(Error::InvalidBlock(_))
        ));
        let mut corrupt = first.clone();
        corrupt.snapshot.finalization[0] ^= 1;
        assert!(matches!(
            apply(&node, corrupt).await,
            Err(Error::InvalidBlock(_))
        ));
        assert_eq!(
            node.status(),
            NodeStatus::CatchingUp {
                observed: None,
                executed: 0
            }
        );
        assert_eq!(node.status().executed_height(), 0);
        apply(&node, first).await.unwrap();
        let second = fixture.next().await;
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
            apply(&node, fixture.certify(bad)).await,
            Err(Error::Query(_))
        ));
        assert_eq!(node.status().executed_height(), 1);
        assert!(node.view().is_err());
        assert!(apply(&node, second).await.is_err());
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
        apply(&node, last.clone()).await.unwrap();
        for _ in 1..260 {
            last = fixture.next().await;
            apply(&node, last.clone()).await.unwrap();
        }
        // Marshal's pruning request is processed asynchronously.
        tokio::time::timeout(Duration::from_secs(5), async {
            while archived(&node, 1).await {
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
        node.accept_finalized(&last).await.unwrap();
        assert_eq!(node.status().executed_height(), 260);
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
        apply(&node, fixture.next().await).await.unwrap();
        assert_eq!(node.status().executed_height(), 261);
        node.shutdown().await.unwrap();
    });
}

#[test]
fn a_state_directory_has_one_writer_and_retained_views_stop_on_shutdown() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, directory.path()).await;
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        assert!(matches!(
            FullNode::start(fixture.config.clone()).await,
            Err(Error::Storage(_))
        ));
        apply(&node, fixture.next().await).await.unwrap();
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
        hellas_rpc::call::ResponseStream<hellas_rpc::pb::chain::GetFinalizedBlockResponse>,
        hellas_wire::WireStatus,
    > {
        if let Some((node, false)) = &self.1 {
            return hellas_rpc::services::chain_sync::ChainSyncHandler::subscribe_finalized(
                node,
                hellas_rpc::pb::chain::GetLatestBlockRequest {},
            )
            .await;
        }
        Ok(hellas_rpc::call::ResponseStream::new(
            futures_util::stream::pending(),
        ))
    }
}

#[test]
fn corrupt_peer_is_dropped_and_marked_failed_in_the_registry() {
    use hellas_wire::peers::{PeerId, ServiceStatus};
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
            fixture.config.chain = crate::chain_dir::ChainDir::open(
                &directory.path().join(if corrupt_certificate {
                    "bad-certificate"
                } else {
                    "bad-block"
                }),
                fixture.config.chain.profile(),
                Crash,
            )
            .unwrap();
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
            assert_eq!(node.status().executed_height(), 0);
            assert_eq!(
                node.status(),
                NodeStatus::CatchingUp {
                    observed: None,
                    executed: 0
                }
            );
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
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new_in(
            runtime,
            directory.path(),
            hellas_kernel::NetworkId::new("custom-indexed-node").unwrap(),
            5000,
        )
        .await;
        fixture.config.archive_blocks = NonZeroU64::new(1);
        let node = FullNode::start_indexed(fixture.config.clone(), "read".into())
            .await
            .unwrap();
        let mut last = fixture.next().await;
        apply(&node, last.clone()).await.unwrap();
        for _ in 1..3 {
            last = fixture.next().await;
            apply(&node, last.clone()).await.unwrap();
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
        assert!(!archived(&node, 1).await);
        node.shutdown().await.unwrap();
        let node = FullNode::start_indexed(fixture.config.clone(), "read".into())
            .await
            .unwrap();
        assert!(node.view().is_err());
        let recovered = node.owner_proof(owner, 0, 32, None).await.unwrap().unwrap();
        assert_eq!(recovered.page(), proof.page());
        assert_eq!(recovered.block().view().payload(), last.snapshot.payload);
        apply(&node, fixture.next().await).await.unwrap();
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
        let (archive, handle) = crate::indexer::fixtures::spawn_archive(
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
            archive.archive.clone(),
            activity,
            endpoint.clone(),
            fixture.database.clone(),
            fixture.committee.verifier.clone(),
        ));
        let block = fixture.next().await;
        archive
            .publish_proof(
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

// Fixtures submit certified input through the normal node interface and wait for
// its published read view; they never execute or finalize the consumer database.
async fn apply(node: &FullNode, incoming: FinalizedBlock) -> Result<(), Error> {
    node.accept_finalized(&incoming).await?;
    tokio::time::timeout(Duration::from_secs(10), node.wait_ready())
        .await
        .expect("node execution is bounded")?;
    Ok(())
}

async fn archived(node: &FullNode, height: u64) -> bool {
    hellas_rpc::services::chain_sync::ChainSyncHandler::get_finalized_block(
        node,
        hellas_rpc::pb::chain::GetFinalizedBlockRequest {
            query: Some(hellas_rpc::pb::chain::get_finalized_block_request::Query::Height(height)),
        },
    )
    .await
    .unwrap()
    .block
    .is_some()
}

#[test]
fn current_state_root_and_operation_sync_target_survive_node_restart() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, directory.path()).await;
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        let finalized = fixture.next().await;
        let block = HellasBlock::decode(finalized.block.as_slice()).unwrap();
        let target = block.sync_target();
        assert_ne!(block.state_root(), target.root);
        {
            let producer = fixture.database.read().await;
            assert_eq!(block.state_root(), producer.root());
        }
        apply(&node, finalized.clone()).await.unwrap();
        node.shutdown().await.unwrap();
        let node = FullNode::start(fixture.config).await.unwrap();
        node.accept_finalized(&finalized).await.unwrap();
        // Acceptance queues the block; the published watch marks executed state.
        let mut executed = node.finalized();
        tokio::time::timeout(Duration::from_secs(10), async {
            executed
                .wait_for(|height| *height >= block.height().get())
                .await
                .expect("execution progress remains published");
        })
        .await
        .expect("the accepted block executes");
        assert_eq!(node.status().executed_height(), block.height().get());
        assert_eq!(
            node.view()
                .unwrap()
                .client()
                .get_state_root()
                .await
                .unwrap(),
            Some(block.state_root())
        );
        node.shutdown().await.unwrap();
    });
}

#[test]
fn state_sync_blocks_bad_proofs_and_advances_its_floor_from_the_live_feed() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new(runtime, &directory.path().join("seed")).await;
        let seed = FullNode::start(fixture.config.clone()).await.unwrap();
        let block = fixture.next().await;
        apply(&seed, block.clone()).await.unwrap();
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
        config.chain = crate::chain_dir::ChainDir::open(
            &directory.path().join("replica"),
            config.chain.profile(),
            Crash,
        )
        .unwrap();
        config.peers = endpoints.iter().map(|e| e.addr()).collect();
        let starting = tokio::spawn(FullNode::start(config));
        tokio::time::timeout(Duration::from_secs(20), requested.requested.notified())
            .await
            .unwrap();
        let block = fixture.next().await;
        apply(&seed, block.clone()).await.unwrap();
        let node = tokio::time::timeout(Duration::from_secs(30), starting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(node.status().executed_height(), 2);
        assert_eq!(
            node.view()
                .unwrap()
                .client()
                .get_state_root()
                .await
                .unwrap()
                .unwrap(),
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
fn provisioned_anchor_ignores_legacy_chain_directory() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let fixture = Fixture::new(runtime, directory.path()).await;
        let legacy = directory.path().join("chain/legacy-network");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("old-state"), b"obsolete").unwrap();
        let node = FullNode::start(fixture.config.clone()).await.unwrap();
        node.shutdown().await.unwrap();
        assert_eq!(
            std::fs::read(legacy.join("old-state")).unwrap(),
            b"obsolete"
        );
        assert!(
            fixture
                .config
                .storage_dir()
                .starts_with(directory.path().join("chains"))
        );
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
        apply(&node, first.clone()).await.unwrap();
        node.shutdown().await.unwrap();
        let config = fixture.config.clone();
        let signer = fixture.committee.schemes[0].clone();
        let verifier = fixture.committee.verifier.clone();
        let next = second.clone();
        // Start the validator's signer, mempool and shared execution wiring on
        // the full node's directory. Feed a committee certificate without
        // starting a second consensus network inside this storage-role test.
        tokio::task::spawn_blocking(move || {
            let _lock = pipeline::lock(&config.storage_dir()).unwrap();
            runtime::Runner::new(
                runtime::Config::new().with_storage_directory(config.storage_dir()),
            )
            .start(move |context| async move {
                let settings = ArchiveConfig::default();
                let mut app = crate::Application::new(
                    context.child("app"),
                    domain::network_id(config.genesis()).unwrap(),
                    crate::genesis_digest(config.genesis()),
                    signer.participants().iter().min().unwrap().clone(),
                    genesis_allocations(config.genesis()).unwrap(),
                    "chain",
                    crate::ApplicationConfig::default(),
                )
                .await;
                assert!(app.mempool.is_none());
                let mempool = app.mempool();
                let owner = app.owner_index();
                let genesis = app.genesis_block();
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
                    plan.marshal_start(genesis.clone()),
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
                // Database attachment precedes replay of blocks whose execution
                // was committed before shutdown but not yet acknowledged.
                let restored = tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        let height = pipeline::restore(
                            &indexer,
                            &database,
                            &owner,
                            startup.into_iter().chain(processed).max(),
                            &genesis,
                        )
                        .await
                        .unwrap();
                        if height > 0 {
                            break height;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(restored, 1);
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
                        .get_coins_by_owner(genesis_allocations(config.genesis()).unwrap()[0].0)
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
        node.accept_finalized(&second).await.unwrap();
        let view = tokio::time::timeout(Duration::from_secs(10), node.wait_ready())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            view.client().get_state_root().await.unwrap(),
            Some(second.snapshot.state_root)
        );
        apply(&node, fixture.next().await).await.unwrap();
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
        apply(&seed, block.clone()).await.unwrap();
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
        config.chain = crate::chain_dir::ChainDir::open(
            &directory.path().join("replica"),
            config.chain.profile(),
            Crash,
        )
        .unwrap();
        config.peers = vec![endpoint.addr()];
        let starting = tokio::spawn(FullNode::start(config.clone()));
        tokio::time::timeout(Duration::from_secs(20), requested.requested.notified())
            .await
            .unwrap();
        assert!(crate::execution::pipeline::lock(&config.storage_dir()).is_err());
        starting.abort();
        let _ = starting.await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while crate::execution::pipeline::lock(&config.storage_dir()).is_err() {
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
        assert_eq!(node.status().executed_height(), 1);
        assert_eq!(
            node.view()
                .unwrap()
                .client()
                .get_state_root()
                .await
                .unwrap()
                .unwrap(),
            block.snapshot.state_root
        );
        node.shutdown().await.unwrap();
        serving.abort();
        let _ = serving.await;
        endpoint.close().await;
        seed.shutdown().await.unwrap();
    });
}

#[test]
fn shared_committee_foreign_genesis_is_rejected_before_follower_execution() {
    rejects_foreign_chain(domain::TEST_NETWORK, 5001);
}

#[test]
fn shared_committee_foreign_network_is_rejected_before_follower_execution() {
    rejects_foreign_chain(
        hellas_kernel::NetworkId::new("another-chain").unwrap(),
        5000,
    );
}

fn rejects_foreign_chain(target_network: hellas_kernel::NetworkId, target_balance: u64) {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let mut source =
            Fixture::new(runtime.child("source"), &directory.path().join("source")).await;
        let incoming = source.next().await;
        let (endpoint, serving) = serve_source(CorruptSource(
            crate::server::finalized_block_response(Some(incoming.clone())),
            None,
            None,
        ))
        .await;
        let label = "target";
        let network = target_network;
        let balance = target_balance;
        {
            let target = Fixture::new_in(
                runtime.child(label),
                &directory.path().join(label),
                network,
                balance,
            )
            .await;
            assert_eq!(
                source.config.threshold_identity(),
                target.config.threshold_identity()
            );
            let verifier = ConsensusVerifier::new(
                &target.config.info().unwrap(),
                crate::genesis_digest(target.config.genesis()),
            )
            .unwrap();
            let trust = Trust::Genesis(Arc::new(verifier));
            // Exercise ChainSync's untrusted fetch, the same gate used for startup floors.
            let client = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .bind()
                .await
                .unwrap();
            let network = replication::Network::new(client.clone(), trust);
            network.seed(endpoint.addr());
            assert!(
                network.fetch(FinalizedBlockQuery::Latest).await.is_none(),
                "{label}: ChainSync accepted foreign history"
            );
            client.close().await;
            let follower = FullNode::start(target.config).await.unwrap();
            assert!(matches!(
                apply(&follower, incoming.clone()).await,
                Err(Error::InvalidBlock(_))
            ));
            assert_eq!(follower.status().executed_height(), 0);
            assert!(!matches!(follower.status(), NodeStatus::Stopped { .. }));
            follower.shutdown().await.unwrap();
        }
        serving.abort();
        let _ = serving.await;
        endpoint.close().await;
    });
}

#[test]
fn genesis_digest_distinguishes_allocations_and_networks() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let source = Fixture::new(runtime.child("source"), &directory.path().join("source")).await;
        for (label, network, balance) in [
            ("allocations", domain::TEST_NETWORK, 5001),
            (
                "network",
                hellas_kernel::NetworkId::new("another-chain").unwrap(),
                5000,
            ),
        ] {
            let target = Fixture::new_in(
                runtime.child(label),
                &directory.path().join(label),
                network,
                balance,
            )
            .await;
            assert_eq!(
                source.config.threshold_identity(),
                target.config.threshold_identity()
            );
            assert_ne!(
                crate::genesis_digest(source.config.genesis()),
                crate::genesis_digest(target.config.genesis())
            );
        }
    });
}

#[test]
fn full_node_derives_h0_from_the_selected_custom_genesis() {
    run_qmdb(|runtime| async move {
        let directory = tempfile::tempdir().unwrap();
        let fixture = Fixture::new(runtime, directory.path()).await;
        let expected = fixture.head.digest();
        let node = FullNode::start(fixture.config).await.unwrap();
        assert_eq!(node.genesis_payload(), expected);
        node.shutdown().await.unwrap();
    });
}

#[test]
fn nonindexed_full_node_refuses_an_expiring_threshold_key() {
    use commonware_cryptography::{Hasher as _, Sha256};
    let mut genesis: hellas_genesis::Genesis =
        serde_json::from_str(hellas_genesis::HELLAS_DEVNET_2_JSON).unwrap();
    genesis.network_id = "custom-node-rotating-1".into();
    let genesis_json = serde_json::to_string(&genesis).unwrap();
    let mut trust = hellas_genesis::ChainProfile::known(hellas_genesis::Chain::Devnet)
        .trust()
        .clone();
    trust.network_id = genesis.network_id.clone();
    trust.genesis_sha256 = hex::encode(Sha256::hash(genesis_json.as_bytes()));
    trust.epochs[0].end_height = Some(2);
    let mut next = trust.epochs[0].clone();
    next.epoch = 1;
    next.start_height = 2;
    next.end_height = None;
    trust.epochs.push(next);
    let profile = hellas_genesis::ChainProfile::custom(hellas_genesis::CustomChainFile {
        trust,
        validators: vec!["ws://127.0.0.1:9080".into()],
        genesis_json,
    })
    .unwrap();
    let home = tempfile::tempdir().unwrap();
    let chain = crate::chain_dir::ChainDir::open(home.path(), &profile, Crash).unwrap();
    let error = Config::for_profile(chain, vec![], None).unwrap_err();
    assert!(error.to_string().contains("one open trusted epoch"));
}

#[test]
fn one_home_keeps_each_chains_state_across_a_switch_and_back() {
    run_qmdb(|runtime| async move {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("identity"), b"device identity").unwrap();
        let mut a =
            Fixture::new_in(runtime.child("a"), home.path(), domain::TEST_NETWORK, 5000).await;
        let first = a.next().await;
        let second = a.next().await;
        let node = FullNode::start(a.config.clone()).await.unwrap();
        apply(&node, first).await.unwrap();
        node.shutdown().await.unwrap();

        // A different genesis under the same home gets its own, empty state.
        let b = Fixture::new_in(runtime.child("b"), home.path(), domain::TEST_NETWORK, 6000).await;
        assert_ne!(a.config.storage_dir(), b.config.storage_dir());
        let node = FullNode::start(b.config.clone()).await.unwrap();
        assert_eq!(node.status().executed_height(), 0);
        assert!(apply(&node, second.clone()).await.is_err());
        node.shutdown().await.unwrap();

        // Back on A, its executed state is intact: the next block extends it.
        let node = FullNode::start(a.config.clone()).await.unwrap();
        apply(&node, second).await.unwrap();
        assert_eq!(node.status().executed_height(), 2);
        node.shutdown().await.unwrap();
        assert_eq!(
            std::fs::read(home.path().join("identity")).unwrap(),
            b"device identity"
        );
    });
}
