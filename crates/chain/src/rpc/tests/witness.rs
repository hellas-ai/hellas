use super::*;
use crate::{HellasBlock, client::RemoteLightClient};
use commonware_consensus::{
    CertifiableBlock as _, Heightable as _,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Hasher as _, Signer as _};
use hellas_rpc::pb::chain::{GetObjectProofsRequest, GetObjectProofsResponse};
use std::sync::{Arc, Mutex};

type Pending = crate::execution::finalized::Executed<commonware_runtime::tokio::Context>;

mod adversarial;

#[derive(Default)]
struct Operations {
    requests: Vec<GetObjectProofsRequest>,
    corrupt: u8,
    saved: Option<hellas_rpc::pb::chain::ObjectProof>,
    old_response: Option<GetObjectProofsResponse>,
    replay_old: bool,
    pause_second_owner_page: bool,
    owner_page_entered: Option<Arc<tokio::sync::Semaphore>>,
    owner_page_release: Option<Arc<tokio::sync::Semaphore>>,
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
    async fn get_object_proofs(
        &self,
        request: GetObjectProofsRequest,
    ) -> Result<GetObjectProofsResponse, QueryError> {
        let (corrupt, saved, old_response, replay_old, pause) = {
            let mut operations = self.operations.lock().unwrap();
            operations.requests.push(request.clone());
            (
                operations.corrupt,
                operations.saved.clone(),
                operations.old_response.clone(),
                operations.replay_old,
                if request.owner_after_key.is_some() && operations.pause_second_owner_page {
                    Some((
                        operations.owner_page_entered.as_ref().unwrap().clone(),
                        operations.owner_page_release.as_ref().unwrap().clone(),
                    ))
                } else {
                    None
                },
            )
        };
        if let Some((entered, release)) = pause {
            entered.add_permits(1);
            release.acquire().await.expect("test release").forget();
        }
        if replay_old {
            return Ok(old_response.expect("prior response"));
        }
        let mut response = self.local.get_object_proofs(request).await?;
        self.operations
            .lock()
            .unwrap()
            .old_response
            .get_or_insert_with(|| response.clone());
        if let Some(first) = response.proofs.first() {
            self.operations
                .lock()
                .unwrap()
                .saved
                .get_or_insert_with(|| first.clone());
        }
        match corrupt {
            1 => response.proofs[0].proof[1] ^= 1,
            2 => {
                response.proofs.pop();
            }
            4 => response.proofs[0] = saved.expect("prior proof"),
            6 => response.owner_page = None,
            7 => {
                let mut page = response.owner_page.as_ref().unwrap().clone();
                page.holdings.pop();
                response.owner_page = Some(page);
            }
            _ => {}
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
    chain_indexer: crate::indexer::fixtures::ArchiveSource,
    remote: RemoteLightClient,
    applied: HellasBlock,
    archived: HellasBlock,
    pending: Option<Pending>,
    old_coin: ObjectId,
    new_coin: ObjectId,
    owner: SettlementKey,
    server: tokio::task::JoinHandle<()>,
    archive: Handle<()>,
    operations: Arc<Mutex<Operations>>,
    verifier: Arc<crate::proof_verify::ProofVerifier>,
    trust: hellas_genesis::TrustDocument,
    genesis_json: Vec<u8>,
    committee: crate::execution::test_support::ConsensusFixture,
}

impl Fixture {
    async fn stop(self) {
        self.server.abort();
        let _ = self.server.await;
        self.archive.abort();
        let _ = self.archive.await;
    }
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
        crate::execution::store::sync_target(&pending),
        txs,
    )
    .with_owner_root(owner_root);
    (block, pending)
}

async fn fixture(runtime: commonware_runtime::tokio::Context) -> Fixture {
    fixture_with_allocations(runtime, 1).await
}

async fn fixture_with_allocations(
    runtime: commonware_runtime::tokio::Context,
    count: usize,
) -> Fixture {
    let genesis_doc = hellas_genesis::Genesis {
        schema_version: hellas_genesis::GENESIS_SCHEMA_VERSION,
        network_id: crate::domain::TEST_NETWORK.as_str().into(),
        validators: (91..95)
            .map(|seed| hellas_genesis::GenesisValidator {
                public_key: hex::encode(commonware_codec::Encode::encode(
                    &crate::execution::test_support::validator_key(seed).public_key(),
                )),
                label: format!("validator-{seed}"),
            })
            .collect(),
        allocations: vec![],
    };
    let genesis_json = serde_json::to_vec(&genesis_doc).unwrap();
    let genesis_digest = crate::genesis_digest(&genesis_doc);
    let committee = crate::execution::test_support::consensus_fixture_in(
        91,
        4,
        crate::domain::TEST_NETWORK,
        genesis_digest,
    );
    let trust = hellas_genesis::TrustDocument {
        schema_version: hellas_genesis::TRUST_SCHEMA_VERSION,
        network_id: genesis_doc.network_id.clone(),
        genesis_sha256: hex::encode(commonware_cryptography::Sha256::hash(&genesis_json)),
        epochs: vec![hellas_genesis::TrustEpoch {
            epoch: 0,
            start_height: 0,
            end_height: None,
            threshold_identity: hex::encode(committee.assembler.identity().encode()),
        }],
    };
    let proof_verifier = Arc::new(
        crate::proof_verify::ProofVerifier::with_genesis(trust.clone(), &genesis_json).unwrap(),
    );
    let owner = owner_key(41);
    let allocations = vec![(owner, 100); count];
    let (root, target) =
        crate::execution::store::empty_state(runtime.child("genesis"), "witness", 1024, 8).await;
    let genesis = HellasBlock::genesis(committee.leaders[0].clone(), root, target, genesis_digest);
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
        .publish_proof(applied.clone(), &finality_envelope(&committee, &applied))
        .await
        .unwrap();
    owners.apply_finalized(&applied).unwrap();
    let old_coin = genesis_object_id(0);
    let (txs, new_coin) = if count == 0 {
        (Vec::new(), ObjectId::from([0xfa; 32]))
    } else {
        let (reshape, ids) = crate::execution::test_support::reshape(
            41,
            &[old_coin],
            &[(owner, Some(owner_key(42)), 100)],
        );
        (vec![reshape], ids[0])
    };
    let (archived, pending) = prepare(&database, &allocations, &applied, &committee, txs).await;
    // Marshal has the real certificate, but Stateful has not committed this batch.
    archive
        .publish_proof(archived.clone(), &finality_envelope(&committee, &archived))
        .await
        .unwrap();
    let local = LocalLightClient::new(
        database.clone(),
        owners.clone(),
        Mempool::default(),
        archive.archive.clone(),
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
    let remote = RemoteLightClient::connect(format!("ws://{address}"), proof_verifier.clone())
        .await
        .unwrap();
    Fixture {
        database,
        owners,
        chain_indexer: archive,
        remote,
        applied,
        archived,
        pending: Some(pending),
        old_coin,
        new_coin,
        owner,
        server,
        archive: archive_task,
        operations,
        verifier: proof_verifier,
        trust,
        genesis_json,
        committee,
    }
}

#[test]
fn empty_current_database_absence_is_verified_by_hellas() {
    run_qmdb(|runtime| async move {
        let fixture = fixture_with_allocations(runtime, 0).await;
        let missing = ObjectId::from([0x42; 32]);
        let response = fixture
            .remote
            .get_object_proofs(GetObjectProofsRequest {
                object_ids: vec![missing.to_vec()],
                payload: None,
                owner: None,
                owner_limit: 0,
                owner_after_key: None,
            })
            .await
            .unwrap();
        assert!(response.proofs[0].object.is_none());
        let verified = fixture
            .verifier
            .verify_objects(
                response.clone(),
                &BTreeSet::from([missing]),
                FinalizedBlockQuery::Latest,
                None,
            )
            .unwrap();
        assert!(verified.objects().is_empty());
        let mut invalid = response;
        invalid.proofs[0].proof[0] ^= 1;
        assert!(
            fixture
                .verifier
                .verify_objects(
                    invalid,
                    &BTreeSet::from([missing]),
                    FinalizedBlockQuery::Latest,
                    None,
                )
                .is_err()
        );
        fixture.stop().await;
    });
}

#[test]
fn owner_listing_completes_across_five_verified_pages() {
    run_qmdb(|runtime| async move {
        let fixture = fixture_with_allocations(runtime, 129).await;
        let listing = fixture
            .remote
            .get_coins_by_owner(fixture.owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(listing.coins.len(), 129);
        assert_eq!(
            listing.coins.iter().map(|(_, value)| *value).sum::<u64>(),
            12_900
        );
        assert_eq!(
            fixture.operations.lock().unwrap().requests.len(),
            5,
            "129 holdings require five authenticated pages of at most 32 keys"
        );
        fixture.stop().await;
    });
}

#[test]
fn owner_cursor_pages_remain_complete_while_every_page_has_a_new_finalized_root() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture_with_allocations(runtime, 129).await;
        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        fixture.owners.apply_finalized(&fixture.archived).unwrap();
        let allocations = vec![(fixture.owner, 100); 129];
        let mut parent = fixture.archived.clone();
        let mut after = None;
        let mut ids = std::collections::BTreeSet::new();
        for index in 0..5_u64 {
            let page = fixture
                .remote
                .get_coins_by_owner_page(fixture.owner, after)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(page.snapshot.height, index + 2);
            assert_eq!(page.coins.len(), if index == 4 { 1 } else { 32 });
            for (id, value) in &page.coins {
                assert_eq!(*value, 100);
                assert!(ids.insert(*id), "cursor repeated an owner holding");
            }
            after = page.next;
            if index < 4 {
                assert!(after.is_some());
                let (next, batch) = prepare(
                    &fixture.database,
                    &allocations,
                    &parent,
                    &fixture.committee,
                    vec![],
                )
                .await;
                fixture.database.finalize(batch).await;
                fixture
                    .chain_indexer
                    .publish_proof(next.clone(), &finality_envelope(&fixture.committee, &next))
                    .await
                    .unwrap();
                fixture.owners.apply_finalized(&next).unwrap();
                parent = next;
            } else {
                assert!(after.is_none());
            }
        }
        assert_eq!(ids.len(), 129);
        fixture.stop().await;
    });
}

#[test]
fn current_proofs_bind_inclusion_absence_and_requested_root() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        let keys = vec![fixture.old_coin, fixture.new_coin];
        let first = fixture
            .remote
            .get_objects(keys.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.block.payload, fixture.applied.digest());
        assert!(first.objects.contains_key(&fixture.old_coin));
        assert!(!first.objects.contains_key(&fixture.new_coin));
        let request = fixture.operations.lock().unwrap().requests[0].clone();
        assert_eq!(request.object_ids.len(), 2);
        assert!(request.payload.is_none());
        let _ = fixture.remote.get_object_proofs(request).await.unwrap();
        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        fixture.operations.lock().unwrap().corrupt = 1;
        assert!(
            fixture.remote.get_objects(keys.clone()).await.is_err(),
            "invalid newer proof"
        );
        fixture.operations.lock().unwrap().corrupt = 0;
        fixture.operations.lock().unwrap().replay_old = true;
        let still_old = fixture
            .remote
            .get_objects(keys.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            still_old.block.payload,
            fixture.applied.digest(),
            "a failed newer proof must leave the applied progress floor unchanged"
        );
        fixture.operations.lock().unwrap().replay_old = false;
        let second = fixture
            .remote
            .get_objects(keys.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.block.payload, fixture.archived.digest());
        assert!(!second.objects.contains_key(&fixture.old_coin));
        assert!(second.objects.contains_key(&fixture.new_coin));
        fixture.operations.lock().unwrap().replay_old = true;
        assert!(
            matches!(
                fixture.remote.get_objects(keys.clone()).await,
                Err(QueryError::StateUnavailable(_))
            ),
            "a genuine certified older latest response must not lower the applied floor"
        );
        fixture.operations.lock().unwrap().replay_old = false;
        assert!(matches!(
            fixture
                .remote
                .get_objects_at(keys.clone(), fixture.applied.digest())
                .await,
            Err(QueryError::StateUnavailable(_))
        ));
        let pinned = fixture
            .remote
            .get_objects_at(keys, fixture.archived.digest())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pinned.block.payload, fixture.archived.digest());
        fixture.stop().await;
    });
}

#[test]
fn old_current_proof_cannot_authenticate_a_new_root() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        let key = fixture.old_coin;
        assert!(
            fixture
                .remote
                .get_objects(vec![key])
                .await
                .unwrap()
                .unwrap()
                .objects
                .contains_key(&key)
        );
        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        fixture.operations.lock().unwrap().corrupt = 4;
        assert!(
            fixture.remote.get_objects(vec![key]).await.is_err(),
            "old proof cannot authenticate new root"
        );
        fixture.operations.lock().unwrap().corrupt = 0;
        assert!(
            !fixture
                .remote
                .get_objects(vec![key])
                .await
                .unwrap()
                .unwrap()
                .objects
                .contains_key(&key)
        );
        fixture.stop().await;
    });
}

#[test]
fn remote_point_reads_use_a_finalized_floor_after_the_current_root_advances() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        let floor = fixture.applied.digest();
        let newer = fixture.archived.digest();
        let edge_id = crate::domain::edge_object_id(hellas_kernel::EdgeId::from_bytes([0x77; 32]));

        assert!(matches!(
            fixture.remote.get_coin(newer, fixture.new_coin).await,
            Err(QueryError::StateUnavailable(_))
        ));
        assert_eq!(
            fixture
                .remote
                .get_coin(floor, fixture.old_coin)
                .await
                .unwrap()
                .unwrap()
                .value,
            100
        );

        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        let coin = fixture
            .remote
            .get_coin(floor, fixture.new_coin)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(coin.value, 100, "H1 is a floor for a coin proved at H2");
        let edge = fixture
            .remote
            .get_edge(floor, edge_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(edge.state_root, fixture.archived.state_root());
        assert!(edge.edge.is_none(), "edge absence is proved at the H2 root");
        assert!(matches!(
            fixture
                .remote
                .get_objects_at(vec![fixture.new_coin], floor)
                .await,
            Err(QueryError::StateUnavailable(_))
        ));

        fixture.stop().await;
    });
}

#[test]
fn owner_page_and_coin_proofs_share_one_root_and_reject_omission() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        let owner = fixture.owner;
        let first = fixture
            .remote
            .get_coins_by_owner(owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.snapshot.payload, fixture.applied.digest());
        assert_eq!(first.coins, vec![(fixture.old_coin, 100)]);
        let edges = fixture
            .remote
            .get_edges_by_owner(owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(edges.snapshot.payload, first.snapshot.payload);
        assert!(edges.edges.is_empty());
        for mode in [2, 6, 7] {
            fixture.operations.lock().unwrap().corrupt = mode;
            assert!(
                fixture.remote.get_coins_by_owner(owner).await.is_err(),
                "owner proof mutation {mode}"
            );
            assert!(
                fixture.remote.get_edges_by_owner(owner).await.is_err(),
                "edge owner proof mutation {mode}"
            );
        }
        fixture.operations.lock().unwrap().corrupt = 0;
        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        let second = fixture
            .remote
            .get_coins_by_owner(owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.snapshot.payload, fixture.archived.digest());
        assert_eq!(second.coins, vec![(fixture.new_coin, 100)]);
        let delegate = owner_key(42);
        let delegated = fixture
            .remote
            .get_coins_by_delegate(delegate)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delegated.snapshot.payload, fixture.archived.digest());
        assert_eq!(delegated.coins, vec![(fixture.new_coin, 100)]);
        fixture.stop().await;
    });
}

#[test]
fn self_delegated_coin_is_listed_once_for_owner_and_delegate() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        fixture.owners.apply_finalized(&fixture.archived).unwrap();
        let (reshape, ids) = crate::execution::test_support::reshape(
            41,
            &[fixture.new_coin],
            &[(fixture.owner, Some(fixture.owner), 100)],
        );
        let (block, batch) = prepare(
            &fixture.database,
            &[(fixture.owner, 100)],
            &fixture.archived,
            &fixture.committee,
            vec![reshape],
        )
        .await;
        fixture.database.finalize(batch).await;
        fixture
            .chain_indexer
            .publish_proof(
                block.clone(),
                &finality_envelope(&fixture.committee, &block),
            )
            .await
            .unwrap();
        fixture.owners.apply_finalized(&block).unwrap();
        let owned = fixture
            .remote
            .get_coins_by_owner(fixture.owner)
            .await
            .unwrap()
            .unwrap();
        let delegated = fixture
            .remote
            .get_coins_by_delegate(fixture.owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owned.coins, vec![(ids[0], 100)]);
        assert_eq!(delegated.coins, vec![(ids[0], 100)]);
        fixture.stop().await;
    });
}

#[test]
fn human_owner_listing_reports_changed_root_between_verified_pages() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture_with_allocations(runtime, 33).await;
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        {
            let mut operations = fixture.operations.lock().unwrap();
            operations.pause_second_owner_page = true;
            operations.owner_page_entered = Some(entered.clone());
            operations.owner_page_release = Some(release.clone());
        }
        let remote = fixture.remote.clone();
        let owner = fixture.owner;
        let listing = tokio::spawn(async move { remote.get_coins_by_owner(owner).await });
        entered.acquire().await.unwrap().forget();
        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        fixture.owners.apply_finalized(&fixture.archived).unwrap();
        fixture.operations.lock().unwrap().pause_second_owner_page = false;
        release.add_permits(1);
        assert!(matches!(
            listing.await.unwrap(),
            Err(QueryError::StateUnavailable(_))
        ));
        let first_page_requests = {
            let operations = fixture.operations.lock().unwrap();
            operations
                .requests
                .iter()
                .filter(|request| request.owner_after_key.is_none())
                .count()
        };
        assert_eq!(
            first_page_requests, 1,
            "human listing does not restart old roots"
        );
        fixture.stop().await;
    });
}
