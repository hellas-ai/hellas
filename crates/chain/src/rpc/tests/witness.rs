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
        let (corrupt, saved, old_response, replay_old) = {
            let mut operations = self.operations.lock().unwrap();
            operations.requests.push(request.clone());
            (
                operations.corrupt,
                operations.saved.clone(),
                operations.old_response.clone(),
                operations.replay_old,
            )
        };
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

    /// `replay_old` also answers `Latest` with the block of the first proof response.
    async fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        let old = {
            let operations = self.operations.lock().unwrap();
            (operations.replay_old && matches!(query, FinalizedBlockQuery::Latest))
                .then(|| operations.old_response.clone().expect("prior response"))
        };
        match old {
            Some(old) => old
                .block
                .map(crate::client::finalized_block_from_proto)
                .transpose(),
            None => self.local.get_finalized_block(query).await,
        }
    }

    forward! {
        get_state_root() -> Option<Digest>;
        get_proof(object_id: ObjectId) -> Option<Vec<u8>>;
        get_plain_objects(request: GetObjectProofsRequest) -> hellas_rpc::pb::chain::GetObjectsResponse;
        get_finalization(payload: Digest) -> Option<Vec<u8>>;
        get_latest_block() -> Option<LatestBlock>;
        get_applied_finalized_block(query: FinalizedBlockQuery) -> Option<FinalizedBlock>;
        submit_tx(tx: Transaction) -> hellas_rpc::SubmitTxOutcome;
        get_validators() -> Vec<String>;
        get_consensus_info() -> ConsensusInfo;
    }
}

struct Fixture {
    database: UtxoDatabase<commonware_runtime::tokio::Context>,
    owners: OwnerIndex,
    chain_indexer: crate::indexer::fixtures::ArchiveSource,
    remote: RemoteLightClient,
    trusted: crate::client::TrustedReader,
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
    let proof_verifier =
        Arc::new(crate::proof_verify::ProofVerifier::with_genesis(trust, &genesis_json).unwrap());
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
    let trusted = crate::client::TrustedReader::connect(
        format!("ws://{address}"),
        crate::domain::TEST_NETWORK,
    )
    .await
    .unwrap();
    Fixture {
        database,
        owners,
        chain_indexer: archive,
        remote,
        trusted,
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
        assert!(verified.objects.is_empty());
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

/// Every page of `owner`'s holdings, each verified at its own root.
async fn pages(remote: &RemoteLightClient, owner: SettlementKey) -> Vec<crate::ObjectSnapshot> {
    let mut pages = Vec::new();
    let mut after = None;
    loop {
        let page = remote
            .get_holdings(owner, after)
            .await
            .unwrap()
            .unwrap()
            .into_inner();
        after = page.holdings.as_ref().unwrap().next;
        pages.push(page);
        if after.is_none() {
            return pages;
        }
    }
}

fn values(coins: Vec<(ObjectId, crate::domain::Coin)>) -> Vec<(ObjectId, u64)> {
    coins
        .into_iter()
        .map(|(id, coin)| (id, coin.value))
        .collect()
}

#[test]
fn owner_listing_completes_across_five_verified_pages() {
    run_qmdb(|runtime| async move {
        let fixture = fixture_with_allocations(runtime, 129).await;
        let coins: Vec<_> = pages(&fixture.remote, fixture.owner)
            .await
            .iter()
            .flat_map(|page| values(page.owned_coins(fixture.owner)))
            .collect();
        assert_eq!(coins.len(), 129);
        assert_eq!(coins.iter().map(|(_, value)| *value).sum::<u64>(), 12_900);
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
                .get_holdings(fixture.owner, after)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(page.block.height, index + 2);
            let coins = values(page.owned_coins(fixture.owner));
            assert_eq!(coins.len(), if index == 4 { 1 } else { 32 });
            for (id, value) in &coins {
                assert_eq!(*value, 100);
                assert!(ids.insert(*id), "cursor repeated an owner holding");
            }
            after = page.holdings.as_ref().unwrap().next;
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
        fixture.stop().await;
    });
}

#[test]
fn certified_finalized_block_cannot_roll_back_below_a_verified_height() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        let keys = vec![fixture.old_coin];
        let first = fixture.remote.get_objects(keys).await.unwrap().unwrap();
        assert_eq!(first.block.payload, fixture.applied.digest());
        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        let newer = fixture
            .remote
            .get_finalized_block(FinalizedBlockQuery::Latest)
            .await
            .unwrap()
            .unwrap();
        assert!(newer.snapshot.height > first.block.height);
        fixture.operations.lock().unwrap().replay_old = true;
        assert!(matches!(
            fixture
                .remote
                .get_finalized_block(FinalizedBlockQuery::Latest)
                .await,
            Err(QueryError::StateUnavailable(_))
        ));
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
fn owner_page_and_coin_proofs_share_one_root_and_reject_omission() {
    run_qmdb(|runtime| async move {
        let mut fixture = fixture(runtime).await;
        let owner = fixture.owner;
        let first = fixture
            .remote
            .get_holdings(owner, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.block.payload, fixture.applied.digest());
        assert_eq!(
            values(first.owned_coins(owner)),
            vec![(fixture.old_coin, 100)]
        );
        assert!(first.edges().is_empty());
        for mode in [2, 6, 7] {
            fixture.operations.lock().unwrap().corrupt = mode;
            assert!(
                fixture.remote.get_holdings(owner, None).await.is_err(),
                "owner proof mutation {mode}"
            );
        }
        fixture.operations.lock().unwrap().corrupt = 0;
        fixture
            .database
            .finalize(fixture.pending.take().unwrap())
            .await;
        let second = fixture
            .remote
            .get_holdings(owner, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.block.payload, fixture.archived.digest());
        assert_eq!(
            values(second.owned_coins(owner)),
            vec![(fixture.new_coin, 100)]
        );
        let delegate = owner_key(42);
        let delegated = fixture
            .remote
            .get_holdings(delegate, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delegated.block.payload, fixture.archived.digest());
        assert_eq!(
            values(delegated.delegated_coins(delegate)),
            vec![(fixture.new_coin, 100)]
        );
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
        let page = fixture
            .remote
            .get_holdings(fixture.owner, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(values(page.owned_coins(fixture.owner)), vec![(ids[0], 100)]);
        assert_eq!(
            values(page.delegated_coins(fixture.owner)),
            vec![(ids[0], 100)]
        );
        fixture.stop().await;
    });
}

#[test]
fn trusted_reads_answer_the_proven_read_without_proofs() {
    run_qmdb(|runtime| async move {
        let fixture = fixture_with_allocations(runtime, 33).await;
        let keys = vec![fixture.old_coin, fixture.new_coin];
        let proven = fixture
            .remote
            .get_objects(keys.clone())
            .await
            .unwrap()
            .unwrap();
        let plain = fixture.trusted.get_objects(keys).await.unwrap().unwrap();
        assert_eq!(plain.block, proven.block);
        assert_eq!(plain.objects, proven.objects);
        assert!(plain.holdings.is_none());

        let proven = fixture
            .remote
            .get_holdings(fixture.owner, None)
            .await
            .unwrap()
            .unwrap();
        let plain = fixture
            .trusted
            .get_holdings(fixture.owner, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plain.holdings, proven.holdings);
        assert_eq!(plain.owned_coins(fixture.owner).len(), 32);
        assert_eq!(
            plain.owned_coins(fixture.owner),
            proven.owned_coins(fixture.owner)
        );
        let after = plain.holdings.as_ref().unwrap().next;
        let rest = fixture
            .trusted
            .get_holdings(fixture.owner, after)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rest.owned_coins(fixture.owner).len(), 1);
        assert_eq!(rest.holdings.as_ref().unwrap().next, None);
        fixture.stop().await;
    });
}
