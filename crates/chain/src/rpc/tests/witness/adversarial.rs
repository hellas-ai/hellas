use super::*;
use crate::proof_verify::ProofVerifier;
use std::sync::atomic::{AtomicBool, Ordering};

macro_rules! forward_local {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {$ (
        async fn $name(&self, $($arg: $ty),*) -> Result<$out, QueryError> {
            self.local.$name($($arg),*).await
        }
    )*};
}

#[derive(Clone)]
struct ReplayLatestClient {
    local: LocalLightClient,
    old: FinalizedBlock,
    replay_old: Arc<AtomicBool>,
}

impl LightClient for ReplayLatestClient {
    async fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        if matches!(query, FinalizedBlockQuery::Latest) && self.replay_old.load(Ordering::SeqCst) {
            Ok(Some(self.old.clone()))
        } else {
            self.local.get_finalized_block(query).await
        }
    }

    forward_local! {
        get_state_root() -> Option<Digest>;
        get_proof(object_id: ObjectId) -> Option<Vec<u8>>;
        get_coin(payload: Digest, object_id: ObjectId) -> Option<crate::domain::Coin>;
        get_edge(payload: Digest, object_id: ObjectId) -> Option<crate::EdgeLookup>;
        get_finalization(payload: Digest) -> Option<Vec<u8>>;
        get_latest_block() -> Option<LatestBlock>;
        get_applied_finalized_block(query: FinalizedBlockQuery) -> Option<FinalizedBlock>;
        get_object_proofs(request: GetObjectProofsRequest) -> GetObjectProofsResponse;
        submit_tx(tx: Transaction) -> hellas_rpc::SubmitTxOutcome;
        get_validators() -> Vec<String>;
        get_consensus_info() -> ConsensusInfo;
        get_coins_by_owner(owner: SettlementKey) -> Option<crate::CoinListing>;
        get_coins_by_delegate(delegate: SettlementKey) -> Option<crate::CoinListing>;
        get_edges_by_owner(owner: SettlementKey) -> Option<crate::OwnerEdges>;
    }
}

fn request(fixture: &Fixture, owner: bool) -> GetObjectProofsRequest {
    GetObjectProofsRequest {
        object_ids: vec![fixture.old_coin.to_vec(), fixture.new_coin.to_vec()],
        payload: Some(fixture.applied.digest().to_vec()),
        owner: owner.then(|| fixture.owner.as_bytes().to_vec()),
        owner_offset: 0,
        owner_limit: if owner { 32 } else { 0 },
        owner_after_key: None,
    }
}

fn verify(
    fixture: &Fixture,
    response: GetObjectProofsResponse,
    owner: bool,
) -> Result<crate::proof_verify::VerifiedObjects, crate::proof_verify::VerificationError> {
    let keys = BTreeSet::from([fixture.old_coin, fixture.new_coin]);
    fixture.verifier.verify_objects(
        response,
        &keys,
        FinalizedBlockQuery::Payload(fixture.applied.digest()),
        owner.then_some((fixture.owner, 0, 32)),
    )
}

#[test]
fn current_witness_rejects_noncanonical_bytes_and_incomplete_key_sets() {
    run_qmdb(|runtime| async move {
        let fixture = fixture(runtime).await;
        let response = fixture
            .remote
            .get_object_proofs(request(&fixture, false))
            .await
            .unwrap();
        assert!(verify(&fixture, response.clone(), false).is_ok());

        let mut malformed = response.clone();
        malformed.proofs[0].proof.pop();
        assert!(verify(&fixture, malformed, false).is_err());

        let mut trailing = response.clone();
        trailing.proofs[0].proof.push(0);
        assert!(verify(&fixture, trailing, false).is_err());

        let mut missing = response.clone();
        missing.proofs.pop();
        assert!(verify(&fixture, missing, false).is_err());

        let mut duplicate = response.clone();
        duplicate.proofs[1] = duplicate.proofs[0].clone();
        assert!(verify(&fixture, duplicate, false).is_err());

        let mut extra = response;
        let mut unrelated = extra.proofs[0].clone();
        unrelated.object_id = vec![0xfa; 32];
        extra.proofs.push(unrelated);
        assert!(verify(&fixture, extra, false).is_err());
        fixture.server.abort();
        let _ = fixture.server.await;
        fixture.archive.abort();
        let _ = fixture.archive.await;
    });
}

#[test]
fn current_witness_rejects_cryptographically_invalid_inclusion_and_exclusion() {
    run_qmdb(|runtime| async move {
        let fixture = fixture(runtime).await;
        let response = fixture
            .remote
            .get_object_proofs(request(&fixture, false))
            .await
            .unwrap();
        assert!(verify(&fixture, response.clone(), false).is_ok());
        assert_eq!(response.proofs.len(), 2);
        assert!(response.proofs.iter().any(|entry| entry.object.is_some()));
        assert!(response.proofs.iter().any(|entry| entry.object.is_none()));
        for index in 0..response.proofs.len() {
            let mut invalid = response.clone();
            let proof = &mut invalid.proofs[index].proof;
            *proof.last_mut().unwrap() ^= 1;
            assert!(
                verify(&fixture, invalid, false).is_err(),
                "tampered Current proof at index {index} must fail"
            );
        }
        fixture.server.abort();
        let _ = fixture.server.await;
        fixture.archive.abort();
        let _ = fixture.archive.await;
    });
}

#[test]
fn current_owner_page_rejects_offset_rank_root_and_omission() {
    run_qmdb(|runtime| async move {
        let fixture = fixture(runtime).await;
        let response = fixture
            .remote
            .get_object_proofs(request(&fixture, true))
            .await
            .unwrap();
        assert!(verify(&fixture, response.clone(), true).is_ok());
        let page = response.owner_page.as_ref().unwrap().clone();
        assert!(!page.holdings.is_empty());

        let mut wrong_offset = page.clone();
        wrong_offset.offset = 1;
        let mut altered = response.clone();
        altered.owner_page = Some(wrong_offset);
        assert!(verify(&fixture, altered, true).is_err());

        let mut wrong_rank = page.clone();
        wrong_rank.holdings[0].object_id = vec![0xfa; 32];
        let mut altered = response.clone();
        altered.owner_page = Some(wrong_rank);
        assert!(verify(&fixture, altered, true).is_err());

        let mut wrong_root = page.clone();
        wrong_root.summary.as_mut().unwrap().leaf = None;
        let mut altered = response.clone();
        altered.owner_page = Some(wrong_root);
        assert!(verify(&fixture, altered, true).is_err());

        let mut omitted = page;
        omitted.holdings.pop();
        let mut altered = response;
        altered.owner_page = Some(omitted);
        assert!(verify(&fixture, altered, true).is_err());
        fixture.server.abort();
        let _ = fixture.server.await;
        fixture.archive.abort();
        let _ = fixture.archive.await;
    });
}

#[test]
fn current_witness_rejects_other_network_and_epoch_schedule() {
    run_qmdb(|runtime| async move {
        let fixture = fixture(runtime).await;
        let response = fixture
            .remote
            .get_object_proofs(request(&fixture, false))
            .await
            .unwrap();
        assert!(verify(&fixture, response.clone(), false).is_ok());

        let mut genesis: hellas_genesis::Genesis =
            serde_json::from_slice(&fixture.genesis_json).unwrap();
        let keys = BTreeSet::from([fixture.old_coin, fixture.new_coin]);
        let query = FinalizedBlockQuery::Payload(fixture.applied.digest());
        genesis.network_id = "other-network".into();
        let altered_json = serde_json::to_vec(&genesis).unwrap();
        let mut trust = fixture.trust.clone();
        trust.network_id = genesis.network_id;
        trust.genesis_sha256 = hex::encode(commonware_cryptography::Sha256::hash(&altered_json));
        let other_network = ProofVerifier::with_genesis(trust, &altered_json).unwrap();
        assert!(
            other_network
                .verify_objects(response.clone(), &keys, query, None)
                .is_err()
        );

        let mut wrong_epoch = fixture.trust.clone();
        wrong_epoch.epochs[0].epoch = 1;
        let wrong_epoch = ProofVerifier::with_genesis(wrong_epoch, &fixture.genesis_json).unwrap();
        assert!(
            wrong_epoch
                .verify_objects(response, &keys, query, None)
                .is_err()
        );
        fixture.server.abort();
        let _ = fixture.server.await;
        fixture.archive.abort();
        let _ = fixture.archive.await;
    });
}

#[test]
fn certified_latest_block_cannot_roll_back_below_a_verified_height() {
    run_qmdb(|runtime| async move {
        let fixture = fixture(runtime).await;
        let old = fixture
            .remote
            .get_finalized_block(FinalizedBlockQuery::Height(1))
            .await
            .unwrap()
            .unwrap();
        let local = LocalLightClient::new(
            fixture.database.clone(),
            fixture.owners.clone(),
            Mempool::default(),
            fixture.chain_indexer.archive.clone(),
            ConsensusInfo {
                validators: vec![],
                threshold_identity: hex::decode(&fixture.trust.epochs[0].threshold_identity)
                    .unwrap(),
                network_id: crate::domain::TEST_NETWORK.as_str().into(),
            },
        );
        let replay_old = Arc::new(AtomicBool::new(false));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let (activity, _) = tokio::sync::broadcast::channel(8);
        let server = crate::server::spawn_light_client_server(
            address,
            ReplayLatestClient {
                local,
                old,
                replay_old: replay_old.clone(),
            },
            activity,
            crate::server::LightClientRpcState::default(),
        )
        .await
        .unwrap();
        let remote =
            RemoteLightClient::connect(format!("ws://{address}"), fixture.verifier.clone())
                .await
                .unwrap();
        let newer = remote
            .get_finalized_block(FinalizedBlockQuery::Height(2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(newer.snapshot.height, 2);
        replay_old.store(true, Ordering::SeqCst);
        assert!(matches!(
            remote
                .get_finalized_block(FinalizedBlockQuery::Latest)
                .await,
            Err(QueryError::StateUnavailable(_))
        ));
        server.abort();
        let _ = server.await;
        fixture.server.abort();
        let _ = fixture.server.await;
        fixture.archive.abort();
        let _ = fixture.archive.await;
    });
}
