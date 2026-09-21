use super::*;
use crate::{
    domain::{self, Transaction},
    edge_index::{projection::EdgeIndexClient, types::*},
    execution::test_support::{ConsensusFixture, consensus_fixture, finalization, run_qmdb},
    verified_explorer::PROOF_SCHEMA_VERSION,
};
use commonware_codec::Encode as _;
use commonware_consensus::{
    CertifiableBlock as _,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{Supervisor as _, tokio};
use commonware_storage::{mmr::Location, qmdb::sync::Target};
use commonware_utils::non_empty_range;
use hellas_genesis::{
    Genesis, GenesisAllocation, GenesisValidator, HELLAS_DEVNET_1_ID, TrustDocument, TrustEpoch,
};
use hellas_kernel::{
    Auth, BlockHeight, CoinId, Funding, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties, Payout,
    ProtocolCode, Secp256k1Signer, Terms, Tx,
};

pub(crate) struct Harness {
    pub(crate) producer: UtxoDatabase<tokio::Context>,
    pub(crate) replay: Replay<tokio::Context>,
    pub(crate) index: EdgeIndex,
    pub(crate) head: HellasBlock,
    pub(crate) committee: ConsensusFixture,
    pub(crate) verifier: ExplorerVerifier,
    pub(crate) client: EdgeIndexClient,
    pub(crate) allocations: Vec<(SettlementKey, u64)>,
    pub(crate) network: hellas_kernel::NetworkId,
    pub(crate) name: &'static str,
    pub(crate) directory: tempfile::TempDir,
    pub(crate) genesis_json: Vec<u8>,
    pub(crate) trust: TrustDocument,
}
impl Harness {
    pub(crate) async fn new(
        runtime: tokio::Context,
        allocations: Vec<(SettlementKey, u64)>,
        name: &'static str,
    ) -> Self {
        let network = hellas_kernel::NetworkId::new(HELLAS_DEVNET_1_ID).unwrap();
        let committee = consensus_fixture(7191);
        let mut genesis = Genesis {
            schema_version: 1,
            network_id: HELLAS_DEVNET_1_ID.into(),
            validators: committee
                .leaders
                .iter()
                .enumerate()
                .map(|(i, key)| GenesisValidator {
                    public_key: hex::encode(key.encode()),
                    label: format!("validator-{i}"),
                })
                .collect(),
            allocations: allocations
                .iter()
                .map(|(key, value)| GenesisAllocation {
                    address: key.to_string(),
                    balance: *value,
                })
                .collect(),
        };
        // JSON ordering is not the committee's canonical ordering. Keep this
        // deliberately reversed so origin replay cannot rely on its first entry.
        genesis
            .validators
            .sort_by(|a, b| b.public_key.cmp(&a.public_key));
        let genesis_json = serde_json::to_vec(&genesis).unwrap();
        let trust = TrustDocument {
            schema_version: 1,
            network_id: HELLAS_DEVNET_1_ID.into(),
            genesis_sha256: hex::encode(Sha256::hash(&genesis_json)),
            epochs: vec![TrustEpoch {
                epoch: 0,
                start_height: 0,
                end_height: None,
                threshold_identity: hex::encode(committee.assembler.identity().encode()),
            }],
        };
        let verifier = ExplorerVerifier::with_genesis(trust.clone(), &genesis_json).unwrap();
        let client = EdgeIndexClient::with_genesis(trust.clone(), &genesis_json).unwrap();
        let (root, target) = crate::execution::store::empty_state(
            runtime.child("genesis"),
            "edge-test-genesis",
            1024,
            8,
        )
        .await;
        let leader = committee.leaders.iter().min().unwrap().clone();
        let head = HellasBlock::genesis(leader, root, target.clone());
        let origin_genesis = HellasBlock::genesis(
            crate::explorer_origin::genesis_leader(&genesis).unwrap(),
            root,
            target,
        );
        let directory = tempfile::tempdir().unwrap();
        let index = EdgeIndex::open(
            &directory.path().join("index.redb"),
            HELLAS_DEVNET_1_ID.into(),
            trust.genesis_sha256.clone(),
            verifier.trust_sha256().into(),
        )
        .unwrap();
        let replay = Replay::new(
            runtime.child("replay"),
            "edge-test",
            index.clone(),
            network,
            allocations.clone(),
            origin_genesis,
            &verifier,
        )
        .await
        .unwrap();
        let producer = <UtxoDatabase<_> as DatabaseSet<_>>::init(
            runtime.child("producer"),
            utxo_db_config(&runtime, "edge-producer", 1024, 8),
        )
        .await;
        Self {
            producer,
            replay,
            index,
            head,
            committee,
            verifier,
            client,
            allocations,
            network,
            name,
            directory,
            genesis_json,
            trust,
        }
    }
    async fn candidate(
        &self,
        txs: Vec<Transaction>,
    ) -> (
        HellasBlock,
        ProofBundle,
        <UtxoDatabase<tokio::Context> as DatabaseSet<tokio::Context>>::Merkleized,
    ) {
        let height = self.head.height().get() + 1;
        let context = hellas_kernel::Context::with_fees(
            self.network,
            BlockHeight::new(height),
            hellas_kernel::BlockHash::from_bytes(self.head.digest().0),
            domain::KERNEL_FEES,
        );
        let batch = crate::execution::execute_all(
            context,
            &ChainVerifier::new(),
            &txs,
            &self.allocations,
            self.producer.new_batches().await,
        )
        .await
        .unwrap();
        let owner_root = crate::execution::owner_tree::root(&batch).await.unwrap();
        let merkleized = batch.merkleize().await.unwrap();
        let bounds = merkleized.bounds();
        let target = Target {
            root: merkleized.root(),
            range: non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size)),
        };
        let block = HellasBlock::new(
            Context {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: self.committee.leaders[0].clone(),
                parent: (self.head.context().round.view(), self.head.digest()),
            },
            self.head.digest(),
            Height::new(height),
            height,
            merkleized.root(),
            target,
            txs,
        )
        .with_owner_root(owner_root);
        let proof = self.certify(&block);
        self.verifier
            .verify(
                proof.clone(),
                ExplorerQuery::Block(FinalizedBlockQuery::Height(height)),
            )
            .unwrap();
        (block, proof, merkleized)
    }
    fn certify(&self, block: &HellasBlock) -> ProofBundle {
        ProofBundle {
            schema_version: PROOF_SCHEMA_VERSION,
            network_id: HELLAS_DEVNET_1_ID.into(),
            trust_sha256: self.verifier.trust_sha256().into(),
            height: block.height().get(),
            payload: hex::encode(block.digest()),
            state_root: hex::encode(block.state_root()),
            finalization: finalization(&self.committee, block).encode().to_vec(),
            canonical_block: block.encode().to_vec(),
            observed_at_ms: block.height().get(),
            epoch: 0,
        }
    }
    async fn apply(&mut self, block: &HellasBlock, proof: ProofBundle) -> Result<()> {
        let verified = self.verifier.verify(
            proof,
            ExplorerQuery::Block(FinalizedBlockQuery::Height(block.height().get())),
        )?;
        self.replay.apply(block, verified).await
    }
    pub(crate) async fn append(&mut self, txs: Vec<Transaction>) -> ProofBundle {
        let (block, proof, merkleized) = self.candidate(txs).await;
        self.producer.finalize(merkleized).await;
        self.apply(&block, proof.clone()).await.unwrap();
        self.head = block;
        proof
    }
    fn list(&self, limit: u32) -> ListEdgesResponse {
        self.index
            .list_edges(ListEdgesRequest {
                schema_version: crate::edge_index::SCHEMA_VERSION,
                limit: Some(limit),
                ..Default::default()
            })
            .unwrap()
    }
    fn detail(&self, id: hellas_kernel::EdgeId, payload: Option<String>) -> GetEdgeDetailResponse {
        self.index
            .get_edge_detail(GetEdgeDetailRequest {
                schema_version: crate::edge_index::SCHEMA_VERSION,
                edge_id: hex::encode(id.as_bytes()),
                payload,
            })
            .unwrap()
    }
    fn export<T: serde::Serialize + prost::Message>(&self, name: &str, value: &T) {
        if let Ok(directory) = std::env::var("HELLAS_EDGE_FIXTURE_DIR") {
            let directory = std::path::PathBuf::from(directory).join(self.name);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("genesis.json"), &self.genesis_json).unwrap();
            std::fs::write(
                directory.join("trust.json"),
                serde_json::to_vec(&self.trust).unwrap(),
            )
            .unwrap();
            std::fs::write(
                directory.join(format!("{name}.json")),
                serde_json::to_vec_pretty(value).unwrap(),
            )
            .unwrap();
            std::fs::write(directory.join(format!("{name}.pb")), value.encode_to_vec()).unwrap();
            let json = serde_json::to_value(value).unwrap();
            let data = &json["data"];
            let payload = json["snapshot"]["payload"].as_str().unwrap();
            let (kind, path, edge_id) = if let Some(id) =
                data["payment"]["summary"]["edge_id"].as_str()
            {
                (
                    "channel",
                    format!("/api/v1/channels/{id}"),
                    Some(id.to_string()),
                )
            } else if let Some(id) = data["summary"]["edge_id"].as_str() {
                ("edge", format!("/api/v1/edges/{id}"), Some(id.to_string()))
            } else if data["items"][0].get("transaction").is_some() {
                use base64ct::{Base64, Encoding};
                let bytes =
                    Base64::decode_vec(data["items"][0]["canonical_transaction"].as_str().unwrap())
                        .unwrap();
                let Transaction::Kernel(tx) = Transaction::decode(bytes.as_slice()).unwrap() else {
                    panic!()
                };
                let id = match tx {
                    Tx::Open { funding, terms, .. } => Tx::edge_id_of(&funding, &terms),
                    Tx::Close { input, .. } => input,
                    Tx::Move { action } => match action {
                        hellas_kernel::Move::StartPaymentClose(start) => start.payment_edge(),
                        hellas_kernel::Move::RespondPaymentClose(response) => {
                            response.payment_edge()
                        }
                    },
                };
                let id = hex::encode(id.as_bytes());
                ("events", format!("/api/v1/edges/{id}/events"), Some(id))
            } else {
                ("list", "/api/v1/edges".into(), None)
            };
            let manifest_path = directory.join("manifest.json");
            let mut entries: Vec<serde_json::Value> = std::fs::read(&manifest_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
            entries.retain(|entry| entry["name"].as_str() != Some(name));
            entries.push(serde_json::json!({"name":name,"kind":kind,"api_path":path,"payload":payload,"height":json["snapshot"]["height"],"edge_id":edge_id,"json":format!("{name}.json"),"protobuf":format!("{name}.pb")}));
            std::fs::write(manifest_path, serde_json::to_vec_pretty(&entries).unwrap()).unwrap();
        }
    }
}

#[test]
fn native_edge_index_unsorted_committee_genesis_matches_validator() {
    run_qmdb(|runtime| async move {
        let mut harness = Harness::new(runtime, Vec::new(), "unsorted-genesis").await;
        let genesis: Genesis = serde_json::from_slice(&harness.genesis_json).unwrap();
        assert!(genesis.validators.len() > 1);
        assert_ne!(
            genesis.validators[0].public_key,
            hex::encode(harness.head.context().leader.encode()),
        );
        let proof = harness.append(Vec::new()).await;
        assert_eq!(proof.height, 1);
        assert_eq!(harness.list(2).envelope.snapshot.height, 1);
    });
}
fn signer(secret: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([secret; 32]).unwrap()
}
fn funding(index: u16) -> Funding {
    Funding::new(
        List::take(
            [CoinId::from_bytes(domain::genesis_object_id(index).0); MAX_PARTY_INPUTS],
            1,
        ),
        List::take([CoinId::from_bytes([0; 32]); MAX_PARTY_INPUTS], 0),
    )
}
fn open(
    network: hellas_kernel::NetworkId,
    funding: Funding,
    terms: Terms,
    maker: &Secp256k1Signer,
    taker: &Secp256k1Signer,
) -> Tx {
    let hash = Tx::open_hash(network, &funding, &terms);
    Tx::open(
        funding,
        terms,
        Auth::native(maker.sign(hash)),
        Auth::native(taker.sign(hash)),
    )
}
pub(crate) fn basic(
    network: hellas_kernel::NetworkId,
    index: u16,
    maker: &Secp256k1Signer,
    taker: &Secp256k1Signer,
) -> (hellas_kernel::EdgeId, Terms, Tx) {
    let terms = Terms::basic(
        ProtocolCode::new(7),
        Parties::new(maker.party_key(), taker.party_key()),
        BlockHeight::new(2),
        List::take([Payout::new(maker.party_key(), 100); MAX_EDGE_OUTPUTS], 1),
    );
    let funding = funding(index);
    let id = Tx::edge_id_of(&funding, &terms);
    let tx = open(network, funding, terms.clone(), maker, taker);
    (id, terms, tx)
}
#[test]
fn native_edge_index_real_chain_pins_root_checks_and_restart() {
    run_qmdb(|runtime| async move {
        let maker = signer(19);
        let taker = signer(20);
        let maker2 = signer(21);
        let maker3 = signer(22);
        let allocations = vec![
            (SettlementKey::from(maker.party_key()), 100),
            (SettlementKey::from(maker2.party_key()), 100),
            (SettlementKey::from(maker3.party_key()), 100),
        ];
        let mut h = Harness::new(runtime.child("h"), allocations, "basic").await;
        assert_eq!(
            h.index
                .list_edges(ListEdgesRequest {
                    schema_version: crate::edge_index::SCHEMA_VERSION,
                    ..Default::default()
                })
                .unwrap_err()
                .code,
            "index_not_ready"
        );
        let (id, terms, tx) = basic(h.network, 0, &maker, &taker);
        let (id2, terms2, tx2) = basic(h.network, 1, &maker2, &maker2);
        let (_, _, tx3) = basic(h.network, 2, &maker3, &taker);
        let opened = h
            .append(vec![
                Transaction::Kernel(tx),
                Transaction::Kernel(tx2),
                Transaction::Kernel(tx3),
            ])
            .await;
        let first = h.list(1);
        h.client.check_list(&first).unwrap();
        h.export("edges", &first);
        let cursor = first.data.next_cursor.clone().unwrap();
        let detail = h.detail(id, None);
        h.client.check_edge(&detail).unwrap();
        h.export("edge", &detail);
        let mut wrong = detail.clone();
        wrong.data.opening.transaction.transaction_index = 12;
        assert!(h.client.check_edge(&wrong).is_err());
        if let Some(ObjectState::Present(object)) = &mut wrong.data.object_at_snapshot.answer {
            object.decoded.value += 1;
        }
        assert!(h.client.check_edge(&wrong).is_err());
        let (_, root_bad, _) = h.candidate(Vec::new()).await;
        let mut bad = root_bad.clone();
        bad.state_root = "00".repeat(32);
        let block = HellasBlock::decode(root_bad.canonical_block.as_slice()).unwrap();
        assert!(h.apply(&block, bad).await.is_err());
        // Typed evidence is valid but must certify the block replay will execute.
        let other = h
            .verifier
            .verify(
                opened.clone(),
                ExplorerQuery::Block(FinalizedBlockQuery::Height(1)),
            )
            .unwrap();
        assert!(h.replay.apply(&block, other).await.is_err());
        // A typed block from another valid verifier is not this origin's trust anchor.
        let mut other_trust = h.trust.clone();
        other_trust.epochs[0].end_height = Some(100);
        let other_verifier = ExplorerVerifier::with_genesis(other_trust, &h.genesis_json).unwrap();
        let mut other_proof = root_bad.clone();
        other_proof.trust_sha256 = other_verifier.trust_sha256().into();
        let other = other_verifier
            .verify(
                other_proof,
                ExplorerQuery::Block(FinalizedBlockQuery::Height(2)),
            )
            .unwrap();
        assert!(h.replay.apply(&block, other).await.is_err());
        assert_eq!(h.list(64).envelope.snapshot.height, 1);
        // Even a valid threshold certificate cannot bypass deterministic state replay.
        let mut target = block.sync_target();
        target.root = Digest::from([91; 32]);
        let invalid = HellasBlock::new(
            block.context(),
            block.parent(),
            block.height(),
            block.timestamp(),
            target.root,
            target,
            block.txs().to_vec(),
        )
        .with_owner_root(block.owner_root());
        let certificate = h.certify(&invalid);
        h.verifier
            .verify(
                certificate.clone(),
                ExplorerQuery::Block(FinalizedBlockQuery::Height(2)),
            )
            .unwrap();
        assert!(h.apply(&invalid, certificate).await.is_err());
        let conflicting_parent = HellasBlock::new(
            block.context(),
            Digest::from([92; 32]),
            block.height(),
            block.timestamp(),
            block.state_root(),
            block.sync_target(),
            block.txs().to_vec(),
        )
        .with_owner_root(block.owner_root());
        assert!(
            h.apply(&conflicting_parent, h.certify(&conflicting_parent))
                .await
                .is_err()
        );
        let gap = HellasBlock::new(
            block.context(),
            block.parent(),
            Height::new(3),
            block.timestamp(),
            block.state_root(),
            block.sync_target(),
            block.txs().to_vec(),
        )
        .with_owner_root(block.owner_root());
        assert!(h.apply(&gap, h.certify(&gap)).await.is_err());
        let mut conflict = opened.clone();
        conflict.payload = "fe".repeat(32);
        assert!(h.apply(&h.head.clone(), conflict).await.is_err());
        assert_eq!(h.list(64).envelope.snapshot.height, 1);

        // A single in-flight read remains coherent while a new state is published.
        let in_flight = h.index.store.read(Some(&opened.payload)).unwrap();
        let next = h
            .index
            .list_edges(ListEdgesRequest {
                schema_version: SCHEMA_VERSION,
                cursor: Some(cursor.clone()),
                limit: Some(2),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(next.data.items.len(), 2);
        assert!(next.data.next_cursor.is_none());
        let closed = h
            .append(vec![Transaction::Kernel(
                Tx::timeout_close(id, &terms).unwrap(),
            )])
            .await;
        let stale = h
            .index
            .get_edge_detail(GetEdgeDetailRequest {
                schema_version: SCHEMA_VERSION,
                edge_id: hex::encode(id.as_bytes()),
                payload: Some(opened.payload.clone()),
            })
            .unwrap_err();
        assert_eq!((stale.status, stale.code), (409, "snapshot_unavailable"));
        assert_eq!(stale.snapshot.unwrap().snapshot.payload, closed.payload);
        let live = h.detail(id, None);
        assert_eq!(live.data.summary.lifecycle, "closed");
        h.client.check_edge(&live).unwrap();
        h.export("closed-edge", &live);
        let stale = h
            .index
            .list_edges(ListEdgesRequest {
                schema_version: SCHEMA_VERSION,
                cursor: Some(cursor.clone()),
                limit: Some(2),
                ..Default::default()
            })
            .unwrap_err();
        assert_eq!((stale.status, stale.code), (409, "snapshot_unavailable"));
        assert!(
            h.index
                .list_edges(ListEdgesRequest {
                    schema_version: crate::edge_index::SCHEMA_VERSION,
                    cursor: Some(cursor),
                    state: Some("closed".into()),
                    ..Default::default()
                })
                .is_err()
        );
        let events = h
            .index
            .list_edge_events(ListEdgeEventsRequest {
                schema_version: crate::edge_index::SCHEMA_VERSION,
                edge_id: hex::encode(id.as_bytes()),
                limit: Some(1),
                ..Default::default()
            })
            .unwrap();
        h.client
            .check_events(&events, &hex::encode(id.as_bytes()))
            .unwrap();
        assert!(events.data.next_cursor.is_some());
        h.export("events", &events);
        h.apply(&h.head.clone(), closed).await.unwrap();
        assert_eq!(h.list(64).data.items.len(), 2);
        for _ in 0..2 {
            h.append(Vec::new()).await;
        }
        assert_eq!(
            h.index
                .get_edge_detail(GetEdgeDetailRequest {
                    schema_version: crate::edge_index::SCHEMA_VERSION,
                    edge_id: hex::encode(id.as_bytes()),
                    payload: Some(opened.payload)
                })
                .unwrap_err()
                .code,
            "snapshot_unavailable"
        );
        assert!(in_flight.object(id.as_bytes()).unwrap().is_some());
        assert_eq!(
            h.index
                .get_edge_detail(GetEdgeDetailRequest {
                    schema_version: crate::edge_index::SCHEMA_VERSION,
                    edge_id: hex::encode(id.as_bytes()),
                    payload: Some("ff".repeat(32))
                })
                .unwrap_err()
                .code,
            "snapshot_unavailable"
        );
        let index_path = h.directory.path().join("index.redb");
        assert!(index_path.exists());
        let owner = SettlementKey::from(maker2.party_key());
        let committed_owner = h
            .replay
            .owner_proof(owner, 0, 64, None)
            .await
            .unwrap()
            .unwrap();
        // Crash after writing the intent, before QMDB finalize: recovery discards it.
        let transactions = vec![Transaction::Kernel(
            Tx::timeout_close(id2, &terms2).unwrap(),
        )];
        let (_, proof, _) = h.candidate(transactions.clone()).await;
        let tx_digest = hex::encode(crate::verified_explorer::transaction_digest(
            &transactions[0],
        ));
        let context = hellas_kernel::Context::with_fees(
            h.network,
            BlockHeight::new(proof.height),
            hellas_kernel::BlockHash::from_bytes(h.head.digest().0),
            domain::KERNEL_FEES,
        );
        let (_, changes) = execute_all_observed(
            context,
            &ChainVerifier::new(),
            &transactions,
            &h.allocations,
            h.replay.database.new_batches().await,
        )
        .await
        .unwrap();
        assert!(!changes.is_empty());
        h.index.store.prepare(proof.clone(), changes).unwrap();
        assert!(
            h.index
                .store
                .transaction_height(&tx_digest)
                .unwrap()
                .is_none()
        );
        let genesis = h.replay.genesis.clone();
        let previous_height = h.head.height().get();
        drop(h.replay);
        let recovered = Replay::new(
            runtime.child("recovered"),
            "edge-test",
            h.index.clone(),
            h.network,
            h.allocations.clone(),
            genesis.clone(),
            &h.verifier,
        )
        .await
        .unwrap();
        assert_eq!(recovered.cursor, previous_height);
        assert!(h.index.store.intent().unwrap().is_none());
        assert_eq!(recovered.next_height().unwrap(), previous_height + 1);
        let read = h.index.store.read(None).unwrap();
        assert!(read.object(id2.as_bytes()).unwrap().is_some());
        assert!(
            read.edge(&hex::encode(id2.as_bytes()))
                .unwrap()
                .unwrap()
                .closed
                .is_none()
        );
        assert_eq!(
            read.events(&hex::encode(id2.as_bytes()), None, 64)
                .unwrap()
                .len(),
            1
        );
        assert!(
            h.index
                .store
                .transaction_height(&tx_digest)
                .unwrap()
                .is_none()
        );
        drop(read);
        let owner_before_finalize = recovered
            .owner_proof(owner, 0, 64, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            owner_before_finalize.bundle().page,
            committed_owner.bundle().page
        );
        assert_eq!(
            owner_before_finalize.block().bundle().height,
            previous_height
        );
        h.verifier
            .verify_address(owner_before_finalize.bundle().clone(), owner, 0, 64)
            .unwrap();
        // Crash after QMDB finalize but before the index transaction: recover the exact
        // certified intent and expose its rows/cursor together, once.
        let context = hellas_kernel::Context::with_fees(
            h.network,
            BlockHeight::new(proof.height),
            hellas_kernel::BlockHash::from_bytes(h.head.digest().0),
            domain::KERNEL_FEES,
        );
        let (batch, changes) = execute_all_observed(
            context,
            &ChainVerifier::new(),
            &transactions,
            &h.allocations,
            recovered.database.new_batches().await,
        )
        .await
        .unwrap();
        let merkleized = batch.merkleize().await.unwrap();
        assert_eq!(hex::encode(merkleized.root()), proof.state_root);
        h.index.store.prepare(proof.clone(), changes).unwrap();
        recovered.database.finalize(merkleized).await;
        drop(recovered);
        let recovered = Replay::new(
            runtime.child("recovered_after_finalize"),
            "edge-test",
            h.index.clone(),
            h.network,
            h.allocations,
            genesis,
            &h.verifier,
        )
        .await
        .unwrap();
        assert_eq!(recovered.cursor, proof.height);
        let read = h.index.store.read(None).unwrap();
        assert!(read.object(id2.as_bytes()).unwrap().is_none());
        assert_eq!(
            read.edge(&hex::encode(id2.as_bytes()))
                .unwrap()
                .unwrap()
                .closed
                .unwrap()
                .height,
            proof.height
        );
        assert_eq!(
            read.events(&hex::encode(id2.as_bytes()), None, 64)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            h.index.store.transaction_height(&tx_digest).unwrap(),
            Some(proof.height)
        );
        drop(read);
        assert_eq!(
            h.index.store.latest().unwrap().unwrap().payload,
            proof.payload
        );
        let owner_after_finalize = recovered
            .owner_proof(owner, 0, 64, None)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            owner_after_finalize.bundle().page,
            committed_owner.bundle().page
        );
        assert_eq!(owner_after_finalize.block().bundle().payload, proof.payload);
        h.verifier
            .verify_address(owner_after_finalize.bundle().clone(), owner, 0, 64)
            .unwrap();
    });
}
struct WorkPair {
    client: Secp256k1Signer,
    provider: Secp256k1Signer,
    bond: hellas_kernel::EdgeId,
    payment: hellas_kernel::EdgeId,
    terms: Terms,
    bond_terms: Terms,
    bond_open: Tx,
    payment_open: Tx,
}
fn work_pair(
    network: hellas_kernel::NetworkId,
    first: u16,
    client_secret: u8,
    provider_secret: u8,
) -> WorkPair {
    let client = signer(client_secret);
    let provider = signer(provider_secret);
    let body = hellas_kernel::WorkStakeBondTerms {
        parties: Parties::new(provider.party_key(), client.party_key()),
        timeout: BlockHeight::new(5),
        timeout_outputs: List::take([Payout::new(provider.party_key(), 12); MAX_EDGE_OUTPUTS], 1),
        max_job_price: 4,
    };
    let bond_terms = Terms::work_stake_bond(body.clone());
    let bond_funding = funding(first + 1);
    let bond = Tx::edge_id_of(&bond_funding, &bond_terms);
    let bond_open = open(
        network,
        bond_funding,
        bond_terms.clone(),
        &provider,
        &client,
    );
    let terms = Terms::work_payment(hellas_kernel::WorkPaymentTerms {
        bond_edge: bond,
        bond_terms: body,
        private_policy_commitment: [7; 32],
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: 2,
    });
    let payment_funding = funding(first);
    let payment = Tx::edge_id_of(&payment_funding, &terms);
    let payment_open = open(network, payment_funding, terms.clone(), &client, &provider);
    WorkPair {
        client,
        provider,
        bond,
        payment,
        terms,
        bond_terms,
        bond_open,
        payment_open,
    }
}
#[test]
fn native_edge_index_work_channel_lifecycle_and_evidence() {
    run_qmdb(|runtime| async move {
        use hellas_kernel::{
            EarnedCertificate, Move, Party, PaymentCloseResponse, PaymentCloseStart, PendingSlot,
            Proof, RegistryChunk,
        };
        let network = hellas_kernel::NetworkId::new(HELLAS_DEVNET_1_ID).unwrap();
        let a = work_pair(network, 0, 31, 32);
        let b = work_pair(network, 2, 33, 34);
        let allocations = vec![
            (SettlementKey::from(a.client.party_key()), 100),
            (SettlementKey::from(a.provider.party_key()), 12),
            (SettlementKey::from(b.client.party_key()), 100),
            (SettlementKey::from(b.provider.party_key()), 12),
        ];
        let mut h = Harness::new(runtime.child("h"), allocations, "work").await;
        let opened = h
            .append(
                vec![
                    a.bond_open.clone(),
                    a.payment_open.clone(),
                    b.bond_open.clone(),
                    b.payment_open.clone(),
                ]
                .into_iter()
                .map(Transaction::Kernel)
                .collect(),
            )
            .await;
        let channel = |h: &Harness, id: hellas_kernel::EdgeId, payload: Option<String>| {
            h.index
                .get_work_channel_detail(GetWorkChannelDetailRequest {
                    schema_version: crate::edge_index::SCHEMA_VERSION,
                    payment_edge_id: hex::encode(id.as_bytes()),
                    payload,
                    funding: None,
                })
                .unwrap()
        };
        let initial = channel(&h, a.payment, None);
        h.client.check_channel(&initial).unwrap();
        assert_eq!(initial.data.funding_query.len(), 2);
        assert!(initial.data.live_funding.is_empty());
        h.export("channel-open", &initial);
        h.export("edges-open", &h.list(64));
        h.export("payment-open", &h.detail(a.payment, None));
        h.export("bond-open", &h.detail(a.bond, None));
        let mut bad = initial.clone();
        bad.data.lease_slots.pop();
        assert!(h.client.check_channel(&bad).is_err());
        let empty = h
            .index
            .get_work_channel_detail(GetWorkChannelDetailRequest {
                schema_version: crate::edge_index::SCHEMA_VERSION,
                payment_edge_id: hex::encode(a.payment.as_bytes()),
                payload: None,
                funding: Some(FundingQuery { coins: Vec::new() }),
            })
            .unwrap();
        assert!(empty.data.funding_query.is_empty());
        let understated = EarnedCertificate::new(a.payment, a.terms.hash(), 30);
        let earned_hash = understated.digest(network);
        let start_hash = hellas_kernel::start_digest(
            network,
            a.payment,
            a.terms.hash(),
            Party::Maker,
            (2, 2),
            earned_hash,
        );
        let start = Tx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
            a.payment,
            a.terms.clone(),
            Party::Maker,
            (2, 2),
            Some((understated, a.client.sign(earned_hash))),
            a.client.sign(start_hash),
        )));
        let start_id = hellas_kernel::start_id(start_hash, 2);
        let earned = EarnedCertificate::new(a.payment, a.terms.hash(), 60);
        let digest = earned.digest(network);
        let response_hash = hellas_kernel::response_digest(
            network,
            a.payment,
            a.terms.hash(),
            start_id,
            Party::Taker,
            digest,
        );
        let response = Tx::move_action(Move::RespondPaymentClose(PaymentCloseResponse::new(
            a.payment,
            start_id,
            Party::Taker,
            (earned, a.client.sign(digest)),
            a.provider.sign(response_hash),
        )));
        h.append(vec![Transaction::Kernel(start)]).await;
        let started = channel(&h, a.payment, None);
        h.client.check_channel(&started).unwrap();
        // Both openings belong to the same historical block. Evidence occurs once,
        // and every locator is checked against the bytes of that certified block.
        assert!(initial.envelope.evidence.is_empty());
        assert_eq!(started.envelope.evidence.len(), 1);
        assert_eq!(started.envelope.evidence[0].payload, opened.payload);
        let json = serde_json::to_value(&started).unwrap();
        assert!(json["data"]["payment"]["opening"].get("proof").is_none());
        assert!(json["data"]["bond"]["opening"].get("proof").is_none());
        assert_eq!(json["evidence"].as_array().unwrap().len(), 1);
        for mutate in [
            |value: &mut GetWorkChannelDetailResponse| {
                value.envelope.evidence.clear();
            },
            |value: &mut GetWorkChannelDetailResponse| {
                value
                    .envelope
                    .evidence
                    .push(value.envelope.evidence[0].clone());
            },
            |value: &mut GetWorkChannelDetailResponse| {
                value.envelope.evidence[0].canonical_block[0] ^= 1;
            },
            |value: &mut GetWorkChannelDetailResponse| {
                value.data.payment.opening.transaction.transaction_index += 1;
            },
            |value: &mut GetWorkChannelDetailResponse| {
                value.envelope.schema_version = 1;
            },
        ] {
            let mut changed = started.clone();
            mutate(&mut changed);
            assert!(h.client.check_channel(&changed).is_err());
        }
        let read = h.index.store.read(None).unwrap();
        let reference = &started.data.payment.opening.transaction;
        assert!(read.transaction(reference).is_ok());
        let mut corrupt = reference.clone();
        corrupt.transaction_index += 1;
        assert!(read.transaction(&corrupt).is_err());
        corrupt = reference.clone();
        corrupt.payload = "00".repeat(32);
        assert!(read.transaction(&corrupt).is_err());
        drop(read);
        assert!(matches!(
            started.data.pending.answer,
            Some(PendingState::Present(PendingProjection {
                responded: false,
                ..
            }))
        ));
        h.export("channel-start", &started);
        let moved = h.append(vec![Transaction::Kernel(response)]).await;
        let pending = channel(&h, a.payment, None);
        h.client.check_channel(&pending).unwrap();
        assert_eq!(pending.data.payment.summary.lifecycle, "open");
        assert!(matches!(
            pending.data.pending.answer,
            Some(PendingState::Present(PendingProjection {
                responded: true,
                penalty_due: true,
                final_cumulative: 60,
                ..
            }))
        ));
        h.export("channel-pending", &pending);
        let chunk: RegistryChunk = crate::edge_index::projection::decode_canonical(
            pending.data.pending_slot.chunk.as_deref().unwrap(),
        )
        .unwrap();
        let PendingSlot::Present(record) =
            hellas_kernel::parse_pending_close(Some(chunk), a.payment)
        else {
            panic!()
        };
        let outputs = List::take(
            {
                let mut values = [Payout::default(); MAX_EDGE_OUTPUTS];
                values[0] = Payout::new(a.provider.party_key(), 62);
                values[1] = Payout::new(a.client.party_key(), 38);
                values
            },
            2,
        );
        h.append(vec![Transaction::Kernel(Tx::close(
            a.payment,
            Proof::adjudicated(record.contest_commitment(network, a.payment, a.terms.hash())),
            outputs,
        ))])
        .await;
        let closed = channel(&h, a.payment, None);
        h.client.check_channel(&closed).unwrap();
        assert_eq!(closed.data.payment.summary.lifecycle, "closed");
        assert!(matches!(
            closed.data.lease.answer,
            Some(LeaseState::Present(_))
        ));
        assert!(matches!(
            closed.data.pending.answer,
            Some(PendingState::Absent(_))
        ));
        h.export("channel-adjudicated", &closed);
        assert_eq!(h.head.height().get(), 4);
        assert_eq!(
            channel(&h, b.payment, None).data.admission,
            "before_horizon"
        );
        h.append(vec![
            Transaction::Kernel(Tx::timeout_close(a.bond, &a.bond_terms).unwrap()),
            Transaction::Kernel(Tx::timeout_close(b.bond, &b.bond_terms).unwrap()),
        ])
        .await;
        let consumed = channel(&h, b.payment, None);
        h.client.check_channel(&consumed).unwrap();
        assert_eq!(consumed.data.bond_state, "consumed");
        assert_eq!(consumed.data.payment.summary.lifecycle, "open");
        assert_eq!(consumed.data.admission, "ended");
        assert!(matches!(
            consumed.data.lease.answer,
            Some(LeaseState::Absent(_))
        ));
        h.export("channel-bond-consumed", &consumed);
        let freeze_hash =
            hellas_kernel::freeze_digest(network, b.payment, b.terms.hash(), 60, (6, 6));
        let outputs = List::take(
            {
                let mut values = [Payout::default(); MAX_EDGE_OUTPUTS];
                values[0] = Payout::new(b.provider.party_key(), 60);
                values[1] = Payout::new(b.client.party_key(), 40);
                values
            },
            2,
        );
        h.append(vec![Transaction::Kernel(Tx::close(
            b.payment,
            Proof::freeze(
                60,
                (6, 6),
                b.client.sign(freeze_hash),
                b.provider.sign(freeze_hash),
            ),
            outputs,
        ))])
        .await;
        let frozen = channel(&h, b.payment, None);
        h.client.check_channel(&frozen).unwrap();
        assert_eq!(frozen.data.payment.summary.lifecycle, "closed");
        assert_eq!(frozen.data.admission, "ended");
        h.export("channel-frozen", &frozen);
        assert!(h.list(64).data.items.is_empty());
        h.export("edges-empty", &h.list(64));
        for payload in [opened.payload, moved.payload] {
            let error = h
                .index
                .get_work_channel_detail(GetWorkChannelDetailRequest {
                    schema_version: SCHEMA_VERSION,
                    payment_edge_id: hex::encode(a.payment.as_bytes()),
                    payload: Some(payload),
                    funding: None,
                })
                .unwrap_err();
            assert_eq!((error.status, error.code), (409, "snapshot_unavailable"));
            assert_eq!(
                error.snapshot.unwrap().snapshot.payload,
                frozen.envelope.snapshot.payload
            );
        }
        let events = h
            .index
            .list_edge_events(ListEdgeEventsRequest {
                schema_version: crate::edge_index::SCHEMA_VERSION,
                edge_id: hex::encode(a.payment.as_bytes()),
                limit: Some(64),
                ..Default::default()
            })
            .unwrap();
        h.client
            .check_events(&events, &hex::encode(a.payment.as_bytes()))
            .unwrap();
        assert_eq!(
            events
                .data
                .items
                .iter()
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            ["open", "move", "move", "close"]
        );
        h.export("payment-events", &events);
    });
}

#[test]
fn native_edge_index_cold_open_serves_current_owners_without_archive_replay() {
    run_qmdb(|runtime| async move {
        let maker = signer(31);
        let taker = signer(32);
        let untouched = SettlementKey::from(signer(33).party_key());
        let absent = SettlementKey::from(signer(34).party_key());
        let owner = SettlementKey::from(maker.party_key());
        let mut h = Harness::new(
            runtime.child("cold"),
            vec![(owner, 100), (untouched, 1000)],
            "cold-owners",
        )
        .await;
        let genesis = h.head.clone();
        let (id, _, opened) = basic(h.network, 0, &maker, &taker);
        let first = h.append(vec![Transaction::Kernel(opened)]).await;
        let latest = h.append(Vec::new()).await;
        let path = h.directory.path().join("index.redb");
        drop(h.replay);
        drop(h.index);
        // Reopen both persistent stores. No follower, archive, or historical
        // block callback exists in this test or in the owner-proof interface.
        let index = EdgeIndex::open(
            &path,
            HELLAS_DEVNET_1_ID.into(),
            h.trust.genesis_sha256.clone(),
            h.verifier.trust_sha256().into(),
        )
        .unwrap();
        let recovered = Replay::new(
            runtime.child("reopened"),
            "edge-test",
            index.clone(),
            h.network,
            h.allocations,
            genesis,
            &h.verifier,
        )
        .await
        .unwrap();
        assert_eq!(recovered.next_height().unwrap(), latest.height + 1);
        let listing = index
            .list_edges(ListEdgesRequest {
                schema_version: crate::edge_index::SCHEMA_VERSION,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(listing.envelope.snapshot.payload, latest.payload);
        assert_eq!(listing.data.items[0].edge_id, hex::encode(id.as_bytes()));
        for (address, balance, count) in [(owner, 0, 1), (untouched, 1000, 1), (absent, 0, 0)] {
            let bundle = recovered
                .owner_proof(address, 0, 64, None)
                .await
                .unwrap()
                .unwrap();
            let verified = h
                .verifier
                .verify_address(bundle.bundle().clone(), address, 0, 64)
                .unwrap();
            assert_eq!(verified.block().bundle().payload, latest.payload);
            assert_eq!(verified.summary().balance, balance);
            assert_eq!(verified.summary().count, count);
        }
        assert!(
            recovered
                .owner_proof(owner, 0, 64, Some(&first.payload))
                .await
                .unwrap()
                .is_none()
        );
        let pinned = recovered
            .owner_proof(owner, 0, 64, Some(&latest.payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pinned.block().bundle().payload, latest.payload);
    });
}
