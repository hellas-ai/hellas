use super::*;
use crate::{Mempool, OwnerCoins, light_client::QueryError};
use bytes::Bytes;
use hellas_kernel::Encode as _;
use hellas_kernel::test_support::valid_open_tx;
use hellas_rpc::pb::services::light_client::LightClientClientImpl;
use hellas_wire::DefaultClock;
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore, mpsc};

struct ResponseBlocker {
    started: AtomicUsize,
    notify: Notify,
    release: Semaphore,
}

impl Default for ResponseBlocker {
    fn default() -> Self {
        Self {
            started: AtomicUsize::new(0),
            notify: Notify::new(),
            release: Semaphore::new(0),
        }
    }
}

#[derive(Clone, Default)]
struct MempoolClient {
    mempool: Mempool,
    edge_result: Option<Result<Option<EdgeLookup>, QueryError>>,
    owner_edges_result: Option<Result<Option<OwnerEdges>, QueryError>>,
    snapshot_result: Option<WorkChannelSnapshot>,
    response_blocker: Option<Arc<ResponseBlocker>>,
    forced_submit_outcome: Arc<std::sync::Mutex<Option<SubmitTxOutcome>>>,
}

impl FinalizedWorkView for MempoolClient {
    async fn work_channel_snapshot(
        &self,
        _query: WorkChannelQuery,
    ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
        Ok(self.snapshot_result.clone())
    }
}

impl LightClientApi for MempoolClient {
    async fn get_state_root(&self) -> Result<Option<Digest>, QueryError> {
        panic!("unused test method")
    }

    async fn get_proof(&self, _object_id: ObjectId) -> Result<Option<Vec<u8>>, QueryError> {
        panic!("unused test method")
    }

    async fn get_coin(
        &self,
        _payload: Digest,
        _object_id: ObjectId,
    ) -> Result<Option<Coin>, QueryError> {
        panic!("unused test method")
    }

    async fn get_edge(
        &self,
        _payload: Digest,
        _object_id: ObjectId,
    ) -> Result<Option<EdgeLookup>, QueryError> {
        self.edge_result.clone().unwrap_or(Ok(None))
    }

    async fn get_finalization(&self, _payload: Digest) -> Result<Option<Vec<u8>>, QueryError> {
        panic!("unused test method")
    }

    async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        Ok(None)
    }

    async fn get_finalized_block(
        &self,
        _query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        panic!("unused test method")
    }

    async fn submit_tx(&self, tx: Transaction) -> Result<SubmitTxOutcome, QueryError> {
        if let Some(outcome) = *self.forced_submit_outcome.lock().unwrap() {
            return Ok(outcome);
        }
        if payment_close_response(&tx).is_some()
            && let Some(blocker) = &self.response_blocker
        {
            blocker.started.fetch_add(1, Ordering::SeqCst);
            blocker.notify.notify_one();
            blocker.release.acquire().await.unwrap().forget();
        }
        Ok(self.mempool.test_submit(tx).await)
    }

    async fn get_validators(&self) -> Result<Vec<String>, QueryError> {
        Ok(vec!["validator-a".to_string()])
    }

    async fn get_consensus_info(&self) -> Result<ConsensusInfo, QueryError> {
        panic!("unused test method")
    }

    async fn get_coins_by_owner(
        &self,
        _owner: SettlementKey,
    ) -> Result<Option<OwnerCoins>, QueryError> {
        panic!("unused test method")
    }

    async fn get_edges_by_owner(
        &self,
        _owner: SettlementKey,
    ) -> Result<Option<OwnerEdges>, QueryError> {
        self.owner_edges_result.clone().unwrap_or(Ok(None))
    }
}

fn kernel_request(bytes: Vec<u8>) -> pb::SubmitTxRequest {
    pb::SubmitTxRequest {
        tx: Some(submit_tx_request::Tx::KernelTx(bytes)),
    }
}

struct Pipe {
    out: mpsc::UnboundedSender<Bytes>,
    inbox: mpsc::UnboundedReceiver<Bytes>,
}

impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        self.out
            .send(bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed"))
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.inbox.recv().await)
    }
}

fn transport_pair() -> (MuxTransport, MuxTransport) {
    let (to_server, server_inbox) = mpsc::unbounded_channel();
    let (to_client, client_inbox) = mpsc::unbounded_channel();
    let client = MuxTransport::spawn::<64, _, _>(
        MuxRole::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_server,
            inbox: client_inbox,
        },
        TransportContext::default(),
    );
    let server = MuxTransport::spawn::<64, _, _>(
        MuxRole::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_client,
            inbox: server_inbox,
        },
        TransportContext::default(),
    );
    (client, server)
}

fn synthetic_response_request() -> SubmitWorkResponseRequest {
    use hellas_kernel::{EarnedCertificate, Party, PaymentCloseResponse, Sig, StartId, TermsHash};

    let edge = EdgeId::from_bytes([0x31; EdgeId::LENGTH]);
    let response = PaymentCloseResponse::new(
        edge,
        StartId::from_bytes([0x32; StartId::LENGTH]),
        Party::Taker,
        (
            EarnedCertificate::new(edge, TermsHash::from_bytes([0x33; 32]), 9),
            Sig::from_bytes([0x34; Sig::LENGTH]),
        ),
        Sig::from_bytes([0x35; Sig::LENGTH]),
    );
    let mut bytes = vec![0; PaymentCloseResponse::MAX_ENCODED_SIZE];
    let written = response.write_to(&mut bytes);
    bytes.truncate(written);
    SubmitWorkResponseRequest { response: bytes }
}

/// The endpoint's two boundary answers: an argument that is not an
/// edge id, and a node with no finalized state to answer from.
///
/// Absence is reported as an absent snapshot rather than an empty
/// one, because an empty snapshot would read as "this channel does
/// not exist" — a different fact, and the one that would let an
/// endpoint conclude a live lease was gone.
#[tokio::test]
async fn work_channel_snapshot_endpoint_separates_a_bad_argument_from_no_state() {
    let rpc = LightClientRpc::new(MempoolClient::default(), broadcast::channel(4).0);
    let ok = EdgeId::from_bytes([0x11; EdgeId::LENGTH])
        .to_bytes()
        .to_vec();

    let short = LightClientHandler::get_work_channel_snapshot(
        &rpc,
        pb::GetWorkChannelSnapshotRequest {
            bond_edge: ok[..EdgeId::LENGTH - 1].to_vec(),
            payment_edge: ok.clone(),
            funding_coins: Vec::new(),
        },
    )
    .await
    .expect_err("a 31-byte edge id is not an edge id");
    assert_eq!(short.code(), WireCode::InvalidArgument);

    let absent = LightClientHandler::get_work_channel_snapshot(
        &rpc,
        pb::GetWorkChannelSnapshotRequest {
            bond_edge: ok.clone(),
            payment_edge: ok,
            funding_coins: Vec::new(),
        },
    )
    .await
    .expect("an absent snapshot is an answer");
    assert!(absent.snapshot.is_none());
    assert!(absent.lease_slots.is_empty());
    assert!(absent.pending_slot.is_none());
}

#[tokio::test]
async fn kernel_submit_boundary_accepts_only_exact_bounded_canonical_bytes() {
    let client = MempoolClient::default();
    let mempool = client.mempool.clone();
    let (activity_tx, _activity_rx) = broadcast::channel(1);
    let rpc = LightClientRpc::new(client, activity_tx);
    let tx = valid_open_tx().expect("valid kernel open fixture");
    let mut canonical = vec![0; KernelTx::MAX_ENCODED_SIZE];
    let encoded_len = tx.write_to(&mut canonical);
    canonical.truncate(encoded_len);

    let response = LightClientHandler::submit_tx(
        &rpc,
        kernel_request(canonical.clone()),
        TransportContext::default(),
    )
    .await
    .expect("canonical kernel transaction is accepted");
    assert_eq!(response.outcome, ProtoSubmitTxOutcome::Enqueued as i32);
    let pending = mempool.test_transactions().await;
    assert_eq!(pending.len(), 1);
    let Transaction::Kernel(pending_tx) = &pending[0] else {
        panic!("pending transaction was not a kernel transaction")
    };
    assert_eq!(pending_tx, &tx);

    let mut trailing = canonical;
    trailing.push(0);
    for invalid in [
        vec![0xff],
        trailing,
        vec![0; KernelTx::MAX_ENCODED_SIZE + 1],
    ] {
        let error = LightClientHandler::submit_tx(
            &rpc,
            kernel_request(invalid),
            TransportContext::default(),
        )
        .await
        .expect_err("invalid kernel transaction is rejected");
        assert_eq!(error.code(), WireCode::InvalidArgument);
    }
    assert_eq!(mempool.test_transactions().await.len(), 1);
}

#[tokio::test]
async fn round2_full_is_observable() {
    use crate::execution::test_support::kernel_fixture_at;

    let client = MempoolClient::default();
    let mut first = None;
    for index in 0..crate::GENERAL_MEMPOOL_CAPACITY {
        let fixture =
            kernel_fixture_at(10, (index * 2) as u16, 7, 8).expect("distinct valid kernel fixture");
        let tx = Transaction::Kernel(fixture.open);
        first.get_or_insert_with(|| tx.clone());
        assert_eq!(
            client.mempool.test_submit(tx).await,
            SubmitTxOutcome::Enqueued
        );
    }
    assert_eq!(
        client
            .mempool
            .test_submit(first.expect("the capacity is non-zero"))
            .await,
        SubmitTxOutcome::Duplicate,
        "a resident digest stays duplicate even when the mempool is full",
    );

    let (activity_tx, _activity_rx) = broadcast::channel(1);
    let rpc = LightClientRpc::new(client, activity_tx);
    let fixture = kernel_fixture_at(10, 400, 7, 8).expect("overflow fixture");
    let mut canonical = vec![0; KernelTx::MAX_ENCODED_SIZE];
    let encoded_len = fixture.open.write_to(&mut canonical);
    canonical.truncate(encoded_len);

    let response =
        LightClientHandler::submit_tx(&rpc, kernel_request(canonical), TransportContext::default())
            .await
            .expect("a full mempool is an observable submission outcome");
    assert_eq!(response.outcome, ProtoSubmitTxOutcome::Full as i32);
}

#[tokio::test]
async fn bound_and_relay_transports_answer_from_one_node_state() {
    let state = LightClientRpcState::default();
    let blocker = Arc::new(ResponseBlocker::default());
    let client = MempoolClient {
        response_blocker: Some(blocker.clone()),
        ..MempoolClient::default()
    };
    let forced_submit_outcome = client.forced_submit_outcome.clone();
    let (activity_tx, _activity_rx) = broadcast::channel(1);
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let bound_server =
        spawn_light_client_server(addr, client.clone(), activity_tx.clone(), state.clone())
            .await
            .unwrap();
    let bound_transport = hellas_wire::ws::connect(&format!("ws://{addr}"))
        .await
        .unwrap();

    // This pair has the direction of an outbound relay connection: the
    // relay owns the client-role half and opens calls toward the node's
    // server-role half.
    let (relay_transport, node_transport) = transport_pair();
    let relay_server = tokio::spawn(serve_light_client_transport(
        node_transport,
        LightClientRpc::with_state(client, activity_tx, state),
    ));
    let wire_a = LightClientClientImpl::new(bound_transport);
    let wire_b = LightClientClientImpl::new(relay_transport);

    for wire in [&wire_a, &wire_b] {
        let validators = wire
            .get_validators(pb::GetValidatorsRequest {})
            .await
            .expect("both transports answer a real light-client request");
        assert_eq!(validators.validators, ["validator-a"]);
    }

    let response_request = synthetic_response_request();
    let mut held = Vec::new();
    for _ in 0..16 {
        let wire = wire_a.clone();
        let request = response_request.clone();
        held.push(tokio::spawn(async move {
            wire.submit_work_response(request).await
        }));
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while blocker.started.load(Ordering::SeqCst) < 4 {
            blocker.notify.notified().await;
        }
    })
    .await
    .expect("four response workers start");
    tokio::time::sleep(Duration::from_millis(20)).await;

    let overflow = tokio::time::timeout(
        Duration::from_secs(1),
        wire_b.submit_work_response(response_request.clone()),
    )
    .await
    .expect("the second transport receives a prompt saturation result")
    .expect_err("all sixteen node response permits are held by the first transport");
    assert_eq!(overflow.code(), WireCode::ResourceExhausted, "{overflow:?}");

    blocker.release.add_permits(16);
    for call in held {
        call.await
            .expect("response task")
            .expect("held response eventually completes");
    }

    let tx = valid_open_tx().expect("general transaction fixture");
    let mut canonical = vec![0; KernelTx::MAX_ENCODED_SIZE];
    let written = tx.write_to(&mut canonical);
    canonical.truncate(written);
    let request = kernel_request(canonical);
    for wire in [
        &wire_a, &wire_a, &wire_a, &wire_a, &wire_b, &wire_b, &wire_b, &wire_b,
    ] {
        let response = wire
            .submit_tx(request.clone())
            .await
            .expect("the first eight anonymous attempts reach the handler");
        assert!(matches!(
            ProtoSubmitTxOutcome::try_from(response.outcome),
            Ok(ProtoSubmitTxOutcome::Enqueued | ProtoSubmitTxOutcome::Duplicate)
        ));
    }
    let ninth = wire_b
        .submit_tx(request)
        .await
        .expect("the shared anonymous budget returns an outcome");
    assert_eq!(ninth.outcome, ProtoSubmitTxOutcome::Full as i32);

    *forced_submit_outcome.lock().unwrap() = Some(SubmitTxOutcome::ValidationRejected);
    let rejected = wire_b
        .submit_work_response(response_request)
        .await
        .expect("validation rejection survives the response wire route");
    assert_eq!(rejected.outcome, 4);
    assert_eq!(
        ProtoSubmitTxOutcome::try_from(rejected.outcome),
        Ok(ProtoSubmitTxOutcome::ValidationRejected),
    );

    bound_server.abort();
    relay_server.abort();
}

#[cfg(feature = "client")]
#[tokio::test]
async fn activity_stream_does_not_block_unary_requests() {
    use crate::{LightClient as _, client::RemoteLightClient};

    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let (activity_tx, _activity_rx) = broadcast::channel(8);
    let server = spawn_light_client_server(
        addr,
        MempoolClient::default(),
        activity_tx,
        LightClientRpcState::default(),
    )
    .await
    .unwrap();
    let client = RemoteLightClient::connect(format!("ws://{addr}"))
        .await
        .unwrap();
    let _activity = client.subscribe_activity(Vec::new()).await.unwrap();

    let validators = tokio::time::timeout(Duration::from_secs(1), client.get_validators())
        .await
        .expect("unary request was blocked behind activity stream")
        .unwrap();
    assert_eq!(validators, ["validator-a"]);

    server.abort();
}

#[tokio::test]
async fn get_edge_endpoint_preserves_full_state_root_absence_and_wrong_kind() {
    let open = valid_open_tx().expect("valid kernel open fixture");
    let KernelTx::Open { terms, .. } = open else {
        panic!("fixture must be an open")
    };
    let parties = terms.parties();
    let state_root = Digest::from([0x31; 32]);
    let edge = EdgeState {
        value: 101,
        reserve: 9,
        close_fees: hellas_kernel::Fees::new(1, 2, 3, 4),
        timeout: hellas_kernel::BlockHeight::new(55),
        maker: SettlementKey::from(parties.maker()),
        taker: SettlementKey::from(parties.taker()),
        terms_hash: terms.hash(),
    };
    let (activity_tx, _activity_rx) = broadcast::channel(1);
    let found_rpc = LightClientRpc::new(
        MempoolClient {
            edge_result: Some(Ok(Some(EdgeLookup {
                state_root,
                edge: Some(edge),
            }))),
            ..MempoolClient::default()
        },
        activity_tx.clone(),
    );
    let request = pb::GetEdgeRequest {
        payload: vec![0x11; 32],
        object_id: vec![0x22; 32],
    };
    let response = LightClientHandler::get_edge(&found_rpc, request.clone())
        .await
        .expect("edge response");
    assert_eq!(response.state_root, Some(state_root.to_vec()));
    let response_edge = response.edge.expect("full edge state");
    assert_eq!(response_edge.value, edge.value);
    assert_eq!(response_edge.reserve, edge.reserve);
    assert_eq!(response_edge.timeout, edge.timeout.get());
    assert_eq!(response_edge.maker, edge.maker.to_bytes());
    assert_eq!(response_edge.taker, edge.taker.to_bytes());
    assert_eq!(response_edge.terms_hash, edge.terms_hash.to_bytes());
    assert_eq!(
        response_edge.close_fees,
        Some(KernelFees {
            base: 1,
            slot: 2,
            proof: 3,
            lifetime: 4,
        })
    );

    let absent_rpc = LightClientRpc::new(MempoolClient::default(), activity_tx.clone());
    let absent = LightClientHandler::get_edge(&absent_rpc, request.clone())
        .await
        .expect("absent edge response");
    assert_eq!(absent.edge, None);
    assert_eq!(absent.state_root, None);

    let wrong_kind_rpc = LightClientRpc::new(
        MempoolClient {
            edge_result: Some(Err(QueryError::WrongObjectKind {
                expected: crate::domain::ObjectKind::Edge,
                actual: crate::domain::ObjectKind::Coin,
            })),
            ..MempoolClient::default()
        },
        activity_tx,
    );
    let error = LightClientHandler::get_edge(&wrong_kind_rpc, request)
        .await
        .expect_err("coin in edge slot is typed");
    assert!(matches!(
        QueryError::from(error),
        QueryError::WrongObjectKind {
            expected: crate::domain::ObjectKind::Edge,
            actual: crate::domain::ObjectKind::Coin,
        }
    ));
}

#[cfg(feature = "validator")]
#[tokio::test]
async fn get_edges_by_owner_endpoint_tracks_open_close_and_empty_owner() {
    use crate::execution::test_support::{index_block, index_genesis, kernel_fixture};
    use crate::owner_index::ApplyOutcome;
    use commonware_cryptography::Digestible as _;

    fn response_from_index(
        index: &crate::OwnerIndex,
        owner: SettlementKey,
        finalization: Vec<u8>,
    ) -> OwnerEdges {
        let (cursor, edges) = index.get_edges_by_owner_snapshot(&owner);
        OwnerEdges {
            snapshot: LatestBlock {
                height: cursor.height,
                payload: cursor.payload,
                state_root: cursor.state_root,
                finalization,
            },
            edges: edges
                .into_iter()
                .map(|(object_id, edge)| crate::EdgeRecord {
                    object_id,
                    maker: edge.maker,
                    taker: edge.taker,
                })
                .collect(),
        }
    }

    fn rpc_with_owner_edges(owner_edges: OwnerEdges) -> LightClientRpc<MempoolClient> {
        let (activity_tx, _activity_rx) = broadcast::channel(1);
        LightClientRpc::new(
            MempoolClient {
                owner_edges_result: Some(Ok(Some(owner_edges))),
                ..MempoolClient::default()
            },
            activity_tx,
        )
    }

    let genesis = index_genesis();
    let fixture = kernel_fixture(10).expect("kernel fixture");
    let index = crate::OwnerIndex::new(
        crate::domain::TEST_NETWORK,
        &genesis,
        fixture.allocations.clone(),
    );
    let finalization = vec![0xfa, 0xce];
    let request = pb::GetEdgesByOwnerRequest {
        owner: fixture.maker.to_bytes().to_vec(),
    };

    let open_block = index_block(
        &genesis,
        Digest::from([0x41; 32]),
        vec![Transaction::Kernel(fixture.open.clone())],
    );
    assert_eq!(
        index.apply_finalized(&open_block),
        Ok(ApplyOutcome::Applied)
    );
    let open_rpc = rpc_with_owner_edges(response_from_index(
        &index,
        fixture.maker,
        finalization.clone(),
    ));
    let open_response = LightClientHandler::get_edges_by_owner(&open_rpc, request.clone())
        .await
        .expect("open owner listing");
    let open_snapshot = open_response.snapshot.expect("indexed snapshot");
    assert_eq!(open_snapshot.finalization, finalization);
    assert_eq!(open_snapshot.payload, open_block.digest().to_vec());
    assert!(matches!(
        open_response.edges.as_slice(),
        [edge] if edge.object_id == crate::domain::edge_object_id(fixture.edge).to_vec()
            && edge.maker == fixture.maker.to_bytes()
    ));

    let empty_owner = SettlementKey::from_bytes([0x99; SettlementKey::LENGTH]);
    let empty_rpc = rpc_with_owner_edges(response_from_index(
        &index,
        empty_owner,
        finalization.clone(),
    ));
    let empty_response = LightClientHandler::get_edges_by_owner(
        &empty_rpc,
        pb::GetEdgesByOwnerRequest {
            owner: empty_owner.to_bytes().to_vec(),
        },
    )
    .await
    .expect("empty owner listing");
    assert!(empty_response.snapshot.is_some());
    assert!(empty_response.edges.is_empty());

    let close_block = index_block(
        &open_block,
        Digest::from([0x42; 32]),
        vec![Transaction::Kernel(fixture.mutual_close)],
    );
    assert_eq!(
        index.apply_finalized(&close_block),
        Ok(ApplyOutcome::Applied)
    );
    let close_rpc = rpc_with_owner_edges(response_from_index(&index, fixture.maker, finalization));
    let close_response = LightClientHandler::get_edges_by_owner(&close_rpc, request)
        .await
        .expect("closed owner listing");
    let close_snapshot = close_response.snapshot.expect("indexed snapshot");
    assert_eq!(close_snapshot.finalization, vec![0xfa, 0xce]);
    assert_eq!(close_snapshot.payload, close_block.digest().to_vec());
    assert!(close_response.edges.is_empty());
}

#[test]
fn owner_query_accepts_raw_non_p256_settlement_key() {
    let raw = vec![0xa5; SettlementKey::LENGTH];
    let key = settlement_key_from_bytes(raw.clone(), "owner").expect("raw settlement key");
    assert_eq!(key.as_bytes().as_slice(), raw.as_slice());
    assert!(Address::try_from(key).is_err());
}

#[test]
fn owner_query_rejects_wrong_settlement_key_length() {
    let err = settlement_key_from_bytes(vec![0; SettlementKey::LENGTH - 1], "owner")
        .expect_err("short settlement key");
    assert_eq!(err.code(), WireCode::InvalidArgument);
}

#[test]
fn activity_event_contains_validator_observation_timestamp() {
    let before = unix_time_ms();
    let event = activity_to_proto(ConsensusActivity::Nullify {
        epoch: 1,
        view: 2,
        signer: 3,
        signature: vec![4],
    });
    let after = unix_time_ms();

    assert_eq!(event.relay_timestamps.len(), 1);
    assert!((before..=after).contains(&event.relay_timestamps[0]));
}

/// One submission to one validator is one `rpc_ms` sample.
///
/// §4 maximises `rpc_ms + response_worker_ms + validation_ms` over
/// six validators, and this tree fans a write to one validator at a
/// time (`crates/cli/src/commands/serve/node.rs`), so what a seam can
/// honestly emit is the per-validator term and the maximum is the
/// reader's. The interval is the whole call, which is where a
/// submitter actually waits — the server's own worker and validation
/// samples happen inside it.
#[cfg(feature = "client")]
#[tokio::test]
async fn one_validator_submission_is_one_rpc_sample() {
    use crate::{LightClient as _, client::RemoteLightClient};
    use hellas_rpc::observe::Samples;
    use tracing::instrument::WithSubscriber as _;

    let (client_transport, server_transport) = transport_pair();
    let (activity_tx, _activity_rx) = broadcast::channel(1);
    let server = tokio::spawn(serve_light_client_transport(
        server_transport,
        LightClientRpc::new(MempoolClient::default(), activity_tx),
    ));
    let client = RemoteLightClient::new(client_transport);
    let samples = std::sync::Arc::new(Samples::new());

    let tx = Transaction::Kernel(valid_open_tx().expect("general transaction fixture"));
    let outcome = client
        .submit_tx(tx)
        .with_subscriber(samples.clone())
        .await
        .expect("the validator answers");
    assert!(matches!(
        outcome,
        SubmitTxOutcome::Enqueued | SubmitTxOutcome::Duplicate
    ));

    let calls = samples.of("rpc_ms");
    assert_eq!(calls.len(), 1, "one submission, one sample");
    assert_eq!(
        calls[0].field("method"),
        Some("SubmitTx"),
        "which of the two submission methods this validator was asked",
    );
    assert_eq!(calls[0].field("answered"), Some("true"));
    assert!(calls[0].ms >= 0.0);

    server.abort();
}
