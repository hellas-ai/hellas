use crate::domain::Bounded;
use crate::domain::{
    Address, Coin, DecodeExt, Digest, MAX_MERGE_INPUTS, ObjectId, SettlementKey, Transaction,
    UserPublicKey, UserSignature, WebAuthnSignature,
};
use crate::work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot};
use crate::{
    ConsensusActivity, ConsensusInfo, EdgeLookup, EdgeState, FinalizedBlock, FinalizedBlockQuery,
    LatestBlock, LightClient as LightClientApi, MAX_CANONICAL_TRANSACTION_BYTES, OwnerEdges,
    ProposalInfo,
};
use futures_util::{Stream, StreamExt as _};
use hellas_kernel::{Decode as _, EdgeId, Move as KernelMove, Tx as KernelTx};
use hellas_rpc::pb::{
    chain::{
        self as pb, ActivityEvent, CoinEntry, EdgeEntry, EdgeState as ProtoEdgeState,
        FinalizationEvent, FinalizedBlock as ProtoFinalizedBlock, FinalizedSnapshot,
        GetCoinResponse, GetCoinsByOwnerResponse, GetConsensusInfoResponse, GetEdgeResponse,
        GetEdgesByOwnerResponse, GetFinalizationResponse, GetFinalizedBlockResponse,
        GetLatestBlockResponse, GetProofResponse, GetRelayInfoResponse, GetStateRootResponse,
        GetValidatorsResponse, GetWorkChannelSnapshotResponse, KernelFees, MergeCoinTx,
        NotarizationEvent, NotarizeEvent, NullificationEvent, NullifyEvent, RegistrySlot,
        SubmitTxOutcome as ProtoSubmitTxOutcome, SubmitTxResponse, SubmitWorkResponseRequest,
        TransferTx, WebAuthnSignature as ProtoWebAuthnSignature, activity_event, submit_tx_request,
    },
    services::light_client::{LightClientHandler, LightClientServer},
};
use hellas_rpc::{
    SubmitTxOutcome,
    call::{GeneralSubmitRoute, WorkResponseRoute},
};
use hellas_wire::{PeerIdentity, StreamTransport, TransportContext, WireCode, WireStatus};
use p256::ecdsa::Signature as P256Signature;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::broadcast,
    task::JoinHandle,
};
use tokio_stream::wrappers::BroadcastStream;
use tokio_tungstenite::accept_async;
use tracing::{info, warn};

type ActivityStream =
    Pin<Box<dyn Stream<Item = Result<ActivityEvent, WireStatus>> + Send + 'static>>;
pub type LightClientServerError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Clone)]
pub struct LightClientRpc<T> {
    client: T,
    activity_tx: broadcast::Sender<ConsensusActivity>,
    state: LightClientRpcState,
}

/// Node-scoped concurrency and source-accounting state for light-client RPCs.
///
/// Every transport served by one node must receive a clone of the same state,
/// so reconnecting or opening another connection cannot multiply its bounds.
#[derive(Clone)]
pub struct LightClientRpcState {
    response_route: Arc<WorkResponseRoute>,
    general_route: Arc<GeneralSubmitRoute>,
    general_sources: Arc<tokio::sync::Mutex<GeneralSourceTable>>,
}

impl Default for LightClientRpcState {
    fn default() -> Self {
        Self {
            response_route: Arc::new(WorkResponseRoute::default()),
            general_route: Arc::new(GeneralSubmitRoute::default()),
            general_sources: Arc::new(tokio::sync::Mutex::new(GeneralSourceTable::default())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum GeneralSourceKey {
    Anonymous,
    Peer(PeerIdentity),
}

#[derive(Default)]
struct GeneralSourceTable {
    height: Option<u64>,
    attempts: HashMap<GeneralSourceKey, u8>,
}

impl<T> LightClientRpc<T> {
    pub fn new(client: T, activity_tx: broadcast::Sender<ConsensusActivity>) -> Self {
        Self::with_state(client, activity_tx, LightClientRpcState::default())
    }

    pub fn with_state(
        client: T,
        activity_tx: broadcast::Sender<ConsensusActivity>,
        state: LightClientRpcState,
    ) -> Self {
        Self {
            client,
            activity_tx,
            state,
        }
    }

    async fn consume_general_attempt(&self, context: &TransportContext, height: u64) -> bool {
        let mut table = self.state.general_sources.lock().await;
        if table.height != Some(height) {
            table.height = Some(height);
            table.attempts.clear();
        }
        let key = context
            .peer
            .map_or(GeneralSourceKey::Anonymous, GeneralSourceKey::Peer);
        if let Some(attempts) = table.attempts.get_mut(&key) {
            if *attempts >= 8 {
                return false;
            }
            *attempts += 1;
            return true;
        }
        if table.attempts.len() >= 256 {
            return false;
        }
        table.attempts.insert(key, 1);
        true
    }
}

pub async fn spawn_light_client_server<T>(
    addr: SocketAddr,
    client: T,
    activity_tx: broadcast::Sender<ConsensusActivity>,
    state: LightClientRpcState,
) -> io::Result<JoinHandle<()>>
where
    T: LightClientApi + FinalizedWorkView,
{
    let listener = TcpListener::bind(addr).await?;
    Ok(tokio::spawn(async move {
        info!(%addr, "light client rpc server started");
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(connection) => connection,
                Err(err) => {
                    warn!(?err, "light client rpc accept failed");
                    continue;
                }
            };
            let service =
                LightClientRpc::with_state(client.clone(), activity_tx.clone(), state.clone());
            tokio::spawn(async move {
                if let Err(err) = serve_connection(stream, service).await {
                    warn!(?err, %peer, "light client rpc connection failed");
                }
            });
        }
    }))
}

async fn serve_connection<T>(
    stream: TcpStream,
    service: LightClientRpc<T>,
) -> Result<(), LightClientServerError>
where
    T: LightClientApi + FinalizedWorkView,
{
    let ws = accept_async(stream).await?;
    let transport = hellas_wire::ws::accept_upgraded(ws, None);
    serve_light_client_transport(transport, service).await
}

/// Serve the typed light-client API over any inbound-stream transport.
///
/// Each RPC is dispatched in its own task. Server-streaming calls can remain
/// open indefinitely and must not block unary calls on other mux streams.
pub async fn serve_light_client_transport<T, C>(
    transport: T,
    service: LightClientRpc<C>,
) -> Result<(), LightClientServerError>
where
    T: StreamTransport + Send + Sync + 'static,
    T::Stream: 'static,
    <T::Stream as hellas_wire::Stream>::RecvHalf: 'static,
    <T::Stream as hellas_wire::Stream>::SendHalf: 'static,
    C: LightClientApi + FinalizedWorkView,
{
    // Unbounded on purpose: this service exposes long-lived server-streaming
    // calls (activity subscriptions), and an in-flight cap counts open
    // streams, so a handful of subscribers would starve every later call on
    // the connection.
    hellas_wire::serve_dispatched(transport, "light-client", None, || {
        LightClientServer(
            service.clone(),
            service.state.response_route.clone(),
            service.state.general_route.clone(),
        )
    })
    .await?;
    Ok(())
}

#[allow(refining_impl_trait)]
impl<T> LightClientHandler for LightClientRpc<T>
where
    T: LightClientApi + FinalizedWorkView,
{
    fn get_state_root(
        &self,
        _request: pb::GetStateRootRequest,
    ) -> impl Future<Output = Result<GetStateRootResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let state_root = client.get_state_root().await.map_err(WireStatus::from)?;
            Ok(GetStateRootResponse {
                state_root: state_root.map(|root| root.to_vec()),
            })
        }
    }

    fn get_proof(
        &self,
        request: pb::GetProofRequest,
    ) -> impl Future<Output = Result<GetProofResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let object_id = digest_from_bytes(request.object_id, "object_id")?;
            let proof = client
                .get_proof(object_id)
                .await
                .map_err(WireStatus::from)?;
            Ok(GetProofResponse { proof })
        }
    }

    fn get_coin(
        &self,
        request: pb::GetCoinRequest,
    ) -> impl Future<Output = Result<GetCoinResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let payload = digest_from_bytes(request.payload, "payload")?;
            let object_id = digest_from_bytes(request.object_id, "object_id")?;
            let coin = client
                .get_coin(payload, object_id)
                .await
                .map_err(WireStatus::from)?;
            Ok(coin_response(coin))
        }
    }

    fn get_edge(
        &self,
        request: pb::GetEdgeRequest,
    ) -> impl Future<Output = Result<GetEdgeResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let payload = digest_from_bytes(request.payload, "payload")?;
            let object_id = digest_from_bytes(request.object_id, "object_id")?;
            let edge = client
                .get_edge(payload, object_id)
                .await
                .map_err(WireStatus::from)?;
            Ok(edge_response(edge))
        }
    }

    fn get_work_channel_snapshot(
        &self,
        request: pb::GetWorkChannelSnapshotRequest,
    ) -> impl Future<Output = Result<GetWorkChannelSnapshotResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let mut funding = std::collections::BTreeSet::new();
            for bytes in request.funding_coins {
                funding.insert(coin_id_from_bytes(bytes, "funding_coins")?);
            }
            let query = WorkChannelQuery {
                bond_edge: edge_id_from_bytes(request.bond_edge, "bond_edge")?,
                payment_edge: edge_id_from_bytes(request.payment_edge, "payment_edge")?,
                funding,
            };
            let snapshot = client
                .work_channel_snapshot(query)
                .await
                .map_err(WireStatus::from)?;
            Ok(work_channel_snapshot_response(snapshot))
        }
    }

    fn get_finalization(
        &self,
        request: pb::GetFinalizationRequest,
    ) -> impl Future<Output = Result<GetFinalizationResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let payload = digest_from_bytes(request.payload, "payload")?;
            let certificate = client
                .get_finalization(payload)
                .await
                .map_err(WireStatus::from)?;
            Ok(GetFinalizationResponse { certificate })
        }
    }

    fn get_latest_block(
        &self,
        _request: pb::GetLatestBlockRequest,
    ) -> impl Future<Output = Result<GetLatestBlockResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let latest = client.get_latest_block().await.map_err(WireStatus::from)?;
            Ok(latest_block_response(latest))
        }
    }

    fn get_finalized_block(
        &self,
        request: pb::GetFinalizedBlockRequest,
    ) -> impl Future<Output = Result<GetFinalizedBlockResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let query = finalized_block_query_from_proto(request)?;
            let block = client
                .get_finalized_block(query)
                .await
                .map_err(WireStatus::from)?;
            Ok(finalized_block_response(block))
        }
    }

    fn submit_tx(
        &self,
        request: pb::SubmitTxRequest,
        context: TransportContext,
    ) -> impl Future<Output = Result<SubmitTxResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let tx = transaction_from_proto(request)?;
            if payment_close_response(&tx).is_some() {
                return Err(WireStatus::new(
                    WireCode::InvalidArgument,
                    "PaymentCloseResponse must use SubmitWorkResponse",
                ));
            }
            if crate::light_client::canonical_submission_size(&tx) > MAX_CANONICAL_TRANSACTION_BYTES
            {
                return Err(WireStatus::new(
                    WireCode::InvalidArgument,
                    format!(
                        "canonical transaction exceeds {MAX_CANONICAL_TRANSACTION_BYTES} bytes"
                    ),
                ));
            }
            let height = client
                .get_latest_block()
                .await
                .map_err(WireStatus::from)?
                .map_or(0, |latest| latest.height);
            if !self.consume_general_attempt(&context, height).await {
                return Ok(SubmitTxResponse {
                    outcome: ProtoSubmitTxOutcome::Full as i32,
                });
            }
            let outcome = client.submit_tx(tx).await.map_err(WireStatus::from)?;
            Ok(SubmitTxResponse {
                outcome: submit_tx_outcome_to_proto(outcome) as i32,
            })
        }
    }

    fn submit_work_response(
        &self,
        request: SubmitWorkResponseRequest,
    ) -> impl Future<Output = Result<SubmitTxResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let response = hellas_kernel::PaymentCloseResponse::decode_exact(&request.response)
                .map_err(|_| {
                    WireStatus::new(
                        WireCode::InvalidArgument,
                        "response must be one canonical PaymentCloseResponse",
                    )
                })?;
            let tx = Transaction::Kernel(KernelTx::move_action(KernelMove::RespondPaymentClose(
                response,
            )));
            let outcome = client.submit_tx(tx).await.map_err(WireStatus::from)?;
            Ok(SubmitTxResponse {
                outcome: submit_tx_outcome_to_proto(outcome) as i32,
            })
        }
    }

    fn subscribe_activity(
        &self,
        request: pb::SubscribeActivityRequest,
    ) -> impl Future<Output = Result<ActivityStream, WireStatus>> + Send {
        let activity_tx = self.activity_tx.clone();
        async move {
            let urgent_events = request.urgent_events;
            let stream = BroadcastStream::new(activity_tx.subscribe()).filter_map(move |event| {
                let urgent_events = urgent_events.clone();
                async move {
                    match event {
                        Ok(activity) if activity_is_requested(&urgent_events, &activity) => {
                            Some(Ok(activity_to_proto(activity)))
                        }
                        Ok(_) => None,
                        Err(err) => Some(Err(WireStatus::new(
                            WireCode::Unavailable,
                            format!("activity stream lagged: {err}"),
                        ))),
                    }
                }
            });
            Ok(Box::pin(stream) as ActivityStream)
        }
    }

    fn get_validators(
        &self,
        _request: pb::GetValidatorsRequest,
    ) -> impl Future<Output = Result<GetValidatorsResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let validators = client.get_validators().await.map_err(WireStatus::from)?;
            Ok(GetValidatorsResponse { validators })
        }
    }

    fn get_coins_by_owner(
        &self,
        request: pb::GetCoinsByOwnerRequest,
    ) -> impl Future<Output = Result<GetCoinsByOwnerResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let owner = settlement_key_from_bytes(request.owner, "owner")?;
            let response = match client
                .get_coins_by_owner(owner)
                .await
                .map_err(WireStatus::from)?
            {
                Some(owner_coins) => GetCoinsByOwnerResponse {
                    snapshot: Some(latest_block_to_proto(owner_coins.snapshot)),
                    coins: owner_coins
                        .coins
                        .into_iter()
                        .map(|(object_id, value)| CoinEntry {
                            object_id: object_id.to_vec(),
                            value,
                        })
                        .collect(),
                },
                None => GetCoinsByOwnerResponse {
                    snapshot: None,
                    coins: Vec::new(),
                },
            };
            Ok(response)
        }
    }

    fn get_edges_by_owner(
        &self,
        request: pb::GetEdgesByOwnerRequest,
    ) -> impl Future<Output = Result<GetEdgesByOwnerResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let owner = settlement_key_from_bytes(request.owner, "owner")?;
            let response = client
                .get_edges_by_owner(owner)
                .await
                .map_err(WireStatus::from)?;
            Ok(edges_by_owner_response(response))
        }
    }

    async fn get_relay_info(
        &self,
        _request: pb::GetRelayInfoRequest,
    ) -> Result<GetRelayInfoResponse, WireStatus> {
        Ok(GetRelayInfoResponse {
            relay_version: String::new(),
            relay_rev: String::new(),
            node_rpc_version: env!("CARGO_PKG_VERSION").to_string(),
            node_rpc_rev: option_env!("GIT_REV").unwrap_or("unknown").to_string(),
        })
    }

    fn get_consensus_info(
        &self,
        _request: pb::GetConsensusInfoRequest,
    ) -> impl Future<Output = Result<GetConsensusInfoResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let info = client
                .get_consensus_info()
                .await
                .map_err(WireStatus::from)?;
            Ok(consensus_info_response(info))
        }
    }
}

fn consensus_info_response(info: ConsensusInfo) -> GetConsensusInfoResponse {
    GetConsensusInfoResponse {
        validators: info.validators,
        threshold_identity: info.threshold_identity,
        network_id: info.network_id,
    }
}

fn digest_from_bytes(bytes: Vec<u8>, field: &'static str) -> Result<Digest, WireStatus> {
    let len = bytes.len();
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            format!("{field} must be 32 bytes, got {len}"),
        )
    })?;
    Ok(Digest::from(raw))
}

fn address_from_bytes(bytes: Vec<u8>, field: &'static str) -> Result<Address, WireStatus> {
    UserPublicKey::decode(bytes.as_slice())
        .map(Address::from)
        .map_err(|_| {
            WireStatus::new(
                WireCode::InvalidArgument,
                format!("{field} must be a valid public key"),
            )
        })
}

fn settlement_key_from_bytes(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<SettlementKey, WireStatus> {
    let len = bytes.len();
    let raw: [u8; SettlementKey::LENGTH] = bytes.try_into().map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            format!("{field} must be {} bytes, got {len}", SettlementKey::LENGTH),
        )
    })?;
    Ok(SettlementKey::from_bytes(raw))
}

fn user_signature_from_der(bytes: &[u8]) -> Result<UserSignature, WireStatus> {
    let signature = P256Signature::from_der(bytes).map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            "signature must be valid DER-encoded P-256 ECDSA",
        )
    })?;
    let normalized = signature.normalize_s();
    UserSignature::decode(normalized.to_bytes().as_ref()).map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            "signature must be a valid low-S P-256 signature",
        )
    })
}

fn webauthn_signature_from_proto(
    signature: Option<ProtoWebAuthnSignature>,
) -> Result<WebAuthnSignature, WireStatus> {
    let signature = signature
        .ok_or_else(|| WireStatus::new(WireCode::InvalidArgument, "missing WebAuthn signature"))?;
    let user_signature = user_signature_from_der(&signature.ecdsa_signature)?;
    WebAuthnSignature::new(
        user_signature,
        &signature.authenticator_data,
        &signature.client_data_json,
    )
    .ok_or_else(|| {
        WireStatus::new(
            WireCode::InvalidArgument,
            "invalid WebAuthn signature payload",
        )
    })
}

fn submit_tx_outcome_to_proto(outcome: SubmitTxOutcome) -> ProtoSubmitTxOutcome {
    match outcome {
        SubmitTxOutcome::Enqueued => ProtoSubmitTxOutcome::Enqueued,
        SubmitTxOutcome::Duplicate => ProtoSubmitTxOutcome::Duplicate,
        SubmitTxOutcome::Full => ProtoSubmitTxOutcome::Full,
        SubmitTxOutcome::ValidationRejected => ProtoSubmitTxOutcome::ValidationRejected,
    }
}

fn payment_close_response(tx: &Transaction) -> Option<&hellas_kernel::PaymentCloseResponse> {
    let Transaction::Kernel(KernelTx::Move {
        action: KernelMove::RespondPaymentClose(response),
    }) = tx
    else {
        return None;
    };
    Some(response)
}

fn transaction_from_proto(request: pb::SubmitTxRequest) -> Result<Transaction, WireStatus> {
    match request
        .tx
        .ok_or_else(|| WireStatus::new(WireCode::InvalidArgument, "missing transaction"))?
    {
        submit_tx_request::Tx::Transfer(tx) => transfer_from_proto(tx),
        submit_tx_request::Tx::MergeCoin(tx) => merge_from_proto(tx),
        submit_tx_request::Tx::KernelTx(bytes) => kernel_from_proto(&bytes),
    }
}

fn kernel_from_proto(bytes: &[u8]) -> Result<Transaction, WireStatus> {
    KernelTx::decode_exact(bytes)
        .map(Transaction::Kernel)
        .map_err(|_| {
            WireStatus::new(
                WireCode::InvalidArgument,
                "invalid canonical kernel transaction",
            )
        })
}

fn transfer_from_proto(tx: TransferTx) -> Result<Transaction, WireStatus> {
    Ok(Transaction::Transfer {
        input: digest_from_bytes(tx.input, "input")?,
        recipient: address_from_bytes(tx.recipient, "recipient")?,
        amount: tx.amount,
        signature: webauthn_signature_from_proto(tx.signature)?,
    })
}

fn merge_from_proto(tx: MergeCoinTx) -> Result<Transaction, WireStatus> {
    if tx.inputs.len() < 2 {
        return Err(WireStatus::new(
            WireCode::InvalidArgument,
            "merge requires at least 2 inputs",
        ));
    }
    if tx.inputs.len() > MAX_MERGE_INPUTS {
        return Err(WireStatus::new(
            WireCode::InvalidArgument,
            format!("merge supports at most {MAX_MERGE_INPUTS} inputs"),
        ));
    }
    let len = tx.inputs.len();
    let mut inputs = [ObjectId::from([0; 32]); MAX_MERGE_INPUTS];
    for (index, input) in tx.inputs.into_iter().enumerate() {
        inputs[index] = digest_from_bytes(input, "input")?;
    }
    let inputs = Bounded::new(inputs, len).ok_or_else(|| {
        WireStatus::new(
            WireCode::InvalidArgument,
            "merge input count exceeds capacity",
        )
    })?;
    Ok(Transaction::MergeCoin {
        inputs,
        signature: webauthn_signature_from_proto(tx.signature)?,
    })
}

fn coin_response(coin: Option<Coin>) -> GetCoinResponse {
    match coin {
        Some(Coin { owner, value }) => GetCoinResponse {
            owner: Some(owner.to_bytes().to_vec()),
            value: Some(value),
        },
        None => GetCoinResponse {
            owner: None,
            value: None,
        },
    }
}

fn edge_response(lookup: Option<EdgeLookup>) -> GetEdgeResponse {
    match lookup {
        Some(EdgeLookup { state_root, edge }) => GetEdgeResponse {
            edge: edge.map(edge_state_to_proto),
            state_root: Some(state_root.to_vec()),
        },
        None => GetEdgeResponse {
            edge: None,
            state_root: None,
        },
    }
}

pub(crate) fn work_channel_snapshot_response(
    snapshot: Option<WorkChannelSnapshot>,
) -> GetWorkChannelSnapshotResponse {
    match snapshot {
        Some(snapshot) => GetWorkChannelSnapshotResponse {
            snapshot: Some(latest_block_to_proto(snapshot.block().clone())),
            bond_edge: snapshot.bond().map(kernel_bytes),
            payment_edge: snapshot.payment().map(kernel_bytes),
            lease_slots: snapshot
                .lease_slots()
                .iter()
                .map(|slot| RegistrySlot {
                    chunk: slot.as_ref().map(kernel_bytes),
                })
                .collect(),
            pending_slot: Some(RegistrySlot {
                chunk: snapshot.pending_slot().as_ref().map(kernel_bytes),
            }),
            live_funding: snapshot
                .live_funding()
                .iter()
                .map(|coin| coin.to_bytes().to_vec())
                .collect(),
        },
        None => GetWorkChannelSnapshotResponse {
            snapshot: None,
            bond_edge: None,
            payment_edge: None,
            lease_slots: Vec::new(),
            pending_slot: None,
            live_funding: Vec::new(),
        },
    }
}

/// Returns one kernel object's canonical bytes.
///
/// The wire carries exactly what consensus stored rather than a
/// re-spelling of its fields, so a caller decodes the object with the
/// kernel's own decoder and there is no second definition of an edge on
/// this path.
fn kernel_bytes<E: hellas_kernel::Encode>(value: &E) -> Vec<u8> {
    let mut buf = vec![0_u8; value.encoded_size()];
    let written = value.write_to(&mut buf);
    buf.truncate(written);
    buf
}

fn coin_id_from_bytes(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<hellas_kernel::CoinId, WireStatus> {
    hellas_kernel::CoinId::decode_exact(&bytes).map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            format!(
                "{field} was not {} canonical bytes",
                hellas_kernel::CoinId::LENGTH
            ),
        )
    })
}

fn edge_id_from_bytes(bytes: Vec<u8>, field: &'static str) -> Result<EdgeId, WireStatus> {
    EdgeId::decode_exact(&bytes).map_err(|_| {
        WireStatus::new(
            WireCode::InvalidArgument,
            format!("{field} was not {} canonical bytes", EdgeId::LENGTH),
        )
    })
}

fn edge_state_to_proto(edge: EdgeState) -> ProtoEdgeState {
    ProtoEdgeState {
        value: edge.value,
        reserve: edge.reserve,
        close_fees: Some(KernelFees {
            base: edge.close_fees.base(),
            slot: edge.close_fees.slot(),
            proof: edge.close_fees.proof(),
            lifetime: edge.close_fees.lifetime(),
        }),
        timeout: edge.timeout.get(),
        maker: edge.maker.to_bytes().to_vec(),
        taker: edge.taker.to_bytes().to_vec(),
        terms_hash: edge.terms_hash.to_bytes().to_vec(),
    }
}

fn edges_by_owner_response(edges: Option<OwnerEdges>) -> GetEdgesByOwnerResponse {
    match edges {
        Some(owner_edges) => GetEdgesByOwnerResponse {
            snapshot: Some(latest_block_to_proto(owner_edges.snapshot)),
            edges: owner_edges
                .edges
                .into_iter()
                .map(|edge| EdgeEntry {
                    object_id: edge.object_id.to_vec(),
                    maker: edge.maker.to_bytes().to_vec(),
                    taker: edge.taker.to_bytes().to_vec(),
                })
                .collect(),
        },
        None => GetEdgesByOwnerResponse {
            snapshot: None,
            edges: Vec::new(),
        },
    }
}

fn latest_block_response(latest: Option<LatestBlock>) -> GetLatestBlockResponse {
    GetLatestBlockResponse {
        latest: latest.map(latest_block_to_proto),
    }
}

fn finalized_block_query_from_proto(
    request: pb::GetFinalizedBlockRequest,
) -> Result<FinalizedBlockQuery, WireStatus> {
    match request.query {
        Some(pb::get_finalized_block_request::Query::Height(height)) => {
            Ok(FinalizedBlockQuery::Height(height))
        }
        Some(pb::get_finalized_block_request::Query::Payload(payload)) => Ok(
            FinalizedBlockQuery::Payload(digest_from_bytes(payload, "payload")?),
        ),
        None => Ok(FinalizedBlockQuery::Latest),
    }
}

fn finalized_block_response(block: Option<FinalizedBlock>) -> GetFinalizedBlockResponse {
    GetFinalizedBlockResponse {
        block: block.map(finalized_block_to_proto),
    }
}

fn finalized_block_to_proto(block: FinalizedBlock) -> ProtoFinalizedBlock {
    ProtoFinalizedBlock {
        snapshot: Some(latest_block_to_proto(block.snapshot)),
        block: block.block,
    }
}

fn latest_block_to_proto(latest: LatestBlock) -> FinalizedSnapshot {
    FinalizedSnapshot {
        height: latest.height,
        payload: latest.payload.to_vec(),
        state_root: latest.state_root.to_vec(),
        finalization: latest.finalization,
    }
}

fn proposal_to_proto(proposal: ProposalInfo) -> pb::ProposalInfo {
    pb::ProposalInfo {
        epoch: proposal.epoch,
        view: proposal.view,
        parent_view: proposal.parent_view,
        parent_payload: proposal.parent_payload.to_vec(),
        payload: proposal.payload.to_vec(),
    }
}

fn activity_kind(activity: &ConsensusActivity) -> i32 {
    match activity {
        ConsensusActivity::Notarize { .. } => pb::ActivityEventKind::Notarize as i32,
        ConsensusActivity::Notarization { .. } => pb::ActivityEventKind::Notarization as i32,
        ConsensusActivity::Nullify { .. } => pb::ActivityEventKind::Nullify as i32,
        ConsensusActivity::Nullification { .. } => pb::ActivityEventKind::Nullification as i32,
        ConsensusActivity::Finalization { .. } => pb::ActivityEventKind::Finalization as i32,
    }
}

fn activity_is_requested(urgent_events: &[i32], activity: &ConsensusActivity) -> bool {
    urgent_events.is_empty() || urgent_events.contains(&activity_kind(activity))
}

fn unix_time_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn activity_to_proto(activity: ConsensusActivity) -> ActivityEvent {
    let event = match activity {
        ConsensusActivity::Notarize {
            proposal,
            signer,
            signature,
        } => activity_event::Event::Notarize(NotarizeEvent {
            proposal: Some(proposal_to_proto(proposal)),
            signer,
            signature,
        }),
        ConsensusActivity::Notarization {
            proposal,
            signers,
            certificate,
        } => activity_event::Event::Notarization(NotarizationEvent {
            proposal: Some(proposal_to_proto(proposal)),
            signers,
            certificate,
        }),
        ConsensusActivity::Nullify {
            epoch,
            view,
            signer,
            signature,
        } => activity_event::Event::Nullify(NullifyEvent {
            epoch,
            view,
            signer,
            signature,
        }),
        ConsensusActivity::Nullification {
            epoch,
            view,
            signers,
            certificate,
        } => activity_event::Event::Nullification(NullificationEvent {
            epoch,
            view,
            signers,
            certificate,
        }),
        ConsensusActivity::Finalization {
            proposal,
            signers,
            certificate,
        } => activity_event::Event::Finalization(FinalizationEvent {
            proposal: Some(proposal_to_proto(proposal)),
            signers,
            certificate,
        }),
    };
    ActivityEvent {
        event: Some(event),
        // The validator is the first observer in the transport path. Relays
        // may append later observations, preserving this source timestamp.
        relay_timestamps: vec![unix_time_ms()],
        edge_colo: String::new(),
    }
}

#[cfg(test)]
mod tests;
