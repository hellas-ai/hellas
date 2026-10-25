use crate::domain::{Coin, Digest, SettlementKey, Transaction};
use crate::{
    ConsensusActivity, ConsensusInfo, EdgeLookup, EdgeState, FinalizedBlock, FinalizedBlockQuery,
    LatestBlock, LightClient as LightClientApi, MAX_CANONICAL_TRANSACTION_BYTES, OwnerEdges,
    ProposalInfo,
};
use futures_util::StreamExt as _;
use hellas_auth::authority::UnixMillis;
use hellas_kernel::{Decode as _, Move as KernelMove, Tx as KernelTx};
use hellas_rpc::pb::{
    chain::{
        self as pb, ActivityEvent, CoinEntry, EdgeEntry, EdgeState as ProtoEdgeState,
        FinalizationEvent, FinalizedBlock as ProtoFinalizedBlock, FinalizedSnapshot,
        GetCoinResponse, GetCoinsResponse, GetConsensusInfoResponse, GetEdgeResponse,
        GetEdgesByOwnerResponse, GetFinalizationResponse, GetFinalizedBlockResponse,
        GetLatestBlockResponse, GetProofResponse, GetRelayInfoResponse, GetStateRootResponse,
        GetValidatorsResponse, KernelFees, NotarizationEvent, NotarizeEvent, NullificationEvent,
        NullifyEvent, SubmitTxOutcome as ProtoSubmitTxOutcome, SubmitTxResponse,
        SubmitWorkResponseRequest, activity_event, submit_tx_request,
    },
    services::light_client::{LightClientHandler, LightClientServer},
};
use hellas_rpc::{
    SubmitTxOutcome,
    call::{GeneralSubmitRoute, WorkResponseRoute},
};
use hellas_wire::{PeerIdentity, StreamTransport, TransportContext, WireCode, WireStatus};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, broadcast},
    task::{JoinHandle, JoinSet},
    time::{Duration, Instant},
};
use tokio_stream::wrappers::BroadcastStream;
use tokio_tungstenite::accept_async_with_config;
use tracing::{info, warn};

const MAX_CONNECTIONS: usize = 128;
const MAX_CONNECTIONS_PER_IP: usize = 4;
const MAX_CONNECTIONS_PER_SUBNET: usize = 16;
const MAX_DISPATCHES: usize = 16;
const MAX_SUBSCRIPTIONS: usize = 8;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(15 * 60);

type ActivityStream = hellas_rpc::call::ResponseStream<ActivityEvent>;
pub type LightClientServerError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Clone)]
pub struct LightClientRpc<T> {
    client: T,
    activity_tx: broadcast::Sender<ConsensusActivity>,
    state: LightClientRpcState,
    subscriptions: Arc<Semaphore>,
}

/// Node-scoped concurrency and source-accounting state for light-client RPCs.
///
/// Every transport served by one node must receive a clone of the same state,
/// so reconnecting or opening another connection cannot multiply its bounds.
#[derive(Clone)]
pub struct LightClientRpcState {
    response_route: Arc<WorkResponseRoute>,
    general_route: Arc<GeneralSubmitRoute>,
    general_sources: Arc<tokio::sync::Mutex<SubmissionSourceTable>>,
    response_sources: Arc<tokio::sync::Mutex<SubmissionSourceTable>>,
}

impl Default for LightClientRpcState {
    fn default() -> Self {
        Self {
            response_route: Arc::new(WorkResponseRoute::default()),
            general_route: Arc::new(GeneralSubmitRoute::default()),
            general_sources: Arc::new(tokio::sync::Mutex::new(SubmissionSourceTable::default())),
            response_sources: Arc::new(tokio::sync::Mutex::new(SubmissionSourceTable::default())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SubmissionSourceKey {
    Anonymous,
    Peer(PeerIdentity),
}

#[derive(Default)]
struct SubmissionSourceTable {
    height: Option<u64>,
    attempts: HashMap<SubmissionSourceKey, u8>,
}

impl SubmissionSourceTable {
    fn consume(&mut self, context: &TransportContext, height: u64) -> bool {
        if self.height.is_none_or(|observed| height > observed) {
            self.height = Some(height);
            self.attempts.clear();
        }
        let key = context
            .vouched_peer()
            .map_or(SubmissionSourceKey::Anonymous, SubmissionSourceKey::Peer);
        if let Some(attempts) = self.attempts.get_mut(&key) {
            if *attempts >= 8 {
                return false;
            }
            *attempts += 1;
            return true;
        }
        if self.attempts.len() >= 256 {
            return false;
        }
        self.attempts.insert(key, 1);
        true
    }
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
            subscriptions: Arc::new(Semaphore::new(MAX_SUBSCRIPTIONS)),
        }
    }
}

pub async fn spawn_light_client_server<T>(
    addr: SocketAddr,
    client: T,
    activity_tx: broadcast::Sender<ConsensusActivity>,
    state: LightClientRpcState,
) -> io::Result<JoinHandle<()>>
where
    T: LightClientApi,
{
    let listener = TcpListener::bind(addr).await?;
    Ok(tokio::spawn(serve_listener(
        listener,
        client,
        activity_tx,
        state,
        hellas_wire::admission::ConnectionSlots::new(
            MAX_CONNECTIONS,
            MAX_CONNECTIONS_PER_IP,
            MAX_CONNECTIONS_PER_SUBNET,
        ),
    )))
}

async fn serve_listener<T: LightClientApi>(
    listener: TcpListener,
    client: T,
    activity_tx: broadcast::Sender<ConsensusActivity>,
    state: LightClientRpcState,
    slots: hellas_wire::admission::ConnectionSlots,
) {
    info!(addr = ?listener.local_addr(), "light client rpc server started");
    let mut connections = JoinSet::new();
    let mut handshakes = hellas_wire::admission::Handshakes::default();
    let epoch = Instant::now();
    loop {
        let accepted = tokio::select! {
            _ = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(connection) => connection,
            Err(err) => {
                warn!(?err, "light client rpc accept failed");
                continue;
            }
        };
        let Some(slot) = slots.try_acquire(Some(peer.ip())) else {
            continue;
        };
        if !handshakes.admit(Some(peer.ip()), epoch.elapsed().as_millis() as u64) {
            continue;
        }
        let service =
            LightClientRpc::with_state(client.clone(), activity_tx.clone(), state.clone());
        connections.spawn(async move {
            let _slot = slot;
            if let Err(err) = serve_connection(stream, service).await {
                warn!(?err, %peer, "light client rpc connection failed");
            }
        });
    }
}

async fn serve_connection<T>(
    stream: TcpStream,
    service: LightClientRpc<T>,
) -> Result<(), LightClientServerError>
where
    T: LightClientApi,
{
    let ws = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        accept_async_with_config(stream, Some(hellas_wire::ws::websocket_config())),
    )
    .await??;
    let transport = hellas_wire::ws::accept_upgraded(ws, None)?;
    serve_light_client_transport(transport, service).await
}

/// No new RPC Open within the idle deadline ends the connection, including quiet
/// subscriptions. Clients can reopen them; keepalives do not extend this budget.
struct IdleTransport<T>(T);
impl<T: StreamTransport + Sync> StreamTransport for IdleTransport<T> {
    type Stream = T::Stream;
    type Error = T::Error;
    fn context(&self) -> TransportContext {
        self.0.context()
    }
    async fn open(
        &self,
        method: u32,
        headers: hellas_wire::Metadata,
    ) -> Result<Self::Stream, Self::Error> {
        self.0.open(method, headers).await
    }
    async fn accept(&self) -> Result<Option<hellas_wire::Inbound<Self::Stream>>, Self::Error> {
        tokio::time::timeout(IDLE_TIMEOUT, self.0.accept())
            .await
            .unwrap_or(Ok(None))
    }
}

/// Serve the typed light-client API over any inbound-stream transport.
///
/// Subscriptions have their own smaller budget so they leave room for unary
/// calls. Idle and lifetime deadlines bound silent and continuously busy peers.
pub async fn serve_light_client_transport<T, C>(
    transport: T,
    mut service: LightClientRpc<C>,
) -> Result<(), LightClientServerError>
where
    T: StreamTransport + Send + Sync + 'static,
    T::Stream: 'static,
    <T::Stream as hellas_wire::Stream>::RecvHalf: 'static,
    <T::Stream as hellas_wire::Stream>::SendHalf: 'static,
    C: LightClientApi,
{
    service.subscriptions = Arc::new(Semaphore::new(MAX_SUBSCRIPTIONS));
    let serving = hellas_wire::serve_dispatched(
        IdleTransport(transport),
        "light-client",
        Some(MAX_DISPATCHES),
        || {
            LightClientServer(
                service.clone(),
                service.state.response_route.clone(),
                service.state.general_route.clone(),
            )
        },
    );
    if let Ok(result) = tokio::time::timeout(MAX_CONNECTION_LIFETIME, serving).await {
        result?;
    }
    Ok(())
}

#[allow(refining_impl_trait)]
impl<T> LightClientHandler for LightClientRpc<T>
where
    T: LightClientApi,
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

    fn get_finalization(
        &self,
        request: pb::GetFinalizationRequest,
    ) -> impl Future<Output = Result<GetFinalizationResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move { read_finalization(request, |payload| client.get_finalization(payload)).await }
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
        async move { read_finalized_block(request, |query| client.get_finalized_block(query)).await }
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
            if !self
                .state
                .general_sources
                .lock()
                .await
                .consume(&context, height)
            {
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
        context: TransportContext,
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
            let height = client
                .get_latest_block()
                .await
                .map_err(WireStatus::from)?
                .map_or(0, |latest| latest.height);
            if !self
                .state
                .response_sources
                .lock()
                .await
                .consume(&context, height)
            {
                return Ok(SubmitTxResponse {
                    outcome: ProtoSubmitTxOutcome::Full as i32,
                });
            }
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
        let subscriptions = self.subscriptions.clone();
        async move {
            let permit = subscriptions.try_acquire_owned().map_err(|_| {
                WireStatus::new(
                    WireCode::ResourceExhausted,
                    "connection subscription capacity exhausted",
                )
            })?;
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
            Ok(ActivityStream::new(stream.map(move |event| {
                // The stream owns its subscription budget through cancellation.
                let _permit = &permit;
                event
            })))
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
    ) -> impl Future<Output = Result<GetCoinsResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let owner = settlement_key_from_bytes(request.owner, "owner")?;
            let response = client
                .get_coins_by_owner(owner)
                .await
                .map_err(WireStatus::from)?;
            Ok(coin_listing_response(response))
        }
    }

    fn get_coins_by_delegate(
        &self,
        request: pb::GetCoinsByDelegateRequest,
    ) -> impl Future<Output = Result<GetCoinsResponse, WireStatus>> + Send {
        let client = self.client.clone();
        async move {
            let delegate = settlement_key_from_bytes(request.delegate, "delegate")?;
            let response = client
                .get_coins_by_delegate(delegate)
                .await
                .map_err(WireStatus::from)?;
            Ok(coin_listing_response(response))
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

fn coin_response(coin: Option<Coin>) -> GetCoinResponse {
    match coin {
        Some(Coin {
            owner,
            delegate,
            value,
        }) => GetCoinResponse {
            owner: Some(owner.to_bytes().to_vec()),
            value: Some(value),
            delegate: delegate.map(|delegate| delegate.to_bytes().to_vec()),
        },
        None => GetCoinResponse {
            owner: None,
            value: None,
            delegate: None,
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

pub(crate) fn finalized_block_query_from_proto(
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

pub(crate) fn finalized_block_response(block: Option<FinalizedBlock>) -> GetFinalizedBlockResponse {
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
    UnixMillis::now().unwrap_or_default().0
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

#[cfg(all(test, feature = "validator"))]
mod tests;

/// Shared finalized read semantics for LightClient and ChainSync.
pub(crate) async fn read_finalized_block<F, R>(
    request: pb::GetFinalizedBlockRequest,
    read: F,
) -> Result<GetFinalizedBlockResponse, WireStatus>
where
    F: FnOnce(FinalizedBlockQuery) -> R,
    R: Future<Output = Result<Option<FinalizedBlock>, crate::QueryError>>,
{
    Ok(finalized_block_response(
        read(finalized_block_query_from_proto(request)?).await?,
    ))
}
pub(crate) async fn read_finalization<F, R>(
    request: pb::GetFinalizationRequest,
    read: F,
) -> Result<GetFinalizationResponse, WireStatus>
where
    F: FnOnce(Digest) -> R,
    R: Future<Output = Result<Option<Vec<u8>>, crate::QueryError>>,
{
    Ok(GetFinalizationResponse {
        certificate: read(digest_from_bytes(request.payload, "payload")?).await?,
    })
}

fn coin_listing_response(response: Option<crate::CoinListing>) -> GetCoinsResponse {
    match response {
        Some(listing) => GetCoinsResponse {
            snapshot: Some(latest_block_to_proto(listing.snapshot)),
            coins: listing
                .coins
                .into_iter()
                .map(|(object_id, value)| CoinEntry {
                    object_id: object_id.to_vec(),
                    value,
                })
                .collect(),
        },
        None => GetCoinsResponse {
            snapshot: None,
            coins: Vec::new(),
        },
    }
}
