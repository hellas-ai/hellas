use crate::domain::{
    Coin, Digest, Encode, ObjectId, SettlementKey, Transaction,
    WebAuthnSignature as DomainWebAuthnSignature,
};
use crate::work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot};
use crate::{
    ConsensusInfo, ConsensusVerifier, EdgeLookup, EdgeRecord, EdgeState, FinalizedBlock,
    FinalizedBlockQuery, LatestBlock, LightClient, OwnerCoins, OwnerEdges, QueryError,
};
use commonware_cryptography::{Hasher, Sha256};
use hellas_kernel::{
    BOND_LEASE_CHUNKS, Decode as _, Edge, Encode as _, Move as KernelMove, RegistryChunk,
    Tx as KernelTx,
};
use hellas_rpc::{
    SubmitTxOutcome as DomainSubmitTxOutcome,
    call::StreamingCall,
    observe::{LEVEL, TARGET, Timing},
    pb::{chain::*, services::light_client::LightClientClientImpl},
};
use hellas_wire::mux::MuxTransport;
use p256::ecdsa::Signature as P256Signature;
use std::collections::BTreeSet;

/// Wire-backed light client that connects to a remote validator or relay.
#[derive(Clone)]
pub struct RemoteLightClient {
    client: LightClientClientImpl<MuxTransport>,
    verifier: Option<ConsensusVerifier>,
}

/// Wire-backed light client whose finalized snapshots are always verified.
///
/// Unlike [`RemoteLightClient`], this type has no unverified state. It is the
/// client for a caller whose decisions require an authenticated finalized
/// history, while callers that deliberately trust their endpoint can keep
/// using [`RemoteLightClient`] unchanged.
#[derive(Clone)]
pub struct VerifiedRemoteLightClient {
    client: LightClientClientImpl<MuxTransport>,
    verifier: ConsensusVerifier,
}

impl RemoteLightClient {
    pub fn new(transport: MuxTransport) -> Self {
        Self {
            client: LightClientClientImpl::new(transport),
            verifier: None,
        }
    }

    /// Connect to a WebSocket endpoint.
    pub async fn connect(addr: impl Into<String>) -> Result<Self, QueryError> {
        let addr = addr.into();
        Ok(Self::new(connect_transport(&addr).await?))
    }

    /// Configure this client to verify finalized snapshots.
    pub fn with_consensus_info(mut self, info: &ConsensusInfo) -> Result<Self, QueryError> {
        self.verifier = Some(ConsensusVerifier::new(info).map_err(QueryError::from)?);
        Ok(self)
    }

    /// Subscribe to the consensus activity stream.
    pub async fn subscribe_activity(
        &self,
        urgent_events: Vec<ActivityEventKind>,
    ) -> Result<StreamingCall<ActivityEvent>, QueryError> {
        self.client
            .subscribe_activity(SubscribeActivityRequest {
                urgent_events: urgent_events.into_iter().map(|k| k as i32).collect(),
            })
            .await
            .map_err(QueryError::from)
    }

    /// Fetch transport/version metadata from the connected validator path.
    pub async fn get_relay_info(&self) -> Result<GetRelayInfoResponse, QueryError> {
        self.client
            .get_relay_info(GetRelayInfoRequest {})
            .await
            .map_err(QueryError::from)
    }
}

impl VerifiedRemoteLightClient {
    /// Build a client that requires `verifier` for every finalized snapshot.
    pub fn new(transport: MuxTransport, verifier: ConsensusVerifier) -> Self {
        Self {
            client: LightClientClientImpl::new(transport),
            verifier,
        }
    }

    /// Connect to a WebSocket endpoint with a required consensus verifier.
    pub async fn connect(
        addr: impl Into<String>,
        verifier: ConsensusVerifier,
    ) -> Result<Self, QueryError> {
        let addr = addr.into();
        Ok(Self::new(connect_transport(&addr).await?, verifier))
    }
}

async fn connect_transport(addr: &str) -> Result<MuxTransport, QueryError> {
    #[cfg(target_family = "wasm")]
    {
        hellas_wire::ws::wasm::connect(addr)
            .await
            .map_err(|error| QueryError::Connect(error.to_string()))
    }
    #[cfg(all(not(target_family = "wasm"), feature = "client"))]
    {
        hellas_wire::ws::connect(addr)
            .await
            .map_err(|error| QueryError::Connect(error.to_string()))
    }
    #[cfg(all(not(target_family = "wasm"), not(feature = "client")))]
    {
        let _ = addr;
        Err(QueryError::Connect(
            "the wasm-client feature can only connect on a wasm target".to_string(),
        ))
    }
}

/// The shared wire operations of the optional and required-verifier clients.
///
/// Keeping this private leaves the public distinction structural: only the
/// two client types above can select whether snapshot verification exists.
trait RemoteClientState: Clone + Send + Sync + 'static {
    fn rpc_client(&self) -> &LightClientClientImpl<MuxTransport>;
    fn consensus_verifier(&self) -> Option<&ConsensusVerifier>;
}

impl RemoteClientState for RemoteLightClient {
    fn rpc_client(&self) -> &LightClientClientImpl<MuxTransport> {
        &self.client
    }

    fn consensus_verifier(&self) -> Option<&ConsensusVerifier> {
        self.verifier.as_ref()
    }
}

impl RemoteClientState for VerifiedRemoteLightClient {
    fn rpc_client(&self) -> &LightClientClientImpl<MuxTransport> {
        &self.client
    }

    fn consensus_verifier(&self) -> Option<&ConsensusVerifier> {
        Some(&self.verifier)
    }
}

impl<C> LightClient for C
where
    C: RemoteClientState,
{
    fn get_state_root(&self) -> impl Future<Output = Result<Option<Digest>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        async move {
            let response = client
                .get_state_root(GetStateRootRequest {})
                .await
                .map_err(QueryError::from)?;
            match response.state_root {
                Some(bytes) => {
                    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                        QueryError::Remote("state_root was not 32 bytes".to_string())
                    })?;
                    Ok(Some(Digest::from(arr)))
                }
                None => Ok(None),
            }
        }
    }

    fn get_proof(
        &self,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        async move {
            let response = client
                .get_proof(GetProofRequest {
                    object_id: object_id.to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            Ok(response.proof)
        }
    }

    fn get_coin(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<Coin>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        async move {
            let response = client
                .get_coin(GetCoinRequest {
                    payload: payload.to_vec(),
                    object_id: object_id.to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            match (response.owner, response.value) {
                (Some(owner_bytes), Some(value)) => {
                    let actual = owner_bytes.len();
                    let raw: [u8; SettlementKey::LENGTH] =
                        owner_bytes.try_into().map_err(|_| {
                            QueryError::Remote(format!(
                                "owner settlement key was {} bytes, got {actual}",
                                SettlementKey::LENGTH
                            ))
                        })?;
                    Ok(Some(Coin {
                        owner: SettlementKey::from_bytes(raw),
                        value,
                    }))
                }
                _ => Ok(None),
            }
        }
    }

    fn get_edge(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<EdgeLookup>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        async move {
            let response = client
                .get_edge(GetEdgeRequest {
                    payload: payload.to_vec(),
                    object_id: object_id.to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            edge_lookup_from_proto(response)
        }
    }

    fn get_finalization(
        &self,
        payload: Digest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        async move {
            let response = client
                .get_finalization(GetFinalizationRequest {
                    payload: payload.to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            Ok(response.certificate)
        }
    }

    fn get_latest_block(
        &self,
    ) -> impl Future<Output = Result<Option<LatestBlock>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        let verifier = self.consensus_verifier().cloned();
        async move {
            let response = client
                .get_latest_block(GetLatestBlockRequest {})
                .await
                .map_err(QueryError::from)?;
            response
                .latest
                .map(|snapshot| verified_latest_block_from_proto(snapshot, verifier.as_ref()))
                .transpose()
        }
    }

    fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> impl Future<Output = Result<Option<FinalizedBlock>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        let verifier = self.consensus_verifier().cloned();
        async move {
            let response = client
                .get_finalized_block(finalized_block_query_to_proto(query))
                .await
                .map_err(QueryError::from)?;
            response
                .block
                .map(|block| verified_finalized_block_from_proto(block, verifier.as_ref()))
                .transpose()
        }
    }

    fn submit_tx(
        &self,
        tx: Transaction,
    ) -> impl Future<Output = Result<DomainSubmitTxOutcome, QueryError>> + Send {
        let client = self.rpc_client().clone();
        async move {
            // `rpc_ms`: one submission to one validator, measured where a
            // submitter actually waits — the whole call, not the part of
            // it this process can see. §4 maximises it over six
            // validators, and the maximum is the reader's arithmetic:
            // this client speaks to one validator, so one sample is one
            // validator's term. The server's own `response_worker_ms`
            // and `validation_ms` run inside this interval rather than
            // beside it, so adding all three over-counts — which is the
            // safe direction for a floor that fails closed.
            let responding = matches!(
                &tx,
                Transaction::Kernel(KernelTx::Move {
                    action: KernelMove::RespondPaymentClose(_),
                })
            );
            let called = Timing::start();
            let outcome = async {
                if let Transaction::Kernel(KernelTx::Move {
                    action: KernelMove::RespondPaymentClose(response),
                }) = tx
                {
                    let mut bytes =
                        vec![0_u8; hellas_kernel::PaymentCloseResponse::MAX_ENCODED_SIZE];
                    let written = response.write_to(&mut bytes);
                    bytes.truncate(written);
                    let response = client
                        .submit_work_response(SubmitWorkResponseRequest { response: bytes })
                        .await
                        .map_err(QueryError::from)?;
                    return submit_tx_outcome_from_proto(response.outcome);
                }
                let req = transaction_to_proto(tx)?;
                let response = client.submit_tx(req).await.map_err(QueryError::from)?;
                submit_tx_outcome_from_proto(response.outcome)
            }
            .await;
            if let Some(ms) = called.ms() {
                tracing::event!(
                    name: "rpc_ms",
                    target: TARGET,
                    LEVEL,
                    method = if responding { "SubmitWorkResponse" } else { "SubmitTx" },
                    answered = outcome.is_ok(),
                    ms,
                );
            }
            outcome
        }
    }

    fn get_validators(&self) -> impl Future<Output = Result<Vec<String>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        async move {
            let resp = client
                .get_validators(GetValidatorsRequest {})
                .await
                .map_err(QueryError::from)?;
            Ok(resp.validators)
        }
    }

    fn get_consensus_info(&self) -> impl Future<Output = Result<ConsensusInfo, QueryError>> + Send {
        let client = self.rpc_client().clone();
        async move {
            let resp = client
                .get_consensus_info(GetConsensusInfoRequest {})
                .await
                .map_err(QueryError::from)?;
            if resp.threshold_identity.is_empty() {
                return Err(QueryError::Remote(
                    "threshold identity was empty".to_string(),
                ));
            }
            if resp.network_id.is_empty() {
                return Err(QueryError::Remote("network id was empty".to_string()));
            }
            Ok(ConsensusInfo {
                validators: resp.validators,
                threshold_identity: resp.threshold_identity,
                network_id: resp.network_id,
            })
        }
    }

    fn get_coins_by_owner(
        &self,
        owner: SettlementKey,
    ) -> impl Future<Output = Result<Option<OwnerCoins>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        let verifier = self.consensus_verifier().cloned();
        async move {
            let resp = client
                .get_coins_by_owner(GetCoinsByOwnerRequest {
                    owner: owner.to_bytes().to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            let Some(snapshot) = resp.snapshot else {
                if resp.coins.is_empty() {
                    return Ok(None);
                }
                return Err(QueryError::Remote(
                    "GetCoinsByOwnerResponse had coins without a snapshot".to_string(),
                ));
            };
            let snapshot = verified_latest_block_from_proto(snapshot, verifier.as_ref())?;
            let coins = resp
                .coins
                .into_iter()
                .map(|entry| {
                    let arr: [u8; 32] = entry.object_id.try_into().map_err(|_| {
                        QueryError::Remote("object_id was not 32 bytes".to_string())
                    })?;
                    Ok((Digest::from(arr), entry.value))
                })
                .collect::<Result<Vec<_>, QueryError>>()?;
            Ok(Some(OwnerCoins { snapshot, coins }))
        }
    }

    fn get_edges_by_owner(
        &self,
        owner: SettlementKey,
    ) -> impl Future<Output = Result<Option<OwnerEdges>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        let verifier = self.consensus_verifier().cloned();
        async move {
            let resp = client
                .get_edges_by_owner(GetEdgesByOwnerRequest {
                    owner: owner.to_bytes().to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            owner_edges_from_proto(owner, resp, verifier.as_ref())
        }
    }
}

fn edge_lookup_from_proto(response: GetEdgeResponse) -> Result<Option<EdgeLookup>, QueryError> {
    match response.state_root {
        Some(state_root) => Ok(Some(EdgeLookup {
            state_root: digest_from_wire(state_root, "state_root")?,
            edge: response.edge.map(edge_state_from_proto).transpose()?,
        })),
        None if response.edge.is_none() => Ok(None),
        None => Err(QueryError::Remote(
            "GetEdgeResponse had an edge without a state root".to_string(),
        )),
    }
}

fn owner_edges_from_proto(
    owner: SettlementKey,
    response: GetEdgesByOwnerResponse,
    verifier: Option<&ConsensusVerifier>,
) -> Result<Option<OwnerEdges>, QueryError> {
    let Some(snapshot) = response.snapshot else {
        if response.edges.is_empty() {
            return Ok(None);
        }
        return Err(QueryError::Remote(
            "GetEdgesByOwnerResponse had edges without a snapshot".to_string(),
        ));
    };
    let snapshot = verified_latest_block_from_proto(snapshot, verifier)?;
    let mut seen = BTreeSet::new();
    let mut edges = Vec::with_capacity(response.edges.len());
    for edge in response.edges {
        let edge = EdgeRecord {
            object_id: digest_from_wire(edge.object_id, "object_id")?,
            maker: settlement_key_from_wire(edge.maker, "maker")?,
            taker: settlement_key_from_wire(edge.taker, "taker")?,
        };
        if edge.maker != owner && edge.taker != owner {
            return Err(QueryError::Remote(
                "GetEdgesByOwnerResponse contained an edge unrelated to the requested owner"
                    .to_string(),
            ));
        }
        if !seen.insert(edge.object_id) {
            return Err(QueryError::Remote(
                "GetEdgesByOwnerResponse contained a duplicate object_id".to_string(),
            ));
        }
        edges.push(edge);
    }
    Ok(Some(OwnerEdges { snapshot, edges }))
}

impl<C> FinalizedWorkView for C
where
    C: RemoteClientState,
{
    fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> impl Future<Output = Result<Option<WorkChannelSnapshot>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        let verifier = self.consensus_verifier().cloned();
        async move {
            let response = client
                .get_work_channel_snapshot(GetWorkChannelSnapshotRequest {
                    bond_edge: query.bond_edge.to_bytes().to_vec(),
                    payment_edge: query.payment_edge.to_bytes().to_vec(),
                    funding_coins: query
                        .funding
                        .iter()
                        .map(|coin| coin.to_bytes().to_vec())
                        .collect(),
                })
                .await
                .map_err(QueryError::from)?;
            work_channel_snapshot_from_proto(query, response, verifier.as_ref())
        }
    }
}

/// Reads one channel snapshot off the wire.
///
/// The chunk count is checked exactly rather than padded or truncated: a
/// reply carrying one lease slot is not a lease half-read, it is a peer
/// answering a question this build did not ask, and treating its missing
/// slot as empty would read a live lease as absent.
///
/// The pending-close slot is required for the same reason, and it is the
/// half that matters more: an empty slot is a *permission* — it is what
/// says no contest is open and new work may be admitted. A reply that
/// omitted the field entirely would read as that permission. The server
/// always sends the message, present or empty, so a missing one is a
/// peer this build does not agree with.
///
/// The live-funding list is checked against the coins the query named,
/// for the same class of reason and in the opposite direction: a coin
/// reported live that was never asked about is a peer answering some
/// other transaction's preflight, and there is nothing in an
/// unrequested coin id that this build could have checked. A coin the
/// query named and the reply omits is *not* refused — that is exactly
/// how a spent coin is reported.
pub(crate) fn work_channel_snapshot_from_proto(
    query: WorkChannelQuery,
    response: GetWorkChannelSnapshotResponse,
    verifier: Option<&ConsensusVerifier>,
) -> Result<Option<WorkChannelSnapshot>, QueryError> {
    let Some(snapshot) = response.snapshot else {
        return Ok(None);
    };
    let block = verified_latest_block_from_proto(snapshot, verifier)?;

    let slots = response.lease_slots.len();
    let expected = usize::from(BOND_LEASE_CHUNKS);
    if slots != expected {
        return Err(QueryError::Remote(format!(
            "work channel snapshot carried {slots} lease slots, expected {expected}"
        )));
    }
    let mut lease_slots = [None, None];
    for (slot, wire) in lease_slots.iter_mut().zip(response.lease_slots) {
        *slot = registry_chunk_from_wire(wire.chunk, "lease slot")?;
    }
    let Some(pending) = response.pending_slot else {
        return Err(QueryError::Remote(
            "work channel snapshot carried no pending-close slot".to_string(),
        ));
    };
    let pending_slot = registry_chunk_from_wire(pending.chunk, "pending-close slot")?;

    let mut live_funding = std::collections::BTreeSet::new();
    for bytes in response.live_funding {
        let coin = hellas_kernel::CoinId::decode_exact(&bytes)
            .map_err(|_| QueryError::Remote("live funding was not a coin id".to_string()))?;
        if !query.funding.contains(&coin) {
            return Err(QueryError::Remote(
                "work channel snapshot reported a live coin the query did not name".to_string(),
            ));
        }
        live_funding.insert(coin);
    }

    Ok(Some(WorkChannelSnapshot::new(
        query,
        block,
        edge_from_wire(response.bond_edge, "bond edge")?,
        edge_from_wire(response.payment_edge, "payment edge")?,
        lease_slots,
        pending_slot,
        live_funding,
    )))
}

fn edge_from_wire(bytes: Option<Vec<u8>>, field: &'static str) -> Result<Option<Edge>, QueryError> {
    bytes
        .map(|bytes| {
            Edge::decode_exact(&bytes)
                .map_err(|_| QueryError::Remote(format!("{field} was not a canonical kernel edge")))
        })
        .transpose()
}

fn registry_chunk_from_wire(
    bytes: Option<Vec<u8>>,
    field: &'static str,
) -> Result<Option<RegistryChunk>, QueryError> {
    bytes
        .map(|bytes| {
            RegistryChunk::decode_exact(&bytes).map_err(|_| {
                QueryError::Remote(format!("{field} was not a canonical registry chunk"))
            })
        })
        .transpose()
}

fn digest_from_wire(bytes: Vec<u8>, field: &'static str) -> Result<Digest, QueryError> {
    let actual = bytes.len();
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        QueryError::Remote(format!("{field} was expected to be 32 bytes, got {actual}"))
    })?;
    Ok(Digest::from(raw))
}

fn settlement_key_from_wire(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<SettlementKey, QueryError> {
    let actual = bytes.len();
    let raw: [u8; SettlementKey::LENGTH] = bytes.try_into().map_err(|_| {
        QueryError::Remote(format!(
            "{field} settlement key was expected to be {} bytes, got {actual}",
            SettlementKey::LENGTH
        ))
    })?;
    Ok(SettlementKey::from_bytes(raw))
}

fn edge_state_from_proto(edge: hellas_rpc::pb::chain::EdgeState) -> Result<EdgeState, QueryError> {
    let fees = edge
        .close_fees
        .ok_or_else(|| QueryError::Remote("edge close_fees were missing".to_string()))?;
    let terms_hash = hellas_kernel::TermsHash::decode_exact(&edge.terms_hash)
        .map_err(|_| QueryError::Remote("terms_hash was not 32 canonical bytes".to_string()))?;
    Ok(EdgeState {
        value: edge.value,
        reserve: edge.reserve,
        close_fees: hellas_kernel::Fees::new(fees.base, fees.slot, fees.proof, fees.lifetime),
        timeout: hellas_kernel::BlockHeight::new(edge.timeout),
        maker: settlement_key_from_wire(edge.maker, "maker")?,
        taker: settlement_key_from_wire(edge.taker, "taker")?,
        terms_hash,
    })
}

fn verified_latest_block_from_proto(
    snapshot: FinalizedSnapshot,
    verifier: Option<&ConsensusVerifier>,
) -> Result<LatestBlock, QueryError> {
    let latest = latest_block_from_proto(snapshot)?;
    if let Some(verifier) = verifier {
        verifier
            .verify_snapshot(&latest)
            .map_err(QueryError::from)?;
    }
    Ok(latest)
}

fn verified_finalized_block_from_proto(
    block: hellas_rpc::pb::chain::FinalizedBlock,
    verifier: Option<&ConsensusVerifier>,
) -> Result<FinalizedBlock, QueryError> {
    let Some(snapshot) = block.snapshot else {
        return Err(QueryError::Remote(
            "FinalizedBlock had no snapshot".to_string(),
        ));
    };
    let snapshot = verified_latest_block_from_proto(snapshot, verifier)?;
    if Sha256::hash(&block.block) != snapshot.payload {
        return Err(QueryError::Remote(
            "block bytes did not match finalized payload".to_string(),
        ));
    }
    Ok(FinalizedBlock {
        snapshot,
        block: block.block,
    })
}

fn finalized_block_query_to_proto(query: FinalizedBlockQuery) -> GetFinalizedBlockRequest {
    let query = match query {
        FinalizedBlockQuery::Latest => None,
        FinalizedBlockQuery::Height(height) => {
            Some(get_finalized_block_request::Query::Height(height))
        }
        FinalizedBlockQuery::Payload(payload) => Some(get_finalized_block_request::Query::Payload(
            payload.to_vec(),
        )),
    };
    GetFinalizedBlockRequest { query }
}

fn latest_block_from_proto(snapshot: FinalizedSnapshot) -> Result<LatestBlock, QueryError> {
    let payload: [u8; 32] = snapshot
        .payload
        .try_into()
        .map_err(|_| QueryError::Remote("payload was not 32 bytes".to_string()))?;
    let state_root: [u8; 32] = snapshot
        .state_root
        .try_into()
        .map_err(|_| QueryError::Remote("state_root was not 32 bytes".to_string()))?;
    if snapshot.finalization.is_empty() {
        return Err(QueryError::Remote("finalization was empty".to_string()));
    }
    Ok(LatestBlock {
        height: snapshot.height,
        payload: Digest::from(payload),
        state_root: Digest::from(state_root),
        finalization: snapshot.finalization,
    })
}

fn transaction_to_proto(tx: Transaction) -> Result<SubmitTxRequest, QueryError> {
    if crate::light_client::canonical_submission_size(&tx) > crate::MAX_CANONICAL_TRANSACTION_BYTES
    {
        return Err(QueryError::InvalidTransaction(format!(
            "canonical transaction exceeds {} bytes",
            crate::MAX_CANONICAL_TRANSACTION_BYTES,
        )));
    }

    let signature_to_der = |signature: &DomainWebAuthnSignature| {
        let raw = signature.signature.encode();
        let parsed = P256Signature::from_slice(raw.as_ref())
            .expect("internal transaction signature should always be canonical 64-byte secp256r1");
        parsed.to_der().as_bytes().to_vec()
    };

    let tx_oneof = match tx {
        Transaction::Transfer {
            input,
            recipient,
            amount,
            signature,
        } => submit_tx_request::Tx::Transfer(TransferTx {
            input: input.to_vec(),
            recipient: recipient.encode().to_vec(),
            amount,
            signature: Some(WebAuthnSignature {
                ecdsa_signature: signature_to_der(&signature),
                authenticator_data: signature.authenticator_data.as_slice().to_vec(),
                client_data_json: signature.client_data_json.as_slice().to_vec(),
            }),
        }),
        Transaction::MergeCoin { inputs, signature } => {
            submit_tx_request::Tx::MergeCoin(MergeCoinTx {
                inputs: inputs.iter().map(|i| i.to_vec()).collect(),
                signature: Some(WebAuthnSignature {
                    ecdsa_signature: signature_to_der(&signature),
                    authenticator_data: signature.authenticator_data.as_slice().to_vec(),
                    client_data_json: signature.client_data_json.as_slice().to_vec(),
                }),
            })
        }
        Transaction::Kernel(tx) => {
            let mut bytes = vec![0_u8; hellas_kernel::Tx::MAX_ENCODED_SIZE];
            let written = tx.write_to(&mut bytes);
            bytes.truncate(written);
            submit_tx_request::Tx::KernelTx(bytes)
        }
    };
    Ok(SubmitTxRequest { tx: Some(tx_oneof) })
}

fn submit_tx_outcome_from_proto(value: i32) -> Result<DomainSubmitTxOutcome, QueryError> {
    match SubmitTxOutcome::try_from(value) {
        Ok(SubmitTxOutcome::Enqueued) => Ok(DomainSubmitTxOutcome::Enqueued),
        Ok(SubmitTxOutcome::Duplicate) => Ok(DomainSubmitTxOutcome::Duplicate),
        Ok(SubmitTxOutcome::Full) => Ok(DomainSubmitTxOutcome::Full),
        Ok(SubmitTxOutcome::ValidationRejected) => Ok(DomainSubmitTxOutcome::ValidationRejected),
        Ok(SubmitTxOutcome::Unspecified) => Err(QueryError::Remote(
            "submit response contained an unspecified outcome".to_string(),
        )),
        Err(_) => Err(QueryError::Remote(format!(
            "submit response contained unknown outcome {value}",
        ))),
    }
}

#[cfg(test)]
mod tests;
