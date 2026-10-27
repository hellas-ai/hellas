use crate::domain::{Coin, Digest, ObjectId, SettlementKey, Transaction};
use crate::{
    CoinListing, ConsensusInfo, ConsensusVerifier, EdgeLookup, EdgeRecord, EdgeState,
    FinalizedBlock, FinalizedBlockQuery, LatestBlock, LightClient, OwnerEdges, QueryError,
};
use commonware_cryptography::{Hasher, Sha256};
use hellas_kernel::{Decode as _, Encode as _, Move as KernelMove, Tx as KernelTx};
use hellas_rpc::{
    SubmitTxOutcome as DomainSubmitTxOutcome,
    call::StreamingCall,
    observe::{LEVEL, TARGET, Timing},
    pb::{chain::*, services::light_client::LightClientClientImpl},
};
use hellas_wire::mux::MuxTransport;
use std::collections::BTreeSet;

mod objects;

/// Wire-backed light client that connects to a remote validator or relay.
#[derive(Clone)]
pub struct RemoteLightClient {
    client: LightClientClientImpl<MuxTransport>,
    verifier: Option<ConsensusVerifier>,
    finalized_height: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl RemoteLightClient {
    pub(crate) fn pinned_network(&self) -> Result<hellas_kernel::NetworkId, QueryError> {
        self.verifier
            .as_ref()
            .map(ConsensusVerifier::network)
            .ok_or_else(|| QueryError::Remote("a pinned consensus verifier is required".into()))
    }

    /// Notifications only wake the caller; subsequent reads verify their data.
    pub async fn subscribe_finalized(
        &self,
    ) -> Result<StreamingCall<GetFinalizedBlockResponse>, QueryError> {
        self.rpc_client()
            .subscribe_finalized(GetLatestBlockRequest {})
            .await
            .map_err(QueryError::from)
    }

    pub fn new(transport: MuxTransport) -> Self {
        Self {
            client: LightClientClientImpl::new(transport),
            verifier: None,
            finalized_height: Default::default(),
        }
    }

    /// Connect to a WebSocket endpoint.
    pub async fn connect(addr: impl Into<String>) -> Result<Self, QueryError> {
        let addr = addr.into();
        Ok(Self::new(connect_transport(&addr).await?))
    }

    /// Verify snapshots with an independently provisioned consensus authority.
    /// Coin and edge records still need state proofs; this authenticates their snapshot only.
    pub fn with_consensus_verifier(mut self, verifier: ConsensusVerifier) -> Self {
        self.verifier = Some(verifier);
        self.finalized_height = Default::default();
        self
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

fn record_progress(
    progress: &std::sync::atomic::AtomicU64,
    height: u64,
    latest: bool,
) -> Result<(), QueryError> {
    use std::sync::atomic::Ordering;
    let known = progress.fetch_max(height, Ordering::AcqRel);
    if latest && height < known {
        return Err(QueryError::StateUnavailable(format!(
            "remote tip {height} is behind verified height {known}"
        )));
    }
    Ok(())
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

impl RemoteLightClient {
    fn rpc_client(&self) -> &LightClientClientImpl<MuxTransport> {
        &self.client
    }

    fn consensus_verifier(&self) -> Option<&ConsensusVerifier> {
        self.verifier.as_ref()
    }
}

impl LightClient for RemoteLightClient {
    async fn get_operations(
        &self,
        request: GetOperationsRequest,
    ) -> Result<GetOperationsResponse, QueryError> {
        self.rpc_client()
            .get_operations(request)
            .await
            .map_err(QueryError::from)
    }

    async fn get_objects(
        &self,
        keys: Vec<crate::domain::ObjectId>,
    ) -> Result<Option<crate::light_client::ObjectSnapshot>, QueryError> {
        objects::read(self, keys).await
    }

    fn get_state_root(&self) -> impl Future<Output = Result<Option<Digest>, QueryError>> + Send {
        let client = self.clone();
        async move {
            if client.verifier.is_some() {
                return Ok(client
                    .get_latest_block()
                    .await?
                    .map(|snapshot| snapshot.state_root));
            }
            let response = client
                .rpc_client()
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
                (Some(owner), Some(value)) => Ok(Some(Coin {
                    owner: settlement_key_from_wire(owner, "owner")?,
                    delegate: response
                        .delegate
                        .map(|delegate| settlement_key_from_wire(delegate, "delegate"))
                        .transpose()?,
                    value,
                })),
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
        let progress = self.finalized_height.clone();
        let client = self.rpc_client().clone();
        let verifier = self.consensus_verifier().cloned();
        async move {
            let response = client
                .get_latest_block(GetLatestBlockRequest {})
                .await
                .map_err(QueryError::from)?;
            let latest = response.latest.map(latest_block_from_proto).transpose()?;
            if let Some(snapshot) = &latest {
                authenticate_snapshot(&client, snapshot, verifier.as_ref()).await?;
                if verifier.is_some() {
                    record_progress(&progress, snapshot.height, true)?;
                }
            }
            Ok(latest)
        }
    }

    fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> impl Future<Output = Result<Option<FinalizedBlock>, QueryError>> + Send {
        let progress = self.finalized_height.clone();
        let client = self.rpc_client().clone();
        let verifier = self.consensus_verifier().cloned();
        async move {
            let response = client
                .get_finalized_block(finalized_block_query_to_proto(query))
                .await
                .map_err(QueryError::from)?;
            let block = response
                .block
                .map(|block| finalized_block_from_proto(block, verifier.as_ref()))
                .transpose()?;
            if let Some(block) = &block
                && verifier.is_some()
            {
                record_progress(
                    &progress,
                    block.snapshot.height,
                    matches!(query, FinalizedBlockQuery::Latest),
                )?;
            }
            Ok(block)
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
    ) -> impl Future<Output = Result<Option<CoinListing>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        let verifier = self.consensus_verifier().cloned();
        async move {
            let resp = client
                .get_coins_by_owner(GetCoinsByOwnerRequest {
                    owner: owner.to_bytes().to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            let listing = coin_listing_from_proto(resp)?;
            if let Some(listing) = &listing {
                authenticate_snapshot(&client, &listing.snapshot, verifier.as_ref()).await?;
            }
            Ok(listing)
        }
    }

    fn get_coins_by_delegate(
        &self,
        delegate: SettlementKey,
    ) -> impl Future<Output = Result<Option<CoinListing>, QueryError>> + Send {
        let client = self.rpc_client().clone();
        let verifier = self.consensus_verifier().cloned();
        async move {
            let resp = client
                .get_coins_by_delegate(GetCoinsByDelegateRequest {
                    delegate: delegate.to_bytes().to_vec(),
                })
                .await
                .map_err(QueryError::from)?;
            let listing = coin_listing_from_proto(resp)?;
            if let Some(listing) = &listing {
                authenticate_snapshot(&client, &listing.snapshot, verifier.as_ref()).await?;
            }
            Ok(listing)
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
            let listing = owner_edges_from_proto(owner, resp)?;
            if let Some(listing) = &listing {
                authenticate_snapshot(&client, &listing.snapshot, verifier.as_ref()).await?;
            }
            Ok(listing)
        }
    }
}

fn coin_listing_from_proto(resp: GetCoinsResponse) -> Result<Option<CoinListing>, QueryError> {
    let Some(snapshot) = resp.snapshot else {
        if resp.coins.is_empty() {
            return Ok(None);
        }
        return Err(QueryError::Remote(
            "GetCoinsResponse had coins without a snapshot".to_string(),
        ));
    };
    let snapshot = latest_block_from_proto(snapshot)?;
    let coins = resp
        .coins
        .into_iter()
        .map(|entry| {
            let arr: [u8; 32] = entry
                .object_id
                .try_into()
                .map_err(|_| QueryError::Remote("object_id was not 32 bytes".to_string()))?;
            Ok((Digest::from(arr), entry.value))
        })
        .collect::<Result<Vec<_>, QueryError>>()?;
    Ok(Some(CoinListing { snapshot, coins }))
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
) -> Result<Option<OwnerEdges>, QueryError> {
    let Some(snapshot) = response.snapshot else {
        if response.edges.is_empty() {
            return Ok(None);
        }
        return Err(QueryError::Remote(
            "GetEdgesByOwnerResponse had edges without a snapshot".to_string(),
        ));
    };
    let snapshot = latest_block_from_proto(snapshot)?;
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

async fn authenticate_snapshot(
    client: &LightClientClientImpl<MuxTransport>,
    snapshot: &LatestBlock,
    verifier: Option<&ConsensusVerifier>,
) -> Result<(), QueryError> {
    let Some(verifier) = verifier else {
        return Ok(());
    };
    let response = client
        .get_finalized_block(finalized_block_query_to_proto(
            FinalizedBlockQuery::Payload(snapshot.payload),
        ))
        .await
        .map_err(QueryError::from)?;
    let block = response
        .block
        .ok_or_else(|| QueryError::Remote("canonical snapshot block was missing".into()))?;
    verifier
        .verify_snapshot(snapshot, &block.block)
        .map_err(QueryError::from)
}

pub(crate) fn finalized_block_from_proto(
    block: hellas_rpc::pb::chain::FinalizedBlock,
    verifier: Option<&ConsensusVerifier>,
) -> Result<FinalizedBlock, QueryError> {
    let Some(snapshot) = block.snapshot else {
        return Err(QueryError::Remote(
            "FinalizedBlock had no snapshot".to_string(),
        ));
    };
    let snapshot = latest_block_from_proto(snapshot)?;
    if Sha256::hash(&block.block) != snapshot.payload {
        return Err(QueryError::Remote(
            "block bytes did not match finalized payload".to_string(),
        ));
    }
    if let Some(verifier) = verifier {
        verifier
            .verify_snapshot(&snapshot, &block.block)
            .map_err(QueryError::from)?;
    }
    Ok(FinalizedBlock {
        snapshot,
        block: block.block,
    })
}

pub(crate) fn finalized_block_query_to_proto(
    query: FinalizedBlockQuery,
) -> GetFinalizedBlockRequest {
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

    let tx_oneof = match tx {
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
