use crate::domain::{Digest, ObjectId, SettlementKey, Transaction};
use crate::{
    ConsensusInfo, FinalizedBlock, FinalizedBlockQuery, LatestBlock, LightClient, ObjectSnapshot,
    QueryError, Verified,
};
use hellas_kernel::{Encode as _, Move as KernelMove, Tx as KernelTx};
use hellas_rpc::{
    SubmitTxOutcome as DomainSubmitTxOutcome,
    call::StreamingCall,
    observe::{LEVEL, TARGET, Timing},
    pb::{chain::*, services::light_client::LightClientClientImpl},
};
use hellas_wire::mux::MuxTransport;
mod objects;

pub use objects::TrustedReader;

/// The WebSocket carrier to one endpoint. Servers close idle and long-lived
/// connections; the next call after a close opens a fresh one, so a close is
/// never a failed request.
struct Connection {
    address: String,
    transport: std::sync::Mutex<MuxTransport>,
}

impl Connection {
    async fn open(address: String) -> Result<Self, QueryError> {
        let transport = connect_transport(&address).await?;
        Ok(Self {
            address,
            transport: std::sync::Mutex::new(transport),
        })
    }

    fn current(&self) -> MuxTransport {
        self.transport
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// A client on the live carrier, reconnecting if the server closed it.
    async fn client(&self) -> Result<LightClientClientImpl<MuxTransport>, QueryError> {
        let current = self.current();
        if !current.is_closed() {
            return Ok(LightClientClientImpl::new(current));
        }
        let fresh = connect_transport(&self.address).await?;
        let mut transport = self
            .transport
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A concurrent call may have replaced it first; keep the live one.
        if transport.is_closed() {
            *transport = fresh;
        }
        Ok(LightClientClientImpl::new(transport.clone()))
    }
}

/// Wire-backed light client that connects to a remote validator or relay.
#[derive(Clone)]
pub struct RemoteLightClient {
    connection: std::sync::Arc<Connection>,
    finalized_height: std::sync::Arc<std::sync::atomic::AtomicU64>,
    applied_progress: std::sync::Arc<std::sync::atomic::AtomicU64>,
    proof_verifier: std::sync::Arc<crate::proof_verify::ProofVerifier>,
}

impl RemoteLightClient {
    pub(crate) fn pinned_network(&self) -> hellas_kernel::NetworkId {
        self.proof_verifier.network()
    }

    /// Follows finalized blocks from now on. Take it before the read whose
    /// change the caller waits for, so no block in between is missed.
    pub async fn finalized_blocks(&self) -> Result<FinalizedBlocks, QueryError> {
        Ok(FinalizedBlocks {
            stream: Some(self.subscribe_finalized().await?),
            client: self.clone(),
        })
    }

    async fn subscribe_finalized(
        &self,
    ) -> Result<StreamingCall<GetFinalizedBlockResponse>, QueryError> {
        self.rpc()
            .await?
            .subscribe_finalized(GetLatestBlockRequest {})
            .await
            .map_err(QueryError::from)
    }

    /// Connect to a WebSocket endpoint.
    pub async fn connect(
        addr: impl Into<String>,
        proof_verifier: std::sync::Arc<crate::proof_verify::ProofVerifier>,
    ) -> Result<Self, QueryError> {
        Ok(Self {
            connection: std::sync::Arc::new(Connection::open(addr.into()).await?),
            finalized_height: Default::default(),
            applied_progress: Default::default(),
            proof_verifier,
        })
    }

    /// Subscribe to the consensus activity stream.
    pub async fn subscribe_activity(
        &self,
        urgent_events: Vec<ActivityEventKind>,
    ) -> Result<StreamingCall<ActivityEvent>, QueryError> {
        self.rpc()
            .await?
            .subscribe_activity(SubscribeActivityRequest {
                urgent_events: urgent_events.into_iter().map(|k| k as i32).collect(),
            })
            .await
            .map_err(QueryError::from)
    }

    /// Fetch transport/version metadata from the connected validator path.
    pub async fn get_relay_info(&self) -> Result<GetRelayInfoResponse, QueryError> {
        self.rpc()
            .await?
            .get_relay_info(GetRelayInfoRequest {})
            .await
            .map_err(QueryError::from)
    }
}

/// Wakes once per finalized block. A wake carries no data: the caller
/// re-reads, with proofs, after each one.
pub struct FinalizedBlocks {
    client: RemoteLightClient,
    stream: Option<StreamingCall<GetFinalizedBlockResponse>>,
}

impl FinalizedBlocks {
    /// Completes when a block has finalized since the last call.
    ///
    /// The server ends a subscription when its connection closes or a block
    /// read fails; that is resubscribed, over a fresh connection if needed,
    /// and also wakes, since blocks may have passed meanwhile. A refused
    /// subscription is an error.
    pub async fn next(&mut self) -> Result<(), QueryError> {
        use futures_util::StreamExt as _;
        if let Some(stream) = &mut self.stream {
            match stream.next().await {
                Some(Ok(_)) => return Ok(()),
                Some(Err(status)) => {
                    self.stream = None;
                    return Err(status.into());
                }
                None => {}
            }
        }
        if let Some(Err(status)) = self.stream.take().map(StreamingCall::finish)
            && status.code == hellas_wire::WireCode::ResourceExhausted
        {
            return Err(status.into());
        }
        self.stream = Some(self.client.subscribe_finalized().await?);
        Ok(())
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

async fn submit_over(
    client: &LightClientClientImpl<MuxTransport>,
    tx: Transaction,
) -> Result<DomainSubmitTxOutcome, QueryError> {
    if let Transaction::Kernel(KernelTx::Move {
        action: KernelMove::RespondPaymentClose(response),
    }) = tx
    {
        let mut bytes = vec![0_u8; hellas_kernel::PaymentCloseResponse::MAX_ENCODED_SIZE];
        let written = response.write_to(&mut bytes);
        bytes.truncate(written);
        let response = client
            .submit_work_response(SubmitWorkResponseRequest { response: bytes })
            .await
            .map_err(QueryError::from)?;
        return submit_tx_outcome_from_proto(response.outcome);
    }
    let response = client
        .submit_tx(transaction_to_proto(tx)?)
        .await
        .map_err(QueryError::from)?;
    submit_tx_outcome_from_proto(response.outcome)
}

/// Full nodes only forward submissions; this path cannot return chain reads.
#[cfg(feature = "full-node")]
pub(crate) async fn forward_submission(
    address: &str,
    tx: Transaction,
) -> Result<DomainSubmitTxOutcome, QueryError> {
    let transport = connect_transport(address).await?;
    submit_over(&LightClientClientImpl::new(transport), tx).await
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
    async fn rpc(&self) -> Result<LightClientClientImpl<MuxTransport>, QueryError> {
        self.connection.client().await
    }

    /// Completes once the current carrier has ended.
    #[cfg(all(test, feature = "validator"))]
    pub(crate) async fn carrier_closed(&self) {
        self.connection.current().closed().await;
    }
}

impl LightClient for RemoteLightClient {
    /// The raw proven reply, for callers that verify it themselves.
    async fn get_object_proofs(
        &self,
        request: GetObjectProofsRequest,
    ) -> Result<GetObjectProofsResponse, QueryError> {
        self.rpc()
            .await?
            .get_object_proofs(request)
            .await
            .map_err(QueryError::from)
    }

    async fn get_objects(
        &self,
        keys: Vec<crate::domain::ObjectKey>,
    ) -> Result<Option<Verified<ObjectSnapshot>>, QueryError> {
        Box::pin(objects::read(self, keys, None)).await
    }

    async fn get_holdings(
        &self,
        owner: SettlementKey,
        after: Option<crate::domain::ObjectKey>,
    ) -> Result<Option<Verified<ObjectSnapshot>>, QueryError> {
        Box::pin(objects::read(
            self,
            Vec::new(),
            Some((owner, after.map(crate::domain::ObjectKey::id))),
        ))
        .await
    }

    fn get_state_root(&self) -> impl Future<Output = Result<Option<Digest>, QueryError>> + Send {
        let client = self.clone();
        async move {
            Ok(client
                .get_latest_block()
                .await?
                .map(|snapshot| snapshot.state_root))
        }
    }

    fn get_finalization(
        &self,
        payload: Digest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, QueryError>> + Send {
        let this = self.clone();
        async move {
            let response = this
                .rpc()
                .await?
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
        let this = self.clone();
        let verifier = self.proof_verifier.clone();
        async move {
            let client = this.rpc().await?;
            let response = client
                .get_latest_block(GetLatestBlockRequest {})
                .await
                .map_err(QueryError::from)?;
            let latest = response.latest.map(latest_block_from_proto).transpose()?;
            if let Some(snapshot) = &latest {
                authenticate_snapshot(&client, snapshot, &verifier).await?;
                record_progress(&progress, snapshot.height, true)?;
            }
            Ok(latest)
        }
    }

    fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> impl Future<Output = Result<Option<FinalizedBlock>, QueryError>> + Send {
        let progress = self.finalized_height.clone();
        let this = self.clone();
        let verifier = self.proof_verifier.clone();
        async move {
            let response = this
                .rpc()
                .await?
                .get_finalized_block(finalized_block_query_to_proto(query))
                .await
                .map_err(QueryError::from)?;
            let block = response.block.map(finalized_block_from_proto).transpose()?;
            if let Some(block) = &block {
                verifier
                    .verify_finalized(block.clone(), crate::proof_verify::ProofQuery::Block(query))
                    .map_err(|error| QueryError::Remote(error.to_string()))?;
                record_progress(
                    &progress,
                    block.snapshot.height,
                    matches!(query, FinalizedBlockQuery::Latest),
                )?;
            }
            Ok(block)
        }
    }

    fn get_applied_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> impl Future<Output = Result<Option<FinalizedBlock>, QueryError>> + Send {
        let state = self.clone();
        let verifier = self.proof_verifier.clone();
        async move {
            let response = state
                .rpc()
                .await?
                .get_applied_finalized_block(finalized_block_query_to_proto(query))
                .await
                .map_err(QueryError::from)?;
            let block = response.block.map(finalized_block_from_proto).transpose()?;
            if let Some(block) = &block {
                verifier
                    .verify_finalized(block.clone(), crate::proof_verify::ProofQuery::Block(query))
                    .map_err(|error| QueryError::Remote(error.to_string()))?;
                if matches!(query, FinalizedBlockQuery::Latest) {
                    record_progress(&state.applied_progress, block.snapshot.height, true)?;
                }
            }
            Ok(block)
        }
    }

    fn submit_tx(
        &self,
        tx: Transaction,
    ) -> impl Future<Output = Result<DomainSubmitTxOutcome, QueryError>> + Send {
        let this = self.clone();
        // Boxed: a transaction and its RPC call are large, and every chain
        // caller would otherwise compose them inline in its own future.
        Box::pin(async move {
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
            let outcome = match this.rpc().await {
                Ok(client) => submit_over(&client, tx).await,
                Err(error) => Err(error),
            };
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
        })
    }

    fn get_validators(&self) -> impl Future<Output = Result<Vec<String>, QueryError>> + Send {
        let this = self.clone();
        async move {
            let resp = this
                .rpc()
                .await?
                .get_validators(GetValidatorsRequest {})
                .await
                .map_err(QueryError::from)?;
            Ok(resp.validators)
        }
    }

    fn get_consensus_info(&self) -> impl Future<Output = Result<ConsensusInfo, QueryError>> + Send {
        let this = self.clone();
        async move {
            let resp = this
                .rpc()
                .await?
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
}

async fn authenticate_snapshot(
    client: &LightClientClientImpl<MuxTransport>,
    snapshot: &LatestBlock,
    verifier: &crate::proof_verify::ProofVerifier,
) -> Result<(), QueryError> {
    let response = client
        .get_finalized_block(finalized_block_query_to_proto(
            FinalizedBlockQuery::Payload(snapshot.payload),
        ))
        .await
        .map_err(QueryError::from)?;
    let block = finalized_block_from_proto(
        response
            .block
            .ok_or_else(|| QueryError::Remote("canonical snapshot block was missing".into()))?,
    )?;
    verifier
        .verify_finalized(
            block.clone(),
            crate::proof_verify::ProofQuery::Block(FinalizedBlockQuery::Payload(snapshot.payload)),
        )
        .map_err(|error| QueryError::Remote(error.to_string()))?;
    if block.snapshot != *snapshot {
        return Err(QueryError::Remote(
            "listing snapshot differs from certified block".into(),
        ));
    }
    Ok(())
}

pub(crate) fn finalized_block_from_proto(
    block: hellas_rpc::pb::chain::FinalizedBlock,
) -> Result<FinalizedBlock, QueryError> {
    let snapshot = block
        .snapshot
        .ok_or_else(|| QueryError::Remote("FinalizedBlock had no snapshot".into()))?;
    Ok(FinalizedBlock {
        snapshot: latest_block_from_proto(snapshot)?,
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
