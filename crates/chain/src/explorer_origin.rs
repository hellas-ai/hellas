//! Private HTTP proof origin backed by the native Commonware follower archive.
//! Bind only to loopback; Cloudflare Tunnel + Access supplies external authentication.
use crate::{
    Application, ApplicationConfig, ChainIndexer, ConsensusInfo, ConsensusVerifier,
    FinalizedBlockQuery,
    config::Config,
    domain::{Digest, PublicKey},
    follower::{FollowerStatusSink, follow_remote},
    spawn_follower_indexer,
    verified_explorer::{ExplorerQuery, ExplorerVerifier, PROOF_SCHEMA_VERSION, ProofBundle},
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use commonware_codec::DecodeExt as _;
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use hellas_genesis::{Genesis, HELLAS_DEVNET_1_JSON, TrustDocument};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

type OriginResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct OriginOptions {
    pub rpc: String,
    pub trust: TrustDocument,
    pub storage_dir: PathBuf,
    pub partition_prefix: String,
    pub listen: SocketAddr,
    pub status: FollowerStatusSink,
}

pub fn run(options: OriginOptions) -> OriginResult<()> {
    if !options.listen.ip().is_loopback() {
        return Err("private explorer origin must bind to loopback".into());
    }
    // Marshal currently has a constant threshold provider and epoch zero. Reject a schedule
    // it cannot ingest rather than silently use a different key from the portable verifier.
    if options.trust.epochs.len() != 1
        || options.trust.epochs[0].epoch != 0
        || options.trust.epochs[0].end_height.is_some()
    {
        return Err("native follower currently requires one open epoch zero; key rotation requires a marshal provider upgrade".into());
    }
    let verifier = Arc::new(ExplorerVerifier::new(options.trust.clone())?);
    let runtime = tokio::Config::new()
        .with_storage_directory(&options.storage_dir)
        .with_tcp_nodelay(Some(true));
    tokio::Runner::new(runtime).start(move |context| async move {
        let genesis: Genesis = serde_json::from_str(HELLAS_DEVNET_1_JSON)?;
        let info = ConsensusInfo { network_id: genesis.network_id.clone(), validators: genesis.validators.iter().map(|validator| validator.public_key.clone()).collect(), threshold_identity: hex::decode(&options.trust.epochs[0].threshold_identity)? };
        let leader = PublicKey::decode(hex::decode(&info.validators[0])?.as_slice())?;
        let allocations = genesis.allocations.iter().map(|entry| Ok((crate::config::parse_genesis_settlement_key(&entry.address)?,entry.balance))).collect::<Result<Vec<_>,crate::config::ConfigError>>()?;
        let application = Application::new(context.child("app"), crate::domain::network_id(&genesis)?, leader, allocations, &format!("{}-genesis",options.partition_prefix), ApplicationConfig::default()).await;
        let (indexer,_marshal) = spawn_follower_indexer(context.child("indexer"),&options.partition_prefix,Config::default(),ConsensusVerifier::new(&info)?,application.genesis_block()).await?;
        let state = OriginState { indexer:indexer.clone(), verifier, network_id:info.network_id.clone(), transactions:Arc::new(RwLock::new(BTreeMap::new())) };
        let app = router(state.clone());
        let listener = ::tokio::net::TcpListener::bind(options.listen).await?;
        ::tokio::select! {
            result = index_transactions(state) => result,
            result = axum::serve(listener,app) => result.map_err(Into::into),
            result = follow_remote(indexer,options.rpc,info,options.status) => result.map_err(Into::into),
        }
    })
}

#[derive(Clone)]
struct OriginState {
    indexer: ChainIndexer,
    verifier: Arc<ExplorerVerifier>,
    network_id: String,
    transactions: Arc<RwLock<BTreeMap<Digest, u64>>>,
}
fn router(state: OriginState) -> Router {
    Router::new()
        .route("/api/v1/blocks/{selector}", get(block))
        .route("/api/v1/blocks/{selector}/proof", get(block))
        .route("/api/v1/blocks/by-payload/{payload}", get(payload))
        .route("/api/v1/transactions/{digest}", get(transaction))
        .route("/api/v1/transactions/{digest}/proof", get(transaction))
        .with_state(state)
}

async fn block(
    State(state): State<OriginState>,
    Path(selector): Path<String>,
    headers: HeaderMap,
) -> Response {
    let query = if selector == "latest" {
        FinalizedBlockQuery::Latest
    } else if let Some(payload) = digest(&selector) {
        FinalizedBlockQuery::Payload(payload)
    } else {
        match selector.parse::<u64>() {
            Ok(height) => FinalizedBlockQuery::Height(height),
            Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid block height"),
        }
    };
    answer(state, query, ExplorerQuery::Block(query), headers).await
}
async fn payload(
    State(state): State<OriginState>,
    Path(payload): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(payload) = digest(&payload) else {
        return failure(StatusCode::BAD_REQUEST, "invalid payload");
    };
    let query = FinalizedBlockQuery::Payload(payload);
    answer(state, query, ExplorerQuery::Block(query), headers).await
}
#[derive(Deserialize)]
struct TransactionQuery {
    height: Option<u64>,
}
async fn transaction(
    State(state): State<OriginState>,
    Path(tx): Path<String>,
    Query(query): Query<TransactionQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(tx) = digest(&tx) else {
        return failure(StatusCode::BAD_REQUEST, "invalid transaction digest");
    };
    let height = query.height.or_else(|| {
        state
            .transactions
            .read()
            .expect("transaction index lock")
            .get(&tx)
            .copied()
    });
    let Some(height) = height else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "transaction locator is unavailable or still catching up",
        );
    };
    answer(
        state,
        FinalizedBlockQuery::Height(height),
        ExplorerQuery::Transaction(tx),
        headers,
    )
    .await
}
fn digest(value: &str) -> Option<Digest> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let bytes: [u8; 32] = hex::decode(value).ok()?.try_into().ok()?;
    Some(Digest::from(bytes))
}
async fn answer(
    state: OriginState,
    lookup: FinalizedBlockQuery,
    query: ExplorerQuery,
    headers: HeaderMap,
) -> Response {
    let finalized = match state.indexer.get_finalized_block(lookup).await {
        Ok(Some(block)) => block,
        Ok(None) => return failure(StatusCode::NOT_FOUND, "finalized block is unavailable"),
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "archive is unavailable"),
    };
    let bundle = proof_bundle(&state, finalized);
    let verified = match state.verifier.verify(bundle, query) {
        Ok(block) => block,
        Err(crate::verified_explorer::VerificationError::Query) => {
            return failure(
                StatusCode::NOT_FOUND,
                "transaction is absent from the requested block",
            );
        }
        Err(_) => {
            return failure(
                StatusCode::BAD_GATEWAY,
                "archived proof failed verification",
            );
        }
    };
    let protobuf = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|item| item.trim() == "application/x-protobuf")
        });
    let (content_type, body) = if protobuf {
        (
            "application/x-protobuf",
            prost::Message::encode_to_vec(verified.bundle()),
        )
    } else {
        (
            "application/json",
            serde_json::to_vec(verified.bundle()).expect("proof serializes"),
        )
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
            (header::VARY, "Accept"),
        ],
        body,
    )
        .into_response()
}
fn failure(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        message.to_owned(),
    )
        .into_response()
}

fn proof_bundle(state: &OriginState, finalized: crate::FinalizedBlock) -> ProofBundle {
    ProofBundle {
        schema_version: PROOF_SCHEMA_VERSION,
        network_id: state.network_id.clone(),
        trust_sha256: state.verifier.trust_sha256().into(),
        height: finalized.snapshot.height,
        payload: hex::encode(finalized.snapshot.payload),
        state_root: hex::encode(finalized.snapshot.state_root),
        finalization: finalized.snapshot.finalization,
        canonical_block: finalized.block,
        observed_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        epoch: 0,
    }
}
async fn index_transactions(state: OriginState) -> OriginResult<()> {
    let mut height = 1_u64;
    loop {
        match state
            .indexer
            .get_finalized_block(FinalizedBlockQuery::Height(height))
            .await?
        {
            Some(finalized) => {
                let verified = state.verifier.verify(
                    proof_bundle(&state, finalized),
                    ExplorerQuery::Block(FinalizedBlockQuery::Height(height)),
                )?;
                {
                    let mut transactions =
                        state.transactions.write().expect("transaction index lock");
                    for tx in verified.view().txs() {
                        transactions
                            .entry(crate::verified_explorer::transaction_digest(tx))
                            .or_insert(height);
                    }
                }
                height = height
                    .checked_add(1)
                    .ok_or("transaction index height exhausted")?;
                ::tokio::task::yield_now().await;
            }
            None => ::tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::test_support::{
        consensus_fixture, finalization, index_block, index_genesis,
    };
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Digestible as _, Hasher as _, Sha256};
    use commonware_runtime::deterministic;
    use hellas_genesis::{HELLAS_DEVNET_1_ID, TrustEpoch};
    use tower::ServiceExt as _;

    #[test]
    fn http_origin_returns_reverifiable_evidence_and_resolves_transaction_routes() {
        deterministic::Runner::default().start(|context| async move {
            let fixture = consensus_fixture(77);
            let genesis = index_genesis();
            let block = index_block(
                &genesis,
                Digest::from([2; 32]),
                vec![crate::domain::Transaction::Kernel(
                    hellas_kernel::test_support::valid_open_tx().unwrap(),
                )],
            );
            let trust = TrustDocument {
                schema_version: 1,
                network_id: HELLAS_DEVNET_1_ID.into(),
                genesis_sha256: hex::encode(Sha256::hash(HELLAS_DEVNET_1_JSON.as_bytes())),
                epochs: vec![TrustEpoch {
                    epoch: 0,
                    start_height: 0,
                    end_height: None,
                    threshold_identity: hex::encode(fixture.assembler.identity().encode()),
                }],
            };
            let verifier = Arc::new(ExplorerVerifier::new(trust).unwrap());
            let (indexer, _handle) = spawn_follower_indexer(
                context,
                "origin-test",
                Config::default(),
                fixture.verifier.clone(),
                genesis,
            )
            .await
            .unwrap();
            indexer
                .ingest_finalized(block.clone(), finalization(&fixture, &block))
                .await
                .unwrap();
            let tx = crate::verified_explorer::transaction_digest(&block.txs()[0]);
            let transactions = Arc::new(RwLock::new(BTreeMap::from([(tx, 1)])));
            let app = router(OriginState {
                indexer,
                verifier: verifier.clone(),
                network_id: HELLAS_DEVNET_1_ID.into(),
                transactions,
            });
            for uri in [
                "/api/v1/blocks/1/proof".to_owned(),
                format!("/api/v1/blocks/{}/proof", hex::encode(block.digest())),
                format!("/api/v1/transactions/{}/proof", hex::encode(tx)),
            ] {
                let response = app
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .uri(uri)
                            .header(header::ACCEPT, "application/x-protobuf")
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    response.headers()[header::CONTENT_TYPE],
                    "application/x-protobuf"
                );
                let body = axum::body::to_bytes(
                    response.into_body(),
                    crate::verified_explorer::MAX_PROOF_BYTES,
                )
                .await
                .unwrap();
                let bundle = <ProofBundle as prost::Message>::decode(body).unwrap();
                assert!(
                    verifier
                        .verify(bundle, ExplorerQuery::Block(FinalizedBlockQuery::Height(1)))
                        .is_ok()
                );
            }
            let absent = app
                .oneshot(
                    axum::http::Request::builder()
                        .uri(format!("/api/v1/transactions/{}/proof", "00".repeat(32)))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(absent.status(), StatusCode::SERVICE_UNAVAILABLE);
        });
    }
}
