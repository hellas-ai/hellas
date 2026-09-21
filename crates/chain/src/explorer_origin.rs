//! Loopback-only HTTP proof origin backed by the native Commonware follower archive.
use crate::{
    Application, ApplicationConfig, ChainIndexer, ConsensusInfo, FinalizedBlockQuery,
    LightClient as _,
    config::Config,
    domain::{Digest, PublicKey},
    follower::{FollowerStatusSink, ingest_finalized_block},
    verified_explorer::{ExplorerQuery, ExplorerVerifier, PROOF_SCHEMA_VERSION, ProofBundle},
};
use axum::{
    Router,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use commonware_codec::DecodeExt as _;
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use commonware_utils::ordered::Set;
use futures_util::{Stream, StreamExt as _, stream};
use hellas_genesis::{Genesis, HELLAS_DEVNET_1_JSON, TrustDocument};
use serde::Deserialize;
use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

type OriginResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct OriginOptions {
    pub rpc: String,
    pub trust: TrustDocument,
    /// Exact independently provisioned genesis JSON bytes; None uses the embedded devnet.
    pub genesis_json: Option<Vec<u8>>,
    pub storage_dir: PathBuf,
    pub partition_prefix: String,
    pub listen: SocketAddr,
    pub status: FollowerStatusSink,
}

pub(crate) fn genesis_leader(genesis: &Genesis) -> OriginResult<PublicKey> {
    // Validators choose the first member of the canonical participant Set,
    // independently of how the authenticated genesis JSON orders its entries.
    let keys = genesis
        .validators
        .iter()
        .map(|validator| {
            Ok(PublicKey::decode(
                hex::decode(&validator.public_key)?.as_slice(),
            )?)
        })
        .collect::<OriginResult<Vec<_>>>()?;
    let participants = Set::try_from(keys).map_err(|_| "duplicate genesis validators")?;
    participants
        .iter()
        .next()
        .cloned()
        .ok_or_else(|| "empty genesis committee".into())
}

pub fn run(options: OriginOptions) -> OriginResult<()> {
    if !options.listen.ip().is_loopback() {
        return Err("private explorer origin must bind to loopback".into());
    }
    let genesis_json = options
        .genesis_json
        .unwrap_or_else(|| HELLAS_DEVNET_1_JSON.as_bytes().to_vec());
    let verifier = Arc::new(ExplorerVerifier::with_genesis(
        options.trust.clone(),
        &genesis_json,
    )?);
    let genesis: Genesis = serde_json::from_slice(&genesis_json)?;
    let runtime = tokio::Config::new()
        .with_storage_directory(&options.storage_dir)
        .with_tcp_nodelay(Some(true));
    tokio::Runner::new(runtime).start(move |context| async move {
        let info = ConsensusInfo {
            network_id: genesis.network_id.clone(),
            validators: genesis
                .validators
                .iter()
                .map(|validator| validator.public_key.clone())
                .collect(),
            threshold_identity: hex::decode(&options.trust.epochs[0].threshold_identity)?,
        };
        let leader = genesis_leader(&genesis)?;
        let allocations = genesis
            .allocations
            .iter()
            .map(|entry| {
                Ok((
                    crate::config::parse_genesis_settlement_key(&entry.address)?,
                    entry.balance,
                ))
            })
            .collect::<Result<Vec<_>, crate::config::ConfigError>>()?;
        let application = Application::new(
            context.child("app"),
            crate::domain::network_id(&genesis)?,
            leader,
            allocations.clone(),
            &format!("{}-genesis", options.partition_prefix),
            ApplicationConfig::default(),
        )
        .await;
        let (indexer, _marshal) = crate::indexer::spawn_trusted_follower_indexer_with_genesis(
            context.child("indexer"),
            &options.partition_prefix,
            Config::default(),
            options.trust.clone(),
            &genesis_json,
            application.genesis_block(),
        )
        .await?;
        let edge_scope = crate::edge_index::query::cursor_scope(
            &genesis.network_id,
            &options.trust.genesis_sha256,
            verifier.trust_sha256(),
        );
        let edge_index = crate::edge_index::EdgeIndex::open(
            &options.storage_dir.join(format!(
                "{}-edge-index-v{}-{edge_scope}.redb",
                options.partition_prefix,
                crate::edge_index::SCHEMA_VERSION
            )),
            genesis.network_id.clone(),
            options.trust.genesis_sha256.clone(),
            verifier.trust_sha256().into(),
        )?;
        let replay = crate::edge_index::Replay::new(
            context.child("edge_replay"),
            &options.partition_prefix,
            edge_index.clone(),
            crate::domain::network_id(&genesis)?,
            allocations,
            application.genesis_block(),
            &verifier,
        )
        .await?;
        let state = OriginState {
            edge_index,
            replay: Arc::new(::tokio::sync::Mutex::new(replay)),
            indexer: indexer.clone(),
            verifier,
            network_id: info.network_id.clone(),
        };
        let app = router(state.clone());
        let listener = ::tokio::net::TcpListener::bind(options.listen).await?;
        ::tokio::select! {
            result = index_transactions(state.clone()) => result,
            result = axum::serve(listener,app) => result.map_err(Into::into),
            result = follow_trusted(state,options.rpc,options.status) => result,
        }
    })
}

#[derive(Clone)]
struct OriginState {
    edge_index: crate::edge_index::EdgeIndex,
    indexer: ChainIndexer,
    verifier: Arc<ExplorerVerifier>,
    network_id: String,
    // This is the only finalized materializer. Its lock spans QMDB finalize,
    // EdgeIndex publication and all current owner-proof reads.
    replay: Arc<::tokio::sync::Mutex<crate::edge_index::Replay<tokio::Context>>>,
}

fn router(state: OriginState) -> Router {
    Router::new()
        .route("/api/v1/edges", get(edge_index_http))
        .route("/api/v1/edges/{edge_id}", get(edge_index_http))
        .route("/api/v1/edges/{edge_id}/events", get(edge_index_http))
        .route("/api/v1/edges/{edge_id}/evidence", get(edge_index_http))
        .route("/api/v1/channels/{payment_edge_id}", get(edge_index_http))
        .route("/api/v1/edge-index/rpc", get(edge_index_ws))
        .route("/api/v1/blocks/{selector}", get(block))
        .route("/api/v1/blocks/{selector}/proof", get(block))
        .route("/api/v1/blocks/by-payload/{payload}", get(payload))
        .route("/api/v1/transactions/{digest}", get(transaction))
        .route("/api/v1/transactions/{digest}/proof", get(transaction))
        .route("/api/v1/addresses/{owner}/proof", get(address))
        .route("/api/v1/addresses/{owner}", get(address))
        .with_state(state)
}

async fn edge_index_http(
    State(state): State<OriginState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    crate::edge_index::http::handle(state.edge_index, uri, headers).await
}
async fn edge_index_ws(
    State(state): State<OriginState>,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| crate::edge_index::rpc::serve_socket(socket, state.edge_index))
}

async fn block(
    State(state): State<OriginState>,
    Path(selector): Path<String>,
    OriginalUri(uri): OriginalUri,
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
    answer(
        state,
        query,
        ExplorerQuery::Block(query),
        default_proof_accept(headers, &uri),
    )
    .await
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
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let Some(tx) = digest(&tx) else {
        return failure(StatusCode::BAD_REQUEST, "invalid transaction digest");
    };
    let height = query.height.or_else(|| {
        state
            .edge_index
            .transaction_height(&hex::encode(tx))
            .ok()
            .flatten()
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
        default_proof_accept(headers, &uri),
    )
    .await
}
#[derive(Deserialize)]
struct AddressQuery {
    #[serde(default)]
    offset: u64,
    #[serde(default = "address_limit")]
    limit: u32,
    payload: Option<String>,
}
fn address_limit() -> u32 {
    crate::owner_proof::OWNER_PAGE_LIMIT
}

#[derive(Clone, PartialEq, prost::Message, serde::Serialize)]
struct OwnerSnapshotError {
    #[prost(uint32, tag = "1")]
    schema_version: u32,
    #[prost(string, tag = "2")]
    network_id: String,
    #[prost(string, tag = "3")]
    code: String,
    #[prost(string, tag = "4")]
    message: String,
    #[prost(string, optional, tag = "5")]
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_url: Option<String>,
}

fn owner_snapshot_unavailable(
    network_id: &str,
    owner: crate::domain::SettlementKey,
    protobuf: bool,
) -> Response {
    let error = OwnerSnapshotError {
        schema_version: PROOF_SCHEMA_VERSION,
        network_id: network_id.into(),
        code: "snapshot_unavailable".into(),
        message: "The requested verified owner snapshot is unavailable. Request latest holdings explicitly.".into(),
        latest_url: Some(format!("/api/v1/addresses/{owner}")),
    };
    let (content_type, bytes) = if protobuf {
        (
            "application/x-protobuf",
            prost::Message::encode_to_vec(&error),
        )
    } else {
        (
            "application/json",
            serde_json::to_vec(&error).expect("owner error serializes"),
        )
    };
    (
        StatusCode::CONFLICT,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
            (header::VARY, "Accept"),
        ],
        bytes,
    )
        .into_response()
}

async fn address(
    State(state): State<OriginState>,
    Path(owner): Path<String>,
    Query(query): Query<AddressQuery>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let Ok(owner) = owner.parse::<crate::domain::SettlementKey>() else {
        return failure(StatusCode::BAD_REQUEST, "invalid owner");
    };
    let Some(protobuf) = representation(&default_proof_accept(headers, &uri)) else {
        return failure(StatusCode::NOT_ACCEPTABLE, "unsupported representation");
    };
    if query
        .payload
        .as_ref()
        .is_some_and(|payload| digest(payload).is_none())
    {
        return failure(StatusCode::BAD_REQUEST, "invalid payload");
    }
    let verified = match state
        .replay
        .lock()
        .await
        .owner_proof(owner, query.offset, query.limit, query.payload.as_deref())
        .await
    {
        Ok(Some(bundle)) => bundle,
        Ok(None) if query.payload.is_some() => {
            return owner_snapshot_unavailable(&state.network_id, owner, protobuf);
        }
        Ok(None) => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "no durable verified owner checkpoint is available yet",
            );
        }
        Err(error)
            if matches!(
                error.downcast_ref::<crate::owner_proof::OwnerProofError>(),
                Some(crate::owner_proof::OwnerProofError::Page)
            ) =>
        {
            return failure(StatusCode::BAD_REQUEST, "invalid owner page");
        }
        Err(_) => {
            return failure(
                StatusCode::BAD_GATEWAY,
                "durable owner proof failed verification",
            );
        }
    };
    let (content_type, bytes) = if protobuf {
        (
            "application/x-protobuf",
            prost::Message::encode_to_vec(verified.bundle()),
        )
    } else {
        (
            "application/json",
            serde_json::to_vec(verified.bundle()).expect("address bundle serializes"),
        )
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
            (header::VARY, "Accept"),
        ],
        bytes,
    )
        .into_response()
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
    let Some(protobuf) = representation(&headers) else {
        return failure(
            StatusCode::NOT_ACCEPTABLE,
            "supported types are application/json and application/x-protobuf",
        );
    };
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
fn default_proof_accept(mut headers: HeaderMap, uri: &axum::http::Uri) -> HeaderMap {
    if !headers.contains_key(header::ACCEPT) && uri.path().ends_with("/proof") {
        headers.insert(
            header::ACCEPT,
            axum::http::HeaderValue::from_static("application/x-protobuf"),
        );
    }
    headers
}

pub(crate) fn representation(headers: &HeaderMap) -> Option<bool> {
    let Some(accept) = headers.get(header::ACCEPT) else {
        return Some(false);
    };
    let accept = accept.to_str().ok()?;
    let mut json = None;
    let mut protobuf = None;
    let mut protobuf_alias = None;
    for range in accept.split(',') {
        let mut parts = range.trim().split(';');
        let media = parts.next()?.trim();
        let mut quality = 1.0_f32;
        for part in parts {
            if let Some(value) = part.trim().strip_prefix("q=") {
                quality = value.parse().ok()?;
            }
        }
        if !quality.is_finite() || !(0.0..=1.0).contains(&quality) {
            return None;
        }
        let specificity = match media {
            "application/json" | "application/protobuf" | "application/x-protobuf" => 2,
            "application/*" => 1,
            "*/*" => 0,
            _ => continue,
        };
        let applies_json = matches!(media, "application/json" | "application/*" | "*/*");
        let applies_proto = matches!(media, "application/x-protobuf" | "application/*" | "*/*");
        let applies_alias = matches!(media, "application/protobuf" | "application/*" | "*/*");
        for (applies, slot) in [
            (applies_json, &mut json),
            (applies_proto, &mut protobuf),
            (applies_alias, &mut protobuf_alias),
        ] {
            if applies && slot.is_none_or(|(previous, _)| specificity > previous) {
                *slot = Some((specificity, quality));
            }
        }
    }
    let json = json.map_or(0.0, |(_, q)| q);
    let protobuf = protobuf
        .map_or(0.0_f32, |(_, q)| q)
        .max(protobuf_alias.map_or(0.0, |(_, q)| q));
    if json == 0.0 && protobuf == 0.0 {
        None
    } else {
        Some(protobuf > json)
    }
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
    let epoch = crate::finality_proof::FinalityProof::decode(&finalized.snapshot.finalization)
        .map_or(u64::MAX, |proof| proof.certificate_epoch());
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
        epoch,
    }
}
async fn index_transactions(state: OriginState) -> OriginResult<()> {
    // Replay::new recovered the durable checkpoint before the listener opened.
    // Never scan old archive heights merely to rebuild an ephemeral owner tree.
    let mut height = state.replay.lock().await.next_height()?;
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
                let block =
                    crate::HellasBlock::decode(verified.bundle().canonical_block.as_slice())?;
                state.replay.lock().await.apply(&block, verified).await?;
                height = height
                    .checked_add(1)
                    .ok_or("transaction index height exhausted")?;
                ::tokio::task::yield_now().await;
            }
            None => ::tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
}

// Bound both outstanding requests and completed responses waiting for an
// earlier height. Verification and archive ingestion remain serial below.
const FINALIZED_FETCH_WINDOW: usize = 32;

fn ordered_fetches<T, F, Fut>(first: u64, mut fetch: F) -> impl Stream<Item = (u64, T)>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = T>,
{
    stream::iter(std::iter::successors(Some(first), |height| {
        height.checked_add(1)
    }))
    .map(move |height| {
        let pending = fetch(height);
        async move { (height, pending.await) }
    })
    .buffered(FINALIZED_FETCH_WINDOW)
}

async fn follow_trusted(
    state: OriginState,
    rpc: String,
    status: FollowerStatusSink,
) -> OriginResult<()> {
    loop {
        // The remote client is only a transport/codec here. The authenticated height-key
        // schedule below verifies every block before the native archive sees it.
        let client = match crate::client::RemoteLightClient::connect(rpc.clone()).await {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error,"explorer upstream connection failed");
                ::tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        'connection: loop {
            let next = state
                .indexer
                .get_latest_block()
                .await?
                .map_or(1, |latest| latest.height.saturating_add(1));
            let fetched = ordered_fetches(next, |height| {
                client.get_finalized_block(FinalizedBlockQuery::Height(height))
            });
            futures_util::pin_mut!(fetched);
            while let Some((height, result)) = fetched.next().await {
                let remote = match result {
                    Ok(Some(finalized)) => finalized,
                    Ok(None) => {
                        // Never skip a missing height, even if later responses
                        // already arrived. Retry from the committed archive head.
                        ::tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(%error,"explorer upstream disconnected");
                        ::tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        break 'connection;
                    }
                };
                state.verifier.verify(
                    proof_bundle(&state, remote.clone()),
                    ExplorerQuery::Block(FinalizedBlockQuery::Height(height)),
                )?;
                ingest_finalized_block(&state.indexer, remote, height, &status).await?;
                ::tokio::task::yield_now().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::test_support::finalization;
    use commonware_cryptography::Digestible as _;
    use hellas_genesis::HELLAS_DEVNET_1_ID;
    use std::collections::BTreeMap;
    use tower::ServiceExt as _;

    #[test]
    fn fetch_window_is_bounded_and_orders_responses_before_missing_or_failed_heights() {
        use ::tokio::sync::oneshot;
        use futures_util::FutureExt as _;
        use std::{cell::Cell, rc::Rc};

        // Height three completes first, then a hole/error at two, then one.
        // Neither the hole nor the later block may bypass the first response.
        for stopped in [Ok(None), Err("upstream disconnected")] {
            futures::executor::block_on(async {
                let mut senders = BTreeMap::new();
                let mut receivers = BTreeMap::new();
                for height in 1..=FINALIZED_FETCH_WINDOW as u64 + 1 {
                    let (send, receive) = oneshot::channel::<Result<Option<u64>, &str>>();
                    senders.insert(height, send);
                    receivers.insert(height, receive);
                }
                let started = Rc::new(Cell::new(0));
                let count = started.clone();
                let fetched = ordered_fetches(1, move |height| {
                    count.set(count.get() + 1);
                    let receive = receivers.remove(&height);
                    async move {
                        match receive {
                            Some(receive) => receive.await.unwrap(),
                            None => std::future::pending().await,
                        }
                    }
                });
                let mut fetched = Box::pin(fetched);
                assert!(fetched.next().now_or_never().is_none());
                assert_eq!(started.get(), FINALIZED_FETCH_WINDOW);
                senders.remove(&3).unwrap().send(Ok(Some(3))).unwrap();
                senders.remove(&2).unwrap().send(stopped).unwrap();
                assert!(fetched.next().now_or_never().is_none());
                assert_eq!(started.get(), FINALIZED_FETCH_WINDOW);
                senders.remove(&1).unwrap().send(Ok(Some(1))).unwrap();
                assert_eq!(fetched.next().await, Some((1, Ok(Some(1)))));
                assert_eq!(fetched.next().await, Some((2, stopped)));
                // The production consumer stops on this response and drops all
                // later work, retrying from its last contiguous committed height.
                drop(fetched);
                assert!(senders.values().all(oneshot::Sender::is_closed));
            });
        }
    }

    #[test]
    fn representation_respects_qualities_aliases_and_exclusions() {
        for (accept, expected) in [
            ("application/protobuf", Some(true)),
            (
                "application/x-protobuf;q=0,application/protobuf;q=1",
                Some(true),
            ),
            (
                "application/protobuf;q=1,application/x-protobuf;q=0",
                Some(true),
            ),
            (
                "application/x-protobuf;q=0.5, application/json;q=0.9",
                Some(false),
            ),
            ("application/json;q=0, */*;q=1", Some(true)),
            ("application/json;q=0, application/x-protobuf;q=0", None),
            ("text/html", None),
            ("application/json;q=nan", None),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, accept.parse().unwrap());
            assert_eq!(representation(&headers), expected, "{accept}");
        }
        let headers =
            default_proof_accept(HeaderMap::new(), &"/api/v1/blocks/1/proof".parse().unwrap());
        assert_eq!(representation(&headers), Some(true));
    }

    #[test]
    fn http_origin_without_checkpoint_returns_unavailable() {
        crate::execution::test_support::run_qmdb(|context| async move {
            let owner = crate::domain::SettlementKey::from(
                hellas_kernel::Secp256k1Signer::from_secret_scalar([19; 32])
                    .unwrap()
                    .party_key(),
            );
            let h = crate::edge_index::ReplayHarness::new(
                context.child("h"),
                vec![(owner, 100)],
                "origin-empty",
            )
            .await;
            let (indexer, _handle) = crate::spawn_follower_indexer(
                context.child("follower"),
                "origin-empty-test",
                Config::default(),
                h.committee.verifier.clone(),
                h.head,
            )
            .await
            .unwrap();
            let app = router(OriginState {
                edge_index: h.index,
                indexer,
                replay: Arc::new(::tokio::sync::Mutex::new(h.replay)),
                verifier: Arc::new(h.verifier),
                network_id: HELLAS_DEVNET_1_ID.into(),
            });
            for suffix in ["", "/proof"] {
                let response = app
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .uri(format!("/api/v1/addresses/{owner}{suffix}"))
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                assert_eq!(
                    &body[..],
                    b"no durable verified owner checkpoint is available yet"
                );
            }
        });
    }

    #[test]
    fn http_origin_returns_durable_owner_and_transaction_evidence() {
        crate::execution::test_support::run_qmdb(|context| async move {
            let maker = hellas_kernel::Secp256k1Signer::from_secret_scalar([19; 32]).unwrap();
            let taker = hellas_kernel::Secp256k1Signer::from_secret_scalar([20; 32]).unwrap();
            let owner = crate::domain::SettlementKey::from(maker.party_key());
            let mut h = crate::edge_index::ReplayHarness::new(
                context.child("h"),
                vec![(owner, 100)],
                "origin-http",
            )
            .await;
            assert!(
                h.replay
                    .owner_proof(owner, 0, 64, None)
                    .await
                    .unwrap()
                    .is_none()
            );
            let genesis = h.head.clone();
            let (_, _, transaction) = crate::edge_index::replay_basic(h.network, 0, &maker, &taker);
            let first = h
                .append(vec![crate::domain::Transaction::Kernel(transaction)])
                .await;
            let first_block = h.head.clone();
            let first_address = h
                .replay
                .owner_proof(owner, 0, 64, Some(&first.payload))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                h.verifier
                    .verify_address(first_address.bundle().clone(), owner, 0, 64)
                    .unwrap()
                    .summary()
                    .count,
                1
            );
            let latest = h.append(Vec::new()).await;
            let (indexer, _handle) = crate::spawn_follower_indexer(
                context.child("follower"),
                "origin-test",
                Config::default(),
                h.committee.verifier.clone(),
                genesis,
            )
            .await
            .unwrap();
            indexer
                .ingest_finalized(
                    first_block.clone(),
                    finalization(&h.committee, &first_block),
                )
                .await
                .unwrap();
            indexer
                .ingest_finalized(h.head.clone(), finalization(&h.committee, &h.head))
                .await
                .unwrap();
            let tx = crate::verified_explorer::transaction_digest(&first_block.txs()[0]);
            let verifier = Arc::new(h.verifier);
            let state = OriginState {
                edge_index: h.index.clone(),
                indexer,
                replay: Arc::new(::tokio::sync::Mutex::new(h.replay)),
                verifier: verifier.clone(),
                network_id: HELLAS_DEVNET_1_ID.into(),
            };
            let app = router(state);
            for pin in [None, Some(latest.payload.as_str())] {
                let query = pin.map_or(String::new(), |pin| format!("?payload={pin}"));
                let response = app
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .uri(format!("/api/v1/addresses/{owner}/proof{query}"))
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(
                    response.into_body(),
                    crate::verified_explorer::MAX_PROOF_BYTES,
                )
                .await
                .unwrap();
                let bundle =
                    <crate::verified_explorer::AddressProofBundle as prost::Message>::decode(bytes)
                        .unwrap();
                let verified = verifier.verify_address(bundle, owner, 0, 64).unwrap();
                assert_eq!(verified.block().view().height(), latest.height);
                assert_eq!(verified.summary().count, 1);
                assert_eq!(verified.summary().balance, 0); // The coin is locked in the edge.
            }
            for missing in [first.payload, "00".repeat(32)] {
                for accept in ["application/json", "application/x-protobuf"] {
                    let response = app
                        .clone()
                        .oneshot(
                            axum::http::Request::builder()
                                .uri(format!("/api/v1/addresses/{owner}/proof?payload={missing}"))
                                .header(header::ACCEPT, accept)
                                .body(axum::body::Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::CONFLICT);
                    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                    assert_eq!(response.headers()[header::VARY], "Accept");
                    assert_eq!(response.headers()[header::CONTENT_TYPE], accept);
                    let bytes = axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .unwrap();
                    let error = if accept == "application/json" {
                        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
                    } else {
                        serde_json::to_value(
                            <OwnerSnapshotError as prost::Message>::decode(bytes).unwrap(),
                        )
                        .unwrap()
                    };
                    assert_eq!(error["schema_version"], PROOF_SCHEMA_VERSION);
                    assert_eq!(error["network_id"], HELLAS_DEVNET_1_ID);
                    assert_eq!(
                        error["message"],
                        "The requested verified owner snapshot is unavailable. Request latest holdings explicitly."
                    );
                    assert_eq!(error["code"], "snapshot_unavailable");
                    assert_eq!(error["latest_url"], format!("/api/v1/addresses/{owner}"));
                    assert!(error.get("block").is_none());
                    let response = app
                        .clone()
                        .oneshot(
                            axum::http::Request::builder()
                                .uri(error["latest_url"].as_str().unwrap())
                                .body(axum::body::Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                }
            }
            for malformed in ["", "bad", &"A".repeat(64), &"g".repeat(64)] {
                let response = app
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .uri(format!(
                                "/api/v1/addresses/{owner}/proof?payload={malformed}"
                            ))
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            }
            for uri in [
                "/api/v1/blocks/1/proof".to_owned(),
                format!("/api/v1/blocks/{}/proof", hex::encode(first_block.digest())),
                format!("/api/v1/transactions/{}/proof", hex::encode(tx)),
            ] {
                for accept in [
                    None,
                    Some("application/json"),
                    Some("application/x-protobuf"),
                    Some("application/protobuf"),
                    Some("text/html"),
                ] {
                    let mut request = axum::http::Request::builder().uri(&uri);
                    if let Some(accept) = accept {
                        request = request.header(header::ACCEPT, accept);
                    }
                    let response = app
                        .clone()
                        .oneshot(request.body(axum::body::Body::empty()).unwrap())
                        .await
                        .unwrap();
                    if accept == Some("text/html") {
                        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
                        continue;
                    }
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(response.headers()[header::VARY], "Accept");
                    let json = accept == Some("application/json");
                    assert_eq!(
                        response.headers()[header::CONTENT_TYPE],
                        if json {
                            "application/json"
                        } else {
                            "application/x-protobuf"
                        }
                    );
                    let body = axum::body::to_bytes(
                        response.into_body(),
                        crate::verified_explorer::MAX_PROOF_BYTES,
                    )
                    .await
                    .unwrap();
                    let bundle = if json {
                        serde_json::from_slice(&body).unwrap()
                    } else {
                        <ProofBundle as prost::Message>::decode(body).unwrap()
                    };
                    let query = if uri.contains("/transactions/") {
                        ExplorerQuery::Transaction(tx)
                    } else {
                        ExplorerQuery::Block(FinalizedBlockQuery::Height(1))
                    };
                    assert!(verifier.verify(bundle, query).is_ok());
                }
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
