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
            edge_index: Some(edge_index),
            owner_index: application.owner_index(),
            owners: Arc::new(RwLock::new(OwnerSnapshots::default())),
            indexer: indexer.clone(),
            verifier,
            network_id: info.network_id.clone(),
            transactions: Arc::new(RwLock::new(BTreeMap::new())),
        };
        let app = router(state.clone());
        let listener = ::tokio::net::TcpListener::bind(options.listen).await?;
        ::tokio::select! {
            result = index_transactions(state.clone(), replay) => result,
            result = axum::serve(listener,app) => result.map_err(Into::into),
            result = follow_trusted(state,options.rpc,options.status) => result,
        }
    })
}

#[derive(Clone)]
struct OriginState {
    edge_index: Option<crate::edge_index::EdgeIndex>,
    indexer: ChainIndexer,
    verifier: Arc<ExplorerVerifier>,
    network_id: String,
    transactions: Arc<RwLock<BTreeMap<Digest, u64>>>,
    owner_index: crate::OwnerIndex,
    owners: Arc<RwLock<OwnerSnapshots>>,
}

#[derive(Clone)]
struct OwnerSnapshot {
    tree: crate::owner_proof::MemoryOwnerTree,
    block: ProofBundle,
}
/// Keeps pagination pinned to a recently finalized payload while new blocks arrive.
/// Readers hold an Arc, so eviction cannot invalidate an in-flight proof generation.
const OWNER_SNAPSHOT_RETENTION: usize = 32;

#[derive(Default)]
struct OwnerSnapshots {
    by_height: BTreeMap<u64, Arc<OwnerSnapshot>>,
    by_payload: BTreeMap<String, u64>,
}
impl OwnerSnapshots {
    fn insert(&mut self, snapshot: OwnerSnapshot) -> Result<(), &'static str> {
        let height = snapshot.block.height;
        let payload = &snapshot.block.payload;
        if self
            .by_height
            .get(&height)
            .is_some_and(|previous| previous.block.payload != *payload)
            || self
                .by_payload
                .get(payload)
                .is_some_and(|previous| *previous != height)
        {
            return Err("conflicting finalized owner snapshot");
        }
        self.by_payload.insert(payload.clone(), height);
        self.by_height.insert(height, Arc::new(snapshot));
        while self.by_height.len() > OWNER_SNAPSHOT_RETENTION {
            let (_, expired) = self.by_height.pop_first().expect("nonempty snapshot cache");
            self.by_payload.remove(&expired.block.payload);
        }
        Ok(())
    }
    fn get(&self, payload: Option<&str>) -> Option<Arc<OwnerSnapshot>> {
        match payload {
            Some(payload) => self.by_height.get(self.by_payload.get(payload)?).cloned(),
            None => self
                .by_height
                .last_key_value()
                .map(|(_, snapshot)| snapshot.clone()),
        }
    }
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
    match state.edge_index {
        Some(index) => {
            ws.on_upgrade(move |socket| crate::edge_index::rpc::serve_socket(socket, index))
        }
        None => failure(StatusCode::SERVICE_UNAVAILABLE, "index_not_ready"),
    }
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
    let height = query
        .height
        .or_else(|| {
            state
                .edge_index
                .as_ref()
                .and_then(|index| index.transaction_height(&hex::encode(tx)).ok().flatten())
        })
        .or_else(|| {
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
    let Some(snapshot) = state
        .owners
        .read()
        .expect("owner snapshot lock")
        .get(query.payload.as_deref())
    else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "requested verified owner snapshot is unavailable or still catching up",
        );
    };
    let page = match crate::owner_proof::prove_owner_page(
        &snapshot.tree,
        owner,
        query.offset,
        query.limit,
    )
    .await
    {
        Ok(page) => page,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid owner page"),
    };
    let bundle = crate::verified_explorer::AddressProofBundle {
        schema_version: PROOF_SCHEMA_VERSION,
        block: Some(snapshot.block.clone()),
        page: serde_json::to_vec(&page).expect("owner page serializes"),
    };
    let verified = match state
        .verifier
        .verify_address(bundle, owner, query.offset, query.limit)
    {
        Ok(verified) => verified,
        Err(_) => return failure(StatusCode::BAD_GATEWAY, "owner proof failed verification"),
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
async fn index_transactions(
    state: OriginState,
    mut replay: crate::edge_index::Replay<tokio::Context>,
) -> OriginResult<()> {
    let mut height = 1_u64;
    let mut owner_tree = crate::owner_proof::MemoryOwnerTree::default();
    let mut previous = BTreeMap::new();
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
                replay.apply(&block, verified.bundle().clone()).await?;
                state.owner_index.apply_finalized(&block)?;
                let current = state
                    .owner_index
                    .holdings_snapshot()
                    .into_iter()
                    .map(|(owner, id, kind, balance)| ((owner, id), (kind, balance)))
                    .collect::<BTreeMap<_, _>>();
                for ((owner, id), value) in &previous {
                    if current.get(&(*owner, *id)) != Some(value) {
                        crate::owner_proof::update_holding(&mut owner_tree, *owner, *id, None)
                            .await?;
                    }
                }
                for ((owner, id), value) in &current {
                    if previous.get(&(*owner, *id)) != Some(value) {
                        crate::owner_proof::update_holding(
                            &mut owner_tree,
                            *owner,
                            *id,
                            Some(*value),
                        )
                        .await?;
                    }
                }
                if crate::owner_proof::owner_root(&owner_tree).await?
                    != verified.view().owner_root()
                {
                    return Err(
                        "replayed owner state does not match the certified owner root".into(),
                    );
                }
                state
                    .owners
                    .write()
                    .expect("owner snapshot lock")
                    .insert(OwnerSnapshot {
                        tree: owner_tree.clone(),
                        block: verified.bundle().clone(),
                    })?;
                previous = current;
                height = height
                    .checked_add(1)
                    .ok_or("transaction index height exhausted")?;
                ::tokio::task::yield_now().await;
            }
            None => ::tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
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
        loop {
            let next = state
                .indexer
                .get_latest_block()
                .await?
                .map_or(1, |latest| latest.height.saturating_add(1));
            let remote = match client
                .get_finalized_block(FinalizedBlockQuery::Height(next))
                .await
            {
                Ok(Some(finalized)) => finalized,
                Ok(None) => {
                    ::tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error,"explorer upstream disconnected");
                    ::tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    break;
                }
            };
            state.verifier.verify(
                proof_bundle(&state, remote.clone()),
                ExplorerQuery::Block(FinalizedBlockQuery::Height(next)),
            )?;
            ingest_finalized_block(&state.indexer, remote, next, &status).await?;
            ::tokio::task::yield_now().await;
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
    fn owner_snapshot_retention_evicts_oldest_without_regressing_latest() {
        fn snapshot(height: u64) -> OwnerSnapshot {
            OwnerSnapshot {
                tree: crate::owner_proof::MemoryOwnerTree::default(),
                block: ProofBundle {
                    height,
                    payload: format!("{height:064x}"),
                    ..ProofBundle::default()
                },
            }
        }
        let mut snapshots = OwnerSnapshots::default();
        snapshots.insert(snapshot(1)).unwrap();
        let in_flight = snapshots.get(Some(&format!("{:064x}", 1))).unwrap();
        for height in 2..=OWNER_SNAPSHOT_RETENTION as u64 + 1 {
            snapshots.insert(snapshot(height)).unwrap();
        }
        assert_eq!(snapshots.by_height.len(), OWNER_SNAPSHOT_RETENTION);
        assert_eq!(snapshots.by_payload.len(), OWNER_SNAPSHOT_RETENTION);
        assert!(snapshots.get(Some(&format!("{:064x}", 1))).is_none());
        assert_eq!(in_flight.block.height, 1);
        assert_eq!(
            snapshots
                .get(Some(&format!("{:064x}", 2)))
                .unwrap()
                .block
                .height,
            2
        );
        let latest = OWNER_SNAPSHOT_RETENTION as u64 + 1;
        snapshots.insert(snapshot(0)).unwrap();
        assert_eq!(snapshots.get(None).unwrap().block.height, latest);
        assert!(snapshots.get(Some(&format!("{:064x}", 0))).is_none());
        let mut conflict = snapshot(latest);
        conflict.block.payload = "f".repeat(64);
        assert!(snapshots.insert(conflict).is_err());
        let mut conflict = snapshot(latest + 1);
        conflict.block.payload = format!("{latest:064x}");
        assert!(snapshots.insert(conflict).is_err());
        assert_eq!(snapshots.by_payload.len(), OWNER_SNAPSHOT_RETENTION);
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
            let owner = crate::domain::SettlementKey::from_bytes([1; 33]);
            let mut tree = crate::owner_proof::MemoryOwnerTree::default();
            crate::owner_proof::update_holding(
                &mut tree,
                owner,
                Digest::from([7; 32]),
                Some((0, 321)),
            )
            .await
            .unwrap();
            crate::owner_proof::update_holding(
                &mut tree,
                owner,
                Digest::from([8; 32]),
                Some((1, 0)),
            )
            .await
            .unwrap();
            let block = block.with_owner_root(crate::owner_proof::owner_root(&tree).await.unwrap());
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
            let owner_index =
                crate::OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, Vec::new());
            let (indexer, _handle) = crate::spawn_follower_indexer(
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
            let state = OriginState {
                edge_index: None,
                owner_index,
                owners: Arc::new(RwLock::new(OwnerSnapshots::default())),
                indexer,
                verifier: verifier.clone(),
                network_id: HELLAS_DEVNET_1_ID.into(),
                transactions,
            };
            let finalized = state
                .indexer
                .get_finalized_block(FinalizedBlockQuery::Height(1))
                .await
                .unwrap()
                .unwrap();
            state
                .owners
                .write()
                .unwrap()
                .insert(OwnerSnapshot {
                    tree: tree.clone(),
                    block: proof_bundle(&state, finalized),
                })
                .unwrap();
            let app = router(state.clone());
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(format!("/api/v1/addresses/{owner}/proof?offset=0&limit=64"))
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
            assert_eq!(
                verifier
                    .verify_address(bundle, owner, 0, 64)
                    .unwrap()
                    .summary()
                    .balance,
                321
            );
            // New finality changes the owner state before the uncached second page is read.
            crate::owner_proof::update_holding(&mut tree, owner, Digest::from([8; 32]), None)
                .await
                .unwrap();
            crate::owner_proof::update_holding(
                &mut tree,
                owner,
                Digest::from([7; 32]),
                Some((0, 999)),
            )
            .await
            .unwrap();
            let next = index_block(&block, Digest::from([3; 32]), Vec::new())
                .with_owner_root(crate::owner_proof::owner_root(&tree).await.unwrap());
            state
                .indexer
                .ingest_finalized(next.clone(), finalization(&fixture, &next))
                .await
                .unwrap();
            let finalized = state
                .indexer
                .get_finalized_block(FinalizedBlockQuery::Height(2))
                .await
                .unwrap()
                .unwrap();
            state
                .owners
                .write()
                .unwrap()
                .insert(OwnerSnapshot {
                    tree: tree.clone(),
                    block: proof_bundle(&state, finalized),
                })
                .unwrap();
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(format!(
                            "/api/v1/addresses/{owner}/proof?offset=1&limit=1&payload={}",
                            hex::encode(block.digest())
                        ))
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
            let pinned =
                <crate::verified_explorer::AddressProofBundle as prost::Message>::decode(bytes)
                    .unwrap();
            let verified = verifier.verify_address(pinned, owner, 1, 1).unwrap();
            assert_eq!(verified.block().view().height(), 1);
            assert_eq!(verified.summary().balance, 321);
            assert_eq!(verified.page().holdings[0].object_id, [8; 32]);
            assert_eq!(
                state.owners.read().unwrap().get(None).unwrap().block.height,
                2
            );

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
