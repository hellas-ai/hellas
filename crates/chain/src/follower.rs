use crate::domain::{Digest, PublicKey};
use crate::{
    Application, ApplicationConfig, ChainIndexer, ConsensusInfo, ConsensusVerifier, FinalizedBlock,
    FinalizedBlockQuery, IngestError, IngestOutcome, LightClient as _, QueryError,
    client::RemoteLightClient, config::Config, spawn_follower_indexer,
};
use commonware_codec::DecodeExt;
use commonware_consensus::Heightable;
use commonware_cryptography::Digestible;
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use futures_util::StreamExt as _;
use hellas_kernel::NetworkId;
use hellas_rpc::pb::chain::{ActivityEvent, ActivityEventKind, activity_event};
use std::{fmt, path::PathBuf, sync::Arc, time::Duration};
use thiserror::Error;
use tracing::{info, warn};

const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const CATCH_UP_BATCH: u64 = 8;
const IDLE_SYNC_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Error)]
pub enum FollowerError {
    #[error("unable to determine local data directory")]
    MissingDataDirectory,
    #[error("storage directory is not valid UTF-8: {0}")]
    NonUtf8StorageDirectory(PathBuf),
    #[error("invalid validator key data")]
    InvalidValidatorKey,
    #[error("chain reported network id `{0}`, which does not fit a kernel NetworkId")]
    UnrepresentableNetworkId(String),
    #[error("invalid {field}: expected 32 bytes, got {len}")]
    InvalidDigest { field: &'static str, len: usize },
    #[error("activity event was missing its event body")]
    MissingActivityEvent,
    #[error("finalization activity was missing its proposal")]
    MissingFinalizationProposal,
    #[error("activity stream ended")]
    ActivityStreamEnded,
    #[error("activity stream failed: {0}")]
    ActivityStream(String),
    #[error("remote latest is {remote_latest}, but finalized block at height {height} was absent")]
    MissingFinalizedBlock { height: u64, remote_latest: u64 },
    #[error("remote snapshot height {remote} is behind local height {local}")]
    RemoteBehind { local: u64, remote: u64 },
    #[error(
        "requested finalized height {requested}, but snapshot height was {snapshot} and block height was {block}"
    )]
    FinalizedBlockHeightMismatch {
        requested: u64,
        snapshot: u64,
        block: u64,
    },
    #[error("finalized snapshot height {snapshot} did not match block height {block}")]
    SnapshotBlockHeightMismatch { snapshot: u64, block: u64 },
    #[error("finalized snapshot payload {snapshot:?} did not match block payload {block:?}")]
    SnapshotBlockPayloadMismatch { snapshot: Digest, block: Digest },
    #[error("{0}")]
    Query(#[from] QueryError),
    #[error("local follower state query failed: {0}")]
    LocalQuery(QueryError),
    #[error("{0}")]
    Consensus(#[from] crate::ConsensusVerificationError),
    #[error("{0}")]
    Ingest(#[from] IngestError),
}

impl FollowerError {
    const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::ActivityStreamEnded
                | Self::ActivityStream(_)
                | Self::MissingFinalizedBlock { .. }
                | Self::Query(
                    QueryError::ChannelClosed
                        | QueryError::StateUnavailable(_)
                        | QueryError::Remote(_)
                        | QueryError::Connect(_)
                )
        )
    }
}

#[derive(Clone, Debug)]
pub struct FollowerOptions {
    pub rpc: String,
    pub storage_dir: Option<PathBuf>,
    pub partition_prefix: String,
    pub status: FollowerStatusSink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FollowerStatus {
    ActivityStreamSubscribed,
    ActivityFinalization { payload: Digest },
    BlockIngested { height: u64, outcome: IngestOutcome },
}

#[derive(Clone, Default)]
pub struct FollowerStatusSink {
    emit: Option<Arc<dyn Fn(FollowerStatus) + Send + Sync>>,
}

impl FollowerStatusSink {
    pub fn quiet() -> Self {
        Self::default()
    }

    pub fn callback(emit: impl Fn(FollowerStatus) + Send + Sync + 'static) -> Self {
        Self {
            emit: Some(Arc::new(emit)),
        }
    }

    fn emit(&self, status: FollowerStatus) {
        if let Some(emit) = &self.emit {
            emit(status);
        }
    }
}

impl fmt::Debug for FollowerStatusSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FollowerStatusSink")
            .field("enabled", &self.emit.is_some())
            .finish()
    }
}

pub fn run(options: FollowerOptions) -> Result<(), FollowerError> {
    let storage_dir = options
        .storage_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(default_storage_dir)?;
    let storage_dir_utf8 = storage_dir
        .to_str()
        .ok_or_else(|| FollowerError::NonUtf8StorageDirectory(storage_dir.clone()))?;
    let runtime_cfg = tokio::Config::new()
        .with_storage_directory(storage_dir_utf8)
        .with_tcp_nodelay(Some(true));
    tokio::Runner::new(runtime_cfg)
        .start(move |context| async move { follow(context, options).await })
}

async fn follow(context: tokio::Context, options: FollowerOptions) -> Result<(), FollowerError> {
    let client = RemoteLightClient::connect(options.rpc.clone()).await?;
    let consensus_info = client.get_consensus_info().await?;
    let verifier = ConsensusVerifier::new(&consensus_info)?;
    let genesis_leader = genesis_leader(&consensus_info)?;
    let network = NetworkId::new(&consensus_info.network_id).ok_or_else(|| {
        FollowerError::UnrepresentableNetworkId(consensus_info.network_id.clone())
    })?;
    let application = Application::new(
        context.child("app"),
        network,
        genesis_leader,
        Vec::new(),
        &format!("{}-genesis", options.partition_prefix),
        ApplicationConfig::default(),
    )
    .await;
    let (indexer, _marshal) = spawn_follower_indexer(
        context.child("indexer"),
        &options.partition_prefix,
        Config::default(),
        verifier,
        application.genesis_block(),
    )
    .await?;
    follow_remote(indexer, options.rpc, consensus_info, options.status).await
}

pub(crate) async fn follow_remote(
    indexer: ChainIndexer,
    rpc: String,
    consensus_info: ConsensusInfo,
    status: FollowerStatusSink,
) -> Result<(), FollowerError> {
    loop {
        match follow_connection(&indexer, &rpc, &consensus_info, &status).await {
            Ok(()) => unreachable!("follow_connection only returns when the stream disconnects"),
            Err(err) if err.retryable() => {
                warn!(error = %err, "follower upstream disconnected");
                ::tokio::time::sleep(RECONNECT_DELAY).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn follow_connection(
    indexer: &ChainIndexer,
    rpc: &str,
    consensus_info: &ConsensusInfo,
    status: &FollowerStatusSink,
) -> Result<(), FollowerError> {
    let sync_client = RemoteLightClient::connect(rpc.to_string())
        .await?
        .with_consensus_info(consensus_info)?;
    let activity_client = RemoteLightClient::connect(rpc.to_string())
        .await?
        .with_consensus_info(consensus_info)?;
    let mut stream = activity_client
        .subscribe_activity(vec![ActivityEventKind::Finalization])
        .await?;
    info!("follower activity stream subscribed");
    status.emit(FollowerStatus::ActivityStreamSubscribed);

    let mut needs_sync = true;
    loop {
        if needs_sync {
            needs_sync = catch_up_batch(indexer, &sync_client, CATCH_UP_BATCH, status).await?;
        }
        let delay = if needs_sync {
            Duration::ZERO
        } else {
            IDLE_SYNC_INTERVAL
        };
        ::tokio::select! {
            event = stream.next() => {
                let event = event
                    .ok_or(FollowerError::ActivityStreamEnded)?
                    .map_err(|err| FollowerError::ActivityStream(err.to_string()))?;
                match finalized_payload(event) {
                    Ok(Some(payload)) => {
                        status.emit(FollowerStatus::ActivityFinalization { payload });
                        needs_sync = true;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(error = %err, "skipping malformed activity event");
                    }
                }
            }
            () = ::tokio::time::sleep(delay) => {
                needs_sync = true;
            }
        }
    }
}

async fn catch_up_batch(
    indexer: &ChainIndexer,
    client: &RemoteLightClient,
    max_blocks: u64,
    status: &FollowerStatusSink,
) -> Result<bool, FollowerError> {
    let mut next_height = indexer
        .get_latest_block()
        .await
        .map_err(FollowerError::LocalQuery)?
        .map_or(1, |block| block.height.saturating_add(1));
    let Some(remote_latest) = client.get_latest_block().await? else {
        return Ok(false);
    };
    if next_height > remote_latest.height.saturating_add(1) {
        return Err(FollowerError::RemoteBehind {
            local: next_height.saturating_sub(1),
            remote: remote_latest.height,
        });
    }
    let target_height = remote_latest.height;
    let batch_end = target_height.min(next_height.saturating_add(max_blocks.saturating_sub(1)));
    while next_height <= batch_end {
        let Some(finalized) = client
            .get_finalized_block(FinalizedBlockQuery::Height(next_height))
            .await?
        else {
            return Err(FollowerError::MissingFinalizedBlock {
                height: next_height,
                remote_latest: remote_latest.height,
            });
        };
        ingest_finalized_block(indexer, finalized, next_height, status).await?;
        next_height = next_height.saturating_add(1);
    }
    Ok(batch_end < target_height)
}

pub(crate) async fn ingest_finalized_block(
    indexer: &ChainIndexer,
    finalized: FinalizedBlock,
    requested: u64,
    status: &FollowerStatusSink,
) -> Result<(), FollowerError> {
    let block = ChainIndexer::decode_block(&finalized.block)?;
    let block_height = block.height().get();
    let block_payload = block.digest();
    if finalized.snapshot.height != block_height {
        return Err(FollowerError::SnapshotBlockHeightMismatch {
            snapshot: finalized.snapshot.height,
            block: block_height,
        });
    }
    if finalized.snapshot.payload != block_payload {
        return Err(FollowerError::SnapshotBlockPayloadMismatch {
            snapshot: finalized.snapshot.payload,
            block: block_payload,
        });
    }
    if requested != block_height {
        return Err(FollowerError::FinalizedBlockHeightMismatch {
            requested,
            snapshot: finalized.snapshot.height,
            block: block_height,
        });
    }

    let finalization = ChainIndexer::decode_finalization(&finalized.snapshot.finalization)?;
    let outcome = indexer.ingest_finalized(block, finalization).await?;
    status.emit(FollowerStatus::BlockIngested {
        height: block_height,
        outcome,
    });
    Ok(())
}

fn finalized_payload(event: ActivityEvent) -> Result<Option<Digest>, FollowerError> {
    let Some(event) = event.event else {
        return Err(FollowerError::MissingActivityEvent);
    };
    match event {
        activity_event::Event::Finalization(finalization) => {
            let proposal = finalization
                .proposal
                .ok_or(FollowerError::MissingFinalizationProposal)?;
            Ok(Some(digest_from_bytes(
                proposal.payload,
                "finalization.proposal.payload",
            )?))
        }
        _ => Ok(None),
    }
}

fn digest_from_bytes(bytes: Vec<u8>, field: &'static str) -> Result<Digest, FollowerError> {
    let len = bytes.len();
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| FollowerError::InvalidDigest { field, len })?;
    Ok(Digest::from(raw))
}

fn default_storage_dir() -> Result<PathBuf, FollowerError> {
    Ok(dirs::data_local_dir()
        .ok_or(FollowerError::MissingDataDirectory)?
        .join("hellas")
        .join("follower"))
}

fn genesis_leader(info: &ConsensusInfo) -> Result<PublicKey, FollowerError> {
    let validator = info
        .validators
        .first()
        .ok_or(FollowerError::InvalidValidatorKey)?;
    let bytes = hex::decode(validator).map_err(|_| FollowerError::InvalidValidatorKey)?;
    PublicKey::decode(bytes.as_slice()).map_err(|_| FollowerError::InvalidValidatorKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_state_unavailability_is_retryable() {
        let upstream = FollowerError::Query(QueryError::StateUnavailable(
            "finalization is not visible yet".to_string(),
        ));

        assert!(upstream.retryable());
    }

    #[test]
    fn local_state_unavailability_is_fatal() {
        let local = FollowerError::LocalQuery(QueryError::StateUnavailable(
            "stored finalization is missing".to_string(),
        ));

        assert!(!local.retryable());
    }
}
