//! One durable execution pipeline for consensus and replication.
use super::store::{UtxoDatabase, utxo_db_config};
use crate::{
    Application, ChainIndexer, HellasBlock, app::MarshalMailbox, config::Config, domain::Scheme,
};
use commonware_consensus::{Heightable, marshal::standard::Standard};
use commonware_glue::stateful::{
    self, SyncPlan,
    db::{AttachableResolverSet, StateSyncSet, SyncEngineConfig},
};
use commonware_runtime::{Spawner, Supervisor as _, tokio::Context};
use commonware_utils::{NZU64, NZUsize};
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::{Arc, atomic::Ordering},
};
use tokio::sync::watch;

pub(crate) type Execution<R> =
    stateful::Stateful<Context, Application, Scheme, Standard<HellasBlock>, R>;
pub(crate) type Mailbox = stateful::Mailbox<Context, Application>;

pub(crate) fn init<R>(
    context: Context,
    application: Application,
    config: &Config,
    marshal: MarshalMailbox,
    plan: SyncPlan<Context, Scheme, Standard<HellasBlock>>,
    resolvers: R,
    retention: Option<NonZeroU64>,
) -> (Execution<R>, Mailbox)
where
    R: AttachableResolverSet<UtxoDatabase<Context>>,
    UtxoDatabase<Context>: StateSyncSet<Context, R, crate::domain::Digest>,
{
    stateful::Stateful::init(
        context.child("actor"),
        stateful::Config {
            input_provider: application.mempool.clone(),
            application,
            db_config: utxo_db_config(
                &context,
                "chain",
                config.page_cache_size,
                config.page_cache_count,
            ),
            marshal,
            mailbox_size: NonZeroUsize::new(config.mailbox_size).unwrap_or(NonZeroUsize::MIN),
            plan,
            resolvers,
            sync_config: SyncEngineConfig {
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                max_outstanding_requests: 8,
                update_channel_size: NZUsize!(256),
                max_retained_roots: 8,
            },
            // QMDB must retain the ack window for crash recovery. The archive's
            // independent retention cap keeps the complete archive by default.
            prune_config: Some(stateful::PruneConfig {
                max_pending_acks: NonZeroUsize::MIN,
                maintenance_interval: NZUsize!(64),
                retained_marshal_blocks: retention.map_or(0, |n| {
                    usize::try_from(n.get())
                        .unwrap_or(usize::MAX)
                        .saturating_sub(2)
                }),
                retained_qmdb_blocks: 0,
            }),
        },
    )
}

#[derive(Clone)]
pub(crate) struct Publication {
    pub(crate) archive: ChainIndexer,
    pub(crate) retention: Option<NonZeroU64>,
    pub(crate) readiness: Arc<crate::node::Readiness>,
    pub(crate) progress: watch::Sender<u64>,
    #[cfg(feature = "indexer-api")]
    pub(crate) index: Option<crate::edge_index::Publication>,
}
impl Publication {
    pub(crate) async fn finalized<E>(&self, block: &HellasBlock, database: &UtxoDatabase<E>)
    where
        E: commonware_storage::Context + Spawner + Send + Sync + 'static,
    {
        #[cfg(feature = "indexer-api")]
        if let Some(index) = &self.index {
            index
                .finalized(block, database)
                .await
                .expect("certified index publication failed");
        }
        if let Some(retain) = self.retention {
            // Two blocks are needed by Stateful's one-ack recovery window.
            self.archive.retain_from(
                block.height().get().saturating_sub(retain.get() - 1),
                block.height().get().saturating_sub(retain.get().max(2) - 1),
            );
        }
        self.readiness
            .applied
            .fetch_max(block.height().get(), Ordering::AcqRel);
        self.progress.send_if_modified(|height| {
            let advanced = *height < block.height().get();
            *height = (*height).max(block.height().get());
            advanced
        });
        let _ = database;
    }
}

/// All execution roles share the directory lock and provisioned chain identity.
pub(crate) fn lock(directory: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(directory)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("node.lock"))?;
    file.try_lock().map_err(std::io::Error::other)?;
    Ok(file)
}
pub(crate) fn pin(
    directory: &std::path::Path,
    genesis: &hellas_genesis::Genesis,
    threshold: &[u8],
    payload: crate::domain::Digest,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Write};
    let identity = serde_json::to_vec(&(genesis, threshold, hex::encode(payload)))?;
    let path = directory.join("chain-identity.json");
    match std::fs::read(&path) {
        Ok(stored) if stored == identity => Ok(()),
        Ok(_) => Err(Error::new(
            ErrorKind::InvalidData,
            "state directory belongs to another chain",
        )),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)?;
            file.write_all(&identity)?;
            file.sync_all()?;
            #[cfg(unix)]
            std::fs::File::open(directory)?.sync_all()?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn verify_floor<P>(
    plan: &SyncPlan<Context, Scheme, Standard<HellasBlock>>,
    provider: &P,
) -> Result<(), crate::QueryError>
where
    P: commonware_cryptography::certificate::Provider<
            Scope = commonware_consensus::types::Epoch,
            Scheme = Scheme,
        >,
{
    if let Some(floor) = plan.floor() {
        let scheme = provider
            .scheme(floor.proposal.round.epoch())
            .ok_or_else(|| {
                crate::QueryError::StateUnavailable("floor epoch is not provisioned".into())
            })?;
        if !floor.verify(
            &mut rand::rng(),
            scheme.as_ref(),
            &commonware_parallel::Sequential,
        ) {
            return Err(crate::QueryError::StateUnavailable(
                "floor certificate is invalid".into(),
            ));
        }
    }
    Ok(())
}

/// Stateful owns recovery; restore only the cursor of its authenticated database.
pub(crate) async fn restore(
    archive: &ChainIndexer,
    database: &UtxoDatabase<Context>,
    owner: &crate::owner_index::OwnerIndex,
    startup: Option<commonware_consensus::types::Height>,
) -> Result<u64, crate::QueryError> {
    use commonware_consensus::types::Height;
    let processed = archive.marshal.get_processed_height().await;
    let height = startup
        .into_iter()
        .chain(processed)
        .map(|h| h.get())
        .chain([owner.cursor().height])
        .max()
        .unwrap_or(0);
    if height == 0 {
        return Ok(0);
    }
    let reader = database.read().await;
    // At most one finalized application can precede marshal's durable ack.
    for candidate in [height.saturating_add(1), height] {
        if let Some(block) = archive.marshal.get_block(Height::new(candidate)).await
            && reader.root() == block.state_root()
            && block.sync_target().root == reader.root()
            && super::owner_tree::stored_root(&reader)
                .await
                .map_err(|e| crate::QueryError::StateUnavailable(e.to_string()))?
                == block.owner_root()
        {
            owner.publish_cursor(&block);
            return Ok(candidate);
        }
    }
    Err(crate::QueryError::StateUnavailable(
        "executed checkpoint differs from archive".into(),
    ))
}
