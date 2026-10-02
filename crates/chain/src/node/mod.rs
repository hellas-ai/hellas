//! A verified, executing chain node. Paid consumers receive only caught-up views.
use crate::{
    ChainIndexer, ConsensusInfo, ConsensusVerifier, FinalizedBlock, FinalizedBlockQuery,
    FinalizedBlockView, HellasBlock, QueryError,
    config::{Config as ArchiveConfig, genesis_allocations},
    domain::{Digest, PublicKey},
    rpc::LocalLightClient,
};
#[cfg(any(test, feature = "indexer-api"))]
use crate::{domain::SettlementKey, execution::store::UtxoDatabase};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::CertifiableBlock as _;
use commonware_cryptography::Digestible as _;
use commonware_runtime::{Spawner as _, Supervisor as _, tokio as runtime};
use std::{
    num::NonZeroU64,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::watch;

pub(crate) mod replication;
pub(crate) mod transport;
pub use transport::FullNode;
#[cfg(feature = "validator")]
pub(crate) use transport::serve_validator_archive;

/// Independently provisioned execution inputs. Peers supply blocks, never these pins.
#[derive(Clone, Debug)]
pub struct Config {
    pub genesis: hellas_genesis::Genesis,
    pub threshold_identity: Vec<u8>,
    pub genesis_payload: Digest,
    pub storage_dir: PathBuf,
    /// Validator transaction ingress URLs; replication uses ChainSync peers.
    pub validators: Vec<String>,
    /// Additional untrusted sources discovered or configured by the host.
    pub peers: Vec<iroh::EndpointAddr>,
    /// None retains the complete archive; a positive value retains this many blocks.
    pub archive_blocks: Option<NonZeroU64>,
}

pub(crate) enum Indexing {
    Off,
    #[cfg(feature = "indexer-api")]
    On {
        trust: hellas_genesis::TrustDocument,
        genesis_json: Vec<u8>,
        partition: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid node configuration: {0}")]
    Config(String),
    #[error("invalid finalized block: {0}")]
    InvalidBlock(String),
    #[error("certified block execution failed: {0}")]
    Execution(String),
    #[error("chain storage failed: {0}")]
    Storage(String),
    #[error(transparent)]
    Query(#[from] QueryError),
}

impl Config {
    fn info(&self) -> Result<ConsensusInfo, Error> {
        if self.peers.len() + self.validators.len() > 64 {
            return Err(Error::Config(
                "at most 64 chain sources may be configured".into(),
            ));
        }
        self.genesis
            .validate()
            .map_err(|e| Error::Config(e.to_string()))?;
        let info = ConsensusInfo {
            network_id: self.genesis.network_id.clone(),
            validators: self
                .genesis
                .validators
                .iter()
                .map(|v| v.public_key.clone())
                .collect(),
            threshold_identity: self.threshold_identity.clone(),
        };
        ConsensusVerifier::new(&info).map_err(|e| Error::Config(e.to_string()))?;
        Ok(info)
    }
}

#[derive(Default)]
pub(crate) struct Readiness {
    seen: AtomicU64,
    pub(crate) applied: AtomicU64,
    observed: AtomicBool,
    halted: AtomicBool,
}
impl Readiness {
    pub(crate) fn running(&self) -> Result<(), QueryError> {
        if self.halted.load(Ordering::Acquire) {
            return Err(QueryError::StateUnavailable(
                "chain execution halted".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn check(&self) -> Result<(), QueryError> {
        self.running()?;
        if !self.observed.load(Ordering::Acquire)
            || self.applied.load(Ordering::Acquire) < self.seen.load(Ordering::Acquire)
        {
            return Err(QueryError::StateUnavailable(
                "chain node is catching up".into(),
            ));
        }
        Ok(())
    }
}

/// Constructed only after this node has executed every finalized height it has seen.
/// Each local read also checks live readiness; retaining a handle cannot bypass catch-up.
#[derive(Clone)]
pub struct ChainView(LocalLightClient);

/// Commonware's Context owns its Tokio runtime. Keep its final owner outside
/// an async task, including when an application drops its last query handle.
pub(crate) struct RuntimeGuard(pub Option<runtime::Context>);
impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        if let Some(context) = self.0.take() {
            std::thread::spawn(move || drop(context));
        }
    }
}

impl ChainView {
    pub fn client(&self) -> LocalLightClient {
        self.0.clone()
    }
}

/// Epoch authority is provisioned independently of replication peers.
#[derive(Clone)]
pub(super) enum Trust {
    Genesis(Arc<ConsensusVerifier>),
    #[cfg(feature = "indexer-api")]
    Schedule(
        crate::indexer::trusted_epochs::TrustedEpochs,
        Arc<crate::proof_verify::ProofVerifier>,
    ),
}
impl Trust {
    fn verify(&self, incoming: &FinalizedBlock) -> Result<HellasBlock, Error> {
        FinalizedBlockView::decode(incoming).map_err(invalid)?;
        let block = HellasBlock::decode(incoming.block.as_slice()).map_err(invalid)?;
        let proof = crate::finality_proof::FinalityProof::decode(&incoming.snapshot.finalization)
            .map_err(invalid)?;
        proof
            .verify_terminal_context(proof.descendants.last().unwrap_or(&block))
            .map_err(invalid)?;
        match self {
            Self::Genesis(verifier) => {
                if std::iter::once(&block)
                    .chain(&proof.descendants)
                    .any(|b| b.context().round.epoch().get() != 0)
                {
                    return Err(invalid("epoch is absent from the provisioned authority"));
                }
                verifier
                    .verify_snapshot(&incoming.snapshot)
                    .map_err(invalid)?;
            }
            #[cfg(feature = "indexer-api")]
            Self::Schedule(_, verifier) => {
                verifier
                    .verify(
                        verifier.bundle(incoming.clone()),
                        crate::proof_verify::ProofQuery::Block(FinalizedBlockQuery::Height(
                            incoming.snapshot.height,
                        )),
                    )
                    .map_err(invalid)?;
            }
        }
        Ok(block)
    }
}
impl commonware_cryptography::certificate::Provider for Trust {
    type Scope = commonware_consensus::types::Epoch;
    type Scheme = crate::domain::Scheme;
    fn scoped(
        &self,
        epoch: Self::Scope,
    ) -> Option<commonware_cryptography::certificate::Scoped<Self::Scheme>> {
        match self {
            Self::Genesis(v) => (epoch.get() == 0).then(|| {
                commonware_cryptography::certificate::Scoped::scheme(Arc::new(v.scheme().clone()))
            }),
            #[cfg(feature = "indexer-api")]
            Self::Schedule(schedule, _) => schedule.scoped(epoch),
        }
    }
}
impl commonware_consensus::types::Epocher for Trust {
    fn containing(
        &self,
        height: commonware_consensus::types::Height,
    ) -> Option<commonware_consensus::types::EpochInfo> {
        match self {
            Self::Genesis(_) => Some(commonware_consensus::types::EpochInfo::new(
                commonware_consensus::types::Epoch::zero(),
                height,
                self.first(commonware_consensus::types::Epoch::zero())?,
                self.last(commonware_consensus::types::Epoch::zero())?,
            )),
            #[cfg(feature = "indexer-api")]
            Self::Schedule(s, _) => s.containing(height),
        }
    }
    fn first(
        &self,
        epoch: commonware_consensus::types::Epoch,
    ) -> Option<commonware_consensus::types::Height> {
        match self {
            Self::Genesis(_) => (epoch.get() == 0).then(commonware_consensus::types::Height::zero),
            #[cfg(feature = "indexer-api")]
            Self::Schedule(s, _) => s.first(epoch),
        }
    }
    fn last(
        &self,
        epoch: commonware_consensus::types::Epoch,
    ) -> Option<commonware_consensus::types::Height> {
        match self {
            Self::Genesis(_) => {
                (epoch.get() == 0).then(|| commonware_consensus::types::Height::new(u64::MAX))
            }
            #[cfg(feature = "indexer-api")]
            Self::Schedule(s, _) => s.last(epoch),
        }
    }
}

#[derive(Default)]
struct Tasks(Vec<commonware_runtime::Handle<()>>);
impl Tasks {
    async fn stop(&mut self, context: &runtime::Context) {
        for task in &self.0 {
            task.abort();
        }
        for task in self.0.drain(..) {
            let _ = task.await;
        }
        let _ = context
            .child("shutdown")
            .stop(0, Some(std::time::Duration::from_secs(5)))
            .await;
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

pub(crate) struct Core {
    _lock: std::fs::File,
    indexer: ChainIndexer,
    client: LocalLightClient,
    #[cfg(any(test, feature = "indexer-api"))]
    database: UtxoDatabase<runtime::Context>,
    #[cfg(test)]
    trust: Trust,
    #[cfg(feature = "indexer-api")]
    publication: Option<crate::edge_index::Publication>,
    readiness: Arc<Readiness>,
    progress: watch::Sender<u64>,
    tasks: std::sync::Mutex<Tasks>,
}
fn storage(error: impl std::fmt::Display) -> Error {
    Error::Storage(error.to_string())
}
fn invalid(error: impl std::fmt::Display) -> Error {
    Error::InvalidBlock(error.to_string())
}

impl Core {
    async fn open(
        context: runtime::Context,
        config: &Config,
        indexing: Indexing,
        network: &replication::Network,
        stopped: &mut tokio::sync::oneshot::Receiver<()>,
    ) -> Result<Arc<Self>, Error> {
        use commonware_consensus::marshal::{resolver::handler, standard::Standard};
        use commonware_glue::stateful::SyncPlan;
        use commonware_resolver::opaque;
        use commonware_utils::NZUsize;
        let lock = crate::execution::pipeline::lock(&config.storage_dir).map_err(storage)?;
        let info = config.info()?;
        let chain_config = ArchiveConfig::default();
        let leader = config
            .genesis
            .validators
            .iter()
            .map(|v| {
                PublicKey::decode(hex::decode(&v.public_key).map_err(invalid)?.as_slice())
                    .map_err(invalid)
            })
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("empty genesis committee"))?;
        let mut application = crate::Application::new(
            context.child("app"),
            crate::domain::network_id(&config.genesis).map_err(invalid)?,
            leader,
            genesis_allocations(&config.genesis).map_err(invalid)?,
            "chain",
            crate::ApplicationConfig::default(),
        )
        .await;
        let genesis = application.genesis_block();
        if genesis.digest() != config.genesis_payload {
            return Err(Error::Config("genesis payload differs from its pin".into()));
        }
        crate::execution::pipeline::pin(
            &config.storage_dir,
            &config.genesis,
            &config.threshold_identity,
            config.genesis_payload,
        )
        .map_err(storage)?;
        let owner = application.owner_index();
        let mut plan = SyncPlan::<_, crate::domain::Scheme, Standard<HellasBlock>>::init(
            &context.child("startup"),
            "chain",
        )
        .await;
        // Historical indexes need every object transition. Ordinary full nodes
        // may bootstrap their authenticated live state at a certified floor.
        if matches!(indexing, Indexing::Off) && plan.should_state_sync(true) {
            network.discover_all().await;
            if let Some(head) = network.fetch(FinalizedBlockQuery::Latest).await {
                let proof =
                    crate::finality_proof::FinalityProof::decode(&head.snapshot.finalization)
                        .map_err(invalid)?;
                plan = plan.with_floor(proof.certificate);
            }
        }
        crate::execution::pipeline::verify_floor(&plan, &network.trust)?;
        let startup = plan.sync_height();
        let (actor, indexer, processed) = crate::indexer::init(
            context.child("archive"),
            "chain",
            &chain_config,
            plan.marshal_start(genesis.clone()),
            network.trust.clone(),
            network.trust.clone(),
        )
        .await;
        #[cfg(feature = "indexer-api")]
        let publication = match indexing {
            Indexing::Off => None,
            Indexing::On {
                trust,
                genesis_json: _,
                partition,
            } => {
                let Trust::Schedule(_, verifier) = &network.trust else {
                    return Err(invalid("index requires a trust schedule"));
                };
                let scope = crate::edge_index::query::cursor_scope(
                    &config.genesis.network_id,
                    &trust.genesis_sha256,
                    verifier.trust_sha256(),
                );
                let index = crate::edge_index::EdgeIndex::open(
                    &config.storage_dir.join(format!(
                        "{partition}-edge-index-v{}-{scope}.redb",
                        crate::edge_index::SCHEMA_VERSION
                    )),
                    config.genesis.network_id.clone(),
                    trust.genesis_sha256,
                    verifier.trust_sha256().into(),
                )
                .map_err(storage)?;
                let recovered = startup
                    .into_iter()
                    .chain(processed)
                    .map(|h| h.get())
                    .max()
                    .unwrap_or(0);
                crate::edge_index::Publication::check_start(&index, recovered).map_err(storage)?;
                if plan.floor().is_some() {
                    return Err(Error::Config(
                        "historical indexing requires replay from genesis".into(),
                    ));
                }
                Some(crate::edge_index::Publication {
                    index,
                    verifier: verifier.clone(),
                    archive: indexer.clone(),
                })
            }
        };
        let readiness = Arc::new(Readiness::default());
        let (progress, _) = watch::channel(0);
        application.publication = Some(crate::execution::pipeline::Publication {
            archive: indexer.clone(),
            retention: config.archive_blocks,
            readiness: readiness.clone(),
            progress: progress.clone(),
            #[cfg(feature = "indexer-api")]
            index: publication.clone(),
        });
        let (execution, mailbox) = crate::execution::pipeline::init(
            context.child("execution"),
            application,
            &chain_config,
            indexer.marshal.clone(),
            plan,
            network.clone(),
            config.archive_blocks,
        );
        let (receiver, handler) = handler::init(context.child("marshal_handler"), NZUsize!(256));
        let resolver = opaque::init::<_, _, _, PublicKey>(
            context.child("resolver"),
            network.clone(),
            handler,
            NZUsize!(256),
            std::time::Duration::from_millis(500),
        );
        let archive_task = actor.start_unbuffered(mailbox.clone(), (receiver, resolver));
        let execution_task = execution.start();
        let (feed_network, feed_indexer, feed_readiness) =
            (network.clone(), indexer.clone(), readiness.clone());
        let feed_task = context.child("live_feed").spawn(move |_| async move {
            feed_network.feed(feed_indexer, feed_readiness).await;
        });
        let mut tasks = Tasks(vec![archive_task, execution_task, feed_task]);
        let database = tokio::select! {
            database = mailbox.subscribe_databases() => database,
            _ = &mut *stopped => { tasks.stop(&context).await; return Err(Error::Query(QueryError::ChannelClosed)); }
        };
        let restored = crate::execution::pipeline::restore(
            &indexer,
            &database,
            &owner,
            startup.into_iter().chain(processed).max(),
        )
        .await;
        let restored = match restored {
            Ok(height) => height,
            Err(error) => {
                tasks.stop(&context).await;
                return Err(error.into());
            }
        };
        readiness.applied.fetch_max(restored, Ordering::AcqRel);
        progress.send_replace(restored);
        if let Some(retain) = config.archive_blocks {
            let height = readiness.applied.load(Ordering::Acquire);
            indexer.retain_from(
                height.saturating_sub(retain.get() - 1),
                height.saturating_sub(retain.get().max(2) - 1),
            );
        }
        let client = LocalLightClient::full_node(
            database.clone(),
            owner,
            indexer.clone(),
            info,
            config.validators.clone(),
            readiness.clone(),
        );
        Ok(Arc::new(Self {
            _lock: lock,
            indexer,
            client,
            #[cfg(any(test, feature = "indexer-api"))]
            database,
            #[cfg(test)]
            trust: network.trust.clone(),
            readiness,
            progress,
            #[cfg(feature = "indexer-api")]
            publication,
            tasks: std::sync::Mutex::new(tasks),
        }))
    }
    #[cfg(test)]
    fn applied(&self) -> u64 {
        self.readiness.applied.load(Ordering::Acquire)
    }
    #[cfg(test)]
    fn observe(&self, incoming: &FinalizedBlock) -> Result<HellasBlock, Error> {
        self.readiness.observe(&self.trust, incoming)
    }
}
impl Readiness {
    fn observe(&self, trust: &Trust, incoming: &FinalizedBlock) -> Result<HellasBlock, Error> {
        let block = trust.verify(incoming)?;
        let proof = crate::finality_proof::FinalityProof::decode(&incoming.snapshot.finalization)
            .map_err(invalid)?;
        self.seen.fetch_max(
            proof
                .certified_height(incoming.snapshot.height)
                .map_err(invalid)?,
            Ordering::AcqRel,
        );
        self.observed.store(true, Ordering::Release);
        Ok(block)
    }
}

#[cfg(test)]
mod tests;
