//! A verified, executing chain node. Paid consumers receive only caught-up views.
use crate::{
    ChainIndexer, ConsensusInfo, ConsensusVerifier, FinalizedBlock, FinalizedBlockQuery,
    FinalizedBlockView, HellasBlock, QueryError,
    config::{Config as ArchiveConfig, genesis_allocations},
    domain::{Digest, PublicKey},
    rpc::LocalLightClient,
};
#[cfg(feature = "indexer-api")]
use crate::{domain::SettlementKey, execution::store::UtxoDatabase};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::CertifiableBlock as _;
use commonware_cryptography::Digestible as _;
use commonware_runtime::{Spawner as _, Supervisor as _, tokio as runtime};
use std::{num::NonZeroU64, path::PathBuf, sync::Arc};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

mod input;
pub(crate) mod replication;
#[cfg(feature = "indexer-api")]
mod startup;
pub(crate) mod transport;
pub use transport::FullNode;

/// One bounded ChainSync recovery cycle: idle subscription, maximum retry,
/// connection and subscription establishment.
pub const RECOVERY_TIMEOUT: std::time::Duration = replication::STREAM_IDLE_TIMEOUT
    .saturating_add(std::time::Duration::from_millis(
        replication::MAX_RETRY_DELAY_MS,
    ))
    .saturating_add(replication::TIMEOUT.saturating_mul(2));
#[cfg(feature = "validator")]
pub(crate) use transport::serve_validator_archive;

/// Independently provisioned execution inputs. Peers supply blocks, never these pins.
#[derive(Clone, Debug)]
pub struct Config {
    chain: crate::chain_dir::ChainDir,
    indexed: bool,
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
        partition: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid node configuration: {0}")]
    Config(String),
    #[error("invalid finalized block: {0}")]
    InvalidBlock(String),
    #[error("chain storage failed: {0}")]
    Storage(String),
    #[error(transparent)]
    Query(#[from] QueryError),
}

impl Config {
    pub fn genesis(&self) -> &hellas_genesis::Genesis {
        self.chain.profile().genesis()
    }

    pub fn threshold_identity(&self) -> Vec<u8> {
        hex::decode(&self.chain.profile().trust().epochs[0].threshold_identity)
            .expect("validated trust identity")
    }

    pub fn chain(&self) -> &crate::chain_dir::ChainDir {
        &self.chain
    }

    pub fn for_profile(
        chain: crate::chain_dir::ChainDir,
        peers: Vec<iroh::EndpointAddr>,
        archive_blocks: Option<NonZeroU64>,
    ) -> Result<Self, Error> {
        chain
            .profile()
            .static_threshold_identity()
            .map_err(|error| Error::Config(error.to_string()))?;
        Ok(Self::from_profile(chain, peers, archive_blocks, false))
    }

    #[cfg(feature = "indexer-api")]
    pub(crate) fn for_indexed_profile(
        chain: crate::chain_dir::ChainDir,
        peers: Vec<iroh::EndpointAddr>,
        archive_blocks: Option<NonZeroU64>,
    ) -> Result<Self, Error> {
        Ok(Self::from_profile(chain, peers, archive_blocks, true))
    }

    fn from_profile(
        chain: crate::chain_dir::ChainDir,
        peers: Vec<iroh::EndpointAddr>,
        archive_blocks: Option<NonZeroU64>,
        indexed: bool,
    ) -> Self {
        let validators = chain.profile().validators().to_vec();
        Self {
            chain,
            indexed,
            validators,
            peers,
            archive_blocks,
        }
    }

    pub fn storage_dir(&self) -> PathBuf {
        if self.indexed {
            self.chain.indexer().into_path_buf()
        } else {
            self.chain.node().into_path_buf()
        }
    }

    fn info(&self) -> Result<ConsensusInfo, Error> {
        if self.peers.len() + self.validators.len() > 64 {
            return Err(Error::Config(
                "at most 64 chain sources may be configured".into(),
            ));
        }
        let genesis = self.genesis();
        let info = ConsensusInfo {
            network_id: genesis.network_id.clone(),
            validators: genesis
                .validators
                .iter()
                .map(|v| v.public_key.clone())
                .collect(),
            threshold_identity: self.threshold_identity(),
        };
        ConsensusVerifier::new(&info, crate::genesis_digest(genesis))
            .map_err(|e| Error::Config(e.to_string()))?;
        Ok(info)
    }
}

/// Execution readiness relative to verified observations, never untrusted peer claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeState {
    CatchingUp {
        observed: Option<u64>,
        executed: u64,
    },
    Ready {
        height: u64,
    },
    Halted {
        reason: &'static str,
        executed: u64,
    },
}

impl NodeState {
    pub fn executed_height(self) -> u64 {
        match self {
            Self::CatchingUp { executed, .. } | Self::Halted { executed, .. } => executed,
            Self::Ready { height } => height,
        }
    }
    fn running(self) -> Result<(), QueryError> {
        match self {
            Self::Halted { reason, .. } => Err(QueryError::StateUnavailable(reason.into())),
            _ => Ok(()),
        }
    }
    fn check(self) -> Result<(), QueryError> {
        self.running()?;
        match self {
            Self::Ready { .. } => Ok(()),
            _ => Err(QueryError::StateUnavailable(
                "chain node is catching up".into(),
            )),
        }
    }
}

pub(crate) struct Readiness {
    pub(crate) state: watch::Sender<NodeState>,
    cancel: CancellationToken,
}
impl Default for Readiness {
    fn default() -> Self {
        Self::new(CancellationToken::new())
    }
}
impl Readiness {
    fn new(cancel: CancellationToken) -> Self {
        Self {
            state: watch::channel(NodeState::CatchingUp {
                observed: None,
                executed: 0,
            })
            .0,
            cancel,
        }
    }
    fn status(&self) -> NodeState {
        *self.state.borrow()
    }
    pub(crate) fn running(&self) -> Result<(), QueryError> {
        self.status().running()
    }
    pub(crate) fn check(&self) -> Result<(), QueryError> {
        self.status().check()
    }
    pub(crate) fn advance(&self, observation: Option<u64>, executed: u64) {
        self.state.send_if_modified(|state| {
            let previous = *state;
            let executed = executed.max(state.executed_height());
            let observed = match *state {
                NodeState::CatchingUp { observed, .. } => observed,
                NodeState::Ready { height } => Some(height),
                NodeState::Halted { reason, .. } => {
                    *state = NodeState::Halted { reason, executed };
                    return *state != previous;
                }
            }
            .max(observation);
            *state = if observed.is_some_and(|height| executed >= height) {
                NodeState::Ready { height: executed }
            } else {
                NodeState::CatchingUp { observed, executed }
            };
            *state != previous
        });
    }
    fn halt(&self, reason: &'static str) {
        self.state.send_if_modified(|state| {
            if matches!(state, NodeState::Halted { .. }) {
                return false;
            }
            *state = NodeState::Halted {
                reason,
                executed: state.executed_height(),
            };
            true
        });
        self.cancel.cancel();
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
                    .verify_snapshot(&incoming.snapshot, &incoming.block)
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
    genesis_payload: Digest,
    indexer: ChainIndexer,
    client: LocalLightClient,
    #[cfg(feature = "indexer-api")]
    database: UtxoDatabase<runtime::Context>,
    input: input::FinalizedInput,
    #[cfg(feature = "indexer-api")]
    publication: Option<crate::edge_index::Publication>,
    readiness: Arc<Readiness>,
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
        stopped: &CancellationToken,
    ) -> Result<Arc<Self>, Error> {
        use commonware_consensus::marshal::{resolver::handler, standard::Standard};
        use commonware_glue::stateful::SyncPlan;
        use commonware_resolver::opaque;
        use commonware_utils::NZUsize;
        let storage_dir = config.storage_dir();
        let lock = crate::execution::pipeline::lock(&storage_dir).map_err(storage)?;
        let info = config.info()?;
        let chain_config = ArchiveConfig::default();
        let leader = config
            .genesis()
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
            crate::domain::network_id(config.genesis()).map_err(invalid)?,
            crate::genesis_digest(config.genesis()),
            leader,
            genesis_allocations(config.genesis()).map_err(invalid)?,
            "chain",
            crate::ApplicationConfig::default(),
        )
        .await;
        let genesis = application.genesis_block();
        if config
            .chain
            .profile()
            .known_genesis_payload_pin()
            .is_some_and(|pin| genesis.digest().0 != pin)
        {
            return Err(Error::Config("genesis payload differs from its pin".into()));
        }
        let owner = application.owner_index();
        let mut plan = SyncPlan::<_, crate::domain::Scheme, Standard<HellasBlock>>::init(
            &context.child("startup"),
            "chain",
        )
        .await;
        // Historical indexes need every object transition. Ordinary full nodes
        // may bootstrap their authenticated live state at a certified floor.
        if matches!(indexing, Indexing::Off)
            && plan.should_state_sync(true)
            && let Some(head) = network.fetch(FinalizedBlockQuery::Latest).await
        {
            let proof = crate::finality_proof::FinalityProof::decode(&head.snapshot.finalization)
                .map_err(invalid)?;
            plan = plan.with_floor(proof.certificate);
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
            Indexing::On { partition } => {
                let Trust::Schedule(_, verifier) = &network.trust else {
                    return Err(invalid("index requires a trust schedule"));
                };
                let scope = crate::edge_index::query::cursor_scope(
                    &config.genesis().network_id,
                    &config.chain.profile().trust().genesis_sha256,
                    verifier.trust_sha256(),
                );
                let index = crate::edge_index::EdgeIndex::open(
                    &storage_dir.join(format!(
                        "{partition}-edge-index-v{}-{scope}.redb",
                        crate::edge_index::SCHEMA_VERSION
                    )),
                    config.genesis().network_id.clone(),
                    config.chain.profile().trust().genesis_sha256.clone(),
                    verifier.trust_sha256().into(),
                )
                .map_err(storage)?;
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
        let readiness = Arc::new(Readiness::new(stopped.clone()));
        application.publication = Some(crate::execution::pipeline::Publication {
            archive: indexer.clone(),
            retention: config.archive_blocks,
            readiness: readiness.clone(),
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
        #[cfg(feature = "indexer-api")]
        let recovery_target = publication
            .as_ref()
            .map(|index| {
                index.recovery_height().map(|height| {
                    height.max(
                        startup
                            .into_iter()
                            .chain(processed)
                            .map(|h| h.get())
                            .max()
                            .unwrap_or(0),
                    )
                })
            })
            .transpose()
            .map_err(storage)?;
        #[cfg(feature = "indexer-api")]
        let delivery =
            recovery_target.map(|height| startup::Delivery::new(mailbox.clone(), height));
        #[cfg(feature = "indexer-api")]
        let archive_task = match &delivery {
            Some(delivery) => actor.start_unbuffered(delivery.clone(), (receiver, resolver)),
            None => actor.start_unbuffered(mailbox.clone(), (receiver, resolver)),
        };
        #[cfg(not(feature = "indexer-api"))]
        let archive_task = actor.start_unbuffered(mailbox.clone(), (receiver, resolver));
        let execution_task = execution.start();
        let input =
            input::FinalizedInput::new(indexer.clone(), readiness.clone(), network.trust.clone());
        let mut tasks = Tasks(vec![archive_task, execution_task]);
        // Fast state sync follows live targets during startup. Historical indexing
        // replays from genesis and must reconcile publication before new input.
        let defer_feed = {
            #[cfg(feature = "indexer-api")]
            {
                publication.is_some()
            }
            #[cfg(not(feature = "indexer-api"))]
            {
                false
            }
        };
        if !defer_feed {
            let (network, input) = (network.clone(), input.clone());
            tasks
                .0
                .push(context.child("live_feed").spawn(move |_| async move {
                    network.feed(input).await;
                }));
        }
        let database = tokio::select! {
            database = mailbox.subscribe_databases() => database,
            _ = stopped.cancelled() => { tasks.stop(&context).await; return Err(Error::Query(QueryError::ChannelClosed)); }
        };
        let restore = || {
            crate::execution::pipeline::restore(
                &indexer,
                &database,
                &owner,
                startup.into_iter().chain(processed).max(),
                &genesis,
            )
        };
        #[cfg(feature = "indexer-api")]
        if let Some(target) = recovery_target {
            let recovery = async {
                let mut changes = readiness.state.subscribe();
                let initial = restore().await?;
                if initial < target {
                    if indexer
                        .marshal
                        .get_block(commonware_consensus::types::Height::new(target))
                        .await
                        .is_none()
                    {
                        return Err(QueryError::StateUnavailable(
                            "published checkpoint is absent from the archive".into(),
                        ));
                    }
                    changes
                        .wait_for(|state| state.executed_height() >= target)
                        .await
                        .map_err(|_| QueryError::ChannelClosed)?;
                }
                Ok::<_, QueryError>(())
            };
            let result = tokio::select! {
                result = tokio::time::timeout(RECOVERY_TIMEOUT, recovery) => result.map_err(storage).and_then(|result| result.map_err(Error::from)),
                _ = stopped.cancelled() => Err(Error::Query(QueryError::ChannelClosed)),
            };
            if let Err(error) = result {
                tasks.stop(&context).await;
                return Err(error);
            }
        }
        let restored = restore().await;
        let restored = match restored {
            Ok(height) => height,
            Err(error) => {
                tasks.stop(&context).await;
                return Err(error.into());
            }
        };
        #[cfg(feature = "indexer-api")]
        if let Some(publication) = &publication {
            let checkpoint = if restored == 0 {
                genesis.clone()
            } else {
                match indexer
                    .marshal
                    .get_block(commonware_consensus::types::Height::new(restored))
                    .await
                {
                    Some(block) => block,
                    None => {
                        tasks.stop(&context).await;
                        return Err(storage("recovered index checkpoint is absent from archive"));
                    }
                }
            };
            if let Err(error) = publication.recover(&database, &checkpoint).await {
                tasks.stop(&context).await;
                return Err(storage(error));
            }
        }
        #[cfg(feature = "indexer-api")]
        if let Some(delivery) = &delivery
            && let Err(error) = delivery.resume()
        {
            tasks.stop(&context).await;
            return Err(error);
        }
        if defer_feed {
            let (network, input) = (network.clone(), input.clone());
            tasks
                .0
                .push(context.child("live_feed").spawn(move |_| async move {
                    network.feed(input).await;
                }));
        }
        readiness.advance(None, restored);
        if let Some(retain) = config.archive_blocks {
            let height = readiness.status().executed_height();
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
            Arc::new(
                crate::proof_verify::ProofVerifier::with_genesis(
                    config.chain.profile().trust().clone(),
                    config.chain.profile().genesis_json().as_bytes(),
                )
                .map_err(|error| Error::Config(error.to_string()))?,
            ),
            readiness.clone(),
        );
        Ok(Arc::new(Self {
            _lock: lock,
            genesis_payload: genesis.digest(),
            indexer,
            client,
            #[cfg(feature = "indexer-api")]
            database,
            input,
            readiness,
            #[cfg(feature = "indexer-api")]
            publication,
            tasks: std::sync::Mutex::new(tasks),
        }))
    }
}
impl Readiness {
    fn observe(&self, trust: &Trust, incoming: &FinalizedBlock) -> Result<HellasBlock, Error> {
        let block = trust.verify(incoming)?;
        let proof = crate::finality_proof::FinalityProof::decode(&incoming.snapshot.finalization)
            .map_err(invalid)?;
        let height = proof
            .certified_height(incoming.snapshot.height)
            .map_err(invalid)?;
        self.advance(Some(height), 0);
        Ok(block)
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests;
