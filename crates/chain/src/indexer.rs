#[cfg(feature = "explorer-origin")]
mod trusted_epochs;
use crate::domain::{PublicKey, Scheme};
use crate::{
    app::{HellasBlock, MarshalMailbox},
    config::Config,
    consensus::{ConsensusVerificationError, ConsensusVerifier, Finalization},
    light_client::{FinalizedBlock, FinalizedBlockQuery, LatestBlock, QueryError},
};
use commonware_actor::Feedback;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    CertifiableBlock, Heightable, Reporter,
    marshal::{
        self, Identifier as MarshalIdentifier, Start, Update,
        core::Actor as MarshalActor,
        resolver::handler::{self, Annotation, Key as ResolverKey},
        standard::Standard,
    },
    simplex::types::Activity,
    types::{FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::{
    Digestible, certificate::ConstantProvider, certificate::Verifier as _, sha256::Digest,
};
use commonware_resolver::{Fetch, Resolver, TargetedResolver};
use commonware_runtime::{BufferPooler, Clock, Handle, Metrics, Spawner, Storage, tokio};
use commonware_storage::archive::immutable;
use commonware_utils::{Acknowledgement, NZU64, sync::AsyncMutex, vec::NonEmptyVec};
use rand_core::CryptoRng;
use std::{marker::PhantomData, num::NonZeroU64, num::NonZeroUsize, sync::Arc};
use thiserror::Error;
#[cfg(feature = "explorer-origin")]
use trusted_epochs::TrustedEpochs;

pub type FinalizationStore<E = tokio::Context> = immutable::Archive<E, Digest, Finalization>;
pub type BlockStore<E = tokio::Context> = immutable::Archive<E, Digest, HellasBlock>;

pub async fn init_finalization_store<E>(
    context: E,
    partition_prefix: &str,
    config: &Config,
) -> FinalizationStore<E>
where
    E: BufferPooler + Clock + Metrics + Storage,
{
    let page_cache = config.page_cache(&context);
    immutable::Archive::init(
        context,
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
            freezer_table_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-table"
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-key"
            ),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-value"
            ),
            freezer_value_target_size: 65536,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
            items_per_section: NZU64!(256),
            codec_config: Scheme::certificate_codec_config_unbounded(),
            replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
            freezer_key_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            freezer_value_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            ordinal_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
        },
    )
    .await
    .expect("failed to initialize finalizations archive")
}

pub async fn init_block_store<E>(
    context: E,
    partition_prefix: &str,
    config: &Config,
) -> BlockStore<E>
where
    E: BufferPooler + Clock + Metrics + Storage,
{
    let page_cache = config.page_cache(&context);
    immutable::Archive::init(
        context,
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalized-blocks-metadata"),
            freezer_table_partition: format!("{partition_prefix}-finalized-blocks-freezer-table"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!("{partition_prefix}-finalized-blocks-freezer-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{partition_prefix}-finalized-blocks-freezer-value"),
            freezer_value_target_size: 65536,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition_prefix}-finalized-blocks-ordinal"),
            items_per_section: NZU64!(256),
            codec_config: (),
            replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
            freezer_key_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            freezer_value_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            ordinal_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
        },
    )
    .await
    .expect("failed to initialize finalized blocks archive")
}

#[derive(Clone)]
pub struct ChainIndexer {
    marshal: MarshalMailbox,
    verifier: Option<ConsensusVerifier>,
    #[cfg(feature = "explorer-origin")]
    schedule: Option<TrustedEpochs>,
    ingest_lock: Arc<AsyncMutex<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Applied,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IngestError {
    #[error("consensus verifier is not configured")]
    MissingVerifier,
    #[error("invalid trust schedule or finalized epoch: {0}")]
    TrustSchedule(String),
    #[error("{0}")]
    Consensus(#[from] ConsensusVerificationError),
    #[error("invalid block")]
    InvalidBlock,
    #[error("block context round did not match finalization round")]
    RoundMismatch,
    #[error("finalized height {height} already has a different payload")]
    ConflictingHeight {
        height: u64,
        existing: Digest,
        incoming: Digest,
    },
    #[error("finalized payload is already indexed at a different height")]
    ConflictingPayload {
        payload: Digest,
        existing_height: u64,
        incoming_height: u64,
    },
    #[error("marshal actor closed while persisting block")]
    MarshalClosed,
    #[error("marshal did not store the finalized block")]
    NotStored { height: u64 },
}

impl ChainIndexer {
    pub fn new(marshal: MarshalMailbox) -> Self {
        Self {
            marshal,
            verifier: None,
            #[cfg(feature = "explorer-origin")]
            schedule: None,
            ingest_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn with_consensus_info(
        mut self,
        info: &crate::ConsensusInfo,
    ) -> Result<Self, ConsensusVerificationError> {
        self.verifier = Some(ConsensusVerifier::new(info)?);
        Ok(self)
    }

    pub fn with_verifier(mut self, verifier: ConsensusVerifier) -> Self {
        self.verifier = Some(verifier);
        self
    }

    pub fn decode_block(bytes: &[u8]) -> Result<HellasBlock, IngestError> {
        HellasBlock::decode(bytes).map_err(|_| IngestError::InvalidBlock)
    }

    pub fn decode_finalization(bytes: &[u8]) -> Result<Finalization, IngestError> {
        ConsensusVerifier::decode_finalization(bytes).map_err(IngestError::from)
    }

    pub async fn ingest_finalized(
        &self,
        block: HellasBlock,
        finalization: Finalization,
    ) -> Result<IngestOutcome, IngestError> {
        let _guard = self.ingest_lock.lock().await;
        let height = block.height();
        #[cfg(feature = "explorer-origin")]
        let scheduled = self
            .schedule
            .as_ref()
            .map(|schedule| schedule.verifier(height, finalization.proposal.round.epoch()))
            .transpose()?;
        #[cfg(feature = "explorer-origin")]
        let verifier = scheduled
            .or(self.verifier.as_ref())
            .ok_or(IngestError::MissingVerifier)?;
        #[cfg(not(feature = "explorer-origin"))]
        let verifier = self.verifier.as_ref().ok_or(IngestError::MissingVerifier)?;
        let payload = block.digest();

        verifier.verify_finalization(&finalization, payload)?;
        if block.context().round != finalization.round() {
            return Err(IngestError::RoundMismatch);
        }

        if let Some((_, existing_payload)) = self.marshal.get_info(height).await {
            if existing_payload == payload {
                return Ok(IngestOutcome::Duplicate);
            }
            return Err(IngestError::ConflictingHeight {
                height: height.get(),
                existing: existing_payload,
                incoming: payload,
            });
        }
        if let Some((existing_height, _)) = self.marshal.get_info(&payload).await {
            if existing_height == height {
                return Ok(IngestOutcome::Duplicate);
            }
            return Err(IngestError::ConflictingPayload {
                payload,
                existing_height: existing_height.get(),
                incoming_height: height.get(),
            });
        }

        if !self.marshal.verified(finalization.round(), block).await {
            return Err(IngestError::MarshalClosed);
        }

        let mut marshal = self.marshal.clone();
        if !marshal
            .report(Activity::Finalization(finalization))
            .accepted()
        {
            return Err(IngestError::MarshalClosed);
        }

        match self.marshal.get_info(height).await {
            Some((_, stored_payload)) if stored_payload == payload => Ok(IngestOutcome::Applied),
            Some((_, existing)) => Err(IngestError::ConflictingHeight {
                height: height.get(),
                existing,
                incoming: payload,
            }),
            None => Err(IngestError::NotStored {
                height: height.get(),
            }),
        }
    }

    pub async fn get_finalization(&self, payload: Digest) -> Result<Option<Vec<u8>>, QueryError> {
        let Some((height, stored_payload)) = self.marshal.get_info(&payload).await else {
            return Ok(None);
        };
        if stored_payload != payload {
            return Err(QueryError::StateUnavailable(
                "finalization index returned a mismatched payload".to_string(),
            ));
        }
        Ok(self
            .marshal
            .get_finalization(height)
            .await
            .map(|finalization| finalization.encode().to_vec()))
    }

    pub async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        Ok(self
            .get_finalized_block(FinalizedBlockQuery::Latest)
            .await?
            .map(|block| block.snapshot))
    }

    pub async fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        let info = match query {
            FinalizedBlockQuery::Latest => self.marshal.get_info(MarshalIdentifier::Latest).await,
            FinalizedBlockQuery::Height(height) => self.marshal.get_info(Height::new(height)).await,
            FinalizedBlockQuery::Payload(payload) => self.marshal.get_info(&payload).await,
        };
        let Some((height, payload)) = info else {
            return Ok(None);
        };
        if let FinalizedBlockQuery::Payload(expected) = query
            && payload != expected
        {
            return Err(QueryError::StateUnavailable(
                "finalized block index returned a mismatched payload".to_string(),
            ));
        }
        self.get_finalized_block_at(height, payload).await
    }

    async fn get_finalized_block_at(
        &self,
        height: Height,
        payload: Digest,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        let Some(block) = self.marshal.get_block(height).await else {
            return Err(QueryError::StateUnavailable(format!(
                "finalized block is missing at height {}",
                height.get()
            )));
        };
        if block.digest() != payload {
            return Err(QueryError::StateUnavailable(
                "finalized block digest did not match index".to_string(),
            ));
        }
        let Some(finalization) = self.marshal.get_finalization(height).await else {
            return Err(QueryError::StateUnavailable(format!(
                "finalization is missing at height {}",
                height.get()
            )));
        };
        if finalization.proposal.payload != payload {
            return Err(QueryError::StateUnavailable(
                "finalization payload did not match block".to_string(),
            ));
        }
        Ok(Some(finalized_block(block, finalization.encode().to_vec())))
    }
}

pub async fn spawn_follower_indexer<E>(
    context: E,
    partition_prefix: &str,
    config: Config,
    verifier: ConsensusVerifier,
    genesis_block: HellasBlock,
) -> Result<(ChainIndexer, Handle<()>), IngestError>
where
    E: BufferPooler + Clock + Metrics + Spawner + Storage + CryptoRng,
{
    let provider = ConstantProvider::new(verifier.scheme().clone());
    let epocher = FixedEpocher::new(NonZeroU64::new(u64::MAX).unwrap());
    spawn_follower_with_provider(
        context,
        partition_prefix,
        config,
        verifier,
        genesis_block,
        provider,
        epocher,
    )
    .await
}

#[cfg(feature = "explorer-origin")]
pub async fn spawn_trusted_follower_indexer<E>(
    context: E,
    partition_prefix: &str,
    config: Config,
    trust: hellas_genesis::TrustDocument,
    genesis_block: HellasBlock,
) -> Result<(ChainIndexer, Handle<()>), IngestError>
where
    E: BufferPooler + Clock + Metrics + Spawner + Storage + CryptoRng,
{
    let schedule = TrustedEpochs::new(trust)?;
    let verifier = schedule
        .verifier(Height::zero(), commonware_consensus::types::Epoch::zero())?
        .clone();
    let (mut indexer, handle) = spawn_follower_with_provider(
        context,
        partition_prefix,
        config,
        verifier,
        genesis_block,
        schedule.clone(),
        schedule.clone(),
    )
    .await?;
    indexer.schedule = Some(schedule);
    Ok((indexer, handle))
}

async fn spawn_follower_with_provider<E, P, H>(
    context: E,
    partition_prefix: &str,
    config: Config,
    verifier: ConsensusVerifier,
    genesis_block: HellasBlock,
    provider: P,
    epocher: H,
) -> Result<(ChainIndexer, Handle<()>), IngestError>
where
    E: BufferPooler + Clock + Metrics + Spawner + Storage + CryptoRng,
    P: commonware_cryptography::certificate::Provider<
            Scope = commonware_consensus::types::Epoch,
            Scheme = Scheme,
        >,
    H: commonware_consensus::types::Epocher,
{
    let finalizations_by_height = init_finalization_store(
        context.child("finalizations_by_height"),
        partition_prefix,
        &config,
    )
    .await;
    let finalized_blocks =
        init_block_store(context.child("finalized_blocks"), partition_prefix, &config).await;
    let mailbox_size = NonZeroUsize::new(config.mailbox_size).unwrap_or(NonZeroUsize::MIN);
    let marshal_config = marshal::Config {
        provider,
        epocher,
        start: Start::Genesis(genesis_block),
        partition_prefix: partition_prefix.to_string(),
        mailbox_size,
        view_retention_timeout: ViewDelta::new(config.activity_timeout),
        prunable_items_per_section: NZU64!(256),
        page_cache: config.page_cache(&context),
        replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
        key_write_buffer: NonZeroUsize::new(config.write_buffer).unwrap_or(NonZeroUsize::MIN),
        value_write_buffer: NonZeroUsize::new(config.write_buffer).unwrap_or(NonZeroUsize::MIN),
        block_codec_config: (),
        max_repair: NonZeroUsize::new(config.max_repair).unwrap_or(NonZeroUsize::MIN),
        max_pending_acks: NonZeroUsize::MIN,
        strategy: commonware_parallel::Sequential,
    };
    let (actor, marshal, _) = MarshalActor::<_, Standard<HellasBlock>, _, _, _, _, _>::init(
        context.child("marshal"),
        finalizations_by_height,
        finalized_blocks,
        marshal_config,
    )
    .await;
    let (resolver_rx, handler) = handler::init(context.child("marshal_resolver"), mailbox_size);
    let resolver = NoopResolver::<PublicKey, Digest>::new(handler);
    let handle = actor.start_unbuffered(AutoAckApplication, (resolver_rx, resolver));
    Ok((ChainIndexer::new(marshal).with_verifier(verifier), handle))
}

fn finalized_block(block: HellasBlock, finalization: Vec<u8>) -> FinalizedBlock {
    FinalizedBlock {
        snapshot: LatestBlock {
            height: block.height().get(),
            payload: block.digest(),
            state_root: block.state_root(),
            finalization,
        },
        block: block.encode().to_vec(),
    }
}

#[derive(Clone, Copy)]
struct AutoAckApplication;

impl Reporter for AutoAckApplication {
    type Activity = Update<HellasBlock>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if let Update::Block(_, ack) = update {
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

#[derive(Clone)]
struct NoopResolver<P, D>
where
    D: commonware_cryptography::Digest,
{
    _handler: handler::Handler<D>,
    _public_key: PhantomData<fn() -> P>,
}

impl<P, D> NoopResolver<P, D>
where
    D: commonware_cryptography::Digest,
{
    const fn new(handler: handler::Handler<D>) -> Self {
        Self {
            _handler: handler,
            _public_key: PhantomData,
        }
    }
}

impl<P, D> Resolver for NoopResolver<P, D>
where
    P: commonware_cryptography::PublicKey,
    D: commonware_cryptography::Digest,
{
    type Key = ResolverKey<D>;
    type Subscriber = Annotation;

    fn fetch<F>(&mut self, _key: F) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        Feedback::Ok
    }

    fn fetch_all<F>(&mut self, _keys: Vec<F>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        Feedback::Ok
    }

    fn retain(
        &mut self,
        _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        Feedback::Ok
    }
}

impl<P, D> TargetedResolver for NoopResolver<P, D>
where
    P: commonware_cryptography::PublicKey,
    D: commonware_cryptography::Digest,
{
    type PublicKey = P;

    fn fetch_targeted(
        &mut self,
        _fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        _targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        Feedback::Ok
    }

    fn fetch_all_targeted<F>(&mut self, _keys: Vec<(F, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        Feedback::Ok
    }
}

#[cfg(test)]
mod tests;
