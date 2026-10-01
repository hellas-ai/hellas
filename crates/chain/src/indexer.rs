mod retention;
#[cfg(feature = "indexer-api")]
pub(crate) mod trusted_epochs;
#[cfg(any(test, feature = "indexer-api"))]
use crate::ConsensusVerifier;
#[cfg(test)]
use crate::domain::PublicKey;
use crate::domain::Scheme;
use crate::{
    app::{HellasBlock, MarshalMailbox},
    config::Config,
    consensus::{ConsensusVerificationError, Finalization},
    light_client::{FinalizedBlock, FinalizedBlockQuery, LatestBlock, QueryError},
};
#[cfg(test)]
use commonware_actor::Feedback;
#[cfg(test)]
use commonware_codec::DecodeExt;
use commonware_codec::Encode;
use commonware_consensus::{
    Block as _, CertifiableBlock, Heightable,
    marshal::{
        self, Identifier as MarshalIdentifier, Start, core::Actor as MarshalActor,
        standard::Standard,
    },
    types::{Height, ViewDelta},
};
use commonware_cryptography::{Digestible, sha256::Digest};
use commonware_runtime::{BufferPooler, Clock, Handle, Metrics, Spawner, Storage};
use commonware_utils::NZU64;
#[cfg(test)]
use commonware_utils::sync::AsyncMutex;
use rand_core::CryptoRng;
use std::{num::NonZeroUsize, sync::Arc};
use thiserror::Error;
#[cfg(all(test, feature = "indexer-api"))]
use trusted_epochs::TrustedEpochs;

pub(crate) type Archive<E, V> = retention::Retained<
    commonware_storage::archive::prunable::Archive<
        commonware_storage::translator::EightCap,
        E,
        Digest,
        V,
    >,
>;
pub(crate) type ArchiveActor<E, P, H> = MarshalActor<
    E,
    Standard<HellasBlock>,
    P,
    Archive<E, Finalization>,
    Archive<E, HellasBlock>,
    H,
    commonware_parallel::Sequential,
>;

/// All roles open exactly these stores with the same codec and partition names.
pub(crate) async fn init<E, P, H>(
    context: E,
    partition_prefix: &str,
    config: &Config,
    start: Start<Scheme, Digest, HellasBlock>,
    provider: P,
    epocher: H,
) -> (ArchiveActor<E, P, H>, ChainIndexer, Option<Height>)
where
    E: BufferPooler + Clock + Metrics + Spawner + Storage + CryptoRng,
    P: commonware_cryptography::certificate::Provider<
            Scope = commonware_consensus::types::Epoch,
            Scheme = Scheme,
        >,
    H: commonware_consensus::types::Epocher,
{
    let floor = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let certificates = retention::open::<_, Finalization>(
        context.child("finalizations_by_height"),
        format!("{partition_prefix}-certificates"),
        config,
        (),
        floor.clone(),
    )
    .await;
    let blocks = retention::open::<_, HellasBlock>(
        context.child("finalized_blocks"),
        format!("{partition_prefix}-blocks"),
        config,
        (),
        floor.clone(),
    )
    .await;
    let (actor, marshal, processed) = MarshalActor::init(
        context.child("marshal"),
        certificates,
        blocks,
        marshal::Config {
            provider,
            epocher,
            start,
            partition_prefix: partition_prefix.to_owned(),
            mailbox_size: NonZeroUsize::new(config.mailbox_size).unwrap_or(NonZeroUsize::MIN),
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
        },
    )
    .await;
    let mut indexer = ChainIndexer::new(marshal);
    indexer.storage_floor = floor;
    (actor, indexer, processed)
}

#[derive(Clone)]
pub struct ChainIndexer {
    pub(crate) marshal: MarshalMailbox,
    #[cfg(test)]
    verifier: Option<ConsensusVerifier>,
    #[cfg(all(test, feature = "indexer-api"))]
    schedule: Option<TrustedEpochs>,
    #[cfg(test)]
    ingest_lock: Arc<AsyncMutex<()>>,
    #[cfg(test)]
    fixture_source: FixtureSource,
    retained_from: Arc<std::sync::atomic::AtomicU64>,
    storage_floor: Arc<std::sync::atomic::AtomicU64>,
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
    #[cfg(all(test, feature = "full-node"))]
    pub(crate) fn prune_before(&self, height: u64) {
        self.retain_from(height, height);
    }

    #[cfg(feature = "full-node")]
    pub(crate) fn retain_from(&self, public_floor: u64, recovery_floor: u64) {
        self.retained_from
            .fetch_max(public_floor, std::sync::atomic::Ordering::AcqRel);
        self.storage_floor
            .fetch_max(recovery_floor, std::sync::atomic::Ordering::AcqRel);
        self.marshal.prune(Height::new(recovery_floor));
    }

    pub fn new(marshal: MarshalMailbox) -> Self {
        Self {
            marshal,
            #[cfg(test)]
            verifier: None,
            #[cfg(all(test, feature = "indexer-api"))]
            schedule: None,
            #[cfg(test)]
            ingest_lock: Arc::new(AsyncMutex::new(())),
            #[cfg(test)]
            fixture_source: FixtureSource::default(),
            retained_from: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            storage_floor: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    #[cfg(test)]
    pub fn with_verifier(mut self, verifier: ConsensusVerifier) -> Self {
        self.verifier = Some(verifier);
        self
    }

    #[cfg(test)]
    pub fn decode_block(bytes: &[u8]) -> Result<HellasBlock, IngestError> {
        HellasBlock::decode(bytes).map_err(|_| IngestError::InvalidBlock)
    }

    #[cfg(test)]
    pub async fn ingest_finalized(
        &self,
        block: HellasBlock,
        finalization: Finalization,
    ) -> Result<IngestOutcome, IngestError> {
        self.ingest_proven_blocks(
            block,
            crate::finality_proof::FinalityProof {
                certificate: finalization,
                descendants: Vec::new(),
            },
        )
        .await
    }

    #[cfg(test)]
    pub async fn ingest_finalized_proof(
        &self,
        block: HellasBlock,
        encoded_proof: &[u8],
    ) -> Result<IngestOutcome, IngestError> {
        self.ingest_proven_blocks(
            block,
            crate::finality_proof::FinalityProof::decode(encoded_proof)?,
        )
        .await
    }

    #[cfg(test)]
    async fn ingest_proven_blocks(
        &self,
        block: HellasBlock,
        proof: crate::finality_proof::FinalityProof,
    ) -> Result<IngestOutcome, IngestError> {
        let _guard = self.ingest_lock.lock().await;
        let terminal = proof.descendants.last().unwrap_or(&block);
        #[cfg(feature = "indexer-api")]
        let finalization = &proof.certificate;
        #[cfg(feature = "indexer-api")]
        let scheduled = self
            .schedule
            .as_ref()
            .map(|schedule| {
                // Every block's epoch must agree with the authenticated height schedule.
                for candidate in std::iter::once(&block).chain(proof.descendants.iter()) {
                    schedule.verifier(candidate.height(), candidate.context().round.epoch())?;
                }
                schedule.verifier(terminal.height(), finalization.proposal.round.epoch())
            })
            .transpose()?;
        #[cfg(feature = "indexer-api")]
        let verifier = scheduled
            .or(self.verifier.as_ref())
            .ok_or(IngestError::MissingVerifier)?;
        #[cfg(not(feature = "indexer-api"))]
        let verifier = self.verifier.as_ref().ok_or(IngestError::MissingVerifier)?;
        proof.verify(
            verifier,
            &LatestBlock {
                height: block.height().get(),
                payload: block.digest(),
                state_root: block.state_root(),
                finalization: Vec::new(),
            },
        )?;
        proof
            .verify_terminal_context(terminal)
            .map_err(|_| IngestError::RoundMismatch)?;
        let terminal_height = terminal.height();
        let terminal_payload = terminal.digest();
        {
            let mut values = self.fixture_source.0.lock().unwrap();
            values.insert(
                ResolverKey::Finalized {
                    height: terminal_height,
                },
                (proof.certificate.clone(), terminal.clone()).encode(),
            );
            for candidate in std::iter::once(&block).chain(&proof.descendants) {
                values.insert(ResolverKey::Block(candidate.digest()), candidate.encode());
            }
        }
        let mut pending = Vec::new();
        let mut expected_parent = None;
        for candidate in std::iter::once(block).chain(proof.descendants) {
            let height = candidate.height();
            let payload = candidate.digest();
            if let Some((_, existing_payload)) = self.marshal.get_info(height).await {
                if existing_payload != payload {
                    return Err(IngestError::ConflictingHeight {
                        height: height.get(),
                        existing: existing_payload,
                        incoming: payload,
                    });
                }
                expected_parent = Some(payload);
                continue;
            }
            if let Some((existing_height, _)) = self.marshal.get_info(&payload).await {
                return Err(IngestError::ConflictingPayload {
                    payload,
                    existing_height: existing_height.get(),
                    incoming_height: height.get(),
                });
            }
            let parent = match expected_parent {
                Some(parent) => parent,
                None => {
                    self.marshal
                        .get_info(Height::new(
                            height
                                .get()
                                .checked_sub(1)
                                .ok_or(IngestError::InvalidBlock)?,
                        ))
                        .await
                        .ok_or(IngestError::InvalidBlock)?
                        .1
                }
            };
            if candidate.parent() != parent {
                return Err(IngestError::InvalidBlock);
            }
            expected_parent = Some(payload);
            pending.push(candidate);
        }
        if pending.is_empty() {
            return Ok(IngestOutcome::Duplicate);
        }
        // Marshal must know the entire authenticated ancestry before the terminal
        // certificate triggers its normal ancestor finalization and persistence.
        for candidate in pending {
            if !self
                .marshal
                .verified(candidate.context().round, candidate)
                .await
            {
                return Err(IngestError::MarshalClosed);
            }
        }
        let mut marshal = self.marshal.clone();
        if !marshal
            .report(Activity::Finalization(proof.certificate))
            .accepted()
        {
            return Err(IngestError::MarshalClosed);
        }
        match self.marshal.get_info(terminal_height).await {
            Some((_, stored_payload)) if stored_payload == terminal_payload => {
                Ok(IngestOutcome::Applied)
            }
            Some((_, existing)) => Err(IngestError::ConflictingHeight {
                height: terminal_height.get(),
                existing,
                incoming: terminal_payload,
            }),
            None => Err(IngestError::NotStored {
                height: terminal_height.get(),
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
            .get_finalized_block_at(height, payload)
            .await?
            .map(|block| block.snapshot.finalization))
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
        #[cfg(feature = "full-node")]
        if height.get()
            < self
                .retained_from
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(None);
        }
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
        let mut descendants = Vec::new();
        let mut candidate = block.clone();
        let mut proof_bytes = 0usize;
        loop {
            if let Some(finalization) = self.marshal.get_finalization(candidate.height()).await {
                if finalization.proposal.payload != candidate.digest()
                    || finalization.proposal.round != candidate.context().round
                {
                    return Err(QueryError::StateUnavailable(
                        "finalization did not match its certified block".into(),
                    ));
                }
                let encoded = crate::finality_proof::encode(&finalization.encode(), &descendants)?;
                return Ok(Some(finalized_block(block, encoded)));
            }
            if descendants.len() >= crate::finality_proof::MAX_FINALITY_DESCENDANTS {
                return Err(QueryError::StateUnavailable(
                    "finality ancestry exceeds proof block limit".into(),
                ));
            }
            let next_height = candidate.height().get().checked_add(1).ok_or_else(|| {
                QueryError::StateUnavailable("finality ancestry height overflow".into())
            })?;
            let Some(child) = self.marshal.get_block(Height::new(next_height)).await else {
                return Err(QueryError::StateUnavailable(format!(
                    "no certified descendant available for finalized height {}",
                    height.get()
                )));
            };
            if child.height().get() != next_height || child.parent() != candidate.digest() {
                return Err(QueryError::StateUnavailable(
                    "finalized ancestry is not contiguous".into(),
                ));
            }
            proof_bytes = proof_bytes.saturating_add(child.encode().len());
            if proof_bytes > crate::finality_proof::MAX_FINALITY_PROOF_BYTES {
                return Err(QueryError::StateUnavailable(
                    "finality ancestry exceeds proof byte limit".into(),
                ));
            }
            descendants.push(child.clone());
            candidate = child;
        }
    }
}

#[cfg(test)]
pub async fn spawn_archive<E>(
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
    spawn_archive_with_provider(
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

#[cfg(all(test, feature = "indexer-api"))]
pub async fn spawn_trusted_archive<E>(
    context: E,
    partition_prefix: &str,
    config: Config,
    trust: hellas_genesis::TrustDocument,
    genesis_block: HellasBlock,
) -> Result<(ChainIndexer, Handle<()>), IngestError>
where
    E: BufferPooler + Clock + Metrics + Spawner + Storage + CryptoRng,
{
    spawn_trusted_archive_with_genesis(
        context,
        partition_prefix,
        config,
        trust,
        hellas_genesis::HELLAS_DEVNET_1_JSON.as_bytes(),
        genesis_block,
    )
    .await
}

/// Initialize a follower using an independently provisioned genesis document and trust schedule.
#[cfg(all(test, feature = "indexer-api"))]
pub async fn spawn_trusted_archive_with_genesis<E>(
    context: E,
    partition_prefix: &str,
    config: Config,
    trust: hellas_genesis::TrustDocument,
    genesis_json: &[u8],
    genesis_block: HellasBlock,
) -> Result<(ChainIndexer, Handle<()>), IngestError>
where
    E: BufferPooler + Clock + Metrics + Spawner + Storage + CryptoRng,
{
    let schedule = TrustedEpochs::with_genesis(trust, genesis_json)?;
    let verifier = schedule
        .verifier(Height::zero(), commonware_consensus::types::Epoch::zero())?
        .clone();
    let (mut indexer, handle) = spawn_archive_with_provider(
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

#[cfg(test)]
async fn spawn_archive_with_provider<E, P, H>(
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
    let (actor, indexer, _) = init(
        context.child("archive"),
        partition_prefix,
        &config,
        Start::Genesis(genesis_block),
        provider,
        epocher,
    )
    .await;
    let mailbox_size = NonZeroUsize::new(config.mailbox_size).unwrap_or(NonZeroUsize::MIN);
    let (resolver_rx, handler) = handler::init(context.child("marshal_resolver"), mailbox_size);
    let resolver = commonware_resolver::opaque::init::<_, _, _, PublicKey>(
        context.child("fixture_resolver"),
        indexer.fixture_source.clone(),
        handler,
        mailbox_size,
        std::time::Duration::from_secs(1),
    );
    let handle = actor.start_unbuffered(AutoAckApplication, (resolver_rx, resolver));
    Ok((indexer.with_verifier(verifier), handle))
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

#[cfg(test)]
#[derive(Clone, Copy)]
struct AutoAckApplication;

#[cfg(test)]
impl Reporter for AutoAckApplication {
    type Activity = Update<HellasBlock>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if let Update::Block(_, ack) = update {
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

// Test producers expose their certified blocks through an in-memory source.
#[cfg(test)]
#[derive(Clone, Default)]
struct FixtureSource(
    Arc<std::sync::Mutex<std::collections::BTreeMap<ResolverKey<Digest>, bytes::Bytes>>>,
);
#[cfg(test)]
impl commonware_resolver::opaque::Fetcher for FixtureSource {
    type Key = ResolverKey<Digest>;
    type Value = bytes::Bytes;
    async fn fetch(&self, key: Self::Key) -> Option<Self::Value> {
        self.0.lock().unwrap().get(&key).cloned()
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
use commonware_consensus::{
    Reporter,
    marshal::{
        Update,
        resolver::handler::{self, Key as ResolverKey},
    },
    simplex::types::Activity,
    types::FixedEpocher,
};
#[cfg(test)]
use commonware_cryptography::certificate::ConstantProvider;
#[cfg(test)]
use commonware_utils::Acknowledgement;
#[cfg(test)]
use std::num::NonZeroU64;
