//! Certified source history for protocol fixtures. This actor only stores source
//! records; it does not execute or publish a consumer's state. Executing-node
//! tests deliver its output through FullNode::accept_finalized or ChainSync.
#[cfg(all(test, feature = "indexer-api"))]
use super::trusted_epochs::TrustedEpochs;
use super::*;
use crate::{ConsensusVerifier, domain::PublicKey};
use commonware_actor::Feedback;
use commonware_runtime::Handle;

#[derive(Clone)]
pub(crate) struct ArchiveSource {
    pub(crate) archive: ChainIndexer,
    source: FixtureSource,
}
impl std::ops::Deref for ArchiveSource {
    type Target = ChainIndexer;
    fn deref(&self) -> &Self::Target {
        &self.archive
    }
}
impl ArchiveSource {
    pub(crate) async fn publish_proof(
        &self,
        block: HellasBlock,
        encoded: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let proof = crate::finality_proof::FinalityProof::decode(encoded)?;
        let terminal = proof.descendants.last().unwrap_or(&block);
        let terminal_height = terminal.height();
        let terminal_payload = terminal.digest();
        {
            let mut records = self.source.0.lock().unwrap();
            records.insert(
                ResolverKey::Finalized {
                    height: terminal_height,
                },
                (proof.certificate.clone(), terminal.clone()).encode(),
            );
            for candidate in std::iter::once(&block).chain(&proof.descendants) {
                records.insert(ResolverKey::Block(candidate.digest()), candidate.encode());
            }
        }
        for candidate in std::iter::once(block).chain(proof.descendants) {
            if !self
                .archive
                .marshal
                .verified(candidate.context().round, candidate)
                .await
            {
                return Err("source archive closed".into());
            }
        }
        if !self
            .archive
            .marshal
            .clone()
            .report(Activity::Finalization(proof.certificate))
            .accepted()
        {
            return Err("source archive closed".into());
        }
        if self
            .archive
            .marshal
            .get_info(terminal_height)
            .await
            .map(|(_, payload)| payload)
            != Some(terminal_payload)
        {
            return Err("source archive did not store supplied history".into());
        }
        Ok(())
    }
}

pub async fn spawn_archive<E>(
    context: E,
    partition_prefix: &str,
    config: Config,
    verifier: ConsensusVerifier,
    genesis_block: HellasBlock,
) -> Result<(ArchiveSource, Handle<()>), Box<dyn std::error::Error + Send + Sync>>
where
    E: BufferPooler + Clock + Metrics + Spawner + Storage + CryptoRng,
{
    let provider = ConstantProvider::new(verifier.scheme().clone());
    let epocher = FixedEpocher::new(NonZeroU64::new(u64::MAX).unwrap());
    spawn_archive_with_provider(
        context,
        partition_prefix,
        config,
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
) -> Result<(ArchiveSource, Handle<()>), Box<dyn std::error::Error + Send + Sync>>
where
    E: BufferPooler + Clock + Metrics + Spawner + Storage + CryptoRng,
{
    spawn_trusted_archive_with_genesis(
        context,
        partition_prefix,
        config,
        trust,
        hellas_genesis::HELLAS_DEVNET_3_JSON.as_bytes(),
        genesis_block,
    )
    .await
}

/// Construct source history using the production archive codec and epoch schedule.
#[cfg(all(test, feature = "indexer-api"))]
pub async fn spawn_trusted_archive_with_genesis<E>(
    context: E,
    partition_prefix: &str,
    config: Config,
    trust: hellas_genesis::TrustDocument,
    genesis_json: &[u8],
    genesis_block: HellasBlock,
) -> Result<(ArchiveSource, Handle<()>), Box<dyn std::error::Error + Send + Sync>>
where
    E: BufferPooler + Clock + Metrics + Spawner + Storage + CryptoRng,
{
    let schedule = TrustedEpochs::with_genesis(trust, genesis_json)?;
    let (indexer, handle) = spawn_archive_with_provider(
        context,
        partition_prefix,
        config,
        genesis_block,
        schedule.clone(),
        schedule.clone(),
    )
    .await?;
    Ok((indexer, handle))
}

async fn spawn_archive_with_provider<E, P, H>(
    context: E,
    partition_prefix: &str,
    config: Config,
    genesis_block: HellasBlock,
    provider: P,
    epocher: H,
) -> Result<(ArchiveSource, Handle<()>), Box<dyn std::error::Error + Send + Sync>>
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
    let source = FixtureSource::default();
    let mailbox_size = NonZeroUsize::new(config.mailbox_size).unwrap_or(NonZeroUsize::MIN);
    let (resolver_rx, handler) = handler::init(context.child("marshal_resolver"), mailbox_size);
    let resolver = commonware_resolver::opaque::init::<_, _, _, PublicKey>(
        context.child("fixture_resolver"),
        source.clone(),
        handler,
        mailbox_size,
        std::time::Duration::from_secs(1),
    );
    let handle = actor.start_unbuffered(ArchiveOnlySink, (resolver_rx, resolver));
    Ok((
        ArchiveSource {
            archive: indexer,
            source,
        },
        handle,
    ))
}

#[derive(Clone, Copy)]
struct ArchiveOnlySink;

impl Reporter for ArchiveOnlySink {
    type Activity = Update<HellasBlock>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if let Update::Block(_, ack) = update {
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

// Test producers expose their certified blocks through an in-memory source.
#[derive(Clone, Default)]
struct FixtureSource(
    Arc<std::sync::Mutex<std::collections::BTreeMap<ResolverKey<Digest>, bytes::Bytes>>>,
);
impl commonware_resolver::opaque::Fetcher for FixtureSource {
    type Key = ResolverKey<Digest>;
    type Value = bytes::Bytes;
    async fn fetch(&self, key: Self::Key) -> Option<Self::Value> {
        self.0.lock().unwrap().get(&key).cloned()
    }
}

use commonware_consensus::{
    Reporter,
    marshal::{
        Update,
        resolver::handler::{self, Key as ResolverKey},
    },
    simplex::types::Activity,
    types::FixedEpocher,
};
use commonware_cryptography::certificate::ConstantProvider;
use commonware_utils::Acknowledgement;
use std::num::NonZeroU64;
