//! Keep the configured archive window even when marshal advances its processed floor.
//! Both roles cap pruning at durable execution. Zero keeps the complete archive.
use super::*;
use commonware_consensus::marshal::store::{Blocks, Certificates};
use commonware_consensus::simplex::types::Finalization as Certificate;
use commonware_cryptography::Digestible;
use commonware_storage::{
    archive::{Identifier, prunable},
    translator::EightCap,
};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct Retained<T> {
    inner: T,
    floor: Arc<AtomicU64>,
}
impl<T> Retained<T> {
    fn cap(&self, height: Height) -> Height {
        Height::new(height.get().min(self.floor.load(Ordering::Acquire)))
    }
}

pub(super) async fn open<E, V>(
    context: E,
    partition: String,
    config: &Config,
    codec_config: V::Cfg,
    floor: Arc<AtomicU64>,
) -> Retained<prunable::Archive<EightCap, E, Digest, V>>
where
    E: BufferPooler + Clock + Metrics + Storage,
    V: commonware_codec::CodecShared,
{
    let inner = prunable::Archive::init(
        context.child("store"),
        prunable::Config {
            translator: EightCap,
            key_partition: format!("{partition}-key"),
            key_page_cache: config.page_cache(&context),
            value_partition: format!("{partition}-value"),
            compression: None,
            codec_config,
            items_per_section: NZU64!(256),
            replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
            key_write_buffer: NonZeroUsize::new(config.write_buffer).unwrap_or(NonZeroUsize::MIN),
            value_write_buffer: NonZeroUsize::new(config.write_buffer).unwrap_or(NonZeroUsize::MIN),
        },
    )
    .await
    .expect("failed to open retained chain archive");
    Retained { inner, floor }
}

impl<T: Blocks> Blocks for Retained<T> {
    type Block = T::Block;
    type Error = T::Error;
    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        self.inner.put(block).await
    }
    async fn put_start_sync(&mut self, block: Self::Block) -> Result<Handle<()>, Self::Error> {
        self.inner.put_start_sync(block).await
    }
    async fn sync(&mut self) -> Result<(), Self::Error> {
        self.inner.sync().await
    }
    async fn start_sync(&mut self) -> Result<Handle<()>, Self::Error> {
        self.inner.start_sync().await
    }
    async fn get(
        &self,
        id: Identifier<'_, <Self::Block as Digestible>::Digest>,
    ) -> Result<Option<Self::Block>, Self::Error> {
        self.inner.get(id).await
    }
    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        self.inner.prune(self.cap(min)).await
    }
    fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
        self.inner.missing_items(start, max)
    }
    fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
        self.inner.next_gap(value)
    }
    fn last_index(&self) -> Option<Height> {
        self.inner.last_index()
    }
}
impl<T: Certificates> Certificates for Retained<T> {
    type BlockDigest = T::BlockDigest;
    type Commitment = T::Commitment;
    type Scheme = T::Scheme;
    type Error = T::Error;
    async fn put(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        value: Certificate<Self::Scheme, Self::Commitment>,
    ) -> Result<(), Self::Error> {
        self.inner.put(height, digest, value).await
    }
    async fn put_start_sync(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        value: Certificate<Self::Scheme, Self::Commitment>,
    ) -> Result<Handle<()>, Self::Error> {
        self.inner.put_start_sync(height, digest, value).await
    }
    async fn sync(&mut self) -> Result<(), Self::Error> {
        self.inner.sync().await
    }
    async fn start_sync(&mut self) -> Result<Handle<()>, Self::Error> {
        self.inner.start_sync().await
    }
    async fn get(
        &self,
        id: Identifier<'_, Self::BlockDigest>,
    ) -> Result<Option<Certificate<Self::Scheme, Self::Commitment>>, Self::Error> {
        self.inner.get(id).await
    }
    async fn has(&self, height: Height) -> Result<bool, Self::Error> {
        self.inner.has(height).await
    }
    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        self.inner.prune(self.cap(min)).await
    }
    fn last_index(&self) -> Option<Height> {
        self.inner.last_index()
    }
    fn ranges_from(&self, from: Height) -> impl Iterator<Item = (Height, Height)> {
        self.inner.ranges_from(from)
    }
}
