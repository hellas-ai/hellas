use crate::domain::{Object, ObjectId};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_glue::stateful::db::ManagedDb;
#[cfg(any(feature = "validator", feature = "explorer-origin"))]
use commonware_glue::stateful::db::Shared;
use commonware_parallel::Sequential;
use commonware_runtime::{BufferPooler, Spawner, buffer::paged::CacheRef};
use commonware_storage::{
    Context as StorageContext,
    journal::contiguous::fixed::Config as FixedLogConfig,
    mmr::{self, full::Config as MmrConfig},
    qmdb::any::{FixedConfig, unordered::fixed::Db as AnyFixedDb},
    translator::EightCap,
};
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

pub type UtxoDb<E> = AnyFixedDb<mmr::Family, E, ObjectId, Object, Sha256, EightCap, Sequential>;
/// The `DatabaseSet` consensus hands to the application. `execution` is a
/// private module and the crate root only re-exports `UtxoDb`, so this
/// alias is crate-internal — and only the `validator` build executes
/// transactions against it. An `indexer` build reads blocks, it does not
/// replay them.
#[cfg(any(feature = "validator", feature = "explorer-origin"))]
pub type UtxoDatabase<E> = Shared<UtxoDb<E>>;
pub type UtxoDbConfig = FixedConfig<EightCap, Sequential>;
pub use crate::block::UtxoSyncTarget;

const ITEMS_PER_BLOB: NonZeroU64 = NonZeroU64::new(256).unwrap();
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(8192).unwrap();
const INIT_BUFFER: NonZeroUsize = NonZeroUsize::new(1 << 21).unwrap();

pub const DEFAULT_PAGE_CACHE_SIZE: NonZeroU16 = NonZeroU16::new(4096).unwrap();
pub const DEFAULT_PAGE_CACHE_COUNT: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

pub fn utxo_db_config(
    pooler: &impl BufferPooler,
    partition_prefix: &str,
    page_cache_size: u16,
    page_cache_count: usize,
) -> UtxoDbConfig {
    let page_cache_size = NonZeroU16::new(page_cache_size).unwrap_or(DEFAULT_PAGE_CACHE_SIZE);
    let page_cache_count = NonZeroUsize::new(page_cache_count).unwrap_or(DEFAULT_PAGE_CACHE_COUNT);
    let page_cache = CacheRef::from_pooler(pooler, page_cache_size, page_cache_count);

    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: format!("{partition_prefix}_utxo_mmr_journal_v3"),
            metadata_partition: format!("{partition_prefix}_utxo_mmr_metadata_v3"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedLogConfig {
            partition: format!("{partition_prefix}_utxo_log_journal_v3"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache,
            write_buffer: WRITE_BUFFER,
        },
        translator: EightCap,
        init_cache_size: None,
        init_buffer: INIT_BUFFER,
        init_concurrency: (),
    }
}

pub async fn empty_state<E>(
    context: E,
    partition_prefix: &str,
    page_cache_size: u16,
    page_cache_count: usize,
) -> (Digest, UtxoSyncTarget)
where
    E: StorageContext + Spawner,
{
    let config = utxo_db_config(
        &context,
        &format!("{partition_prefix}_genesis_probe"),
        page_cache_size,
        page_cache_count,
    );
    let db = UtxoDb::init(context, config)
        .await
        .expect("genesis probe database must initialize");
    let state_root = db.root();
    let sync_target = <UtxoDb<E> as ManagedDb<E>>::sync_target(&db);
    (state_root, sync_target)
}
