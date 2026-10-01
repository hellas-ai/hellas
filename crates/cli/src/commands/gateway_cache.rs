use hellas_rpc::cache::{CacheOptions, CachePolicy, CacheStore};
use hellas_store::cache::FsCacheStore;
use std::{path::PathBuf, sync::Arc};
fn store_dir(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    explicit
        .or_else(hellas_store::state::dir)
        .ok_or_else(|| anyhow::anyhow!("no store location; set HELLAS_STORE_DIR or --store-dir"))
}
pub fn options(policy: CachePolicy, root: Option<PathBuf>) -> anyhow::Result<CacheOptions> {
    let store = if policy == CachePolicy::Off {
        None
    } else {
        Some(Arc::new(
            FsCacheStore::open(&store_dir(root)?, policy == CachePolicy::Record)
                .map_err(anyhow::Error::msg)?,
        ) as Arc<dyn CacheStore + Send + Sync>)
    };
    Ok(CacheOptions { policy, store })
}
