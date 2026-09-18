//! Cache administration over any RPC transport. Mount behind an explicit
//! admin policy (see crate::serve::Authorized), never inference credentials.

use super::{CacheFilter, CacheKey, CacheOptions, CachePolicy, CachePrune, CacheStore, Eviction};
use crate::pb::host as pb;
use crate::services::cache_control::CacheControlHandler;
use futures_core::Stream;
use hellas_wire::{WireCode, WireStatus};
use std::{pin::Pin, sync::Arc};

pub type CacheReplies =
    Pin<Box<dyn Stream<Item = Result<pb::ManageCacheResponse, WireStatus>> + Send>>;

#[derive(Clone)]
pub struct CacheController {
    store: Option<Arc<dyn CacheStore + Send + Sync>>,
    writable: bool,
}

impl CacheController {
    pub fn new(options: &CacheOptions) -> Self {
        Self {
            store: options.store.clone(),
            writable: options.policy == CachePolicy::Record,
        }
    }

    /// In-process and wire callers share the same operation. Store access is
    /// synchronous; hosts choose the executor on which to poll their handler.
    pub fn manage(&self, request: pb::ManageCacheRequest) -> Result<CacheReplies, WireStatus> {
        use pb::manage_cache_request::Operation;
        use pb::manage_cache_response::Result as Reply;
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| WireStatus::new(WireCode::FailedPrecondition, "cache is not enabled"))?;
        let replies: Box<dyn Iterator<Item = Reply> + Send> = match request
            .operation
            .ok_or_else(|| invalid("cache operation is required"))?
        {
            Operation::List(request) => Box::new(
                store
                    .query(&filter(request)?)
                    .map_err(storage)?
                    .into_iter()
                    .map(|entry| {
                        Reply::Entry(pb::CacheEntry {
                            key: Some(key_to_pb(entry.key)),
                            output: entry.output.to_string(),
                            recorded_at: entry.recorded_at,
                            bytes: entry.bytes,
                        })
                    }),
            ),
            Operation::Read(request) => {
                let key = CacheKey::new(request.kind.parse().map_err(invalid)?, &request.identity)
                    .map_err(invalid)?;
                let bytes = store
                    .get(&key)
                    .map_err(storage)?
                    .ok_or_else(|| WireStatus::new(WireCode::NotFound, "cache entry not found"))?;
                // Read once: concurrent clear/re-record cannot splice objects.
                Box::new((0..bytes.len()).step_by(65536).map(move |offset| {
                    Reply::Data(bytes[offset..(offset + 65536).min(bytes.len())].to_vec())
                }))
            }
            Operation::Stats(request) => {
                let stats = store.stats(&filter(request)?).map_err(storage)?;
                Box::new(std::iter::once(Reply::Stats(pb::CacheStats {
                    entries: stats.entries,
                    bytes: stats.bytes,
                })))
            }
            Operation::Evict(request) => {
                if !request.dry_run && !self.writable {
                    return Err(WireStatus::new(
                        WireCode::PermissionDenied,
                        "cache is read-only",
                    ));
                }
                let filter = filter(request.filter.unwrap_or_default())?;
                if request.prune.is_none()
                    && !request.all
                    && (filter.kind.is_none() || filter.identity.is_none())
                {
                    return Err(invalid("clearing a non-exact selection requires all=true"));
                }
                let eviction = Eviction {
                    filter,
                    dry_run: request.dry_run,
                    prune: request.prune.map(|p| CachePrune {
                        recorded_before: p.recorded_before,
                        max_entries: p.max_entries,
                        max_bytes: p.max_bytes,
                    }),
                };
                eviction.select(Vec::new()).map_err(invalid)?;
                let removed = store.evict(&eviction).map_err(storage)?;
                Box::new(std::iter::once(Reply::Evict(pb::CacheEviction {
                    entries: removed.len() as u64,
                    dry_run: request.dry_run,
                })))
            }
        };
        Ok(Box::pin(futures_util::stream::iter(replies.map(
            |result| {
                Ok(pb::ManageCacheResponse {
                    result: Some(result),
                })
            },
        ))))
    }
}

impl CacheControlHandler for CacheController {
    async fn manage_cache(
        &self,
        request: pb::ManageCacheRequest,
    ) -> Result<CacheReplies, WireStatus> {
        self.manage(request)
    }
}

fn invalid(error: impl std::fmt::Display) -> WireStatus {
    WireStatus::new(WireCode::InvalidArgument, error.to_string())
}
fn storage(error: impl std::fmt::Display) -> WireStatus {
    WireStatus::internal(format!("cache: {error}"))
}
fn filter(value: pb::CacheFilter) -> Result<CacheFilter, WireStatus> {
    let filter = CacheFilter {
        kind: value
            .kind
            .map(|kind| kind.parse())
            .transpose()
            .map_err(invalid)?,
        identity: value.identity,
    };
    filter.validate().map_err(invalid)?;
    Ok(filter)
}
pub fn key_to_pb(key: CacheKey) -> pb::CacheKey {
    pb::CacheKey {
        kind: key.kind.to_string(),
        identity: key.identity,
    }
}

#[cfg(all(test, unix, not(target_os = "espidf")))]
mod tests;
