//! Reusable inference recording, independent of HTTP and native storage.

mod fetch;
pub use fetch::fetch_output_stream;

use std::sync::Arc;

use futures::{StreamExt, stream::BoxStream};
use hellas_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend, OutputEvent,
    Provenance,
};
use hellas_rpc::cache::CacheLocks;
pub use hellas_rpc::cache::{CacheEntry, CacheKey, CacheKind, CacheStore, MemoryCacheStore};
use serde::{Serialize, de::DeserializeOwned};

use crate::{ClientError, ClientResult};

use hellas_rpc::cache::CacheRecording;
pub use hellas_rpc::cache::{CacheOptions, CachePolicy};

pub struct RecordingGuard {
    _guard: tokio::sync::OwnedMutexGuard<()>,
    recording: CacheRecording,
}

/// None denotes a nonterminal event; Some denotes terminal success/failure.
pub trait CacheEvent {
    fn terminal(&self) -> Option<bool>;
}

impl CacheEvent for OutputEvent {
    fn terminal(&self) -> Option<bool> {
        OutputEvent::terminal(self)
    }
}

pub type Transcript<E = OutputEvent, P = Provenance> = hellas_rpc::cache::Transcript<E, P>;

pub struct OutputCache {
    pub policy: CachePolicy,
    store: Arc<dyn CacheStore + Send + Sync>,
    pending: CacheLocks<tokio::sync::Mutex<()>>,
}

impl OutputCache {
    pub fn open(options: &CacheOptions) -> ClientResult<Option<Arc<Self>>> {
        if options.policy == CachePolicy::Off {
            return Ok(None);
        }
        let store = options
            .store
            .clone()
            .ok_or_else(|| cache_error("enabled inference cache requires a store"))?;
        Ok(Some(Arc::new(Self::new(options.policy, store))))
    }

    pub(crate) fn new(policy: CachePolicy, store: Arc<dyn CacheStore + Send + Sync>) -> Self {
        Self {
            policy,
            store,
            pending: CacheLocks::default(),
        }
    }

    pub async fn read<E: CacheEvent + DeserializeOwned, P: DeserializeOwned>(
        &self,
        key: CacheKey,
    ) -> ClientResult<Option<Transcript<E, P>>> {
        let store = self.store.clone();
        let lookup = key.clone();
        let bytes = tokio::task::spawn_blocking(move || store.get(&lookup))
            .await
            .map_err(cache_error)?
            .map_err(cache_error)?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let entry: Transcript<E, P> =
            serde_ipld_dagcbor::from_slice(&bytes).map_err(cache_error)?;
        entry
            .validate(&key, CacheEvent::terminal)
            .map_err(cache_error)?;
        Ok(Some(entry))
    }

    pub async fn acquire(&self, key: &CacheKey) -> ClientResult<RecordingGuard> {
        if self.policy == CachePolicy::ReplayOnly {
            return Err(cache_error(format!(
                "replay miss: {}/{}",
                key.kind, key.identity
            )));
        }
        let guard = self.pending.for_key(key).lock_owned().await;
        Ok(RecordingGuard {
            _guard: guard,
            recording: CacheRecording::new(self.store.clone()).map_err(cache_error)?,
        })
    }

    pub fn record<E, P>(
        self: Arc<Self>,
        key: CacheKey,
        provenance: Option<P>,
        mut upstream: BoxStream<'static, ClientResult<E>>,
        guard: RecordingGuard,
    ) -> BoxStream<'static, ClientResult<E>>
    where
        E: CacheEvent + Clone + Serialize + Send + 'static,
        P: Serialize + Send + 'static,
    {
        Box::pin(async_stream::try_stream! {
            let recording = guard.recording.clone();
            let _guard = guard;
            let mut events = Vec::new();
            let mut terminal = None;
            while let Some(event) = upstream.next().await {
                let event = event?;
                if terminal.is_some() {
                    Err(cache_error("event after terminal"))?;
                }
                match event.terminal() {
                    Some(false) => {
                        yield event;
                        return;
                    }
                    Some(true) => terminal = Some(event.clone()),
                    None => yield event.clone(),
                }
                events.push(event);
            }
            let terminal = terminal
                .ok_or_else(|| cache_error("stream ended without terminal event"))?;
            let transcript = Transcript {
                version: 1,
                key: key.clone(),
                initial_provenance: provenance,
                events,
            };
            let bytes = serde_ipld_dagcbor::to_vec(&transcript).map_err(cache_error)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(cache_error)?
                .as_secs();
            tokio::task::spawn_blocking(move || recording.insert(&key, &bytes, now))
                .await
                .map_err(cache_error)?
                .map_err(cache_error)?;
            yield terminal;
        })
    }
}

pub trait CacheIdentity {
    fn cache_key(&self, request: &BackendRequest) -> Result<CacheKey, BackendError>;
}

pub struct CachedBackend<B> {
    pub backend: B,
    pub cache: Option<Arc<OutputCache>>,
}

fn cache_error(error: impl std::fmt::Display) -> ClientError {
    ClientError::protocol(format!("inference cache: {error}"))
}

fn backend_error(error: impl std::fmt::Display) -> BackendError {
    BackendError::failed(error.to_string())
}

fn replay(entry: Transcript) -> BackendStream {
    BackendStream::new(
        futures::stream::iter(entry.events.into_iter().map(Ok)),
        entry.initial_provenance,
    )
}

impl<B: ExecutionBackend + CacheIdentity + Send + Sync> ExecutionBackend for CachedBackend<B> {
    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let Some(cache) = self.cache.clone() else {
                return self.backend.stream(request).await;
            };
            let key = self.backend.cache_key(&request)?;
            if let Some(entry) = cache.read(key.clone()).await.map_err(backend_error)? {
                return Ok(replay(entry));
            }
            let guard = cache.acquire(&key).await.map_err(backend_error)?;
            if let Some(entry) = cache.read(key.clone()).await.map_err(backend_error)? {
                return Ok(replay(entry));
            }
            let upstream = self.backend.stream(request).await?;
            let provenance = upstream.initial_provenance;
            let events = cache.record(
                key,
                provenance.clone(),
                upstream
                    .events
                    .map(|event| event.map_err(cache_error))
                    .boxed(),
                guard,
            );
            Ok(BackendStream::new(
                events.map(|event| event.map_err(backend_error)),
                provenance,
            ))
        })
    }
}
#[cfg(test)]
mod tests;
