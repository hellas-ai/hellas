use super::*;
use hellas_adaptors::{
    CanonicalExecution, ExecutionRequest, Input, ModelRef, RawRequest, StopReason, TextChannel,
};
use hellas_rpc::cache::CacheResult;
use std::sync::atomic::{AtomicUsize, Ordering};

fn request() -> BackendRequest {
    BackendRequest::new(
        ExecutionRequest::new(CanonicalExecution::new(
            ModelRef::new("m"),
            Input::Text("hello".into()),
        )),
        RawRequest::from_slice(br#"{"input":"hello","model":"m"}"#).unwrap(),
    )
}

fn key() -> CacheKey {
    CacheKey::hash(CacheKind::Proxy, &[b"fixture"])
}
fn finished() -> OutputEvent {
    OutputEvent::Finished {
        stop_reason: StopReason::EndOfText,
        usage: None,
    }
}
fn transcript() -> Transcript {
    Transcript {
        version: 1,
        key: key(),
        initial_provenance: Some(Provenance {
            call_commitment: Some("recorded".into()),
        }),
        events: vec![
            OutputEvent::TextDelta {
                index: 0,
                delta: "world".into(),
                channel: TextChannel::Output,
            },
            finished(),
        ],
    }
}

#[derive(Clone)]
struct Fake {
    calls: Arc<AtomicUsize>,
    events: Vec<OutputEvent>,
}
impl CacheIdentity for Fake {
    fn cache_key(&self, _: &BackendRequest) -> Result<CacheKey, BackendError> {
        Ok(key())
    }
}
impl ExecutionBackend for Fake {
    fn stream<'a>(&'a self, _: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(BackendStream::new(
                futures::stream::iter(self.events.clone().into_iter().map(Ok)),
                transcript().initial_provenance,
            ))
        })
    }
}
fn fake() -> Fake {
    Fake {
        calls: Arc::new(AtomicUsize::new(0)),
        events: transcript().events,
    }
}
fn cached(
    backend: Fake,
    policy: CachePolicy,
    store: Arc<dyn CacheStore + Send + Sync>,
) -> CachedBackend<Fake> {
    CachedBackend {
        backend,
        cache: Some(Arc::new(OutputCache::new(policy, store))),
    }
}

#[tokio::test]
async fn concurrent_recording_runs_once_and_replays_original_provenance() {
    let backend = cached(
        fake(),
        CachePolicy::Record,
        Arc::new(MemoryCacheStore::default()),
    );
    let run = || async {
        backend
            .stream(request())
            .await
            .unwrap()
            .collect()
            .await
            .unwrap()
    };
    let (first, second) = tokio::join!(run(), run());
    assert_eq!(first, second);
    assert_eq!(first.provenance, transcript().initial_provenance);
    assert_eq!(backend.backend.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn replay_miss_never_calls_backend() {
    let backend = cached(
        fake(),
        CachePolicy::ReplayOnly,
        Arc::new(MemoryCacheStore::default()),
    );
    assert!(
        backend
            .stream(request())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("replay miss")
    );
    assert_eq!(backend.backend.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn incomplete_failed_cancelled_and_invalid_suffix_are_not_recorded() {
    for events in [
        vec![transcript().events[0].clone()],
        vec![OutputEvent::Error {
            message: "failed".into(),
            code: None,
        }],
        vec![OutputEvent::Finished {
            stop_reason: StopReason::Cancelled,
            usage: None,
        }],
        vec![finished(), transcript().events[0].clone()],
    ] {
        let store = Arc::new(MemoryCacheStore::default());
        let mut source = fake();
        source.events = events;
        let backend = cached(source, CachePolicy::Record, store.clone());
        let _ = backend.stream(request()).await.unwrap().collect().await;
        assert!(store.get(&key()).unwrap().is_none());
    }
}

#[tokio::test]
async fn dropping_stream_leaves_no_recording_and_releases_request_lock() {
    let store = Arc::new(MemoryCacheStore::default());
    let backend = cached(fake(), CachePolicy::Record, store.clone());
    let mut first = backend.stream(request()).await.unwrap();
    first.events.next().await.unwrap().unwrap();
    drop(first);
    assert!(store.get(&key()).unwrap().is_none());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        backend
            .stream(request())
            .await
            .unwrap()
            .collect()
            .await
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(backend.backend.calls.load(Ordering::SeqCst), 2);
}

struct FailingStore;
impl CacheStore for FailingStore {
    fn get(&self, _: &CacheKey) -> CacheResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn generation(&self) -> CacheResult<u64> {
        Ok(0)
    }
    fn insert_at_generation(&self, _: &CacheKey, _: &[u8], _: u64, _: u64) -> CacheResult<bool> {
        Err("disk full".into())
    }
    fn list(&self) -> CacheResult<Vec<CacheEntry>> {
        Ok(Vec::new())
    }
    fn evict(&self, _: &hellas_rpc::cache::Eviction) -> CacheResult<Vec<CacheKey>> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn persistence_failure_prevents_successful_terminal() {
    let backend = cached(fake(), CachePolicy::Record, Arc::new(FailingStore));
    let error = backend
        .stream(request())
        .await
        .unwrap()
        .collect()
        .await
        .unwrap_err();
    assert!(error.to_string().contains("disk full"));
}

#[tokio::test]
async fn clear_during_streaming_does_not_repopulate_the_cache() {
    let store = Arc::new(MemoryCacheStore::default());
    let backend = cached(fake(), CachePolicy::Record, store.clone());
    let mut stream = backend.stream(request()).await.unwrap();
    stream.events.next().await.unwrap().unwrap();
    store
        .evict(&hellas_rpc::cache::Eviction::default())
        .unwrap();
    let tail = stream.events.collect::<Vec<_>>().await;
    assert!(tail.iter().all(Result::is_ok));
    assert!(store.list().unwrap().is_empty());
    backend
        .stream(request())
        .await
        .unwrap()
        .collect()
        .await
        .unwrap();
    assert_eq!(backend.backend.calls.load(Ordering::SeqCst), 2);
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn invalid_keys_and_versions_are_rejected() {
    assert!("../proxy".parse::<CacheKind>().is_err());
    assert!(CacheKey::new(CacheKind::Proxy, "../../entry").is_err());
    let mut entry = transcript();
    entry.version = 2;
    assert!(entry.validate(&key(), CacheEvent::terminal).is_err());
    entry.version = 1;
    assert!(
        entry
            .validate(
                &CacheKey::hash(CacheKind::Proxy, &[b"other"]),
                CacheEvent::terminal
            )
            .is_err()
    );
}
