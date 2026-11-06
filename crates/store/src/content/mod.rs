//! Generic verified objects, trees, pins and scoped content operations.
mod acquire;
mod core;
mod disk;
mod local;
mod memory;
mod page;
mod policy;
mod remote;
pub(crate) mod reservation;
mod server;
mod storage;
mod tree;
mod upload;
mod wire;

use std::{ops::Range, pin::Pin, sync::Arc};

use bytes::Bytes;
use futures_core::Stream;
use hellas_auth::{
    Digest,
    authority::{GrantId, UnixMillis},
};
use hellas_rpc::ContentRef;
use hellas_xet::Chunk;

pub use disk::{DiskStore, IndexMode};
pub use local::{JobContent, LocalStore, VerifiedReader};
pub use memory::MemoryStore;
pub use page::{body_limit, chunk_page};
pub use policy::{
    AllowList, Eviction, Lru, Miss, MissDecision, OnMiss, Refuse, StoreStats, Unpinned,
};
pub use remote::RemoteStore;
pub use reservation::Reservations;
pub use server::ContentService;
pub use tree::{MAX_NAME_BYTES, MAX_PATH_BYTES, MAX_TREE_BYTES, MAX_TREE_ENTRIES, PinName, Tree};
pub use upload::UploadSession;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid content: {0}")]
    Invalid(&'static str),
    #[error("content access denied")]
    Denied,
    #[error("content is missing")]
    Missing,
    #[error("pin or cursor changed")]
    Conflict,
    #[error("content reservation exhausted")]
    Capacity,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Object(ContentRef),
    Tree(ContentRef),
}
impl Target {
    pub fn object(self) -> ContentRef {
        match self {
            Self::Object(object) | Self::Tree(object) => object,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinPolicy {
    Owner,
    Jobs,
    Channel(Digest),
    Granted,
    Public,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinValue {
    pub target: Target,
    pub policy: PinPolicy,
    pub expires: Option<UnixMillis>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinTarget {
    pub name: PinName,
    pub policy: PinPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    pub pin: PinName,
    pub path: String,
}
impl Path {
    pub fn new(pin: PinName, path: String) -> Result<Self> {
        tree::validate_path(&path, true)?;
        Ok(Self { pin, path })
    }
}

/// The authenticated channel and work identifier, never supplied as authority by a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct JobId {
    pub channel: Digest,
    pub id: Digest,
}

/// Exact-pin evidence; the concrete authority layer rechecks the grant at every effect.
#[derive(Clone, Debug)]
pub struct GrantHandle {
    pub grant: GrantId,
    pub pin: PinName,
}

pub type Closure = Vec<ContentRef>;
pub type ReservationId = u64;

type AuthorityGuard = Box<dyn Fn() -> Result<()> + Send>;
struct LiveAuthority {
    acquire:
        Box<dyn Fn() -> futures::future::BoxFuture<'static, Result<AuthorityGuard>> + Send + Sync>,
    ended: Box<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync>,
}

#[derive(Clone)]
pub struct Scope {
    pub kind: ScopeKind,
    live: Option<Arc<LiveAuthority>>,
}
impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scope")
            .field("kind", &self.kind)
            .field("bound", &self.live.is_some())
            .finish()
    }
}
impl Scope {
    #[allow(non_upper_case_globals)]
    pub const Owner: Self = Self {
        kind: ScopeKind::Owner,
        live: None,
    };
    #[allow(non_upper_case_globals)]
    pub const Public: Self = Self {
        kind: ScopeKind::Public,
        live: None,
    };
    pub fn grant(handle: GrantHandle) -> Self {
        Self {
            kind: ScopeKind::Grant(handle),
            live: None,
        }
    }
    pub fn work(job: JobId, closure: Closure, reservation: ReservationId) -> Self {
        Self {
            kind: ScopeKind::Work {
                job,
                closure,
                reservation,
            },
            live: None,
        }
    }
    /// The concrete host returns a fresh-check closure owning its authority writer.
    /// Keeping that closure alive keeps the writer alive through the local commit.
    pub fn bind<F, Fut, G, E, End>(mut self, acquire: F, ended: E) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<G>> + Send + 'static,
        G: Fn() -> Result<()> + Send + 'static,
        E: Fn() -> End + Send + Sync + 'static,
        End: std::future::Future<Output = ()> + Send + 'static,
    {
        use futures::FutureExt;
        self.live = Some(Arc::new(LiveAuthority {
            acquire: Box::new(move || {
                let future = acquire();
                Box::pin(async move { Ok(Box::new(future.await?) as AuthorityGuard) })
            }),
            ended: Box::new(move || ended().boxed()),
        }));
        self
    }
    // Each waiter owns its monitor so dropping a select branch also cancels any
    // queued authority-writer acquisition before the carrier writes its response.
    pub async fn ended(&self) {
        match &self.live {
            Some(live) => (live.ended)().await,
            None => std::future::pending().await,
        }
    }
}
#[derive(Clone, Debug)]
pub enum ScopeKind {
    Owner,
    Grant(GrantHandle),
    Work {
        job: JobId,
        closure: Closure,
        reservation: ReservationId,
    },
    Public,
}

#[derive(Clone, Debug)]
pub enum Source {
    Peer {
        node: [u8; 32],
        at: Path,
    },
    HfXet {
        repo: crate::hf::Repo,
        commit: String,
        path: Option<String>,
    },
    Https {
        url: url::Url,
        sha256: Option<[u8; 32]>,
        bytes: u64,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub offset: u64,
    pub object: Option<ContentRef>,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub target: Target,
}

#[derive(Clone, Debug)]
pub struct ChunkPage {
    pub object: ContentRef,
    pub chunks: Vec<Chunk>,
    pub next: Option<Cursor>,
}

pub struct ByteStream {
    pub object: ContentRef,
    pub bytes: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>,
}

#[derive(Clone, Copy, Debug)]
pub struct Acquisition {
    pub object: ContentRef,
}

#[derive(Clone, Debug)]
pub struct PinPage {
    pub cursor: Cursor,
    pub pins: Vec<(PinName, PinValue)>,
    pub next: Option<Cursor>,
}

#[derive(Clone, Debug)]
pub enum PinEvent {
    Set {
        cursor: Cursor,
        name: PinName,
        value: Option<PinValue>,
    },
    Resync {
        cursor: Cursor,
    },
}
pub type PinEvents = Pin<Box<dyn Stream<Item = Result<PinEvent>> + Send>>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Collected {
    pub objects: u64,
    pub bytes: u64,
}

#[async_trait::async_trait]
pub trait ContentStore: Send + Sync {
    async fn stat(&self, s: &Scope, at: &Path) -> Result<Option<Stat>>;
    async fn chunks(&self, s: &Scope, at: &Path, page: Cursor) -> Result<ChunkPage>;
    async fn read(&self, s: &Scope, at: &Path, range: Range<u64>) -> Result<ByteStream>;
    async fn upload(
        &self,
        s: &Scope,
        object: ContentRef,
        pin: Option<PinTarget>,
    ) -> Result<UploadSession>;
    async fn acquire(
        &self,
        s: &Scope,
        source: Source,
        expect: Option<ContentRef>,
        pin: PinTarget,
    ) -> Result<Acquisition>;
    async fn set_pin(
        &self,
        s: &Scope,
        name: &PinName,
        expected: Option<&PinValue>,
        new: Option<PinValue>,
    ) -> Result<()>;
    async fn pins(&self, s: &Scope, prefix: &str, page: Cursor) -> Result<PinPage>;
    async fn watch(&self, s: &Scope, prefix: &str, from: Cursor) -> Result<PinEvents>;
    async fn collect(&self, s: &Scope) -> Result<Collected>;
}

// Both local backends execute one implementation of every scoped operation.
macro_rules! impl_local_content {
    ($backend:ty) => {
        #[async_trait::async_trait]
        impl ContentStore for $backend {
            async fn stat(&self, s: &Scope, at: &Path) -> Result<Option<Stat>> {
                self.core().stat(s, at).await
            }
            async fn chunks(&self, s: &Scope, at: &Path, page: Cursor) -> Result<ChunkPage> {
                self.core().chunks(s, at, page).await
            }
            async fn read(&self, s: &Scope, at: &Path, range: Range<u64>) -> Result<ByteStream> {
                self.core().read(s, at, range).await
            }
            async fn upload(
                &self,
                s: &Scope,
                object: ContentRef,
                pin: Option<PinTarget>,
            ) -> Result<UploadSession> {
                self.core().upload(s, object, pin).await
            }
            async fn acquire(
                &self,
                s: &Scope,
                source: Source,
                expect: Option<ContentRef>,
                pin: PinTarget,
            ) -> Result<Acquisition> {
                self.core().acquire(s, source, expect, pin).await
            }
            async fn set_pin(
                &self,
                s: &Scope,
                name: &PinName,
                expected: Option<&PinValue>,
                new: Option<PinValue>,
            ) -> Result<()> {
                self.core().set_pin(s, name, expected, new).await
            }
            async fn pins(&self, s: &Scope, prefix: &str, page: Cursor) -> Result<PinPage> {
                self.core().pins(s, prefix, page).await
            }
            async fn watch(&self, s: &Scope, prefix: &str, from: Cursor) -> Result<PinEvents> {
                self.core().watch(s, prefix, from).await
            }
            async fn collect(&self, s: &Scope) -> Result<Collected> {
                self.core().collect(s).await
            }
        }
    };
}
impl MemoryStore {
    fn core(&self) -> &core::Core {
        &self.core
    }
}
impl DiskStore {
    fn core(&self) -> &core::Core {
        &self.core
    }
}
impl_local_content!(LocalStore);
impl_local_content!(MemoryStore);

impl_local_content!(DiskStore);

#[cfg(test)]
mod conformance;
