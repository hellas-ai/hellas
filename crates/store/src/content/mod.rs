//! Generic verified objects, trees, pins and scoped content operations.
mod page;
mod tree;
mod upload;

use std::{ops::Range, pin::Pin};

use bytes::Bytes;
use futures_core::Stream;
use hellas_auth::{
    Digest,
    authority::{GrantId, UnixMillis},
};
use hellas_rpc::ContentRef;
use hellas_xet::Chunk;

pub use page::{body_limit, chunk_page};
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug)]
pub enum Scope {
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
