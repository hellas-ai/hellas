//! A content store addressed by Xet file hash.
//!
//! # The shape
//!
//! A Nix store, or a BitTorrent client's view of its own disk: an entry
//! is named by a hash of its content, so *where it came from is not part
//! of its identity*. That single property is what makes everything else
//! work — any source producing the right bytes is as good as any other,
//! so content can be substituted from a local HuggingFace cache, a peer,
//! an HTTP seed, or a tarball without any of them being privileged.
//!
//! We reuse HuggingFace's exact hashing scheme ([`hellas_xet`]), which
//! is the trick the whole design turns on: **an existing HuggingFace
//! cache is already a populated store**. Adopting one is indexing, not
//! downloading.
//!
//! # Indexing produces two things, and the second is the valuable one
//!
//! [`ContentStore::index`] returns the content id *and* the chunk list.
//! Keeping only the id would throw away the expensive half of a pass we
//! must make anyway.
//!
//! The chunk list is the metainfo, in the BitTorrent sense. A Xet file
//! hash is a Merkle root over exactly those descriptors, so holding them
//! makes any later *partial* fetch of that file verifiable. This matters
//! because HuggingFace's reconstruction protocol returns no chunk hashes
//! at all — content arriving from an untrusted peer is otherwise
//! unverifiable until the whole file is reassembled, which is a fine way
//! to waste fourteen gigabytes on a liar.
//!
//! # Never trust an id you did not compute
//!
//! HuggingFace advertises an `x-xet-hash` per file. For Xet-native
//! uploads it is exactly the Xet hash of the content. For legacy-LFS
//! content bridged into Xet it is **not** — measured, on real files,
//! with matching sha256 confirming the bytes were the ones HF meant.
//!
//! So an advertised id is a hint that lets us skip work when it agrees,
//! and never a key. Ids in this store are ones we computed: a
//! content-addressed store cannot defend a key it did not derive from
//! the bytes.

pub mod fastresume;
pub mod hf;
pub mod hf_cache;
pub mod state;
pub mod xorb;

use std::collections::HashMap;
#[cfg(any(unix, test))]
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use hellas_xet::{Chunk, XetFileHasher, XetHash};

/// Bytes read per `read` while hashing. Large enough that the syscall is
/// not the bottleneck, small enough to be irrelevant beside a model.
const STREAM_BUFFER: usize = 1024 * 1024;

/// Opens a local regular file without first opening a FIFO or device for I/O.
///
/// Explicit content paths may be symlinks: the target descriptor, rather than
/// the symlink name, is the authority. Linux first acquires an `O_PATH`
/// descriptor, which does not open the underlying object, checks its type, and
/// then reopens that exact inode through `/proc/self/fd`. Consequently a path
/// replacement between the type check and the readable open cannot substitute
/// a FIFO or device. The returned descriptor is read-only, seekable, and
/// close-on-exec.
///
/// Other platforms do not expose an equivalent through `std`: they preflight
/// the followed path, use nonblocking open where Unix provides it, and verify
/// the resulting descriptor. That rejects stable special files but cannot
/// close an adversarial replacement race as Linux does.
pub fn open_regular_file(path: &Path) -> io::Result<std::fs::File> {
    open_regular_file_impl(path)
}

fn not_a_regular_file(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} is not a regular file", path.display()),
    )
}

#[cfg(target_os = "linux")]
fn open_regular_file_impl(path: &Path) -> io::Result<std::fs::File> {
    let path_handle = open_path_handle(path)?;
    reopen_regular_path_handle(path, &path_handle)
}

/// Acquires an inode reference without invoking the target's file operations.
#[cfg(target_os = "linux")]
fn open_path_handle(path: &Path) -> io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // OpenOptions masks custom flags with !O_ACCMODE. On musl that mask
    // includes O_PATH, turning a descriptor-only open into a blocking read.
    loop {
        // SAFETY: path is NUL-terminated and live for the call. These flags
        // do not create a file, so open needs no variadic mode argument.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd >= 0 {
            // SAFETY: open returned a new descriptor, owned only here.
            return Ok(unsafe { std::fs::File::from_raw_fd(fd) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Converts an `O_PATH` reference to a readable descriptor for the same inode.
#[cfg(target_os = "linux")]
fn reopen_regular_path_handle(
    path: &Path,
    path_handle: &std::fs::File,
) -> io::Result<std::fs::File> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let expected = path_handle.metadata()?;
    if !expected.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }

    let descriptor_path = Path::new("/proc/self/fd").join(path_handle.as_raw_fd().to_string());
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_CLOEXEC);
    let file = options.open(&descriptor_path).map_err(|source| {
        // Once the held descriptor has been fstat-ed successfully, ENOENT can
        // only mean procfs cannot provide the safe reopen. Do not report the
        // caller's existing content as a cache miss.
        let kind = if source.kind() == io::ErrorKind::NotFound {
            io::ErrorKind::Unsupported
        } else {
            source.kind()
        };
        io::Error::new(
            kind,
            format!(
                "cannot safely reopen {} through {}: {source}",
                path.display(),
                descriptor_path.display()
            ),
        )
    })?;
    let actual = file.metadata()?;
    if !actual.file_type().is_file()
        || (expected.dev(), expected.ino()) != (actual.dev(), actual.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} did not reopen the inode held by its path descriptor",
                path.display()
            ),
        ));
    }
    Ok(file)
}

/// Best available fallback where `O_PATH` plus descriptor reopen is absent.
#[cfg(all(unix, not(target_os = "linux")))]
fn open_regular_file_impl(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let expected = std::fs::metadata(path)?;
    if !expected.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = options.open(path)?;
    let actual = file.metadata()?;
    if !actual.file_type().is_file()
        || (expected.dev(), expected.ino()) != (actual.dev(), actual.ino())
    {
        return Err(not_a_regular_file(path));
    }
    Ok(file)
}

/// Best available fallback for non-Unix targets.
#[cfg(not(unix))]
fn open_regular_file_impl(path: &Path) -> io::Result<std::fs::File> {
    let expected = std::fs::metadata(path)?;
    if !expected.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }
    Ok(file)
}

/// What indexing one file learned about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Indexed {
    /// The content id: a Merkle root over `chunks`.
    pub id: XetHash,
    /// Chunk descriptors, in order. The metainfo that makes a partial
    /// fetch of this content verifiable.
    pub chunks: Vec<Chunk>,
    /// Total length in bytes.
    pub len: u64,
}

/// Hashes exactly the length captured from the descriptor, then probes one
/// byte past it. `None` means the file was truncated or grew while it was
/// being read; importantly, a writer that grows forever cannot extend this
/// loop forever.
fn hash_exact_length(reader: &mut impl io::Read, expected_len: u64) -> io::Result<Option<Indexed>> {
    let mut hasher = XetFileHasher::new();
    let mut buffer = vec![0_u8; STREAM_BUFFER];
    let mut remaining = expected_len;
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(STREAM_BUFFER as u64))
            .expect("the read is bounded by STREAM_BUFFER");
        let read = reader.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Ok(None);
        }
        remaining -= read as u64;
        hasher.update(&buffer[..read]);
    }

    let mut sentinel = [0_u8; 1];
    if reader.read(&mut sentinel)? != 0 {
        return Ok(None);
    }

    let chunks = hasher.finalize_chunks();
    Ok(Some(Indexed {
        id: hellas_xet::file_hash(&chunks),
        chunks,
        len: expected_len,
    }))
}

/// A read-only handle to content whose identity and exact length the store
/// verified.
///
/// The descriptor, rather than its path, is the authority. A cache name may
/// be replaced after this value is returned without changing the inode that a
/// consumer receives. This is not an immutable-file seal: another writable
/// descriptor can still modify the same inode after verification.
#[derive(Debug)]
pub struct VerifiedFile {
    file: std::fs::File,
    id: XetHash,
    len: u64,
}

impl VerifiedFile {
    /// The Xet content id this descriptor was verified against.
    #[must_use]
    pub fn id(&self) -> XetHash {
        self.id
    }

    /// The exact verified length of the file.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the verified file is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Transfers the read-only descriptor to its consumer.
    #[must_use]
    pub fn into_file(self) -> std::fs::File {
        self.file
    }
}

/// Anything that can make content appear that is not here yet.
///
/// Separate from [`Substituter`] on purpose. A substituter answers
/// cheaply and locally; a fetcher may spend bandwidth and disk. Keeping
/// the interfaces separate lets callers choose explicitly whether an
/// operation may perform remote work.
pub trait Fetcher: Send + Sync {
    /// Name, for diagnostics.
    fn name(&self) -> &str;

    /// Writes content `id` to `dest`, verifying it.
    ///
    /// `expected` is our chunk list for this content when we have one,
    /// which lets an implementation check a partial response as it
    /// arrives instead of only once it is whole.
    fn fetch(
        &self,
        id: XetHash,
        dest: &Path,
        expected: Option<&[Chunk]>,
    ) -> core::result::Result<u64, crate::hf::FetchError>;
}

/// Anything that might already hold content we want.
///
/// Deliberately narrow: a substituter answers "do you have this, and
/// where", and nothing else. It does not fetch, because a source that
/// can fetch and a source that can answer cheaply have very different
/// costs. An availability check must not silently become network
/// activity.
pub trait Substituter: Send + Sync {
    /// Name, for diagnostics.
    fn name(&self) -> &str;

    /// Path to content with this id, if this source already holds it.
    fn locate(&self, id: XetHash) -> Option<PathBuf>;
}

/// Errors from store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("reading {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is cache debris, not content")]
    Debris { path: PathBuf },
    #[error("{path} changed while it was being read")]
    Raced { path: PathBuf },
    #[error("{path} now names a different file than the one that was read")]
    Replaced { path: PathBuf },
    #[error("{path} holds {actual}, which is not the {expected} that was asked for")]
    WrongContent {
        expected: String,
        actual: String,
        path: PathBuf,
    },
    #[error("{path} is {actual} bytes, not the {expected} bytes declared for {id}")]
    WrongLength {
        id: String,
        expected: u64,
        actual: u64,
        path: PathBuf,
    },
    #[error("{path} is {actual} bytes, over the {maximum}-byte limit for {id}")]
    TooLarge {
        id: String,
        maximum: u64,
        actual: u64,
        path: PathBuf,
    },
    #[error("materialising {id}")]
    Fetch {
        id: String,
        #[source]
        source: crate::hf::FetchError,
    },
}

type Result<T> = std::result::Result<T, StoreError>;

/// A content-addressed store over local paths.
///
/// Cheap to clone; clones share one index.
#[derive(Clone, Default)]
pub struct ContentStore {
    index: Arc<RwLock<HashMap<XetHash, Entry>>>,
    /// What this store has already hashed. Owned, so two stores never
    /// invalidate each other's work.
    records: Arc<fastresume::Records>,
    substituters: Arc<Vec<Arc<dyn Substituter>>>,
}

#[derive(Clone, Debug)]
struct Entry {
    path: PathBuf,
    /// The file this id was computed from, as `stat` described it.
    ///
    /// An entry says "these bytes are at this path", and a path is not a
    /// promise. Keeping the identity is what lets [`ContentStore::locate`]
    /// notice that the name now refers to something else, instead of
    /// answering `have` for content that was overwritten an hour ago.
    identity: fastresume::FileIdentity,
    chunks: Vec<Chunk>,
}

impl ContentStore {
    /// An empty store with no substituters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a place content may already be. Consulted in the order
    /// added, after the store's own index.
    #[must_use]
    pub fn with_substituter(mut self, substituter: Arc<dyn Substituter>) -> Self {
        let mut substituters = self.substituters.as_ref().clone();
        substituters.push(substituter);
        self.substituters = Arc::new(substituters);
        self
    }

    /// Hashes the file at `path` and records it — "give it data to hash
    /// and start seeding".
    ///
    /// Streams, so cost is one read regardless of size. An unchanged
    /// file is hashed once: [`fastresume`] remembers the result against
    /// the file's identity.
    pub fn index(&self, path: &Path) -> Result<Indexed> {
        self.index_open(path).map(|(indexed, _file)| indexed)
    }

    /// Indexes `path` while retaining the descriptor whose bytes justified
    /// the result.
    fn index_open(&self, path: &Path) -> Result<(Indexed, std::fs::File)> {
        use std::io::Seek as _;

        if fastresume::is_cache_debris(path) {
            return Err(StoreError::Debris {
                path: path.to_path_buf(),
            });
        }

        let read_err = |source| StoreError::Read {
            path: path.to_path_buf(),
            source,
        };
        let mut file = open_regular_file(path).map_err(read_err)?;
        let before = file.metadata().map_err(read_err)?;
        let identity = fastresume::FileIdentity::of(&before);

        let remembered = self.records.get(&before);
        let indexed = match remembered.clone() {
            Some(indexed) => indexed,
            None => hash_exact_length(&mut file, before.len())
                .map_err(read_err)?
                .ok_or_else(|| StoreError::Raced {
                    path: path.to_path_buf(),
                })?,
        };

        // Nothing is remembered, recorded or returned until this holds.
        // Whether the id was computed just now or looked up, it is an id
        // for the descriptor; recording it against a *name* needs that
        // name to still refer to the same file, and an id that cannot be
        // bound to what was read is an error rather than an answer.
        still_the_file_that_was_read(path, identity, &file)?;
        file.rewind().map_err(read_err)?;
        if remembered.is_none() {
            self.records.put(&before, &indexed);
        }
        self.record(path, identity, &indexed);
        Ok((indexed, file))
    }

    /// Indexes every regular file under `directory`, skipping cache
    /// debris. Returns what was indexed.
    ///
    /// This is how an existing HuggingFace cache becomes a populated
    /// store: no download, no copy, just a read of what is already
    /// there.
    pub fn adopt(&self, directory: &Path) -> Result<Vec<Indexed>> {
        let mut adopted = Vec::new();
        let mut pending = vec![directory.to_path_buf()];
        while let Some(dir) = pending.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                // A cache we do not own can have directories we cannot
                // read. Skipping one is better than refusing all of it.
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                // `file_type` is `lstat`, and only a regular file is
                // content. A symlink here would be followed to bytes
                // that are already indexed under their own name — or,
                // pointed at `/dev/zero`, read forever. A fifo under
                // `blobs/` would block adoption of the whole cache on
                // `open`. Neither is exotic in a directory we do not own.
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                if kind.is_dir() {
                    pending.push(path);
                } else if kind.is_file()
                    && !fastresume::is_cache_debris(&path)
                    && let Ok(indexed) = self.index(&path)
                {
                    adopted.push(indexed);
                }
            }
        }
        Ok(adopted)
    }

    /// True when this content is available locally, right now, without
    /// touching the network.
    ///
    /// Deliberately narrower than [`Self::materialize`]: checking
    /// availability never causes a remote fetch.
    #[must_use]
    pub fn have(&self, id: XetHash) -> bool {
        self.locate(id).is_some()
    }

    /// Where this content is, if anywhere reachable already holds it.
    #[must_use]
    pub fn locate(&self, id: XetHash) -> Option<PathBuf> {
        if let Some(entry) = self
            .index
            .read()
            .ok()
            .and_then(|index| index.get(&id).cloned())
        {
            // Existence is not the question. The question is whether the
            // name still refers to the file whose bytes produced this id:
            // an ordinary rewrite leaves the path there and the entry
            // false, and `have` must not claim bytes the store no longer
            // holds.
            if std::fs::metadata(&entry.path)
                .is_ok_and(|metadata| fastresume::FileIdentity::of(&metadata) == entry.identity)
            {
                return Some(entry.path);
            }
            if let Ok(mut index) = self.index.write() {
                index.remove(&id);
            }
        }
        self.substituters
            .iter()
            .find_map(|substituter| substituter.locate(id))
    }

    /// Opens locally available content as the exact inode the store verified.
    ///
    /// An indexed hit is opened and matched against the full file identity
    /// recorded when it was hashed, so replacing its path cannot substitute a
    /// different inode between lookup and open. This path does not rehash an
    /// unchanged indexed file. A substituter hit is less trusted: it is
    /// indexed, checked against `id`, and returned through the same descriptor
    /// that was indexed. No fetcher is consulted and no content is acquired.
    ///
    /// `expected_len` is part of the caller's content contract and must match
    /// the descriptor exactly.
    pub fn open_verified(&self, id: XetHash, expected_len: u64) -> Result<Option<VerifiedFile>> {
        self.open_verified_with(id, LengthContract::Exact(expected_len))
    }

    /// Opens locally available content whose exact length is not known by the
    /// caller, refusing it before allocation when it exceeds `maximum_len`.
    ///
    /// This is for content-addressed metadata such as an application-owned
    /// manifest root: its hash is the identity, while its decoder owns the
    /// exact shape and length. As with [`Self::open_verified`], this performs
    /// no network fetch and returns the descriptor whose identity was checked.
    pub fn open_verified_bounded(
        &self,
        id: XetHash,
        maximum_len: u64,
    ) -> Result<Option<VerifiedFile>> {
        self.open_verified_with(id, LengthContract::AtMost(maximum_len))
    }

    fn open_verified_with(
        &self,
        id: XetHash,
        length: LengthContract,
    ) -> Result<Option<VerifiedFile>> {
        if let Some(entry) = self
            .index
            .read()
            .ok()
            .and_then(|index| index.get(&id).cloned())
        {
            if let Some(verified) = open_indexed_file(id, length, &entry)? {
                return Ok(Some(verified));
            }
            self.forget_if_stale(id, &entry);
        }

        for substituter in self.substituters.iter() {
            let Some(path) = substituter.locate(id) else {
                continue;
            };
            let (indexed, file) = self.index_open(&path)?;
            if indexed.id != id {
                return Err(StoreError::WrongContent {
                    expected: id.to_string(),
                    actual: indexed.id.to_string(),
                    path,
                });
            }
            let actual = file
                .metadata()
                .map_err(|source| StoreError::Read {
                    path: path.clone(),
                    source,
                })?
                .len();
            check_length(id, actual, &path, length)?;
            return Ok(Some(VerifiedFile {
                file,
                id,
                len: actual,
            }));
        }

        Ok(None)
    }

    /// The chunk list for indexed content — the metainfo needed to
    /// verify a partial fetch of it.
    #[must_use]
    pub fn chunks(&self, id: XetHash) -> Option<Vec<Chunk>> {
        self.index
            .read()
            .ok()
            .and_then(|index| index.get(&id).map(|entry| entry.chunks.clone()))
    }

    /// Makes content `id` available locally, fetching it if it is not
    /// already here, and indexes the result.
    ///
    /// Unlike [`Self::have`], this operation may cost bandwidth and disk.
    /// The caller decides when that remote work is permitted.
    ///
    /// `fetch` is handed the chunk list when we already hold one, so a
    /// partial response can be checked chunk by chunk rather than only
    /// at the end.
    pub fn materialize(&self, id: XetHash, dest: &Path, fetch: &dyn Fetcher) -> Result<Indexed> {
        if let Some(path) = self.locate(id) {
            let indexed = self.index(&path)?;
            // A source said it held this id. Believing that without
            // looking is how `materialize(a)` comes to return content
            // `b` — a substituter is another node's answer, not ours.
            if indexed.id != id {
                return Err(StoreError::WrongContent {
                    expected: id.to_string(),
                    actual: indexed.id.to_string(),
                    path,
                });
            }
            return Ok(indexed);
        }
        // Only what we made appear is ours to clean up. A `dest` that was
        // already there belongs to whoever put it there.
        let ours = dest.symlink_metadata().is_err();
        fetch
            .fetch(id, dest, self.chunks(id).as_deref())
            .map_err(|source| StoreError::Fetch {
                id: id.to_string(),
                source,
            })?;
        let indexed = self.index(dest)?;
        // A fetcher that wrote the wrong bytes must not leave them in
        // the store under a name they do not own.
        if indexed.id != id {
            if ours {
                let _ = std::fs::remove_file(dest);
            }
            return Err(StoreError::Fetch {
                id: id.to_string(),
                source: crate::hf::FetchError::WrongContent {
                    expected: id,
                    actual: indexed.id,
                },
            });
        }
        Ok(indexed)
    }

    /// What this store remembers having hashed.
    ///
    /// Exposed so a caller can persist it across restarts — adopting a
    /// terabyte cache should cost one read per file ever, not one per
    /// boot.
    #[must_use]
    pub fn records(&self) -> &fastresume::Records {
        &self.records
    }

    /// Number of distinct contents indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.read().map(|index| index.len()).unwrap_or(0)
    }

    /// True when nothing is indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn record(&self, path: &Path, identity: fastresume::FileIdentity, indexed: &Indexed) {
        if let Ok(mut index) = self.index.write() {
            index.insert(
                indexed.id,
                Entry {
                    path: path.to_path_buf(),
                    identity,
                    chunks: indexed.chunks.clone(),
                },
            );
        }
    }

    fn forget_if_stale(&self, id: XetHash, stale: &Entry) {
        if let Ok(mut index) = self.index.write()
            && index.get(&id).is_some_and(|current| {
                current.path == stale.path && current.identity == stale.identity
            })
        {
            index.remove(&id);
        }
    }
}

#[derive(Clone, Copy)]
enum LengthContract {
    Exact(u64),
    AtMost(u64),
}

/// Opens an indexed path, then decides from the descriptor rather than from a
/// second lookup of the name. If replacement happened before `open`, the new
/// inode is refused. If it happened after `open`, the already-open verified
/// inode remains the one returned.
fn open_indexed_file(
    id: XetHash,
    length: LengthContract,
    entry: &Entry,
) -> Result<Option<VerifiedFile>> {
    let file = match open_regular_file(&entry.path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StoreError::Read {
                path: entry.path.clone(),
                source,
            });
        }
    };
    verify_opened_indexed_file(id, length, entry, file)
}

fn verify_opened_indexed_file(
    id: XetHash,
    length: LengthContract,
    entry: &Entry,
    file: std::fs::File,
) -> Result<Option<VerifiedFile>> {
    let metadata = file.metadata().map_err(|source| StoreError::Read {
        path: entry.path.clone(),
        source,
    })?;
    if fastresume::FileIdentity::of(&metadata) != entry.identity {
        return Ok(None);
    }
    let actual = metadata.len();
    check_length(id, actual, &entry.path, length)?;
    Ok(Some(VerifiedFile {
        file,
        id,
        len: actual,
    }))
}

fn check_length(id: XetHash, actual: u64, path: &Path, contract: LengthContract) -> Result<()> {
    match contract {
        LengthContract::Exact(expected) if actual != expected => Err(StoreError::WrongLength {
            id: id.to_string(),
            expected,
            actual,
            path: path.to_path_buf(),
        }),
        LengthContract::AtMost(maximum) if actual > maximum => Err(StoreError::TooLarge {
            id: id.to_string(),
            maximum,
            actual,
            path: path.to_path_buf(),
        }),
        LengthContract::Exact(_) | LengthContract::AtMost(_) => Ok(()),
    }
}

/// The file that was read is still the file this name refers to.
///
/// Two questions, and they are not the same one.
///
/// `file` is the descriptor the bytes came from. If its identity moved
/// while it was being read, the id is a Merkle root over bytes that were
/// never on disk together — a hash of nothing real. The old code noticed
/// this and declined to *remember* it, but still put it in the live index
/// and returned it, which is the half that mattered.
///
/// `path` is the name the id is about to be recorded against. A rename
/// over an open file leaves the descriptor untouched, so no amount of
/// re-`fstat`ing sees it; only stat-ing the name does. Without this the
/// index would map A's id to a path that now holds B, and `locate` would
/// hand that path to a caller who asked for A.
///
/// Either way this is an error rather than a silent skip. The caller
/// asked what the bytes at this name are, and the honest answer is that
/// nobody knows.
fn still_the_file_that_was_read(
    path: &Path,
    read: fastresume::FileIdentity,
    file: &std::fs::File,
) -> Result<()> {
    let read_err = |source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    };
    if fastresume::FileIdentity::of(&file.metadata().map_err(read_err)?) != read {
        return Err(StoreError::Raced {
            path: path.to_path_buf(),
        });
    }
    if fastresume::FileIdentity::of(&std::fs::metadata(path).map_err(read_err)?) != read {
        return Err(StoreError::Replaced {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

impl core::fmt::Debug for ContentStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContentStore")
            .field("indexed", &self.len())
            .field(
                "substituters",
                &self
                    .substituters
                    .iter()
                    .map(|substituter| substituter.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests;
