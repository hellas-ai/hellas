//! Scoped content stores and verified local-file indexing primitives.
//!
//! [`content`] supplies the shared Memory and Disk implementation and the
//! remote adapter. File identities and chunk descriptors remain available
//! through [`fastresume`] for explicit, bounded lower-layer indexing.

pub mod content;
pub mod fastresume;
pub mod hf;
pub mod xorb;

use std::io;
use std::path::{Path, PathBuf};

use hellas_xet::{Chunk, XetFileHasher, XetHash};

/// Bytes read per `read` while hashing. Large enough that the syscall is
/// not the bottleneck, small enough to be irrelevant beside a model.
const STREAM_BUFFER: usize = 1024 * 1024;

pub use hellas_private::open_regular_file;

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

/// Bound for a hung wait, not a performance requirement: CI runs many suites at
/// once on shared machines, and the property never depends on how fast that is.
#[cfg(test)]
pub(crate) const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(600);

#[cfg(test)]
thread_local! {
    static HASH_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Hashes exactly the length captured from the descriptor, then probes one
/// byte past it. `None` means the file was truncated or grew while it was
/// being read; importantly, a writer that grows forever cannot extend this
/// loop forever.
fn hash_exact_length(reader: &mut impl io::Read, expected_len: u64) -> io::Result<Option<Indexed>> {
    #[cfg(test)]
    HASH_CALLS.with(|calls| calls.set(calls.get() + 1));
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
    backing: Option<Box<content::BadBacking>>,
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

/// Errors from store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("reading {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} changed while it was being read")]
    Raced { path: PathBuf },
    #[error("{path} now names a different file than the one that was read")]
    Replaced { path: PathBuf },
    #[error("{path} is {actual} bytes, not the {expected} bytes declared for {id}")]
    WrongLength {
        id: String,
        expected: u64,
        actual: u64,
        path: PathBuf,
    },
}

type Result<T> = std::result::Result<T, StoreError>;

#[derive(Clone, Debug)]
struct Entry {
    path: PathBuf,
    /// The file this id was computed from, as `stat` described it.
    ///
    /// An entry says "these bytes are at this path", and a path is not a
    /// promise. Keeping the identity lets the verified open
    /// notice that the name now refers to something else, instead of
    /// answering `have` for content that was overwritten an hour ago.
    identity: fastresume::FileIdentity,
    chunks: Vec<Chunk>,
}

/// Opens an indexed path, then decides from the descriptor rather than from a
/// second lookup of the name. If replacement happened before `open`, the new
/// inode is refused. If it happened after `open`, the already-open verified
/// inode remains the one returned.
fn open_indexed_file(id: XetHash, length: u64, entry: &Entry) -> Result<Option<VerifiedFile>> {
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
    length: u64,
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
    let mut file = file;
    if !fastresume::FileIdentity::REMEMBERS {
        // An unchanged identity does not prove unchanged bytes here (see
        // `fastresume`), so prove it by hashing. The descriptor denies
        // writers (`open_regular_file`), so the bytes returned are the
        // bytes hashed.
        use std::io::Seek as _;
        let read = |source| StoreError::Read {
            path: entry.path.clone(),
            source,
        };
        match hash_exact_length(&mut file, actual).map_err(read)? {
            Some(indexed) if indexed.id == id => {}
            _ => return Ok(None),
        }
        file.seek(std::io::SeekFrom::Start(0)).map_err(read)?;
    }
    Ok(Some(VerifiedFile {
        file,
        id,
        len: actual,
        backing: None,
    }))
}

fn check_length(id: XetHash, actual: u64, path: &Path, expected: u64) -> Result<()> {
    if actual != expected {
        return Err(StoreError::WrongLength {
            id: id.to_string(),
            expected,
            actual,
            path: path.to_path_buf(),
        });
    }
    Ok(())
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
/// index would map A's id to a path that now holds B and could
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

// Symlink, descriptor-flag and inode tests: Unix-specific by construction.
#[cfg(all(test, unix))]
mod tests;
