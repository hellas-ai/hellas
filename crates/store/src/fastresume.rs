//! Remembering that a file has already been hashed.
//!
//! Identifying a large file costs a full read of it. Repeating that work
//! on every scan makes routine indexing expensive and turns large cache
//! trees into a denial-of-service surface, so the result has to be
//! remembered.
//!
//! Named after libtorrent's fastresume data, which is the same idea and
//! the same hazard: after a hash-check a client records what it learned
//! about each file so a restart need not re-verify, and validates that
//! record against the file's size and mtime before trusting it. Every
//! such client also offers "force recheck", because the record can be
//! wrong.
//!
//! # Why this one has to be stricter than a torrent client's
//!
//! A stale entry in a torrent client means a corrupt download. A stale
//! entry here makes the index claim that content still occupies a path
//! whose bytes have changed. So the key carries more than libtorrent's
//! `(size, mtime)`:
//!
//! - `dev` + `ino` — in the HuggingFace layout a content change *is* an
//!   inode change, because the client writes a new blob and re-points
//!   the snapshot symlink. Weak to inode reuse on its own.
//! - `size` — catches truncation and extension.
//! - `mtime_ns` — catches ordinary edits. Defeated by `utimensat`
//!   backdating, and by coarse filesystem resolution within one second.
//! - `ctime_ns` — cannot be set backwards from userspace, which is what
//!   closes the two holes above.
//!
//! Any disagreement discards the entry. There is no partial trust.
//!
//! # Windows
//!
//! Stable `std` exposes no inode (volume serial + file index are behind the
//! unstable `windows_by_handle`), and NTFS's ChangeTime -- the obvious
//! stand-in for `ctime` -- *can* be set from userspace through
//! `SetFileInformationByHandle(FileBasicInfo)`, so it would not close the
//! backdating hole `ctime` closes here. Rather than trust a weaker key,
//! Windows remembers nothing: [`Records`] stays empty and every scan
//! re-hashes, and the store proves an indexed file still holds its content
//! by hashing it rather than by comparing identities. [`FileIdentity`]
//! still exists there, built from size, last-write and creation time, for
//! the before/after check around a read, which Windows backs with a share
//! mode that denies writers for the duration (see `open_regular_file`).
//!
//! # Persistence
//!
//! Records survive restarts via [`load`] and [`save`], because a store
//! that re-hashes a 1.5 TB cache every boot is a store nobody will
//! adopt. The file format carries a magic and a version, and anything
//! it does not recognise is discarded rather than guessed at — a
//! misparsed record is a wrong content id, which is the one failure
//! this module exists to prevent.
//!
//! Loading is not trusting: a loaded record is still checked against the
//! live file's identity before it is used, exactly as an in-process one
//! is. The file is a cache of work, never a source of truth.

use std::collections::HashMap;
use std::fs::Metadata;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;

use crate::{Indexed, open_regular_file};
use hellas_xet::{Chunk, XetHash};

/// What a file must still look like for its recorded hash to be reused.
///
/// Every field is a way the file could have changed underneath us. They
/// are checked together; there is no most-significant one.
///
/// Public because it is the one definition of "the same file" this
/// workspace has. Anything else that remembers work done on a file must
/// ask the same question this asks; a second implementation would be a
/// second answer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

impl FileIdentity {
    /// Whether this platform's identity is strong enough to key remembered
    /// work (see the module docs); where it is not, [`Records`] stays empty.
    pub const REMEMBERS: bool = cfg!(unix);

    /// This file's identity, as `stat` describes it.
    #[cfg(unix)]
    #[must_use]
    pub fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            mtime_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            ctime_ns: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
        }
    }

    /// This file's identity as far as stable `std` can describe it on
    /// Windows: no file id, and creation time where `ctime` would be. Good
    /// for comparing one file against itself across a read; never used as
    /// a [`Records`] key (`REMEMBERS` is false).
    #[cfg(windows)]
    #[must_use]
    pub fn of(metadata: &Metadata) -> Self {
        use std::os::windows::fs::MetadataExt as _;

        // FILETIMEs count 100 ns intervals.
        Self {
            dev: 0,
            ino: 0,
            size: metadata.file_size(),
            mtime_ns: i128::from(metadata.last_write_time()) * 100,
            ctime_ns: i128::from(metadata.creation_time()) * 100,
        }
    }
}

/// What one store remembers about files it has hashed.
///
/// Owned rather than global. A process-wide table would mean one
/// store's `force_recheck` silently emptied another's, and two stores in
/// one process could never be reasoned about independently — which also
/// made tests interfere with each other, which is how this was noticed.
#[derive(Debug, Default)]
pub struct Records {
    entries: Mutex<HashMap<FileIdentity, Indexed>>,
}

impl Records {
    /// What indexing this file produced last time, if it still looks
    /// exactly the same.
    ///
    /// Keyed on identity rather than path, so one blob reached through
    /// two revisions' snapshot symlinks is hashed once.
    #[must_use]
    pub fn get(&self, metadata: &Metadata) -> Option<Indexed> {
        if !FileIdentity::REMEMBERS {
            return None;
        }
        let identity = FileIdentity::of(metadata);
        self.entries
            .lock()
            .ok()
            .and_then(|entries| entries.get(&identity).cloned())
    }

    /// Records what indexing this file produced.
    ///
    /// The chunk list is stored, not just the id: re-deriving the id
    /// costs a full read, and the chunk list is what a later partial
    /// fetch needs to be verifiable.
    pub fn put(&self, metadata: &Metadata, indexed: &Indexed) {
        if !FileIdentity::REMEMBERS {
            return;
        }
        let identity = FileIdentity::of(metadata);
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(identity, indexed.clone());
        }
    }

    /// Discards every record, forcing a re-hash of everything.
    ///
    /// The "force recheck" every fastresume implementation needs,
    /// because the identity check is a heuristic and heuristics are
    /// wrong eventually.
    pub fn force_recheck(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }

    /// Number of files remembered.
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }
}

/// Magic at the head of a fastresume file. Present so a truncated or
/// unrelated file is refused rather than read as records.
const MAGIC: &[u8; 8] = b"HELLASFR";
/// Bumped whenever the record layout changes. Old files are discarded,
/// never reinterpreted.
const FORMAT_VERSION: u32 = 1;
/// Maximum persisted cache file accepted or produced. A 1 GiB ceiling keeps
/// very large multi-terabyte content indexes practical while preventing an
/// untrusted or corrupt index from driving an unbounded allocation.
const MAX_FASTRESUME_INDEX_BYTES: usize = 1024 * 1024 * 1024;
/// A persisted index is a cache, so excess entries may be re-hashed instead of
/// allowing an attacker-controlled record count to size an unbounded table.
const MAX_FASTRESUME_RECORDS: usize = 1_000_000;
const FASTRESUME_HEADER_BYTES: usize = 8 + 4 + 8;
const FASTRESUME_RECORD_FIXED_BYTES: usize = 8 + 8 + 8 + 16 + 16 + 32 + 8 + 8;
const FASTRESUME_CHUNK_BYTES: usize = 32 + 8;

/// Writes a bounded subset of remembered records to `path`, atomically.
///
/// Written and synced through a uniquely-created sibling before an atomic
/// rename and parent-directory sync. A crash midway therefore leaves the
/// previous file intact rather than a half-written one that would parse into
/// wrong ids. Missing parent components are created owner-only and every new
/// directory edge is synced before publication. Path-based publication still
/// assumes the parent and its ancestors remain stable and trusted while this
/// operation runs.
///
/// # Errors
///
/// Returns the underlying I/O error if the file cannot be written or
/// renamed.
impl Records {
    #[allow(clippy::missing_errors_doc, reason = "documented on the item above")]
    pub fn save(&self, path: &Path) -> std::io::Result<usize> {
        let records = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return Ok(0),
        };

        let capacity = records
            .len()
            .min(MAX_FASTRESUME_RECORDS)
            .saturating_mul(128)
            .clamp(FASTRESUME_HEADER_BYTES, MAX_FASTRESUME_INDEX_BYTES);
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&0_u64.to_le_bytes());
        let mut saved = 0_usize;
        for (identity, indexed) in records.iter() {
            if saved == MAX_FASTRESUME_RECORDS {
                break;
            }
            let Some(record_bytes) = indexed
                .chunks
                .len()
                .checked_mul(FASTRESUME_CHUNK_BYTES)
                .and_then(|chunks| FASTRESUME_RECORD_FIXED_BYTES.checked_add(chunks))
            else {
                continue;
            };
            if out
                .len()
                .checked_add(record_bytes)
                .is_none_or(|total| total > MAX_FASTRESUME_INDEX_BYTES)
            {
                continue;
            }
            out.extend_from_slice(&identity.dev.to_le_bytes());
            out.extend_from_slice(&identity.ino.to_le_bytes());
            out.extend_from_slice(&identity.size.to_le_bytes());
            out.extend_from_slice(&identity.mtime_ns.to_le_bytes());
            out.extend_from_slice(&identity.ctime_ns.to_le_bytes());
            out.extend_from_slice(indexed.id.as_bytes());
            out.extend_from_slice(&indexed.len.to_le_bytes());
            out.extend_from_slice(&(indexed.chunks.len() as u64).to_le_bytes());
            for chunk in &indexed.chunks {
                out.extend_from_slice(chunk.hash.as_bytes());
                out.extend_from_slice(&chunk.data_len.to_le_bytes());
            }
            saved += 1;
        }
        out[12..FASTRESUME_HEADER_BYTES]
            .copy_from_slice(&u64::try_from(saved).unwrap_or(u64::MAX).to_le_bytes());
        drop(records);

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        create_durable_parent(parent)?;
        hellas_private::write_atomically(path, ".fastresume.tmp", &out)?;
        Ok(saved)
    }
}

/// Create any missing index-parent components and durably link every new
/// directory into its parent before the index itself is published.
fn create_durable_parent(path: &Path) -> std::io::Result<()> {
    // Checked on every platform before anything is created.
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} contains a parent-directory component", path.display()),
        ));
    }
    hellas_private::create_dir_all_durable(path)?;
    Ok(())
}

/// Reads records from `path` into memory, returning how many were
/// adopted.
///
/// A file that is missing, truncated, of another version, or otherwise
/// unreadable yields zero — never an error and never a partial parse.
/// The cost of ignoring a cache is a re-hash; the cost of misreading one
/// is a wrong content id.
impl Records {
    /// Reads records from `path`, returning how many were adopted.
    #[must_use]
    pub fn load(&self, path: &Path) -> usize {
        let Ok(file) = open_regular_file(path) else {
            return 0;
        };
        let Ok(metadata) = file.metadata() else {
            return 0;
        };
        let max_bytes = u64::try_from(MAX_FASTRESUME_INDEX_BYTES).unwrap_or(u64::MAX);
        if metadata.len() > max_bytes {
            return 0;
        }
        // The descriptor can grow after metadata inspection. Read one byte
        // beyond the limit so that race is rejected rather than truncated
        // into a different valid-looking index.
        let mut bytes = Vec::new();
        if file
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() > MAX_FASTRESUME_INDEX_BYTES
        {
            return 0;
        }
        let Some(parsed) = parse(&bytes) else {
            return 0;
        };
        let count = parsed.len();
        if let Ok(mut entries) = self.entries.lock() {
            entries.extend(parsed);
        }
        count
    }
}

fn parse(bytes: &[u8]) -> Option<Vec<(FileIdentity, Indexed)>> {
    let mut at = 0;
    let mut take = |n: usize| -> Option<&[u8]> {
        let slice = bytes.get(at..at + n)?;
        at += n;
        Some(slice)
    };
    if take(8)? != MAGIC {
        return None;
    }
    if u32::from_le_bytes(take(4)?.try_into().ok()?) != FORMAT_VERSION {
        return None;
    }
    let count = usize::try_from(u64::from_le_bytes(take(8)?.try_into().ok()?)).ok()?;
    if count > MAX_FASTRESUME_RECORDS {
        return None;
    }

    let mut parsed = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let identity = FileIdentity {
            dev: u64::from_le_bytes(take(8)?.try_into().ok()?),
            ino: u64::from_le_bytes(take(8)?.try_into().ok()?),
            size: u64::from_le_bytes(take(8)?.try_into().ok()?),
            mtime_ns: i128::from_le_bytes(take(16)?.try_into().ok()?),
            ctime_ns: i128::from_le_bytes(take(16)?.try_into().ok()?),
        };
        let id = XetHash::from_bytes(take(32)?.try_into().ok()?);
        let len = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let chunk_count = usize::try_from(u64::from_le_bytes(take(8)?.try_into().ok()?)).ok()?;
        let mut chunks = Vec::with_capacity(chunk_count.min(1 << 20));
        for _ in 0..chunk_count {
            let hash = XetHash::from_bytes(take(32)?.try_into().ok()?);
            chunks.push(Chunk::new(
                hash,
                u64::from_le_bytes(take(8)?.try_into().ok()?),
            ));
        }
        parsed.push((identity, Indexed { id, chunks, len }));
    }
    // Trailing bytes mean this is not the file we think it is.
    (at == bytes.len()).then_some(parsed)
}

/// True when `path` cannot be content: HuggingFace caches carry lock
/// files, partial downloads and negative-cache markers alongside real
/// blobs, and none of them are complete content.
///
/// An explicitly named file is still checked. This helper also keeps the
/// filtering rule in one place for callers that index a cache directory
/// wholesale.
#[must_use]
pub fn is_cache_debris(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    // `hf-hub` writes `<etag>.lock` INSIDE blobs/; Python writes
    // `.incomplete` files whose embedded etag is a goal, not a fact.
    name.ends_with(".lock")
        || name.ends_with(".incomplete")
        || path
            .components()
            .any(|component| component.as_os_str() == ".no_exist")
}

#[cfg(test)]
mod tests;
