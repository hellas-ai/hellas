//! Files, directories and local IPC endpoints that only the current user can
//! reach, and durable private writes.
//!
//! Unix expresses privacy as modes (0600 files, 0700 directories), ownership
//! by the effective uid, and opening without following a symlink. Windows has
//! neither modes nor `O_NOFOLLOW`; the equivalents are the owner SID, the DACL,
//! and `FILE_FLAG_OPEN_REPARSE_POINT`. SYSTEM and Administrators are tolerated
//! in a Windows DACL for the same reason root is on Unix: they can reach the
//! object regardless of what it says.

use std::fs::File;
use std::io::{self, Write as _};
use std::path::Path;

use tempfile::NamedTempFile;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as imp;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
use windows as imp;

/// Opens `path` for reading without following a final symlink (Unix) or
/// reparse point (Windows). `NotFound` passes through unchanged.
pub fn open_nofollow(path: &Path) -> io::Result<File> {
    imp::open_nofollow(path)
}

/// Whether `file` is a regular file that only this user can reach.
pub fn is_private(file: &File) -> io::Result<bool> {
    if !file.metadata()?.is_file() {
        return Ok(false);
    }
    imp::is_private(file)
}

/// Makes an existing directory private to this user: mode 0700 on Unix; on
/// Windows an owner-only, protected DACL that files and directories created
/// inside it inherit.
pub fn restrict_directory(path: &Path) -> io::Result<()> {
    imp::restrict_directory(path)
}

/// Opens a directory itself, refusing anything that is not one; a FIFO or
/// device swapped in under the name cannot turn the open into a wait.
/// Symlinks to directories are followed, for operator-managed state paths.
pub fn open_directory(path: &Path) -> io::Result<File> {
    let directory = imp::open_directory(path)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", path.display()),
        ));
    }
    Ok(directory)
}

/// Makes prior changes to `path`'s entries durable. Windows has no directory
/// fsync; there the renamed file's own flush is what survives.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    if cfg!(windows) {
        return Ok(());
    }
    open_directory(path)?.sync_all()
}

/// Creates `path` and any missing ancestors durably: new directories are made
/// 0700 on Unix (so a permissive umask cannot widen them) and synced from leaf
/// to root, followed by the first pre-existing ancestor, so a successful
/// return survives power loss. A non-directory in the way is an error.
/// Returns whether anything was created.
pub fn create_dir_all_durable(path: &Path) -> io::Result<bool> {
    let path = std::path::absolute(path)?;
    let mut missing = Vec::new();
    let mut candidate = path.as_path();
    loop {
        match std::fs::metadata(candidate) {
            Ok(metadata) if metadata.is_dir() => break,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a directory", candidate.display()),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing.push(candidate),
            Err(error) => return Err(error),
        }
        candidate = candidate.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} has no existing directory ancestor", path.display()),
            )
        })?;
    }
    imp::create_dir_all(&path)?;
    for directory in &missing {
        sync_directory(directory)?;
    }
    if let Some(existing) = missing.last().and_then(|directory| directory.parent()) {
        sync_directory(existing)?;
    }
    Ok(!missing.is_empty())
}

/// A new temporary file in `directory`, named `{prefix}<random>{suffix}`, that
/// is private from the moment it exists: mode 0600 and never through a link on
/// Unix; an owner-only protected DACL on Windows. Dropping it removes it.
pub fn private_tempfile(directory: &Path, prefix: &str, suffix: &str) -> io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .make_in(directory, imp::create_private_new)
}

/// Atomically replaces `path` with `bytes`, privately and durably: through a
/// private temporary beside it (named `.{file name}.<random>{suffix}`, so a
/// caller can recognise its own debris), flushed before the rename, with the
/// directory entry flushed after it. The temporary is removed on any failure.
pub fn write_atomically(path: &Path, suffix: &str, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;
    let mut temporary = private_tempfile(parent, &format!(".{}.", name.to_string_lossy()), suffix)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    // Close first, keeping the TempPath as the guard that removes the file if
    // the rename fails. std's rename, not TempPath::persist: on Windows it
    // uses POSIX semantics and replaces a destination another handle has
    // open, where MoveFileEx reports access denied.
    let temporary = temporary.into_temp_path();
    std::fs::rename(&temporary, path)?;
    let _published = temporary.keep();
    sync_directory(parent)
}

#[cfg(test)]
mod tests;
