use std::{
    fs::OpenOptions,
    io::{self, Read as _},
    path::Path,
};

/// Reads one ordinary file confined to an explicitly selected directory.
/// Portable relative names use `/`, with no parent, root or symlink components.
/// Unix resolves beneath held directory descriptors without following symlinks.
/// Windows holds directory handles that deny replacement for the read's lifetime.
#[derive(Debug)]
pub struct ReadDirectory {
    _root: std::fs::File,
    #[cfg(windows)]
    _parents: Vec<std::fs::File>,
    #[cfg(windows)]
    path: std::path::PathBuf,
}

impl ReadDirectory {
    pub fn open(root: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                _root: crate::imp::open_directory(root)?,
            })
        }
        #[cfg(windows)]
        {
            let path = root.canonicalize()?;
            let mut current = std::path::PathBuf::new();
            let mut handles = Vec::new();
            for component in path.components() {
                current.push(component);
                if matches!(component, std::path::Component::Prefix(_)) {
                    continue;
                }
                let handle = pinned_windows_file(&current)?;
                if !handle.metadata()?.is_dir() {
                    return Err(not_a_regular_file(&current));
                }
                handles.push(handle);
            }
            let _root = handles
                .pop()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing directory"))?;
            Ok(Self {
                _root,
                _parents: handles,
                path,
            })
        }
    }

    pub fn read(&self, relative: &Path, maximum: usize) -> io::Result<Vec<u8>> {
        use std::path::Component;
        let spelling = relative.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 relative path")
        })?;
        if spelling.is_empty()
            || spelling.contains(['\\', ':'])
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path must stay inside the selected folder",
            ));
        }
        #[cfg(unix)]
        let file = {
            use std::{
                ffi::CString,
                os::fd::{AsRawFd as _, FromRawFd as _},
            };
            let mut directory = self._root.try_clone()?;
            let mut components = relative.components().peekable();
            loop {
                let component = components.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing filename")
                })?;
                let name = CString::new(component.as_os_str().to_str().unwrap_or_default())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                let last = components.peek().is_none();
                let flags = libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | if last {
                        libc::O_NONBLOCK
                    } else {
                        libc::O_DIRECTORY
                    };
                let next = loop {
                    // SAFETY: a held directory fd, valid C name and read-only flags.
                    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
                    if fd >= 0 {
                        break unsafe { std::fs::File::from_raw_fd(fd) };
                    }
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                };
                if last {
                    if !next.metadata()?.is_file() {
                        return Err(not_a_regular_file(relative));
                    }
                    break next;
                }
                directory = next;
            }
        };
        #[cfg(windows)]
        {
            let mut path = self.path.clone();
            let mut parents = Vec::new();
            let mut components = relative.components().peekable();
            let file = loop {
                let component = components.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing filename")
                })?;
                path.push(component);
                let handle = pinned_windows_file(&path)?;
                if components.peek().is_none() {
                    if !handle.metadata()?.is_file() {
                        return Err(not_a_regular_file(relative));
                    }
                    break handle;
                }
                if !handle.metadata()?.is_dir() {
                    return Err(not_a_regular_file(relative));
                }
                parents.push(handle);
            };
            // Retain every parent until the selected file has been opened and read.
            return read_bounded(file, maximum);
        };
        #[cfg(unix)]
        {
            read_bounded(file, maximum)
        }
    }
}

#[cfg(windows)]
fn pinned_windows_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ,
    };
    // Deny directory replacement and reparse edits while any descendant is read.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "job paths must not be reparse points",
        ));
    }
    Ok(file)
}

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

/// Open a regular configuration file while refusing a final symlink/reparse
/// point. Unlike `open_nofollow`, a FIFO cannot block this operation. Linux
/// retains the descriptor-first type check used by `open_regular_file`.
pub fn open_regular_file_nofollow(path: &Path) -> io::Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        let handle = open_path_handle_flags(path, libc::O_NOFOLLOW)?;
        reopen_regular_path_handle(path, &handle)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if !std::fs::symlink_metadata(path)?.is_file() {
            return Err(not_a_regular_file(path));
        }
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)?
        };
        #[cfg(not(unix))]
        let file = crate::open_nofollow(path)?;
        if !file.metadata()?.is_file() {
            return Err(not_a_regular_file(path));
        }
        Ok(file)
    }
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
    open_path_handle_flags(path, 0)
}

#[cfg(target_os = "linux")]
fn open_path_handle_flags(path: &Path, extra_flags: i32) -> io::Result<std::fs::File> {
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
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC | extra_flags) };
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

/// Best available fallback where Unix descriptors are absent. Windows adds a
/// read-only share mode, so no writer can open the file while it is being
/// hashed -- the guarantee the Unix paths approximate with identity checks
/// (fastresume's Windows identity is deliberately weak; see there).
#[cfg(not(unix))]
fn open_regular_file_impl(path: &Path) -> io::Result<std::fs::File> {
    let expected = std::fs::metadata(path)?;
    if !expected.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_SHARE_READ: other readers may share the file; writers and
        // deleters are refused until it is closed.
        options.share_mode(0x0000_0001);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }
    Ok(file)
}

/// Read at most `maximum` bytes and require EOF, including after concurrent growth.
pub fn read_bounded(reader: impl io::Read, maximum: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    read_bounded_into(reader, maximum, &mut bytes)?;
    Ok(bytes)
}

fn read_bounded_into(
    mut reader: impl io::Read,
    maximum: usize,
    bytes: &mut Vec<u8>,
) -> io::Result<()> {
    reader.by_ref().take(maximum as u64).read_to_end(bytes)?;
    // Keep one spare byte in the private buffer, and probe EOF separately so
    // filling it cannot reallocate and leave a previous secret allocation behind.
    let mut extra = zeroize::Zeroizing::new(Vec::with_capacity(2));
    reader.take(1).read_to_end(&mut extra)?;
    if !extra.is_empty() {
        return Err(too_large());
    }
    Ok(())
}
fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, ReadLimit)
}

#[derive(Debug)]
pub struct ReadLimit;
impl std::fmt::Display for ReadLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("file exceeds byte limit")
    }
}
impl std::error::Error for ReadLimit {}

/// The caller selects whether to follow a link when opening the regular file.
/// Secret bytes are cleared on errors as well as when the returned buffer drops.
pub fn read_private_bounded(
    file: std::fs::File,
    maximum: usize,
) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    if !crate::is_private(&file)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file must be private",
        ));
    }
    if file.metadata()?.len() > maximum as u64 {
        return Err(too_large());
    }
    let capacity = maximum.checked_add(1).ok_or_else(too_large)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
    read_bounded_into(file, maximum, &mut bytes)?;
    Ok(bytes)
}

/// Open and bound a regular file; path replacements cannot substitute a FIFO.
pub fn read_bounded_regular_file(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let file = open_regular_file(path)?;
    if file.metadata()?.len() > maximum as u64 {
        return Err(too_large());
    }
    read_bounded(file, maximum)
}

#[cfg(test)]
mod tests;
