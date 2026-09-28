use std::{fs::OpenOptions, io, path::Path};

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

/// Read a regular file with a one-byte sentinel so concurrent growth cannot
/// turn a bounded configuration read into an unbounded allocation.
pub fn read_bounded_regular_file(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    use io::Read as _;
    let file = open_regular_file(path)?;
    if file.metadata()?.len() > maximum as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds byte limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds byte limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
