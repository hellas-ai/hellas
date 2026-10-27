//! Parent-owned native build files are removed after loading or worker teardown.
use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{FileExt, OpenOptionsExt},
    },
    path::PathBuf,
    sync::OnceLock,
};

pub(crate) fn descriptor_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

pub(crate) struct Scratch {
    pub(crate) directory: File,
    _owner: tempfile::TempDir,
}
impl Scratch {
    pub(crate) fn new() -> io::Result<Self> {
        let owner = tempfile::Builder::new()
            .prefix("hellas-catena-")
            .tempdir()?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(owner.path())?;
        Ok(Self {
            directory,
            _owner: owner,
        })
    }
    pub(crate) fn clear(&self) -> io::Result<()> {
        for entry in std::fs::read_dir(descriptor_path(&self.directory))? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(entry.path())?;
            } else {
                std::fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

// Directory handoff only: the worker itself remains the child of the host.
const NAME: &std::ffi::CStr = c"hellas-catena-scratch";
impl Scratch {
    pub(crate) fn inherit(&self) -> io::Result<(File, File)> {
        let directory = File::from(copy_above_stdio(self.directory.as_raw_fd())?);
        let raw = unsafe {
            libc::memfd_create(NAME.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let original = unsafe { OwnedFd::from_raw_fd(raw) };
        let marker = File::from(copy_above_stdio(original.as_raw_fd())?);
        let mut bytes = [0u8; 12];
        bytes[..4].copy_from_slice(&std::process::id().to_ne_bytes());
        bytes[4..8]
            .copy_from_slice(&(unsafe { libc::syscall(libc::SYS_gettid) } as i32).to_ne_bytes());
        bytes[8..].copy_from_slice(&directory.as_raw_fd().to_ne_bytes());
        marker.write_all_at(&bytes, 0)?;
        if unsafe {
            libc::fcntl(
                marker.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        cloexec(directory.as_raw_fd(), false)?;
        cloexec(marker.as_raw_fd(), false)?;
        // Withdraw the marker before closing the descriptor it publishes.
        Ok((marker, directory))
    }
}

fn copy_above_stdio(fd: i32) -> io::Result<OwnedFd> {
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}
fn cloexec(fd: i32, enabled: bool) -> io::Result<()> {
    if unsafe {
        libc::fcntl(
            fd,
            libc::F_SETFD,
            if enabled { libc::FD_CLOEXEC } else { 0 },
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Runs only in the fresh, single-threaded native child before Runtime starts.
pub(crate) fn install_child() -> io::Result<()> {
    static DIRECTORY: OnceLock<File> = OnceLock::new();
    let mut selected = None;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Ok(path) = std::fs::read_link(entry.path()) else {
            continue;
        };
        if !path
            .to_string_lossy()
            .starts_with("/memfd:hellas-catena-scratch (deleted)")
        {
            continue;
        }
        let fd: i32 = entry
            .file_name()
            .to_string_lossy()
            .parse()
            .map_err(io::Error::other)?;
        let marker = unsafe { File::from_raw_fd(fd) };
        let mut bytes = [0u8; 12];
        marker.read_exact_at(&mut bytes, 0)?;
        let parent = i32::from_ne_bytes(bytes[..4].try_into().unwrap());
        let creator = i32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        let directory = i32::from_ne_bytes(bytes[8..].try_into().unwrap());
        cloexec(directory, true)?;
        if parent != unsafe { libc::getppid() } {
            continue;
        }
        let children =
            match std::fs::read_to_string(format!("/proc/{parent}/task/{creator}/children")) {
                Ok(children) => children,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
        if children
            .split_whitespace()
            .any(|pid| pid.parse::<u32>() == Ok(std::process::id()))
        {
            if selected.is_some() {
                return Err(io::Error::other("ambiguous compiler scratch"));
            }
            selected = Some(unsafe { File::from_raw_fd(directory) });
        }
    }
    if let Some(directory) = selected {
        // Compiler drivers may close their own descriptors, so name this worker's.
        let path = format!("/proc/{}/fd/{}", std::process::id(), directory.as_raw_fd());
        unsafe { std::env::set_var("TMPDIR", path) };
        DIRECTORY
            .set(directory)
            .map_err(|_| io::Error::other("compiler scratch already installed"))?;
    }
    Ok(())
}
