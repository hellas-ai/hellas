use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

pub(super) fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

pub(super) fn open_nofollow_rw(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

pub(super) fn is_private(file: &File) -> io::Result<bool> {
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    Ok(metadata.permissions().mode() & 0o077 == 0 && metadata.uid() == euid)
}

pub(super) fn create_private_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

pub(super) fn restrict_directory(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Non-blocking, so a FIFO swapped in under the name cannot hang the open.
pub(super) fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
        .open(path)
}

pub(super) fn create_dir_all(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

/// Opens the directory itself without following its final symlink and requires
/// ownership by this user. Callers choose whether to restrict or reject its mode.
pub fn open_owned_directory(path: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if directory.metadata()?.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory belongs to another user",
        ));
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    #[test]
    fn owned_directory_refuses_symlinks_and_non_directories() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(root.path(), &link).unwrap();
        let file = root.path().join("file");
        std::fs::write(&file, b"data").unwrap();
        assert!(super::open_owned_directory(root.path()).is_ok());
        assert!(super::open_owned_directory(&link).is_err());
        assert!(super::open_owned_directory(&file).is_err());
    }
}
