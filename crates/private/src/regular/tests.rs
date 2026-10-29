use super::*;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// The Linux primitive is the contract, not merely an implementation
/// detail: a harmless path descriptor is acquired before type inspection,
/// and the readable descriptor remains bound to that inode even if the
/// name is replaced with a device.
#[cfg(target_os = "linux")]
#[test]
fn regular_open_is_safe_readable_seekable_and_close_on_exec() {
    use std::io::{Read as _, Seek as _, SeekFrom};
    use std::os::fd::AsRawFd as _;

    let temporary = tempfile::tempdir().unwrap();
    let dir = temporary.path();
    let target = dir.join("blob");
    let content = b"ordinary bytes";
    std::fs::write(&target, content).expect("write target");
    let link = dir.join("snapshot");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    assert!(open_regular_file_nofollow(&target).is_ok());
    assert!(open_regular_file_nofollow(&link).is_err());

    let mut file = open_regular_file(&link).expect("open regular symlink");
    let mut read = Vec::new();
    file.read_to_end(&mut read).expect("read");
    assert_eq!(read, content);
    file.seek(SeekFrom::Start(0)).expect("seek");
    read.clear();
    file.read_to_end(&mut read).expect("read again");
    assert_eq!(read, content);
    // SAFETY: F_GETFD only observes the live descriptor owned by `file`.
    let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    assert!(
        descriptor_flags >= 0,
        "F_GETFD: {}",
        io::Error::last_os_error()
    );
    assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);

    // Hold the ordinary inode without opening it for I/O, replace its
    // public name with a device, then finish the reopen. The bytes must
    // still come from the held inode.
    let path_handle = open_path_handle(&link).expect("path handle");
    // O_PATH must survive libc-specific access-mode flags (notably musl).
    // SAFETY: F_GETFL only observes the live descriptor owned by path_handle.
    let path_flags = unsafe { libc::fcntl(path_handle.as_raw_fd(), libc::F_GETFL) };
    assert!(path_flags >= 0, "F_GETFL: {}", io::Error::last_os_error());
    assert_ne!(path_flags & libc::O_PATH, 0);
    let replacement = dir.join("replacement");
    std::os::unix::fs::symlink("/dev/null", &replacement).expect("device symlink");
    std::fs::rename(&replacement, &link).expect("replace link");
    let mut held =
        reopen_regular_path_handle(&link, &path_handle, false).expect("reopen held inode");
    read.clear();
    held.read_to_end(&mut read).expect("read held inode");
    assert_eq!(read, content);

    let fifo = dir.join("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "the fixture needs a fifo");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        assert!(open_regular_file_nofollow(&fifo).is_err());
        let _ = sender.send(open_regular_file(&fifo));
    });
    let fifo_error = receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("opening the FIFO blocked before its type check")
        .expect_err("a FIFO is not regular content");
    assert_eq!(fifo_error.kind(), io::ErrorKind::InvalidInput);

    if Path::new("/dev/null").exists() {
        assert!(open_regular_file_nofollow(Path::new("/dev/null")).is_err());
        let device_error = open_regular_file(Path::new("/dev/null"))
            .expect_err("a character device is not regular content");
        assert_eq!(device_error.kind(), io::ErrorKind::InvalidInput);
    }

    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    let mut nul_path = target.as_os_str().as_bytes().to_vec();
    nul_path.extend_from_slice(b"\0ignored-suffix");
    let nul_path = PathBuf::from(std::ffi::OsString::from_vec(nul_path));
    assert_eq!(
        open_regular_file(&nul_path)
            .expect_err("NUL must not truncate the path")
            .kind(),
        io::ErrorKind::InvalidInput,
    );
}

#[test]
fn bounded_read_accepts_exact_limit_and_rejects_larger_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    std::fs::write(&path, b"1234").unwrap();
    assert_eq!(read_bounded_regular_file(&path, 4).unwrap(), b"1234");
    assert_eq!(
        read_bounded_regular_file(&path, 3).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn bounded_reader_distinguishes_overflow_from_a_decoder_failure_at_the_limit() {
    struct BadEof(io::Cursor<&'static [u8]>);
    impl io::Read for BadEof {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.0.position() == self.0.get_ref().len() as u64 {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing trailer",
                ))
            } else {
                io::Read::read(&mut self.0, output)
            }
        }
    }
    let overflow = read_bounded(b"12345".as_slice(), 4).unwrap_err();
    assert!(overflow.get_ref().unwrap().is::<ReadLimit>());
    let corrupt = read_bounded(BadEof(io::Cursor::new(b"1234")), 4).unwrap_err();
    assert_eq!(corrupt.kind(), io::ErrorKind::UnexpectedEof);
    assert!(!corrupt.get_ref().unwrap().is::<ReadLimit>());
}

#[cfg(target_os = "linux")]
#[test]
fn writable_regular_opens_preserve_content_and_inode_safety() {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("journal");
    let mut lock = crate::open_lock_beside(&journal).unwrap();
    lock.write_all(b"lock").unwrap();
    drop(lock);
    let mut reopened = crate::open_lock_beside(&journal).unwrap();
    reopened.write_all(b"L").unwrap();
    assert_eq!(
        std::fs::read(directory.path().join("journal.lock")).unwrap(),
        b"Lock"
    );
    drop(reopened);
    let path = directory.path().join("marker");
    std::fs::write(&path, b"identity").unwrap();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let mut file = open_regular_file_rw(&link).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"identity", "opening must not truncate");
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"I").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"Identity");
    file.try_lock().unwrap();
    let other = open_regular_file_nofollow_rw(&path).unwrap();
    assert!(matches!(
        other.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    assert!(open_regular_file_nofollow_rw(&link).is_err());
    drop(other);
    drop(file);
    let handle = open_path_handle(&link).unwrap();
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink("/dev/null", &link).unwrap();
    let mut pinned = reopen_regular_path_handle(&link, &handle, true).unwrap();
    pinned.write_all(b"i").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"identity");
    assert!(open_regular_file_rw(&link).is_err());
    assert!(open_regular_file_nofollow_rw(Path::new("/dev/null")).is_err());
    let fifo = directory.path().join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        assert!(open_regular_file_rw(&fifo).is_err());
        assert!(open_regular_file_nofollow_rw(&fifo).is_err());
        sent.send(()).unwrap();
    });
    received
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("special files must not block");
    let missing = directory.path().join("missing");
    assert!(open_regular_file_rw(&missing).is_err());
    assert!(!missing.exists());
}
