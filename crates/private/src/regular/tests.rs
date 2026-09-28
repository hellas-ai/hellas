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
    let mut held = reopen_regular_path_handle(&link, &path_handle).expect("reopen held inode");
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
        let _ = sender.send(open_regular_file(&fifo));
    });
    let fifo_error = receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("opening the FIFO blocked before its type check")
        .expect_err("a FIFO is not regular content");
    assert_eq!(fifo_error.kind(), io::ErrorKind::InvalidInput);

    if Path::new("/dev/null").exists() {
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
