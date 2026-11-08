//! Explicit indexing refuses special files before any blocking read.
use std::path::Path;

/// Bound for a hung wait, not a performance requirement: CI runs many suites at
/// once on shared machines, and the property never depends on how fast that is.
const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(600);

/// Explicit paths may follow a symlink to ordinary content, but neither that
/// convenience nor the adoption walk's earlier `file_type` observation may
/// turn a FIFO or device into a blocking content read.
#[cfg(unix)]
#[test]
fn explicit_indexing_opens_only_regular_file_descriptors() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = directory.path();
    let content = b"ordinary content reached through a symlink";
    let target = fixture.join("ordinary");
    std::fs::write(&target, content).unwrap();
    let regular_link = fixture.join("regular-link");
    std::os::unix::fs::symlink(&target, &regular_link).expect("regular symlink");
    let records = hellas_store::fastresume::Records::default();
    let ram = hellas_store::content::Reservations::ram(1 << 20);
    let indexed = records
        .index_file(&regular_link, &ram, false)
        .expect("an explicit symlink to a regular file remains supported");
    assert_eq!(indexed.id, hellas_xet::XetHash::hash(content));

    let fifo = fixture.join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "the fixture needs a fifo");
    let fifo_link = fixture.join("fifo-link");
    std::os::unix::fs::symlink(&fifo, &fifo_link).expect("fifo symlink");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(hellas_store::fastresume::Records::default().index_file(
            &fifo_link,
            &hellas_store::content::Reservations::ram(1 << 20),
            false,
        ));
    });
    let error = receiver
        .recv_timeout(HANG_GUARD)
        .expect("indexing blocked while opening a FIFO")
        .expect_err("a FIFO is not content");
    assert!(
        matches!(error, hellas_store::content::Error::Io(source) if source.kind() == std::io::ErrorKind::InvalidInput)
    );

    if Path::new("/dev/zero").exists() {
        let error = records
            .index_file(Path::new("/dev/zero"), &ram, false)
            .expect_err("a character device is not content");
        assert!(
            matches!(error, hellas_store::content::Error::Io(source) if source.kind() == std::io::ErrorKind::InvalidInput)
        );
    }
}
