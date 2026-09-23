use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
use std::path::Path;

/// A retained directory descriptor pins the opened inode for locking,
/// permission changes and syncing even if a child name is later unlinked and
/// recreated. It does not make later path-based child access
/// descriptor-relative: those callers still require stable, trusted
/// ancestors. Directory advisory locks coordinate cooperating processes; they
/// cannot exclude malicious code running as the same user.
pub(crate) use hellas_private::open_directory;

/// Creates and durably publishes a runtime-state directory that only its owner
/// can traverse.
///
/// `DirBuilderExt::mode` prevents a permissive umask from making a newly
/// created component group- or world-accessible. Resetting the final path's
/// permissions also narrows a pre-existing operator-supplied root. Every newly
/// created directory is synced from leaf to root, followed by the first
/// pre-existing parent, so a successful return means the complete new path can
/// survive a power loss rather than only the files later written beneath it.
pub(crate) fn create_private_dir_all(path: &Path) -> io::Result<()> {
    hellas_private::create_dir_all_durable(path)?;
    hellas_private::restrict_directory(path)?;
    // Makes the narrowing durable, and the leaf's entries when it pre-existed.
    hellas_private::sync_directory(path)
}

/// Narrows the opened directory inode itself, rather than looking its path up
/// again after the caller has acquired a lock on it.
pub(crate) fn make_directory_private(directory: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        directory.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}

/// Reads at most `maximum` bytes from an ordinary file descriptor.
///
/// The nonblocking open happens before descriptor metadata is inspected, so a
/// FIFO/device or a symlink swapped to one cannot hang startup. The extra byte
/// in the read limit also rejects a regular file which grows after `fstat`.
pub(crate) fn read_bounded_regular_file(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let maximum_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
    if metadata.len() > maximum_u64 {
        return Err(too_large(path, maximum));
    }
    let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(maximum));
    file.take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(too_large(path, maximum));
    }
    Ok(bytes)
}

fn too_large(path: &Path, maximum: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{} exceeds the {maximum}-byte limit", path.display()),
    )
}

/// Runs a complete filesystem transaction while preserving synchronous ordering.
///
/// On a multithread Tokio runtime, `block_in_place` hands off the worker before
/// running the transaction. Other tasks can progress, but branches of the same
/// `join!` or `select!` still wait. A current-thread runtime uses the blocking
/// pool and waits synchronously; its sole worker cannot progress during this
/// call. Callers outside Tokio run the transaction directly.
pub(crate) fn run_blocking_io<T, F>(operation: F) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return Ok(operation());
    };
    if matches!(
        handle.runtime_flavor(),
        tokio::runtime::RuntimeFlavor::MultiThread
    ) {
        // Do the I/O here instead of queueing another blocking job and waiting
        // for it. Nested jobs can deadlock when the blocking pool is full.
        return tokio::task::block_in_place(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
                .map_err(|_| io::Error::other("blocking filesystem operation panicked"))
        });
    }

    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let _blocking_task = tokio::task::spawn_blocking(move || {
        let _ = result_tx.send(operation());
    });
    result_rx.recv().map_err(io::Error::other)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn creation_and_reopen_leave_the_root_owner_only() {
        let parent = std::env::current_dir()
            .expect("current directory")
            .join("target/private-directory-tests")
            .join(uuid::Uuid::new_v4().to_string());
        let root = parent.join("state");

        create_private_dir_all(&root).expect("create private root");
        assert_eq!(
            fs::metadata(&root)
                .expect("root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        fs::set_permissions(&root, fs::Permissions::from_mode(0o777))
            .expect("make existing fixture permissive");
        create_private_dir_all(&root).expect("narrow existing root");
        assert_eq!(
            fs::metadata(&root)
                .expect("root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        fs::remove_dir_all(parent).expect("remove fixture");
    }

    #[test]
    fn permission_narrowing_applies_to_the_opened_directory_inode() {
        let parent = std::env::current_dir()
            .expect("current directory")
            .join("target/private-directory-tests")
            .join(uuid::Uuid::new_v4().to_string());
        let root = parent.join("state");
        let displaced = parent.join("opened-state");
        fs::create_dir_all(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777))
            .expect("make opened fixture permissive");
        let directory = open_directory(&root).expect("open fixture directory");
        fs::rename(&root, &displaced).expect("move opened directory");
        fs::create_dir(&root).expect("create replacement path");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("set replacement permissions");

        make_directory_private(&directory).expect("narrow opened inode");
        assert_eq!(
            fs::metadata(&displaced)
                .expect("opened inode metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&root)
                .expect("replacement metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "descriptor permission changes must not follow a replacement path"
        );

        fs::remove_dir_all(parent).expect("remove fixture");
    }

    #[test]
    fn directory_open_rejects_a_fifo_without_blocking() {
        let parent = std::env::current_dir()
            .expect("current directory")
            .join("target/private-directory-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&parent).expect("create fixture parent");
        let fifo = parent.join("not-a-directory");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success(), "the fixture needs a FIFO");

        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(open_directory(&fifo));
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("directory open blocked on a FIFO")
            .expect_err("a FIFO is not a directory");
        fs::remove_dir_all(parent).expect("remove fixture");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn blocking_io_releases_the_shared_runtime_worker() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let operation = tokio::spawn(async move {
            run_blocking_io(move || {
                entered_tx.send(()).expect("signal transaction started");
                resume_rx.recv_timeout(std::time::Duration::from_secs(2))
            })
        });

        entered_rx.await.expect("transaction started");
        tokio::spawn(async move {
            resume_tx.send(()).expect("resume transaction");
        })
        .await
        .expect("other task runs on the single worker");
        operation
            .await
            .expect("transaction task joins")
            .expect("blocking operation returns")
            .expect("another task progresses before the transaction finishes");
    }

    #[tokio::test]
    async fn current_thread_runtime_runs_the_filesystem_operation_off_worker() {
        let runtime_thread = std::thread::current().id();
        let operation_thread =
            run_blocking_io(|| std::thread::current().id()).expect("blocking operation returns");
        assert_ne!(operation_thread, runtime_thread);
    }

    #[test]
    fn a_blocking_pool_caller_does_not_need_another_pool_slot() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .expect("runtime");
        let result = runtime.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::task::spawn_blocking(|| run_blocking_io(|| 42_u8)),
            )
            .await
        });
        // A regression must fail the test instead of hanging runtime shutdown.
        runtime.shutdown_timeout(std::time::Duration::from_millis(100));
        let value = result
            .expect("store operation waited for an unavailable blocking slot")
            .expect("outer blocking task joins")
            .expect("store operation returns");
        assert_eq!(value, 42);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_panicking_transaction_returns_an_io_error() {
        let error = run_blocking_io(|| panic!("failed transaction"))
            .expect_err("transaction panics must not unwind the executor task");
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }
}
