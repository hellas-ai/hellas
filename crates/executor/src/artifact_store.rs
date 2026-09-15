use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use commonware_runtime::Blob as _;

use crate::ExecutorError;

/// The number of distinct successful retained Evaluate executions a provider
/// keeps.  The limit is deliberately on executions, not canonical blobs:
/// each retained execution owns one durable reservation before it can publish
/// its graph, so deduplication cannot make the capacity accounting ambiguous.
pub const DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY: usize = 1024;

const CAPACITY_METADATA_NAME: &str = ".hellas-evaluate-retained-execution-capacity";
const MAX_CAPACITY_METADATA_BYTES: usize = 32;

type StorageResult<T> = Result<T, String>;

#[derive(Clone)]
pub struct ArtifactStoreConfig {
    storage: Option<Arc<dyn ArtifactStorage>>,
    retained_execution_capacity: usize,
    root: Option<Arc<ArtifactStoreRoot>>,
}

impl ArtifactStoreConfig {
    pub fn new<S: commonware_runtime::Storage>(storage: S) -> Self {
        Self {
            storage: Some(Arc::new(CommonwareStorage(storage))),
            retained_execution_capacity: DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY,
            root: None,
        }
    }

    pub fn memory() -> Self {
        Self {
            storage: None,
            retained_execution_capacity: DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY,
            root: None,
        }
    }

    pub fn with_retained_execution_capacity(mut self, capacity: usize) -> Self {
        self.retained_execution_capacity = capacity;
        self
    }

    /// Bind Evaluate storage to a provider artifact root held by one
    /// cooperating runtime.
    ///
    /// The caller acquires this before opening either its content index or the
    /// Commonware child directory, because Commonware itself leaves concurrent
    /// opens undefined. The descriptor lock is advisory and assumes the path's
    /// ancestors remain stable and trusted; it does not exclude malicious code
    /// running as the same user. The descriptor is carried into the artifact
    /// store and released only when that runtime is dropped.
    pub fn lock_root(
        root: impl Into<PathBuf>,
        retained_execution_capacity: usize,
    ) -> Result<ArtifactStoreRoot, ExecutorError> {
        let root = root.into();
        crate::private_fs::run_blocking_io(move || {
            ArtifactStoreRoot::open(root, retained_execution_capacity)
        })
        .map_err(root_error)?
    }

    pub fn with_locked_root(mut self, root: ArtifactStoreRoot) -> Self {
        self.retained_execution_capacity = root.retained_execution_capacity;
        self.root = Some(Arc::new(root));
        self
    }

    pub(crate) fn storage(&self) -> Option<Arc<dyn ArtifactStorage>> {
        self.storage.clone()
    }

    pub(crate) const fn retained_execution_capacity(&self) -> usize {
        self.retained_execution_capacity
    }

    pub(crate) fn root(&self) -> Option<Arc<ArtifactStoreRoot>> {
        self.root.clone()
    }
}

/// A live claim on one provider artifact root used by Evaluate.
///
/// The opened root directory is intentionally retained, rather than locking a
/// replaceable child name only around setup. Advisory locks disappear when the
/// descriptor is dropped, so it coordinates cooperating providers resolving
/// the same inode for exactly this runtime's lifetime. The root and its trusted
/// ancestors must not be renamed or replaced while path-based child access is
/// active.
#[derive(Debug)]
pub struct ArtifactStoreRoot {
    _root_directory: File,
    retained_execution_capacity: usize,
}

impl ArtifactStoreRoot {
    fn open(root: PathBuf, retained_execution_capacity: usize) -> Result<Self, ExecutorError> {
        crate::private_fs::create_private_dir_all(&root).map_err(root_error)?;
        let root_directory = crate::private_fs::open_directory(&root).map_err(root_error)?;
        match root_directory.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(ExecutorError::ArtifactStore(format!(
                    "Evaluate artifact store at {} is already open by another process",
                    root.display()
                )));
            }
            Err(TryLockError::Error(error)) => return Err(root_error(error)),
        }
        crate::private_fs::make_directory_private(&root_directory).map_err(root_error)?;

        let metadata_path = root.join(CAPACITY_METADATA_NAME);
        let expected = format!("{retained_execution_capacity}\n");
        let bytes = match crate::private_fs::read_bounded_regular_file(
            &metadata_path,
            MAX_CAPACITY_METADATA_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                publish_capacity_metadata(
                    &root,
                    &root_directory,
                    &metadata_path,
                    expected.as_bytes(),
                )?;
                expected.into_bytes()
            }
            Err(error) => return Err(root_error(error)),
        };
        let persisted = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|value| value.strip_suffix('\n'))
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                ExecutorError::ArtifactStore(format!(
                    "invalid retained Evaluate capacity metadata at {}",
                    metadata_path.display()
                ))
            })?;
        if persisted != retained_execution_capacity {
            return Err(ExecutorError::ArtifactStore(format!(
                "Evaluate artifact store at {} has retained execution capacity {persisted}, not configured {retained_execution_capacity}; stop every process sharing the root before changing it",
                root.display()
            )));
        }
        Ok(Self {
            _root_directory: root_directory,
            retained_execution_capacity,
        })
    }
}

/// Publishes the first capacity record whole or not at all. Creating the final
/// name in place can leave an empty-but-existing record after power loss,
/// permanently failing subsequent startup. A synced sibling followed by rename
/// and directory sync leaves only the two recoverable states: absent or whole.
fn publish_capacity_metadata(
    root: &std::path::Path,
    root_directory: &File,
    metadata_path: &std::path::Path,
    bytes: &[u8],
) -> Result<(), ExecutorError> {
    let temporary = root.join(format!(
        ".{CAPACITY_METADATA_NAME}.{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| {
        let mut metadata = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(root_error)?;
        metadata.write_all(bytes).map_err(root_error)?;
        metadata.sync_all().map_err(root_error)?;
        drop(metadata);
        fs::rename(&temporary, metadata_path).map_err(root_error)?;
        #[cfg(unix)]
        root_directory.sync_all().map_err(root_error)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn root_error(error: std::io::Error) -> ExecutorError {
    ExecutorError::ArtifactStore(format!("Evaluate artifact store root: {error}"))
}

#[async_trait]
pub(crate) trait ArtifactStorage: Send + Sync {
    async fn scan(&self, partition: &'static str) -> StorageResult<Vec<Vec<u8>>>;
    async fn read(&self, partition: &'static str, name: Vec<u8>) -> StorageResult<Vec<u8>>;
    async fn write_once(
        &self,
        partition: &'static str,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> StorageResult<Option<Vec<u8>>>;
    async fn replace(
        &self,
        partition: &'static str,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> StorageResult<()>;
}

struct CommonwareStorage<S>(S);

#[async_trait]
impl<S: commonware_runtime::Storage> ArtifactStorage for CommonwareStorage<S> {
    async fn scan(&self, partition: &'static str) -> StorageResult<Vec<Vec<u8>>> {
        match self.0.scan(partition).await {
            Ok(names) => Ok(names),
            Err(commonware_runtime::Error::PartitionMissing(_)) => Ok(Vec::new()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn read(&self, partition: &'static str, name: Vec<u8>) -> StorageResult<Vec<u8>> {
        let (blob, size) = self
            .0
            .open(partition, &name)
            .await
            .map_err(|err| err.to_string())?;
        let len = usize::try_from(size).map_err(|_| format!("blob is too large: {size}"))?;
        let bytes = blob
            .read_at(0, len)
            .await
            .map_err(|err| err.to_string())?
            .coalesce();
        Ok(bytes.as_ref().to_vec())
    }

    async fn write_once(
        &self,
        partition: &'static str,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> StorageResult<Option<Vec<u8>>> {
        let (blob, size) = self
            .0
            .open(partition, &name)
            .await
            .map_err(|err| err.to_string())?;
        if size != 0 {
            let len = usize::try_from(size).map_err(|_| format!("blob is too large: {size}"))?;
            let bytes = blob
                .read_at(0, len)
                .await
                .map_err(|err| err.to_string())?
                .coalesce();
            return Ok(Some(bytes.as_ref().to_vec()));
        }
        blob.write_at_sync(0, value)
            .await
            .map_err(|err| err.to_string())?;
        Ok(None)
    }

    async fn replace(
        &self,
        partition: &'static str,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> StorageResult<()> {
        let (blob, _) = self
            .0
            .open(partition, &name)
            .await
            .map_err(|err| err.to_string())?;
        blob.resize(0).await.map_err(|err| err.to_string())?;
        blob.write_at(0, value)
            .await
            .map_err(|err| err.to_string())?;
        blob.sync().await.map_err(|err| err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{ArtifactStoreConfig, CAPACITY_METADATA_NAME};
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    fn test_root() -> std::path::PathBuf {
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("artifact-store-lock-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn root_capacity_metadata_rejects_a_different_configuration() {
        let root = test_root();
        let first = ArtifactStoreConfig::lock_root(&root, 1).unwrap();
        assert_eq!(
            std::fs::read(root.join(CAPACITY_METADATA_NAME)).unwrap(),
            b"1\n"
        );
        assert!(!root.join(".hellas-evaluate-artifacts.lock").exists());
        assert!(
            std::fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp")),
            "capacity publication must leave no live temporary alongside it"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        drop(first);

        let error = ArtifactStoreConfig::lock_root(&root, 2).unwrap_err();
        assert!(
            matches!(
                &error,
                crate::ExecutorError::ArtifactStore(message)
                    if message.contains("retained execution capacity 1")
                        && message.contains("not configured 2")
            ),
            "unexpected root capacity reconfiguration error: {error}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn root_capacity_metadata_rejects_a_fifo_without_blocking() {
        let root = test_root();
        std::fs::create_dir_all(&root).unwrap();
        let metadata = root.join(CAPACITY_METADATA_NAME);
        let status = Command::new("mkfifo").arg(&metadata).status().unwrap();
        assert!(status.success(), "the fixture needs a FIFO");

        let (sender, receiver) = std::sync::mpsc::channel();
        let thread_root = root.clone();
        std::thread::spawn(move || {
            let _ = sender.send(ArtifactStoreConfig::lock_root(thread_root, 1));
        });
        let error = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("Evaluate capacity metadata open blocked on a FIFO")
            .expect_err("capacity metadata must be a regular file");
        assert!(error.to_string().contains("not a regular file"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn root_lock_is_exclusive_across_processes() {
        let root = test_root();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "artifact_store::tests::hold_root_lock",
                "--ignored",
                "--nocapture",
            ])
            .env("HELLAS_ARTIFACT_STORE_LOCK_TEST_ROOT", &root)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "lock holder exited"
            );
            if line == "locked\n" {
                break;
            }
        }

        // The old implementation locked this child. Replacing it admitted a
        // second process on a fresh inode; a directory-inode lock ignores the
        // child entirely and remains exclusive.
        let obsolete_child = root.join(".hellas-evaluate-artifacts.lock");
        match std::fs::remove_file(&obsolete_child) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove obsolete child: {error}"),
        }
        std::fs::write(&obsolete_child, b"replacement").unwrap();

        let error = ArtifactStoreConfig::lock_root(&root, 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("already open by another process")
        );
        child.kill().unwrap();
        child.wait().unwrap();
        let reopened = ArtifactStoreConfig::lock_root(&root, 1)
            .expect("the released artifact root can be reopened");
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "started by root_lock_is_exclusive_across_processes"]
    fn hold_root_lock() {
        let root = std::env::var_os("HELLAS_ARTIFACT_STORE_LOCK_TEST_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap();
        let _root = ArtifactStoreConfig::lock_root(root, 1).unwrap();
        println!("locked");
        std::thread::sleep(Duration::from_secs(30));
    }
}
