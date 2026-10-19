//! Anchor an explicitly initialized private journal to the persistent identity.
use hellas_rpc::ProviderEnrollmentBundle;
use hellas_work::model::grant::grant_network;
use hellas_work::work_store::{grant::NodeStore, journal::Journal};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, ManagedGrantError>;

#[derive(Debug, thiserror::Error)]
pub enum ManagedGrantError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Store(#[from] hellas_work::work_store::grant::NodeStoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("grant journal binding changed; refusing startup")]
    BindingChanged,
    #[error("managed control path is not an owned socket")]
    SocketOwned,
    #[error("control socket changed during recovery")]
    SocketChanged,
    #[error("grant provider is not ready")]
    NotReady,
    #[error("grant journal missing; restore it or provision a new machine identity")]
    MissingJournal,
    #[error("managed control socket is already serving")]
    SocketBusy,
    #[error("socket parent missing")]
    SocketParent,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Anchor {
    provider: String,
    journal: PathBuf,
}

pub(crate) async fn prepare(
    data: &Path,
    private: &Path,
    provider: ProviderEnrollmentBundle,
) -> Result<PathBuf> {
    // A separate private container filesystem may disappear while the mounted
    // identity survives. Never interpret that loss as a fresh allowance.
    let anchor = Anchor {
        provider: provider.content_id().to_string(),
        journal: private.join("grants"),
    };
    let anchor_path = data.join("grant-journal.json");
    if anchor_path.exists() {
        let saved: Anchor = crate::config::read_json(&anchor_path)?;
        if saved != anchor {
            return Err(ManagedGrantError::BindingChanged);
        }
        let stems = Journal::stems(&anchor.journal)
            .map_err(hellas_work::work_store::grant::NodeStoreError::from)?;
        if !stems.iter().any(|stem| stem == "grants") {
            return Err(ManagedGrantError::MissingJournal);
        }
    }
    // Validate/replay initialized authority before starting the worker, and
    // conservatively settle interrupted jobs. Open never bootstraps authority.
    drop(
        NodeStore::open(
            &anchor.journal,
            grant_network(),
            Some(provider.clone()),
            hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
        )
        .await?,
    );
    if !anchor_path.exists() {
        crate::config::save_private(&anchor_path, &anchor, true)?;
    }
    let grant_config = private.join("default-resources.json");
    crate::config::save_private(
        &grant_config,
        &serde_json::json!({
            "journal_root": anchor.journal,
            "control_socket": private.join("control.sock"),
            "control_certificate": private.join("control.cert.der"),
            "control_private_key": private.join("control.key.der"),
            "max_job_millis": 1_800_000,
            "resources": [],
        }),
        false,
    )?;
    Ok(grant_config)
}

/// The agent holds the machine lease and has reaped its previous worker. A
/// forced stop may leave this socket; never replace a live listener or other file.
pub(crate) fn reclaim_socket(path: &Path) -> Result<()> {
    use std::os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    };
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !(metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() }) {
        return Err(ManagedGrantError::SocketOwned);
    }
    match UnixStream::connect(path) {
        Ok(_) => return Err(ManagedGrantError::SocketBusy),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(error) => return Err(error.into()),
    }
    let current = std::fs::symlink_metadata(path)?;
    if !(metadata.dev() == current.dev() && metadata.ino() == current.ino()) {
        return Err(ManagedGrantError::SocketChanged);
    }
    std::fs::remove_file(path)?;
    hellas_private::sync_directory(path.parent().ok_or(ManagedGrantError::SocketParent)?)?;
    Ok(())
}

/// Readiness uses the same explicit application profile and checked CLI path as
/// other callers. Socket ownership alone cannot read private node status.
pub(crate) async fn ready(cli: &Path, identity: &Path, directory: &Path) -> Result<()> {
    let status = tokio::process::Command::new(cli)
        .arg("--identity")
        .arg(identity)
        .arg("admin")
        .arg("--profile")
        .arg(directory.join("control-profile.json"))
        .arg("--control-socket")
        .arg(directory.join("control.sock"))
        .arg("status")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .status()
        .await?;
    if !status.success() {
        return Err(ManagedGrantError::NotReady);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn enrollment() -> ProviderEnrollmentBundle {
        hellas_work::test_support::software_enrollment(
            7,
            *iroh::SecretKey::generate().public().as_bytes(),
        )
    }
    #[test]
    fn socket_recovery_preserves_live_listeners_and_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("s");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert!(reclaim_socket(&socket).is_err());
        assert!(socket.exists());
        drop(listener);
        // Parallel subprocess tests may briefly inherit a CLOEXEC descriptor
        // between fork and exec. Refusing it while still live is correct.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while reclaim_socket(&socket).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "listener did not close"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!socket.exists());
        std::fs::write(&socket, b"keep").unwrap();
        assert!(reclaim_socket(&socket).is_err());
        assert_eq!(std::fs::read(&socket).unwrap(), b"keep");
    }
    #[tokio::test]
    async fn restart_pins_authority_and_missing_or_moved_journal_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let private = root.path().join("private");
        crate::management::private_directory(&data).unwrap();
        crate::management::private_directory(&private).unwrap();
        let provider = enrollment();
        assert!(matches!(
            prepare(&data, &private, provider.clone()).await,
            Err(ManagedGrantError::Store(
                hellas_work::work_store::grant::NodeStoreError::Uninitialized
            ))
        ));
        drop(
            crate::test_node::bootstrap_node(
                &private.join("grants"),
                grant_network(),
                Some(provider.clone()),
                hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
            )
            .await
            .unwrap(),
        );
        prepare(&data, &private, provider.clone()).await.unwrap();
        prepare(&data, &private, provider.clone()).await.unwrap();
        assert!(prepare(&data, &private, enrollment()).await.is_err());
        let moved = root.path().join("moved");
        std::fs::rename(&private, &moved).unwrap();
        assert!(prepare(&data, &moved, provider.clone()).await.is_err());
        crate::management::private_directory(&private).unwrap();
        let error = prepare(&data, &private, provider).await.unwrap_err();
        assert!(error.to_string().contains("grant journal missing"));
        assert!(!private.join("grants").exists());
    }
}
