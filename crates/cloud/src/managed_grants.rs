//! Bootstrap authority and anchor the private journal to the persistent identity.
use hellas_rpc::protocol::work_grant::{grant_network, records::Principal};
use hellas_work::work_store::{grant::GrantStore, journal::journal_name_parts};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, ManagedGrantError>;

#[derive(Debug, thiserror::Error)]
pub enum ManagedGrantError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Store(#[from] hellas_work::work_store::grant::GrantStoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Wire(#[from] hellas_wire::WireStatus),
    #[error("grant journal binding changed; refusing startup")]
    BindingChanged,
    #[error("owner enrollment changed; refusing startup")]
    OwnerChanged,
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
    #[error("provider status missing")]
    ProviderMissing,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Anchor {
    provider: String,
    journal: PathBuf,
}

pub(crate) fn prepare(
    data: &Path,
    private: &Path,
    provider: Principal,
    owner: Option<&Principal>,
) -> Result<(Option<PathBuf>, PathBuf)> {
    // A separate private container filesystem may disappear while the mounted
    // identity survives. Never interpret that loss as a fresh allowance.
    let anchor = Anchor {
        provider: provider.id().0.to_string(),
        journal: private.join("grants"),
    };
    let anchor_path = data.join("grant-journal.json");
    if anchor_path.exists() {
        let saved: Anchor = crate::config::read_json(&anchor_path)?;
        if saved != anchor {
            return Err(ManagedGrantError::BindingChanged);
        }
        let entries = std::fs::read_dir(&anchor.journal).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                ManagedGrantError::MissingJournal
            } else {
                ManagedGrantError::Io(source)
            }
        })?;
        let mut found = false;
        for entry in entries {
            let entry = entry?;
            found |= entry
                .file_name()
                .to_str()
                .and_then(journal_name_parts)
                .is_some_and(|(stem, _)| stem == "grants");
        }
        if !found {
            return Err(ManagedGrantError::MissingJournal);
        }
    }
    let owner_binding = data.join("owner-enrollment.json");
    if owner_binding.exists() {
        let saved: Option<Principal> = crate::config::read_json(&owner_binding)?;
        if saved.as_ref() != owner {
            return Err(ManagedGrantError::OwnerChanged);
        }
    } else {
        crate::config::save_private(&owner_binding, &owner, true)?;
    }
    // Establish a durable journal before the anchor or the worker exists. Open
    // also validates/replays it and conservatively settles interrupted jobs.
    drop(GrantStore::open(
        &anchor.journal,
        grant_network(),
        provider.bundle().clone(),
        hellas_work::grant_service::wall_clock(),
    )?);
    if !anchor_path.exists() {
        crate::config::save_private(&anchor_path, &anchor, true)?;
    }
    let owner_path = owner
        .map(|p| {
            let path = private.join("owner.enrollment");
            hellas_private::write_atomically(&path, ".enrollment", &p.bundle().canonical_bytes())?;
            Ok::<_, ManagedGrantError>(path)
        })
        .transpose()?;
    let grant_config = private.join("bootstrap-grants.json");
    crate::config::save_private(
        &grant_config,
        &serde_json::json!({
            "journal_root": anchor.journal,
            "control_socket": private.join("control.sock"),
            "machine_limits": null,
            "max_in_flight": 256,
            "max_job_millis": 1_800_000,
            "resources": [],
        }),
        false,
    )?;
    Ok((owner_path, grant_config))
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

/// An actual HostControl response confirms resource validation and journal open
/// completed. This socket is owner-only and never exposed by the cloud protocol.
pub(crate) async fn ready(socket: &Path) -> Result<()> {
    let transport = hellas_wire::local::connect(socket).await?;
    let status = hellas_rpc::services::host_control::HostControlClientImpl::new(transport)
        .get_host_status(hellas_rpc::pb::host::GetHostStatusRequest {})
        .await?;
    if status
        .provider
        .ok_or(ManagedGrantError::ProviderMissing)?
        .state
        != hellas_rpc::pb::host::RuntimeState::Running as i32
    {
        return Err(ManagedGrantError::NotReady);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn principal() -> Principal {
        Principal::verify(crate::test_support::bundle(&iroh::SecretKey::generate())).unwrap()
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
    #[test]
    fn restart_pins_authority_and_missing_or_moved_journal_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let private = root.path().join("private");
        crate::management::private_directory(&data).unwrap();
        crate::management::private_directory(&private).unwrap();
        let provider = principal();
        let owner = principal();
        prepare(&data, &private, provider.clone(), Some(&owner)).unwrap();
        prepare(&data, &private, provider.clone(), Some(&owner)).unwrap();
        assert!(prepare(&data, &private, provider.clone(), Some(&principal())).is_err());
        assert!(prepare(&data, &private, provider.clone(), None).is_err());
        assert!(prepare(&data, &private, principal(), Some(&owner)).is_err());
        let moved = root.path().join("moved");
        std::fs::rename(&private, &moved).unwrap();
        assert!(prepare(&data, &moved, provider.clone(), Some(&owner)).is_err());
        crate::management::private_directory(&private).unwrap();
        let error = prepare(&data, &private, provider, Some(&owner)).unwrap_err();
        assert!(error.to_string().contains("grant journal missing"));
        assert!(!private.join("grants").exists());
    }
}
