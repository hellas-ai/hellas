use super::*;

#[test]
fn explicit_files_roundtrip_overwrite_delete_and_scope_names() {
    let root = tempfile::tempdir().unwrap();
    crate::restrict_directory(root.path()).unwrap();
    let store = SecretStore::headless_files(root.path().into(), "hellas-test").unwrap();
    assert!(store.get("token").unwrap().is_none());
    assert!(!store.delete("token").unwrap());
    for value in [
        b"\0\xff\x80opaque".as_slice(),
        b"replacement".as_slice(),
        b"".as_slice(),
    ] {
        store.set("token", value).unwrap();
        let reopened = SecretStore::headless_files(root.path().into(), "hellas-test").unwrap();
        assert_eq!(reopened.get("token").unwrap().unwrap().as_slice(), value);
    }
    let other = SecretStore::headless_files(root.path().into(), "other-service").unwrap();
    assert!(other.get("token").unwrap().is_none());
    for key in ["", "..", "../escape", "/absolute", "a/b", "a\\b", "a.b"] {
        assert!(store.get(key).is_err());
        assert!(store.set(key, b"private").is_err());
        assert!(store.delete(key).is_err());
    }
    assert!(SecretStore::native("../service").is_err());
    assert!(store.set("large", &vec![0; MAX_SECRET_BYTES + 1]).is_err());
    assert!(store.delete("token").unwrap());
    assert!(!store.delete("token").unwrap());
}

#[test]
fn private_files_reject_oversize_and_special_entries() {
    let root = tempfile::tempdir().unwrap();
    crate::restrict_directory(root.path()).unwrap();
    let store = SecretStore::headless_files(root.path().into(), "test").unwrap();
    store.set("key", b"private").unwrap();
    let path = root.path().join("test/key");
    assert!(crate::is_private(&crate::open_regular_file_nofollow(&path).unwrap()).unwrap());
    assert!(
        crate::imp::is_private(&crate::open_directory(&root.path().join("test")).unwrap()).unwrap()
    );
    crate::write_atomically(&path, ".test", &vec![0; MAX_SECRET_BYTES + 1]).unwrap();
    assert!(store.get("key").is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(store.get("key").is_err());
    assert!(store.set("key", b"replacement").is_err());
    assert!(store.delete("key").is_err());
}

#[cfg(unix)]
#[test]
fn files_reject_links_and_public_permissions() {
    use std::os::unix::{fs::PermissionsExt as _, fs::symlink};
    let root = tempfile::tempdir().unwrap();
    crate::restrict_directory(root.path()).unwrap();
    let store = SecretStore::headless_files(root.path().into(), "test").unwrap();
    store.set("key", b"private").unwrap();
    let path = root.path().join("test/key");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.get("key").is_err());
    assert!(store.set("key", b"replacement").is_err());
    assert!(store.delete("key").is_err());
    std::fs::remove_file(&path).unwrap();
    let target = root.path().join("outside");
    crate::write_atomically(&target, ".test", b"untouched").unwrap();
    symlink(&target, &path).unwrap();
    assert!(store.get("key").is_err());
    assert!(store.set("key", b"replacement").is_err());
    assert!(store.delete("key").is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    let linked = SecretStore::headless_files(root.path().into(), "linked").unwrap();
    symlink(root.path().join("test"), root.path().join("linked")).unwrap();
    assert!(linked.get("key").is_err());
    assert!(linked.set("key", b"replacement").is_err());
    assert!(linked.delete("key").is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn native_without_a_session_bus_refuses_without_file_fallback() {
    let root = tempfile::tempdir().unwrap();
    crate::restrict_directory(root.path()).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "secrets::tests::native_unavailable_child",
            "--ignored",
            "--nocapture",
        ])
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/missing-bus", root.path().display()),
        )
        .env("HELLAS_SECRET_UNAVAILABLE_TEST", "1")
        .env("XDG_DATA_HOME", root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "only invoked by the isolated unavailable-bus parent"]
fn native_unavailable_child() {
    assert_eq!(
        std::env::var("HELLAS_SECRET_UNAVAILABLE_TEST").unwrap(),
        "1"
    );
    let store = SecretStore::native("hellas-unavailable-test").unwrap();
    assert!(matches!(
        store.get("key"),
        Err(SecretError::Unavailable | SecretError::AccessDenied)
    ));
    assert!(store.set("key", b"PRIVATE-PAYLOAD").is_err());
    assert!(store.delete("key").is_err());
}

#[test]
#[ignore = "requires an explicitly prepared disposable native secret-store session"]
fn native_store_roundtrip() {
    let service =
        std::env::var("HELLAS_SECRET_TEST_SERVICE").expect("explicit disposable test namespace");
    assert!(service.starts_with("hellas-secret-test-"));
    let store = SecretStore::native(&service).unwrap();
    assert!(store.get("opaque").unwrap().is_none());
    for bytes in [b"\0\xff\x80opaque".as_slice(), b"replacement".as_slice()] {
        store.set("opaque", bytes).unwrap();
        assert_eq!(
            SecretStore::native(&service)
                .unwrap()
                .get("opaque")
                .unwrap()
                .unwrap()
                .as_slice(),
            bytes
        );
    }
    assert!(store.delete("opaque").unwrap());
    assert!(store.get("opaque").unwrap().is_none());
    assert!(!store.delete("opaque").unwrap());
}

#[cfg(unix)]
#[test]
fn public_roots_are_refused_and_missing_reads_create_nothing() {
    use std::os::unix::fs::PermissionsExt as _;
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("missing");
    let store = SecretStore::headless_files(root.clone(), "test").unwrap();
    assert!(store.get("key").unwrap().is_none());
    assert!(!store.delete("key").unwrap());
    assert!(!root.exists());
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(store.get("key").is_err());
    assert!(store.set("key", b"private").is_err());
    assert!(store.delete("key").is_err());
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o777
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the isolated Secret Service test bus"]
fn native_locked_store_refuses_access() {
    assert_eq!(std::env::var("HELLAS_SECRET_TEST_ISOLATED").unwrap(), "1");
    let service = std::env::var("HELLAS_SECRET_TEST_SERVICE").unwrap();
    assert!(service.starts_with("hellas-secret-test-"));
    let store = SecretStore::native(&service).unwrap();
    store.set("locked", b"PRIVATE-PAYLOAD").unwrap();
    assert_eq!(
        store.get("locked").unwrap().unwrap().as_slice(),
        b"PRIVATE-PAYLOAD"
    );
    let output = std::process::Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.secrets",
            "--object-path",
            "/org/freedesktop/secrets",
            "--method",
            "org.freedesktop.Secret.Service.Lock",
            "['/org/freedesktop/secrets/collection/login']",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("/org/freedesktop/secrets/collection/login")
    );
    let error = store.get("locked").unwrap_err();
    assert!(matches!(
        error,
        SecretError::AccessDenied | SecretError::Unavailable
    ));
    assert!(!format!("{error:?}: {error}").contains("PRIVATE-PAYLOAD"));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an explicitly prepared disposable native secret-store session"]
fn native_malformed_encoding_is_rejected() {
    use keyring_core::api::CredentialStoreApi as _;
    let service = std::env::var("HELLAS_SECRET_TEST_SERVICE").unwrap();
    assert!(service.starts_with("hellas-secret-test-"));
    let entry = dbus_secret_service_keyring_store::Store::new()
        .unwrap()
        .build(&service, "malformed", None)
        .unwrap();
    entry.set_secret(b"not!base64").unwrap();
    let result = SecretStore::native(&service).unwrap().get("malformed");
    entry.delete_credential().unwrap();
    assert_eq!(result.unwrap_err(), SecretError::InvalidData);
}
