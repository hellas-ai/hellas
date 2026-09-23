use super::*;
use std::io::Read as _;

#[test]
fn a_private_tempfile_is_private_and_removed_on_drop() {
    let directory = tempfile::tempdir().unwrap();
    let mut temporary = private_tempfile(directory.path(), ".x.", ".tmp").unwrap();
    temporary.write_all(b"secret").unwrap();
    let path = temporary.path().to_path_buf();
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with(".x.") && name.ends_with(".tmp"));
    let mut opened = open_nofollow(&path).unwrap();
    assert!(is_private(&opened).unwrap());
    let mut text = String::new();
    opened.read_to_string(&mut text).unwrap();
    assert_eq!(text, "secret");
    drop(opened);
    drop(temporary);
    assert!(!path.exists());
}

#[test]
fn write_atomically_replaces_privately_and_leaves_no_temporaries() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("record");
    std::fs::write(&path, b"old").unwrap();
    write_atomically(&path, ".record.tmp", b"new").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    assert!(is_private(&open_nofollow(&path).unwrap()).unwrap());
    let names: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("record")]);
}

#[test]
fn a_failed_publication_removes_its_temporary() {
    let directory = tempfile::tempdir().unwrap();
    // A directory in the way makes the final rename fail.
    let path = directory.path().join("occupied");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("inside"), b"x").unwrap();
    assert!(write_atomically(&path, ".tmp", b"new").is_err());
    let names: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("occupied")]);
}

#[test]
fn open_directory_refuses_a_file() {
    let directory = tempfile::tempdir().unwrap();
    assert!(open_directory(directory.path()).is_ok());
    let file = directory.path().join("file");
    std::fs::write(&file, b"x").unwrap();
    assert!(open_directory(&file).is_err());
    sync_directory(directory.path()).unwrap();
}

#[test]
fn files_created_in_a_restricted_directory_are_private() {
    let directory = tempfile::tempdir().unwrap();
    restrict_directory(directory.path()).unwrap();
    let path = directory.path().join("inherited");
    std::fs::write(&path, b"x").unwrap();
    #[cfg(unix)]
    {
        // Unix modes do not inherit; the directory itself is what is private.
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(directory.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
    #[cfg(windows)]
    assert!(is_private(&open_nofollow(&path).unwrap()).unwrap());
}

#[cfg(unix)]
#[test]
fn a_symlink_is_not_followed() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    std::fs::write(&target, b"x").unwrap();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(open_nofollow(&link).is_err());
}

#[cfg(unix)]
#[test]
fn a_group_readable_file_is_not_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("shared");
    std::fs::write(&path, b"x").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(!is_private(&open_nofollow(&path).unwrap()).unwrap());
}

#[cfg(windows)]
#[test]
fn this_process_runs_as_the_current_user() {
    assert!(windows::process_is_current_user(std::process::id()).unwrap());
}
