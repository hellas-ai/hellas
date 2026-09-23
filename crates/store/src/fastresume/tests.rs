use super::*;

fn test_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("store crate lives below the workspace root")
        .join("target/fastresume-tests")
        .join(format!("{name}-{}.bin", std::process::id()))
}

fn one_record(marker: u8) -> Records {
    let hash = XetHash::from_bytes([marker; 32]);
    Records {
        entries: Mutex::new(HashMap::from([(
            FileIdentity {
                dev: u64::from(marker),
                ino: u64::from(marker) + 1,
                size: u64::from(marker) + 2,
                mtime_ns: i128::from(marker) + 3,
                ctime_ns: i128::from(marker) + 4,
            },
            Indexed {
                id: hash,
                chunks: vec![Chunk::new(hash, u64::from(marker) + 5)],
                len: u64::from(marker) + 5,
            },
        )])),
    }
}

#[test]
fn debris_is_recognised_and_real_files_are_not() {
    assert!(is_cache_debris(Path::new("/c/blobs/abc.lock")));
    assert!(is_cache_debris(Path::new("/c/download/x.abc.incomplete")));
    assert!(is_cache_debris(Path::new("/c/.no_exist/sha/config.json")));
    assert!(!is_cache_debris(Path::new("/c/blobs/abcdef")));
    assert!(!is_cache_debris(Path::new(
        "/c/snapshots/sha/model.safetensors"
    )));
}

#[test]
fn oversized_persisted_index_is_rejected_without_reading_its_body() {
    let path = test_path("oversized-index");
    std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
    let file = std::fs::File::create(&path).expect("create sparse oversized index");
    file.set_len(
        u64::try_from(MAX_FASTRESUME_INDEX_BYTES)
            .unwrap()
            .saturating_add(1),
    )
    .expect("size sparse oversized index");

    assert_eq!(Records::default().load(&path), 0);
    std::fs::remove_file(path).expect("remove oversized fixture");
}

#[cfg(unix)]
#[test]
fn special_file_index_is_rejected_without_blocking() {
    let path = test_path("fifo-index");
    std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "the fixture needs a FIFO");

    let (sender, receiver) = std::sync::mpsc::channel();
    let thread_path = path.clone();
    std::thread::spawn(move || {
        let _ = sender.send(Records::default().load(&thread_path));
    });
    assert_eq!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("fastresume load blocked while opening a FIFO"),
        0
    );
    std::fs::remove_file(path).expect("remove FIFO fixture");
}

#[test]
fn excessive_record_count_is_rejected_before_allocation() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(
        &u64::try_from(MAX_FASTRESUME_RECORDS)
            .unwrap()
            .saturating_add(1)
            .to_le_bytes(),
    );

    assert!(parse(&bytes).is_none());
}

#[cfg(unix)]
#[test]
fn save_does_not_follow_the_legacy_fixed_temporary_symlink() {
    use std::os::unix::fs::symlink;

    let path = test_path("legacy-temporary-symlink");
    let parent = path.parent().expect("fixture parent");
    std::fs::create_dir_all(parent).expect("create fixture parent");
    let victim = parent.join(format!("fastresume-victim-{}", std::process::id()));
    let legacy_temporary = path.with_extension("fastresume.tmp");
    std::fs::write(&victim, b"operator data").expect("create victim");
    symlink(&victim, &legacy_temporary).expect("plant legacy temporary symlink");

    assert_eq!(one_record(1).save(&path).expect("save fastresume"), 1);
    assert_eq!(
        std::fs::read(&victim).expect("read victim"),
        b"operator data"
    );
    assert!(
        std::fs::symlink_metadata(&legacy_temporary)
            .expect("legacy temporary remains")
            .file_type()
            .is_symlink()
    );
    assert_eq!(Records::default().load(&path), 1);

    std::fs::remove_file(path).expect("remove index");
    std::fs::remove_file(legacy_temporary).expect("remove legacy temporary");
    std::fs::remove_file(victim).expect("remove victim");
}

#[test]
fn concurrent_saves_publish_only_complete_parseable_indexes() {
    let path = test_path("concurrent-publication");
    let parent = path.parent().expect("fixture parent");
    std::fs::create_dir_all(parent).expect("create fixture parent");
    one_record(1).save(&path).expect("seed complete index");

    let publishers = 12;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(publishers + 1));
    let mut threads = Vec::new();
    for marker in 2..=u8::try_from(publishers + 1).unwrap() {
        let path = path.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            one_record(marker).save(&path)
        }));
    }
    barrier.wait();
    for thread in threads {
        assert_eq!(thread.join().expect("publisher thread").expect("save"), 1);
        let bytes = std::fs::read(&path).expect("read published index");
        assert_eq!(parse(&bytes).expect("published index parses").len(), 1);
    }
    assert_eq!(Records::default().load(&path), 1);

    let final_name = path.file_name().expect("final file name").to_string_lossy();
    let temporary_prefix = format!(".{final_name}.");
    assert!(
        std::fs::read_dir(parent)
            .expect("read fixture parent")
            .filter_map(Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.starts_with(&temporary_prefix) || !name.ends_with(".fastresume.tmp")
            }),
        "successful publication must clean every unique temporary"
    );
    std::fs::remove_file(path).expect("remove index");
}

#[cfg(unix)]
#[test]
fn save_durably_creates_a_private_parent() {
    use std::os::unix::fs::PermissionsExt as _;

    let existing_parent = test_path("missing-parent").with_extension(format!(
        "{}-dir",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(existing_parent.parent().expect("fixture root"))
        .expect("create fixture root");
    std::fs::create_dir(&existing_parent).expect("create existing parent");
    std::fs::set_permissions(&existing_parent, std::fs::Permissions::from_mode(0o755))
        .expect("make existing parent permissive");
    let missing_parent = existing_parent.join("new").join("state");
    let path = missing_parent.join("content-index.bin");

    assert_eq!(one_record(1).save(&path).expect("save index"), 1);

    assert!(path.is_file());
    assert_eq!(
        std::fs::metadata(&missing_parent)
            .expect("leaf parent metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(existing_parent.join("new"))
            .expect("intermediate parent metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&existing_parent)
            .expect("existing parent metadata")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    std::fs::remove_file(path).expect("remove index");
    std::fs::remove_dir(missing_parent).expect("remove parent");
    std::fs::remove_dir(existing_parent.join("new")).expect("remove intermediate parent");
    std::fs::remove_dir(existing_parent).expect("remove existing parent");
}

#[test]
fn save_rejects_parent_components_before_creating_directories() {
    let existing_parent = test_path("parent-component").with_extension(format!(
        "{}-dir",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(existing_parent.parent().expect("fixture root"))
        .expect("create fixture root");
    std::fs::create_dir(&existing_parent).expect("create existing parent");
    let unrelated = existing_parent.join("must-not-be-created");
    let path = unrelated.join("..").join("content-index.bin");

    let error = one_record(1)
        .save(&path)
        .expect_err("parent components must be refused before mutation");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(!unrelated.exists());
    assert!(!existing_parent.join("content-index.bin").exists());
    std::fs::remove_dir(existing_parent).expect("remove existing parent");
}
