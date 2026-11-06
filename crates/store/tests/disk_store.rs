use futures::StreamExt;
use hellas_auth::Digest;
use hellas_rpc::ContentRef;
use hellas_store::content::*;
use std::{collections::BTreeMap, path::PathBuf};
fn name(s: &str) -> PinName {
    PinName::new(s.into()).unwrap()
}
fn path(s: &str) -> Path {
    Path::new(name(s), String::new()).unwrap()
}
fn pin(s: &str) -> PinTarget {
    PinTarget {
        name: name(s),
        policy: PinPolicy::Jobs,
    }
}
fn job() -> JobId {
    JobId {
        channel: Digest::from_bytes([1; 32]),
        id: Digest::from_bytes([2; 32]),
    }
}
async fn open(
    root: PathBuf,
    lower: Vec<PathBuf>,
    mode: IndexMode,
    capacity: Option<u64>,
) -> DiskStore {
    DiskStore::open(root, lower, mode, capacity, Reservations::ram(32 << 20))
        .await
        .unwrap()
}
async fn fill(mut session: UploadSession, bytes: &[u8]) {
    if session.complete() {
        return;
    }
    let chunks = hellas_xet::chunk(bytes);
    session.declare(&chunks, true).await.unwrap();
    let mut offset = 0;
    for chunk in chunks {
        let end = offset + chunk.data_len as usize;
        session.accept_chunk(&bytes[offset..end]).await.unwrap();
        offset = end;
    }
    assert!(session.complete());
}
async fn put(store: &DiskStore, name: &str, bytes: &[u8]) -> ContentRef {
    let object = ContentRef::for_bytes(bytes);
    fill(
        store
            .upload(&Scope::Owner, object, Some(pin(name)))
            .await
            .unwrap(),
        bytes,
    )
    .await;
    object
}
async fn bytes(store: &DiskStore, at: &Path, range: std::ops::Range<u64>) -> Vec<u8> {
    let mut stream = store.read(&Scope::Owner, at, range).await.unwrap();
    let mut out = Vec::new();
    while let Some(bytes) = stream.bytes.next().await {
        out.extend(bytes.unwrap());
    }
    out
}
async fn unpin(store: &DiskStore, key: &str) {
    let old = store
        .pins(&Scope::Owner, key, Cursor::default())
        .await
        .unwrap()
        .pins
        .into_iter()
        .find(|(n, _)| n.as_str() == key)
        .unwrap()
        .1;
    store
        .set_pin(&Scope::Owner, &name(key), Some(&old), None)
        .await
        .unwrap();
}
#[tokio::test]
async fn disk_upload_moves_outstanding_to_used_and_reopens_with_its_atomic_pin() {
    let root = tempfile::tempdir().unwrap();
    let upper = root.path().join("upper");
    let store = open(upper.clone(), vec![], IndexMode::Resume, Some(200_000)).await;
    assert!(matches!(
        store.collect(&Scope::Owner).await,
        Err(Error::Denied)
    ));
    store.finish_recovery().await.unwrap();
    let data = vec![7; 150_000];
    let object = ContentRef::for_bytes(&data);
    let mut session = store
        .upload(&Scope::Owner, object, Some(pin("data")))
        .await
        .unwrap();
    assert_eq!(store.stats().unwrap().outstanding, 150_000);
    session
        .declare(&hellas_xet::chunk(&data), true)
        .await
        .unwrap();
    let first = hellas_xet::chunk(&data)[0].data_len as usize;
    session.accept_chunk(&data[..first]).await.unwrap();
    assert_eq!(store.stats().unwrap().used, first as u64);
    assert_eq!(store.stats().unwrap().outstanding, 150_000 - first as u64);
    assert!(
        store
            .stat(&Scope::Owner, &path("data"))
            .await
            .unwrap()
            .is_none()
    );
    drop(session);
    assert_eq!(store.stats().unwrap().used, 0);
    assert_eq!(store.stats().unwrap().outstanding, 0);
    put(&store, "data", &data).await;
    store.close().await;
    drop(store);
    let store = open(upper, vec![], IndexMode::Resume, Some(200_000)).await;
    assert_eq!(
        bytes(&store, &path("data"), 120_000..140_000).await,
        data[120_000..140_000]
    );
    assert_eq!(store.stats().unwrap().used, 150_000);
    assert_eq!(store.stats().unwrap().outstanding, 0);
    store.finish_recovery().await.unwrap();
    unpin(&store, "data").await;
    assert_eq!(store.collect(&Scope::Owner).await.unwrap().bytes, 150_000);
}
#[tokio::test]
async fn normal_large_objects_never_materialize_as_tree_metadata() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path().join("upper"), vec![], IndexMode::Resume, None).await;
    store.finish_recovery().await.unwrap();
    let data = vec![19; MAX_TREE_BYTES + 1];
    let object = put(&store, "large", &data).await;
    assert!(
        store
            .upload(&Scope::Owner, object, Some(pin("second")))
            .await
            .unwrap()
            .complete()
    );
    assert_eq!(
        store
            .stat(&Scope::Owner, &path("large"))
            .await
            .unwrap()
            .unwrap()
            .target
            .object(),
        object
    );
    assert_eq!(
        bytes(&store, &path("second"), 100_000..150_000).await,
        data[100_000..150_000]
    );
    let local = LocalStore::Disk(store.clone());
    assert!(
        local
            .open_verified(
                &Scope::Owner,
                ContentRef::new(object.id(), object.bytes() + 1),
                Some(&path("large"))
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        local
            .open_verified(&Scope::Owner, object, Some(&path("large")))
            .await
            .unwrap()
            .is_some()
    );
}
#[tokio::test]
async fn lower_alternates_survive_bad_backings_and_collection_never_deletes_them() {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("a");
    let b = root.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    std::fs::write(a.join("one"), b"data").unwrap();
    std::fs::write(b.join("two"), b"data").unwrap();
    let store = open(
        root.path().join("upper"),
        vec![a.clone(), b.clone()],
        IndexMode::Resume,
        None,
    )
    .await;
    store.finish_recovery().await.unwrap();
    let object = ContentRef::for_bytes(b"data");
    store
        .set_pin(
            &Scope::Owner,
            &name("lower"),
            None,
            Some(PinValue {
                target: Target::Object(object),
                policy: PinPolicy::Jobs,
                expires: None,
            }),
        )
        .await
        .unwrap();
    std::fs::write(a.join("one"), b"evil").unwrap();
    assert_eq!(bytes(&store, &path("lower"), 0..4).await, b"data");
    store
        .rescan(vec![a.clone(), b.clone()], IndexMode::Resume)
        .await
        .unwrap();
    assert_eq!(bytes(&store, &path("lower"), 0..4).await, b"data");
    unpin(&store, "lower").await;
    assert_eq!(store.collect(&Scope::Owner).await.unwrap().bytes, 0);
    assert_eq!(std::fs::read(a.join("one")).unwrap(), b"evil");
    assert_eq!(std::fs::read(b.join("two")).unwrap(), b"data");
}
#[tokio::test]
async fn require_uses_only_explicit_records_until_reload() {
    let root = tempfile::tempdir().unwrap();
    let lower = root.path().join("lower");
    std::fs::create_dir(&lower).unwrap();
    std::fs::write(lower.join("file"), b"indexed").unwrap();
    let upper = root.path().join("upper");
    assert!(
        DiskStore::open(
            upper.clone(),
            vec![lower.clone()],
            IndexMode::Require,
            None,
            Reservations::ram(32 << 20)
        )
        .await
        .is_err()
    );
    let store = open(upper.clone(), vec![lower.clone()], IndexMode::Resume, None).await;
    store.close().await;
    drop(store);
    let store = open(upper, vec![lower.clone()], IndexMode::Require, None).await;
    store.finish_recovery().await.unwrap();
    std::fs::write(lower.join("new"), b"new").unwrap();
    assert!(store.rescan(vec![lower], IndexMode::Require).await.is_err());
}
#[tokio::test]
async fn private_completed_work_survives_reopen_and_rescan_without_becoming_public() {
    let root = tempfile::tempdir().unwrap();
    let upper = root.path().join("upper");
    let data = b"private completed bytes";
    let object = ContentRef::for_bytes(data);
    let store = open(upper.clone(), vec![], IndexMode::Resume, None).await;
    store.finish_recovery().await.unwrap();
    let tree = Tree::new(vec![("leaf".into(), Target::Object(object))]).unwrap();
    let tree_ref = put(&store, "published-root", &tree.bytes()).await;
    let old = store
        .pins(&Scope::Owner, "published-root", Cursor::default())
        .await
        .unwrap()
        .pins
        .remove(0)
        .1;
    store
        .set_pin(
            &Scope::Owner,
            &name("published-root"),
            Some(&old),
            Some(PinValue {
                target: Target::Tree(tree_ref),
                policy: PinPolicy::Public,
                expires: None,
            }),
        )
        .await
        .unwrap();
    let scope = store
        .open_work(job(), vec![object], object.bytes())
        .await
        .unwrap();
    fill(store.upload(&scope, object, None).await.unwrap(), data).await;
    store.rescan(vec![], IndexMode::Resume).await.unwrap();
    let leaf = Path::new(name("published-root"), "leaf".into()).unwrap();
    assert!(
        store
            .read(&Scope::Public, &leaf, 0..object.bytes())
            .await
            .is_err()
    );
    let other = store
        .open_work(
            JobId {
                id: Digest::from_bytes([3; 32]),
                ..job()
            },
            vec![object],
            object.bytes(),
        )
        .await
        .unwrap();
    assert!(!store.upload(&other, object, None).await.unwrap().complete());
    store.end_work(&other).await.unwrap();
    store.close().await;
    drop(store);
    let store = open(upper, vec![], IndexMode::Resume, None).await;
    let scope = store
        .open_work(job(), vec![object], object.bytes())
        .await
        .unwrap();
    assert_eq!(store.stats().unwrap().outstanding, 0);
    assert!(store.upload(&scope, object, None).await.is_err());
    store
        .promote_work(&scope, Target::Object(object), pin("accepted"))
        .await
        .unwrap();
    store.finish_recovery().await.unwrap();
    assert_eq!(
        bytes(&store, &path("accepted"), 0..object.bytes()).await,
        data
    );
    store.end_work(&scope).await.unwrap();
    assert_eq!(
        store.stats().unwrap().used,
        object.bytes() + tree_ref.bytes()
    );
}
#[tokio::test]
async fn job_memory_uses_declared_live_lower_pins_and_never_spills_its_own_bytes() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path().join("upper"), vec![], IndexMode::Resume, None).await;
    store.finish_recovery().await.unwrap();
    let held = put(&store, "held", b"weights").await;
    let own = ContentRef::for_bytes(b"ephemeral");
    let job = JobContent::new(
        &store,
        job(),
        vec![held, own],
        own.bytes(),
        BTreeMap::from([(held.id(), path("held"))]),
    )
    .await
    .unwrap();
    let before = store.stats().unwrap().used;
    fill(
        job.store().upload(job.scope(), own, None).await.unwrap(),
        b"ephemeral",
    )
    .await;
    assert_eq!(store.stats().unwrap().used, before);
    let local = LocalStore::Job(job.clone());
    assert!(matches!(
        local.open_verified(job.scope(), own, None).await.unwrap(),
        Some(VerifiedReader::Memory(_))
    ));
    assert!(matches!(
        local
            .open_verified(job.scope(), held, Some(&path("held")))
            .await
            .unwrap(),
        Some(VerifiedReader::File(_))
    ));
    unpin(&store, "held").await;
    assert!(
        local
            .open_verified(job.scope(), held, Some(&path("held")))
            .await
            .unwrap()
            .is_none()
    );
    job.end().await.unwrap();
}

#[tokio::test]
async fn corrupt_reachable_tree_aborts_collection_before_any_upper_deletion() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path().join("upper"), vec![], IndexMode::Resume, None).await;
    store.finish_recovery().await.unwrap();
    let leaf = put(&store, "leaf", b"keep me").await;
    let tree = Tree::new(vec![("leaf".into(), Target::Object(leaf))]).unwrap();
    let root_ref = put(&store, "tree", &tree.bytes()).await;
    let old = store
        .pins(&Scope::Owner, "tree", Cursor::default())
        .await
        .unwrap()
        .pins
        .remove(0)
        .1;
    store
        .set_pin(
            &Scope::Owner,
            &name("tree"),
            Some(&old),
            Some(PinValue {
                target: Target::Tree(root_ref),
                ..old.clone()
            }),
        )
        .await
        .unwrap();
    unpin(&store, "leaf").await;
    let garbage = put(&store, "garbage", b"also preserve until the tree verifies").await;
    unpin(&store, "garbage").await;
    let tree_path = root
        .path()
        .join("upper/objects")
        .join(root_ref.id().to_string());
    let mut bad = std::fs::read(&tree_path).unwrap();
    *bad.last_mut().unwrap() ^= 1;
    std::fs::write(tree_path, bad).unwrap();
    assert!(store.collect(&Scope::Owner).await.is_err());
    for object in [leaf, garbage] {
        assert!(
            root.path()
                .join("upper/objects")
                .join(object.id().to_string())
                .exists()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn lower_scans_skip_special_files_and_verified_opens_refuse_replacements() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::symlink},
    };
    let root = tempfile::tempdir().unwrap();
    let lower = root.path().join("lower");
    std::fs::create_dir(&lower).unwrap();
    let a = lower.join("a");
    let b = lower.join("b");
    std::fs::write(&a, b"bytes").unwrap();
    std::fs::write(&b, b"bytes").unwrap();
    symlink("/dev/zero", lower.join("symlink")).unwrap();
    let fifo = lower.join("fifo");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let store = open(
        root.path().join("upper"),
        vec![lower],
        IndexMode::Resume,
        None,
    )
    .await;
    store.finish_recovery().await.unwrap();
    let object = ContentRef::for_bytes(b"bytes");
    store
        .set_pin(
            &Scope::Owner,
            &name("held"),
            None,
            Some(PinValue {
                target: Target::Object(object),
                policy: PinPolicy::Public,
                expires: None,
            }),
        )
        .await
        .unwrap();
    std::fs::remove_file(&a).unwrap();
    symlink("/dev/zero", &a).unwrap();
    assert_eq!(bytes(&store, &path("held"), 0..5).await, b"bytes");
    std::fs::remove_file(&b).unwrap();
    let b_c = CString::new(b.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(b_c.as_ptr(), 0o600) }, 0);
    assert!(
        store
            .read(&Scope::Owner, &path("held"), 0..5)
            .await
            .is_err()
    );
    assert!(a.symlink_metadata().unwrap().file_type().is_symlink());
    assert!(fifo.exists());
}

#[tokio::test]
async fn publication_keeps_the_lower_alternative_when_the_upper_is_later_collected() {
    let root = tempfile::tempdir().unwrap();
    let lower = root.path().join("lower");
    std::fs::create_dir(&lower).unwrap();
    std::fs::write(lower.join("blob"), b"data").unwrap();
    let store = open(
        root.path().join("upper"),
        vec![lower.clone()],
        IndexMode::Resume,
        None,
    )
    .await;
    store.finish_recovery().await.unwrap();
    let object = put(&store, "upper", b"data").await;
    assert_eq!(store.stats().unwrap().used, 4);
    unpin(&store, "upper").await;
    assert_eq!(store.collect(&Scope::Owner).await.unwrap().bytes, 4);
    assert_eq!(store.stats().unwrap().used, 0);
    store
        .set_pin(
            &Scope::Owner,
            &name("lower"),
            None,
            Some(PinValue {
                target: Target::Object(object),
                policy: PinPolicy::Public,
                expires: None,
            }),
        )
        .await
        .unwrap();
    assert_eq!(bytes(&store, &path("lower"), 0..4).await, b"data");
    assert_eq!(std::fs::read(lower.join("blob")).unwrap(), b"data");
    assert!(
        !root
            .path()
            .join("upper/objects")
            .join(object.id().to_string())
            .exists()
    );
}
