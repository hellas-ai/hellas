use super::*;
use futures::{FutureExt, StreamExt};
use std::io::Write;
fn pin(name: &str) -> PinTarget {
    PinTarget {
        name: PinName::new(name.into()).unwrap(),
        policy: PinPolicy::Public,
    }
}
fn at(name: &str) -> Path {
    Path::new(PinName::new(name.into()).unwrap(), String::new()).unwrap()
}
async fn open(root: &FsPath) -> DiskStore {
    let store = DiskStore::open(
        root.into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
    )
    .await
    .unwrap();
    store.finish_recovery().await.unwrap();
    store
}
async fn put(store: &DiskStore, name: &str, bytes: &[u8]) -> ContentRef {
    let object = ContentRef::for_bytes(bytes);
    let mut session = store
        .upload(&Scope::Owner, object, Some(pin(name)))
        .await
        .unwrap();
    session
        .declare(&hellas_xet::chunk(bytes), true)
        .await
        .unwrap();
    let mut offset = 0;
    for chunk in hellas_xet::chunk(bytes) {
        let end = offset + chunk.data_len as usize;
        session.accept_chunk(&bytes[offset..end]).await.unwrap();
        offset = end;
    }
    assert!(session.complete());
    object
}
#[tokio::test]
async fn failed_sqlite_commit_never_exposes_a_pin_to_an_existing_watch() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    let object = put(&store, "base", b"bytes").await;
    let cursor = store
        .pins(&Scope::Owner, "", Cursor::default())
        .await
        .unwrap()
        .cursor;
    let mut watch = store.watch(&Scope::Owner, "new", cursor).await.unwrap();
    let disk = store.core.disk.as_ref().unwrap();
    sqlx::raw_sql("CREATE TRIGGER reject_pin BEFORE INSERT ON pins BEGIN SELECT RAISE(ABORT,'injected'); END;").execute(&disk.db).await.unwrap();
    let value = PinValue {
        target: Target::Object(object),
        policy: PinPolicy::Public,
        expires: None,
    };
    assert!(
        store
            .set_pin(&Scope::Owner, &pin("new").name, None, Some(value.clone()))
            .await
            .is_err()
    );
    assert!(
        store
            .stat(&Scope::Public, &at("new"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(watch.next().now_or_never().is_none());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM pins WHERE name='new'")
        .fetch_one(&disk.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::raw_sql("DROP TRIGGER reject_pin")
        .execute(&disk.db)
        .await
        .unwrap();
    store
        .set_pin(&Scope::Owner, &pin("new").name, None, Some(value))
        .await
        .unwrap();
    assert!(
        matches!(watch.next().await.unwrap().unwrap(),PinEvent::Set{name,..}if name.as_str()=="new")
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM pins WHERE name='new'")
        .fetch_one(&disk.db)
        .await
        .unwrap();
    assert_eq!(count, 1);
}
#[tokio::test]
async fn cancelling_the_caller_during_sqlite_wait_still_commits_before_watch_and_reopen() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    let object = put(&store, "base", b"bytes").await;
    let cursor = store
        .pins(&Scope::Owner, "", Cursor::default())
        .await
        .unwrap()
        .cursor;
    let mut watch = store.watch(&Scope::Owner, "new", cursor).await.unwrap();
    let disk = store.core.disk.as_ref().unwrap().clone();
    // Keep the sole connection occupied while the effect updates its pending
    // state. Its returned watcher must remain behind the shared commit gate.
    let tx = disk.db.begin().await.unwrap();
    let applying = store.clone();
    let caller = tokio::spawn(async move {
        applying
            .set_pin(
                &Scope::Owner,
                &pin("new").name,
                None,
                Some(PinValue {
                    target: Target::Object(object),
                    policy: PinPolicy::Public,
                    expires: None,
                }),
            )
            .await
    });
    while store.core.state.lock().unwrap().generation == cursor.generation {
        tokio::task::yield_now().await;
    }
    assert!(watch.next().now_or_never().is_none());
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    tx.rollback().await.unwrap();
    assert!(
        matches!(watch.next().await.unwrap().unwrap(),PinEvent::Set{name,..}if name.as_str()=="new")
    );
    assert!(
        store
            .stat(&Scope::Public, &at("new"))
            .await
            .unwrap()
            .is_some()
    );
    drop(watch);
    store.close().await;
    drop(disk);
    drop(store);
    let store = open(root.path()).await;
    assert_eq!(
        store
            .stat(&Scope::Public, &at("new"))
            .await
            .unwrap()
            .unwrap()
            .target
            .object(),
        object
    );
}
#[tokio::test]
async fn tree_bytes_modified_after_verified_open_are_rejected_and_only_that_backing_is_bad() {
    let root = tempfile::tempdir().unwrap();
    let lower = root.path().join("lower");
    fs::create_dir(&lower).unwrap();
    let tree = Tree::new(vec![]).unwrap();
    let bytes = tree.bytes();
    let object = ContentRef::for_bytes(&bytes);
    let path = lower.join("tree");
    fs::write(&path, &bytes).unwrap();
    let store = DiskStore::open(
        root.path().join("upper"),
        vec![lower],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
    )
    .await
    .unwrap();
    store.finish_recovery().await.unwrap();
    let stored = store.core.state.lock().unwrap().objects[&object.id()].clone();
    let Data::File(file) = &stored.data else {
        unreachable!()
    };
    let (handle, entry) = file.open_location().unwrap();
    fs::write(&path, [0xff; 4]).unwrap();
    let charge = store.core.pool.reserve(object.bytes()).unwrap();
    assert!(file.load_opened(handle, entry, charge).is_err());
    assert!(file.open().is_err());
    // Rechecking through the shared GC walk must now fail closed too.
    store.core.state.lock().unwrap().pins.insert(
        pin("tree").name,
        PinValue {
            target: Target::Tree(object),
            policy: PinPolicy::Public,
            expires: None,
        },
    );
    assert!(store.collect(&Scope::Owner).await.is_err());
}
#[tokio::test]
async fn invalid_acquired_tree_drops_private_files_and_cannot_fill_an_existing_pin() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    let object = ContentRef::for_bytes(b"not a tree");
    let tree = Tree::new(vec![("absent".into(), Target::Object(object))]).unwrap();
    let tree_ref = put(&store, "tree", &tree.bytes()).await;
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
            &pin("tree").name,
            Some(&old),
            Some(PinValue {
                target: Target::Tree(tree_ref),
                ..old.clone()
            }),
        )
        .await
        .unwrap();
    let before = store.stats().unwrap().used;
    let core = store.core.clone();
    let result = core
        .effect(move |core| {
            let charge = core.data_pool().reserve(object.bytes())?;
            let mut buffer = super::super::storage::Buffer::new(&core, object.bytes(), charge)?;
            buffer.write_all(b"not a tree")?;
            let chunks = hellas_xet::chunk(b"not a tree");
            let data = buffer.finish(object, chunks.clone())?;
            core.publish_acquired(
                vec![(object, data, chunks)],
                Target::Tree(object),
                pin("bad"),
            )
        })
        .await;
    assert!(result.is_err());
    assert_eq!(store.stats().unwrap().used, before);
    assert_eq!(store.stats().unwrap().outstanding, 0);
    assert!(
        fs::read_dir(root.path().join("staging"))
            .unwrap()
            .next()
            .is_none()
    );
    let absent = Path::new(pin("tree").name, "absent".into()).unwrap();
    assert!(
        store
            .read(&Scope::Public, &absent, 0..object.bytes())
            .await
            .is_err()
    );
    assert!(
        store
            .stat(&Scope::Public, &at("bad"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn failed_promotion_remains_scope_protected_until_retry_or_journal_recovery() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    let object = ContentRef::for_bytes(b"retain me");
    let job = JobId {
        channel: hellas_auth::Digest::from_bytes([1; 32]),
        id: hellas_auth::Digest::from_bytes([2; 32]),
    };
    let scope = store
        .open_work(job, vec![object], object.bytes())
        .await
        .unwrap();
    let mut session = store.upload(&scope, object, None).await.unwrap();
    session
        .declare(&hellas_xet::chunk(b"retain me"), true)
        .await
        .unwrap();
    session.accept_chunk(b"retain me").await.unwrap();
    drop(session);
    sqlx::raw_sql("CREATE TRIGGER reject_pin BEFORE INSERT ON pins BEGIN SELECT RAISE(ABORT,'injected'); END;").execute(&store.core.disk.as_ref().unwrap().db).await.unwrap();
    assert!(
        store
            .promote_work(&scope, Target::Object(object), pin("retained"))
            .await
            .is_err()
    );
    assert_eq!(store.collect(&Scope::Owner).await.unwrap().bytes, 0);
    assert_eq!(store.stats().unwrap().used, object.bytes());
    sqlx::raw_sql("DROP TRIGGER reject_pin")
        .execute(&store.core.disk.as_ref().unwrap().db)
        .await
        .unwrap();
    // A restarted host restores its already-journaled reference before the
    // recovery barrier; global publication alone has not made it collectible.
    store.close().await;
    drop(store);
    let store = DiskStore::open(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
    )
    .await
    .unwrap();
    assert!(matches!(
        store.collect(&Scope::Owner).await,
        Err(Error::Denied)
    ));
    store
        .set_pin(
            &Scope::Owner,
            &pin("retained").name,
            None,
            Some(PinValue {
                target: Target::Object(object),
                policy: PinPolicy::Public,
                expires: None,
            }),
        )
        .await
        .unwrap();
    store.finish_recovery().await.unwrap();
    let mut bytes = store
        .read(&Scope::Public, &at("retained"), 0..object.bytes())
        .await
        .unwrap();
    assert_eq!(
        bytes.bytes.next().await.unwrap().unwrap().as_ref(),
        b"retain me"
    );
}

#[tokio::test]
async fn jobs_wait_for_provider_pin_commit_and_ignore_failed_pending_policy() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    let object = put(&store, "held", b"bytes").await;
    let old = store
        .pins(&Scope::Owner, "held", Cursor::default())
        .await
        .unwrap()
        .pins
        .remove(0)
        .1;
    store
        .set_pin(
            &Scope::Owner,
            &pin("held").name,
            Some(&old),
            Some(PinValue {
                policy: PinPolicy::Owner,
                ..old.clone()
            }),
        )
        .await
        .unwrap();
    let old = PinValue {
        policy: PinPolicy::Owner,
        ..old
    };
    let job_id = JobId {
        channel: hellas_auth::Digest::from_bytes([1; 32]),
        id: hellas_auth::Digest::from_bytes([2; 32]),
    };
    let bindings = BTreeMap::from([(object.id(), at("held"))]);
    let job = JobContent::new(
        &store,
        job_id,
        vec![object],
        object.bytes(),
        bindings.clone(),
    )
    .await
    .unwrap();
    let local = LocalStore::Job(job.clone());
    sqlx::raw_sql("CREATE TRIGGER reject_pin BEFORE INSERT ON pins BEGIN SELECT RAISE(ABORT,'injected'); END;").execute(&store.core.disk.as_ref().unwrap().db).await.unwrap();
    let tx = store.core.disk.as_ref().unwrap().db.begin().await.unwrap();
    let generation = store.core.state.lock().unwrap().generation;
    let applying = store.clone();
    let pending = tokio::spawn(async move {
        applying
            .set_pin(
                &Scope::Owner,
                &pin("held").name,
                Some(&old),
                Some(PinValue {
                    policy: PinPolicy::Jobs,
                    ..old.clone()
                }),
            )
            .await
    });
    while store.core.state.lock().unwrap().generation == generation {
        tokio::task::yield_now().await;
    }
    let path = at("held");
    let reading = local.open_verified(job.scope(), object, Some(&path));
    tokio::pin!(reading);
    assert!(reading.as_mut().now_or_never().is_none());
    let admitting = JobContent::new(
        &store,
        JobId {
            id: hellas_auth::Digest::from_bytes([3; 32]),
            ..job_id
        },
        vec![object],
        0,
        bindings,
    );
    tokio::pin!(admitting);
    assert!(admitting.as_mut().now_or_never().is_none());
    tx.rollback().await.unwrap();
    assert!(pending.await.unwrap().is_err());
    assert!(reading.await.unwrap().is_none());
    assert!(matches!(admitting.await, Err(Error::Capacity)));
    job.end().await.unwrap();
}
#[tokio::test]
async fn corrupt_existing_destination_cannot_destroy_verified_private_staging() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    let object = ContentRef::for_bytes(b"private bytes");
    let job = JobId {
        channel: hellas_auth::Digest::from_bytes([1; 32]),
        id: hellas_auth::Digest::from_bytes([2; 32]),
    };
    let scope = store
        .open_work(job, vec![object], object.bytes())
        .await
        .unwrap();
    let mut session = store.upload(&scope, object, None).await.unwrap();
    session
        .declare(&hellas_xet::chunk(b"private bytes"), true)
        .await
        .unwrap();
    session.accept_chunk(b"private bytes").await.unwrap();
    drop(session);
    let destination = root.path().join("objects").join(object.id().to_string());
    fs::write(&destination, b"corrupt bytes").unwrap();
    assert!(
        store
            .promote_work(&scope, Target::Object(object), pin("retained"))
            .await
            .is_err()
    );
    let mut reader = store.open_staged(&scope, object).await.unwrap().unwrap();
    let mut data = Vec::new();
    reader.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"private bytes");
    drop(reader);
    assert!(matches!(
        LocalStore::Disk(store.clone())
            .open_verified(&scope, object, None)
            .await,
        Err(Error::Denied)
    ));
    // The owner removes the deliberately corrupt foreign destination; retry
    // must use the original verified staging rather than downloading again.
    fs::remove_file(destination).unwrap();
    store
        .promote_work(&scope, Target::Object(object), pin("retained"))
        .await
        .unwrap();
    store.close().await;
    drop(store);
    let store = DiskStore::open(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
    )
    .await
    .unwrap();
    let scope = store
        .open_work(job, vec![object], object.bytes())
        .await
        .unwrap();
    assert!(store.open_staged(&scope, object).await.unwrap().is_some());
    store.finish_recovery().await.unwrap();
    store.end_work(&scope).await.unwrap();
    let mut read = store
        .read(&Scope::Public, &at("retained"), 0..object.bytes())
        .await
        .unwrap();
    assert_eq!(
        read.bytes.next().await.unwrap().unwrap().as_ref(),
        b"private bytes"
    );
}
