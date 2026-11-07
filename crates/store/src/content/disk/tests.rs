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
        Default::default(),
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
    let mut watch = store
        .watch(&Scope::Owner, "new", cursor.clone())
        .await
        .unwrap();
    let disk = store.core.disk.as_ref().unwrap();
    sqlx::raw_sql("CREATE TRIGGER keep_base_insert BEFORE INSERT ON pins WHEN NEW.name='base' BEGIN SELECT RAISE(ABORT,'unchanged pin written'); END; CREATE TRIGGER keep_base_update BEFORE UPDATE ON pins WHEN OLD.name='base' BEGIN SELECT RAISE(ABORT,'unchanged pin written'); END; CREATE TRIGGER keep_base_delete BEFORE DELETE ON pins WHEN OLD.name='base' BEGIN SELECT RAISE(ABORT,'unchanged pin written'); END;").execute(&disk.db).await.unwrap();
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
    let mut watch = store
        .watch(&Scope::Owner, "new", cursor.clone())
        .await
        .unwrap();
    let disk = store.core.disk.as_ref().unwrap().clone();
    // Keep the sole connection occupied while the effect updates its pending
    // state. Its returned watcher must remain behind the shared commit gate.
    let tx = disk.db.begin().await.unwrap();
    let authority = Arc::new(tokio::sync::Mutex::new(()));
    let acquiring = authority.clone();
    let scope = Scope::Owner.bind(
        move || {
            let acquiring = acquiring.clone();
            async move {
                let writer = acquiring.lock_owned().await;
                Ok(move || {
                    let _held = &writer;
                    Ok(())
                })
            }
        },
        std::future::pending,
    );
    let applying = store.clone();
    let caller = tokio::spawn(async move {
        applying
            .set_pin(
                &scope,
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
    assert!(authority.try_lock().is_err());
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(authority.try_lock().is_err());
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
    assert!(authority.try_lock().is_ok());
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
        Default::default(),
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
        .effect(&Scope::Owner, move |core| {
            let charge = core.data_pool().reserve(object.bytes())?;
            let mut buffer = super::super::storage::Buffer::new(&core, object.bytes(), charge)?;
            buffer.write_all(b"not a tree")?;
            let chunks = hellas_xet::chunk(b"not a tree");
            let data = buffer.finish(object, chunks.clone())?;
            core.publish_acquired(
                vec![(object, data, chunks)],
                Target::Tree(object),
                pin("bad"),
                None,
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
            .restore_root(job, Target::Object(object), pin("retained"), None)
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
        Default::default(),
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
    let job = JobContent::new(&store, job_id, vec![object], object.bytes())
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
async fn corrupt_existing_destination_is_replaced_from_verified_private_staging() {
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
    store
        .restore_root(job, Target::Object(object), pin("retained"), None)
        .await
        .unwrap();
    assert_eq!(store.stats().unwrap().used, object.bytes());
    let mut reader = store.open_staged(&scope, object).await.unwrap().unwrap();
    let mut data = Vec::new();
    reader.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"private bytes");
    drop(reader);
    let mut read = store
        .read(&Scope::Owner, &at("retained"), 0..object.bytes())
        .await
        .unwrap();
    assert_eq!(
        read.bytes.next().await.unwrap().unwrap().as_ref(),
        b"private bytes"
    );
    drop(read);
    store.close().await;
    drop(store);
    let store = DiskStore::open(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
        Default::default(),
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

fn recovery_job() -> JobId {
    JobId {
        channel: hellas_auth::Digest::from_bytes([11; 32]),
        id: hellas_auth::Digest::from_bytes([12; 32]),
    }
}

#[tokio::test]
async fn root_reconciliation_preserves_an_owner_policy_change_queued_before_publication() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    let object = put(&store, "proposal", b"root").await;
    let old = store
        .pins(&Scope::Owner, "proposal", Cursor::default())
        .await
        .unwrap()
        .pins
        .remove(0)
        .1;
    let disk = store.core.disk.as_ref().unwrap();
    let tx = disk.db.begin().await.unwrap();
    let generation = store.core.state.lock().unwrap().generation;
    let owner = store.clone();
    let update = tokio::spawn(async move {
        owner
            .set_pin(
                &Scope::Owner,
                &pin("proposal").name,
                Some(&old),
                Some(PinValue {
                    policy: PinPolicy::Owner,
                    ..old.clone()
                }),
            )
            .await
    });
    while store.core.state.lock().unwrap().generation == generation {
        tokio::task::yield_now().await;
    }
    let publishing = store.clone();
    // This stale candidate is what reconciliation prepared before the Owner CAS.
    let reconcile = tokio::spawn(async move {
        publishing
            .restore_root(
                recovery_job(),
                Target::Object(object),
                PinTarget {
                    policy: PinPolicy::Jobs,
                    ..pin("accepted")
                },
                Some(pin("proposal").name),
            )
            .await
    });
    tx.rollback().await.unwrap();
    update.await.unwrap().unwrap();
    reconcile.await.unwrap().unwrap();
    let pins = store
        .pins(&Scope::Owner, "", Cursor::default())
        .await
        .unwrap()
        .pins;
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].0, pin("accepted").name);
    assert_eq!(pins[0].1.policy, PinPolicy::Owner);
    assert!(
        store
            .stat(&Scope::Public, &at("accepted"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn failed_root_reconciliation_stays_protected_and_retry_cleans_its_temporary_scope() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    let object = put(&store, "cache", b"journal-authoritative root").await;
    let old = store
        .pins(&Scope::Owner, "cache", Cursor::default())
        .await
        .unwrap()
        .pins
        .remove(0)
        .1;
    store
        .set_pin(&Scope::Owner, &pin("cache").name, Some(&old), None)
        .await
        .unwrap();
    let disk = store.core.disk.as_ref().unwrap();
    sqlx::raw_sql("CREATE TRIGGER reject_pin BEFORE INSERT ON pins BEGIN SELECT RAISE(ABORT,'injected'); END;").execute(&disk.db).await.unwrap();
    assert!(
        store
            .restore_root(
                recovery_job(),
                Target::Object(object),
                pin("retained"),
                None
            )
            .await
            .is_err()
    );
    assert_eq!(store.collect(&Scope::Owner).await.unwrap().bytes, 0);
    assert!(matches!(
        store
            .open_work(recovery_job(), vec![object], object.bytes())
            .await,
        Err(Error::Denied)
    ));
    sqlx::raw_sql("DROP TRIGGER reject_pin")
        .execute(&disk.db)
        .await
        .unwrap();
    store
        .restore_root(
            recovery_job(),
            Target::Object(object),
            pin("retained"),
            None,
        )
        .await
        .unwrap();
    assert!(store.core.live_jobs().unwrap().is_empty());
    assert_eq!(store.collect(&Scope::Owner).await.unwrap().bytes, 0);
    store.close().await;
    drop(store);
    let store = open(root.path()).await;
    let mut read = store
        .read(&Scope::Public, &at("retained"), 0..object.bytes())
        .await
        .unwrap();
    assert_eq!(
        read.bytes.next().await.unwrap().unwrap().as_ref(),
        b"journal-authoritative root"
    );
}

#[tokio::test]
async fn an_opener_cannot_adopt_the_temporary_root_scope_while_its_pin_is_committing() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    let object = put(&store, "base", b"root").await;
    // Claim ownership before deliberately occupying the connection: this test
    // pauses pin commit, rather than the preceding durable ownership claim.
    store.claim_work().await.unwrap();
    let disk = store.core.disk.as_ref().unwrap();
    let tx = disk.db.begin().await.unwrap();
    let generation = store.core.state.lock().unwrap().generation;
    let recovering = store.clone();
    let restored = tokio::spawn(async move {
        recovering
            .restore_root(
                recovery_job(),
                Target::Object(object),
                pin("retained"),
                None,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while store.core.state.lock().unwrap().generation == generation {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let adopting = store.open_work(recovery_job(), vec![object], object.bytes());
    tokio::pin!(adopting);
    assert!(adopting.as_mut().now_or_never().is_none());
    tx.rollback().await.unwrap();
    let adopted = adopting.await;
    restored.await.unwrap().unwrap();
    match adopted {
        Err(Error::Denied) => {}
        Ok(scope) => {
            store.reserve_output(&scope, 1).await.unwrap();
            store.end_work(&scope).await.unwrap();
        }
        Err(error) => panic!("unexpected admission error: {error}"),
    }
    assert!(store.core.live_jobs().unwrap().is_empty());
}

#[tokio::test]
async fn acquired_pin_deletion_can_retry_after_sql_failure_even_when_work_has_ended() {
    for ephemeral in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut store = open(root.path()).await;
        let object = ContentRef::for_bytes(b"weights");
        let (url, http, serving) = super::super::acquire::tests::https(b"weights");
        store.core.http = http;
        store
            .set_on_miss(Arc::new(AllowList(BTreeMap::from([(
                object.id(),
                (
                    object.bytes(),
                    Source::Https {
                        url,
                        sha256: None,
                        bytes: object.bytes(),
                    },
                ),
            )]))))
            .unwrap();
        let (local, scope) = if ephemeral {
            let work = JobContent::new(&store, recovery_job(), vec![], 0)
                .await
                .unwrap();
            let scope = work.scope().clone();
            (LocalStore::Job(work), scope)
        } else {
            let scope = store.open_work(recovery_job(), vec![], 0).await.unwrap();
            (LocalStore::Disk(store.clone()), scope)
        };
        local.acquire_missing(&scope, vec![object]).await.unwrap();
        serving.join().unwrap();
        let disk = store.core.disk.as_ref().unwrap();
        sqlx::raw_sql("CREATE TRIGGER reject_delete BEFORE DELETE ON pins BEGIN SELECT RAISE(ABORT,'injected'); END;").execute(&disk.db).await.unwrap();
        let end = async {
            match &local {
                LocalStore::Job(work) => work.end().await,
                LocalStore::Disk(node) => node.end_work(&scope).await,
                _ => unreachable!(),
            }
        };
        assert!(end.await.is_err());
        assert_eq!(
            store
                .pins(&Scope::Owner, "work/", Cursor::default())
                .await
                .unwrap()
                .pins
                .len(),
            1
        );
        sqlx::raw_sql("DROP TRIGGER reject_delete")
            .execute(&disk.db)
            .await
            .unwrap();
        match &local {
            LocalStore::Job(work) => work.end().await.unwrap(),
            LocalStore::Disk(node) => node.end_work(&scope).await.unwrap(),
            _ => unreachable!(),
        };
        assert!(
            store
                .pins(&Scope::Owner, "work/", Cursor::default())
                .await
                .unwrap()
                .pins
                .is_empty()
        );
        assert_eq!(
            store.collect(&Scope::Owner).await.unwrap().bytes,
            object.bytes()
        );
        assert_eq!(store.stats().unwrap().outstanding, 0);
    }
}

#[tokio::test]
async fn work_owned_is_durable_before_the_first_scope_and_survives_all_pin_removal() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    put(&store, "ordinary", b"ordinary owner content").await;
    store.close().await;
    drop(store);
    let store = DiskStore::open_owner(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
        Default::default(),
    )
    .await
    .unwrap();
    store.finish_recovery().await.unwrap();
    let scope = store
        .open_work(
            JobId {
                channel: Digest::hash(b"channel"),
                id: Digest::hash(b"work"),
            },
            vec![],
            0,
        )
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM work_owned")
        .fetch_one(&store.core.disk.as_ref().unwrap().db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    store.end_work(&scope).await.unwrap();
    let page = store
        .pins(&Scope::Owner, "", Cursor::default())
        .await
        .unwrap();
    for (name, value) in page.pins {
        store
            .set_pin(&Scope::Owner, &name, Some(&value), None)
            .await
            .unwrap();
    }
    assert!(store.collect(&Scope::Owner).await.unwrap().bytes > 0);
    assert_eq!(store.stats().unwrap().used, 0);
    assert_eq!(store.stats().unwrap().outstanding, 0);
    store.close().await;
    drop(store);
    // Refusal must precede startup cleanup, even when an owner removed every
    // lifecycle pin and only the monotone database fact identifies ownership.
    let incomplete = root.path().join("staging/incomplete");
    fs::write(&incomplete, b"do not clean a work-owned upper").unwrap();
    let result = DiskStore::open_owner(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
        Default::default(),
    )
    .await;
    assert!(matches!(result, Err(Error::WorkOwned)));
    assert_eq!(
        fs::read(&incomplete).unwrap(),
        b"do not clean a work-owned upper"
    );
    let daemon = open(root.path()).await;
    daemon.claim_work().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM work_owned")
        .fetch_one(&daemon.core.disk.as_ref().unwrap().db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    daemon.close().await;
}

#[tokio::test]
async fn a_failed_ownership_commit_cannot_open_a_work_scope_or_reserve_content() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    sqlx::raw_sql("CREATE TRIGGER refuse_work_owned BEFORE INSERT ON work_owned BEGIN SELECT RAISE(FAIL, 'ownership write refused'); END;")
        .execute(&store.core.disk.as_ref().unwrap().db).await.unwrap();
    let job = JobId {
        channel: Digest::hash(b"channel"),
        id: Digest::hash(b"work"),
    };
    assert!(
        store
            .open_work(job, vec![ContentRef::for_bytes(b"not written")], 100)
            .await
            .is_err()
    );
    assert!(store.core.live_jobs().unwrap().is_empty());
    assert_eq!(store.stats().unwrap().used, 0);
    assert_eq!(store.stats().unwrap().outstanding, 0);
    assert!(
        store
            .pins(&Scope::Owner, "", Cursor::default())
            .await
            .unwrap()
            .pins
            .is_empty()
    );
    assert!(
        !store
            .core
            .disk
            .as_ref()
            .unwrap()
            .work_owned
            .load(Ordering::Acquire)
    );
    store.close().await;
    drop(store);
    let ordinary = DiskStore::open_owner(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
        Default::default(),
    )
    .await
    .unwrap();
    ordinary.close().await;
}

#[tokio::test]
async fn durability_modes_apply_real_sqlite_pragmas() {
    for (durability, expected) in [(Durability::default(), 1), (Durability::Power, 2)] {
        let root = tempfile::tempdir().unwrap();
        let store = DiskStore::open(
            root.path().into(),
            vec![],
            IndexMode::Resume,
            None,
            Reservations::ram(32 << 20),
            durability,
        )
        .await
        .unwrap();
        let db = &store.core.disk.as_ref().unwrap().db;
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(db)
            .await
            .unwrap();
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(db)
            .await
            .unwrap();
        let busy: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(synchronous, expected);
        assert_eq!(busy, 0);
        #[cfg(target_os = "macos")]
        {
            let fullfsync: i64 = sqlx::query_scalar("PRAGMA fullfsync")
                .fetch_one(db)
                .await
                .unwrap();
            assert_eq!(fullfsync, i64::from(durability == Durability::Power));
        }
        store.close().await;
    }
}
#[tokio::test]
async fn content_ownership_probe() {
    let Some(root) = std::env::var_os("HELLAS_CONTENT_OWNERSHIP_PROBE") else {
        return;
    };
    let started = std::time::Instant::now();
    let result = DiskStore::open(
        root.into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
        Durability::default(),
    )
    .await;
    assert!(matches!(result, Err(Error::Locked)));
    assert!(
        started.elapsed() < std::time::Duration::from_millis(250),
        "must refuse before the former busy wait"
    );
}
#[tokio::test]
async fn a_second_process_cannot_open_the_content_database() {
    let root = tempfile::tempdir().unwrap();
    let store = open(root.path()).await;
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "content::disk::tests::content_ownership_probe"])
        .env("HELLAS_CONTENT_OWNERSHIP_PROBE", root.path())
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    store.close().await;
}

#[tokio::test]
async fn failed_lower_initialization_releases_the_writer_before_returning() {
    let root = tempfile::tempdir().unwrap();
    let upper = root.path().join("upper");
    assert!(
        DiskStore::open(
            upper.clone(),
            vec![root.path().join("missing-lower")],
            IndexMode::Resume,
            None,
            Reservations::ram(32 << 20),
            Durability::default()
        )
        .await
        .is_err()
    );
    let reopened = DiskStore::open(
        upper,
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
        Durability::default(),
    )
    .await
    .unwrap();
    reopened.close().await;
}

#[tokio::test]
async fn corrupt_upper_is_removed_without_losing_pins_and_can_be_uploaded_again() {
    for repair in ["read", "startup", "rescan-grow", "rescan-shrink"] {
        let root = tempfile::tempdir().unwrap();
        let mut store = open(root.path()).await;
        let content = b"verified owned bytes";
        let object = put(&store, "kept", content).await;
        let path = root.path().join("objects").join(object.id().to_string());
        let mut reading = if repair == "read" {
            Some(
                store
                    .read(&Scope::Owner, &at("kept"), 0..object.bytes())
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        fs::write(
            &path,
            if repair == "rescan-shrink" {
                b"x".to_vec()
            } else {
                vec![0xff; content.len() * 2]
            },
        )
        .unwrap();
        match repair {
            "read" => {
                assert!(
                    reading
                        .as_mut()
                        .unwrap()
                        .bytes
                        .next()
                        .await
                        .unwrap()
                        .is_err()
                );
                drop(reading);
            }
            "startup" => {
                store.close().await;
                drop(store);
                store = open(root.path()).await;
            }
            _ => store.rescan(vec![], IndexMode::Resume).await.unwrap(),
        }
        assert!(!path.exists(), "{repair}");
        assert_eq!(store.stats().unwrap().used, 0, "{repair}");
        let pins = store
            .pins(&Scope::Owner, "", Cursor::default())
            .await
            .unwrap();
        assert_eq!(pins.pins.len(), 1, "{repair}");
        assert_eq!(pins.pins[0].1.target.object(), object, "{repair}");
        assert!(
            matches!(
                store.stat(&Scope::Owner, &at("kept")).await,
                Err(Error::Missing)
            ),
            "{repair}"
        );
        assert_eq!(put(&store, "kept", content).await, object);
        let mut read = store
            .read(&Scope::Owner, &at("kept"), 0..object.bytes())
            .await
            .unwrap();
        assert_eq!(
            read.bytes.next().await.unwrap().unwrap().as_ref(),
            content,
            "{repair}"
        );
        assert_eq!(store.stats().unwrap().used, object.bytes(), "{repair}");
        drop(read);
        store.close().await;
    }
}

#[cfg(unix)]
#[tokio::test]
async fn failed_reads_retire_only_the_bad_backing_and_preserve_replacements() {
    for local in [false, true] {
        for replacement in ["none", "healthy", "corrupt"] {
            let root = tempfile::tempdir().unwrap();
            let store = open(root.path()).await;
            let bytes = b"verified owned bytes";
            let object = put(&store, "kept", bytes).await;
            let lower = root.path().join("lower");
            fs::create_dir(&lower).unwrap();
            fs::write(lower.join("healthy"), bytes).unwrap();
            store
                .rescan(vec![lower.clone()], IndexMode::Resume)
                .await
                .unwrap();
            let path = root.path().join("objects").join(object.id().to_string());
            fs::write(&path, vec![0xff; bytes.len()]).unwrap();
            let stored = store.core.state.lock().unwrap().objects[&object.id()].clone();
            let Data::File(file) = &stored.data else {
                unreachable!()
            };
            let metadata = fs::metadata(&path).unwrap();
            // Inject a stale resume record for the current identity: this models
            // bit rot whose metadata still matches the previously verified bytes.
            file.entries
                .lock()
                .unwrap()
                .iter_mut()
                .find(|entry| entry.path == path)
                .unwrap()
                .identity = FileIdentity::of(&metadata);
            file.disk.records.put(
                &metadata,
                &Indexed {
                    id: object.id().digest(),
                    len: object.bytes(),
                    chunks: hellas_xet::chunk(bytes),
                },
            );
            let reader = LocalStore::Disk(store.clone())
                .open_verified(&Scope::Owner, object, None)
                .await
                .unwrap()
                .unwrap();
            let mut stream = store
                .read(&Scope::Owner, &at("kept"), 0..object.bytes())
                .await
                .unwrap();
            if replacement != "none" {
                let previous = store
                    .pins(&Scope::Owner, "kept", Cursor::default())
                    .await
                    .unwrap()
                    .pins[0]
                    .1
                    .clone();
                store
                    .set_pin(&Scope::Owner, &pin("kept").name, Some(&previous), None)
                    .await
                    .unwrap();
                assert_eq!(
                    store.collect(&Scope::Owner).await.unwrap().bytes,
                    object.bytes()
                );
                assert_eq!(put(&store, "kept", bytes).await, object);
                if replacement == "corrupt" {
                    fs::write(&path, vec![0xfe; bytes.len()]).unwrap();
                }
            }
            if local {
                assert!(reader.read_all(object, &store.ram_pool()).await.is_err());
            } else {
                assert!(stream.bytes.next().await.unwrap().is_err());
            }
            drop(stream);
            assert_eq!(path.exists(), replacement == "healthy");
            assert_eq!(
                store.stats().unwrap().used,
                if replacement == "healthy" {
                    object.bytes()
                } else {
                    0
                }
            );
            let mut read = store
                .read(&Scope::Owner, &at("kept"), 0..object.bytes())
                .await
                .unwrap();
            assert_eq!(read.bytes.next().await.unwrap().unwrap().as_ref(), bytes);
            assert_eq!(
                store
                    .pins(&Scope::Owner, "kept", Cursor::default())
                    .await
                    .unwrap()
                    .pins[0]
                    .1
                    .target
                    .object(),
                object
            );
            store.close().await;
        }
    }
}
