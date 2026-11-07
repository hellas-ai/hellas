use hellas_auth::Digest;
use hellas_rpc::ContentRef;
use hellas_store::content::*;
fn pin(name: &str) -> PinTarget {
    PinTarget {
        name: PinName::new(name.into()).unwrap(),
        policy: PinPolicy::Owner,
    }
}
fn job() -> JobId {
    JobId {
        channel: Digest::from_bytes([1; 32]),
        id: Digest::from_bytes([2; 32]),
    }
}
async fn store(root: &std::path::Path, capacity: u64) -> DiskStore {
    let store = DiskStore::open(
        root.into(),
        vec![],
        IndexMode::Resume,
        Some(capacity),
        Reservations::ram(8 << 20),
        false,
        Default::default(),
    )
    .await
    .unwrap();
    store.finish_recovery().await.unwrap();
    store
}
async fn fill(mut session: UploadSession, bytes: &[u8]) {
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
}
#[tokio::test]
async fn concurrent_real_uploads_cannot_each_spend_the_same_capacity() {
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path(), 12).await;
    let requests = (0..8).map(|n| {
        let store = &store;
        async move {
            store
                .upload(
                    &Scope::Owner,
                    ContentRef::for_bytes(&[n; 4]),
                    Some(pin(&format!("p/{n}"))),
                )
                .await
        }
    });
    let sessions = futures::future::join_all(requests)
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    assert_eq!(sessions.len(), 3);
    assert_eq!(store.stats().unwrap().used, 0);
    assert_eq!(store.stats().unwrap().outstanding, 12);
    drop(sessions);
    assert_eq!(store.stats().unwrap().outstanding, 0);
}
#[tokio::test]
async fn input_conversion_keeps_output_reserved_and_parallel_outputs_cannot_overcommit() {
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path(), 12).await;
    let input = ContentRef::for_bytes(b"data");
    let scope = store.open_work(job(), vec![input], 4).await.unwrap();
    store.reserve_output(&scope, 8).await.unwrap();
    store.reserve_output(&scope, 8).await.unwrap();
    fill(store.upload(&scope, input, None).await.unwrap(), b"data").await;
    assert_eq!(store.stats().unwrap().used, 4);
    assert_eq!(store.stats().unwrap().outstanding, 8);
    let output = ContentRef::for_bytes(b"output");
    let session = store.stage_output(&scope, output).await.unwrap();
    assert!(matches!(
        store
            .stage_output(&scope, ContentRef::for_bytes(b"new"))
            .await,
        Err(Error::Capacity)
    ));
    drop(session);
    let session = store.stage_output(&scope, output).await.unwrap();
    fill(session, b"output").await;
    assert_eq!(store.stats().unwrap().used, 10);
    assert_eq!(store.stats().unwrap().outstanding, 2);
    store.reserve_output(&scope, 8).await.unwrap();
    assert_eq!(store.stats().unwrap().outstanding, 2);
    assert!(matches!(
        store
            .stage_output(&scope, ContentRef::for_bytes(b"new"))
            .await,
        Err(Error::Capacity)
    ));
    store
        .restore_root(job(), Target::Object(output), pin("transcript"), None)
        .await
        .unwrap();
    store.end_work(&scope).await.unwrap();
    assert_eq!(store.stats().unwrap().used, 6);
    assert_eq!(store.stats().unwrap().outstanding, 0);
}
#[tokio::test]
async fn admission_collects_oldest_cache_and_stops_once_it_fits() {
    use futures::StreamExt;
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path(), 12).await;
    for (name, data) in [("old", b"aaaa"), ("new", b"bbbb")] {
        fill(
            store
                .upload(&Scope::Owner, ContentRef::for_bytes(data), Some(pin(name)))
                .await
                .unwrap(),
            data,
        )
        .await;
    }
    let at = Path::new(PinName::new("new".into()).unwrap(), String::new()).unwrap();
    let mut read = store.read(&Scope::Owner, &at, 0..4).await.unwrap();
    assert_eq!(read.bytes.next().await.unwrap().unwrap().as_ref(), b"bbbb");
    drop(read);
    for key in ["old", "new"] {
        let value = store
            .pins(&Scope::Owner, key, Cursor::default())
            .await
            .unwrap()
            .pins
            .remove(0)
            .1;
        store
            .set_pin(
                &Scope::Owner,
                &PinName::new(key.into()).unwrap(),
                Some(&value),
                None,
            )
            .await
            .unwrap();
    }
    let scope = store
        .open_work(job(), vec![ContentRef::for_bytes(b"12345678")], 8)
        .await
        .unwrap();
    assert_eq!(store.stats().unwrap().used, 4);
    assert_eq!(store.stats().unwrap().outstanding, 8);
    assert!(
        !root
            .path()
            .join("objects")
            .join(ContentRef::for_bytes(b"aaaa").id().to_string())
            .exists()
    );
    assert!(
        root.path()
            .join("objects")
            .join(ContentRef::for_bytes(b"bbbb").id().to_string())
            .exists()
    );
    store.end_work(&scope).await.unwrap();
}
#[test]
fn durable_private_output_survives_actual_process_exit_before_pin() {
    const CHILD: &str = "HELLAS_CONTENT_STAGE_CRASH_ROOT";
    let input = ContentRef::for_bytes(b"input");
    let output = ContentRef::for_bytes(b"transcript");
    if let Some(root) = std::env::var_os(CHILD) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let store = store(std::path::Path::new(&root), 64).await;
            let scope = store
                .open_work(job(), vec![input], input.bytes())
                .await
                .unwrap();
            store.reserve_output(&scope, output.bytes()).await.unwrap();
            fill(store.upload(&scope, input, None).await.unwrap(), b"input").await;
            fill(
                store.stage_output(&scope, output).await.unwrap(),
                b"transcript",
            )
            .await;
            // Stand-in for the application's durable reference: no pin yet.
            let path = std::path::Path::new(&root).join("journal-reference");
            std::fs::write(&path, output.id().to_string()).unwrap();
            std::fs::File::open(path).unwrap().sync_all().unwrap();
            std::process::exit(0);
        });
        unreachable!();
    }
    let root = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "durable_private_output_survives_actual_process_exit_before_pin",
            "--nocapture",
        ])
        .env(CHILD, root.path())
        .status()
        .unwrap();
    assert!(status.success());
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let store = DiskStore::open(
            root.path().into(),
            vec![],
            IndexMode::Resume,
            Some(64),
            Reservations::ram(8 << 20),
            false,
            Default::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("journal-reference")).unwrap(),
            output.id().to_string()
        );
        assert!(matches!(
            store.collect(&Scope::Owner).await,
            Err(Error::Denied)
        ));
        let scope = store
            .open_work(job(), vec![input], input.bytes())
            .await
            .unwrap();
        assert_eq!(store.stats().unwrap().outstanding, 0);
        store
            .restore_root(job(), Target::Object(output), pin("transcript"), None)
            .await
            .unwrap();
        store.finish_recovery().await.unwrap();
        let at = Path::new(PinName::new("transcript".into()).unwrap(), String::new()).unwrap();
        let mut read = store
            .read(&Scope::Owner, &at, 0..output.bytes())
            .await
            .unwrap();
        use futures::StreamExt;
        assert_eq!(
            read.bytes.next().await.unwrap().unwrap().as_ref(),
            b"transcript"
        );
        store.end_work(&scope).await.unwrap();
        assert_eq!(store.stats().unwrap().used, output.bytes());
    });
}

#[tokio::test]
async fn output_allowance_cannot_mask_a_later_input_reservation_extension() {
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path(), 20).await;
    let a = ContentRef::for_bytes(b"aaaa");
    let b = ContentRef::for_bytes(b"bbbb");
    fill(
        store
            .upload(&Scope::Owner, a, Some(pin("a")))
            .await
            .unwrap(),
        b"aaaa",
    )
    .await;
    fill(
        store
            .upload(
                &Scope::Owner,
                b,
                Some(PinTarget {
                    policy: PinPolicy::Jobs,
                    ..pin("b")
                }),
            )
            .await
            .unwrap(),
        b"bbbb",
    )
    .await;
    let scope = store.open_work(job(), vec![a, b], 8).await.unwrap();
    store.reserve_output(&scope, 8).await.unwrap();
    fill(store.upload(&scope, a, None).await.unwrap(), b"aaaa").await;
    for (name, policy) in [("a", PinPolicy::Jobs), ("b", PinPolicy::Owner)] {
        let old = store
            .pins(&Scope::Owner, name, Cursor::default())
            .await
            .unwrap()
            .pins
            .remove(0)
            .1;
        store
            .set_pin(
                &Scope::Owner,
                &pin(name).name,
                Some(&old),
                Some(PinValue {
                    policy,
                    ..old.clone()
                }),
            )
            .await
            .unwrap();
    }
    assert!(matches!(
        store.upload(&scope, b, None).await,
        Err(Error::Capacity)
    ));
    assert_eq!(store.stats().unwrap().used, 12);
    assert_eq!(store.stats().unwrap().outstanding, 8);
    store.end_work(&scope).await.unwrap();
    assert_eq!(store.stats().unwrap().used, 8);
    assert_eq!(store.stats().unwrap().outstanding, 0);
}
#[tokio::test]
async fn reopening_root_only_then_widening_does_not_reserve_recovered_inputs_twice() {
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path(), 16).await;
    let a = ContentRef::for_bytes(b"root");
    let b = ContentRef::for_bytes(b"leaf");
    let scope = store.open_work(job(), vec![a, b], 8).await.unwrap();
    fill(store.upload(&scope, a, None).await.unwrap(), b"root").await;
    fill(store.upload(&scope, b, None).await.unwrap(), b"leaf").await;
    store.close().await;
    drop(store);
    let store = DiskStore::open(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        Some(16),
        Reservations::ram(8 << 20),
        false,
        Default::default(),
    )
    .await
    .unwrap();
    let scope = store.open_work(job(), vec![a], 8).await.unwrap();
    assert_eq!(store.stats().unwrap().outstanding, 0);
    let scope = store.widen_work(&scope, vec![a, b], 8).await.unwrap();
    assert_eq!(store.stats().unwrap().outstanding, 0);
    assert!(store.open_staged(&scope, a).await.unwrap().is_some());
    store.finish_recovery().await.unwrap();
    store.end_work(&scope).await.unwrap();
    assert_eq!(store.stats().unwrap().used, 0);
}

#[test]
fn authoritative_root_recovery_discards_unjournaled_output_before_restoring_exact_allowance() {
    const CHILD: &str = "HELLAS_CONTENT_EXACT_RECOVERY_ROOT";
    let input_bytes = b"retained input";
    let output_bytes = b"uncommitted transcript";
    let input = ContentRef::for_bytes(input_bytes);
    let output = ContentRef::for_bytes(output_bytes);
    let initial = Tree::new(vec![("input".into(), Target::Object(input))])
        .unwrap()
        .bytes();
    let initial_ref = ContentRef::for_bytes(&initial);
    let replacement = Tree::new(vec![
        ("input".into(), Target::Object(input)),
        ("transcript".into(), Target::Object(output)),
    ])
    .unwrap()
    .bytes();
    let total_output = initial.len() as u64 + replacement.len() as u64 + output.bytes();
    let capacity = input.bytes() + total_output;
    let job_pin = PinTarget {
        policy: PinPolicy::Channel(job().channel),
        ..pin("channel/job")
    };
    let cache = b"cache";
    if let Some(root) = std::env::var_os(CHILD) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let store = store(std::path::Path::new(&root), capacity + cache.len() as u64).await;
            fill(
                store
                    .upload(
                        &Scope::Owner,
                        ContentRef::for_bytes(cache),
                        Some(pin("cache")),
                    )
                    .await
                    .unwrap(),
                cache,
            )
            .await;
            let value = store
                .pins(&Scope::Owner, "cache", Cursor::default())
                .await
                .unwrap()
                .pins
                .remove(0)
                .1;
            store
                .set_pin(&Scope::Owner, &pin("cache").name, Some(&value), None)
                .await
                .unwrap();
            let scope = store
                .open_work(job(), vec![input], input.bytes())
                .await
                .unwrap();
            store.reserve_output(&scope, total_output).await.unwrap();
            fill(
                store.upload(&scope, input, None).await.unwrap(),
                input_bytes,
            )
            .await;
            fill(
                store.stage_output(&scope, initial_ref).await.unwrap(),
                &initial,
            )
            .await;
            store
                .restore_root(job(), Target::Tree(initial_ref), job_pin.clone(), None)
                .await
                .unwrap();
            fill(
                store.stage_output(&scope, output).await.unwrap(),
                output_bytes,
            )
            .await;
            fill(
                store
                    .stage_output(&scope, ContentRef::for_bytes(&replacement))
                    .await
                    .unwrap(),
                &replacement,
            )
            .await;
            // This incomplete temporary has no durable Complete marker or journal reference.
            std::fs::write(
                std::path::Path::new(&root).join("staging/incomplete"),
                b"partial",
            )
            .unwrap();
            std::process::exit(0);
        });
        unreachable!();
    }
    let root = tempfile::tempdir().unwrap();
    assert!(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "authoritative_root_recovery_discards_unjournaled_output_before_restoring_exact_allowance", "--nocapture"])
        .env(CHILD, root.path()).status().unwrap().success());
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let node = DiskStore::open(
            root.path().into(),
            vec![],
            IndexMode::Resume,
            Some(capacity),
            Reservations::ram(8 << 20),
            false,
            Default::default(),
        )
        .await
        .unwrap();
        assert!(!root.path().join("staging/incomplete").exists());
        assert!(matches!(
            node.collect(&Scope::Owner).await,
            Err(Error::Denied)
        ));
        // The application's durable root is still the initial tree, even though
        // the private directory also holds a complete unjournaled replacement.
        let recovery = node.open_work(job(), vec![], 0).await.unwrap();
        node.restore_root(job(), Target::Tree(initial_ref), job_pin, None)
            .await
            .unwrap();
        node.end_work(&recovery).await.unwrap();
        let scope = node
            .open_work(job(), vec![input], input.bytes())
            .await
            .unwrap();
        node.restore_output(&scope, total_output, initial.len() as u64)
            .await
            .unwrap();
        assert_eq!(
            node.stats().unwrap().outstanding,
            total_output - initial.len() as u64
        );
        assert!(node.stats().unwrap().used + node.stats().unwrap().outstanding > capacity);
        node.finish_recovery().await.unwrap();
        assert_eq!(
            node.stats().unwrap().used + node.stats().unwrap().outstanding,
            capacity
        );
        assert!(
            !root
                .path()
                .join("objects")
                .join(ContentRef::for_bytes(cache).id().to_string())
                .exists()
        );
        assert!(
            !root
                .path()
                .join("objects")
                .join(output.id().to_string())
                .exists()
        );
        assert!(
            !root
                .path()
                .join("objects")
                .join(ContentRef::for_bytes(&replacement).id().to_string())
                .exists()
        );
        assert!(
            LocalStore::Disk(node.clone())
                .open_verified(&scope, input, None)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(node.collect(&Scope::Owner).await.unwrap().objects, 0);
        node.end_work(&scope).await.unwrap();
    });
}

#[tokio::test]
async fn verified_file_body_keeps_its_ram_charge_through_shared_body_ownership() {
    let root = tempfile::tempdir().unwrap();
    let node = store(root.path(), 4).await;
    let object = ContentRef::for_bytes(b"data");
    fill(
        node.upload(&Scope::Owner, object, Some(pin("body")))
            .await
            .unwrap(),
        b"data",
    )
    .await;
    let reader = LocalStore::Disk(node.clone())
        .open_verified(&Scope::Owner, object, None)
        .await
        .unwrap()
        .unwrap();
    let pool = Reservations::ram(object.bytes());
    let body = reader.read_all(object, &pool).await.unwrap();
    assert_eq!(pool.held(), object.bytes());
    let shared = body.clone();
    drop(body);
    assert_eq!(shared.as_ref(), b"data");
    assert_eq!(pool.held(), object.bytes());
    drop(shared);
    assert_eq!(pool.held(), 0);
}
