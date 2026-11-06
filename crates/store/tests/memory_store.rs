use futures::{FutureExt, StreamExt};
use hellas_auth::Digest;
use hellas_rpc::ContentRef;
use hellas_store::content::*;

fn name(value: &str) -> PinName {
    PinName::new(value.into()).unwrap()
}
fn at(pin: &str, path: &str) -> Path {
    Path::new(name(pin), path.into()).unwrap()
}
fn job(channel: u8, id: u8) -> JobId {
    JobId {
        channel: Digest::from_bytes([channel; 32]),
        id: Digest::from_bytes([id; 32]),
    }
}
async fn put(store: &MemoryStore, pin: &str, bytes: &[u8], policy: PinPolicy) -> ContentRef {
    let object = ContentRef::for_bytes(bytes);
    let mut session = store
        .upload(
            &Scope::Owner,
            object,
            Some(PinTarget {
                name: name(pin),
                policy,
            }),
        )
        .await
        .unwrap();
    if !session.complete() {
        let chunks = hellas_xet::chunk(bytes);
        session.declare(&chunks, true).await.unwrap();
        let mut offset = 0;
        for chunk in chunks {
            let end = offset + chunk.data_len as usize;
            session.accept_chunk(&bytes[offset..end]).await.unwrap();
            offset = end;
        }
    }
    assert!(session.complete());
    object
}
async fn remove(store: &MemoryStore, pin: &str) {
    let value = store
        .pins(&Scope::Owner, pin, Cursor::default())
        .await
        .unwrap()
        .pins
        .into_iter()
        .find(|(n, _)| n.as_str() == pin)
        .unwrap()
        .1;
    store
        .set_pin(&Scope::Owner, &name(pin), Some(&value), None)
        .await
        .unwrap();
}
async fn read(
    store: &MemoryStore,
    scope: &Scope,
    path: Path,
    range: std::ops::Range<u64>,
) -> Vec<u8> {
    let mut stream = store.read(scope, &path, range).await.unwrap();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.bytes.next().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    bytes
}

#[tokio::test]
async fn owner_upload_publishes_with_its_pin_and_cancel_releases_reservation() {
    let pool = Reservations::ram(200_000);
    let store = MemoryStore::new(pool.clone());
    let bytes = vec![b'x'; 150_000];
    let object = ContentRef::for_bytes(&bytes);
    let mut session = store
        .upload(
            &Scope::Owner,
            object,
            Some(PinTarget {
                name: name("new"),
                policy: PinPolicy::Public,
            }),
        )
        .await
        .unwrap();
    assert_eq!(pool.held(), object.bytes());
    session
        .declare(&hellas_xet::chunk(&bytes), true)
        .await
        .unwrap();
    assert!(
        store
            .stat(&Scope::Owner, &at("new", ""))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.collect(&Scope::Owner).await.unwrap().objects, 0);
    drop(session);
    assert_eq!(pool.held(), 0);
    assert!(
        store
            .stat(&Scope::Owner, &at("new", ""))
            .await
            .unwrap()
            .is_none()
    );
    put(&store, "new", &bytes, PinPolicy::Public).await;
    assert_eq!(
        read(&store, &Scope::Public, at("new", ""), 130_000..140_000).await,
        bytes[130_000..140_000]
    );
    assert_eq!(pool.held(), object.bytes());
    remove(&store, "new").await;
    assert_eq!(
        store.collect(&Scope::Owner).await.unwrap().bytes,
        object.bytes()
    );
    assert_eq!(pool.held(), 0);
}

#[tokio::test]
async fn private_objects_and_other_scopes_progress_do_not_count_as_missing_answers() {
    let pool = Reservations::ram(10_000);
    let store = MemoryStore::new(pool.clone());
    let payload = b"private payload";
    let object = put(&store, "private", payload, PinPolicy::Owner).await;
    let first = store
        .open_work(job(1, 1), vec![object], object.bytes())
        .await
        .unwrap();
    let second = store
        .open_work(job(2, 1), vec![object], object.bytes())
        .await
        .unwrap();
    let mut one = store.upload(&first, object, None).await.unwrap();
    one.declare(&hellas_xet::chunk(payload), true)
        .await
        .unwrap();
    one.accept_chunk(payload).await.unwrap();
    assert!(one.complete());
    assert_eq!(
        store
            .own_bytes(&first, object)
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        payload
    );
    let two = store.upload(&second, object, None).await.unwrap();
    assert!(!two.complete());
    assert!(
        store
            .stat(&second, &at("private", ""))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .pins(&second, "", Cursor::default())
            .await
            .unwrap()
            .pins
            .is_empty()
    );
    assert_eq!(pool.held(), object.bytes() * 3);
    drop(two);
    drop(one);
    store.end_work(&first).await.unwrap();
    store.end_work(&second).await.unwrap();
    assert_eq!(pool.held(), object.bytes());
}

#[tokio::test]
async fn declared_jobs_and_channel_policy_both_limit_access_and_cas_covers_policy() {
    let store = MemoryStore::new(Reservations::ram(10_000));
    let a = put(&store, "served", b"weight", PinPolicy::Jobs).await;
    let b = put(
        &store,
        "channel",
        b"channel weight",
        PinPolicy::Channel(job(1, 1).channel),
    )
    .await;
    let allowed = store.open_work(job(1, 1), vec![a, b], 100).await.unwrap();
    let other = store.open_work(job(2, 1), vec![a, b], 100).await.unwrap();
    let undeclared = store.open_work(job(1, 2), vec![a], 100).await.unwrap();
    assert!(
        store
            .stat(&allowed, &at("channel", ""))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .stat(&other, &at("channel", ""))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .stat(&undeclared, &at("channel", ""))
            .await
            .unwrap()
            .is_none()
    );
    let old = store
        .pins(&Scope::Owner, "served", Cursor::default())
        .await
        .unwrap()
        .pins[0]
        .1
        .clone();
    let mut wrong = old.clone();
    wrong.policy = PinPolicy::Owner;
    assert!(matches!(
        store
            .set_pin(&Scope::Owner, &name("served"), Some(&wrong), None)
            .await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        store
            .set_pin(&allowed, &name("served"), Some(&old), None)
            .await,
        Err(Error::Denied)
    ));
    assert!(matches!(
        store.collect(&Scope::Public).await,
        Err(Error::Denied)
    ));
    store
        .set_pin(&Scope::Owner, &name("served"), Some(&old), Some(wrong))
        .await
        .unwrap();
    assert!(
        store
            .stat(&allowed, &at("served", ""))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_resolved_tree_with_absent_leaves_does_not_bypass_ram_admission() {
    let pool = Reservations::ram(1024);
    let store = MemoryStore::new(pool.clone());
    let leaf = ContentRef::for_bytes(&vec![7; 2000]);
    let tree = Tree::new(vec![("weights".into(), Target::Object(leaf))]).unwrap();
    let tree_object = put(&store, "metadata", &tree.bytes(), PinPolicy::Owner).await;
    store
        .set_pin(
            &Scope::Owner,
            &name("declared"),
            None,
            Some(PinValue {
                target: Target::Tree(tree_object),
                policy: PinPolicy::Jobs,
                expires: None,
            }),
        )
        .await
        .unwrap();
    assert!(matches!(
        store.open_work(job(1, 1), vec![leaf], leaf.bytes()).await,
        Err(Error::Capacity)
    ));
    assert_eq!(pool.held(), tree_object.bytes());
}

#[tokio::test]
async fn loss_of_a_readable_pin_rechecks_reservation_before_accepting_payload() {
    let pool = Reservations::ram(300);
    let store = MemoryStore::new(pool.clone());
    let object = put(&store, "held", &vec![8; 256], PinPolicy::Jobs).await;
    let scope = store.open_work(job(1, 1), vec![object], 256).await.unwrap();
    assert_eq!(pool.held(), 256);
    remove(&store, "held").await;
    assert!(matches!(
        store.upload(&scope, object, None).await,
        Err(Error::Capacity)
    ));
    assert_eq!(pool.held(), 256);
}

#[tokio::test]
async fn acceptance_transfers_staging_charge_to_live_ram_without_losing_bytes() {
    let pool = Reservations::ram(1000);
    let store = MemoryStore::new(pool.clone());
    let bytes = vec![9; 512];
    let object = ContentRef::for_bytes(&bytes);
    let scope = store.open_work(job(1, 1), vec![object], 512).await.unwrap();
    let mut session = store.upload(&scope, object, None).await.unwrap();
    session
        .declare(&hellas_xet::chunk(&bytes), true)
        .await
        .unwrap();
    session.accept_chunk(&bytes).await.unwrap();
    drop(session);
    assert!(matches!(
        store
            .open_work(job(2, 1), vec![ContentRef::for_bytes(&vec![1; 600])], 600)
            .await,
        Err(Error::Capacity)
    ));
    store.accept_work(&scope).await.unwrap();
    assert_eq!(pool.held(), 0);
    assert_eq!(
        store
            .own_bytes(&scope, object)
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        bytes
    );
    store
        .open_work(job(2, 1), vec![ContentRef::for_bytes(&vec![1; 600])], 600)
        .await
        .unwrap();
    store.end_work(&scope).await.unwrap();
    assert!(store.own_bytes(&scope, object).await.is_err());
}

#[tokio::test]
async fn tree_pins_retain_leaves_and_validate_every_shared_alias_path() {
    let store = MemoryStore::new(Reservations::ram(100_000));
    let leaf = put(&store, "leaf", b"a leaf", PinPolicy::Owner).await;
    let mut tree = Tree::new(vec![("x".repeat(20), Target::Object(leaf))]).unwrap();
    let mut root = put(&store, "tree0", &tree.bytes(), PinPolicy::Owner).await;
    for i in 0..15 {
        tree = Tree::new(vec![("x".repeat(255), Target::Tree(root))]).unwrap();
        root = put(
            &store,
            &format!("tree{}", i + 1),
            &tree.bytes(),
            PinPolicy::Owner,
        )
        .await;
    }
    let alias = Tree::new(vec![
        ("a".repeat(255), Target::Tree(root)),
        ("z".into(), Target::Tree(root)),
    ])
    .unwrap();
    let alias_object = put(&store, "alias-bytes", &alias.bytes(), PinPolicy::Owner).await;
    assert!(
        store
            .set_pin(
                &Scope::Owner,
                &name("invalid"),
                None,
                Some(PinValue {
                    target: Target::Tree(alias_object),
                    policy: PinPolicy::Public,
                    expires: None
                })
            )
            .await
            .is_err()
    );
    assert!(
        store
            .stat(&Scope::Owner, &at("invalid", ""))
            .await
            .unwrap()
            .is_none()
    );
    let small = Tree::new(vec![("leaf".into(), Target::Object(leaf))]).unwrap();
    let small_object = put(&store, "small-bytes", &small.bytes(), PinPolicy::Owner).await;
    store
        .set_pin(
            &Scope::Owner,
            &name("tree"),
            None,
            Some(PinValue {
                target: Target::Tree(small_object),
                policy: PinPolicy::Public,
                expires: None,
            }),
        )
        .await
        .unwrap();
    remove(&store, "leaf").await;
    remove(&store, "small-bytes").await;
    store.collect(&Scope::Owner).await.unwrap();
    assert_eq!(
        read(&store, &Scope::Public, at("tree", "leaf"), 2..5).await,
        b"lea"
    );
}

#[tokio::test]
async fn watch_filters_private_changes_and_resyncs_instead_of_unbounded_history() {
    let store = MemoryStore::new(Reservations::ram(1_000_000));
    let object = put(&store, "object", b"x", PinPolicy::Owner).await;
    let cursor = store
        .pins(&Scope::Owner, "", Cursor::default())
        .await
        .unwrap()
        .cursor;
    let mut watch = store.watch(&Scope::Public, "", cursor).await.unwrap();
    let value = PinValue {
        target: Target::Object(object),
        policy: PinPolicy::Owner,
        expires: None,
    };
    store
        .set_pin(&Scope::Owner, &name("private"), None, Some(value.clone()))
        .await
        .unwrap();
    assert!(watch.next().now_or_never().is_none());
    let public = PinValue {
        policy: PinPolicy::Public,
        ..value.clone()
    };
    store
        .set_pin(&Scope::Owner, &name("visible"), None, Some(public.clone()))
        .await
        .unwrap();
    assert!(
        matches!(watch.next().await.unwrap().unwrap(),PinEvent::Set {name:n,value:Some(_),..} if n.as_str()=="visible")
    );
    store
        .set_pin(
            &Scope::Owner,
            &name("visible"),
            Some(&public),
            Some(value.clone()),
        )
        .await
        .unwrap();
    assert!(matches!(
        watch.next().await.unwrap().unwrap(),
        PinEvent::Resync { .. }
    ));
    let long = name(
        &std::iter::repeat_n("x".repeat(255), 16)
            .collect::<Vec<_>>()
            .join("/"),
    );
    let mut previous = None;
    for _ in 0..300 {
        store
            .set_pin(&Scope::Owner, &long, previous.as_ref(), Some(value.clone()))
            .await
            .unwrap();
        previous = Some(value.clone());
    }
    let mut lagged = store.watch(&Scope::Owner, "", cursor).await.unwrap();
    assert!(matches!(
        lagged.next().await.unwrap().unwrap(),
        PinEvent::Resync { .. }
    ));
    let scope = store.open_work(job(1, 1), vec![object], 100).await.unwrap();
    let mut work_watch = store
        .watch(
            &scope,
            "",
            store
                .pins(&scope, "", Cursor::default())
                .await
                .unwrap()
                .cursor,
        )
        .await
        .unwrap();
    store.end_work(&scope).await.unwrap();
    assert!(matches!(
        work_watch.next().await.unwrap(),
        Err(Error::Denied)
    ));
    assert!(work_watch.next().await.is_none());
}

#[tokio::test]
async fn retained_read_and_upper_handles_keep_their_ram_charge_until_drop() {
    let pool = Reservations::ram(512);
    let store = MemoryStore::new(pool.clone());
    let object = put(&store, "read", &vec![5; 512], PinPolicy::Public).await;
    let mut read = store
        .read(&Scope::Public, &at("read", ""), 0..512)
        .await
        .unwrap();
    let held = read.bytes.next().await.unwrap().unwrap();
    drop(read);
    remove(&store, "read").await;
    store.collect(&Scope::Owner).await.unwrap();
    assert_eq!(pool.held(), 512);
    assert!(matches!(
        store.open_work(job(1, 1), vec![object], 512).await,
        Err(Error::Capacity)
    ));
    drop(held);
    assert_eq!(pool.held(), 0);
    let scope = store.open_work(job(1, 1), vec![object], 512).await.unwrap();
    let mut session = store.upload(&scope, object, None).await.unwrap();
    session
        .declare(&hellas_xet::chunk(&vec![5; 512]), true)
        .await
        .unwrap();
    session.accept_chunk(&vec![5; 512]).await.unwrap();
    drop(session);
    let held = store.own_bytes(&scope, object).await.unwrap().unwrap();
    store.end_work(&scope).await.unwrap();
    assert_eq!(pool.held(), 512);
    drop(held);
    assert_eq!(pool.held(), 0);
}

#[tokio::test]
async fn own_progress_retries_do_not_allocate_again_and_undeclared_metadata_is_hidden() {
    let pool = Reservations::ram(512);
    let store = MemoryStore::new(pool.clone());
    let payload = vec![6; 512];
    let object = ContentRef::for_bytes(&payload);
    let scope = store.open_work(job(1, 1), vec![object], 512).await.unwrap();
    let mut first = store.upload(&scope, object, None).await.unwrap();
    assert!(matches!(
        store.upload(&scope, object, None).await,
        Err(Error::Conflict)
    ));
    first
        .declare(&hellas_xet::chunk(&payload), true)
        .await
        .unwrap();
    first.accept_chunk(&payload).await.unwrap();
    drop(first);
    assert!(store.upload(&scope, object, None).await.unwrap().complete());
    assert_eq!(pool.held(), 512);
    store.end_work(&scope).await.unwrap();
    assert_eq!(pool.held(), 0);
    let served = put(&store, "undeclared", b"secret id", PinPolicy::Jobs).await;
    let scope = store
        .open_work(job(2, 1), vec![ContentRef::for_bytes(b"other")], 100)
        .await
        .unwrap();
    assert!(
        store
            .pins(&scope, "", Cursor::default())
            .await
            .unwrap()
            .pins
            .is_empty()
    );
    assert!(
        store
            .stat(&scope, &at("undeclared", ""))
            .await
            .unwrap()
            .is_none()
    );
    let owner = store
        .pins(&Scope::Owner, "undeclared", Cursor::default())
        .await
        .unwrap()
        .pins[0]
        .1
        .clone();
    store
        .set_pin(
            &Scope::Owner,
            &name("undeclared"),
            Some(&owner),
            Some(PinValue {
                target: Target::Object(served),
                policy: PinPolicy::Public,
                expires: None,
            }),
        )
        .await
        .unwrap();
    let public = store
        .pins(&Scope::Owner, "undeclared", Cursor::default())
        .await
        .unwrap()
        .pins[0]
        .1
        .clone();
    store
        .set_pin(
            &Scope::Owner,
            &name("undeclared"),
            Some(&public),
            Some(owner),
        )
        .await
        .unwrap();
    let mut replay = store
        .watch(&Scope::Public, "", Cursor::default())
        .await
        .unwrap();
    assert!(matches!(
        replay.next().await.unwrap().unwrap(),
        PinEvent::Resync { .. }
    ));
}

#[tokio::test]
async fn globally_pinning_a_private_copy_cannot_reuse_its_ram_for_another_object() {
    let pool = Reservations::ram(12);
    let store = MemoryStore::new(pool.clone());
    let a = put(&store, "a", b"aaaa", PinPolicy::Owner).await;
    let b = put(&store, "b", b"bbbb", PinPolicy::Jobs).await;
    let scope = store.open_work(job(1, 2), vec![a, b], 8).await.unwrap();
    let mut session = store.upload(&scope, a, None).await.unwrap();
    session
        .declare(&hellas_xet::chunk(b"aaaa"), true)
        .await
        .unwrap();
    session.accept_chunk(b"aaaa").await.unwrap();
    let old = store
        .pins(&Scope::Owner, "a", Cursor::default())
        .await
        .unwrap()
        .pins
        .remove(0)
        .1;
    let new = PinValue {
        policy: PinPolicy::Jobs,
        ..old.clone()
    };
    store
        .set_pin(&Scope::Owner, &name("a"), Some(&old), Some(new))
        .await
        .unwrap();
    remove(&store, "b").await;
    assert!(matches!(
        store.upload(&scope, b, None).await,
        Err(Error::Capacity)
    ));
    assert_eq!(pool.held(), 12);
    assert_eq!(
        store.own_bytes(&scope, a).await.unwrap().unwrap().as_ref(),
        b"aaaa"
    );
    store.end_work(&scope).await.unwrap();
    drop(session);
    assert_eq!(pool.held(), 8);
}
