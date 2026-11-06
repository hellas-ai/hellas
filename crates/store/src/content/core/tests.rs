use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[tokio::test]
async fn live_authority_checks_fresh_time_after_waiting_for_the_store_gate() {
    for lower in [false, true] {
        let mut store = MemoryStore::new(Reservations::ram(1));
        let blocking = if lower {
            let provider = Core::new(Reservations::ram(1));
            let gate = provider.gate.clone();
            store.core.lower = Some(Box::new(provider));
            gate
        } else {
            store.core.gate.clone()
        };
        let gate = blocking.lock().await;
        let writer = Arc::new(tokio::sync::Mutex::new(()));
        let time = Arc::new(AtomicU64::new(1000));
        let acquired = Arc::new(tokio::sync::Notify::new());
        let scope = {
            let writer = writer.clone();
            let time = time.clone();
            let acquired = acquired.clone();
            Scope::Owner.bind(
                move || {
                    let writer = writer.clone();
                    let time = time.clone();
                    let acquired = acquired.clone();
                    async move {
                        let held = writer.lock_owned().await;
                        acquired.notify_one();
                        Ok(move || {
                            let _held = &held;
                            if time.load(Ordering::SeqCst) < 1100 {
                                Ok(())
                            } else {
                                Err(Error::Denied)
                            }
                        })
                    }
                },
                std::future::pending(),
            )
        };
        let reading = store.clone();
        let task = tokio::spawn(async move {
            reading
                .stat(
                    &scope,
                    &Path::new(PinName::new("absent".into()).unwrap(), String::new()).unwrap(),
                )
                .await
        });
        acquired.notified().await;
        assert!(writer.try_lock().is_err());
        time.store(1100, Ordering::SeqCst);
        drop(gate);
        assert!(matches!(task.await.unwrap(), Err(Error::Denied)));
        assert!(writer.try_lock().is_ok());
    }
}

#[tokio::test]
async fn lower_admission_walks_a_shared_large_tree_once_for_the_whole_closure() {
    use std::sync::atomic::Ordering;
    let provider = MemoryStore::new(Reservations::ram((MAX_TREE_BYTES * 2) as u64));
    let mut closure = Vec::new();
    let mut entries = Vec::new();
    {
        let mut state = provider.core.state.lock().unwrap();
        for index in 0..MAX_TREE_ENTRIES {
            let bytes = Bytes::copy_from_slice(&(index as u64).to_be_bytes());
            let object = ContentRef::for_bytes(&bytes);
            state.objects.insert(
                object.id(),
                Arc::new(Stored::new(
                    super::super::storage::Data::Ram(bytes.clone()),
                    hellas_xet::chunk(&bytes),
                )),
            );
            closure.push(object);
            entries.push((index.to_string(), Target::Object(object)));
        }
    }
    let bytes = Tree::new(entries).unwrap().bytes();
    let root = ContentRef::for_bytes(&bytes);
    let mut upload = provider
        .upload(
            &Scope::Owner,
            root,
            Some(PinTarget {
                name: PinName::new("shared".into()).unwrap(),
                policy: PinPolicy::Jobs,
            }),
        )
        .await
        .unwrap();
    let chunks = hellas_xet::chunk(&bytes);
    upload.declare(&chunks, true).await.unwrap();
    let mut offset = 0;
    for chunk in chunks {
        let end = offset + chunk.data_len as usize;
        upload.accept_chunk(&bytes[offset..end]).await.unwrap();
        offset = end;
    }
    let old = PinValue {
        target: Target::Object(root),
        policy: PinPolicy::Jobs,
        expires: None,
    };
    let tree = PinValue {
        target: Target::Tree(root),
        ..old.clone()
    };
    provider
        .set_pin(
            &Scope::Owner,
            &PinName::new("shared".into()).unwrap(),
            Some(&old),
            Some(tree.clone()),
        )
        .await
        .unwrap();
    provider
        .set_pin(
            &Scope::Owner,
            &PinName::new("alias".into()).unwrap(),
            None,
            Some(tree),
        )
        .await
        .unwrap();
    let before = provider
        .core
        .state
        .lock()
        .unwrap()
        .tree_reads
        .load(Ordering::Relaxed);
    let mut upper = Core::new(Reservations::ram(1));
    upper.lower = Some(Box::new(provider.core.clone()));
    let scope = upper
        .access(&Scope::Owner, move |core| {
            core.open_work(
                JobId {
                    channel: hellas_auth::Digest::ZERO,
                    id: hellas_auth::Digest::ZERO,
                },
                closure,
                0,
            )
        })
        .await
        .unwrap();
    let after = provider
        .core
        .state
        .lock()
        .unwrap()
        .tree_reads
        .load(Ordering::Relaxed);
    assert_eq!(after - before, 1);
    upper
        .access(&Scope::Owner, move |core| core.end_work(&scope))
        .await
        .unwrap();
}
