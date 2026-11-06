use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[tokio::test]
async fn live_authority_checks_fresh_time_after_waiting_for_the_store_gate() {
    for lower in [false, true] {
        let mut store = MemoryStore::new(Reservations::ram(1));
        let blocking = if lower {
            let provider = Core::new(Reservations::ram(1));
            let gate = provider.gate.clone();
            store.core.lower = Some((Box::new(provider), BTreeMap::new()));
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
