use super::{Scope, Source};
use hellas_rpc::{ContentId, ContentRef};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Default)]
pub struct StoreStats {
    pub used: u64,
    pub outstanding: u64,
    pub free: u64,
}
pub struct Miss {
    pub scope: Scope,
    pub object: ContentRef,
}
pub enum MissDecision {
    Refuse,
    Acquire { source: Source },
}
pub trait OnMiss: Send + Sync {
    fn decide(&self, miss: &Miss, stats: &StoreStats) -> MissDecision;
}
pub struct Refuse;
impl OnMiss for Refuse {
    fn decide(&self, _: &Miss, _: &StoreStats) -> MissDecision {
        MissDecision::Refuse
    }
}
pub struct AllowList(pub BTreeMap<ContentId, (u64, Source)>);
impl OnMiss for AllowList {
    fn decide(&self, miss: &Miss, _: &StoreStats) -> MissDecision {
        self.0
            .get(&miss.object.id())
            .filter(|(bytes, _)| *bytes == miss.object.bytes())
            .map_or(MissDecision::Refuse, |(_, source)| MissDecision::Acquire {
                source: source.clone(),
            })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::*;
    use std::{io::Read, sync::Arc};
    fn job() -> JobId {
        JobId {
            channel: hellas_auth::Digest::from_bytes([41; 32]),
            id: hellas_auth::Digest::from_bytes([42; 32]),
        }
    }
    async fn node(root: &std::path::Path, lower: Vec<std::path::PathBuf>) -> DiskStore {
        let node = DiskStore::open(
            root.into(),
            lower,
            IndexMode::Resume,
            None,
            Reservations::ram(8 << 20),
            false,
            Default::default(),
        )
        .await
        .unwrap();
        node.finish_recovery().await.unwrap();
        node
    }
    fn allow(node: &DiskStore, object: ContentRef, url: url::Url) {
        node.set_on_miss(Arc::new(AllowList(BTreeMap::from([(
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
    }
    #[tokio::test]
    async fn the_same_policy_fetches_before_ram_widening_and_releases_work_pins_for_both_uppers() {
        for ephemeral in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let mut node = node(root.path(), vec![]).await;
            let object = ContentRef::for_bytes(b"provider weights");
            let reference = ContentRef::for_bytes(b"root");
            let (url, http, serving) = super::super::acquire::tests::https(b"provider weights");
            node.core.http = http;
            let (local, scope) = if ephemeral {
                let work = JobContent::new(&node, job(), vec![reference], reference.bytes())
                    .await
                    .unwrap();
                let scope = work.scope().clone();
                (LocalStore::Job(work), scope)
            } else {
                let scope = node
                    .open_work(job(), vec![reference], reference.bytes())
                    .await
                    .unwrap();
                (LocalStore::Disk(node.clone()), scope)
            };
            let requested = vec![reference, object];
            assert!(
                local
                    .acquire_missing(&scope, requested.clone())
                    .await
                    .unwrap()
                    .is_empty()
            );
            allow(&node, object, url);
            let wrong = ContentRef::new(object.id(), object.bytes() + 1);
            assert!(
                local
                    .acquire_missing(&scope, vec![reference, wrong])
                    .await
                    .unwrap()
                    .is_empty()
            );
            match &local {
                LocalStore::Job(work) => assert!(matches!(
                    work.widen(requested.clone(), reference.bytes()).await,
                    Err(Error::Capacity)
                )),
                LocalStore::Disk(node) => assert!(matches!(
                    node.widen_work(&scope, requested.clone(), reference.bytes())
                        .await,
                    Err(Error::Capacity)
                )),
                _ => unreachable!(),
            }
            assert_eq!(
                local
                    .acquire_missing(&scope, requested.clone())
                    .await
                    .unwrap(),
                std::collections::BTreeSet::from([object.id()])
            );
            let (local, scope) = match local {
                LocalStore::Job(work) => {
                    let work = work.widen(requested, reference.bytes()).await.unwrap();
                    let scope = work.scope().clone();
                    (LocalStore::Job(work), scope)
                }
                LocalStore::Disk(node) => {
                    let scope = node
                        .widen_work(&scope, requested, reference.bytes())
                        .await
                        .unwrap();
                    (LocalStore::Disk(node), scope)
                }
                _ => unreachable!(),
            };
            let mut reader = local.preflight(&scope, object).await.unwrap().unwrap();
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"provider weights");
            drop(reader);
            let pins = node
                .pins(&Scope::Owner, "work/", Cursor::default())
                .await
                .unwrap()
                .pins;
            assert_eq!(pins.len(), 1);
            assert_eq!(pins[0].1.policy, PinPolicy::Jobs);
            let private_channel = hellas_auth::Digest::from_bytes([43; 32]);
            node.core
                .effect(&Scope::Owner, move |core| {
                    core.publish_acquired(
                        vec![(
                            reference,
                            super::super::storage::Data::Ram(bytes::Bytes::from_static(b"root")),
                            hellas_xet::chunk(b"root"),
                        )],
                        Target::Object(reference),
                        PinTarget {
                            name: PinName::new("channel-private".into())?,
                            policy: PinPolicy::Channel(private_channel),
                        },
                        None,
                    )
                })
                .await
                .unwrap();
            // Same work id on a different channel must independently retain shared content.
            // Admission of a cache hit must retain it without acquire_missing.
            let other = JobContent::new(
                &node,
                JobId {
                    channel: private_channel,
                    ..job()
                },
                vec![reference, object],
                reference.bytes(),
            )
            .await
            .unwrap();
            assert_eq!(
                node.pins(&Scope::Owner, "work/", Cursor::default())
                    .await
                    .unwrap()
                    .pins
                    .len(),
                1
            );
            match local {
                LocalStore::Job(work) => work.end().await.unwrap(),
                LocalStore::Disk(node) => node.end_work(&scope).await.unwrap(),
                _ => unreachable!(),
            };
            assert_eq!(node.collect(&Scope::Owner).await.unwrap().bytes, 0);
            assert!(
                LocalStore::Job(other.clone())
                    .open_verified(other.scope(), object, None)
                    .await
                    .unwrap()
                    .is_some()
            );
            other.end().await.unwrap();
            let private_name = PinName::new("channel-private".into()).unwrap();
            let private = node
                .pins(&Scope::Owner, "channel-private", Cursor::default())
                .await
                .unwrap()
                .pins[0]
                .1
                .clone();
            node.set_pin(&Scope::Owner, &private_name, Some(&private), None)
                .await
                .unwrap();
            assert!(
                node.pins(&Scope::Owner, "work/", Cursor::default())
                    .await
                    .unwrap()
                    .pins
                    .is_empty()
            );
            assert_eq!(node.ram_pool().held(), 0);
            assert_eq!(
                node.collect(&Scope::Owner).await.unwrap().bytes,
                object.bytes() + reference.bytes()
            );
            serving.join().unwrap();
        }
    }
    #[tokio::test]
    async fn preflight_reacquires_an_invalid_lower_through_the_same_policy_without_writing_the_lower()
     {
        let root = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();
        let file = lower.path().join("weights");
        std::fs::write(&file, b"weights").unwrap();
        let mut node = node(root.path(), vec![lower.path().to_owned()]).await;
        let object = ContentRef::for_bytes(b"weights");
        node.set_pin(
            &Scope::Owner,
            &PinName::new("weights".into()).unwrap(),
            None,
            Some(PinValue {
                target: Target::Object(object),
                policy: PinPolicy::Jobs,
                expires: None,
            }),
        )
        .await
        .unwrap();
        let (url, http, serving) = super::super::acquire::tests::https(b"weights");
        node.core.http = http;
        let work = JobContent::new(&node, job(), vec![object], 0)
            .await
            .unwrap();
        allow(&node, object, url);
        std::fs::write(&file, b"changed").unwrap();
        let local = LocalStore::Job(work.clone());
        let mut reader = local
            .preflight(work.scope(), object)
            .await
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"weights");
        drop(reader);
        assert_eq!(std::fs::read(&file).unwrap(), b"changed");
        work.end().await.unwrap();
        assert!(
            node.pins(&Scope::Owner, "work/", Cursor::default())
                .await
                .unwrap()
                .pins
                .is_empty()
        );
        serving.join().unwrap();
    }
    #[tokio::test]
    async fn a_stopped_requester_cannot_publish_after_network_staging_and_the_writer_remains_available()
     {
        let root = tempfile::tempdir().unwrap();
        let mut node = node(root.path(), vec![]).await;
        let object = ContentRef::for_bytes(b"weights");
        let reference = ContentRef::for_bytes(b"root");
        let writer = Arc::new(tokio::sync::Mutex::new(()));
        let (entered, received) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let network_writer = writer.clone();
        let (url, http, serving) =
            super::super::acquire::tests::https_with(b"weights", move || {
                assert!(network_writer.try_lock().is_ok());
                entered.send(()).unwrap();
                wait.recv().unwrap();
            });
        node.core.http = http;
        let work = JobContent::new(&node, job(), vec![reference], reference.bytes())
            .await
            .unwrap();
        allow(&node, object, url);
        let scope = work.scope().clone().bind(
            move || {
                let writer = writer.clone();
                async move {
                    let held = writer.lock_owned().await;
                    Ok(move || {
                        let _ = &held;
                        Ok(())
                    })
                }
            },
            std::future::pending,
        );
        let local = LocalStore::Job(work.clone());
        let fetching =
            tokio::spawn(
                async move { local.acquire_missing(&scope, vec![reference, object]).await },
            );
        received.await.unwrap();
        work.end().await.unwrap();
        release.send(()).unwrap();
        assert!(matches!(fetching.await.unwrap(), Err(Error::Denied)));
        serving.join().unwrap();
        assert!(
            node.pins(&Scope::Owner, "work/", Cursor::default())
                .await
                .unwrap()
                .pins
                .is_empty()
        );
        assert_eq!(node.stats().unwrap().used, 0);
        assert_eq!(node.stats().unwrap().outstanding, 0);
        assert_eq!(node.ram_pool().held(), 0);
    }
    #[tokio::test]
    async fn boot_removes_orphan_acquired_pins_and_keeps_only_restored_work_lifetimes() {
        for restore in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let mut node = node(root.path(), vec![]).await;
            let object = ContentRef::for_bytes(b"weights");
            let reference = ContentRef::for_bytes(b"root");
            let (url, http, serving) = super::super::acquire::tests::https(b"weights");
            node.core.http = http;
            allow(&node, object, url);
            let scope = node
                .open_work(job(), vec![reference], reference.bytes())
                .await
                .unwrap();
            let local = LocalStore::Disk(node.clone());
            local
                .acquire_missing(&scope, vec![reference, object])
                .await
                .unwrap();
            serving.join().unwrap();
            drop(local);
            node.close().await;
            drop(node);
            let node = DiskStore::open(
                root.path().to_owned(),
                vec![],
                IndexMode::Resume,
                None,
                Reservations::ram(8 << 20),
                false,
                Default::default(),
            )
            .await
            .unwrap();
            assert_eq!(
                node.pins(&Scope::Owner, "work/", Cursor::default())
                    .await
                    .unwrap()
                    .pins
                    .len(),
                1
            );
            let restored = if restore {
                Some(
                    node.open_work(
                        JobId {
                            channel: hellas_auth::Digest::from_bytes([43; 32]),
                            ..job()
                        },
                        vec![reference, object],
                        reference.bytes(),
                    )
                    .await
                    .unwrap(),
                )
            } else {
                None
            };
            assert!(matches!(
                node.collect(&Scope::Owner).await,
                Err(Error::Denied)
            ));
            node.finish_recovery().await.unwrap();
            assert_eq!(
                node.pins(&Scope::Owner, "work/", Cursor::default())
                    .await
                    .unwrap()
                    .pins
                    .len(),
                usize::from(restore)
            );
            if let Some(scope) = restored {
                node.end_work(&scope).await.unwrap();
            }
            assert_eq!(
                node.collect(&Scope::Owner).await.unwrap().bytes,
                object.bytes()
            );
            assert_eq!(node.stats().unwrap().outstanding, 0);
        }
    }
    #[tokio::test]
    async fn ending_an_old_ram_scope_cannot_remove_its_replacements_acquired_pin() {
        let root = tempfile::tempdir().unwrap();
        let mut node = node(root.path(), vec![]).await;
        let object = ContentRef::for_bytes(b"weights");
        let reference = ContentRef::for_bytes(b"root");
        let (url, http, serving) = super::super::acquire::tests::https(b"weights");
        node.core.http = http;
        allow(&node, object, url);
        let a = JobContent::new(&node, job(), vec![reference], reference.bytes())
            .await
            .unwrap();
        LocalStore::Job(a.clone())
            .acquire_missing(a.scope(), vec![reference, object])
            .await
            .unwrap();
        serving.join().unwrap();
        a.end().await.unwrap();
        let (url, http, serving) = super::super::acquire::tests::https(b"weights");
        node.core.http = http;
        allow(&node, object, url);
        let b = JobContent::new(&node, job(), vec![reference], reference.bytes())
            .await
            .unwrap();
        LocalStore::Job(b.clone())
            .acquire_missing(b.scope(), vec![reference, object])
            .await
            .unwrap();
        serving.join().unwrap();
        a.end().await.unwrap();
        assert_eq!(
            node.pins(&Scope::Owner, "work/", Cursor::default())
                .await
                .unwrap()
                .pins
                .len(),
            1
        );
        let b = b
            .widen(vec![reference, object], reference.bytes())
            .await
            .unwrap();
        assert!(
            LocalStore::Job(b.clone())
                .open_verified(b.scope(), object, None)
                .await
                .unwrap()
                .is_some()
        );
        b.end().await.unwrap();
        assert!(
            node.pins(&Scope::Owner, "work/", Cursor::default())
                .await
                .unwrap()
                .pins
                .is_empty()
        );
    }
    #[tokio::test]
    async fn a_late_recovery_effect_and_repeated_completion_preserve_live_ram_acquisitions() {
        let root = tempfile::tempdir().unwrap();
        let mut node = node(root.path(), vec![]).await;
        let object = ContentRef::for_bytes(b"weights");
        let (url, http, serving) = super::super::acquire::tests::https(b"weights");
        node.core.http = http;
        allow(&node, object, url);
        let work = JobContent::new(&node, job(), vec![], 0).await.unwrap();
        LocalStore::Job(work.clone())
            .acquire_missing(work.scope(), vec![object])
            .await
            .unwrap();
        serving.join().unwrap();
        // Execute the actual cleanup effect after admission opens, as a delayed
        // concurrent finish can. RAM job scopes live outside the node Core.
        let gate = node.core.gate.clone().lock_owned().await;
        let delayed = node.core.clone();
        let cleanup = tokio::spawn(async move {
            delayed
                .effect(&Scope::Owner, |core| core.clear_orphan_acquired())
                .await
        });
        drop(gate);
        cleanup.await.unwrap().unwrap();
        let (a, b) = tokio::join!(node.finish_recovery(), node.finish_recovery());
        a.unwrap();
        b.unwrap();
        assert_eq!(
            node.pins(&Scope::Owner, "work/", Cursor::default())
                .await
                .unwrap()
                .pins
                .len(),
            1
        );
        work.end().await.unwrap();
        assert!(
            node.pins(&Scope::Owner, "work/", Cursor::default())
                .await
                .unwrap()
                .pins
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_owner_policy_override_during_network_staging_is_checked_again_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let mut node = node(root.path(), vec![]).await;
        let data = b"weights";
        let object = ContentRef::for_bytes(data);
        let mut upload = node
            .upload(
                &Scope::Owner,
                object,
                Some(PinTarget {
                    name: PinName::new("private".into()).unwrap(),
                    policy: PinPolicy::Owner,
                }),
            )
            .await
            .unwrap();
        upload
            .declare(&hellas_xet::chunk(data), true)
            .await
            .unwrap();
        upload.accept_chunk(data).await.unwrap();
        drop(upload);
        let before = node.stats().unwrap().used;
        let (entered, received) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let (url, http, serving) = super::super::acquire::tests::https_with(data, move || {
            entered.send(()).unwrap();
            wait.recv().unwrap();
        });
        node.core.http = http;
        allow(&node, object, url);
        let work = JobContent::new(&node, job(), vec![], 0).await.unwrap();
        let local = LocalStore::Job(work.clone());
        let scope = work.scope().clone();
        let acquiring =
            tokio::spawn(async move { local.acquire_missing(&scope, vec![object]).await });
        received.await.unwrap();
        let name = PinName::new(format!(
            "work/{}/{}/acquired/{}",
            job().channel,
            job().id,
            object.id()
        ))
        .unwrap();
        node.set_pin(
            &Scope::Owner,
            &name,
            None,
            Some(PinValue {
                target: Target::Object(object),
                policy: PinPolicy::Owner,
                expires: None,
            }),
        )
        .await
        .unwrap();
        release.send(()).unwrap();
        assert!(matches!(acquiring.await.unwrap(), Err(Error::Denied)));
        serving.join().unwrap();
        assert_eq!(node.stats().unwrap().used, before);
        assert_eq!(node.stats().unwrap().outstanding, 0);
        assert_eq!(
            node.pins(&Scope::Owner, "work/", Cursor::default())
                .await
                .unwrap()
                .pins[0]
                .1
                .policy,
            PinPolicy::Owner
        );
        work.end().await.unwrap();
    }
}
