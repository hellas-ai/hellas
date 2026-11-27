use hellas_rpc::ContentRef;
use hellas_store::content::*;
fn pin() -> PinTarget {
    PinTarget {
        name: PinName::new("acquired".into()).unwrap(),
        policy: PinPolicy::Owner,
    }
}
#[tokio::test]
async fn untrusted_scopes_cannot_acquire_and_invalid_sources_never_reserve() {
    let pool = Reservations::ram(1024);
    let store = MemoryStore::new(pool.clone());
    let source = Source::Https {
        url: "https://example.invalid/file".parse().unwrap(),
        sha256: None,
        bytes: Some(1),
    };
    assert!(matches!(
        store.acquire(&Scope::Public, source, None, pin()).await,
        Err(Error::Denied)
    ));
    for url in [
        "http://example.invalid/file",
        "https://user:password@example.invalid/file",
        "https://example.invalid/file#fragment",
    ] {
        assert!(
            store
                .acquire(
                    &Scope::Owner,
                    Source::Https {
                        url: url.parse().unwrap(),
                        sha256: None,
                        bytes: Some(1)
                    },
                    None,
                    pin()
                )
                .await
                .is_err()
        );
    }
    let repo = hellas_store::hf::Repo {
        id: "org/repo".into(),
        revision: "main".into(),
        default_branch: false,
        kind: hellas_store::hf::RepoKind::Model,
    };
    assert!(
        store
            .acquire(
                &Scope::Owner,
                Source::HfXet { repo, path: None },
                None,
                pin()
            )
            .await
            .is_err()
    );
    assert_eq!(pool.held(), 0);
}
#[tokio::test]
async fn incorrect_declared_length_fails_before_starting_a_source() {
    let pool = Reservations::ram(1024);
    let store = MemoryStore::new(pool.clone());
    let source = Source::Https {
        url: "https://example.invalid/file".parse().unwrap(),
        sha256: None,
        bytes: Some(7),
    };
    assert!(
        store
            .acquire(
                &Scope::Owner,
                source,
                Some(ContentRef::for_bytes(b"short")),
                pin()
            )
            .await
            .is_err()
    );
    assert_eq!(pool.held(), 0);
    assert!(
        store
            .pins(&Scope::Owner, "", Cursor::default())
            .await
            .unwrap()
            .pins
            .is_empty()
    );
}

mod support;
#[tokio::test]
async fn peer_acquisition_fetches_a_verified_tree_and_leaves_by_path_without_partial_pins() {
    use hellas_rpc::services::content::{Content, ContentServer};
    use hellas_wire::{
        Dispatcher, ServiceMarker, StreamTransport,
        iroh::{IrohTransport, Pool, PoolOptions},
    };
    use std::collections::BTreeMap;
    use support::{File, Fixture, Handler, Mode};
    let weights = File::new(b"weights".to_vec(), false);
    let tokenizer = File::new(b"{}".to_vec(), false);
    let directory = File::new(
        Tree::new(vec![("model.bin".into(), Target::Object(weights.object))])
            .unwrap()
            .bytes(),
        true,
    );
    let root = File::new(
        Tree::new(vec![
            ("tokenizer.json".into(), Target::Object(tokenizer.object)),
            ("weights".into(), Target::Tree(directory.object)),
        ])
        .unwrap()
        .bytes(),
        true,
    );
    let fixture = Fixture::new(
        BTreeMap::from([
            (String::new(), root.clone()),
            ("weights".into(), directory),
            ("weights/model.bin".into(), weights),
            ("tokenizer.json".into(), tokenizer),
        ]),
        Mode::Good,
    );
    async fn serve(
        fixture: std::sync::Arc<Fixture>,
    ) -> (iroh::Endpoint, tokio::task::JoinHandle<()>) {
        let server = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .alpns(vec![Content::ALPN.as_bytes().to_vec()])
            .bind()
            .await
            .unwrap();
        let endpoint = server.clone();
        let serving = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let fixture = fixture.clone();
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    let transport = IrohTransport::new(connection);
                    while let Ok(Some(stream)) = transport.accept().await {
                        let service = ContentServer(Handler(fixture.clone()));
                        tokio::spawn(async move {
                            let _ = Dispatcher::<IrohTransport>::dispatch(&service, stream).await;
                        });
                    }
                });
            }
        });
        (server, serving)
    }
    let incomplete = Fixture::new(BTreeMap::from([(String::new(), root.clone())]), Mode::Good);
    let (first, incomplete_task) = serve(incomplete.clone()).await;
    let (server, serving) = serve(fixture).await;
    let client = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let peers = Pool::for_service::<Content>(client.clone(), PoolOptions::default());
    let pool = Reservations::ram(8 << 20);
    let store = MemoryStore::new(pool.clone()).with_peers(peers);
    let source = Source::Peer {
        id: root.object.id(),
        seeds: vec![first.addr(), server.addr()],
    };
    let got = store
        .acquire(
            &Scope::Owner,
            source.clone(),
            Some(root.object),
            PinTarget {
                name: PinName::new("peer".into()).unwrap(),
                policy: PinPolicy::Public,
            },
        )
        .await
        .unwrap();
    assert_eq!(got.object, root.object);
    assert!(incomplete.reads.load(std::sync::atomic::Ordering::Relaxed) > 0);
    let mut read = store
        .read(
            &Scope::Public,
            &Path::new(
                PinName::new("peer".into()).unwrap(),
                "weights/model.bin".into(),
            )
            .unwrap(),
            0..7,
        )
        .await
        .unwrap();
    use futures::StreamExt;
    assert_eq!(
        read.bytes.next().await.unwrap().unwrap().as_ref(),
        b"weights"
    );
    drop(read);
    let held = pool.held();
    assert!(
        store
            .acquire(
                &Scope::Owner,
                source,
                Some(ContentRef::for_bytes(b"wrong")),
                PinTarget {
                    name: PinName::new("failed".into()).unwrap(),
                    policy: PinPolicy::Owner
                }
            )
            .await
            .is_err()
    );
    assert_eq!(pool.held(), held);
    assert!(
        store
            .stat(
                &Scope::Owner,
                &Path::new(PinName::new("failed".into()).unwrap(), String::new()).unwrap()
            )
            .await
            .unwrap()
            .is_none()
    );
    let alias = PinName::new("peer".into()).unwrap();
    let canonical = PinName::object(root.object.id());
    for name in [alias, canonical] {
        let old = owner_pin(&store, &name).await.unwrap().unwrap();
        store
            .set_pin(&Scope::Owner, &name, Some(&old), None)
            .await
            .unwrap();
    }
    assert_eq!(store.collect(&Scope::Owner).await.unwrap().objects, 4);
    assert_eq!(pool.held(), 0);
    drop(store);
    client.close().await;
    server.close().await;
    first.close().await;
    incomplete_task.abort();
    serving.abort();
}
