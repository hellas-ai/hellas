//! One behavioral suite over RAM, disk, and the actual RPC adapter over disk.
//! Private fixture origins stay test-only; the product gains no CA/config knob.
use super::acquire::tests::{framed, https, hub};
use super::*;
use bytes::Bytes;
use futures::StreamExt;
use hellas_auth::Digest;
use hellas_rpc::{
    ContentRef,
    services::content::{Content, ContentServer},
};
use hellas_wire::{
    Dispatcher, ServiceMarker, StreamTransport, TransportContext,
    clock::DefaultClock,
    mux::{MessagePipe, MuxConfig, MuxTransport, Role},
};
use prost::Message;
use std::sync::{Arc, Mutex};

struct Pipe(
    tokio::sync::mpsc::UnboundedSender<Bytes>,
    tokio::sync::mpsc::UnboundedReceiver<Bytes>,
);
impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;
    async fn send_message(&mut self, bytes: Bytes) -> std::io::Result<()> {
        self.0.send(bytes).map_err(std::io::Error::other)
    }
    async fn recv_message(&mut self) -> std::io::Result<Option<Bytes>> {
        Ok(self.1.recv().await)
    }
}
fn mux<S: ContentStore + 'static>(store: Arc<S>, scope: Scope) -> MuxTransport {
    let (a_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
    let client = MuxTransport::spawn::<8, _, _>(
        Role::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe(a_tx, b_rx),
        TransportContext::default(),
    );
    let server = MuxTransport::spawn::<8, _, _>(
        Role::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe(b_tx, a_rx),
        TransportContext::default(),
    );
    let service = ContentService::new(store, scope);
    tokio::spawn(async move {
        while let Ok(Some(inbound)) = server.accept().await {
            let service = service.clone();
            tokio::spawn(async move {
                let _ = <ContentServer<ContentService<S>> as Dispatcher<MuxTransport>>::dispatch(
                    &ContentServer(service),
                    inbound,
                )
                .await;
            });
        }
    });
    client
}
enum Backend {
    Ram(MemoryStore),
    Disk(DiskStore),
    Rpc(DiskStore),
}
struct Case {
    backend: Backend,
    remotes: Mutex<Vec<Arc<RemoteStore<MuxTransport>>>>,
}
impl Case {
    fn core(&self) -> &core::Core {
        match &self.backend {
            Backend::Ram(s) => &s.core,
            Backend::Disk(s) | Backend::Rpc(s) => &s.core,
        }
    }
    fn core_mut(&mut self) -> &mut core::Core {
        match &mut self.backend {
            Backend::Ram(s) => &mut s.core,
            Backend::Disk(s) | Backend::Rpc(s) => &mut s.core,
        }
    }
    fn client(&self, scope: Scope) -> Arc<dyn ContentStore> {
        match &self.backend {
            Backend::Ram(store) => Arc::new(store.clone()),
            Backend::Disk(store) => Arc::new(store.clone()),
            Backend::Rpc(store) => {
                let client = Arc::new(RemoteStore::new(
                    mux(Arc::new(store.clone()), scope),
                    self.core().pool.clone(),
                ));
                self.remotes.lock().unwrap().push(client.clone());
                client
            }
        }
    }
    async fn work(&self, job: JobId, closure: Closure, bytes: u64) -> Scope {
        match &self.backend {
            Backend::Ram(s) => s.open_work(job, closure, bytes).await.unwrap(),
            Backend::Disk(s) | Backend::Rpc(s) => s.open_work(job, closure, bytes).await.unwrap(),
        }
    }
    async fn end(&self, scope: &Scope) {
        match &self.backend {
            Backend::Ram(s) => s.end_work(scope).await.unwrap(),
            Backend::Disk(s) | Backend::Rpc(s) => s.end_work(scope).await.unwrap(),
        }
    }
    async fn close(&self) {
        let clients = std::mem::take(&mut *self.remotes.lock().unwrap());
        for client in clients {
            client.finish_uploads().await.unwrap();
        }
        if let Backend::Disk(s) | Backend::Rpc(s) = &self.backend {
            s.close().await;
        }
    }
}
fn name(s: &str) -> PinName {
    PinName::new(s.into()).unwrap()
}
fn at(pin: &str, path: &str) -> Path {
    Path::new(name(pin), path.into()).unwrap()
}
fn pin(s: &str, policy: PinPolicy) -> PinTarget {
    PinTarget {
        name: name(s),
        policy,
    }
}
async fn put(
    store: &dyn ContentStore,
    scope: &Scope,
    bytes: &[u8],
    pin: Option<PinTarget>,
) -> ContentRef {
    let object = ContentRef::for_bytes(bytes);
    let mut session = store.upload(scope, object, pin).await.unwrap();
    if !session.complete() {
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
    }
    assert!(session.complete());
    object
}
async fn read(
    store: &dyn ContentStore,
    scope: &Scope,
    at: &Path,
    range: std::ops::Range<u64>,
) -> Vec<u8> {
    let mut stream = store.read(scope, at, range).await.unwrap();
    let mut out = Vec::new();
    while let Some(bytes) = stream.bytes.next().await {
        out.extend_from_slice(&bytes.unwrap());
    }
    out
}
async fn remove(store: &dyn ContentStore, key: &str) {
    let page = store
        .pins(&Scope::Owner, key, Cursor::default())
        .await
        .unwrap();
    let value = page
        .pins
        .into_iter()
        .find(|(name, _)| name.as_str() == key)
        .unwrap()
        .1;
    store
        .set_pin(&Scope::Owner, &name(key), Some(&value), None)
        .await
        .unwrap();
}
async fn suite(mut case: Case) {
    let owner = case.client(Scope::Owner);
    let public = case.client(Scope::Public);
    let data = vec![17; hellas_xet::MAX_CHUNK_SIZE + hellas_xet::MIN_CHUNK_SIZE + 1];
    let object = put(
        owner.as_ref(),
        &Scope::Owner,
        &data,
        Some(pin("owner", PinPolicy::Owner)),
    )
    .await;
    assert!(
        public
            .stat(&Scope::Public, &at("owner", ""))
            .await
            .unwrap()
            .is_none()
    );
    let value = PinValue {
        target: Target::Object(object),
        policy: PinPolicy::Public,
        expires: None,
    };
    owner
        .set_pin(&Scope::Owner, &name("public"), None, Some(value.clone()))
        .await
        .unwrap();
    assert_eq!(
        read(
            public.as_ref(),
            &Scope::Public,
            &at("public", ""),
            (hellas_xet::MIN_CHUNK_SIZE - 1) as u64..(hellas_xet::MAX_CHUNK_SIZE + 1) as u64
        )
        .await,
        data[hellas_xet::MIN_CHUNK_SIZE - 1..hellas_xet::MAX_CHUNK_SIZE + 1]
    );
    let empty = put(
        owner.as_ref(),
        &Scope::Owner,
        b"",
        Some(pin("empty", PinPolicy::Public)),
    )
    .await;
    assert_eq!(empty.bytes(), 0);
    assert!(
        read(public.as_ref(), &Scope::Public, &at("empty", ""), 0..0)
            .await
            .is_empty()
    );
    assert!(
        owner
            .set_pin(&Scope::Owner, &name("public"), None, None)
            .await
            .is_err()
    );
    let tree = Tree::new(vec![
        ("file".into(), Target::Object(object)),
        ("empty".into(), Target::Object(empty)),
    ])
    .unwrap();
    let tree_ref = put(
        owner.as_ref(),
        &Scope::Owner,
        &tree.bytes(),
        Some(pin("tree", PinPolicy::Public)),
    )
    .await;
    let old = PinValue {
        target: Target::Object(tree_ref),
        policy: PinPolicy::Public,
        expires: None,
    };
    let tree_value = PinValue {
        target: Target::Tree(tree_ref),
        ..old.clone()
    };
    owner
        .set_pin(&Scope::Owner, &name("tree"), Some(&old), Some(tree_value))
        .await
        .unwrap();
    assert_eq!(
        read(public.as_ref(), &Scope::Public, &at("tree", "file"), 1..7).await,
        &data[1..7]
    );
    assert!(
        owner
            .stat(
                &Scope::Owner,
                &Path {
                    pin: name("tree"),
                    path: "x".repeat(MAX_PATH_BYTES + 1),
                }
            )
            .await
            .is_err()
    );
    let mut child = Target::Object(empty);
    let mut deep_names = Vec::new();
    for depth in 0..=MAX_PATH_BYTES / (MAX_NAME_BYTES + 1) {
        let bytes = Tree::new(vec![("x".repeat(MAX_NAME_BYTES), child)])
            .unwrap()
            .bytes();
        let key = format!("path-limit/{depth}");
        let object = put(
            owner.as_ref(),
            &Scope::Owner,
            &bytes,
            Some(pin(&key, PinPolicy::Owner)),
        )
        .await;
        child = Target::Tree(object);
        deep_names.push(key);
    }
    let old = PinValue {
        target: Target::Object(child.object()),
        policy: PinPolicy::Owner,
        expires: None,
    };
    assert!(
        owner
            .set_pin(
                &Scope::Owner,
                &name(deep_names.last().unwrap()),
                Some(&old),
                Some(PinValue {
                    target: child,
                    ..old.clone()
                })
            )
            .await
            .is_err()
    );
    for key in deep_names {
        remove(owner.as_ref(), &key).await;
    }
    let bound = public
        .chunks(
            &Scope::Public,
            &at("public", ""),
            Cursor {
                object: Some(object),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(bound.object, object);
    owner
        .set_pin(
            &Scope::Owner,
            &name("public"),
            Some(&value),
            Some(PinValue {
                target: Target::Object(empty),
                ..value.clone()
            }),
        )
        .await
        .unwrap();
    assert!(
        public
            .chunks(
                &Scope::Public,
                &at("public", ""),
                Cursor {
                    object: Some(object),
                    offset: 1,
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    assert!(public.collect(&Scope::Public).await.is_err());
    assert!(
        public
            .pins(&Scope::Public, "", Cursor::default())
            .await
            .unwrap()
            .pins
            .iter()
            .all(|(_, value)| value.policy == PinPolicy::Public)
    );
    // Expiration removes visibility and the GC root, without a timer task.
    owner
        .set_pin(
            &Scope::Owner,
            &name("expired"),
            None,
            Some(PinValue {
                expires: Some(hellas_auth::authority::UnixMillis(0)),
                ..value.clone()
            }),
        )
        .await
        .unwrap();
    assert!(
        public
            .stat(&Scope::Public, &at("expired", ""))
            .await
            .unwrap()
            .is_none()
    );
    let grant_scope = Scope::grant(GrantHandle {
        grant: hellas_auth::authority::GrantId([4; 16]),
        pin: name("granted"),
    });
    let granted = case.client(grant_scope.clone());
    for key in ["granted", "another-granted"] {
        owner
            .set_pin(
                &Scope::Owner,
                &name(key),
                None,
                Some(PinValue {
                    policy: PinPolicy::Granted,
                    ..value.clone()
                }),
            )
            .await
            .unwrap();
    }
    assert!(
        granted
            .stat(&grant_scope, &at("granted", ""))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        granted
            .stat(&grant_scope, &at("another-granted", ""))
            .await
            .unwrap()
            .is_none()
    );
    assert!(granted.collect(&grant_scope).await.is_err());
    assert!(granted.upload(&grant_scope, object, None).await.is_err());
    // Valid hashes for an arbitrary partition still fail canonical CDC checks.
    let noncanonical = vec![17; hellas_xet::MIN_CHUNK_SIZE * 2];
    let split = hellas_xet::MIN_CHUNK_SIZE;
    let chunks = [
        hellas_xet::Chunk::new(hellas_xet::chunk_hash(&noncanonical[..split]), split as u64),
        hellas_xet::Chunk::new(hellas_xet::chunk_hash(&noncanonical[split..]), split as u64),
    ];
    assert_ne!(chunks.as_slice(), hellas_xet::chunk(&noncanonical));
    let fake = ContentRef::new(
        hellas_rpc::ContentId::from_bytes(hellas_xet::file_hash(&chunks).into_bytes()),
        noncanonical.len() as u64,
    );
    let mut bad = owner
        .upload(
            &Scope::Owner,
            fake,
            Some(pin("noncanonical", PinPolicy::Public)),
        )
        .await
        .unwrap();
    bad.declare(&chunks, true).await.unwrap();
    let first = bad.accept_chunk(&noncanonical[..split]).await;
    let rejected = first.is_err() || bad.accept_chunk(&noncanonical[split..]).await.is_err();
    assert!(rejected && !bad.complete());
    drop(bad);
    assert!(
        owner
            .stat(&Scope::Owner, &at("noncanonical", ""))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        public
            .set_pin(
                &Scope::Public,
                &name("forbidden"),
                None,
                Some(value.clone())
            )
            .await
            .is_err()
    );
    let job = JobId {
        channel: Digest::from_bytes([1; 32]),
        id: Digest::from_bytes([2; 32]),
    };
    let scope = case.work(job, vec![object], object.bytes()).await;
    let worker = case.client(scope.clone());
    assert!(
        worker
            .stat(&scope, &at("owner", ""))
            .await
            .unwrap()
            .is_none()
    );
    owner
        .set_pin(
            &Scope::Owner,
            &name("channel"),
            None,
            Some(PinValue {
                target: Target::Object(object),
                policy: PinPolicy::Channel(job.channel),
                expires: None,
            }),
        )
        .await
        .unwrap();
    assert!(
        worker
            .stat(&scope, &at("channel", ""))
            .await
            .unwrap()
            .is_some()
    );
    let other = case
        .work(
            JobId {
                channel: Digest::from_bytes([3; 32]),
                id: job.id,
            },
            vec![object],
            object.bytes(),
        )
        .await;
    let foreign = case.client(other.clone());
    assert!(
        foreign
            .stat(&other, &at("channel", ""))
            .await
            .unwrap()
            .is_none()
    );
    assert!(worker.collect(&scope).await.is_err());
    assert!(
        worker
            .acquire(
                &scope,
                Source::Https {
                    url: "https://example.invalid/file".parse().unwrap(),
                    sha256: None,
                    bytes: 1
                },
                None,
                pin("bad", PinPolicy::Owner)
            )
            .await
            .is_err()
    );
    // One completed private upload counts only for its own live Work scope.
    let private_bytes = b"private unaccepted payload";
    let private = ContentRef::for_bytes(private_bytes);
    let private_scope = case
        .work(
            JobId {
                id: Digest::from_bytes([5; 32]),
                ..job
            },
            vec![private],
            private.bytes(),
        )
        .await;
    let private_client = case.client(private_scope.clone());
    put(private_client.as_ref(), &private_scope, private_bytes, None).await;
    assert!(
        private_client
            .upload(&private_scope, private, None)
            .await
            .unwrap()
            .complete()
    );
    let isolated_scope = case
        .work(
            JobId {
                id: Digest::from_bytes([6; 32]),
                ..job
            },
            vec![private],
            private.bytes(),
        )
        .await;
    let isolated = case.client(isolated_scope.clone());
    let mut missing = isolated
        .upload(&isolated_scope, private, None)
        .await
        .unwrap();
    assert!(!missing.complete());
    missing
        .declare(&hellas_xet::chunk(private_bytes), true)
        .await
        .unwrap();
    case.end(&isolated_scope).await;
    assert!(missing.accept_chunk(private_bytes).await.is_err());
    assert!(!missing.complete());
    drop(missing);
    case.end(&private_scope).await;
    case.end(&scope).await;
    case.end(&other).await;
    let public_only = put(
        owner.as_ref(),
        &Scope::Owner,
        b"public outside job policy",
        Some(pin("public-only", PinPolicy::Public)),
    )
    .await;
    let local = case
        .work(
            JobId {
                id: Digest::from_bytes([7; 32]),
                ..job
            },
            vec![public_only],
            public_only.bytes(),
        )
        .await;
    let worker = case.client(local.clone());
    assert!(
        worker
            .stat(&local, &at("public-only", ""))
            .await
            .unwrap()
            .is_none()
    );
    let missing = worker.upload(&local, public_only, None).await.unwrap();
    assert!(!missing.complete());
    drop(missing);
    let old = PinValue {
        target: Target::Object(public_only),
        policy: PinPolicy::Public,
        expires: None,
    };
    owner
        .set_pin(
            &Scope::Owner,
            &name("public-only"),
            Some(&old),
            Some(PinValue {
                policy: PinPolicy::Jobs,
                ..old.clone()
            }),
        )
        .await
        .unwrap();
    assert!(
        worker
            .stat(&local, &at("public-only", ""))
            .await
            .unwrap()
            .is_some()
    );
    case.end(&local).await;
    remove(owner.as_ref(), "public-only").await;
    // A late watch from an old snapshot must resync after one real body window.
    let mut watch_names = Vec::new();
    let from = public
        .pins(&Scope::Public, "watch/", Cursor::default())
        .await
        .unwrap()
        .cursor;
    let mut encoded = 0usize;
    while encoded <= hellas_wire::mux::DEFAULT_STREAM_WINDOW as usize {
        let prefix = format!("watch/{encoded}/");
        let long = format!(
            "{prefix}{}",
            vec!["x"; (MAX_PATH_BYTES - prefix.len()) / 2].join("/")
        );
        let new = PinValue {
            target: Target::Object(empty),
            policy: PinPolicy::Public,
            expires: Some(hellas_auth::authority::UnixMillis(
                u64::MAX - encoded as u64,
            )),
        };
        owner
            .set_pin(&Scope::Owner, &name(&long), None, Some(new.clone()))
            .await
            .unwrap();
        encoded += hellas_rpc::pb::content::WatchPinsResponse {
            cursor: None,
            pin: Some(wire::pin(&name(&long), &new)),
            removed: false,
            resync: false,
        }
        .encoded_len();
        watch_names.push(long);
    }
    let first = public
        .pins(&Scope::Public, "watch/", Cursor::default())
        .await
        .unwrap();
    let next = first
        .next
        .expect("the actual encoded list exceeds one body");
    let rest = public.pins(&Scope::Public, "watch/", next).await.unwrap();
    assert_eq!(first.pins.len() + rest.pins.len(), watch_names.len());
    assert!(rest.next.is_none());
    let changed = PinValue {
        target: Target::Object(empty),
        policy: PinPolicy::Public,
        expires: None,
    };
    owner
        .set_pin(&Scope::Owner, &name("watch/new"), None, Some(changed))
        .await
        .unwrap();
    watch_names.push("watch/new".into());
    assert!(public.pins(&Scope::Public, "watch/", next).await.is_err());
    let mut events = public.watch(&Scope::Public, "watch/", from).await.unwrap();
    assert!(matches!(
        events.next().await.unwrap().unwrap(),
        PinEvent::Resync { .. }
    ));
    drop(events);
    // Both transport-SHA and canonical-ID mismatches leave no pin.
    for (key, sha256, expect) in [
        ("https", None, None),
        ("bad-sha", Some([0; 32]), None),
        (
            "bad-id",
            None,
            Some(ContentRef::new(
                hellas_rpc::ContentId::from_bytes([0; 32]),
                16,
            )),
        ),
    ] {
        let (url, http, serving) = https(b"cold HTTPS bytes");
        case.core_mut().http = http;
        let client = case.client(Scope::Owner);
        let source = Source::Https {
            url,
            sha256,
            bytes: 16,
        };
        let result = client
            .acquire(&Scope::Owner, source, expect, pin(key, PinPolicy::Public))
            .await;
        serving.join().unwrap();
        if key != "https" {
            assert!(result.is_err());
            assert!(
                client
                    .stat(&Scope::Owner, &at(key, ""))
                    .await
                    .unwrap()
                    .is_none()
            );
        } else {
            assert_eq!(
                result.unwrap().object,
                ContentRef::for_bytes(b"cold HTTPS bytes")
            );
            assert_eq!(
                read(client.as_ref(), &Scope::Owner, &at("https", ""), 0..16).await,
                b"cold HTTPS bytes"
            );
        }
    }
    let sha = "a".repeat(40);
    let weights = ContentRef::for_bytes(b"weights");
    let xorb = hellas_xet::XetHash::ZERO;
    let frame = framed(b"weights");
    let (base, serving) = hub(|base| {
        vec![
        (format!("/api/models/org/repo/tree/{sha}?recursive=true"),200,serde_json::json!([{"type":"file","path":"tokenizer.json","size":2},{"type":"file","path":"weights.bin","size":7,"xetHash":weights.id().to_string()}]).to_string().into_bytes()),
        (format!("/org/repo/resolve/{sha}/tokenizer.json"),200,b"{}".to_vec()),
        (format!("/api/models/org/repo/xet-read-token/{sha}"),200,format!("{{\"accessToken\":\"t\",\"casUrl\":\"{base}\"}}").into_bytes()),
        (format!("/v2/reconstructions/{}",weights.id()),200,serde_json::json!({"terms":[{"hash":xorb.to_string(),"range":{"start":0,"end":1},"unpacked_length":7}],"xorbs":{xorb.to_string():[{"url":format!("{base}/xorb"),"ranges":[{"chunks":{"start":0,"end":1},"bytes":{"start":0,"end":frame.len()-1}}]}]}}).to_string().into_bytes()),
        ("/xorb".into(),206,frame),
    ]
    });
    case.core_mut().hf_hub = Some(base);
    let client = case.client(Scope::Owner);
    let root = client
        .acquire(
            &Scope::Owner,
            Source::HfXet {
                repo: crate::hf::Repo {
                    id: "org/repo".into(),
                    kind: crate::hf::RepoKind::Model,
                    revision: sha.clone(),
                },
                commit: sha,
                path: None,
            },
            None,
            pin("hf", PinPolicy::Public),
        )
        .await
        .unwrap();
    serving.join().unwrap();
    assert!(root.object.bytes() > 0);
    assert_eq!(
        read(
            client.as_ref(),
            &Scope::Owner,
            &at("hf", "weights.bin"),
            0..7
        )
        .await,
        b"weights"
    );
    // Peer source speaks the actual adapter and transport too.
    let source = Arc::new(MemoryStore::new(Reservations::ram(32 << 20)));
    put(
        source.as_ref(),
        &Scope::Owner,
        b"peer bytes",
        Some(pin("peer-source", PinPolicy::Public)),
    )
    .await;
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
            let source = source.clone();
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let transport = hellas_wire::iroh::IrohTransport::new(connection);
                while let Ok(Some(inbound)) = transport.accept().await {
                    let service = ContentService::new(source.clone(), Scope::Public);
                    tokio::spawn(async move {
                        let _ = <ContentServer<ContentService<MemoryStore>> as Dispatcher<
                            hellas_wire::iroh::IrohTransport,
                        >>::dispatch(
                            &ContentServer(service), inbound
                        )
                        .await;
                    });
                }
            });
        }
    });
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let pool = hellas_wire::iroh::Pool::for_service::<Content>(
        endpoint.clone(),
        hellas_wire::iroh::PoolOptions::default(),
    );
    pool.connection(server.addr()).await.unwrap();
    case.core_mut().peers = Some(pool);
    let client = case.client(Scope::Owner);
    let got = client
        .acquire(
            &Scope::Owner,
            Source::Peer {
                node: *server.id().as_bytes(),
                at: at("peer-source", ""),
            },
            Some(ContentRef::for_bytes(b"peer bytes")),
            pin("peer", PinPolicy::Public),
        )
        .await
        .unwrap();
    assert_eq!(got.object, ContentRef::for_bytes(b"peer bytes"));
    assert_eq!(
        read(client.as_ref(), &Scope::Owner, &at("peer", ""), 0..10).await,
        b"peer bytes"
    );
    endpoint.close().await;
    server.close().await;
    serving.abort();
    // Tree reachability protects the payload after its direct pin disappears.
    remove(owner.as_ref(), "owner").await;
    assert_eq!(
        read(public.as_ref(), &Scope::Public, &at("tree", "file"), 0..4).await,
        &data[..4]
    );
    for key in [
        "public",
        "tree",
        "channel",
        "empty",
        "https",
        "hf",
        "peer",
        "granted",
        "another-granted",
    ] {
        remove(owner.as_ref(), key).await;
    }
    for key in watch_names {
        remove(owner.as_ref(), &key).await;
    }
    assert!(owner.collect(&Scope::Owner).await.unwrap().objects > 0);
    case.close().await;
}
#[tokio::test]
async fn memory() {
    suite(Case {
        backend: Backend::Ram(MemoryStore::new(Reservations::ram(32 << 20))),
        remotes: Mutex::new(vec![]),
    })
    .await;
}
#[tokio::test]
async fn disk() {
    let root = tempfile::tempdir().unwrap();
    let store = DiskStore::open(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
    )
    .await
    .unwrap();
    store.finish_recovery().await.unwrap();
    suite(Case {
        backend: Backend::Disk(store),
        remotes: Mutex::new(vec![]),
    })
    .await;
}
#[tokio::test]
async fn rpc_disk() {
    let root = tempfile::tempdir().unwrap();
    let store = DiskStore::open(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
    )
    .await
    .unwrap();
    store.finish_recovery().await.unwrap();
    suite(Case {
        backend: Backend::Rpc(store),
        remotes: Mutex::new(vec![]),
    })
    .await;
}
