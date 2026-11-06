//! Real owner authentication, generic content framing and concurrent watch delivery.
use futures::StreamExt;
use hellas_auth::authority::GrantId;
use hellas_authority::{
    node::{NodeCoordinator, SessionKey},
    test_support as common,
};
use hellas_channel::test_support::actors::ROOT;
use hellas_rpc::{ContentRef, pb::resolve, services::resolve::ResolveClientImpl};
use hellas_sdk::node_control::{NodeControl, connect_tls, profile};
use hellas_store::content::*;
use std::time::Duration;

#[tokio::test]
async fn owner_content_uses_the_authenticated_providerless_control_connection() {
    let root = tempfile::tempdir().unwrap();
    let clock = common::TestClock::default();
    let (journal, secret) = common::common_node::bootstrap_node_with_credential(
        root.path(),
        common::network(),
        None,
        clock.now(),
    )
    .await
    .unwrap();
    let authority = journal.state().authority().authority();
    let node = NodeCoordinator::new(journal, clock.source());
    let store = common::content_store(root.path()).await;
    let control = NodeControl::new(node.clone()).with_content_store(store.clone());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = profile::server_tls(
        cert.cert.der().clone(),
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    )
    .unwrap();
    let (client_config, name) =
        profile::local_trust(cert.cert.der().clone(), "localhost".into()).unwrap();
    let (client, server_stream) =
        tokio::io::duplex(hellas_wire::transport::DEFAULT_STREAM_WINDOW as usize);
    let serving = tokio::spawn(async move { control.serve_tls(server_stream, server).await });
    let (client, _) = connect_tls(
        client,
        client_config,
        name,
        authority,
        &secret,
        SessionKey::Passkey(&ROOT.passkey()),
    )
    .await
    .unwrap();
    let remote = RemoteStore::new(
        client.transport().clone(),
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
    );
    let bytes = b"owner content with a live authority";
    let object = ContentRef::for_bytes(bytes);
    let pin = PinName::new("rpc/source".into()).unwrap();
    hellas_channel::content::upload_bytes(
        &remote,
        &Scope::Owner,
        bytes,
        Some(PinTarget {
            name: pin.clone(),
            policy: PinPolicy::Owner,
        }),
    )
    .await
    .unwrap();
    let path = Path::new(pin.clone(), String::new()).unwrap();
    assert_eq!(
        remote
            .stat(&Scope::Owner, &path)
            .await
            .unwrap()
            .unwrap()
            .target
            .object(),
        object
    );
    assert!(
        !remote
            .chunks(&Scope::Owner, &path, Default::default())
            .await
            .unwrap()
            .chunks
            .is_empty()
    );
    let mut read = remote
        .read(&Scope::Owner, &path, 0..object.bytes())
        .await
        .unwrap();
    let mut body = Vec::new();
    while let Some(chunk) = read.bytes.next().await {
        body.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(body, bytes);
    let pins = remote
        .pins(&Scope::Owner, "rpc/", Default::default())
        .await
        .unwrap();
    assert_eq!(pins.pins.len(), 1);
    let old = pins.pins[0].1.clone();
    let mut watch = remote
        .watch(&Scope::Owner, "rpc/", pins.cursor)
        .await
        .unwrap();
    assert!(futures::poll!(watch.next()).is_pending());
    remote
        .set_pin(
            &Scope::Owner,
            &pin,
            Some(&old),
            Some(PinValue {
                policy: PinPolicy::Public,
                ..old.clone()
            }),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(10), watch.next())
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
    drop(watch);
    let changed = remote
        .pins(&Scope::Owner, "rpc/", Default::default())
        .await
        .unwrap()
        .pins
        .remove(0)
        .1;
    assert_eq!(changed.policy, PinPolicy::Public);
    remote
        .set_pin(&Scope::Owner, &pin, Some(&changed), None)
        .await
        .unwrap();
    assert!(remote.collect(&Scope::Owner).await.unwrap().objects > 0);
    // Resolve is mounted on the same authenticated connection, with its own operation.
    assert!(
        ResolveClientImpl::new(client.transport().clone())
            .resolve(resolve::ResolveRequest {
                uri: "https://not-an-hf-uri.invalid".into()
            })
            .await
            .is_err()
    );
    // Revoke a credential after declaration; the next local effect must fail.
    let private = b"revoked before payload";
    let mut upload = remote
        .upload(
            &Scope::Owner,
            ContentRef::for_bytes(private),
            Some(PinTarget {
                name: PinName::new("rpc/revoked".into()).unwrap(),
                policy: PinPolicy::Owner,
            }),
        )
        .await
        .unwrap();
    upload
        .declare(&hellas_xet::chunk(private), true)
        .await
        .unwrap();
    let caller = common::session(&node, &secret).await;
    node.revoke_credential(
        &caller,
        GrantId([0; 16]),
        secret.id(),
        hellas_auth::authority::Revision(1),
    )
    .await
    .unwrap();
    assert!(upload.accept_chunk(private).await.is_err());
    drop(upload);
    drop(remote);
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .pins(&Scope::Owner, "rpc/", Default::default())
            .await
            .unwrap()
            .pins
            .len(),
        0
    );
    store.close().await;
}

#[tokio::test]
async fn public_content_is_served_by_the_host_without_a_running_provider() {
    use hellas_rpc::services::content::Content;
    use hellas_sdk::node_control::host::{HostHandle, HostOptions};
    use hellas_wire::{
        ServiceMarker,
        iroh::{Pool, PoolOptions},
    };
    let root = tempfile::tempdir().unwrap();
    let store = common::content_store(root.path()).await;
    let public = PinName::new("published/tokenizer".into()).unwrap();
    let private = PinName::new("private/source".into()).unwrap();
    for (name, policy, body) in [
        (
            public.clone(),
            PinPolicy::Public,
            b"public tokenizer bytes".as_slice(),
        ),
        (
            private.clone(),
            PinPolicy::Owner,
            b"private source bytes".as_slice(),
        ),
    ] {
        hellas_channel::content::upload_bytes(
            &store,
            &Scope::Owner,
            body,
            Some(PinTarget { name, policy }),
        )
        .await
        .unwrap();
    }
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let address = endpoint.addr();
    let host = HostHandle::start(HostOptions {
        content: store.clone(),
        transport: Some(endpoint),
        start_provider: false,
        control: None,
        provider: None,
        gateway: None,
    })
    .await
    .unwrap();
    let client = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let pool = Pool::for_service::<Content>(client.clone(), PoolOptions::default());
    let connection = pool.connection(address).await.unwrap();
    assert_eq!(connection.alpn(), Content::ALPN.as_bytes());
    let remote = RemoteStore::new(
        pool.transport(connection.remote_id()).await.unwrap(),
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
    );
    let pins = remote
        .pins(&Scope::Public, "", Default::default())
        .await
        .unwrap();
    assert_eq!(
        pins.pins.iter().map(|(name, _)| name).collect::<Vec<_>>(),
        [&public]
    );
    let path = Path::new(public.clone(), String::new()).unwrap();
    let mut read = remote.read(&Scope::Public, &path, 7..16).await.unwrap();
    let mut bytes = Vec::new();
    while let Some(chunk) = read.bytes.next().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(bytes, b"tokenizer");
    // Keep a clone made before host startup: startup must attach the pool to
    // the shared store used by all consumers, including this existing handle.
    let recipient = common::content_store(&root.path().join("recipient")).await;
    let lookup = iroh::address_lookup::MemoryLookup::new();
    lookup.add_endpoint_info(host.endpoint().unwrap().addr());
    let recipient_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .address_lookup(lookup)
        .bind()
        .await
        .unwrap();
    let recipient_host = HostHandle::start(HostOptions {
        content: recipient.clone(),
        transport: Some(recipient_endpoint),
        start_provider: false,
        control: None,
        provider: None,
        gateway: None,
    })
    .await
    .unwrap();
    let acquired = recipient
        .acquire(
            &Scope::Owner,
            Source::Peer {
                node: *connection.remote_id().as_bytes(),
                at: path.clone(),
            },
            Some(ContentRef::for_bytes(b"public tokenizer bytes")),
            PinTarget {
                name: public.clone(),
                policy: PinPolicy::Owner,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        acquired.object,
        ContentRef::for_bytes(b"public tokenizer bytes")
    );
    assert!(
        remote
            .stat(&Scope::Owner, &Path::new(private, String::new()).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        remote.collect(&Scope::Owner).await.is_err(),
        "request scope cannot select Owner on the public connection"
    );
    let value = pins.pins[0].1.clone();
    store
        .set_pin(
            &Scope::Owner,
            &public,
            Some(&value),
            Some(PinValue {
                policy: PinPolicy::Owner,
                ..value.clone()
            }),
        )
        .await
        .unwrap();
    assert!(remote.stat(&Scope::Public, &path).await.unwrap().is_none());
    drop(remote);
    pool.shutdown();
    client.close().await;
    host.shutdown().await.unwrap();
    recipient_host.shutdown().await.unwrap();
    recipient.close().await;
    store.close().await;
}

struct UnusedRoot;
impl hellas_sdk::RootProver for UnusedRoot {
    async fn prove_statement(
        &self,
        _: &[u8],
    ) -> std::result::Result<hellas_rpc::RootProof, hellas_sdk::AttestationError> {
        panic!("public content must not request attestation")
    }
    async fn prove_open_binding(
        &self,
        _: hellas_auth::Digest,
    ) -> std::result::Result<hellas_rpc::RootProof, hellas_sdk::AttestationError> {
        panic!("public content must not request attestation")
    }
}

#[tokio::test]
async fn an_open_public_watch_cannot_delay_standalone_provider_shutdown() {
    use hellas_rpc::{Assurance, services::content::Content};
    use hellas_wire::{ServiceMarker, iroh::IrohTransport};
    use std::sync::Arc;
    let root = tempfile::tempdir().unwrap();
    let content = common::content_store(root.path()).await;
    let secret_key = iroh::SecretKey::from_bytes(&[13; 32]);
    let enrollment =
        hellas_channel::test_support::software_enrollment(2, *secret_key.public().as_bytes());
    let signer = Arc::new(hellas_auth::ProducerSigningKey::from_secret_bytes([2; 32]).unwrap());
    let provider = hellas_sdk::start_fetch_provider(hellas_sdk::ProviderOptions {
        executor: hellas_executor::ExecutorSpawnConfig::new(
            signer.clone(),
            Assurance::ProducerSigned,
            Default::default(),
        ),
        content: content.clone(),
        grants: None,
        port: Some(0),
        build: String::new(),
        graffiti: vec![],
        discovery: false,
        work: None,
        secret_key,
        open_identity: Arc::new(
            hellas_sdk::ProviderOpen::<UnusedRoot>::new(signer, enrollment, None).unwrap(),
        ),
    })
    .await
    .unwrap();
    let address = iroh::EndpointAddr::new(provider.node_id()).with_addrs(
        provider
            .bound_sockets()
            .into_iter()
            .filter(|address| address.is_ipv4())
            .map(|mut address| {
                address.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
                iroh::TransportAddr::Ip(address)
            }),
    );
    let client = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let connection = client
        .connect(address, Content::ALPN.as_bytes())
        .await
        .unwrap();
    let remote = RemoteStore::new(
        IrohTransport::new(connection.clone()),
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
    );
    let snapshot = remote
        .pins(&Scope::Public, "public/", Default::default())
        .await
        .unwrap();
    let mut watch = remote
        .watch(&Scope::Public, "public/", snapshot.cursor)
        .await
        .unwrap();
    assert!(futures::poll!(watch.next()).is_pending());
    hellas_channel::content::upload_bytes(
        &content,
        &Scope::Owner,
        b"watch registration",
        Some(PinTarget {
            name: PinName::new("public/probe".into()).unwrap(),
            policy: PinPolicy::Public,
        }),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), watch.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The stream has delivered an event and is still open; do not close its
    // transport or drop the watch before waiting for the real provider stop.
    assert!(futures::poll!(watch.next()).is_pending());
    tokio::time::timeout(Duration::from_secs(10), provider.shutdown())
        .await
        .expect("public watch cannot hold the provider's reply drain")
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(10), watch.next())
            .await
            .unwrap()
            .is_none_or(|event| event.is_err())
    );
    drop(watch);
    drop(remote);
    client.close().await;
    content.close().await;
}
