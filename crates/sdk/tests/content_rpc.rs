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
