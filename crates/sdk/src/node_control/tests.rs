use super::*;
mod admission;
mod authentication;
mod authenticator;
#[cfg(unix)]
mod lifecycle;
mod local;
mod remote;
mod sessions;
use hellas_rpc::authentication::{decode_challenge, encode_response};
use hellas_rpc::protocol::value::decode_dag_cbor;
use hellas_work::model::grant::budget::{Limit, Meter, Window};
use hellas_work::test_support::{
    Actor,
    actors::{OPERATOR, ROOT},
    ids::ROOT_GRANT,
};
use hellas_work::{
    node::{HOST_STATUS, WORK_CAPACITY_CONFIGURE, host_resource, machine_resource},
    work_store::grant::NodeStore,
};
use iroh::{
    Endpoint, EndpointAddr, SecretKey, TransportAddr,
    endpoint::{RecvStream, SendStream, presets},
};
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn authority() -> AuthorityId {
    hellas_work::test_support::authority()
}
fn scope(actor: Actor) -> GrantSpec {
    let authority = authority();
    hellas_work::test_support::common_node::admin_spec(
        authority,
        actor.principal(),
        &[
            (HOST_STATUS, host_resource(authority)),
            (
                hellas_work::node::HOST_PROVIDER_CONFIGURE,
                host_resource(authority),
            ),
            (
                hellas_work::node::HOST_GATEWAY_CONFIGURE,
                host_resource(authority),
            ),
            (
                hellas_work::node::HOST_GATEWAY_ACCESS,
                host_resource(authority),
            ),
            (
                hellas_work::node::HOST_PROVIDER_BIND,
                host_resource(authority),
            ),
            (hellas_work::node::GATEWAY_INVOKE, host_resource(authority)),
            (WORK_CAPACITY_CONFIGURE, machine_resource(authority)),
        ],
        (UnixMillis(1000), UnixMillis(1_000_000)),
        (1_000_000, 8),
        &[],
    )
}
struct Fixture {
    directory: tempfile::TempDir,
    node: NodeCoordinator,
    service: NodeControl,
    secret: CredentialSecret,
}
async fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let world = hellas_work::test_support::Node::bootstrap(directory.path())
        .with_provider(crate::test_support::provider_enrollment())
        .build()
        .await;
    let secret = world.secret(ROOT);
    let secret = CredentialSecret::from_parts(secret.id(), *secret.expose_secret());
    let node = NodeCoordinator::new(world.store, world.clock.source());
    Fixture {
        service: NodeControl::new(node.clone()).with_remote_admission(
            RemoteControlAdmission::new(vec![SecretKey::from_bytes(&[62; 32]).public()]).unwrap(),
        ),
        directory,
        node,
        secret,
    }
}
async fn pair() -> (Endpoint, Endpoint, Connection, Connection) {
    let server = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[61; 32]))
        .alpns(vec![HostControl::ALPN.as_bytes().to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let target = EndpointAddr::from_parts(
        server.id(),
        server.bound_sockets().into_iter().map(TransportAddr::Ip),
    );
    let client = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[62; 32]))
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let (client_connection, server_connection) = tokio::join!(
        client.connect(target, HostControl::ALPN.as_bytes()),
        async {
            server
                .accept()
                .await
                .unwrap()
                .accept()
                .unwrap()
                .await
                .unwrap()
        }
    );
    (
        client,
        server,
        client_connection.unwrap(),
        server_connection,
    )
}
fn serve(
    service: &NodeControl,
    connection: Connection,
) -> tokio::task::JoinHandle<Result<(), WireStatus>> {
    let service = service.clone();
    tokio::spawn(async move { service.serve_iroh(connection).await })
}

fn read_request(grant: GrantId) -> GetHostStatusRequest {
    GetHostStatusRequest {
        authorization: grant.0.to_vec(),
    }
}
async fn rejected(task: tokio::task::JoinHandle<Result<(), WireStatus>>) {
    let error = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, WireCode::PermissionDenied);
}

fn tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = super::profile::server_tls(
        cert.cert.der().clone(),
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    )
    .unwrap();
    let (client, name) =
        super::profile::local_trust(cert.cert.der().clone(), "localhost".into()).unwrap();
    assert_eq!(
        name,
        rustls::pki_types::ServerName::try_from("localhost").unwrap()
    );
    (server, client)
}
fn tls_configs_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(crypto.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(crypto)
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    server.alpn_protocols = vec![HostControl::ALPN.as_bytes().to_vec()];
    client.alpn_protocols = server.alpn_protocols.clone();
    (Arc::new(server), Arc::new(client))
}
