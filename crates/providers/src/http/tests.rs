use super::*;
use hellas_rpc::http_fetch::{HttpTls, HttpTrustRoots};
use hellas_rpc::{Digest, InputCommitment, JsonBytes};
use rcgen::generate_simple_self_signed;
use sha2::{Digest as _, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use x509_cert::der::{Decode as _, Encode as _};

async fn server(
    status: u16,
    bytes: Vec<u8>,
    location: Option<String>,
) -> (
    HttpFetchRequest,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let key = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = key.cert.der().clone();
    let parsed = x509_cert::Certificate::from_der(cert.as_ref()).unwrap();
    let pin = Sha256::digest(
        parsed
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap(),
    )
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect();
    let private = rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], private.into())
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}/resource",
        listener.local_addr().unwrap().port()
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            let bytes = bytes.clone();
            let location = location.clone();
            tokio::spawn(async move {
                let Ok(mut socket) = acceptor.accept(socket).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") && request.len() < 32768 {
                    if socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    request.push(byte[0]);
                }
                seen.fetch_add(1, Ordering::SeqCst);
                let location = location
                    .map(|v| format!("Location: {v}\r\n"))
                    .unwrap_or_default();
                let header = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{location}\r\n",
                    bytes.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(&bytes).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (
        HttpFetchRequest {
            url,
            method: "GET".into(),
            headers: vec![],
            body_base64: String::new(),
            tls: HttpTls {
                roots: HttpTrustRoots::Certificates {
                    der_base64: vec![STANDARD.encode(&cert)],
                },
                spki_sha256: vec![pin],
            },
            credential: None,
            max_response_bytes: 4096,
        },
        calls,
        task,
    )
}

fn provider() -> HttpFetchProvider {
    HttpFetchProvider::new(
        HttpEgressPolicy {
            allowed_hosts: vec!["localhost".into()],
            allow_private_addresses: true,
        },
        BTreeMap::new(),
    )
    .unwrap()
}
fn prepared(request: &HttpFetchRequest) -> PreparedFetchRequest {
    let call = FetchCall::new(
        "http",
        "request",
        JsonBytes::new(serde_json::to_vec(request).unwrap()),
        InputCommitment::from_digest(Digest::from_bytes([1; 32])),
    );
    HttpFetchAdaptorFactory
        .create(&call)
        .unwrap()
        .provider_request
}

#[tokio::test]
async fn custom_roots_and_spki_deliver_exact_binary_bytes() {
    let bytes = vec![0, 255, 1, 13, 10, 128];
    let (request, calls, task) = server(200, bytes.clone(), None).await;
    let mut response = provider().run(prepared(&request)).await.unwrap();
    assert_eq!(response.head.http.as_ref().unwrap().status, 200);
    let mut body = Vec::new();
    while let Some(chunk) = response.stream.next().await {
        body.extend(chunk.unwrap());
    }
    assert_eq!(body, bytes);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn wrong_pin_wrong_roots_and_wrong_hostname_send_no_http_request() {
    let (valid, calls, task) = server(200, b"ok".to_vec(), None).await;
    let mut wrong_pin = valid.clone();
    wrong_pin.tls.spki_sha256 = vec!["00".repeat(32)];
    let mut wrong_root = valid.clone();
    wrong_root.tls.roots = HttpTrustRoots::WebPki;
    let mut wrong_name = valid.clone();
    wrong_name.url = wrong_name.url.replace("localhost", "127.0.0.1");
    let configured = HttpFetchProvider::new(
        HttpEgressPolicy {
            allowed_hosts: vec!["localhost".into(), "127.0.0.1".into()],
            allow_private_addresses: true,
        },
        BTreeMap::new(),
    )
    .unwrap();
    for request in [wrong_pin, wrong_root, wrong_name] {
        assert!(configured.run(prepared(&request)).await.is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    task.abort();
}

#[tokio::test]
async fn redirects_are_returned_without_following_them() {
    let (target, target_calls, target_task) = server(200, b"private".to_vec(), None).await;
    let (origin, origin_calls, origin_task) = server(302, vec![], Some(target.url)).await;
    let response = provider().run(prepared(&origin)).await.unwrap();
    assert_eq!(response.head.http.unwrap().status, 302);
    assert_eq!(origin_calls.load(Ordering::SeqCst), 1);
    assert_eq!(target_calls.load(Ordering::SeqCst), 0);
    origin_task.abort();
    target_task.abort();
}

#[tokio::test]
async fn signed_response_size_and_default_private_address_denial_are_enforced() {
    let (mut request, calls, task) = server(200, vec![42; 100], None).await;
    let public = HttpFetchProvider::new(HttpEgressPolicy::default(), BTreeMap::new()).unwrap();
    assert!(public.run(prepared(&request)).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    request.max_response_bytes = 16;
    let mut response = provider().run(prepared(&request)).await.unwrap();
    assert!(response.stream.next().await.unwrap().is_err());
    task.abort();
}

#[test]
fn credentials_cannot_be_redirected_or_used_with_caller_trust_anchors() {
    let credential = HttpCredential {
        allowed_origins: vec!["https://api.example.com".into()],
        allowed_paths: vec!["/path".into()],
        allowed_methods: vec!["POST".into()],
        header_name: "authorization".into(),
        header_value: "Bearer PRIVATE".into(),
    };
    let provider = HttpFetchProvider::new(
        HttpEgressPolicy::default(),
        BTreeMap::from([("account-1".into(), credential)]),
    )
    .unwrap();
    let mut request = HttpFetchRequest {
        url: "https://api.example.com/path".into(),
        method: "POST".into(),
        headers: vec![],
        body_base64: String::new(),
        tls: HttpTls {
            roots: HttpTrustRoots::WebPki,
            spki_sha256: vec![],
        },
        credential: Some("account-1".into()),
        max_response_bytes: 1024,
    };
    assert!(
        provider
            .credential(&request, &request.parsed_url().unwrap())
            .unwrap()
            .is_some()
    );
    request.method = "DELETE".into();
    assert!(
        provider
            .credential(&request, &request.parsed_url().unwrap())
            .is_err()
    );
    request.method = "POST".into();
    request.url = "https://api.example.com/other".into();
    assert!(
        provider
            .credential(&request, &request.parsed_url().unwrap())
            .is_err()
    );
    request.url = "https://attacker.example/".into();
    assert!(
        provider
            .credential(&request, &request.parsed_url().unwrap())
            .is_err()
    );
    request.url = "https://api.example.com/path".into();
    request.tls.roots = HttpTrustRoots::Certificates { der_base64: vec![] };
    assert!(
        provider
            .credential(&request, &request.parsed_url().unwrap())
            .is_err()
    );
    assert!(!format!("{provider:?}").contains("PRIVATE"));
}

#[test]
fn special_addresses_never_qualify_as_public_egress() {
    for ip in [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "192.0.2.1",
        "198.18.0.1",
        "224.0.0.1",
        "::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "2001:db8::1",
        "2002:7f00:1::",
    ] {
        assert!(!public_address(ip.parse().unwrap()), "{ip}");
    }
    assert!(public_address("8.8.8.8".parse().unwrap()));
    assert!(public_address("2606:4700:4700::1111".parse().unwrap()));
}
