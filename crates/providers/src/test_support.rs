//! Shared process fixtures for sealed upstream clients.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod operator_interception;
pub use operator_interception::rejects_operator_interception;

/// A fresh private CA and a TLS acceptor serving its `localhost` leaf.
pub fn private_ca_acceptor() -> (
    rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    tokio_rustls::TlsAcceptor,
) {
    use rcgen::*;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Hellas test CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    (
        ca,
        tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)),
    )
}

/// Give a local plaintext HTTP fixture a real private-CA TLS front door.
/// Only the test client trusts that CA; production factories remain unchanged.
pub fn https_forward(
    mut endpoint: reqwest::Url,
    headers: reqwest::header::HeaderMap,
) -> (reqwest::Url, reqwest::Client) {
    use base64::Engine as _;
    let backend = endpoint.socket_addrs(|| None).unwrap()[0];
    let (ca, acceptor) = private_ca_acceptor();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    return;
                };
                let mut plain = tokio::net::TcpStream::connect(backend).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
            });
        }
    });
    endpoint.set_scheme("https").unwrap();
    endpoint.set_host(Some("localhost")).unwrap();
    endpoint.set_port(Some(port)).unwrap();
    let tls = crate::http::tls::config(&hellas_rpc::http_fetch::HttpTls {
        roots: hellas_rpc::http_fetch::HttpTrustRoots::Certificates {
            der_base64: vec![base64::engine::general_purpose::STANDARD.encode(ca.der())],
        },
        spki_sha256: vec![],
    })
    .unwrap();
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .no_proxy()
        .tls_info(true)
        .tls_backend_preconfigured(tls)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    (endpoint, client)
}
