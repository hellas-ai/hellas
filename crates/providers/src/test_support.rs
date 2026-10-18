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
