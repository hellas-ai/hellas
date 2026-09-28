use hellas_rpc::http_fetch::{HttpTls, HttpTrustRoots, decode_base64, decode_pin};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use x509_cert::der::{Decode as _, Encode as _};

pub(super) fn config(settings: &HttpTls) -> Result<rustls::ClientConfig, &'static str> {
    settings.validate().map_err(|_| "invalid TLS settings")?;
    let mut roots = rustls::RootCertStore::empty();
    match &settings.roots {
        HttpTrustRoots::WebPki => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        HttpTrustRoots::Certificates { der_base64 } => {
            for der in der_base64 {
                let bytes = decode_base64(der).map_err(|_| "invalid trust anchor")?;
                roots
                    .add(CertificateDer::from(bytes))
                    .map_err(|_| "invalid trust anchor")?;
            }
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let chain = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| "invalid trust anchors")?;
    let pins = settings
        .spki_sha256
        .iter()
        .map(|pin| decode_pin(pin))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid SPKI pins")?;
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "TLS versions unavailable")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { chain, pins }))
        .with_no_client_auth())
}

#[derive(Debug)]
struct PinnedVerifier {
    chain: Arc<WebPkiServerVerifier>,
    pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Pins are additional constraints: they never bypass chain, validity,
        // hostname, or the handshake proof of possession.
        let verified = self
            .chain
            .verify_server_cert(leaf, intermediates, name, ocsp, now)?;
        if !self.pins.is_empty() {
            let cert = x509_cert::Certificate::from_der(leaf.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
            let spki = cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|_| {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                })?;
            let digest: [u8; 32] = Sha256::digest(spki).into();
            if !self.pins.contains(&digest) {
                return Err(rustls::Error::General("SPKI pin mismatch".into()));
            }
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.chain.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.chain.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.chain.supported_verify_schemes()
    }
}
