//! Read the peer certificate from the completed TLS connection, never from
//! response headers or operator configuration.
use hellas_executor::FetchProviderError;
use hellas_rpc::upstream::{UpstreamPeer, UpstreamPolicy};
use sha2::{Digest as _, Sha256};
use x509_cert::der::{Decode as _, Encode as _};

pub(crate) fn require_host(
    policy: Option<&UpstreamPolicy>,
    endpoint: &reqwest::Url,
) -> Result<(), FetchProviderError> {
    if endpoint.scheme() != "https" {
        return Err(FetchProviderError::failed("upstream must use HTTPS"));
    }
    if let Some(policy) = policy {
        policy
            .permits_host(
                endpoint
                    .host_str()
                    .ok_or_else(|| FetchProviderError::failed("missing upstream hostname"))?,
            )
            .map_err(FetchProviderError::failed)?;
    }
    Ok(())
}

pub(crate) fn observed_peer(
    response: &reqwest::Response,
) -> Result<UpstreamPeer, FetchProviderError> {
    let fail = || FetchProviderError::failed("upstream TLS peer certificate missing or invalid");
    let der = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .ok_or_else(fail)?;
    let cert = x509_cert::Certificate::from_der(der).map_err(|_| fail())?;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|_| fail())?;
    let digest = Sha256::digest(spki);
    Ok(UpstreamPeer {
        host: response.url().host_str().ok_or_else(fail)?.into(),
        spki_sha256: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
    })
}
