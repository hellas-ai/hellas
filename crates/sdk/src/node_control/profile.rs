//! Explicit caller trust and credentials, using the existing private-file helpers.
//! These files are client configuration; node authority remains in NodeStore.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use super::HostControl;
use hellas_auth::authority::{AuthorityId, CredentialId, CredentialSecret, GrantId};
use hellas_wire::ServiceMarker;
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::*};
use serde::Deserialize;
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const MAX_FILE: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    authority: AuthorityId,
    authorization: GrantId,
    credential: PathBuf,
    local: Option<LocalTrust>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalTrust {
    certificate: PathBuf,
    server_name: String,
}

/// One application's audience, selected grant, secret and independently trusted
/// local server. No profile is discovered or created as a connection side effect.
pub struct ClientProfile {
    pub authority: AuthorityId,
    pub authorization: GrantId,
    pub credential: CredentialSecret,
    pub local: Option<(Arc<ClientConfig>, ServerName<'static>)>,
}

impl ClientProfile {
    pub fn load(path: &Path) -> io::Result<Self> {
        let profile: ProfileFile = serde_json::from_slice(&read_private(path)?)
            .map_err(|_| invalid("invalid control profile"))?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("profile needs a parent"))?;
        Ok(Self {
            authority: profile.authority,
            authorization: profile.authorization,
            credential: read_credential(&parent.join(profile.credential))?,
            local: profile.local.map(|trust| trust.load(parent)).transpose()?,
        })
    }
}

impl LocalTrust {
    fn load(self, parent: &Path) -> io::Result<(Arc<ClientConfig>, ServerName<'static>)> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                read_private(&parent.join(self.certificate))?.to_vec(),
            ))
            .map_err(|_| invalid("invalid control certificate"))?;
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| invalid("TLS 1.3 unavailable"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![HostControl::ALPN.as_bytes().to_vec()];
        Ok((
            Arc::new(tls),
            ServerName::try_from(self.server_name)
                .map_err(|_| invalid("invalid control server name"))?,
        ))
    }
}

/// Provisioned DER certificate and PKCS#8 key; ordinary startup generates neither.
pub fn server_identity(certificate: &Path, key: &Path) -> io::Result<Arc<ServerConfig>> {
    let certificate = CertificateDer::from(read_private(certificate)?.to_vec());
    let mut key = read_private(key)?;
    let key = PrivatePkcs8KeyDer::from(std::mem::take(&mut *key)).into();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| invalid("TLS 1.3 unavailable"))?
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .map_err(|_| invalid("invalid control TLS identity"))?;
    config.alpn_protocols = vec![HostControl::ALPN.as_bytes().to_vec()];
    Ok(Arc::new(config))
}

fn read_private(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    hellas_private::read_private_bounded(
        hellas_private::open_regular_file(path)?,
        MAX_FILE as usize,
    )
}

/// A credential file is exactly its 16-byte ID followed by its 32-byte secret.
pub fn read_credential(path: &Path) -> io::Result<CredentialSecret> {
    let bytes = read_private(path)?;
    if bytes.len() != 48 {
        return Err(invalid("invalid application credential"));
    }
    let id = CredentialId::try_from(&bytes[..16]).map_err(|_| invalid("invalid credential ID"))?;
    let secret = bytes[16..]
        .try_into()
        .map_err(|_| invalid("invalid credential secret"))?;
    Ok(CredentialSecret::from_parts(id, secret))
}

/// Publish a durably issued secret once. Never overwrite another application's
/// credential; a failed publication does not undo the committed node transition.
pub fn save_credential(
    mut file: tempfile::NamedTempFile,
    path: &Path,
    credential: &CredentialSecret,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !hellas_private::is_private(file.as_file())? {
        return Err(invalid("credential output must be private"));
    }
    file.write_all(&credential.id().0)?;
    file.write_all(credential.expose_secret())?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|e| e.error)?;
    hellas_private::sync_directory(parent)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Explicit local HTTP authority. Embedded hosts pass their existing coordinator
/// directly instead of opening its journal a second time.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayProfile {
    pub journal: PathBuf,
    pub authority: AuthorityId,
    pub authorization: GrantId,
    pub credential: PathBuf,
}
impl GatewayProfile {
    pub async fn load(path: &Path) -> hellas_gateway::GatewayResult<hellas_gateway::GatewayAccess> {
        let profile: Self = serde_json::from_slice(&read_private(path)?)
            .map_err(|_| invalid("invalid gateway profile"))?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("profile needs a parent"))?;
        let store = hellas_work::work_store::grant::NodeStore::open(
            &parent.join(profile.journal),
            hellas_work::model::grant::grant_network(),
            None,
            hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
        )
        .await?;
        if store.state().authority().authority() != profile.authority {
            return Err(invalid("gateway profile authority mismatch").into());
        }
        let node = hellas_work::node::NodeCoordinator::new(
            store,
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        );
        hellas_gateway::GatewayAccess::new(
            node,
            profile.authorization,
            read_credential(&parent.join(profile.credential))?,
        )
        .await
    }
}
