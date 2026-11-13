//! Explicit caller trust and credentials, using the existing private-file helpers.
//! These files are client configuration; node authority remains in NodeStore.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use super::HostControl;
use hellas_auth::authority::{AuthorityId, CredentialId, CredentialSecret, GrantId};
use hellas_wire::ServiceMarker;
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::*};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const MAX_FILE: u64 = 64 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    authority: AuthorityId,
    authorization: GrantId,
    credential: PathBuf,
    local: Option<LocalTrust>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_node: Option<iroh::EndpointId>,
    /// The addresses the node's invite named; dialed beside discovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    remote_addresses: Vec<std::net::SocketAddr>,
}

#[derive(Deserialize, Serialize)]
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
    /// The transport pin established by an explicit owner pairing, and the
    /// addresses its invite named.
    pub fn remote_node(
        path: &Path,
    ) -> io::Result<Option<(iroh::EndpointId, Vec<std::net::SocketAddr>)>> {
        let profile: ProfileFile = serde_json::from_slice(&read_private(path)?)
            .map_err(|_| invalid("invalid control profile"))?;
        Ok(profile
            .remote_node
            .map(|node| (node, profile.remote_addresses)))
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let profile: ProfileFile = serde_json::from_slice(&read_private(path)?)
            .map_err(|_| invalid("invalid control profile"))?;
        Self::from_file(path, profile)
    }

    fn from_file(path: &Path, profile: ProfileFile) -> io::Result<Self> {
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

/// Retain the independently trusted pairing target beside its new credential.
pub fn pin_remote(
    path: &Path,
    node: iroh::EndpointId,
    addresses: &[std::net::SocketAddr],
) -> io::Result<()> {
    let mut profile: ProfileFile = serde_json::from_slice(&read_private(path)?)
        .map_err(|_| invalid("invalid control profile"))?;
    if profile.local.is_some() || profile.remote_node.is_some_and(|existing| existing != node) {
        return Err(invalid("profile already pins a different server"));
    }
    profile.remote_node = Some(node);
    profile.remote_addresses = addresses.to_vec();
    hellas_private::write_atomically(
        path,
        ".pinning",
        &serde_json::to_vec(&profile).map_err(io::Error::other)?,
    )
}

impl LocalTrust {
    fn load(self, parent: &Path) -> io::Result<(Arc<ClientConfig>, ServerName<'static>)> {
        let certificate =
            CertificateDer::from(read_private(&parent.join(self.certificate))?.to_vec());
        local_trust(certificate, self.server_name)
    }
}

/// Trust exactly one local HostControl server certificate over TLS 1.3.
pub fn local_trust(
    certificate: CertificateDer<'static>,
    server_name: String,
) -> io::Result<(Arc<ClientConfig>, ServerName<'static>)> {
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate)
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
        ServerName::try_from(server_name).map_err(|_| invalid("invalid control server name"))?,
    ))
}

/// Load a provisioned DER certificate and PKCS#8 key from private files.
pub fn server_identity(certificate: &Path, key: &Path) -> io::Result<Arc<ServerConfig>> {
    let certificate = CertificateDer::from(read_private(certificate)?.to_vec());
    let mut key = read_private(key)?;
    server_tls(
        certificate,
        PrivatePkcs8KeyDer::from(std::mem::take(&mut *key)),
    )
}

/// The HostControl TLS 1.3 server identity; ordinary startup generates none.
pub fn server_tls(
    certificate: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
) -> io::Result<Arc<ServerConfig>> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| invalid("TLS 1.3 unavailable"))?
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key.into())
            .map_err(|_| invalid("invalid control TLS identity"))?;
    config.alpn_protocols = vec![HostControl::ALPN.as_bytes().to_vec()];
    Ok(Arc::new(config))
}

fn read_private(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    hellas_private::open_regular_file(path)
        .and_then(|file| hellas_private::read_private_bounded(file, MAX_FILE as usize))
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))
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
    file: tempfile::NamedTempFile,
    path: &Path,
    credential: &CredentialSecret,
) -> io::Result<()> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(48));
    bytes.extend_from_slice(&credential.id().0);
    bytes.extend_from_slice(credential.expose_secret());
    publish_private(file, path, &bytes)
}

/// Durably publish secret-bearing bytes through a private temporary file
/// beside `path`. An existing file is never replaced.
pub fn publish_private(
    mut file: tempfile::NamedTempFile,
    path: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    if !hellas_private::is_private(file.as_file())? {
        return Err(invalid("secret output must be private"));
    }
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|e| e.error)?;
    hellas_private::sync_directory(parent(path))
}

/// Write a remote-only profile and its credential into a new or empty private
/// directory, returning the profile path. Nothing existing is overwritten.
pub fn install_remote(
    directory: &Path,
    authority: AuthorityId,
    authorization: GrantId,
    credential: &CredentialSecret,
) -> io::Result<PathBuf> {
    hellas_private::create_dir_all_durable(directory)?;
    if std::fs::read_dir(directory)?.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "profile directory is not empty",
        ));
    }
    hellas_private::restrict_directory(directory)?;
    let temporary = || hellas_private::private_tempfile(directory, ".profile-", ".writing");
    save_credential(temporary()?, &directory.join("credential"), credential)?;
    let profile = serde_json::to_vec(&ProfileFile {
        authority,
        authorization,
        credential: "credential".into(),
        local: None,
        remote_node: None,
        remote_addresses: vec![],
    })
    .map_err(io::Error::other)?;
    let path = directory.join("profile.json");
    publish_private(temporary()?, &path, &profile)?;
    Ok(path)
}

pub(crate) fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Explicit local HTTP authority. Embedded hosts pass their existing coordinator
/// directly instead of opening its journal a second time.
#[cfg(test)]
mod pin_tests {
    use super::*;

    #[test]
    fn pairing_pin_is_retained_and_cannot_be_silently_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.json");
        let profile = ProfileFile {
            authority: AuthorityId(hellas_auth::Digest::hash(b"paired authority")),
            authorization: GrantId([1; 16]),
            credential: "credential".into(),
            local: None,
            remote_node: None,
            remote_addresses: vec![],
        };
        hellas_private::write_atomically(&path, ".writing", &serde_json::to_vec(&profile).unwrap())
            .unwrap();
        let first = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let second = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let addresses = vec!["127.0.0.1:31145".parse().unwrap()];
        assert_eq!(ClientProfile::remote_node(&path).unwrap(), None);
        pin_remote(&path, first, &addresses).unwrap();
        let pinned = Some((first, addresses.clone()));
        assert_eq!(ClientProfile::remote_node(&path).unwrap(), pinned);
        assert!(pin_remote(&path, second, &[]).is_err());
        assert_eq!(ClientProfile::remote_node(&path).unwrap(), pinned);
    }
}
