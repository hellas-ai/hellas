//! Explicit caller trust and credentials, using the existing private-file helpers.
//! These files are client configuration; node authority remains in NodeStore.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use super::HostControl;
use hellas_auth::authority::{AuthorityId, CredentialId, CredentialSecret, GrantId};
use hellas_private::StoreLocation;
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
    /// The transport pin established by an explicit owner pairing.
    pub fn remote_node(path: &Path) -> io::Result<Option<iroh::EndpointId>> {
        let profile: ProfileFile = serde_json::from_slice(&read_private(path)?)
            .map_err(|_| invalid("invalid control profile"))?;
        Ok(profile.remote_node)
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
pub fn pin_remote(path: &Path, node: iroh::EndpointId) -> io::Result<()> {
    let mut profile: ProfileFile = serde_json::from_slice(&read_private(path)?)
        .map_err(|_| invalid("invalid control profile"))?;
    if profile.local.is_some() || profile.remote_node.is_some_and(|existing| existing != node) {
        return Err(invalid("profile already pins a different server"));
    }
    profile.remote_node = Some(node);
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayProfile {
    pub journal: PathBuf,
    pub authority: AuthorityId,
    pub authorization: GrantId,
    pub credential: PathBuf,
    /// Optional local HostControl on this writer, so credentials can be issued
    /// and revoked while the gateway runs. Omit it to serve no administration.
    pub control: Option<GatewayControl>,
}

/// Private socket and independently provisioned TLS identity for local control.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayControl {
    pub socket: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

/// HTTP admission and, when configured, the control listener sharing its writer.
/// Shut the listener down after the gateway stops.
pub struct GatewayHost {
    /// The same live authority writer used by HTTP admission and HostControl.
    pub node: hellas_authority::node::NodeCoordinator,
    pub access: hellas_gateway::GatewayAccess,
    pub control: Option<hellas_wire::local::LocalControlServer>,
}

impl GatewayProfile {
    pub async fn load(path: &StoreLocation) -> hellas_gateway::GatewayResult<GatewayHost> {
        let profile: Self = serde_json::from_slice(&read_private(path)?)
            .map_err(|_| invalid("invalid gateway profile"))?;
        let parent = path.child(
            path.parent()
                .ok_or_else(|| invalid("profile needs a parent"))?,
        );
        let store = hellas_authority::work_store::grant::NodeStore::open(
            &parent.child(profile.journal),
            hellas_authority::model::grant::grant_network(),
            None,
            hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
        )
        .await?;
        if store.state().authority().authority() != profile.authority {
            return Err(invalid("gateway profile authority mismatch").into());
        }
        let node = hellas_authority::node::NodeCoordinator::new(
            store,
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        );
        let access = hellas_gateway::GatewayAccess::new(
            node.clone(),
            profile.authorization,
            read_credential(&parent.join(profile.credential))?,
        )
        .await?;
        let control = profile
            .control
            .map(|control| {
                let tls = server_identity(
                    &parent.join(control.certificate),
                    &parent.join(control.private_key),
                )?;
                super::NodeControl::new(node.clone()).bind_local(parent.join(control.socket), tls)
            })
            .transpose()?;
        Ok(GatewayHost {
            node,
            access,
            control,
        })
    }
}

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
        };
        hellas_private::write_atomically(&path, ".writing", &serde_json::to_vec(&profile).unwrap())
            .unwrap();
        let first = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let second = iroh::SecretKey::from_bytes(&[2; 32]).public();
        assert_eq!(ClientProfile::remote_node(&path).unwrap(), None);
        pin_remote(&path, first).unwrap();
        assert_eq!(ClientProfile::remote_node(&path).unwrap(), Some(first));
        assert!(pin_remote(&path, second).is_err());
        assert_eq!(ClientProfile::remote_node(&path).unwrap(), Some(first));
    }
}
