//! One-shot owner bootstrap on the normal, independently pinned node transport.
//! The pairing secret is delivered through the authenticated machine console.
use super::*;
use hellas_rpc::ProviderEnrollmentBundle;
use hellas_work::work_store::grant::{NodeStore, PreparedBootstrap};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::Path};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

const VERSION: u8 = 2;
const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;
const MAX_PAIRING_ATTEMPTS: usize = 8;
pub const PAIRING_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// Public pin and one-use pairing material. Obtain this whole document through
/// the provider's authenticated console, never through an untrusted lookup.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub node: iroh::EndpointId,
    pub addresses: Vec<SocketAddr>,
    pub pairing: [u8; 32],
    pub expires: UnixMillis,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    pairing: [u8; 32],
    root: GrantId,
    approval: PreparedBootstrap,
}

impl Invitation {
    pub fn create(endpoint: &iroh::Endpoint, now: UnixMillis) -> Result<Self, WireStatus> {
        use rand::Rng;
        let mut pairing = [0; 32];
        rand::rng().fill_bytes(&mut pairing);
        Ok(Self {
            node: endpoint.id(),
            addresses: endpoint.addr().ip_addrs().copied().collect(),
            pairing,
            expires: UnixMillis(
                now.0
                    .checked_add(PAIRING_LIFETIME.as_millis() as u64)
                    .ok_or_else(invalid)?,
            ),
        })
    }
}

/// The caller transfers the already-bound normal node endpoint into HostHandle
/// after success, preserving its pin and direct addresses without rebinding.
/// The store itself decides whether initialization is allowed; no receipt file
/// can reset an existing authority. Accepted writes finish despite disconnection.
pub async fn accept(
    endpoint: &iroh::Endpoint,
    invitation: &Invitation,
    directory: &Path,
    network: hellas_kernel::NetworkId,
    provider: Option<ProviderEnrollmentBundle>,
) -> Result<(), WireStatus> {
    let now = UnixMillis::now().map_err(|_| unavailable())?;
    let remaining = invitation.expires.0.checked_sub(now.0).ok_or_else(denied)?;
    if remaining == 0
        || remaining > PAIRING_LIFETIME.as_millis() as u64
        || endpoint.id() != invitation.node
    {
        return Err(denied());
    }
    let deadline = Instant::now() + Duration::from_millis(remaining);
    for _ in 0..MAX_PAIRING_ATTEMPTS {
        let incoming = tokio::time::timeout_at(deadline, endpoint.accept())
            .await
            .map_err(|_| denied())?
            .ok_or_else(unavailable)?;
        let request =
            tokio::time::timeout_at(deadline.min(Instant::now() + HANDSHAKE_TIMEOUT), async {
                let connection = incoming
                    .accept()
                    .map_err(|_| denied())?
                    .await
                    .map_err(|_| denied())?;
                let close = CloseConnection(Some(connection.clone()));
                if connection.alpn() != HostControl::ALPN.as_bytes() {
                    return Err(denied());
                }
                let (mut send, mut recv) = connection.accept_bi().await.map_err(|_| denied())?;
                if recv.read_u8().await.map_err(|_| denied())? != VERSION {
                    return Err(denied());
                }
                let length = recv.read_u32().await.map_err(|_| denied())? as usize;
                if length == 0 || length > MAX_BOOTSTRAP_BYTES {
                    return Err(invalid());
                }
                let mut bytes = Zeroizing::new(vec![0; length]);
                recv.read_exact(&mut bytes).await.map_err(|_| denied())?;
                let request: Request =
                    decode_bounded(&bytes, MAX_BOOTSTRAP_BYTES).map_err(|_| invalid())?;
                if !bool::from(request.pairing.ct_eq(&invitation.pairing)) {
                    return Err(denied());
                }
                let now = UnixMillis::now().map_err(|_| unavailable())?;
                if now.0 >= invitation.expires.0 {
                    return Err(denied());
                }
                // Keep transport and stream alive while the durable commit completes.
                send.flush().await.map_err(|_| denied())?;
                Ok::<_, WireStatus>((close, send, request, now))
            })
            .await;
        let Ok(Ok((_close, mut send, request, now))) = request else {
            tracing::warn!("owner bootstrap admission refused");
            continue;
        };
        let store = NodeStore::bootstrap_prepared(
            directory,
            network,
            request.root,
            request.approval,
            provider.clone(),
            now,
        )
        .await
        .map_err(node_error)?;
        // Authority has committed. A lost acknowledgement is recovered by normal
        // authentication with the credential the owner saved before submission.
        let _ = send.write_all(&[VERSION]).await;
        let _ = send.finish();
        let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, send.stopped()).await;
        drop(store);
        tracing::info!("owner bootstrap committed");
        return Ok(());
    }
    tracing::warn!("owner bootstrap pairing attempts exhausted");
    Err(denied())
}

/// Only verifiers cross the wire. Save the corresponding credential before this
/// call; after a lost reply authenticate normally and inspect its exact ID.
pub async fn connect(
    endpoint: &iroh::Endpoint,
    invitation: &Invitation,
    root: GrantId,
    approval: PreparedBootstrap,
) -> Result<(), WireStatus> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let now = UnixMillis::now().map_err(|_| unavailable())?;
        if now.0 >= invitation.expires.0 || invitation.addresses.len() > 16 {
            return Err(denied());
        }
        let address = invitation.addresses.iter().fold(
            iroh::EndpointAddr::new(invitation.node),
            |address, socket| address.with_ip_addr(*socket),
        );
        let connection = endpoint
            .connect(address, HostControl::ALPN.as_bytes())
            .await
            .map_err(|_| denied())?;
        let _close = CloseConnection(Some(connection.clone()));
        let (mut send, mut recv) = connection.open_bi().await.map_err(|_| denied())?;
        let request = Request {
            pairing: invitation.pairing,
            root,
            approval,
        };
        let bytes = Zeroizing::new(canonical_dag_cbor(&request).map_err(|_| invalid())?);
        if bytes.len() > MAX_BOOTSTRAP_BYTES {
            return Err(invalid());
        }
        send.write_u8(VERSION).await.map_err(|_| unavailable())?;
        send.write_u32(bytes.len() as u32)
            .await
            .map_err(|_| unavailable())?;
        send.write_all(&bytes).await.map_err(|_| unavailable())?;
        send.finish().map_err(|_| unavailable())?;
        if tokio::time::timeout(HANDSHAKE_TIMEOUT, recv.read_u8())
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?
            != VERSION
        {
            return Err(denied());
        }
        Ok(())
    })
    .await
    .map_err(|_| unavailable())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_work::test_support::{actors::ROOT, common_node};
    async fn endpoints() -> (iroh::Endpoint, iroh::Endpoint) {
        let server = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![HostControl::ALPN.as_bytes().to_vec()])
            .bind()
            .await
            .unwrap();
        let client = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        (server, client)
    }
    fn prepared() -> (GrantId, PreparedBootstrap, CredentialSecret) {
        let root = hellas_work::test_support::ids::ROOT_GRANT;
        let scope = common_node::admin_spec(
            hellas_work::test_support::authority(),
            ROOT.principal(),
            &[],
            (UnixMillis(0), UnixMillis(u64::MAX)),
            (u64::MAX, 8),
            &[],
        );
        let approval =
            common_node::approval_for(Ownership::Bootstrap { root }, scope.clone(), scope.clone());
        let (credential, secret) =
            Credential::prepare(scope, CredentialHolder::Node(approval.holder), 1).unwrap();
        (
            root,
            PreparedBootstrap {
                administrator: approval.administrator,
                credential,
                assertion: approval.assertion,
            },
            secret,
        )
    }
    #[tokio::test]
    async fn pairing_commits_the_saved_credential_and_cannot_be_replayed() {
        let directory = tempfile::tempdir().unwrap();
        let (server, client) = endpoints().await;
        let invitation = Invitation::create(&server, UnixMillis::now().unwrap()).unwrap();
        let (root, approval, secret) = prepared();
        let (server_result, client_result) = tokio::join!(
            accept(
                &server,
                &invitation,
                directory.path(),
                hellas_work::test_support::network(),
                None
            ),
            connect(&client, &invitation, root, approval.clone()),
        );
        server_result.unwrap();
        client_result.unwrap();
        let node = NodeCoordinator::new(
            NodeStore::open(
                directory.path(),
                hellas_work::test_support::network(),
                None,
                UnixMillis::now().unwrap(),
            )
            .await
            .unwrap(),
            Arc::new(|| UnixMillis::now().unwrap()),
        );
        node.authenticate_session(&secret, SessionKey::Passkey(&ROOT.passkey()))
            .await
            .unwrap();
        drop(node);
        assert!(
            NodeStore::bootstrap_prepared(
                directory.path(),
                hellas_work::test_support::network(),
                root,
                approval,
                None,
                UnixMillis::now().unwrap()
            )
            .await
            .is_err()
        );
        client.close().await;
        server.close().await;
    }
    #[tokio::test]
    async fn wrong_pairing_exhausts_the_invitation_without_creating_authority() {
        let directory = tempfile::tempdir().unwrap();
        let (server, client) = endpoints().await;
        let invitation = Invitation::create(&server, UnixMillis::now().unwrap()).unwrap();
        let mut wrong: Invitation =
            serde_json::from_slice(&serde_json::to_vec(&invitation).unwrap()).unwrap();
        wrong.pairing[0] ^= 1;
        let (root, approval, _) = prepared();
        let (result, ()) = tokio::join!(
            accept(
                &server,
                &invitation,
                directory.path(),
                hellas_work::test_support::network(),
                None
            ),
            async {
                for _ in 0..MAX_PAIRING_ATTEMPTS {
                    assert!(
                        connect(&client, &wrong, root, approval.clone())
                            .await
                            .is_err()
                    );
                }
            },
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        client.close().await;
        server.close().await;
    }
    #[tokio::test]
    async fn replacement_invitation_refuses_old_secret_and_prebootstrap_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let (server, client) = endpoints().await;
        let old = Invitation::create(&server, UnixMillis::now().unwrap()).unwrap();
        let current = Invitation::create(&server, UnixMillis::now().unwrap()).unwrap();
        assert_ne!(old.pairing, current.pairing);
        let (root, approval, secret) = prepared();
        let (result, ()) = tokio::join!(
            accept(
                &server,
                &current,
                directory.path(),
                hellas_work::test_support::network(),
                None
            ),
            async {
                let connection = client
                    .connect(server.addr(), HostControl::ALPN.as_bytes())
                    .await
                    .unwrap();
                assert!(
                    super::super::connect_iroh(
                        connection,
                        approval.credential.scope().authority,
                        &secret,
                        SessionKey::Passkey(&ROOT.passkey())
                    )
                    .await
                    .is_err()
                );
                assert!(
                    connect(&client, &old, root, approval.clone())
                        .await
                        .is_err()
                );
                connect(&client, &current, root, approval).await.unwrap();
            },
        );
        result.unwrap();
        client.close().await;
        server.close().await;
    }
}
