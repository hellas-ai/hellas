//! One-shot owner bootstrap on the normal, independently pinned node transport.
//! The pairing secret is delivered through the authenticated machine console.
use super::*;
use hellas_authority::work_store::grant::{NodeStore, PreparedBootstrap};
use hellas_rpc::ProviderEnrollmentBundle;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::Path};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

const VERSION: u8 = 4;
const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;
const MAX_PAIRING_ATTEMPTS: usize = 8;
const MAX_HANDSHAKES: usize = 16;
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
    endpoint.set_alpns(vec![HostControl::ALPN.as_bytes().to_vec()]);
    let deadline = Instant::now() + Duration::from_millis(remaining);
    let mut attempts = 0;
    let slots = hellas_wire::admission::ConnectionSlots::new(MAX_HANDSHAKES, 2, 8);
    let mut pending = tokio::task::JoinSet::new();
    while attempts < MAX_PAIRING_ATTEMPTS {
        let result = tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Err(denied()),
            incoming = endpoint.accept() => {
                let incoming = incoming.ok_or_else(unavailable)?;
                if pending.len() >= MAX_HANDSHAKES {
                    tracing::warn!("owner bootstrap pending capacity refused");
                    incoming.refuse();
                    continue;
                }
                let Some(permits) = slots.try_acquire(crate::transport_admission::source_ip(incoming.remote_addr())) else {
                    tracing::warn!("owner bootstrap connection capacity refused");
                    incoming.refuse();
                    continue;
                };
                pending.spawn(async move {
                    let _permits = permits;
                    tokio::time::timeout_at(deadline.min(Instant::now() + HANDSHAKE_TIMEOUT), async {
                        let connection = incoming.accept().map_err(|_| denied())?
                            .await.map_err(|_| denied())?;
                        let close = CloseConnection(Some(connection.clone()));
                        if connection.alpn() != HostControl::ALPN.as_bytes() {
                            return Err(denied());
                        }
                        let (mut send, mut recv) = connection.accept_bi().await.map_err(|_| denied())?;
                        if recv.read_u8().await.map_err(|_| denied())? != VERSION {
                            return Err(denied());
                        }
                        let length = recv.read_u32().await.map_err(|_| denied())? as usize;
                        if length == 0 || length > MAX_BOOTSTRAP_BYTES { return Err(invalid()); }
                        let mut bytes = Zeroizing::new(vec![0; length]);
                        recv.read_exact(&mut bytes).await.map_err(|_| denied())?;
                        let request: Request = decode_bounded(&bytes, MAX_BOOTSTRAP_BYTES)
                            .map_err(|_| invalid())?;
                        send.flush().await.map_err(|_| denied())?;
                        Ok::<_, WireStatus>((close, send, request))
                    }).await.map_err(|_| denied())?
                });
                continue;
            },
            result = pending.join_next(), if !pending.is_empty() => result,
        };
        let Some(Ok(Ok((_close, mut send, request)))) = result else {
            tracing::warn!("owner bootstrap admission refused");
            continue;
        };
        // Compare in the coordinator, so concurrent readers cannot evaluate
        // guesses beyond the remaining budget. Malformed traffic never counts.
        if !bool::from(request.pairing.ct_eq(&invitation.pairing)) {
            attempts += 1;
            tracing::warn!("owner bootstrap pairing proof refused");
            continue;
        }
        if request.approval.target != Some(*invitation.node.as_bytes()) {
            tracing::warn!("owner bootstrap target refused");
            continue;
        }
        let now = UnixMillis::now().map_err(|_| unavailable())?;
        if now.0 >= invitation.expires.0 {
            return Err(denied());
        }
        // Admission ends the client's handshake deadline. Accepted writes must
        // still finish if the client disconnects before either reply arrives.
        let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, send.write_all(&[VERSION])).await;
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
        // The store is now the crash-safe completion marker. No other request
        // can commit; cancel remaining unauthenticated connections before handoff.
        pending.shutdown().await;
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
/// Connecting and admission are bounded; durable completion inherits the caller's deadline.
pub async fn connect(
    endpoint: &iroh::Endpoint,
    invitation: &Invitation,
    root: GrantId,
    approval: PreparedBootstrap,
) -> Result<(), WireStatus> {
    let (_close, mut recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
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
        let close = CloseConnection(Some(connection.clone()));
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
        if recv.read_u8().await.map_err(|_| unavailable())? != VERSION {
            return Err(denied());
        }
        Ok((close, recv))
    })
    .await
    .map_err(|_| unavailable())??;
    #[cfg(test)]
    tests::commit_wait_started();
    // Admission is not success: only the second reply confirms publication.
    if recv.read_u8().await.map_err(|_| unavailable())? != VERSION {
        return Err(denied());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use {hellas_authority::test_support::common_node, hellas_channel::test_support::actors::ROOT};
    async fn endpoints() -> (iroh::Endpoint, iroh::Endpoint) {
        let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .alpns(vec![HostControl::ALPN.as_bytes().to_vec()])
            .bind()
            .await
            .unwrap();
        let client = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        (server, client)
    }
    fn invitation(server: &iroh::Endpoint) -> Invitation {
        let mut invitation = Invitation::create(server, UnixMillis::now().unwrap()).unwrap();
        // These endpoints bind loopback explicitly. Avoid waiting for asynchronous
        // address advertisement; this fixture knows its exact direct sockets.
        invitation.addresses = server.bound_sockets();
        invitation
    }
    fn prepared(node: iroh::EndpointId) -> (GrantId, PreparedBootstrap, CredentialSecret) {
        let root = hellas_authority::test_support::ids::ROOT_GRANT;
        let scope = common_node::admin_spec(
            hellas_authority::test_support::authority(),
            ROOT.principal(),
            &[],
            (UnixMillis(0), UnixMillis(u64::MAX)),
            (u64::MAX, 8),
            &[],
        );
        let approval = common_node::approval_for(
            Ownership::Bootstrap {
                root,
                target: Some(*node.as_bytes()),
            },
            scope.clone(),
            scope.clone(),
        );
        let (approval, secret) = approval.prepare(Some(*node.as_bytes())).unwrap();
        (root, approval, secret)
    }
    tokio::task_local! {
        static COMMIT_WAIT: Arc<tokio::sync::Notify>;
    }

    pub(super) fn commit_wait_started() {
        let _ = COMMIT_WAIT.try_with(|ready| ready.notify_one());
    }

    #[tokio::test]
    async fn slow_bootstrap_commit_outlives_handshake_timeout() {
        use hellas_authority::test_support::BOOTSTRAP_COMMIT_PAUSE;
        let directory = tempfile::tempdir().unwrap();
        let (server, client) = endpoints().await;
        let invitation = invitation(&server);
        let (root, approval, secret) = prepared(server.id());
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let waiting = Arc::new(tokio::sync::Notify::new());
        let (accepted, connected) = tokio::join!(
            BOOTSTRAP_COMMIT_PAUSE.scope(
                (entered.clone(), release.clone()),
                accept(
                    &server,
                    &invitation,
                    directory.path(),
                    hellas_channel::test_support::network(),
                    None,
                ),
            ),
            async {
                let connecting = COMMIT_WAIT.scope(
                    waiting.clone(),
                    connect(&client, &invitation, root, approval),
                );
                tokio::pin!(connecting);
                tokio::select! {
                    result = &mut connecting => panic!("completed before publication: {result:?}"),
                    () = async {
                        entered.notified().await;
                        waiting.notified().await;
                    } => {}
                }
                // Both the real store and the client are at the commit boundary.
                tokio::time::pause();
                tokio::time::advance(HANDSHAKE_TIMEOUT + Duration::from_secs(1)).await;
                assert!(futures::poll!(&mut connecting).is_pending());
                tokio::time::resume();
                release.notify_one();
                hellas_authority::test_support::within(connecting).await
            },
        );
        accepted.unwrap();
        connected.unwrap();
        let node = NodeCoordinator::new(
            NodeStore::open(
                directory.path(),
                hellas_channel::test_support::network(),
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
        server.close().await;
        client.close().await;
    }

    #[tokio::test]
    async fn unreachable_bootstrap_is_bounded_by_handshake_timeout() {
        let (server, client) = endpoints().await;
        let mut invitation = invitation(&server);
        // A bound but unread UDP socket silently drops the connection attempt.
        let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        invitation.addresses = vec![sink.local_addr().unwrap()];
        let (root, approval, _) = prepared(server.id());
        tokio::time::pause();
        let started = Instant::now();
        let error = connect(&client, &invitation, root, approval)
            .await
            .unwrap_err();
        assert_eq!(error.code(), WireCode::Unavailable);
        // Tokio rounds timer expiry up to its next millisecond tick.
        assert!(started.elapsed() <= HANDSHAKE_TIMEOUT + Duration::from_millis(1));
        tokio::time::resume();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn silent_bootstrap_is_bounded_by_handshake_timeout() {
        let (server, client) = endpoints().await;
        let invitation = invitation(&server);
        let (root, approval, _) = prepared(server.id());
        let connecting = connect(&client, &invitation, root, approval);
        tokio::pin!(connecting);
        let (_connection, _send) = tokio::select! {
            result = &mut connecting => panic!("completed before the server received the request: {result:?}"),
            streams = async {
                let connection = server.accept().await.unwrap().accept().unwrap().await.unwrap();
                let (send, mut recv) = connection.accept_bi().await.unwrap();
                let bytes = recv.read_to_end(MAX_BOOTSTRAP_BYTES + 5).await.unwrap();
                assert_eq!(bytes[0], VERSION);
                (connection, send)
            } => streams,
        };
        tokio::time::pause();
        // Include the timer wheel's rounding tick, not another protocol deadline.
        tokio::time::advance(HANDSHAKE_TIMEOUT + Duration::from_millis(1)).await;
        let std::task::Poll::Ready(result) = futures::poll!(&mut connecting) else {
            panic!("silent server exceeded the handshake deadline");
        };
        assert_eq!(result.unwrap_err().code(), WireCode::Unavailable);
        tokio::time::resume();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn bootstrap_accepts_an_external_async_authenticator_assertion() {
        use hellas_authority::authenticator::{Authenticator, PublicKey};
        struct Prompt(hellas_kernel::SoftPasskey);
        #[async_trait::async_trait]
        impl Authenticator for Prompt {
            fn public_key(&self) -> Result<PublicKey, AuthorityError> {
                self.0.public_key()
            }
            async fn assert(&self, digest: Digest) -> Result<PasskeyAssertion, AuthorityError> {
                tokio::task::yield_now().await;
                self.0.assert(digest).await
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let (server, client) = endpoints().await;
        let invitation = invitation(&server);
        let (root, mut approval, _) = prepared(server.id());
        let CredentialHolder::Node(holder) = approval.credential.holder() else {
            panic!("device credential");
        };
        let digest = ownership_digest(
            Ownership::Bootstrap {
                root,
                target: Some(*server.id().as_bytes()),
            },
            &approval.administrator,
            approval.credential.scope(),
            holder,
        );
        approval.assertion = Prompt(ROOT.passkey()).assert(digest).await.unwrap();
        let (accepted, connected) = tokio::join!(
            accept(
                &server,
                &invitation,
                directory.path(),
                hellas_channel::test_support::network(),
                None
            ),
            connect(&client, &invitation, root, approval),
        );
        accepted.unwrap();
        connected.unwrap();
        server.close().await;
        client.close().await;
    }

    #[tokio::test]
    async fn owner_approval_cannot_be_retargeted_to_another_machine() {
        let directory = tempfile::tempdir().unwrap();
        let (server, other) = endpoints().await;
        let (root, mut approval, _) = prepared(other.id());
        // Changing the public target cannot adapt the owner's signature.
        approval.target = Some(*server.id().as_bytes());
        assert!(
            NodeStore::bootstrap_prepared(
                directory.path(),
                hellas_channel::test_support::network(),
                root,
                approval,
                None,
                UnixMillis::now().unwrap()
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        server.close().await;
        other.close().await;
    }

    #[tokio::test]
    async fn stalled_bootstrap_does_not_block_a_valid_owner() {
        let directory = tempfile::tempdir().unwrap();
        let (server, client) = endpoints().await;
        let staller = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let invitation = invitation(&server);
        let (root, approval, _) = prepared(server.id());
        let (result, ()) = tokio::join!(
            accept(
                &server,
                &invitation,
                directory.path(),
                hellas_channel::test_support::network(),
                None
            ),
            async {
                let stalled = staller
                    .connect(server.addr(), HostControl::ALPN.as_bytes())
                    .await
                    .unwrap();
                // Assert transport admission before the stalled reader's five-
                // second deadline. Durable store I/O happens only afterwards.
                let address = invitation
                    .addresses
                    .iter()
                    .fold(iroh::EndpointAddr::new(server.id()), |address, socket| {
                        address.with_ip_addr(*socket)
                    });
                let connection = tokio::time::timeout(
                    Duration::from_secs(3),
                    client.connect(address, HostControl::ALPN.as_bytes()),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(stalled.close_reason().is_none());
                let (mut send, mut recv) = connection.open_bi().await.unwrap();
                let bytes = canonical_dag_cbor(&Request {
                    pairing: invitation.pairing,
                    root,
                    approval,
                })
                .unwrap();
                send.write_u8(VERSION).await.unwrap();
                send.write_u32(bytes.len() as u32).await.unwrap();
                send.write_all(&bytes).await.unwrap();
                send.finish().unwrap();
                assert_eq!(recv.read_u8().await.unwrap(), VERSION);
                assert_eq!(
                    hellas_authority::test_support::within(recv.read_u8())
                        .await
                        .unwrap(),
                    VERSION
                );
                drop(stalled);
            }
        );
        result.unwrap();
        server.close().await;
        client.close().await;
        staller.close().await;
    }

    #[tokio::test]
    async fn expired_invitation_cannot_initialize_or_send_approval() {
        let directory = tempfile::tempdir().unwrap();
        let (server, client) = endpoints().await;
        let mut invitation = invitation(&server);
        invitation.expires = UnixMillis(0);
        let (root, approval, _) = prepared(server.id());
        assert!(
            accept(
                &server,
                &invitation,
                directory.path(),
                hellas_channel::test_support::network(),
                None
            )
            .await
            .is_err()
        );
        assert!(connect(&client, &invitation, root, approval).await.is_err());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        client.close().await;
        server.close().await;
    }
    #[tokio::test]
    async fn pairing_commits_the_saved_credential_and_cannot_be_replayed() {
        let directory = tempfile::tempdir().unwrap();
        let (server, client) = endpoints().await;
        let invitation = invitation(&server);
        let (root, approval, secret) = prepared(server.id());
        let (server_result, client_result) = tokio::join!(
            accept(
                &server,
                &invitation,
                directory.path(),
                hellas_channel::test_support::network(),
                None
            ),
            connect(&client, &invitation, root, approval.clone()),
        );
        server_result.unwrap();
        client_result.unwrap();
        let node = NodeCoordinator::new(
            NodeStore::open(
                directory.path(),
                hellas_channel::test_support::network(),
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
                hellas_channel::test_support::network(),
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
        let invitation = invitation(&server);
        let mut wrong: Invitation =
            serde_json::from_slice(&serde_json::to_vec(&invitation).unwrap()).unwrap();
        wrong.pairing[0] ^= 1;
        let (root, approval, _) = prepared(server.id());
        let (result, ()) = tokio::join!(
            accept(
                &server,
                &invitation,
                directory.path(),
                hellas_channel::test_support::network(),
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
        // Start with the ordinary node's wider protocol set. Pairing must
        // narrow it before handling any incoming request.
        server.set_alpns(vec![
            HostControl::ALPN.as_bytes().to_vec(),
            hellas_rpc::services::work::Work::ALPN.as_bytes().to_vec(),
        ]);
        let old = invitation(&server);
        let current = invitation(&server);
        assert_ne!(old.pairing, current.pairing);
        let (root, approval, secret) = prepared(server.id());
        let (result, ()) = tokio::join!(
            accept(
                &server,
                &current,
                directory.path(),
                hellas_channel::test_support::network(),
                None
            ),
            async {
                assert!(
                    client
                        .connect(
                            server.addr(),
                            hellas_rpc::services::work::Work::ALPN.as_bytes()
                        )
                        .await
                        .is_err()
                );
                let mut offline = approval.clone();
                offline.target = None;
                assert!(connect(&client, &current, root, offline).await.is_err());
                // Refuse an oversized declared length before allocating its body.
                for _ in 0..=MAX_PAIRING_ATTEMPTS {
                    let oversized = client
                        .connect(server.addr(), HostControl::ALPN.as_bytes())
                        .await
                        .unwrap();
                    let (mut send, mut recv) = oversized.open_bi().await.unwrap();
                    send.write_u8(VERSION).await.unwrap();
                    send.write_u32(u32::MAX).await.unwrap();
                    send.flush().await.unwrap();
                    assert!(
                        hellas_authority::test_support::within(recv.read_u8())
                            .await
                            .is_err()
                    );
                    oversized.close(0u32.into(), b"done");
                }
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
