//! Exercise the public Work handshake over QUIC, including attacks before RPC decoding.
use super::*;
use crate::{
    test_identity::OpenProof,
    work_router::{WorkConnection, WorkRouter},
};
use hellas_auth::authority::{AuthorityId, CredentialSecret};
use hellas_rpc::authentication::MAX_AUTHENTICATION_MESSAGE_BYTES;
use hellas_rpc::pb::work::{FundingKind, WorkRoute};
use hellas_rpc::services::work::{AcceptWork, Open, Work, WorkClientImpl};
use hellas_wire::{Dispatcher, Metadata, WireCode};
use iroh::{EndpointAddr, TransportAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use {hellas_authority::test_support::within, hellas_channel::test_support::assert_err};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplicationAttack {
    Identity,
    Audience,
    Secret,
    Authorization,
    Oversize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FundingAttack {
    BeforeOpen,
    BeforeCredential,
    TrailingPayment,
    UnknownFunding,
    ShortGrant,
}

struct Pair {
    client: Endpoint,
    provider: Endpoint,
    outgoing: IrohTransport,
    incoming: IrohTransport,
}
impl Pair {
    async fn new() -> Self {
        Self::with_client(9).await
    }
    async fn with_client(seed: u8) -> Self {
        let provider = Self::endpoint(2, true).await;
        let client = Self::endpoint(seed, false).await;
        Self::connect(client, provider).await
    }
    async fn endpoint(seed: u8, serving: bool) -> Endpoint {
        Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[seed; 32]))
            .alpns(if serving {
                vec![Work::ALPN.as_bytes().to_vec()]
            } else {
                vec![]
            })
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap()
    }
    async fn connect(client: Endpoint, provider: Endpoint) -> Self {
        let address = EndpointAddr::from_parts(
            provider.id(),
            provider.bound_sockets().into_iter().map(TransportAddr::Ip),
        );
        let (outgoing, incoming) =
            tokio::join!(client.connect(address, Work::ALPN.as_bytes()), async {
                provider.accept().await.unwrap().await.unwrap()
            },);
        Self {
            client,
            provider,
            outgoing: IrohTransport::new(outgoing.unwrap()),
            incoming: IrohTransport::new(incoming),
        }
    }
    async fn open(&self) {
        hellas_client::confidential_open::<Open>(
            &self.outgoing,
            &ProviderTrustAnchor {
                expected_genesis: crate::grant_client::tests::provider_enrollment(2).content_id(),
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            },
        )
        .await
        .unwrap();
    }
    async fn admit(
        &self,
        router: &WorkRouter,
        application: Option<&ClientProfile>,
    ) -> WorkConnection {
        let identity = principal(1).1;
        let (server, client) = tokio::join!(router.accept_iroh(&self.incoming, proof()), async {
            self.open().await;
            crate::work_router::connect_work(&self.outgoing, application.map(|a| (a, &identity)))
                .await
        },);
        client.unwrap();
        server.unwrap()
    }
    async fn close(self) {
        self.client.close().await;
        self.provider.close().await;
    }
}
fn proof() -> OpenProof {
    OpenProof(
        crate::grant_client::tests::provider_enrollment(2),
        principal(2).1,
    )
}
fn current(f: &Fixture) {
    f.clock.set(UnixMillis::now().unwrap_or_default());
}

#[tokio::test]
async fn funding_is_fixed_for_the_authenticated_connection() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let f = Fixture::new().await;
        current(&f);
        let router = WorkRouter::both(
            crate::paid_provider::MountedWork::with_backend(backend(
                Arc::new(Semaphore::new(1)),
                f.calls.clone(),
            )),
            f.service.clone(),
        );
        for grant in [false, true] {
            let pair = Pair::new().await;
            let server = pair
                .admit(&router, grant.then_some(f.application.as_ref()))
                .await;
            let route = if grant {
                WorkRoute::payment(Digest::hash(b"payment"))
            } else {
                WorkRoute::grant(ChannelId(Digest::hash(b"grant")).0)
            };
            let client =
                WorkClientImpl::new(IrohTransport::new(pair.outgoing.connection().clone()));
            let (result, handled) = tokio::join!(
                client.accept_work(AcceptWorkRequest {
                    route: Some(route),
                    ..Default::default()
                }),
                async {
                    Dispatcher::<IrohTransport>::dispatch(
                        &server,
                        pair.incoming.accept().await.unwrap().unwrap(),
                    )
                    .await
                },
            );
            assert_eq!(result.unwrap_err().code, WireCode::PermissionDenied);
            handled.unwrap();
            assert_eq!(f.calls.load(Ordering::SeqCst), 0);
            // A host must not reuse this admitted dispatcher for a different carrier.
            let other = Pair::new().await;
            let _stream = other
                .outgoing
                .open(AcceptWork::METHOD_ID, Metadata::default())
                .await
                .unwrap();
            let inbound = other.incoming.accept().await.unwrap().unwrap();
            assert_err!(
                within(Dispatcher::<IrohTransport>::dispatch(&server, inbound)).await,
                hellas_wire::TransportError::Protocol(_)
            );
            other.close().await;
            drop(server);
            pair.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn work_rejects_wrong_application_identity_audience_and_grant_binding() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let f = Fixture::new().await;
        current(&f);
        let router = WorkRouter::grants(f.service.clone());
        for attack in [
            ApplicationAttack::Identity,
            ApplicationAttack::Audience,
            ApplicationAttack::Secret,
            ApplicationAttack::Authorization,
            ApplicationAttack::Oversize,
        ] {
            let pair = Pair::new().await;
            let (server, ()) = tokio::join!(router.accept_iroh(&pair.incoming, proof()), async {
                pair.open().await;
                let (mut send, mut recv) = pair.outgoing.connection().open_bi().await.unwrap();
                send.write_all(&[FundingKind::Grant as u8]).await.unwrap();
                send.write_all(&f.application.authorization.0)
                    .await
                    .unwrap();
                if attack == ApplicationAttack::Oversize {
                    send.write_all(&[1]).await.unwrap();
                    let length = recv.read_u16().await.unwrap();
                    let mut challenge = vec![0; usize::from(length)];
                    recv.read_exact(&mut challenge).await.unwrap();
                    let oversize = u16::try_from(MAX_AUTHENTICATION_MESSAGE_BYTES + 1).unwrap();
                    send.write_u16(oversize).await.unwrap();
                    // No body follows: reject the length without waiting for bytes.
                    recv.read_u8().await.unwrap_err();
                } else {
                    let authorization = if attack == ApplicationAttack::Authorization {
                        GrantId([77; 16])
                    } else {
                        f.application.authorization
                    };
                    let transport = hellas_rpc::authentication::session_binding(
                        &pair.outgoing.context(),
                        Work::ALPN.as_bytes(),
                    )
                    .unwrap();
                    let binding = hellas_auth::hash_tuple(
                        "hellas.work.application.v1",
                        &[transport.as_bytes(), &authorization.0],
                    );
                    let credential =
                        CredentialSecret::from_parts(f.application.credential.id(), [99; 32]);
                    let result = crate::application_handshake::connect(
                        if attack == ApplicationAttack::Audience {
                            AuthorityId(Digest::hash(b"other authority"))
                        } else {
                            f.application.authority
                        },
                        binding,
                        if attack == ApplicationAttack::Secret {
                            &credential
                        } else {
                            &f.application.credential
                        },
                        hellas_authority::node::SessionKey::Node(
                            &if attack == ApplicationAttack::Identity {
                                hellas_channel::test_support::actors::STRANGER
                            } else {
                                hellas_channel::test_support::actors::ROOT
                            }
                            .node_key(),
                        ),
                        &mut recv,
                        &mut send,
                        crate::application_handshake::Framing::Substream,
                    )
                    .await;
                    assert_eq!(
                        result.unwrap_err().code(),
                        WireCode::PermissionDenied,
                        "{attack:?}"
                    );
                    pair.outgoing
                        .connection()
                        .close(0u32.into(), b"failed authentication");
                }
            });
            let refusal = server.err().unwrap();
            assert_eq!(refusal.code, WireCode::PermissionDenied, "{attack:?}");
            if attack == ApplicationAttack::Oversize {
                assert_eq!(
                    refusal.message(),
                    "application authentication failed",
                    "the frame reader must reject the length before reading the body",
                );
            }
            pair.close().await;
        }
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ordinary_work_and_malformed_funding_cannot_bypass_authentication() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let f = Fixture::new().await;
        current(&f);
        let router = WorkRouter::both(
            crate::paid_provider::MountedWork::with_backend(backend(
                Arc::new(Semaphore::new(1)),
                f.calls.clone(),
            )),
            f.service.clone(),
        );
        for attack in [
            FundingAttack::BeforeOpen,
            FundingAttack::BeforeCredential,
            FundingAttack::TrailingPayment,
            FundingAttack::UnknownFunding,
            FundingAttack::ShortGrant,
        ] {
            let pair = Pair::new().await;
            let (server, ()) = tokio::join!(router.accept_iroh(&pair.incoming, proof()), async {
                if attack != FundingAttack::BeforeOpen {
                    pair.open().await;
                }
                if attack == FundingAttack::BeforeOpen || attack == FundingAttack::BeforeCredential
                {
                    assert_err!(WorkClientImpl::new(IrohTransport::new(pair.outgoing.connection().clone()))
                        .accept_work(AcceptWorkRequest::default()).await,
                        status if matches!(status.code(), WireCode::Internal | WireCode::Unavailable));
                } else {
                    let bytes: &[u8] = match attack {
                        FundingAttack::TrailingPayment => &[1, 99],
                        FundingAttack::UnknownFunding => &[99],
                        FundingAttack::ShortGrant => &[2, 0],
                        FundingAttack::BeforeOpen | FundingAttack::BeforeCredential => {
                            unreachable!()
                        }
                    };
                    let (mut send, mut recv) = pair.outgoing.connection().open_bi().await.unwrap();
                    send.write_all(bytes).await.unwrap();
                    send.shutdown().await.unwrap();
                    recv.read_u8().await.unwrap_err();
                }
            });
            assert_eq!(
                server.err().unwrap().code,
                WireCode::PermissionDenied,
                "{attack:?}"
            );
            pair.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn revoked_credentials_are_rejected_before_work_body_decoding() {
    let f = Fixture::new().await;
    current(&f);
    let router = WorkRouter::grants(f.service.clone());
    let pair = Pair::new().await;
    let server = pair.admit(&router, Some(&f.application)).await;
    let node = f.service.node();
    let caller = hellas_authority::test_support::session(&node, &f.administrator).await;
    node.revoke_credential(
        &caller,
        GrantId([0; 16]),
        f.application.credential.id(),
        Revision(1),
    )
    .await
    .unwrap();
    let _stream = pair
        .outgoing
        .open(AcceptWork::METHOD_ID, Metadata::default())
        .await
        .unwrap();
    let inbound = pair.incoming.accept().await.unwrap().unwrap();
    assert_err!(
        within(Dispatcher::<IrohTransport>::dispatch(&server, inbound)).await,
        hellas_wire::TransportError::Protocol(_)
    );
    within(pair.outgoing.connection().closed()).await;
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    drop(server);
    pair.close().await;
}

#[tokio::test]
async fn public_connections_leave_grant_capacity_and_sessions_recover_after_close() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let f = Fixture::new().await;
        current(&f);
        let router = WorkRouter::both(
            crate::paid_provider::MountedWork::default(),
            f.service.clone(),
        );
        // Share endpoint runtimes while keeping all 128 QUIC connections live.
        let provider = Pair::endpoint(2, true).await;
        let grant_client = Pair::endpoint(9, false).await;
        let newcomer = Pair::endpoint(80, false).await;
        let mut clients = Vec::new();
        for seed in 20..28 {
            clients.push(Pair::endpoint(seed, false).await);
        }
        let mut held = Vec::new();
        for n in 0..64 {
            let pair = Pair::connect(clients[n / 8].clone(), provider.clone()).await;
            let server = pair.admit(&router, None).await;
            held.push((pair, server));
        }
        let refused = async |pair: Pair, application: Option<&ClientProfile>| {
            let identity = principal(1).1;
            let (server, client) =
                tokio::join!(router.accept_iroh(&pair.incoming, proof()), async {
                    pair.open().await;
                    crate::work_router::connect_work(
                        &pair.outgoing,
                        application.map(|a| (a, &identity)),
                    )
                    .await
                });
            assert_eq!(server.err().unwrap().code, WireCode::ResourceExhausted);
            assert_eq!(client.unwrap_err().code(), WireCode::PermissionDenied);
            pair.outgoing.connection().closed().await;
            drop(pair);
        };
        // A fresh public endpoint cannot consume the grant reserve.
        refused(
            Pair::connect(newcomer.clone(), provider.clone()).await,
            None,
        )
        .await;
        for _ in 0..64 {
            let pair = Pair::connect(grant_client.clone(), provider.clone()).await;
            let server = pair.admit(&router, Some(&f.application)).await;
            held.push((pair, server));
        }
        // All 128 session slots are now occupied. Successful application proof
        // cannot exceed that total, and does not spend an unauthenticated token.
        refused(
            Pair::connect(grant_client.clone(), provider.clone()).await,
            Some(&f.application),
        )
        .await;
        let (pair, server) = held.pop().unwrap();
        drop(server);
        drop(pair);
        let pair = Pair::connect(grant_client.clone(), provider.clone()).await;
        let server = pair.admit(&router.clone(), Some(&f.application)).await;
        held.push((pair, server));
        drop(held);
        for endpoint in clients
            .into_iter()
            .chain([grant_client, newcomer, provider])
        {
            endpoint.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stalled_handshakes_release_admission_on_cancellation_and_deadline() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let f = Fixture::new().await;
        current(&f);
        let router = WorkRouter::grants(f.service.clone());
        let provider = Pair::endpoint(2, true).await;
        let first = Pair::endpoint(20, false).await;
        let second = Pair::endpoint(21, false).await;
        let newcomer = Pair::endpoint(30, false).await;
        let mut pairs = Vec::new();
        for n in 0..16 {
            let client = if n < 8 { &first } else { &second };
            pairs.push(Pair::connect(client.clone(), provider.clone()).await);
        }
        let mut pending: Vec<_> = pairs
            .iter()
            .map(|pair| Box::pin(router.accept_iroh(&pair.incoming, proof())))
            .collect();
        for handshake in &mut pending {
            assert!(futures::poll!(handshake.as_mut()).is_pending());
        }
        let refused = Pair::connect(newcomer.clone(), provider.clone()).await;
        assert_eq!(
            router
                .accept_iroh(&refused.incoming, proof())
                .await
                .err()
                .unwrap()
                .code,
            WireCode::ResourceExhausted
        );
        drop(refused);
        // Cancellation returns a pending slot immediately, without waiting for
        // the ten-second deadline or taking capacity from admitted sessions.
        drop(pending.pop());
        let admitted = Pair::connect(newcomer.clone(), provider.clone()).await;
        let session = admitted.admit(&router, Some(&f.application)).await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(10)).await;
        for handshake in pending {
            assert_eq!(
                handshake.await.err().unwrap().code,
                WireCode::PermissionDenied
            );
        }
        tokio::time::resume();
        // The previously saturated endpoint can authenticate after its stale
        // connections expire; its endpoint lease was returned too.
        let recovered = Pair::connect(first.clone(), provider.clone()).await;
        let recovered_session = recovered.admit(&router, Some(&f.application)).await;
        drop(recovered_session);
        drop(recovered);
        drop(session);
        drop(admitted);
        drop(pairs);
        for endpoint in [first, second, newcomer, provider] {
            endpoint.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelling_application_authentication_closes_the_uncached_connection() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let f = Fixture::new().await;
        let pair = Pair::new().await;
        let link = WorkLink::new(
            pair.provider.id(),
            pair.provider.bound_sockets(),
            pair.client.clone(),
            ProviderTrustAnchor {
                expected_genesis: crate::grant_client::tests::provider_enrollment(2).content_id(),
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            },
        )
        .with_application(f.application.clone(), Arc::new(principal(1).1));
        let dialing = tokio::spawn(async move { link.work().await });
        let transport = IrohTransport::new(pair.provider.accept().await.unwrap().await.unwrap());
        let inbound = transport.accept().await.unwrap().unwrap();
        hellas_rpc::call::dispatch_unary_with_context::<IrohTransport, Open, _, _, _>(
            inbound,
            |request, context| async move {
                hellas_rpc::open::OpenHandler::open(
                    &proof(),
                    request,
                    context,
                    Work::ALPN.as_bytes(),
                )
                .await
            },
        )
        .await
        .unwrap();
        let (_send, mut recv) = transport.connection().accept_bi().await.unwrap();
        assert_eq!(recv.read_u8().await.unwrap(), FundingKind::Grant as u8);
        dialing.abort();
        assert!(dialing.await.err().unwrap().is_cancelled());
        transport.connection().closed().await;
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn exact_pin_content_reads_use_the_live_grant_on_the_authenticated_work_carrier() {
    for draining in [false, true] {
        use futures::StreamExt as _;
        use hellas_auth::authority::{GrantCommand, GrantSpec, OperationId, Permission};
        use hellas_authority::{
            content::{READ, pin_resource},
            test_support as common,
        };
        use hellas_store::content::{
            ContentStore as _, Cursor, Error, Path, PinName, PinPolicy, PinTarget, PinValue,
            RemoteStore, Reservations, Scope, Source, Target,
        };
        let f = Fixture::new().await;
        current(&f);
        let selected = PinName::new("granted/selected".into()).unwrap();
        let neighbor = PinName::new("granted/selected-neighbor".into()).unwrap();
        let bytes = b"private-exact-pin-granted-body";
        let object = hellas_channel::content::upload_bytes(
            &f.content,
            &Scope::Owner,
            bytes,
            Some(PinTarget {
                name: selected.clone(),
                policy: PinPolicy::Granted,
            }),
        )
        .await
        .unwrap();
        let value = PinValue {
            target: Target::Object(object),
            policy: PinPolicy::Granted,
            expires: None,
        };
        f.content
            .set_pin(&Scope::Owner, &neighbor, None, Some(value.clone()))
            .await
            .unwrap();
        let node = f.service.node();
        let administrator = common::session(&node, &f.administrator).await;
        let grant = GrantId([81; 16]);
        let spec = GrantSpec {
            authority: administrator.authority(),
            subject: principal(1).0,
            permissions: [Permission {
                operation: OperationId::new(READ).unwrap(),
                resource: pin_resource(administrator.authority(), &selected),
            }]
            .into(),
            not_before: f.clock.now(),
            expires: administrator.expires(),
            delegation_depth: 0,
            issuance: None,
        };
        let issued = node
            .grant(
                &administrator,
                GrantCommand::Issue {
                    authorization: GrantId([0; 16]),
                    id: grant,
                    spec: spec.clone(),
                },
            )
            .await
            .unwrap();
        let [credential] = common::credentials::issue(
            common::credentials::Issuer::Node(&node),
            &administrator,
            GrantId([0; 16]),
            None,
            spec,
        )
        .await;
        let profile = ClientProfile {
            authority: administrator.authority(),
            authorization: grant,
            credential,
            local: None,
        };
        let pair = Pair::new().await;
        let server = pair
            .admit(&WorkRouter::grants(f.service.clone()), Some(&profile))
            .await;
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let mut serving = tokio::spawn(crate::provider::serve_loop(
            Arc::new(IrohTransport::new(pair.incoming.connection().clone())),
            server,
            stopped,
            crate::transport_admission::IDLE_TIMEOUT,
            tokio::time::Instant::now() + crate::transport_admission::MAX_LIFETIME,
        ));
        let remote = RemoteStore::new(
            IrohTransport::new(pair.outgoing.connection().clone()),
            Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
        );
        let at = Path::new(selected.clone(), String::new()).unwrap();
        // Client-side Scope::Owner cannot select the server's authority.
        assert_eq!(
            remote
                .stat(&Scope::Owner, &at)
                .await
                .unwrap()
                .unwrap()
                .target,
            Target::Object(object)
        );
        assert!(matches!(
            remote
                .stat(&Scope::Owner, &Path::new(neighbor, String::new()).unwrap())
                .await,
            Err(Error::Denied)
        ));
        let pins = remote
            .pins(&Scope::Owner, selected.as_str(), Cursor::default())
            .await
            .unwrap();
        assert_eq!(pins.pins, vec![(selected.clone(), value.clone())]);
        let mut read = remote.read(&Scope::Owner, &at, 2..8).await.unwrap();
        let mut actual = Vec::new();
        while let Some(chunk) = read.bytes.next().await {
            actual.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(actual, bytes[2..8]);
        assert!(matches!(
            remote
                .set_pin(&Scope::Owner, &selected, Some(&value), None)
                .await,
            Err(Error::Denied)
        ));
        assert!(matches!(
            remote.collect(&Scope::Owner).await,
            Err(Error::Denied)
        ));
        assert!(matches!(
            remote
                .acquire(
                    &Scope::Owner,
                    Source::Peer {
                        node: *pair.provider.id().as_bytes(),
                        at: at.clone()
                    },
                    Some(object),
                    PinTarget {
                        name: selected.clone(),
                        policy: PinPolicy::Owner
                    },
                )
                .await,
            Err(Error::Denied)
        ));
        let client = hellas_rpc::services::content::ContentClientImpl::new(IrohTransport::new(
            pair.outgoing.connection().clone(),
        ));
        let mut upload = client.upload().await.unwrap();
        upload
            .send(hellas_rpc::pb::content::UploadRequest {
                part: Some(hellas_rpc::pb::content::upload_request::Part::Open(
                    hellas_rpc::pb::content::UploadOpen {
                        object: Some(hellas_rpc::pb::content::ContentRef {
                            id: object.id().as_bytes().to_vec(),
                            bytes: object.bytes(),
                        }),
                        pin: Some(hellas_rpc::pb::content::PinTarget {
                            name: selected.as_str().into(),
                            policy: None,
                        }),
                        work: None,
                    },
                )),
            })
            .await
            .unwrap();
        let _ = upload.close().await;
        assert!(upload.next().await.is_none());
        assert_eq!(
            upload.finish().unwrap_err().code(),
            WireCode::PermissionDenied
        );
        let owner = PinValue {
            policy: PinPolicy::Owner,
            ..value.clone()
        };
        f.content
            .set_pin(&Scope::Owner, &selected, Some(&value), Some(owner.clone()))
            .await
            .unwrap();
        assert!(remote.stat(&Scope::Owner, &at).await.unwrap().is_none());
        f.content
            .set_pin(&Scope::Owner, &selected, Some(&owner), Some(value.clone()))
            .await
            .unwrap();
        let snapshot = remote
            .pins(&Scope::Owner, selected.as_str(), Cursor::default())
            .await
            .unwrap();
        let mut watch = remote
            .watch(&Scope::Owner, selected.as_str(), snapshot.cursor)
            .await
            .unwrap();
        let timed = PinValue {
            expires: Some(administrator.expires()),
            ..value.clone()
        };
        f.content
            .set_pin(&Scope::Owner, &selected, Some(&value), Some(timed))
            .await
            .unwrap();
        assert!(
            matches!(within(watch.next()).await.unwrap().unwrap(), hellas_store::content::PinEvent::Set { name, value: Some(_), .. } if name == selected)
        );
        if draining {
            // Keep the authenticated watch and credential alive through the actual
            // Work reply drain; no expiry, revocation or client disconnect helps it.
            assert!(futures::poll!(watch.next()).is_pending());
            stop.send_replace(true);
            within(f.service.drain()).await.unwrap();
            within(&mut serving).await.unwrap().unwrap();
        } else {
            node.grant(
                &administrator,
                GrantCommand::Revoke {
                    authorization: GrantId([0; 16]),
                    id: grant,
                    expected: issued.revision(),
                },
            )
            .await
            .unwrap();
        }
        assert!(matches!(within(watch.next()).await, Some(Err(_)) | None));
        if !draining {
            assert!(matches!(
                remote.stat(&Scope::Owner, &at).await,
                Err(Error::Denied)
            ));
        }
        assert_eq!(
            f.calls.load(Ordering::SeqCst),
            0,
            "content permission requires no Work execution grant"
        );
        drop(watch);
        stop.send_replace(true);
        if !draining {
            within(serving).await.unwrap().unwrap();
        }
        pair.close().await;
    }
}
