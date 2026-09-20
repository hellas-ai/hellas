use super::*;
use crate::cache::{
    CacheKey, CacheKind, CacheOptions, CachePolicy, CacheRecording, CacheStore, MemoryCacheStore,
};
use crate::call::WithTrailer;
use crate::pb::host as pb;
use crate::serve::{AdminPolicy, Authorized, MethodDispatcher};
use crate::services::cache_control::{CacheControlClientImpl, CacheControlServer, ManageCache};
use crate::services::host_control::{HostControlClientImpl, HostControlHandler, HostControlServer};
use futures_util::{StreamExt, TryStreamExt};
use hellas_wire::unix::{LocalControlServer, connect};
use hellas_wire::{
    AuthLevel, Dispatcher, PeerIdentity, StreamTransport, TransportContext, WireCode, WireStatus,
};
use std::os::unix::fs::PermissionsExt;

struct TestHost;

#[tokio::test]
async fn local_socket_requires_private_parent_and_preserves_existing_paths() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("control.sock");
    let (_, controller) = controller();
    let bind = || LocalControlServer::bind(&socket, CacheControlServer(controller.clone()));
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        bind().err().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(!socket.exists());

    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(&socket, b"existing file").unwrap();
    assert!(bind().is_err());
    assert_eq!(std::fs::read(&socket).unwrap(), b"existing file");
    std::fs::remove_file(&socket).unwrap();

    let server = bind().unwrap();
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(bind().is_err());
    drop(server);
    assert!(!socket.exists());

    let server = bind().unwrap();
    std::fs::rename(&socket, directory.path().join("original.sock")).unwrap();
    std::fs::write(&socket, b"replacement").unwrap();
    drop(server);
    assert_eq!(std::fs::read(&socket).unwrap(), b"replacement");
}

impl HostControlHandler for TestHost {
    async fn get_host_status(
        &self,
        _: pb::GetHostStatusRequest,
    ) -> Result<impl Into<WithTrailer<pb::HostStatus>> + Send, WireStatus> {
        Ok(pb::HostStatus {
            version: "test-host".into(),
            ..Default::default()
        })
    }

    async fn set_provider_state(
        &self,
        _: pb::SetProviderStateRequest,
    ) -> Result<impl Into<WithTrailer<pb::HostStatus>> + Send, WireStatus> {
        Err::<pb::HostStatus, _>(WireStatus::unimplemented("test host is read-only"))
    }

    async fn set_gateway_state(
        &self,
        _: pb::SetGatewayStateRequest,
    ) -> Result<impl Into<WithTrailer<pb::HostStatus>> + Send, WireStatus> {
        Err::<pb::HostStatus, _>(WireStatus::unimplemented("test host is read-only"))
    }

    async fn get_gateway_access(
        &self,
        _: pb::GetGatewayAccessRequest,
    ) -> Result<impl Into<WithTrailer<pb::GatewayAccess>> + Send, WireStatus> {
        Err::<pb::GatewayAccess, _>(WireStatus::unimplemented("test host has no gateway"))
    }
}

#[tokio::test]
async fn multiple_services_share_one_control_connection_with_or_without_caching() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().join("control.sock");
    for options in [
        CacheOptions::default(),
        CacheOptions {
            policy: CachePolicy::Record,
            store: Some(Arc::new(MemoryCacheStore::default())),
        },
    ] {
        let dispatcher = MethodDispatcher::<_, _, ManageCache>::new(
            CacheControlServer(CacheController::new(&options)),
            HostControlServer(TestHost),
        );
        let _server = LocalControlServer::bind(
            &socket,
            Authorized {
                service: dispatcher,
                policy: AdminPolicy {
                    local_owner: true,
                    ..Default::default()
                },
            },
        )
        .unwrap();
        let connection = connect(&socket).await.unwrap();
        let host = HostControlClientImpl::new(connection.clone());
        let cache = CacheControlClientImpl::new(connection);
        assert_eq!(
            host.get_host_status(pb::GetHostStatusRequest {})
                .await
                .unwrap()
                .version,
            "test-host"
        );
        let result = collect(
            cache
                .manage_cache(pb::ManageCacheRequest {
                    operation: Some(pb::manage_cache_request::Operation::Stats(
                        pb::CacheFilter::default(),
                    )),
                })
                .await,
        )
        .await;
        if options.store.is_some() {
            assert!(matches!(
                result.unwrap().pop().unwrap(),
                pb::manage_cache_response::Result::Stats(pb::CacheStats {
                    entries: 0,
                    bytes: 0
                })
            ));
        } else {
            assert_eq!(result.unwrap_err().code(), WireCode::FailedPrecondition);
        }
        assert_eq!(
            host.get_gateway_access(pb::GetGatewayAccessRequest {})
                .await
                .unwrap_err()
                .code(),
            WireCode::Unimplemented
        );
        assert_eq!(
            host.get_host_status(pb::GetHostStatusRequest {})
                .await
                .unwrap()
                .version,
            "test-host"
        );
    }
}

use pb::manage_cache_request::Operation;
use pb::manage_cache_response::Result as Reply;

async fn collect(
    call: Result<crate::call::StreamingCall<pb::ManageCacheResponse>, WireStatus>,
) -> Result<Vec<Reply>, WireStatus> {
    let mut call = call?;
    let messages: Vec<pb::ManageCacheResponse> = call.by_ref().try_collect().await?;
    call.finish()?;
    Ok(messages.into_iter().map(|r| r.result.unwrap()).collect())
}

fn request(operation: Operation) -> pb::ManageCacheRequest {
    pb::ManageCacheRequest {
        operation: Some(operation),
    }
}

fn controller() -> (Arc<MemoryCacheStore>, CacheController) {
    let store = Arc::new(MemoryCacheStore::default());
    let controller = CacheController::new(&CacheOptions {
        policy: CachePolicy::Record,
        store: Some(store.clone()),
    });
    (store, controller)
}

#[test]
fn unknown_wire_kinds_are_invalid_arguments_without_mutating_the_cache() {
    let (store, controller) = controller();
    for kind in ["unknown", "Proxy", "../proxy", ""] {
        let filter = pb::CacheFilter {
            kind: Some(kind.into()),
            identity: None,
        };
        for operation in [
            Operation::List(filter.clone()),
            Operation::Stats(filter.clone()),
            Operation::Read(pb::CacheKey {
                kind: kind.into(),
                identity: "0".repeat(64),
            }),
            Operation::Evict(pb::EvictCacheEntries {
                filter: Some(filter),
                all: true,
                ..Default::default()
            }),
        ] {
            assert_eq!(
                controller.manage(request(operation)).err().unwrap().code(),
                WireCode::InvalidArgument
            );
        }
    }
    assert_eq!(store.generation().unwrap(), 0);
}

async fn serve<T, S>(transport: T, service: S)
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send,
    S: Dispatcher<T> + Send + Sync,
{
    while let Ok(Some(inbound)) = transport.accept().await {
        if service.dispatch(inbound).await.is_err() {
            break;
        }
    }
}

#[tokio::test]
async fn streaming_read_is_one_snapshot_and_management_is_read_only_safe() {
    let (store, controller) = controller();
    let key = CacheKey::hash(CacheKind::Proxy, &[b"large"]);
    let bytes = vec![7; 150000];
    store.insert(&key, &bytes, 1).unwrap();
    let stream = controller
        .manage(request(Operation::Read(key_to_pb(key.clone()))))
        .unwrap();
    let pending = CacheRecording::new(store.clone()).unwrap();
    store.evict(&Eviction::default()).unwrap();
    pending.insert(&key, b"late", 2).unwrap();
    assert!(store.list().unwrap().is_empty());
    store.insert(&key, b"replacement", 3).unwrap();
    let responses: Vec<_> = stream.try_collect().await.unwrap();
    assert_eq!(
        responses
            .into_iter()
            .flat_map(|r| match r.result.unwrap() {
                Reply::Data(bytes) => bytes,
                _ => panic!(),
            })
            .collect::<Vec<_>>(),
        bytes
    );
    let read_only = CacheController::new(&CacheOptions {
        policy: CachePolicy::ReplayOnly,
        store: Some(store.clone()),
    });
    let clear = |dry_run| {
        request(Operation::Evict(pb::EvictCacheEntries {
            all: true,
            dry_run,
            ..Default::default()
        }))
    };
    assert_eq!(
        read_only.manage(clear(false)).err().unwrap().code(),
        WireCode::PermissionDenied
    );
    read_only
        .manage(clear(true))
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    assert_eq!(store.list().unwrap().len(), 1);
    assert!(
        controller
            .manage(request(Operation::Evict(Default::default())))
            .is_err()
    );
    controller
        .manage(clear(false))
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    assert!(store.list().unwrap().is_empty());
}

#[tokio::test]
async fn framed_byte_stream_uses_the_same_policy_and_rejects_claimed_identity() {
    use hellas_wire::framed::LengthDelimitedMessagePipe;
    use hellas_wire::mux::{MuxConfig, MuxTransport, Role};
    let admin = PeerIdentity([1; 32]);
    for (auth_level, peer, allowed) in [
        (AuthLevel::None, Some(admin), false),
        (AuthLevel::Vouched, Some(PeerIdentity([2; 32])), false),
        (AuthLevel::Vouched, Some(admin), true),
        (AuthLevel::LocalOwner, None, false),
    ] {
        let (left, right) = tokio::io::duplex(1024);
        let server = MuxTransport::spawn::<8, _, _>(
            Role::Server,
            hellas_wire::DefaultClock,
            MuxConfig::default(),
            LengthDelimitedMessagePipe::new(left, 2 * 1024 * 1024).unwrap(),
            TransportContext {
                peer,
                auth_level,
                ..Default::default()
            },
        );
        let client = MuxTransport::spawn::<8, _, _>(
            Role::Client,
            hellas_wire::DefaultClock,
            MuxConfig::default(),
            LengthDelimitedMessagePipe::new(right, 2 * 1024 * 1024).unwrap(),
            TransportContext::default(),
        );
        let (_, controller) = controller();
        let task = tokio::spawn(serve(
            server,
            Authorized {
                service: CacheControlServer(controller),
                policy: AdminPolicy {
                    local_owner: false,
                    peers: vec![admin],
                },
            },
        ));
        let client = CacheControlClientImpl::new(client);
        let result = collect(
            client
                .manage_cache(request(Operation::Stats(Default::default())))
                .await,
        )
        .await;
        if allowed {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().code(), WireCode::PermissionDenied);
        }
        task.abort();
    }
}

#[tokio::test]
async fn websocket_carrier_does_not_turn_an_unauthenticated_upgrade_into_admin() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (_, controller) = controller();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(socket).await.unwrap();
        serve(
            hellas_wire::ws::accept_upgraded(ws, None),
            Authorized {
                service: CacheControlServer(controller),
                policy: AdminPolicy {
                    local_owner: true,
                    peers: vec![PeerIdentity([1; 32])],
                },
            },
        )
        .await;
    });
    let transport = hellas_wire::ws::connect(&format!("ws://{address}"))
        .await
        .unwrap();
    let client = CacheControlClientImpl::new(transport);
    assert_eq!(
        collect(
            client
                .manage_cache(request(Operation::Stats(Default::default())))
                .await
        )
        .await
        .unwrap_err()
        .code(),
        WireCode::PermissionDenied
    );
    task.abort();
}
