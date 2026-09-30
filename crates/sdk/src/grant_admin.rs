//! Node control uses live journal permissions on every request. Mutations
//! recheck authority inside the writer after decoding.
use hellas_rpc::{
    pb::host::*,
    protocol::work_grant::{admin::*, records::GrantPolicy},
    services::host_control::{HostControlHandler, HostControlServer},
};
use hellas_wire::{WireCode, WireStatus};
use hellas_work::grant_service::GrantService;
use std::{num::NonZeroU64, sync::Arc};

#[derive(Clone)]
pub struct GrantAdmin {
    service: GrantService,
    resources: Arc<Vec<GrantPolicy>>,
    max_job_millis: NonZeroU64,
}
impl GrantAdmin {
    pub fn new(
        service: GrantService,
        resources: Vec<GrantPolicy>,
        max_job_millis: NonZeroU64,
    ) -> Self {
        Self {
            service,
            resources: Arc::new(resources),
            max_job_millis,
        }
    }
    pub fn dispatcher(self) -> Self {
        self
    }
    fn allows(&self, context: &hellas_wire::TransportContext) -> bool {
        self.service
            .administer(|store, _| Ok(store.state().allows_admin(context)))
            .unwrap_or(false)
    }
    fn command(
        &self,
        request: GrantControlRequest,
        context: &hellas_wire::TransportContext,
    ) -> Result<GrantControlResponse, WireStatus> {
        let command = GrantCommand::decode(&request.command)
            .map_err(|e| WireStatus::new(WireCode::InvalidArgument, e.to_string()))?;
        let reply = self
            .service
            .control_as(command, &self.resources, self.max_job_millis, context)
            .map_err(|e| {
                let code = if matches!(
                    e,
                    hellas_work::work_store::grant::GrantStoreError::Grant(
                        hellas_rpc::protocol::work_grant::records::GrantError::Unauthorized
                    )
                ) {
                    WireCode::PermissionDenied
                } else {
                    WireCode::FailedPrecondition
                };
                WireStatus::new(code, e.to_string())
            })?;
        Ok(GrantControlResponse {
            reply: reply
                .encode()
                .map_err(|e| WireStatus::new(WireCode::ResourceExhausted, e.to_string()))?,
        })
    }
}
impl<T> hellas_wire::Dispatcher<T> for GrantAdmin
where
    T: hellas_wire::StreamTransport + Send + Sync,
    T::Stream: Send,
    <T::Stream as hellas_wire::Stream>::SendHalf: 'static,
    <T::Stream as hellas_wire::Stream>::RecvHalf: 'static,
{
    type Error = hellas_wire::TransportError;
    async fn dispatch(
        &self,
        inbound: hellas_wire::transport::Inbound<T::Stream>,
    ) -> Result<(), Self::Error> {
        use hellas_wire::{MethodMarker, SendHalf, Stream};
        if !self.allows(&inbound.context) {
            let (mut send, _recv) = inbound.stream.split();
            return send
                .close_send(Some(
                    WireStatus::new(
                        WireCode::PermissionDenied,
                        "administrative access is not granted",
                    )
                    .into(),
                ))
                .await
                .map_err(|e| hellas_wire::TransportError::Io(e.to_string()));
        }
        if inbound.method_id == hellas_rpc::services::host_control::GrantControl::METHOD_ID {
            hellas_rpc::call::dispatch_unary_with_context::<
                T,
                hellas_rpc::services::host_control::GrantControl,
                _,
                _,
                _,
            >(inbound, |request, context| async move {
                self.command(request, &context)
            })
            .await
        } else {
            hellas_wire::Dispatcher::<T>::dispatch(&HostControlServer(self.clone()), inbound).await
        }
    }
}

fn host_managed() -> WireStatus {
    WireStatus::new(
        WireCode::Unimplemented,
        "process lifecycle is managed by the host service manager",
    )
}
#[allow(refining_impl_trait)]
impl HostControlHandler for GrantAdmin {
    async fn grant_control(
        &self,
        request: GrantControlRequest,
    ) -> Result<GrantControlResponse, WireStatus> {
        let _ = request;
        Err(WireStatus::new(
            WireCode::PermissionDenied,
            "node control requires transport authority",
        ))
    }

    async fn get_host_status(&self, _: GetHostStatusRequest) -> Result<HostStatus, WireStatus> {
        let available = self.service.administer(|_, _| Ok(())).is_ok();
        Ok(HostStatus {
            version: env!("CARGO_PKG_VERSION").into(),
            provider: Some(ServiceStatus {
                state: if available {
                    RuntimeState::Running
                } else {
                    RuntimeState::Failed
                } as i32,
                detail: "grant Work provider".into(),
            }),
            ..Default::default()
        })
    }
    async fn set_provider_state(
        &self,
        _: SetProviderStateRequest,
    ) -> Result<HostStatus, WireStatus> {
        Err(host_managed())
    }
    async fn set_gateway_state(&self, _: SetGatewayStateRequest) -> Result<HostStatus, WireStatus> {
        Err(host_managed())
    }
    async fn get_gateway_access(
        &self,
        _: GetGatewayAccessRequest,
    ) -> Result<GatewayAccess, WireStatus> {
        Err(host_managed())
    }
}

#[cfg(all(test, unix, feature = "paid-client"))]
mod tests {
    use super::*;
    use hellas_rpc::protocol::work_grant::{UnixMillis, records::Principal};
    use hellas_wire::{
        AuthLevel, Dispatcher, StreamTransport, TransportContext,
        mux::{MuxTransport, Role},
    };
    use hellas_work::{work::WorkBackend, work_store::grant::GrantStore};
    #[derive(Clone)]
    struct NoBackend;
    impl WorkBackend for NoBackend {}
    #[tokio::test]
    async fn host_control_requires_local_owner_before_decoding_and_serves_real_unix() {
        let root = tempfile::tempdir().unwrap();
        hellas_private::restrict_directory(root.path()).unwrap();
        let (bundle, key) =
            crate::test_support::enrollment(iroh::SecretKey::from_bytes(&[6; 32]).public());
        let principal = Principal::verify(bundle).unwrap();
        let mut store = GrantStore::open(
            &root.path().join("journal"),
            hellas_kernel::NetworkId::new("local-admin-test").unwrap(),
            principal.bundle().clone(),
            UnixMillis(1000),
        )
        .unwrap();
        store
            .configure_machine(vec![], 4, UnixMillis(1000))
            .unwrap();
        let service = GrantService::new(
            store,
            Arc::new(key),
            NoBackend,
            vec![],
            Arc::new(|| UnixMillis(1000)),
        )
        .unwrap();
        let admin = GrantAdmin::new(service, vec![], NonZeroU64::new(1000).unwrap());
        let (a, b) = tokio::io::duplex(8192);
        let client =
            hellas_wire::local::transport(a, Role::Client, TransportContext::default()).unwrap();
        let server = hellas_wire::local::transport(
            b,
            Role::Server,
            TransportContext {
                auth_level: AuthLevel::Vouched,
                peer: Some(hellas_wire::PeerIdentity([6; 32])),
                ..Default::default()
            },
        )
        .unwrap();
        let dispatcher = admin.clone().dispatcher();
        let task = tokio::spawn(async move {
            Dispatcher::<MuxTransport>::dispatch(
                &dispatcher,
                server.accept().await.unwrap().unwrap(),
            )
            .await
            .unwrap();
            // Keep the mux alive until the refusal trailer is consumed.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        });
        let error = hellas_rpc::services::host_control::HostControlClientImpl::new(client)
            .grant_control(GrantControlRequest {
                command: vec![0xff],
            })
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("administrative access is not granted"),
            "{error}"
        );
        task.await.unwrap();
        let socket = root.path().join("control.sock");
        let _server = crate::local::LocalControlServer::bind(&socket, admin.dispatcher()).unwrap();
        let client = hellas_rpc::services::host_control::HostControlClientImpl::new(
            crate::local::connect(&socket).await.unwrap(),
        );
        let response = client
            .grant_control(GrantControlRequest {
                command: GrantCommand::Users(UserCommand::List).encode().unwrap(),
            })
            .await
            .unwrap();
        assert!(
            matches!(GrantReply::decode(&response.reply).unwrap(), GrantReply::Users(entries) if entries.len() == 1 && entries[0].permissions == UserPermissions::Owner)
        );
    }
    #[tokio::test]
    async fn revocation_is_checked_on_every_rpc_of_an_existing_connection() {
        let root = tempfile::tempdir().unwrap();
        let (bundle, key) =
            crate::test_support::enrollment(iroh::SecretKey::from_bytes(&[6; 32]).public());
        let admin_principal = Principal::verify(
            crate::test_support::enrollment(iroh::SecretKey::from_bytes(&[7; 32]).public()).0,
        )
        .unwrap();
        let store = GrantStore::open(
            root.path(),
            hellas_kernel::NetworkId::new("admin-revoke").unwrap(),
            bundle,
            UnixMillis(1000),
        )
        .unwrap();
        let service = GrantService::new(
            store,
            Arc::new(key),
            NoBackend,
            vec![],
            Arc::new(|| UnixMillis(1000)),
        )
        .unwrap();
        let max = NonZeroU64::new(1000).unwrap();
        service
            .control(
                GrantCommand::Users(UserCommand::Add {
                    principal: Box::new(admin_principal.clone()),
                    expected_revision: None,
                    admin: true,
                    work: None,
                }),
                &[],
                max,
            )
            .unwrap();
        let admin = GrantAdmin::new(service.clone(), vec![], max);
        let (a, b) = tokio::io::duplex(16384);
        let client =
            hellas_wire::local::transport(a, Role::Client, TransportContext::default()).unwrap();
        let server = hellas_wire::local::transport(
            b,
            Role::Server,
            TransportContext {
                peer: Some(hellas_wire::PeerIdentity(admin_principal.transport())),
                auth_level: AuthLevel::Vouched,
                ..Default::default()
            },
        )
        .unwrap();
        let serving = tokio::spawn(async move {
            while let Some(inbound) = server.accept().await.unwrap() {
                Dispatcher::<MuxTransport>::dispatch(&admin, inbound)
                    .await
                    .unwrap();
            }
        });
        let client = hellas_rpc::services::host_control::HostControlClientImpl::new(client);
        let request = || GrantControlRequest {
            command: GrantCommand::Users(UserCommand::List).encode().unwrap(),
        };
        assert!(client.grant_control(request()).await.is_ok());
        service
            .control(
                GrantCommand::Users(UserCommand::Remove {
                    id: admin_principal.id(),
                    expected_revision: hellas_rpc::protocol::work_grant::Revision(1),
                }),
                &[],
                max,
            )
            .unwrap();
        let error = client.grant_control(request()).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("administrative access is not granted"),
            "{error}"
        );
        serving.abort();
    }
}
