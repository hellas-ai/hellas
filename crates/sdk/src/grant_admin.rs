//! Local-only HostControl adapter. Administrative access is checked before any
//! command is decoded; remote Work only exposes signed standing and job methods.
use hellas_rpc::{
    pb::host::{
        GatewayAccess, GetGatewayAccessRequest, GetHostStatusRequest, GrantControlRequest,
        GrantControlResponse, HostStatus, RuntimeState, ServiceStatus, SetGatewayStateRequest,
        SetProviderStateRequest,
    },
    protocol::work_grant::{admin::GrantCommand, records::GrantPolicy},
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
    /// Mount only on the authenticated local-control carrier. This wrapper
    /// does not include any peer grants and therefore cannot authorize QUIC.
    pub fn dispatcher(self) -> hellas_rpc::serve::Authorized<HostControlServer<Self>> {
        hellas_rpc::serve::Authorized {
            service: HostControlServer(self),
            policy: hellas_rpc::serve::AdminPolicy {
                local_owner: true,
                peers: vec![],
            },
        }
    }
}
fn unsupported() -> WireStatus {
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
        let command = GrantCommand::decode(&request.command)
            .map_err(|e| WireStatus::new(WireCode::InvalidArgument, e.to_string()))?;
        let reply = self
            .service
            .control(command, &self.resources, self.max_job_millis)
            .map_err(|e| WireStatus::new(WireCode::FailedPrecondition, e.to_string()))?;
        Ok(GrantControlResponse {
            reply: reply
                .encode()
                .map_err(|e| WireStatus::new(WireCode::ResourceExhausted, e.to_string()))?,
        })
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
        Err(unsupported())
    }
    async fn set_gateway_state(&self, _: SetGatewayStateRequest) -> Result<HostStatus, WireStatus> {
        Err(unsupported())
    }
    async fn get_gateway_access(
        &self,
        _: GetGatewayAccessRequest,
    ) -> Result<GatewayAccess, WireStatus> {
        Err(unsupported())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use hellas_rpc::protocol::work_grant::admin::GrantReply;
    use hellas_rpc::protocol::work_grant::{UnixMillis, records::Principal};
    use hellas_wire::{
        AuthLevel, Dispatcher, StreamTransport, TransportContext,
        mux::{MuxTransport, Role},
    };
    use hellas_work::{work::WorkBackend, work_store::grant::GrantStore};
    #[derive(Clone)]
    struct NoBackend;
    impl WorkBackend for NoBackend {
        fn try_admit(
            &self,
            domain: hellas_work::work::admission::CapacityDomain,
        ) -> Result<hellas_work::work::admission::WorkPermit, hellas_work::work::BackendFault>
        {
            Err(hellas_work::work::admission::AdmissionError::Unsupported(domain).into())
        }
    }
    #[tokio::test]
    async fn host_control_requires_local_owner_before_decoding_and_serves_real_unix() {
        let root = tempfile::tempdir().unwrap();
        hellas_private::restrict_directory(root.path()).unwrap();
        let (bundle, key) =
            crate::test_identity::enrollment(iroh::SecretKey::from_bytes(&[6; 32]).public());
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
                command: GrantCommand::List.encode().unwrap(),
            })
            .await
            .unwrap();
        assert!(
            matches!(GrantReply::decode(&response.reply).unwrap(), GrantReply::Listing(entries) if entries.is_empty())
        );
    }
}
