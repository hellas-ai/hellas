//! Content RPC on the existing authenticated owner control connection.
use super::*;
use hellas_authority::content as access;
use hellas_rpc::services::{content as rpc, resolve};
use hellas_store::content::{ContentService, DiskStore};
use hellas_wire::{Inbound, MethodMarker, TransportError};

impl ControlSession {
    async fn owner_content(
        &self,
        operation: &'static str,
    ) -> Result<ContentService<DiskStore>, WireStatus> {
        let store = self.content.clone().ok_or_else(unavailable)?;
        let (scope, writer) = self
            .node
            .content_owner_for_session(self.session.clone(), self.binding, operation)
            .await
            .map_err(node_error)?;
        Ok(ContentService::new(Arc::new(store), scope).with_write_authority(writer))
    }
}
impl<T> Dispatcher<T> for ControlSession
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send,
    <T::Stream as hellas_wire::Stream>::SendHalf: 'static,
    <T::Stream as hellas_wire::Stream>::RecvHalf: 'static,
{
    type Error = TransportError;
    async fn dispatch(&self, mut inbound: Inbound<T::Stream>) -> Result<(), Self::Error> {
        if self.caller().await.is_err() {
            use hellas_wire::Stream;
            inbound.stream.reset(WireCode::PermissionDenied);
            return Err(TransportError::Protocol(
                "control session is no longer authenticated".into(),
            ));
        }
        let operation = match inbound.method_id {
            rpc::Stat::METHOD_ID
            | rpc::Chunks::METHOD_ID
            | rpc::Read::METHOD_ID
            | rpc::ListPins::METHOD_ID
            | rpc::WatchPins::METHOD_ID => Some(access::READ),
            rpc::Upload::METHOD_ID => Some(access::UPLOAD),
            rpc::Acquire::METHOD_ID => Some(access::ACQUIRE),
            rpc::SetPin::METHOD_ID => Some(access::SET_PIN),
            rpc::Collect::METHOD_ID => Some(access::COLLECT),
            resolve::ResolveMethod::METHOD_ID => Some(access::RESOLVE),
            _ => None,
        };
        if let Some(operation) = operation {
            let service = match self.owner_content(operation).await {
                Ok(service) => service,
                Err(_) => {
                    use hellas_wire::Stream;
                    inbound.stream.reset(WireCode::PermissionDenied);
                    return Err(TransportError::Protocol(
                        "content authority unavailable".into(),
                    ));
                }
            };
            if operation == access::RESOLVE {
                Dispatcher::<T>::dispatch(&resolve::ResolveServer(service), inbound).await
            } else {
                Dispatcher::<T>::dispatch(&rpc::ContentServer(service), inbound).await
            }
        } else {
            Dispatcher::<T>::dispatch(&HostControlServer(self.clone()), inbound).await
        }
    }
}
