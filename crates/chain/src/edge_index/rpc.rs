//! Separate read-only EdgeIndex RPC service, exposed by the native indexer.
use super::{EdgeIndex, EdgeIndexError, types};
use hellas_rpc::pb::services::edge_index::{EdgeIndexHandler, EdgeIndexServer};
use hellas_wire::{WireCode, WireStatus};
use prost::Message;

fn failure(error: EdgeIndexError) -> WireStatus {
    let (mut status, mut details) = error.into_details();
    if details.encoded_len() > types::MAX_RESPONSE_BYTES {
        status = 413;
        details.code = "response_too_large".into();
        details.message = "error evidence exceeds 8 MiB".into();
        details.envelope = None;
    }
    let mut status = WireStatus::new(
        match status {
            400 => WireCode::InvalidArgument,
            404 => WireCode::NotFound,
            409 | 410 => WireCode::FailedPrecondition,
            413 => WireCode::ResourceExhausted,
            500 => WireCode::Internal,
            _ => WireCode::Unavailable,
        },
        format!("{}: {}", details.code, details.message),
    );
    status.details = details.encode_to_vec().into();
    status
}
macro_rules! method {
    ($name:ident,$req:ident,$res:ident) => {
        async fn $name(&self, request: types::$req) -> Result<types::$res, WireStatus> {
            let result = self
                .execute(move |index| index.$name(request))
                .await
                .map_err(failure)?;
            if result.encoded_len() > types::MAX_RESPONSE_BYTES {
                return Err(failure(EdgeIndexError {
                    status: 413,
                    code: "response_too_large",
                    message: "response exceeds 8 MiB".into(),
                    snapshot: None,
                }));
            }
            Ok(result)
        }
    };
}
#[allow(refining_impl_trait)]
impl EdgeIndexHandler for EdgeIndex {
    method!(list_edges, ListEdgesRequest, ListEdgesResponse);
    method!(get_edge_detail, GetEdgeDetailRequest, GetEdgeDetailResponse);
    method!(
        list_edge_events,
        ListEdgeEventsRequest,
        ListEdgeEventsResponse
    );
    method!(
        get_work_channel_detail,
        GetWorkChannelDetailRequest,
        GetWorkChannelDetailResponse
    );
}
struct Pipe(axum::extract::ws::WebSocket);
impl hellas_wire::mux::MessagePipe for Pipe {
    type SendError = axum::Error;
    type RecvError = axum::Error;
    async fn send_message(&mut self, bytes: bytes::Bytes) -> Result<(), Self::SendError> {
        self.0.send(axum::extract::ws::Message::Binary(bytes)).await
    }
    async fn recv_message(&mut self) -> Result<Option<bytes::Bytes>, Self::RecvError> {
        while let Some(message) = self.0.recv().await {
            match message? {
                axum::extract::ws::Message::Binary(bytes) => return Ok(Some(bytes)),
                axum::extract::ws::Message::Close(_) => return Ok(None),
                _ => {}
            }
        }
        Ok(None)
    }
}
/// Concurrent dispatches allowed per EdgeIndex connection.
const MAX_IN_FLIGHT: usize = 16;

pub(crate) async fn serve_socket(socket: axum::extract::ws::WebSocket, index: EdgeIndex) {
    let transport = hellas_wire::mux::MuxTransport::spawn::<32, hellas_wire::clock::DefaultClock, _>(
        hellas_wire::mux::Role::Server,
        hellas_wire::clock::DefaultClock,
        hellas_wire::mux::MuxConfig::default(),
        Pipe(socket),
        hellas_wire::TransportContext::default(),
    );
    // Bounded: every EdgeIndex method is a short read, so capping concurrent
    // dispatches costs nothing and keeps one connection from monopolising the
    // index. Unlike the light-client service, nothing here holds a stream open.
    let served = hellas_wire::serve_dispatched(transport, "edge-index", Some(MAX_IN_FLIGHT), || {
        EdgeIndexServer(index.clone())
    })
    .await;
    if let Err(error) = served {
        tracing::warn!(%error, "edge index rpc transport closed with an error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn http_and_rpc_share_query_capacity_and_structured_errors() {
        let dir = tempfile::tempdir().unwrap();
        let index = EdgeIndex::open(
            &dir.path().join("index.redb"),
            "hellas-devnet-1".into(),
            "ab".repeat(32),
            "cd".repeat(32),
        )
        .unwrap();
        let permit = index.permits.clone().try_acquire_many_owned(16).unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/x-protobuf"),
        );
        let response =
            super::super::http::handle(index.clone(), "/api/v1/edges".parse().unwrap(), headers)
                .await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let bytes = axum::body::to_bytes(response.into_body(), types::MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        let error = types::IndexError::decode(bytes).unwrap();
        assert_eq!(error.code, "index_not_ready");
        assert!(error.message.contains("capacity"));
        let status = EdgeIndexHandler::get_edge_detail(
            &index,
            types::GetEdgeDetailRequest {
                edge_id: "01".repeat(32),
                payload: None,
                schema_version: super::types::SCHEMA_VERSION,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), WireCode::Unavailable);
        let error = types::IndexError::decode(status.details().clone()).unwrap();
        assert_eq!(error.code, "index_not_ready");
        assert!(error.message.contains("capacity"));
        drop(permit);
        assert_eq!(index.permits.available_permits(), 16);
    }
}
