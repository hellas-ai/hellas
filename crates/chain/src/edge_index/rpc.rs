//! Separate read-only EdgeIndex RPC service, exposed by the native indexer.
use super::{EdgeIndex, EdgeIndexError, types};
use hellas_rpc::{
    pb::hellas::chain::v1 as pb,
    pb::services::edge_index::{EdgeIndexHandler, EdgeIndexServer},
};
use hellas_wire::{Dispatcher, StreamTransport, WireCode, WireStatus};
use prost::Message;

fn transcode<A: Message, B: Message + Default>(value: A) -> Result<B, WireStatus> {
    B::decode(value.encode_to_vec().as_slice()).map_err(|e| WireStatus::internal(e.to_string()))
}
fn failure(mut error: EdgeIndexError) -> WireStatus {
    let mut details = types::IndexError {
        schema_version: types::SCHEMA_VERSION,
        code: error.code.into(),
        message: error.message.clone(),
        envelope: error.snapshot.take().map(|value| *value),
    };
    if details.encoded_len() > types::MAX_RESPONSE_BYTES
        || serde_json::to_vec(&details)
            .map_or(true, |bytes| bytes.len() > types::MAX_RESPONSE_BYTES)
    {
        error.status = 413;
        error.code = "response_too_large";
        error.message = "error evidence exceeds 8 MiB".into();
        details.code = error.code.into();
        details.message = error.message.clone();
        details.envelope = None;
    }
    let mut status = WireStatus::new(
        match error.status {
            400 => WireCode::InvalidArgument,
            404 => WireCode::NotFound,
            409 | 410 => WireCode::FailedPrecondition,
            413 => WireCode::ResourceExhausted,
            _ => WireCode::Unavailable,
        },
        format!("{}: {}", error.code, error.message),
    );
    status.details = details.encode_to_vec().into();
    status
}
fn unavailable(message: &str) -> WireStatus {
    failure(EdgeIndexError {
        status: 503,
        code: "index_not_ready",
        message: message.into(),
        snapshot: None,
    })
}
macro_rules! method {
    ($name:ident,$req:ident,$res:ident,$shared:ident) => {
        async fn $name(&self, request: pb::$req) -> Result<pb::$res, WireStatus> {
            let request: types::$shared = transcode(request)?;
            let index = self.clone();
            let permit = index
                .permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| unavailable("index query capacity exhausted; retry later"))?;
            let task = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                index.$name(request)
            });
            let result = tokio::time::timeout(std::time::Duration::from_secs(2), task)
                .await
                .map_err(|_| unavailable("index query deadline exceeded; retry later"))?
                .map_err(|_| unavailable("index query failed"))?
                .map_err(failure)?;
            transcode(result)
        }
    };
}
#[allow(refining_impl_trait)]
impl EdgeIndexHandler for EdgeIndex {
    method!(
        list_edges,
        EdgeIndexListEdgesRequest,
        EdgeIndexListEdgesResponse,
        ListEdgesRequest
    );
    method!(
        get_edge_detail,
        EdgeIndexGetEdgeDetailRequest,
        EdgeIndexGetEdgeDetailResponse,
        GetEdgeDetailRequest
    );
    method!(
        list_edge_events,
        EdgeIndexListEdgeEventsRequest,
        EdgeIndexListEdgeEventsResponse,
        ListEdgeEventsRequest
    );
    method!(
        get_work_channel_detail,
        EdgeIndexGetWorkChannelDetailRequest,
        EdgeIndexGetWorkChannelDetailResponse,
        GetWorkChannelDetailRequest
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
pub(crate) async fn serve_socket(socket: axum::extract::ws::WebSocket, index: EdgeIndex) {
    let transport = hellas_wire::mux::MuxTransport::spawn::<32, hellas_wire::clock::DefaultClock, _>(
        hellas_wire::mux::Role::Server,
        hellas_wire::clock::DefaultClock,
        hellas_wire::mux::MuxConfig::default(),
        Pipe(socket),
        hellas_wire::TransportContext::default(),
    );
    let mut calls = tokio::task::JoinSet::new();
    while let Ok(Some(inbound)) = transport.accept().await {
        while calls.len() >= 16 {
            let _ = calls.join_next().await;
        }
        let server = EdgeIndexServer(index.clone());
        calls.spawn(async move{let _=<EdgeIndexServer<EdgeIndex> as Dispatcher<hellas_wire::mux::MuxTransport>>::dispatch(&server,inbound).await;});
        while calls.try_join_next().is_some() {}
    }
    calls.abort_all();
    while calls.join_next().await.is_some() {}
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
        let response = super::super::http::handle(
            Some(index.clone()),
            "/api/v1/edges".parse().unwrap(),
            headers,
        )
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
            pb::EdgeIndexGetEdgeDetailRequest {
                edge_id: "01".repeat(32),
                payload: None,
                schema_version: 1,
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
