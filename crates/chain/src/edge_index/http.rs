use super::{
    EdgeIndex, EdgeIndexError,
    query::{Request, parse_request},
    types::MAX_RESPONSE_BYTES,
};
use axum::{
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use prost::Message;
use serde::Serialize;
pub(crate) async fn handle(index: Option<EdgeIndex>, uri: Uri, headers: HeaderMap) -> Response {
    let protobuf = match crate::explorer_origin::representation(&headers) {
        Some(value) => value,
        None => {
            return failure(
                406,
                "not_acceptable",
                "supported representations are JSON and protobuf",
                None,
                false,
            );
        }
    };
    let Some(index) = index else {
        return failure(
            503,
            "index_not_ready",
            "initial replay is not complete",
            None,
            protobuf,
        );
    };
    let request = match parse_request(uri.path(), uri.query()) {
        Ok(value) => value,
        Err(error) => return failure(400, "invalid_request", &error, None, protobuf),
    };
    let permit = match index.permits.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return failure(
                503,
                "index_not_ready",
                "index query capacity exhausted; retry later",
                None,
                protobuf,
            );
        }
    };
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match request {
            Request::List(request) => answer(index.list_edges(request), protobuf),
            Request::Detail(request) => answer(index.get_edge_detail(request), protobuf),
            Request::Events(request) => answer(index.list_edge_events(request), protobuf),
            Request::Channel(request) => answer(index.get_work_channel_detail(request), protobuf),
        }
    });
    match tokio::time::timeout(std::time::Duration::from_secs(2), task).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => failure(503, "index_not_ready", "index query failed", None, protobuf),
        Err(_) => failure(
            503,
            "index_not_ready",
            "index query deadline exceeded; retry later",
            None,
            protobuf,
        ),
    }
}

fn answer<T: Serialize + Message>(result: Result<T, EdgeIndexError>, protobuf: bool) -> Response {
    match result {
        Ok(value) => {
            let (content_type, body) = if protobuf {
                ("application/x-protobuf", value.encode_to_vec())
            } else {
                match serde_json::to_vec(&value) {
                    Ok(bytes) => ("application/json", bytes),
                    Err(_) => {
                        return failure(
                            503,
                            "index_not_ready",
                            "JSON encoding failed",
                            None,
                            protobuf,
                        );
                    }
                }
            };
            if body.len() > MAX_RESPONSE_BYTES {
                return failure(
                    413,
                    "response_too_large",
                    "response exceeds 8 MiB",
                    None,
                    protobuf,
                );
            }
            (
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CACHE_CONTROL, "no-store"),
                    (header::VARY, "Accept"),
                ],
                body,
            )
                .into_response()
        }
        Err(error) => failure(
            error.status,
            error.code,
            &error.message,
            error.snapshot.map(|value| *value),
            protobuf,
        ),
    }
}
fn failure(
    mut status: u16,
    code: &str,
    message: &str,
    snapshot: Option<super::types::EdgeIndexMetadata>,
    protobuf: bool,
) -> Response {
    let mut error = super::types::IndexError {
        schema_version: super::types::SCHEMA_VERSION,
        code: code.into(),
        message: message.into(),
        envelope: snapshot,
    };
    if error.encoded_len() > MAX_RESPONSE_BYTES
        || serde_json::to_vec(&error).map_or(true, |bytes| bytes.len() > MAX_RESPONSE_BYTES)
    {
        status = 413;
        error.code = "response_too_large".into();
        error.message = "error evidence exceeds 8 MiB".into();
        error.envelope = None;
    }
    let (content_type, body) = if protobuf {
        ("application/x-protobuf", error.encode_to_vec())
    } else {
        (
            "application/json",
            serde_json::to_vec(&error).expect("error serializes"),
        )
    };
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
            (header::VARY, "Accept"),
        ],
        body,
    )
        .into_response()
}
