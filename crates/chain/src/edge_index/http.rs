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
    match index
        .execute(move |index| {
            Ok(match request {
                Request::List(request) => answer(index.list_edges(request), protobuf),
                Request::Detail(request) => answer(index.get_edge_detail(request), protobuf),
                Request::Events(request) => answer(index.list_edge_events(request), protobuf),
                Request::Channel(request) => {
                    answer(index.get_work_channel_detail(request), protobuf)
                }
            })
        })
        .await
    {
        Ok(response) => response,
        Err(error) => failure(
            error.status,
            error.code,
            &error.message,
            error.snapshot.map(|v| *v),
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
    status: u16,
    code: &'static str,
    message: &str,
    snapshot: Option<super::types::EdgeIndexMetadata>,
    protobuf: bool,
) -> Response {
    let (status, error) = EdgeIndexError {
        status,
        code,
        message: message.into(),
        snapshot: snapshot.map(Box::new),
    }
    .into_details();
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
