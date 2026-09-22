use super::{
    EdgeIndex, EdgeIndexError,
    query::{Request, parse_request},
    types::MAX_RESPONSE_BYTES,
};
use axum::{
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use prost::Message;
use serde::Serialize;
pub(crate) async fn handle(index: EdgeIndex, uri: Uri, headers: HeaderMap) -> Response {
    let protobuf = match crate::http_api::representation(&headers) {
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
            let (content_type, body) = match encode(&value, protobuf) {
                Ok(encoded) => encoded,
                Err(()) => {
                    return failure(
                        413,
                        "response_too_large",
                        "response exceeds 8 MiB",
                        None,
                        protobuf,
                    );
                }
            };
            crate::http_api::respond(StatusCode::OK, content_type, body)
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
    let (content_type, body) = match encode(&error, protobuf) {
        Ok(encoded) => encoded,
        Err(()) => {
            return failure(
                413,
                "response_too_large",
                "error evidence exceeds 8 MiB",
                None,
                protobuf,
            );
        }
    };
    crate::http_api::respond(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        content_type,
        body,
    )
}

fn encode<T: Serialize + Message>(
    value: &T,
    protobuf: bool,
) -> Result<(&'static str, Vec<u8>), ()> {
    crate::http_api::encode(value, protobuf, MAX_RESPONSE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_selected_representation_must_fit() {
        let value = super::super::types::FundingQuery {
            coins: vec!["\"".repeat(MAX_RESPONSE_BYTES / 2)],
        };
        let (_, protobuf) = encode(&value, true).unwrap();
        assert!(protobuf.len() < MAX_RESPONSE_BYTES);
        assert!(encode(&value, false).is_err());
        let value = super::super::types::FundingQuery {
            coins: vec!["a".repeat(MAX_RESPONSE_BYTES)],
        };
        assert!(encode(&value, true).is_err());
        assert!(encode(&value, false).is_err());
    }
}
