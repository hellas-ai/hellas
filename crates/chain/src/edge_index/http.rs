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
pub(crate) async fn handle(index: EdgeIndex, uri: Uri, headers: HeaderMap) -> Response {
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

/// Encode only the negotiated representation and stop JSON at the response budget.
fn encode<T: Serialize + Message>(
    value: &T,
    protobuf: bool,
) -> Result<(&'static str, Vec<u8>), ()> {
    if protobuf {
        if value.encoded_len() > MAX_RESPONSE_BYTES {
            return Err(());
        }
        return Ok(("application/x-protobuf", value.encode_to_vec()));
    }
    struct Limited(Vec<u8>);
    impl std::io::Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_RESPONSE_BYTES.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other("response too large"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Limited(Vec::new());
    serde_json::to_writer(&mut output, value).map_err(|_| ())?;
    Ok(("application/json", output.0))
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
