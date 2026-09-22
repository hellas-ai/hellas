//! Shared HTTP representation layer for the node's read API.
//!
//! Content negotiation, bounded encoding and the response envelope were
//! written twice: once for the EdgeIndex routes and once for the block,
//! transaction and address routes. The header triple below appeared three
//! times. `edge_index::http` also had to reach into `indexer_api` for
//! negotiation, pointing the index module at the server that hosts it.
//! Both adapters now depend on this instead of on each other.
use axum::{
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use prost::Message;
use serde::Serialize;

pub(crate) fn representation(headers: &HeaderMap) -> Option<bool> {
    let Some(accept) = headers.get(header::ACCEPT) else {
        return Some(false);
    };
    let accept = accept.to_str().ok()?;
    let mut json = None;
    let mut protobuf = None;
    let mut protobuf_alias = None;
    for range in accept.split(',') {
        let mut parts = range.trim().split(';');
        let media = parts.next()?.trim();
        let mut quality = 1.0_f32;
        for part in parts {
            if let Some(value) = part.trim().strip_prefix("q=") {
                quality = value.parse().ok()?;
            }
        }
        if !quality.is_finite() || !(0.0..=1.0).contains(&quality) {
            return None;
        }
        let specificity = match media {
            "application/json" | "application/protobuf" | "application/x-protobuf" => 2,
            "application/*" => 1,
            "*/*" => 0,
            _ => continue,
        };
        let applies_json = matches!(media, "application/json" | "application/*" | "*/*");
        let applies_proto = matches!(media, "application/x-protobuf" | "application/*" | "*/*");
        let applies_alias = matches!(media, "application/protobuf" | "application/*" | "*/*");
        for (applies, slot) in [
            (applies_json, &mut json),
            (applies_proto, &mut protobuf),
            (applies_alias, &mut protobuf_alias),
        ] {
            if applies && slot.is_none_or(|(previous, _)| specificity > previous) {
                *slot = Some((specificity, quality));
            }
        }
    }
    let json = json.map_or(0.0, |(_, q)| q);
    let protobuf = protobuf
        .map_or(0.0_f32, |(_, q)| q)
        .max(protobuf_alias.map_or(0.0, |(_, q)| q));
    if json == 0.0 && protobuf == 0.0 {
        None
    } else {
        Some(protobuf > json)
    }
}

/// Encode only the negotiated representation, refusing to exceed `limit`.
///
/// Only the chosen encoding is produced: a value that is small as protobuf
/// and oversized as JSON is still served to a protobuf client.
pub(crate) fn encode<T: Serialize + Message>(
    value: &T,
    protobuf: bool,
    limit: usize,
) -> Result<(&'static str, Vec<u8>), ()> {
    if protobuf {
        if value.encoded_len() > limit {
            return Err(());
        }
        return Ok(("application/x-protobuf", value.encode_to_vec()));
    }
    struct Limited(Vec<u8>, usize);
    impl std::io::Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.1.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other("response too large"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Limited(Vec::new(), limit);
    serde_json::to_writer(&mut output, value).map_err(|_| ())?;
    Ok(("application/json", output.0))
}

/// The response envelope every read route shares.
///
/// `no-store` because these bodies carry consensus proofs bound to a
/// checkpoint, and `Vary: Accept` because the body differs by negotiated
/// representation.
pub(crate) fn respond(status: StatusCode, content_type: &'static str, body: Vec<u8>) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
            (header::VARY, "Accept"),
        ],
        body,
    )
        .into_response()
}

/// Structured failure, in the negotiated representation.
///
/// Every route on this API now answers errors the same way. The proof
/// routes used to return a bare string while the EdgeIndex routes returned
/// an encoded `IndexError`, so a client could not parse failures uniformly
/// and had to branch on which path it had called.
///
/// The code is derived from the status rather than supplied per call site,
/// which keeps the vocabulary closed: the same condition cannot acquire two
/// spellings in two handlers.
pub(crate) fn failure(headers: &HeaderMap, status: StatusCode, message: &str) -> Response {
    let code = match status {
        StatusCode::BAD_REQUEST => "invalid_request",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::NOT_ACCEPTABLE => "not_acceptable",
        StatusCode::PAYLOAD_TOO_LARGE => "response_too_large",
        StatusCode::BAD_GATEWAY => "verification_failed",
        StatusCode::SERVICE_UNAVAILABLE => "unavailable",
        _ => "internal",
    };
    let error = hellas_rpc::edge_index::IndexError {
        schema_version: hellas_rpc::edge_index::SCHEMA_VERSION,
        code: code.into(),
        message: message.to_owned(),
        envelope: None,
    };
    // Negotiation may itself be why we are here; JSON is the documented
    // default and is readable by any client.
    let protobuf = representation(headers).unwrap_or(false);
    match encode(&error, protobuf, crate::proof_verify::MAX_PROOF_BYTES) {
        Ok((content_type, body)) => respond(status, content_type, body),
        Err(()) => (
            status,
            [(header::CACHE_CONTROL, "no-store")],
            "error too large",
        )
            .into_response(),
    }
}

/// `Query<T>` that reports rejection through [`failure`].
///
/// Axum's own `Query` rejection is emitted before any handler runs, so it
/// escapes the negotiated error layer entirely: a malformed `?height=bad`
/// came back as `400 text/plain` with none of the shared headers, no code,
/// and no protobuf encoding, however the client had negotiated. Extractors
/// run first, so uniformity has to be implemented here rather than in the
/// handler.
pub(crate) struct ApiQuery<T>(pub(crate) T);

impl<S, T> axum::extract::FromRequestParts<S> for ApiQuery<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(value)) => Ok(Self(value)),
            Err(rejection) => {
                // Honour the same `Accept` defaulting the handlers apply, so a
                // `/proof` rejection is protobuf exactly like a `/proof` answer.
                let headers =
                    crate::indexer_api::default_proof_accept(parts.headers.clone(), &parts.uri);
                Err(failure(
                    &headers,
                    StatusCode::BAD_REQUEST,
                    rejection.body_text().as_str(),
                ))
            }
        }
    }
}
