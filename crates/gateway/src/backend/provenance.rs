use axum::http::{HeaderName, HeaderValue};
use hellas_adaptors::{Provenance, StopReason, Usage};
use hellas_rpc::protocol::invocation::compute::StopReason as RuntimeStopReason;
use hellas_rpc::provenance::{
    ExecutionProvenance, MAX_INLINE_TRANSCRIPT_BYTES, TRANSCRIPT_DIGEST_KEY, TRANSCRIPT_KEY,
    encode_hex, encode_public_key,
};

/// The evidence header for a completed job's signed transcript: the base64
/// canonical bytes while they fit [`MAX_INLINE_TRANSCRIPT_BYTES`], otherwise
/// the lowercase hex SHA-256 of those bytes. In the latter case the transcript
/// is not delivered to the HTTP caller: the digest only lets a caller who
/// obtains the canonical bytes out of band verify them, and the gateway
/// neither retains nor serves a copy.
pub(crate) fn transcript_header(transcript: &[u8]) -> (HeaderName, HeaderValue) {
    use base64::Engine as _;
    use sha2::Digest as _;
    if transcript.len().div_ceil(3) * 4 <= MAX_INLINE_TRANSCRIPT_BYTES {
        let encoded = base64::engine::general_purpose::STANDARD.encode(transcript);
        (
            HeaderName::from_static(TRANSCRIPT_KEY),
            HeaderValue::from_str(&encoded).expect("base64 is always a valid header value"),
        )
    } else {
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&sha2::Sha256::digest(transcript));
        (
            HeaderName::from_static(TRANSCRIPT_DIGEST_KEY),
            HeaderValue::from_str(&encode_hex(&digest))
                .expect("hex is always a valid header value"),
        )
    }
}

pub(crate) fn json_response(
    status: axum::http::StatusCode,
    mut body: serde_json::Value,
    accepted: Option<&ExecutionProvenance>,
    transcript: Option<&[u8]>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(transcript) = transcript {
        body["hellas"] = serde_json::to_value(completed_provenance(accepted, transcript))
            .expect("provenance serializes");
    }
    (status, axum::Json(body)).into_response()
}

/// The provenance of a completed job: its accepted identity, if the source
/// reported one, and the base64 canonical bytes of its signed transcript.
pub(crate) fn completed_provenance(
    accepted: Option<&ExecutionProvenance>,
    transcript: &[u8],
) -> Provenance {
    use base64::Engine as _;
    Provenance {
        transcript: Some(base64::engine::general_purpose::STANDARD.encode(transcript)),
        ..accepted.map(provenance_from_execution).unwrap_or_default()
    }
}

/// The accepted job's identity, as the `hellas` object renders it.
pub(crate) fn provenance_from_execution(provenance: &ExecutionProvenance) -> Provenance {
    Provenance {
        commitment: Some(encode_hex(&provenance.commitment_id)),
        provider: Some(encode_public_key(&provenance.provider)),
        transcript: None,
    }
}

pub(super) fn usage(input_tokens: u32, output_tokens: u64) -> Usage {
    let input = u64::from(input_tokens);
    Usage {
        input_tokens: Some(input),
        output_tokens: Some(output_tokens),
        total_tokens: Some(input.saturating_add(output_tokens)),
    }
}

pub(super) fn stop_reason_from_runtime(stop_reason: RuntimeStopReason) -> StopReason {
    match stop_reason {
        RuntimeStopReason::Matched(_) => StopReason::EndOfText,
        RuntimeStopReason::MaxSteps => StopReason::MaxOutputTokens,
    }
}
