use hellas_adaptors::{Provenance, StopReason, Usage};
use hellas_rpc::protocol::invocation::compute::StopReason as RuntimeStopReason;
use hellas_rpc::provenance::{ExecutionProvenance, encode_hex, encode_public_key};

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
