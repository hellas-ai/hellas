//! Shared framing and payload encoding for sealed Responses streams.

use hellas_adaptors::{OutputEvent, SseDecoder, WireStreamEvent};
use hellas_executor::{FetchAdaptorError, ProjectedFetch};
use hellas_rpc::fetch::{FetchPayloadError, encode_fetch_event_payload};

/// Reject framing that a permissive SSE decoder would silently normalize.
pub fn push_sse(
    decoder: &mut SseDecoder,
    bytes: &[u8],
) -> Result<Vec<WireStreamEvent>, FetchAdaptorError> {
    let before = decoder.frame_count();
    let ignored_before = decoder.ignored_line_count();
    let noncanonical_before = decoder.noncanonical_line_count();
    let frames = decoder
        .push(bytes)
        .map_err(|_| FetchAdaptorError::failed("invalid SSE framing"))?;
    if decoder.frame_count() - before != frames.len() as u64 {
        return Err(FetchAdaptorError::failed(
            "stream contained a non-data SSE frame",
        ));
    }
    if decoder.ignored_line_count() != ignored_before {
        return Err(FetchAdaptorError::failed(
            "stream contained non-canonical SSE lines",
        ));
    }
    if decoder.noncanonical_line_count() != noncanonical_before {
        return Err(FetchAdaptorError::failed(
            "stream contained non-canonical SSE framing",
        ));
    }
    Ok(frames)
}

pub fn project_events(events: &[OutputEvent]) -> Result<Vec<ProjectedFetch>, FetchPayloadError> {
    events
        .iter()
        .map(|event| encode_fetch_event_payload(event).map(ProjectedFetch::Event))
        .collect()
}
