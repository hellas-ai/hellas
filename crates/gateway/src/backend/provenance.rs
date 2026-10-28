use crate::execution::StopReason as RuntimeStopReason;
use hellas_adaptors::{Provenance, StopReason, Usage};
use hellas_rpc::provenance::{ExecutionProvenance, encode_hex, encode_public_key};

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
        RuntimeStopReason::StopToken(_) => StopReason::EndOfText,
        RuntimeStopReason::MaxNewTokens => StopReason::MaxOutputTokens,
    }
}
