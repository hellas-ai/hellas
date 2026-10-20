use hellas_rpc::protocol::value::CanonicalDecodeError;
use hellas_rpc::{FetchContract, FetchEgress, FetchSchema};

pub const OPENAI_RESPONSES_ENDPOINT: &str = "https://api.openai.com/v1/responses";

/// Exact request builder, driver, projector and egress implemented by this adapter.
pub fn responses_contract() -> Result<FetchContract, CanonicalDecodeError> {
    FetchContract::new(
        "openai-responses-0.0.3",
        FetchSchema::StatelessResponsesV1,
        "openai-responses-driver-0.0.2",
        FetchEgress::FixedHttps(OPENAI_RESPONSES_ENDPOINT.into()),
    )
}
