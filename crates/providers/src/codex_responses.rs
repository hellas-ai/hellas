//! Sealed Codex Responses contract; the request lens and projector live in
//! `hellas_adaptors::openai::codex_responses::fetch`.

use hellas_adaptors::openai::codex_responses::fetch::create_session;
use hellas_executor::{FetchAdaptorError, FetchAdaptorSession, FetchCall};

pub const CODEX_RESPONSES_ENDPOINT: &str = "https://chatgpt.com/backend-api/codex/responses";

pub fn codex_responses_contract()
-> Result<hellas_rpc::FetchContract, hellas_rpc::protocol::value::CanonicalDecodeError> {
    hellas_rpc::FetchContract::new(
        "codex-responses-0.0.2",
        hellas_rpc::FetchSchema::ResponsesItemsV1,
        "codex-responses-driver-0.0.2",
        hellas_rpc::FetchEgress::FixedHttps(CODEX_RESPONSES_ENDPOINT.into()),
    )
}

#[derive(Clone, Copy, Debug)]
pub struct CodexResponsesAdaptorFactory(hellas_rpc::ContentId);
impl CodexResponsesAdaptorFactory {
    pub fn new() -> Result<Self, hellas_rpc::protocol::value::CanonicalDecodeError> {
        Ok(Self(codex_responses_contract()?.manifest_id()))
    }
}
impl hellas_executor::FetchAdaptorFactory for CodexResponsesAdaptorFactory {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        self.0
    }
    fn create(&self, request: &FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError> {
        create_session(request)
    }
}
