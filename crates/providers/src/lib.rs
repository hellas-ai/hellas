//! Audited sealed-Fetch HTTP egress shared by native hosts and the Hellas
//! CLI: clients, deadlines, credentials and the fixed vendor endpoints.

mod codex_responses;
mod http;
mod openai_responses;
mod responses_fetch;
pub use http::{
    CredentialRefresh, HttpCredential, HttpCredentialConfig, HttpEgressPolicy,
    HttpFetchAdaptorFactory, HttpFetchProvider, HttpProviderConfig, HttpSecret, HttpSecretConfig,
    HttpSecretStore,
};

pub use codex_responses::{
    CODEX_RESPONSES_ENDPOINT, CodexResponsesAdaptorFactory, codex_responses_contract,
};
pub use openai_responses::{OpenAiConfigError, OpenAiResponsesFetchProvider};
pub use responses_fetch::{execute_responses_request, responses_http_client};

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
