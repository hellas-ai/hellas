//! Audited sealed-Fetch upstream drivers and projectors shared by native
//! hosts and the Hellas CLI.

pub mod account;
mod codex_responses;
mod http;
mod responses_fetch;
pub mod stream;
pub use http::{
    CredentialRefresh, HttpCredential, HttpCredentialConfig, HttpEgressPolicy,
    HttpFetchAdaptorFactory, HttpFetchProvider, HttpProviderConfig, HttpSecret, HttpSecretConfig,
    HttpSecretStore,
};

pub use codex_responses::{
    CODEX_RESPONSES_ENDPOINT, CodexResponsesAdaptorFactory, codex_responses_contract,
};
pub use responses_fetch::{execute_responses_request, responses_http_client};

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

mod openai;
mod openai_contract;
mod openai_responses_projector;
pub use openai::{OpenAiConfigError, OpenAiResponsesFetchProvider};
pub use openai_contract::{OPENAI_RESPONSES_ENDPOINT, responses_contract};
pub use openai_responses_projector::OpenAiResponsesAdaptorFactory;

mod upstream;
