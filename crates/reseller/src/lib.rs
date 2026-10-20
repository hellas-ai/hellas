//! Vendor adapters composed with Hellas' shared authority, Work and SDK services.
//! Generic protocol consumption and host services remain in SDK.
// The SDK host's nested transport futures exceed rustc's default query depth.
#![recursion_limit = "256"]

mod contract;
mod host;
pub use contract::{OPENAI_RESPONSES_ENDPOINT, responses_contract};
mod openai;
mod policy;
mod responses_projector;
pub use host::{OpenAiProviderError, OpenAiProviderOptions, start_openai_provider};
pub use openai::{OpenAiConfigError, OpenAiResponsesFetchProvider};
pub use policy::responses_policy;
pub use responses_projector::OpenAiResponsesAdaptorFactory;
