//! Vendor adapters composed with Hellas' shared authority, Work and SDK services.
//! Generic protocol consumption and host services remain in SDK.
// The SDK host's nested transport futures exceed rustc's default query depth.
#![recursion_limit = "256"]

mod host;
mod policy;
pub use host::{OpenAiProviderError, OpenAiProviderOptions, start_openai_provider};
pub use policy::responses_policy;
