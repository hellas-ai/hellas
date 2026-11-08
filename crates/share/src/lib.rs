//! Shares a vendor API account through Hellas grants: a sealed Fetch route
//! backed by the owner's account, its grant terms and the host wiring that
//! serves it. Wire formats live in adaptors; HTTP egress lives in providers.
// The SDK host's nested transport futures exceed rustc's default query depth.
#![recursion_limit = "256"]

mod host;
mod policy;
pub use host::{OpenAiProviderError, OpenAiProviderOptions, start_openai_provider};
pub use policy::{ResponsesPolicyOptions, responses_policy};
