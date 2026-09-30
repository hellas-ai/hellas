pub type CliResult<T = ()> = anyhow::Result<T>;

use anyhow::Context as _;
use std::path::Path;
use std::time::Duration;

#[cfg(any(feature = "node", all(feature = "cloud", unix)))]
pub mod admin;
#[cfg(feature = "chain")]
pub mod chain;
pub(crate) mod codex_auth;
pub mod contributions;
#[cfg(feature = "node")]
pub(crate) mod discovery;
pub mod environment;
#[cfg(feature = "gateway")]
pub mod gateway_cache;
#[cfg(feature = "gateway")]
pub mod grant_gateway;
pub mod identity;
#[cfg(feature = "gateway")]
pub mod llm;
pub mod monitor;
#[cfg(feature = "node")]
pub mod paid_work;
pub mod rpc;
#[cfg(feature = "node")]
pub mod serve;
pub mod store;

/// Open an operator-selected ordinary file without hanging on a FIFO or
/// device, then retain at most one byte beyond its protocol limit.
///
/// The extra byte distinguishes an exact-limit input from an oversized one
/// even if the file grows after it is opened. Callers parse only after this
/// function has enforced the bound.
pub(crate) fn read_bounded_regular_file(
    path: &Path,
    label: &str,
    maximum: usize,
) -> CliResult<Vec<u8>> {
    hellas_private::read_bounded_regular_file(path, maximum).with_context(|| {
        format!(
            "failed to read {label} {} (limit {maximum} bytes)",
            path.display()
        )
    })
}

pub(crate) fn http_client(request_timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(request_timeout)
        .build()
        .expect("HTTP client configuration is valid")
}
