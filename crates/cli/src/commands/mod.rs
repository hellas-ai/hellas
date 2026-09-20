pub type CliResult<T = ()> = anyhow::Result<T>;

use anyhow::Context as _;
use std::io::Read as _;
use std::path::Path;
use std::time::Duration;

pub mod artifact;
#[cfg(feature = "chain")]
pub mod chain;
pub(crate) mod codex_auth;
#[cfg(feature = "node")]
pub(crate) mod discovery;
pub mod environment;
pub mod fetch;
pub mod identity;
#[cfg(feature = "llm")]
pub mod llm;
#[cfg(any(feature = "gateway", feature = "node", test))]
pub mod local_control;
pub mod monitor;
pub mod output_cache;
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
    let file = hellas_store::open_regular_file(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= maximum,
        "{label} {} is {} bytes, over the {maximum}-byte limit",
        path.display(),
        bytes.len()
    );
    Ok(bytes)
}

pub(crate) fn http_client(request_timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(request_timeout)
        .build()
        .expect("HTTP client configuration is valid")
}
