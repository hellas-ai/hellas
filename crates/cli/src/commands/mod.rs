pub type CliResult<T = ()> = anyhow::Result<T>;

use anyhow::Context as _;
use std::path::Path;

pub mod admin;
pub mod chain;
pub mod chain_node;
pub(crate) mod codex_auth;
pub mod contributions;

pub mod grant_gateway;
pub mod identity;
pub mod monitor;
pub mod rpc;
pub mod serve;
pub mod store;
pub mod transact;
pub mod trust;

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
