//! Services exposed by the CLI's local control endpoint. Keep registration
//! separate from the socket transport and from peer/inference routing.

use std::path::Path;

use hellas_rpc::cache::CacheOptions;

/// The cache-control service as the local endpoint serves it: admin calls
/// admitted for the local owner only.
#[cfg(any(unix, windows))]
pub(crate) fn cache_control(
    cache: &CacheOptions,
) -> hellas_rpc::serve::Authorized<
    hellas_rpc::services::cache_control::CacheControlServer<
        hellas_rpc::cache::control::CacheController,
    >,
> {
    use hellas_rpc::cache::control::CacheController;
    use hellas_rpc::serve::{AdminPolicy, Authorized};
    use hellas_rpc::services::cache_control::CacheControlServer;

    Authorized {
        service: CacheControlServer(CacheController::new(cache)),
        policy: AdminPolicy {
            local_owner: true,
            ..Default::default()
        },
    }
}

#[cfg(any(unix, windows))]
pub fn serve(
    path: Option<&Path>,
    cache: &CacheOptions,
) -> anyhow::Result<Option<hellas_wire::local::LocalControlServer>> {
    path.map(|path| hellas_wire::local::LocalControlServer::bind(path, cache_control(cache)))
        .transpose()
        .map_err(Into::into)
}

#[cfg(not(any(unix, windows)))]
pub fn serve(path: Option<&Path>, _: &CacheOptions) -> anyhow::Result<()> {
    anyhow::ensure!(
        path.is_none(),
        "local control RPC is not supported on this platform"
    );
    Ok(())
}
