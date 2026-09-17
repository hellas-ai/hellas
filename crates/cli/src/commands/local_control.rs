//! Services exposed by the CLI's local control endpoint. Keep registration
//! separate from the socket transport and from peer/inference routing.

use std::path::Path;

use hellas_rpc::cache::CacheOptions;

#[cfg(unix)]
pub fn serve(
    path: Option<&Path>,
    cache: &CacheOptions,
) -> anyhow::Result<Option<hellas_wire::unix::LocalControlServer>> {
    use hellas_rpc::cache::control::CacheController;
    use hellas_rpc::serve::{AdminPolicy, Authorized};
    use hellas_rpc::services::cache_control::CacheControlServer;
    use hellas_wire::unix::LocalControlServer;

    path.map(|path| {
        LocalControlServer::bind(
            path,
            Authorized {
                service: CacheControlServer(CacheController::new(cache)),
                policy: AdminPolicy {
                    local_owner: true,
                    ..Default::default()
                },
            },
        )
    })
    .transpose()
    .map_err(Into::into)
}

#[cfg(not(unix))]
pub fn serve(path: Option<&Path>, _: &CacheOptions) -> anyhow::Result<()> {
    anyhow::ensure!(path.is_none(), "local control RPC requires Unix sockets");
    Ok(())
}
