use crate::{ArchiveOptions, GatewayResult, Route, WorkExecutionBackend, jobs::Jobs};
use std::{net::SocketAddr, sync::Arc};
pub struct Server {
    address: SocketAddr,
    bearer: String,
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<GatewayResult<()>>,
    work: Arc<dyn WorkExecutionBackend>,
}
impl Server {
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn bearer(&self) -> &str {
        &self.bearer
    }
    pub async fn shutdown(mut self) -> GatewayResult<()> {
        self.stop.send_replace(true);
        let result = (&mut self.task).await?;
        self.work.drain().await?;
        result
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}
pub async fn serve(
    node: hellas_authority::node::NodeCoordinator,
    bearer: String,
    archive: ArchiveOptions,
    work: Arc<dyn WorkExecutionBackend>,
    jobs: Arc<Jobs>,
    routes: Vec<Route>,
) -> GatewayResult<Server> {
    let router = crate::router::router(routes, work.clone(), jobs, Default::default()).await?;
    let router = crate::listener_router(router, node, archive).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(crate::serve_listener(listener, router, stopped));
    Ok(Server {
        address,
        bearer,
        stop,
        task,
        work,
    })
}
