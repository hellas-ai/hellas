use hellas_gateway::{ArchiveOptions, GatewayResult, Route, WorkExecutionBackend, jobs::Jobs};
use std::{net::SocketAddr, sync::Arc};
pub(crate) struct Server {
    address: SocketAddr,
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<GatewayResult<()>>,
    work: Arc<dyn WorkExecutionBackend>,
}
impl Server {
    pub fn address(&self) -> SocketAddr {
        self.address
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
pub(crate) async fn serve(
    node: hellas_authority::node::NodeCoordinator,
    archive: ArchiveOptions,
    work: Arc<dyn WorkExecutionBackend>,
    jobs: Arc<Jobs>,
    routes: Vec<Route>,
) -> GatewayResult<Server> {
    let router =
        hellas_gateway::router::router(routes, work.clone(), jobs, Default::default()).await?;
    let router = hellas_gateway::listener_router(router, node, archive).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task = hellas_gateway::serve_listener(listener, router, stopped);
    Ok(Server {
        address,
        stop,
        task,
        work,
    })
}
