use super::{Core, Result};
use crate::{
    ProviderOpen,
    gateway_work::provider::IrohBackend,
    node_control::NodeControl,
    paid_provider::{MountedSetup, MountedWork, WorkRunner, WorkRunnerConfig, WorkWatcher},
    work_router::WorkRouter,
};
use hellas_authority::grant_service::{GrantService, WorkAdministration};
use hellas_wire::peers::{PeerDirectory, PeerId};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

pub(super) struct Bound {
    pub port: u16,
    pub endpoint: iroh::Endpoint,
    open: Arc<ProviderOpen>,
    grants: GrantService,
    administration: WorkAdministration,
    work: MountedWork,
    setup: MountedSetup,
    runner: Mutex<Option<WorkRunner>>,
    chain: crate::work_config::WorkConfig,
}
impl Bound {
    pub async fn prepare(core: &Arc<Core>, id: &str, port: u16) -> Result<Self> {
        let options = &core.runtime.options;
        let chain = crate::work_config::WorkConfig::from_chain_dir(options.chain.clone())?;
        let open = options
            .prover
            .clone()
            .ok_or("iroh listener requires its enrollment and prover")?;
        if hellas_authority::model::grant::records::grant_transport(open.enrollment())?
            != *options.transport.public().as_bytes()
        {
            return Err("iroh transport differs from the provider enrollment".into());
        }
        let alpns = crate::provider::served_alpns(true, true, options.remote_control.enabled());
        let endpoint = match core.runtime.endpoint.lock().await.take() {
            Some(endpoint) => {
                endpoint.set_alpns(alpns);
                endpoint
            }
            None => {
                crate::provider::bind_port(
                    iroh::Endpoint::builder(iroh::endpoint::presets::N0)
                        .secret_key(options.transport.clone())
                        .hooks(options.remote_control.clone())
                        .alpns(alpns),
                    port,
                )?
                .bind()
                .await?
            }
        };
        let backend = IrohBackend {
            core: Arc::downgrade(core),
            listener: id.into(),
            assurance: match open.enrollment().genesis.statement.root_kind {
                hellas_rpc::RootKind::Software => hellas_rpc::Assurance::ProducerSigned,
                hellas_rpc::RootKind::SecureEnclave => hellas_rpc::Assurance::AppleAppAttest,
            },
        };
        let prepare = async {
            let grants = GrantService::from_node(
                options.node.clone(),
                open.enrollment(),
                options.signer.clone(),
                backend.clone(),
                endpoint
                    .addr()
                    .ip_addrs()
                    .map(ToString::to_string)
                    .collect(),
                options.content.clone(),
            )
            .await?;
            let administration = WorkAdministration::new(
                grants.clone(),
                Default::default(),
                std::num::NonZeroU64::new(u64::MAX).unwrap(),
            );
            let work = MountedWork::with_backend(backend);
            let setup = MountedSetup::with_content_store(options.content.clone());
            let runner = WorkRunner::discover(
                WorkRunnerConfig {
                    chain: options.chain.clone(),
                    settlement_key: options.settlement.clone(),
                },
                work.clone(),
                setup.clone(),
            )
            .await?;
            Ok(Self {
                port,
                chain,
                endpoint: endpoint.clone(),
                open,
                grants,
                administration,
                work,
                setup,
                runner: Mutex::new(Some(runner)),
            })
        }
        .await;
        if prepare.is_err() {
            endpoint.close().await;
        }
        prepare
    }

    pub fn control(&self) -> NodeControl {
        NodeControl::with_work(self.administration.clone())
    }

    pub async fn serve(
        &self,
        core: std::sync::Weak<Core>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let runner = self
            .runner
            .lock()
            .map_err(|_| "iroh runner lock poisoned")?
            .take()
            .ok_or("iroh listener already running")?;
        let core_options = core.upgrade().ok_or("daemon stopped")?;
        let mut watcher = WorkWatcher::spawn(
            runner.on_chain(
                self.chain.clone(),
                core_options.node().clone(),
                self.open.enrollment().clone(),
                self.endpoint
                    .addr()
                    .ip_addrs()
                    .map(ToString::to_string)
                    .collect(),
            ),
        );
        let content = core_options.runtime.options.content.clone();
        let control = core_options
            .control()?
            .with_remote_admission(core_options.runtime.options.remote_control.clone());
        drop(core_options);
        let directory = Arc::new(PeerDirectory::with_config(
            PeerId::from_bytes(*self.endpoint.id().as_bytes()),
            hellas_rpc::peer_directory_config(),
        ));
        let mut node = crate::provider::NodeHandlerImpl::new(
            self.endpoint.id(),
            hellas_rpc::GIT_REV.into(),
            vec![],
            directory.clone(),
        );
        node.service_alpns =
            crate::provider::served_alpns(true, true, control.remote_admission().enabled())
                .into_iter()
                .map(|alpn| String::from_utf8_lossy(&alpn).into_owned())
                .collect();
        let router = WorkRouter::both(self.work.clone(), self.grants.clone());
        let (quiesce, quiesced) = watch::channel(false);
        let mut tasks = tokio::task::JoinSet::new();
        let mut admission = crate::transport_admission::Admission::new();
        loop {
            let incoming = tokio::select! {
                biased;
                _ = stop.wait_for(|stop| *stop) => break,
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed { tracing::warn!(%error, "iroh connection failed"); }
                    continue;
                }
                incoming = self.endpoint.accept() => match incoming { Some(incoming) => incoming, None => break },
            };
            if tasks.len() >= 128 {
                incoming.refuse();
                continue;
            }
            let Some(pending) = admission.accept(incoming) else {
                continue;
            };
            let (open, node, manager, setup, router, content, mut stopped) = (
                self.open.clone(),
                node.clone(),
                directory.manager(),
                self.setup.clone(),
                router.clone(),
                content.clone(),
                quiesced.clone(),
            );
            let control = control.clone();
            tasks.spawn(async move {
                let admitted = tokio::select! {
                    _ = stopped.wait_for(|stop| *stop) => return,
                    admitted = pending.finish() => match admitted { Some(admitted) => admitted, None => return },
                };
                let connection = admitted.connection.clone();
                if let Some(Err(error)) = admitted.run(crate::provider::serve_connection(connection.alpn().to_vec(), connection, open, node, manager, Some(setup), Some(router), Some(control), content, stopped)).await {
                    tracing::warn!(%error, "iroh request failed");
                }
            });
        }
        let grants = self.grants.shutdown().await;
        let paid = watcher.shutdown().await;
        quiesce.send_replace(true);
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "iroh connection failed while draining");
            }
        }
        self.endpoint.close().await;
        grants?;
        paid?;
        Ok(())
    }
}
