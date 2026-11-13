use super::{Core, Result};
use crate::{
    ProviderOpen,
    gateway_work::provider::IrohBackend,
    paid_provider::{MountedSetup, MountedWork, WorkRunner, WorkRunnerConfig, WorkWatcher},
    work_router::WorkRouter,
};
use hellas_authority::grant_service::{GrantService, WorkAdministration};
use hellas_wire::peers::{PeerDirectory, PeerId};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

pub(super) struct Bound {
    pub port: u16,
    pub profile: Option<hellas_chain::genesis::CustomChainFile>,
    pub endpoint: iroh::Endpoint,
    alpns: Vec<Vec<u8>>,
    open: Arc<ProviderOpen>,
    grants: GrantService,
    pub administration: WorkAdministration,
    work: MountedWork,
    setup: MountedSetup,
    runner: Mutex<Option<WorkRunner>>,
    chain: crate::work_config::WorkConfig,
}
impl Bound {
    pub async fn prepare(
        core: &Arc<Core>,
        id: &str,
        port: u16,
        profile: &Option<hellas_chain::genesis::CustomChainFile>,
    ) -> Result<Self> {
        let options = &core.runtime.options;
        let chain = crate::work_config::WorkConfig::from_chain_dir(core.runtime.chain(profile)?)?;
        let enrollment = options
            .node
            .provider()
            .await?
            .ok_or("bind a provider enrollment before adding an iroh listener")?;
        let open = Arc::new(ProviderOpen::new(
            options.signer.clone(),
            enrollment,
            options.prover.clone(),
        )?);
        if hellas_authority::model::grant::records::grant_transport(open.enrollment())?
            != *options.transport.public().as_bytes()
        {
            return Err("iroh transport differs from the provider enrollment".into());
        }
        let alpns = crate::provider::served_alpns(options.remote_control.enabled());
        let endpoint = match core.runtime.endpoint.lock().await.take() {
            Some(endpoint) => {
                endpoint.set_alpns(alpns.clone());
                endpoint
            }
            None => {
                crate::provider::bind_port(
                    iroh::Endpoint::builder(iroh::endpoint::presets::N0)
                        .secret_key(options.transport.clone())
                        .hooks(options.remote_control.clone())
                        .alpns(alpns.clone()),
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
                std::num::NonZeroU64::new(u64::MAX).unwrap(),
            );
            let work = MountedWork::with_backend(backend);
            let setup = MountedSetup::with_content_store(options.content.clone());
            let runner = WorkRunner::discover(
                WorkRunnerConfig {
                    chain: chain.chain.clone(),
                    settlement_key: options.settlement.clone(),
                },
                work.clone(),
                setup.clone(),
            )
            .await?;
            Ok(Self {
                port,
                alpns,
                profile: profile.clone(),
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
        let discovery = core_options
            .runtime
            .options
            .discovery
            .then(|| {
                crate::provider::discovery::start_server_advertising(&self.endpoint, &self.alpns)
            })
            .transpose()?;
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
        node.service_alpns = self
            .alpns
            .iter()
            .map(|alpn| String::from_utf8_lossy(alpn).into_owned())
            .collect();
        let services = crate::provider::Services {
            open_identity: self.open.clone(),
            node,
            setup: self.setup.clone(),
            work: WorkRouter::both(self.work.clone(), self.grants.clone()),
            control,
            content,
        };
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
            let services = services.clone();
            let mut stopped = quiesced.clone();
            tasks.spawn(async move {
                let admitted = tokio::select! {
                    _ = stopped.wait_for(|stop| *stop) => return,
                    admitted = pending.finish() => match admitted { Some(admitted) => admitted, None => return },
                };
                let connection = admitted.connection.clone();
                if let Some(Err(error)) = admitted.run(services.serve(connection, stopped)).await {
                    tracing::warn!(%error, "iroh request failed");
                }
            });
        }
        if let Some(discovery) = discovery {
            discovery.shutdown().await;
        }
        self.work.stop_pending();
        quiesce.send_replace(true);
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "iroh connection failed while draining");
            }
        }
        let grants = self.grants.shutdown().await;
        let paid = watcher.shutdown().await;
        self.endpoint.close().await;
        grants?;
        paid?;
        Ok(())
    }
}
