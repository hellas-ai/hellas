//! A validated candidate owns sockets and models; storage opens only at activation.
use super::*;
use hellas_gateway::{
    BackendInfo, ComputeEvent, WorkFetchRequest, WorkGatewayError, WorkOutputStream,
    WorkShutdownError,
};
use std::sync::OnceLock;

pub(super) struct Prepared {
    pub revision: Revision,
    pub document: Document,
    pub models: hellas_gateway::router::Models,
    pub index: BTreeMap<String, runtime::Files>,
    pub entries: BTreeMap<String, runtime::PreparedBackend>,
    pub reuse: BTreeSet<String>,
    pub work: Arc<PreparedWork>,
    pub routers: BTreeMap<String, Router>,
    pub listeners: BTreeMap<String, Arc<BoundListener>>,
}

impl Prepared {
    pub fn configuration(
        &self,
        core: &Core,
    ) -> Result<hellas_authority::model::grant::configuration::NodeConfiguration> {
        let old = core.snapshot.load_full();
        for (id, entry) in &self.entries {
            if let runtime::PreparedBackend::Ready(entry) = entry
                && let crate::BackendState::Unavailable(error) = &entry.backend.state
                && !(old.document.backends.get(id) == self.document.backends.get(id)
                    && old
                        .work
                        .backend(id)
                        .is_some_and(|backend| backend.error().is_some()))
            {
                return Err(format!("backend {id}: {error}").into());
            }
        }
        let configuration = self.document.configuration(&self.work.info, &self.models)?;
        let allowed: BTreeSet<_> = self
            .document
            .listeners
            .values()
            .find_map(|listener| match listener {
                Listener::Iroh { backends, .. } => Some(backends),
                _ => None,
            })
            .map_or_else(
                || self.document.backends.keys().collect(),
                |backends| backends.iter().collect(),
            );
        let mut executable: Vec<_> = self
            .entries
            .iter()
            .filter(|(id, _)| allowed.contains(id))
            .filter_map(|(_, entry)| match entry {
                runtime::PreparedBackend::Ready(entry) => {
                    Some((&entry.backend, entry.evaluator.as_deref()))
                }
                runtime::PreparedBackend::Paid { .. } => None,
            })
            .collect();
        for info in &self.work.info {
            if self.reuse.contains(&info.id) && allowed.contains(&info.id) {
                executable.push((
                    old.work.backend(&info.id).expect("reused backend"),
                    info.evaluator.as_deref(),
                ));
            }
        }
        crate::gateway_work::provider::validate_resources(&executable, configuration.resources())
            .map_err(Error::from)?;
        Ok(configuration)
    }

    pub async fn activate(self, core: &Core) -> Arc<Snapshot> {
        #[cfg(feature = "compute")]
        let mut prepared = self;
        #[cfg(not(feature = "compute"))]
        let prepared = self;
        #[cfg(feature = "compute")]
        for (id, files) in prepared.index {
            if let Err(error) = core.runtime.index(files).await {
                let error = configuration_error(error, &prepared.document.redacted().1).to_string();
                prepared.entries.insert(
                    id.clone(),
                    runtime::PreparedBackend::unavailable(&prepared.document.backends[&id], error),
                );
                prepared.reuse.remove(&id);
            }
        }
        #[cfg(not(feature = "compute"))]
        let _ = prepared.index;
        let mut entries = BTreeMap::new();
        for (id, entry) in prepared.entries {
            let entry = match entry.activate(&core.runtime).await {
                Ok(entry) => entry,
                Err(error) => {
                    let error =
                        configuration_error(error, &prepared.document.redacted().1).to_string();
                    let runtime::PreparedBackend::Ready(entry) =
                        runtime::PreparedBackend::unavailable(
                            &prepared.document.backends[&id],
                            error,
                        )
                    else {
                        unreachable!()
                    };
                    *entry
                }
            };
            entries.insert(id, entry);
        }
        for listener in prepared.listeners.values() {
            if !listener.started.load(std::sync::atomic::Ordering::Acquire)
                && let Bound::Iroh(bound) = &listener.bound
                && let Err(error) = bound.activate(core).await
            {
                let error = configuration_error(error, &prepared.document.redacted().1).to_string();
                let _ = listener.failure.set(error);
                bound.endpoint.close().await;
            }
        }
        let old = core.snapshot.load_full();
        let work = ExecutorGateway::prepare_identified(
            entries,
            core.runtime.options.signer.clone(),
            core.jobs.clone(),
            Some(&old.work),
            &prepared.reuse,
            &prepared.work.info,
        );
        assert!(
            prepared.work.active.set(work.clone()).is_ok(),
            "candidate activates once"
        );
        Arc::new(Snapshot {
            revision: prepared.revision,
            document: prepared.document,
            work,
            routers: prepared.routers,
            listeners: prepared.listeners,
        })
    }
}

/// Model loading needs resolved backend metadata. Requests become reachable only
/// after activation installs the executor and the core publishes its snapshot.
pub(super) struct PreparedWork {
    pub info: Vec<BackendInfo>,
    active: OnceLock<Arc<ExecutorGateway>>,
}
impl PreparedWork {
    pub fn new(info: Vec<BackendInfo>) -> Arc<Self> {
        Arc::new(Self {
            info,
            active: OnceLock::new(),
        })
    }
    fn active(&self) -> &ExecutorGateway {
        self.active.get().expect("published candidate is active")
    }
}
impl WorkExecutionBackend for PreparedWork {
    fn backends(&self) -> Vec<BackendInfo> {
        self.active
            .get()
            .map_or_else(|| self.info.clone(), |work| work.backends())
    }
    fn max_steps<'a>(
        &'a self,
        backend: &'a str,
    ) -> futures::future::BoxFuture<'a, std::result::Result<Option<u64>, WorkGatewayError>> {
        self.active().max_steps(backend)
    }
    fn fetch(
        &self,
        backend: &str,
        job: Arc<hellas_gateway::jobs::Job>,
        request: WorkFetchRequest,
    ) -> std::result::Result<WorkOutputStream<hellas_rpc::output::OutputEvent>, WorkGatewayError>
    {
        self.active().fetch(backend, job, request)
    }
    fn run(
        &self,
        backend: &str,
        job: Arc<hellas_gateway::jobs::Job>,
        input: hellas_client::model::ComputeJob,
    ) -> std::result::Result<WorkOutputStream<ComputeEvent>, WorkGatewayError> {
        self.active().run(backend, job, input)
    }
    fn drain(&self) -> futures::future::BoxFuture<'_, std::result::Result<(), WorkShutdownError>> {
        self.active().drain()
    }
}
