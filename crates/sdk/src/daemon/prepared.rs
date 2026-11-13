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
    pub configuration: hellas_authority::model::grant::configuration::NodeConfiguration,
    pub entries: BTreeMap<String, runtime::PreparedBackend>,
    pub reuse: BTreeSet<String>,
    pub work: Arc<PreparedWork>,
    pub counters: Arc<crate::counter_store::PreparedCounters>,
    pub routers: BTreeMap<String, Router>,
    pub listeners: BTreeMap<String, Arc<BoundListener>>,
}

impl Prepared {
    pub async fn activate(self, core: &Core) -> Result<Arc<Snapshot>> {
        self.counters.activate()?;
        let mut entries = BTreeMap::new();
        for (id, entry) in self.entries {
            let entry = entry.activate(&core.runtime).await?;
            entries.insert(id, entry);
        }
        for listener in self.listeners.values() {
            if !listener.started.load(std::sync::atomic::Ordering::Acquire)
                && let Bound::Iroh(bound) = &listener.bound
            {
                bound.activate(core).await?;
            }
        }
        let old = core.snapshot.load_full();
        let work = ExecutorGateway::prepare_identified(
            entries,
            core.runtime.options.signer.clone(),
            core.jobs.clone(),
            Some(&old.work),
            &self.reuse,
            &self.work.info,
        );
        assert!(
            self.work.active.set(work.clone()).is_ok(),
            "candidate activates once"
        );
        Ok(Arc::new(Snapshot {
            revision: self.revision,
            document: self.document,
            work,
            routers: self.routers,
            listeners: self.listeners,
        }))
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
