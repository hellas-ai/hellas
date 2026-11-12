//! Provider-side exact lookup. An admitted permit owns its selected snapshot entry.
use super::{Backend, ExecutorGateway, Inner};
use crate::daemon::Core;
use hellas_auth::PublicKey;
use hellas_channel::work::{
    Admitted, BackendFault, PaidProgress, WorkBackend,
    admission::{AdmissionError, BackendKey, WorkAdmission, WorkPermit},
};
use hellas_gateway::jobs::{Job, Origin, Outcome, Request};
use hellas_rpc::OutputEventEnvelope;
use std::sync::{Arc, Weak};

#[derive(Clone)]
pub(crate) struct IrohBackend {
    pub core: Weak<Core>,
    pub listener: String,
    pub assurance: hellas_rpc::Assurance,
}
struct AdmittedBackend {
    inner: Arc<Inner>,
    job: Arc<Job>,
    _slot: tokio::sync::OwnedSemaphorePermit,
}
impl Inner {
    fn executor(&self) -> Result<&hellas_executor::ExecutorHandle, BackendFault> {
        match &self.target {
            Backend::Fetch { execution, .. } => Ok(execution),
            #[cfg(feature = "compute")]
            Backend::Local { execution, .. } => Ok(&execution.backend),
            _ => Err(BackendFault::caused_by(std::io::Error::other(
                "iroh cannot forward work",
            ))),
        }
    }
}
impl ExecutorGateway {
    fn lookup(&self, allowed: &[String], key: &BackendKey) -> Result<Arc<Inner>, BackendFault> {
        self.backends.iter().find_map(|(id, inner)| {
            if !allowed.contains(id) { return None; }
            let matches = match key {
                BackendKey::Compute(evaluator) => inner.evaluator.as_ref() == Some(evaluator),
                BackendKey::Fetch { service, method } => inner.target.fetch_routes().iter().any(|(_, route)| {
                    matches!(route, hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy::SealedRoute { service: offered_service, method: offered_method } if service == offered_service && method == offered_method)
                }),
            };
            matches.then(|| inner.clone())
        }).ok_or_else(|| AdmissionError::Unsupported(key.domain()).into())
    }
}
impl IrohBackend {
    fn admit(
        &self,
        key: &BackendKey,
        caller: PublicKey,
    ) -> Result<(Arc<Job>, Arc<Inner>), BackendFault> {
        let core = self.core.upgrade().ok_or(AdmissionError::Closed)?;
        let job = core
            .jobs
            .admit(&Request {
                origin: Origin::Iroh {
                    peer: hex::encode(caller.bytes()),
                },
                method: "work.execute".into(),
                path: self.listener.clone(),
            })
            .map_err(BackendFault::caused_by)?;
        let snapshot = core.snapshot.load_full();
        let Some(crate::daemon_config::Listener::Iroh { backends, .. }) =
            snapshot.document.listeners.get(&self.listener)
        else {
            return Err(AdmissionError::Closed.into());
        };
        let inner = snapshot.work.lookup(backends, key)?;
        Ok((job, inner))
    }
}
impl WorkBackend for IrohBackend {
    fn try_admit(&self, key: &BackendKey, caller: PublicKey) -> Result<WorkPermit, BackendFault> {
        let (job, inner) = self.admit(key, caller)?;
        let slot = inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionError::Capacity)?;
        let permit = inner
            .executor()?
            .try_admit(key, caller)?
            .cancellable(job.cancellation());
        Ok(permit.retaining(Arc::new(AdmittedBackend {
            inner,
            job,
            _slot: slot,
        })))
    }

    async fn execute_stream(
        &self,
        input: Admitted,
        progress: PaidProgress,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        if input.invocation().request.assurance != self.assurance {
            return Err(BackendFault::caused_by(std::io::Error::other(
                "invocation assurance differs from this listener's prover",
            )));
        }
        let input = if input.admission().backend::<AdmittedBackend>().is_some() {
            input
        } else {
            let key = BackendKey::of(input.invocation())?;
            let caller = input.admission().caller().ok_or(AdmissionError::Closed)?;
            let (job, inner) = self.admit(&key, caller)?;
            // A payment already accepted is owed execution; it waits for its bounded worker.
            let slot = inner
                .slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| AdmissionError::Closed)?;
            let permit = inner
                .executor()?
                .reserve(&key)
                .await?
                .cancellable(job.cancellation());
            let permit = permit.retaining(Arc::new(AdmittedBackend {
                inner,
                job,
                _slot: slot,
            }));
            let domain = input.capacity_domain();
            let (prepared, limits, content, _) = input.into_parts_and_admission();
            Admitted::new(
                prepared,
                limits,
                domain,
                content,
                WorkAdmission::reserved(permit),
            )
        };
        let selected = input
            .admission()
            .backend::<AdmittedBackend>()
            .ok_or(AdmissionError::Closed)?;
        selected.job.running(&selected.inner.id);
        selected.job.accepted();
        let result = selected
            .inner
            .executor()?
            .execute_stream(input, progress)
            .await;
        if selected.job.is_cancelled() {
            selected.job.stopped();
        } else {
            selected.job.finish(
                if result.as_ref().is_ok_and(|events| {
                    events.last().is_some_and(|event| {
                        event.event().body().kind()
                            == hellas_rpc::protocol::invocation::output::TERMINAL
                    })
                }) {
                    Outcome::Completed
                } else {
                    Outcome::Failed
                },
            );
        }
        result
    }
}
