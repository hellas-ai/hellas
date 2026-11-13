//! Provider-side exact lookup. An admitted permit owns its selected snapshot entry.
use super::{Backend, BackendState, ExecutorGateway};
use crate::daemon::Core;
use hellas_auth::PublicKey;
use hellas_channel::work::{
    Admitted, BackendFault, PaidProgress, WorkBackend,
    admission::{AdmissionError, BackendKey, ReservedExecution, WorkAdmission, WorkPermit},
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
impl Backend {
    fn executor(&self) -> Result<&hellas_executor::ExecutorHandle, BackendFault> {
        match &self.state {
            BackendState::Local { execution, .. } => Ok(&execution.backend),
            BackendState::Fetch { execution, .. } => Ok(execution),
            BackendState::Grant(_) | BackendState::Paid(_) => Err(BackendFault::caused_by(
                std::io::Error::other("iroh cannot forward work"),
            )),
        }
    }
}
pub(crate) fn validate_resources(
    backends: &[(&Backend, Option<&str>)],
    resources: &[hellas_authority::model::grant::records::GrantPolicy],
) -> Result<(), &'static str> {
    use hellas_rpc::protocol::invocation::{Admission, fetch::FetchRoutePolicy};
    for resource in resources {
        for admission in &resource.invocation_policy.admissions {
            let available = backends.iter().any(|(inner, _evaluator_name)| match (admission, &inner.state) {
                    #[cfg(feature = "compute")]
                    (Admission::Compute { evaluator, .. }, BackendState::Local { .. }) => *_evaluator_name == Some(evaluator.as_str()),
                    (Admission::Fetch { admission }, BackendState::Fetch { policy, .. }) =>
                        matches!(admission.route, FetchRoutePolicy::SealedRoute { .. }) && policy.admissions.iter().any(|offered| {
                            matches!(offered, Admission::Fetch { admission: offered } if offered.route == admission.route && offered.contract == admission.contract)
                        }),
                    _ => false,
                });
            if !available {
                return Err("resource has no backend with its evaluator or Fetch contract");
            }
        }
    }
    Ok(())
}
impl ExecutorGateway {
    fn lookup(&self, allowed: &[String], key: &BackendKey) -> Result<Arc<Backend>, BackendFault> {
        self.backends.iter().find_map(|(id, inner)| {
            if !allowed.contains(id) { return None; }
            let matches = match key {
                BackendKey::Compute(evaluator) => inner.evaluator.as_ref() == Some(evaluator),
                BackendKey::Fetch { service, method } => inner.fetch_routes().iter().any(|(_, route)| {
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
        recovered: bool,
    ) -> Result<(Arc<Job>, Arc<Backend>), BackendFault> {
        let core = self.core.upgrade().ok_or(AdmissionError::Closed)?;
        let request = Request {
            origin: Origin::Iroh {
                peer: hex::encode(caller.bytes()),
            },
            method: "work.execute".into(),
            path: self.listener.clone(),
        };
        let job = if recovered {
            core.jobs.recover(&request)
        } else {
            core.jobs.admit(&request)
        }
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
        let (job, inner) = self.admit(key, caller, false)?;
        let slot = inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionError::Capacity)?;
        let permit = inner
            .executor()?
            .try_admit(key, caller)?
            .cancellable(job.cancellation());
        Ok(permit.retaining(reserved(inner, job, slot)))
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
        let input = if input.admission().backend().is_some() {
            input
        } else {
            let key = BackendKey::of(input.invocation())?;
            let caller = input.admission().caller().ok_or(AdmissionError::Closed)?;
            let (job, inner) = self.admit(&key, caller, true)?;
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
            let permit = permit.retaining(reserved(inner, job, slot));
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
        let selected = input.admission().backend().ok_or(AdmissionError::Closed)?;
        (selected.execute)(input, progress).await
    }
}
fn reserved(
    inner: Arc<Backend>,
    job: Arc<Job>,
    slot: tokio::sync::OwnedSemaphorePermit,
) -> Arc<ReservedExecution> {
    let selected = Arc::new((inner, job, slot));
    Arc::new(ReservedExecution {
        execute: Box::new(move |input, progress| {
            let selected = selected.clone();
            Box::pin(async move {
                let (inner, job, _) = &*selected;
                job.running(&inner.id);
                job.accepted();
                let result = inner.executor()?.execute_stream(input, progress).await;
                if job.is_cancelled() {
                    job.stopped();
                } else {
                    job.finish(
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
            })
        }),
    })
}
