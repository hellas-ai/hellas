//! This machine's executor on the shared execution core: the caller's own
//! policy, no ledger, no session, no transport.
use super::{Completed, ExecutionError, ExecutionObservers, Result, Stop, before_proposal};
use crate::job::{JobError, JobInput};
use hellas_auth::ProducerSigningKey;
use hellas_channel::work::{WorkBackend, admission::WorkAdmission};
use hellas_rpc::protocol::invocation::{InvocationPolicy, Limits, MAX_INVOCATION_BYTES};
use hellas_store::content::{DiskStore, LocalStore, Scope};

#[derive(Clone)]
pub struct LocalExecution {
    /// Spawned with the caller's producer key: it signs its own transcript.
    pub backend: hellas_executor::ExecutorHandle,
    /// Holds the model weights; the job's program is copied in before it runs.
    pub content: DiskStore,
}

/// The caller's own terms for running `input` here: exactly its program,
/// within the protocol's byte bounds and `timeout`.
pub fn policy(
    input: &JobInput,
    timeout: std::time::Duration,
) -> std::result::Result<InvocationPolicy, JobError> {
    let JobInput::Compute {
        evaluator,
        environment,
        plan,
        ..
    } = input
    else {
        return Err(JobError::Invalid(
            "local execution runs Compute jobs".into(),
        ));
    };
    let manifest = environment.manifest(evaluator)?;
    Ok(InvocationPolicy {
        admissions: vec![hellas_rpc::protocol::invocation::Admission::Compute {
            evaluator: manifest.application().evaluator().into(),
            programs: hellas_rpc::protocol::invocation::ComputePrograms::Only {
                manifests: vec![manifest.content_id()],
            },
        }],
        limits: Limits {
            max_upload_bytes: MAX_INVOCATION_BYTES as u64,
            max_output_bytes: MAX_INVOCATION_BYTES as u64,
            max_steps: plan.step.as_ref().map_or(1, |step| step.stop.max_steps),
            execution_timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        },
    })
}

impl LocalExecution {
    /// Run `input` under `policy` and verify its signed transcript. `stop`
    /// cancels at any point: nothing was proposed to anyone.
    pub async fn run(
        &self,
        input: &JobInput,
        policy: &InvocationPolicy,
        signer: &ProducerSigningKey,
        deadline: Option<tokio::time::Instant>,
        stop: &Stop,
        observers: ExecutionObservers,
    ) -> Result<Completed> {
        let JobInput::Compute {
            environment,
            content: job,
            ..
        } = input
        else {
            return Err(JobError::Invalid("local execution runs Compute jobs".into()).into());
        };
        let content = |error| ExecutionError::Job(JobError::Content(error));
        let root = environment.canonical_bytes().map_err(JobError::from)?;
        hellas_channel::content::upload_object(&self.content, &root)
            .await
            .map_err(content)?;
        for source in &environment.sources {
            let bytes = hellas_channel::content::read(
                &job.0,
                &job.1,
                *source,
                hellas_rpc::protocol::invocation::compute::MAX_SOURCE_BYTES,
            )
            .await
            .map_err(content)?;
            hellas_channel::content::upload_object(&self.content, &bytes)
                .await
                .map_err(content)?;
        }
        run(
            &self.backend,
            (LocalStore::Disk(self.content.clone()), Scope::Owner),
            input,
            policy,
            signer,
            deadline,
            stop,
            observers,
        )
        .await
    }
}

/// Local Compute and Fetch have the same admission, cancellation and signed result path.
#[expect(clippy::too_many_arguments, reason = "shared local execution boundary")]
pub(crate) async fn run(
    backend: &hellas_executor::ExecutorHandle,
    content: (LocalStore, Scope),
    input: &JobInput,
    policy: &InvocationPolicy,
    signer: &ProducerSigningKey,
    deadline: Option<tokio::time::Instant>,
    stop: &Stop,
    observers: ExecutionObservers,
) -> Result<Completed> {
    let key = signer.public_key();
    // The caller's own disk store retains what it runs.
    let prepared = input.prepare(
        &input.manifest()?,
        signer,
        rand::random(),
        key,
        policy,
        true,
    )?;
    let work_id = prepared
        .request
        .commitment()
        .map_err(JobError::from)?
        .digest();
    let permit = backend
        .try_admit(
            &hellas_channel::work::admission::BackendKey::of(&prepared)
                .map_err(|error| ExecutionError::LocalAdmission(error.to_string()))?,
            key,
        )
        .map_err(|error| ExecutionError::LocalAdmission(error.to_string()))?;
    if let Some(accepted) = &observers.accepted {
        accepted(hellas_rpc::provenance::ExecutionProvenance {
            commitment_id: *work_id.as_bytes(),
            provider: key,
        });
    }
    let events = before_proposal(
        deadline,
        stop,
        None,
        hellas_channel::work::run_admitted(
            backend,
            prepared.clone(),
            policy,
            content,
            WorkAdmission::reserved(permit),
            observers
                .progress
                .unwrap_or_else(|| std::sync::Arc::new(|_| Ok(()))),
        ),
    )
    .await?
    .map_err(|fault| ExecutionError::Local(fault.to_string()))?;
    let verified = prepared
        .verify_output(policy, &key, &key, &events)
        .map_err(JobError::from)?;
    Ok(Completed {
        work_id,
        output: verified.output,
        transcript: verified.transcript_bytes,
        provider_key: key,
        paid: None,
        live: None,
    })
}
