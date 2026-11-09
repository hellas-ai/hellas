//! One job on one target: open it, run the one lifecycle, close. A command
//! runs one; a gateway runs one per request.
use super::{
    AttemptError, Completed, Controls, Delivery, ExecutionAttempt, ExecutionError,
    ExecutionObservers, ExecutionSession, ExecutionTarget, ExecutionTerms, PaidOpen, Result, Stop,
    Terminal, before_proposal, open_paid_session, within,
};
use crate::gateway_work::WorkRequest;
use crate::job::Job;
use hellas_auth::ProducerSigningKey;

/// Where one job runs. The caller bound the endpoint and closes it.
pub enum Executor {
    Paid(PaidExecution),
    Grant(GrantExecution),
    /// This machine, under the caller's own policy; nothing is tracked.
    #[cfg(feature = "compute")]
    Local(
        super::local::LocalExecution,
        hellas_rpc::protocol::invocation::InvocationPolicy,
    ),
}

pub struct PaidExecution {
    pub options: crate::paid_client::PaidWorkOptions,
    pub endpoint: iroh::Endpoint,
    pub settlement_key: hellas_kernel::Secp256k1Signer,
    pub owner: std::sync::Arc<crate::client_owner::ClientOwner>,
    pub funding: crate::paid_client::SessionFundingOptions,
    /// A command's durable attempt; a gateway request has none and its
    /// proposed work is finished by the running process.
    pub attempt: Option<ExecutionAttempt>,
    /// Settle the channel after delivery, within the same deadline.
    pub settle: bool,
}

pub struct GrantExecution {
    pub options: crate::grant_client::GrantSessionOptions,
    pub transport: crate::grant_client::GrantTransport,
    pub resource: hellas_auth::authority::ResourceId,
    /// As for [`PaidExecution::attempt`].
    pub attempt: Option<ExecutionAttempt>,
}

impl Executor {
    /// Run `job` once. A retained result is delivered again without opening
    /// anything. One absolute `deadline` covers opening, queueing, execution,
    /// delivery, its report and settlement; `stop` abandons only unproposed
    /// work. An unresolved earlier attempt is reported with its facts.
    /// `observers` see acceptance and signed output prefixes as they arrive.
    pub async fn run(
        self,
        job: &Job,
        signer: &ProducerSigningKey,
        deadline: Option<tokio::time::Instant>,
        stop: Stop,
        observers: ExecutionObservers,
        deliver: Delivery<'_>,
    ) -> Result<Completed> {
        let controls = Controls {
            deadline,
            stop: Some(stop.clone()),
            observers,
            deliver: Some(deliver),
        };
        match self {
            Self::Paid(target) => target.run(job, signer, stop, controls).await,
            Self::Grant(target) => target.run(job, stop, controls).await,
            #[cfg(feature = "compute")]
            Self::Local(target, policy) => {
                let Controls {
                    observers, deliver, ..
                } = controls;
                let completed = target
                    .run(job.input(), &policy, signer, deadline, &stop, observers)
                    .await?;
                deliver.map_or(Ok(()), |deliver| deliver(&completed))
                    .map_err(ExecutionError::Delivery)?;
                Ok(completed)
            }
        }
    }
}

/// Deliver retained bytes again; nothing is opened or proposed.
fn replay(
    attempt: &mut ExecutionAttempt,
    completed: Completed,
    deliver: Option<Delivery<'_>>,
) -> Result<Completed> {
    if let Some(deliver) = deliver {
        deliver(&completed).map_err(ExecutionError::Delivery)?;
    }
    attempt.reported()?;
    Ok(completed)
}

impl PaidExecution {
    async fn run(
        self,
        job: &Job,
        signer: &ProducerSigningKey,
        stop: Stop,
        controls: Controls<'_>,
    ) -> Result<Completed> {
        let Self {
            options,
            endpoint,
            settlement_key,
            owner,
            funding,
            attempt,
            settle,
        } = self;
        let deadline = controls.deadline;
        let open = |open| {
            open_paid_session(
                options.clone(),
                endpoint.clone(),
                settlement_key.clone(),
                owner.clone(),
                funding,
                open,
                None,
            )
        };
        let request = WorkRequest::Job(job.input().clone());
        let terms = ExecutionTerms::Paid { price: job.price() };
        let mut completed = match attempt {
            None => {
                let mut session =
                    before_proposal(deadline, &stop, None, open(PaidOpen::Job(job))).await??;
                let run = ExecutionSession::Paid(&mut session)
                    .run(&request, terms, signer, controls, None)
                    .await;
                session.shutdown().await;
                run?
            }
            Some(mut attempt) => match attempt.retained_paid_result()? {
                Some(completed) => {
                    attempt.bind_target(ExecutionTarget {
                        network: options.config.network(),
                        provider: options.provider,
                    })?;
                    replay(&mut attempt, completed, controls.deliver)?
                }
                None => {
                    if attempt.inspect()?.terminal == Terminal::Rejected {
                        return Err(ExecutionError::Terminal);
                    }
                    let mut session = before_proposal(
                        deadline,
                        &stop,
                        None,
                        open(PaidOpen::Attempt(job, &mut attempt)),
                    )
                    .await??;
                    let run = ExecutionSession::Paid(&mut session)
                        .run(&request, terms, signer, controls, Some(&mut attempt))
                        .await;
                    let run = unresolved(run, deadline, async {
                        ExecutionSession::Paid(&mut session)
                            .recover(&mut attempt)
                            .await
                    })
                    .await;
                    session.shutdown().await;
                    run?
                }
            },
        };
        if settle && let Some(paid) = &mut completed.paid {
            let receipt = within(
                deadline,
                crate::paid_client::settle_channel(
                    &options,
                    paid.bond_edge,
                    owner.principal(),
                    &settlement_key,
                ),
            )
            .await??;
            if receipt.channel != paid.channel_id {
                return Err(ExecutionError::Identity);
            }
            paid.settled = Some(receipt.provider_payout);
        }
        Ok(completed)
    }
}

impl GrantExecution {
    async fn run(self, job: &Job, stop: Stop, controls: Controls<'_>) -> Result<Completed> {
        let Self {
            options,
            transport,
            resource,
            attempt,
        } = self;
        let deadline = controls.deadline;
        let request = WorkRequest::Job(job.input().clone());
        let terms = ExecutionTerms::Grant { resource };
        let Some(mut attempt) = attempt else {
            let mut session = before_proposal(
                deadline,
                &stop,
                None,
                crate::grant_client::GrantSession::open(options, transport),
            )
            .await??;
            let signer = session.execution_signer().clone();
            let run = ExecutionSession::Grant(&mut session)
                .run(&request, terms, &signer, controls, None)
                .await;
            let closed = session.shutdown().await;
            let completed = run?;
            closed?;
            return Ok(completed);
        };
        if let Some(retained) = attempt.retained_result()? {
            let provider_key = hellas_auth::PublicKey::Secp256k1(
                hellas_authority::model::grant::records::grant_producer(
                    &options.target.offer().provider,
                )
                .map_err(crate::grant_client::GrantClientError::from)?
                .to_bytes(),
            );
            let completed = Completed {
                work_id: attempt.inspect()?.work.ok_or(ExecutionError::Identity)?,
                output: retained.output,
                transcript: retained.transcript,
                provider_key,
                paid: None,
                live: None,
            };
            return replay(&mut attempt, completed, controls.deliver);
        }
        let mut session = before_proposal(
            deadline,
            &stop,
            None,
            attempt.open_grant_session(options, transport),
        )
        .await??;
        let signer = session.execution_signer().clone();
        let run = ExecutionSession::Grant(&mut session)
            .run(&request, terms, &signer, controls, Some(&mut attempt))
            .await;
        let run = unresolved(run, deadline, async {
            ExecutionSession::Grant(&mut session)
                .recover(&mut attempt)
                .await
        })
        .await;
        let closed = session.shutdown().await;
        let completed = run?;
        closed?;
        Ok(completed)
    }
}

/// An earlier proposal for this attempt is reconciled, never proposed again;
/// its facts are surfaced instead of a bare refusal.
async fn unresolved(
    run: std::result::Result<Completed, AttemptError>,
    deadline: Option<tokio::time::Instant>,
    recover: impl std::future::Future<Output = Result<super::ExecutionFacts>>,
) -> Result<Completed> {
    match run {
        Err(AttemptError::Committed(error))
            if matches!(*error, ExecutionError::RecoveryRequired) =>
        {
            Err(ExecutionError::Unresolved(Box::new(
                within(deadline, recover).await??,
            )))
        }
        run => Ok(run?),
    }
}
