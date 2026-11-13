//! One job on one target: open it, run the one lifecycle, close. A command
//! runs one; a gateway runs one per request.
use super::{
    AttemptError, Completed, Controls, Delivery, ExecutionAttempt, ExecutionError,
    ExecutionObservers, ExecutionSession, ExecutionTarget, ExecutionTerms, PaidOpen, Result, Stop,
    Terminal, before_proposal, open_paid_session, within,
};
use crate::job::Job;
use crate::{BackendState, gateway_work::WorkRequest};
use hellas_auth::ProducerSigningKey;

/// One invocation's lifecycle options, independent of the backend kind.
pub struct Executor {
    pub backend: crate::Backend,
    pub funding: crate::paid_client::SessionFundingOptions,
    pub attempt: Option<ExecutionAttempt>,
    pub settle: bool,
}

impl Executor {
    pub fn new(backend: crate::Backend) -> Self {
        Self {
            backend,
            funding: Default::default(),
            attempt: None,
            settle: false,
        }
    }

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
        let local_policy;
        // Box remote lifecycles to bound the caller's async state.
        let (execution, content, policy) = match &self.backend.state {
            BackendState::Paid(paid) => {
                return Box::pin(async {
                    let crate::PaidBackend {
                        options,
                        endpoint,
                        settlement_key,
                        owner,
                        ..
                    } = paid.as_ref();
                    let open = |open| {
                        open_paid_session(
                            options.clone(),
                            endpoint.clone(),
                            settlement_key.clone(),
                            owner.clone(),
                            self.funding,
                            open,
                            None,
                        )
                    };
                    let request = WorkRequest::Job(job.input().clone());
                    let terms = ExecutionTerms::Paid { price: job.price() };
                    let mut completed = match self.attempt {
                        None => {
                            let mut session =
                                before_proposal(deadline, &stop, None, open(PaidOpen::Job(job)))
                                    .await??;
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
                    if self.settle
                        && let Some(paid) = &mut completed.paid
                    {
                        let receipt = within(
                            deadline,
                            crate::paid_client::settle_channel(
                                options,
                                paid.bond_edge,
                                owner.principal(),
                                settlement_key,
                            ),
                        )
                        .await??;
                        if receipt.channel != paid.channel_id {
                            return Err(ExecutionError::Identity);
                        }
                        paid.settled = Some(receipt.provider_payout);
                    }
                    Ok(completed)
                })
                .await;
            }
            BackendState::Grant(grant) => {
                return Box::pin(async {
                    let crate::GrantBackend {
                        options,
                        transport,
                        policy,
                        ..
                    } = grant.as_ref();
                    let request = WorkRequest::Job(job.input().clone());
                    let terms = ExecutionTerms::Grant {
                        resource: policy.resource,
                    };
                    let Some(mut attempt) = self.attempt else {
                        let mut session = before_proposal(
                            deadline,
                            &stop,
                            None,
                            crate::grant_client::GrantSession::open(
                                options.clone(),
                                transport.clone(),
                            ),
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
                        attempt.open_grant_session(options.clone(), transport.clone()),
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
                })
                .await;
            }
            BackendState::Local { execution, timeout } => {
                local_policy = super::local::policy(job.input(), *timeout)?;
                (
                    &execution.backend,
                    super::local::prepare(&execution.content, job.input()).await?,
                    &local_policy,
                )
            }
            BackendState::Fetch { execution, policy } => (execution, job.input().content(), policy),
        };
        let completed = super::local::run(
            execution,
            content,
            job.input(),
            policy,
            signer,
            deadline,
            &stop,
            controls.observers,
        )
        .await?;
        controls
            .deliver
            .map_or(Ok(()), |deliver| deliver(&completed))
            .map_err(ExecutionError::Delivery)?;
        Ok(completed)
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
