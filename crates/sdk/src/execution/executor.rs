//! Task execution over the existing grant and purchase journals.
use super::*;
use hellas_rpc::protocol::invocation::output::InvocationOutput;
use std::sync::Arc;

pub enum Executor {
    #[cfg(feature = "local")]
    Local(LocalExecutor),
    Grant(GrantExecutor),
    Paid(PaidExecutor),
}

pub struct GrantExecutor {
    pub options: crate::grant_client::GrantSessionOptions,
    /// Remote endpoints are owned and closed by this executor.
    pub transport: crate::grant_client::GrantTransport,
    pub resource: ResourceId,
    pub attempt: ExecutionAttempt,
}

pub struct PaidExecutor {
    pub options: PaidWorkOptions,
    /// Owned by this executor and closed when execution finishes.
    pub endpoint: iroh::Endpoint,
    pub settlement_key: hellas_kernel::Secp256k1Signer,
    pub owner: Arc<crate::client_owner::ClientOwner>,
    pub signer: ProducerSigningKey,
    pub attempt: ExecutionAttempt,
    pub settle: bool,
}

/// Local output is unsigned. Remote evidence retains the verified event transcript.
pub enum Evidence {
    Local,
    Remote(Box<RemoteEvidence>),
}

pub struct RemoteEvidence {
    pub terms: ExecutionTerms,
    pub provider: hellas_client::ProviderAddress,
    pub provider_key: hellas_auth::PublicKey,
    pub channel: Digest,
    pub work: Digest,
    pub transcript: Vec<u8>,
    pub settled_provider_payout: Option<u64>,
}

pub struct Completion {
    pub output: InvocationOutput,
    pub evidence: Evidence,
    attempt: Option<ExecutionAttempt>,
    settlement: Option<Settlement>,
}

struct Settlement {
    options: PaidWorkOptions,
    owner: hellas_auth::authority::PrincipalId,
    key: hellas_kernel::Secp256k1Signer,
}

impl Completion {
    /// Call after writing and flushing output; acknowledge delivery before settlement.
    pub async fn deliver_and_settle(&mut self) -> Result<()> {
        if let Some(attempt) = &mut self.attempt {
            attempt.reported()?;
            if let Some(settlement) = &self.settlement {
                let AttemptRecord::Paid(purchase) = &attempt.record else {
                    return Err(ExecutionError::Identity);
                };
                let (channel, bond) = purchase.bound_channel().ok_or(ExecutionError::Identity)?;
                let receipt = crate::paid_client::settle_channel(
                    &settlement.options,
                    bond,
                    settlement.owner,
                    &settlement.key,
                )
                .await?;
                if receipt.channel != channel {
                    return Err(ExecutionError::Identity);
                }
                attempt.settled(receipt.provider_payout)?;
                if let Evidence::Remote(evidence) = &mut self.evidence {
                    evidence.settled_provider_payout = Some(receipt.provider_payout);
                }
            }
        }
        self.settlement = None;
        Ok(())
    }
    fn grant(
        attempt: ExecutionAttempt,
        retained: RetainedExecutionResult,
        provider: hellas_client::ProviderAddress,
    ) -> Result<Self> {
        let AttemptRecord::Grant(grant) = &attempt.record else {
            return Err(ExecutionError::Identity);
        };
        let channel = grant.record.channel.ok_or(ExecutionError::Identity)?.0;
        let events = hellas_channel::model::work::decode_transcript(
            &retained.transcript,
            retained.transcript.len(),
        )
        .map_err(|_| ExecutionError::Identity)?;
        let provider_key = *events
            .first()
            .ok_or(ExecutionError::Identity)?
            .event()
            .public_key();
        let work = attempt.inspect()?.work.ok_or(ExecutionError::Identity)?;
        Ok(Self {
            output: retained.output,
            evidence: Evidence::Remote(Box::new(RemoteEvidence {
                terms: attempt.terms,
                provider,
                provider_key,
                channel,
                work,
                transcript: retained.transcript,
                settled_provider_payout: None,
            })),
            attempt: Some(attempt),
            settlement: None,
        })
    }

    fn paid(
        attempt: ExecutionAttempt,
        retained: PaidCompletion,
        settled: Option<u64>,
        provider: hellas_client::ProviderAddress,
        settlement: Option<Settlement>,
    ) -> Self {
        Self {
            output: retained.output,
            evidence: Evidence::Remote(Box::new(RemoteEvidence {
                terms: ExecutionTerms::Paid {
                    price: retained.job_price,
                },
                provider,
                provider_key: retained.provider_key,
                channel: retained.channel_id,
                work: retained.work_id,
                transcript: retained.transcript,
                settled_provider_payout: settled,
            })),
            attempt: Some(attempt),
            settlement,
        }
    }
}

impl ExecutionAttempt {
    /// Retained grant delivery takes precedence over reported terminal state.
    fn replay(
        &self,
        input: &JobInput,
        terms: ExecutionTerms,
    ) -> Result<Option<RetainedExecutionResult>> {
        self.matches(input, terms)?;
        if let Some(result) = self.retained_result()? {
            return Ok(Some(result));
        }
        let facts = self.inspect()?;
        if self.read_receipt()?.is_some() || facts.reported {
            return Err(ExecutionError::ResultUnavailable);
        }
        Ok(None)
    }
    fn settled(&mut self, payout: u64) -> Result<()> {
        let mut receipt = self
            .read_receipt()?
            .ok_or(ExecutionError::RecoveryRequired)?;
        receipt.settled_provider_payout = Some(payout);
        hellas_private::write_atomically(
            &self.sidecar(".receipt")?,
            ".writing",
            &serde_json::to_vec(&receipt)?,
        )?;
        Ok(())
    }
}

impl Executor {
    pub fn execute(
        self,
        input: JobInput,
        observers: ExecutionObservers,
    ) -> impl std::future::Future<Output = Result<Completion>> {
        let endpoint = match &self {
            Self::Paid(paid) => Some(paid.endpoint.clone()),
            Self::Grant(grant) => match &grant.transport {
                crate::grant_client::GrantTransport::Remote(endpoint) => Some(endpoint.clone()),
                crate::grant_client::GrantTransport::Local(_) => None,
            },
            #[cfg(feature = "local")]
            Self::Local(_) => None,
        };
        let execution = self.execute_inner(input, observers);
        async move {
            let result = execution.await;
            if let Some(endpoint) = endpoint {
                endpoint.close().await;
            }
            result
        }
    }

    fn execute_inner(
        self,
        input: JobInput,
        observers: ExecutionObservers,
    ) -> impl std::future::Future<Output = Result<Completion>> {
        // Keep the execution state off the caller's stack.
        Box::pin(async move {
            input.manifest()?;
            match self {
                #[cfg(feature = "local")]
                Self::Local(local) => local.execute(input).await,
                Self::Grant(mut grant) => {
                    let offer = grant.options.target.offer();
                    let provider = hellas_client::ProviderAddress::of(&offer.provider)
                        .map_err(crate::grant_client::GrantClientError::from)?;
                    grant.attempt.bind_target(ExecutionTarget {
                        network: offer.network,
                        provider,
                    })?;
                    let terms = ExecutionTerms::Grant {
                        resource: grant.resource,
                    };
                    if let Some(retained) = grant.attempt.replay(&input, terms)? {
                        return Completion::grant(grant.attempt, retained, provider);
                    }
                    let signer = grant.options.signer.clone();
                    let mut session = grant
                        .attempt
                        .open_grant_session(grant.options, grant.transport)
                        .await?;
                    let result = ExecutionSession::Grant(&mut session)
                        .execute(input, terms, &signer, observers, Some(&mut grant.attempt))
                        .await;
                    let result = match result {
                        Err(ExecutionError::RecoveryRequired) => {
                            match ExecutionSession::Grant(&mut session)
                                .recover(&mut grant.attempt)
                                .await
                            {
                                Ok(_) => Err(ExecutionError::RecoveryRequired),
                                Err(error) => Err(error),
                            }
                        }
                        result => result,
                    };
                    let closed = session.shutdown().await;
                    result?;
                    closed?;
                    let retained = grant
                        .attempt
                        .retained_result()?
                        .ok_or(ExecutionError::ResultUnavailable)?;
                    Completion::grant(grant.attempt, retained, provider)
                }
                Self::Paid(mut paid) => {
                    let provider = paid.options.provider;
                    let terms = ExecutionTerms::Paid {
                        price: paid.options.expected_price,
                    };
                    paid.attempt.bind_target(ExecutionTarget {
                        network: paid.options.config.chain.network,
                        provider: paid.options.provider,
                    })?;
                    paid.attempt.matches(&input, terms)?;
                    let retained = paid.attempt.retained_paid_result()?;
                    let settled = paid
                        .attempt
                        .read_receipt()?
                        .and_then(|receipt| receipt.settled_provider_payout);
                    let settlement = (paid.settle && settled.is_none()).then(|| Settlement {
                        options: paid.options.clone(),
                        owner: paid.owner.principal(),
                        key: paid.settlement_key.clone(),
                    });
                    if let Some(retained) = retained {
                        return Ok(Completion::paid(
                            paid.attempt,
                            retained,
                            settled,
                            provider,
                            settlement,
                        ));
                    }
                    let mut session = paid
                        .attempt
                        .open_paid_session(
                            &input,
                            paid.options,
                            paid.endpoint,
                            paid.settlement_key,
                            paid.owner,
                            Default::default(),
                        )
                        .await?;
                    let result: Result<_> = async {
                        let result = ExecutionSession::Paid(&mut session)
                            .execute(
                                input,
                                terms,
                                &paid.signer,
                                observers,
                                Some(&mut paid.attempt),
                            )
                            .await;
                        if matches!(result, Err(ExecutionError::RecoveryRequired)) {
                            ExecutionSession::Paid(&mut session)
                                .recover(&mut paid.attempt)
                                .await?;
                        }
                        result?;
                        let retained = paid
                            .attempt
                            .retained_paid_result()?
                            .ok_or(ExecutionError::ResultUnavailable)?;
                        Ok(retained)
                    }
                    .await;
                    session.shutdown().await;
                    let retained = result?;
                    Ok(Completion::paid(
                        paid.attempt,
                        retained,
                        settled,
                        provider,
                        settlement,
                    ))
                }
            }
        })
    }
}

#[cfg(feature = "local")]
pub struct LocalExecutor {
    pub limits: hellas_rpc::protocol::invocation::Limits,
    pub gpu: hellas_executor::GpuConfig,
}

#[cfg(feature = "local")]
impl Default for LocalExecutor {
    fn default() -> Self {
        Self {
            limits: hellas_rpc::protocol::invocation::Limits {
                max_upload_bytes: 64 << 20,
                max_output_bytes: 64 << 20,
                max_steps: 1_000_000,
                execution_timeout_ms: 300_000,
            },
            gpu: Default::default(),
        }
    }
}

#[cfg(feature = "local")]
impl LocalExecutor {
    async fn execute(self, input: JobInput) -> Result<Completion> {
        let JobInput::Compute {
            environment,
            plan,
            inputs,
            content,
        } = input
        else {
            return Err(ExecutionError::Local(
                "this executor requires Compute input".into(),
            ));
        };
        let cancel = hellas_executor::catena::Cancellation::default();
        let signal = cancel.clone();
        let _cancel_on_drop = hellas_channel::work::admission::CancelOnFailure(vec![
            hellas_channel::work::admission::Cancellation::with_cleanup(move || signal.cancel()),
        ]);
        let output = tokio::task::spawn_blocking(move || {
            hellas_executor::catena::local::execute(
                &environment,
                &plan,
                &inputs,
                &content,
                &self.limits,
                self.gpu,
                cancel,
            )
            .map_err(|error| ExecutionError::Local(error.to_string()))
        })
        .await
        .map_err(|error| ExecutionError::Local(error.to_string()))??;
        Ok(Completion {
            output,
            evidence: Evidence::Local,
            attempt: None,
            settlement: None,
        })
    }
}
