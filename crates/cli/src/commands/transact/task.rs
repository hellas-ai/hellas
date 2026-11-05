//! Common task target selection; model commands only prepare and decode.
use super::*;
use hellas_client::model::ComputeJob;
use hellas_sdk::execution::{Completion, Executor, PaidExecutor};

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("execution_target").required(true).multiple(true).args(["provider", "offer", "local"])))]
pub(super) struct TaskArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(flatten)]
    pub grant: grant::GrantArgs,
    #[arg(long, conflicts_with = "offer", value_parser = clap::value_parser!(u64).range(1..))]
    #[arg(required_unless_present_any = ["offer", "local"])]
    payment: Option<u64>,
    /// Execute on this machine without an identity or provider (heavy CLI).
    #[arg(long, conflicts_with_all = ["provider", "offer", "payment", "settle", "buy_again", "faucet", "faucet_account", "passkey", "trust_store", "trust_policy", "addresses", "validators", "trust", "genesis", "state_dir"])]
    local: bool,
    /// Local GPU backend.
    #[cfg(feature = "heavy")]
    #[arg(long, requires = "local", default_value = "auto", value_parser = crate::compute::parse_gpu_backend)]
    backend: hellas_executor::GpuDialect,
}

impl TaskArgs {
    pub fn is_local(&self) -> bool {
        self.local
    }
    pub fn job(&self, rendered: ComputeJob, model: &Path) -> anyhow::Result<Job> {
        let content = rendered.content;
        #[cfg(feature = "heavy")]
        let content = if self.local {
            let store = hellas_store::ContentStore::new();
            if model.is_dir() {
                store.adopt(model)?;
            } else {
                store.index(model)?;
            }
            content.with_held(store)
        } else {
            content
        };
        #[cfg(not(feature = "heavy"))]
        let _ = model;
        Ok(Job::compute(
            self.payment.unwrap_or(0),
            rendered.environment,
            rendered.plan,
            rendered.inputs,
            hellas_channel::content::InvocationContent::Ephemeral(content),
        )?)
    }
    pub async fn execute(
        &self,
        job: &Job,
        context: Option<&Context>,
    ) -> super::super::CliResult<Completion> {
        #[cfg(feature = "heavy")]
        if self.local {
            let gpu = hellas_executor::GpuConfig {
                backend: self.backend,
                ..Default::default()
            };
            let mut local = hellas_sdk::execution::LocalExecutor {
                gpu,
                ..Default::default()
            };
            if let Some(timeout) = self.client.timeout {
                local.limits.execution_timeout_ms = timeout.as_millis().try_into()?;
            }
            return Ok(Executor::Local(local)
                .execute(job.input().clone(), Default::default())
                .await?);
        }
        let context = context.context("remote execution requires a client identity")?;
        let directory = self
            .client
            .root(context)
            .join("jobs")
            .join(job.digest().to_string());
        job.save(&directory)?;
        eprintln!("job: {}", directory.display());
        bounded(
            self.client.timeout,
            remote(&self.client, &self.grant, context, job),
            |timeout| {
                format!(
                    "task exceeded {timeout:?}; repeat the command to recover its existing attempt"
                )
            },
        )
        .await
    }
}

pub(super) async fn remote(
    client: &ClientArgs,
    grant: &grant::GrantArgs,
    context: &Context,
    job: &Job,
) -> super::super::CliResult<Completion> {
    let executor = if grant.offer.is_some() {
        let options = grant.options(client, context, job.assurance())?;
        grant.executor(client, context, job, options).await?
    } else {
        let options = client
            .options(context, job.price(), job.assurance())
            .await?;
        let endpoint = bind_paid_endpoint(context.transport.clone()).await?;
        client.executor(context, job, options, endpoint).await?
    };
    execute(executor, job).await
}

impl ClientArgs {
    pub(super) async fn executor(
        &self,
        context: &Context,
        job: &Job,
        options: PaidWorkOptions,
        endpoint: iroh::Endpoint,
    ) -> super::super::CliResult<Executor> {
        let owner = self.owner(context)?;
        let attempt = self.purchase(context, job, &options).await?;
        Ok(Executor::Paid(PaidExecutor {
            options,
            endpoint,
            settlement_key: context.settlement.clone(),
            owner,
            signer: context.producer.clone(),
            attempt,
            settle: self.settle,
        }))
    }
}

pub(super) async fn execute(executor: Executor, job: &Job) -> super::super::CliResult<Completion> {
    let result = executor
        .execute(job.input().clone(), Default::default())
        .await;
    Ok(result?)
}

pub(super) async fn deliver_and_settle(completion: &mut Completion) -> super::super::CliResult<()> {
    completion.deliver_and_settle().await?;
    if let Evidence::Remote(evidence) = &completion.evidence
        && let Some(payout) = evidence.settled_provider_payout
    {
        eprintln!(
            "settled channel {}: provider payout {payout}",
            evidence.channel
        );
        std::io::stderr().lock().flush()?;
    }
    Ok(())
}
