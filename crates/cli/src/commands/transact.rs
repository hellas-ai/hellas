//! Job folders and helpers share the SDK transaction and its existing journals.
use anyhow::{Context as _, bail, ensure};
use clap::Args;
use futures::TryFutureExt as _;
use hellas_auth::authority::ResourceId;
use hellas_client::model::{ComputeJob, ModelPackage, ModelResponse};
use hellas_rpc::Assurance;
use hellas_sdk::BackendState;
use hellas_sdk::{
    Backend,
    execution::{Completed, ExecutionError, Executor, RequestStopped},
    job::{Job, JobInput},
    paid_client::PaidWorkOptions,
};
use std::{
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

mod client;
mod run;
mod transcribe;
use run::RunArgs;
use transcribe::TranscribeArgs;
mod image;
use image::ImageArgs;
mod text;
use text::TextArgs;
mod speak;
use speak::SpeakArgs;
mod decide;
use decide::DecideArgs;
#[cfg(test)]
mod tests;

#[derive(clap::Subcommand)]
pub enum JobCommand {
    /// Execute a reusable job folder, or settle its provider channels.
    Transact(TransactArgs),
    /// Buy an HTTPS Fetch using the same job and payment path.
    Fetch(FetchArgs),
    /// Buy one call of a Catena program using the same job and payment path.
    Run(RunArgs),
    /// Synthesize a WAV with a client-rendered speech job.
    Speak(SpeakArgs),
    /// Transcribe one WAV with a client-rendered Whisper job.
    Transcribe(TranscribeArgs),
    /// Answer one prompt with a client-rendered Qwen text job.
    Text(TextArgs),
    /// Answer one decision request with a client-rendered d1 job.
    Decide(DecideArgs),
    /// Generate one PNG with a client-rendered Flux job.
    Image(ImageArgs),
}
impl JobCommand {
    pub async fn run(self, context: Context) -> super::CliResult<()> {
        context
            .command(async {
                match self {
                    Self::Transact(args) => run(args, &context).await,
                    Self::Run(args) => run::run(args, &context).await,
                    Self::Fetch(args) => fetch(args, &context).await,
                    Self::Speak(args) => speak::speak(args, &context).await,
                    Self::Transcribe(args) => transcribe::transcribe(args, &context).await,
                    Self::Text(args) => text::text(args, &context).await,
                    Self::Decide(args) => decide::decide(args, &context).await,
                    Self::Image(args) => image::image(args, &context).await,
                }
            })
            .await
    }
}

/// `ENROLLMENT_ID@NODE_ID`, optionally followed by `@IP:PORT`.
#[derive(Clone, Debug)]
pub struct Provider {
    pub address: hellas_sdk::client::ProviderAddress,
    pub addresses: Vec<SocketAddr>,
}
impl std::str::FromStr for Provider {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, direct) = value
            .match_indices('@')
            .nth(1)
            .map_or((value, None), |(at, _)| {
                (&value[..at], Some(&value[at + 1..]))
            });
        Ok(Self {
            address: address.parse()?,
            addresses: direct
                .map(str::parse)
                .transpose()
                .context("invalid provider @IP:PORT")?
                .into_iter()
                .collect(),
        })
    }
}

pub(crate) fn duration(value: &str) -> Result<Duration, String> {
    let (digits, scale) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1000)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60_000)
    } else if let Some(value) = value.strip_suffix('h') {
        (value, 3_600_000)
    } else if let Some(value) = value.strip_suffix('d') {
        (value, 86_400_000)
    } else {
        return Err("duration needs a unit: ms, s, m, h or d".into());
    };
    let millis = digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(scale))
        .filter(|n| *n > 0)
        .ok_or("duration must be positive and bounded")?;
    Ok(Duration::from_millis(millis))
}

#[derive(Clone, Debug, Args)]
pub struct ClientArgs {
    /// Provider address ENROLLMENT_ID@NODE_ID, optionally followed by @IP:PORT.
    /// Paid work requires it; --access derives it from the signed offer.
    #[arg(long)]
    provider: Option<Provider>,
    /// Additional direct UDP addresses for the provider.
    #[arg(long = "address", value_delimiter = ',')]
    addresses: Vec<SocketAddr>,
    /// Wall-clock deadline for quote, funding, execution and payment.
    /// Without it, wait until the job is done.
    #[arg(long, value_parser = duration)]
    timeout: Option<Duration>,
    /// Finalized blocks allowed for paid-job admission and input upload.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    acceptance_blocks: u64,
    /// Finalized blocks after admission allowed for execution and delivery.
    #[arg(long, default_value_t = 3000, value_parser = clap::value_parser!(u64).range(1..))]
    terminal_blocks: u64,
    /// Finalized blocks after execution allowed for payment.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(1..))]
    payment_blocks: u64,
    /// Wait for channel settlement after the job.
    #[arg(long)]
    settle: bool,
    /// Deliberately purchase again after a paid result was lost.
    #[arg(long)]
    buy_again: bool,
    /// Validator WebSocket URL; repeat to override the selected chain defaults.
    #[arg(long = "validator")]
    validators: Vec<String>,
    /// Independent Apple App Attest approval directory and policy.
    #[arg(long, requires = "trust_policy")]
    trust_store: Option<PathBuf>,
    #[arg(long, requires = "trust_store")]
    trust_policy: Option<String>,
}

#[derive(Debug, Args)]
pub struct TransactArgs {
    #[command(flatten)]
    client: ClientArgs,
    /// Unsigned hellas.job.v1 folder. Omit only with --settle.
    #[arg(long, required_unless_present = "settle", value_name = "DIR")]
    job: Option<PathBuf>,
    /// Write the signed transcript and decoded outputs to this directory.
    #[arg(short = 'o', long = "output", requires = "job", value_name = "DIR")]
    output: Option<PathBuf>,
    #[command(flatten)]
    target: TargetArgs,
}

/// Where a job runs: paid under `--provider`, granted under `--access`, or,
/// with local compute, on this machine.
#[derive(Debug, Args)]
#[cfg_attr(
    not(feature = "compute"),
    command(group(clap::ArgGroup::new("execution_target").required(true).multiple(true).args(["provider", "access"])))
)]
#[cfg_attr(
    feature = "compute",
    command(group(clap::ArgGroup::new("execution_target").required(true).multiple(true).args(["provider", "access", "local"])))
)]
pub(super) struct TargetArgs {
    /// The access file someone shared with you (`hellas share`); the job runs
    /// under its grant on the sharing node.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["settle", "buy_again", "validators", "addresses", "acceptance_blocks", "terminal_blocks", "payment_blocks"])]
    access: Option<PathBuf>,
    /// Select a resource ID when the access file's offer has several.
    #[arg(long, requires = "access")]
    resource: Option<ResourceId>,
    /// Durable attempt record (default: under the client state, by offer and job).
    #[arg(long, requires = "access", value_name = "FILE")]
    attempt: Option<PathBuf>,
    /// Run on this machine's executor under your own limits; nothing is
    /// paid, granted or tracked.
    #[cfg(feature = "compute")]
    #[arg(long, conflicts_with_all = ["access", "provider", "backend", "settle", "buy_again", "validators", "addresses", "acceptance_blocks", "terminal_blocks", "payment_blocks", "trust_store"])]
    local: bool,
    #[cfg(feature = "compute")]
    #[command(flatten)]
    native: crate::compute::LocalArgs,
    /// The registered renderer (evaluator id) remote jobs are rendered for,
    /// as `hellas program --backend` takes; local jobs render for this
    /// machine's GPU runtime.
    #[arg(long, value_name = "EVALUATOR")]
    backend: Option<String>,
}

#[derive(Debug, Args)]
pub struct FetchArgs {
    url: String,
    #[command(flatten)]
    client: ClientArgs,
    /// Pay the provider named by --provider its quoted price per job, at most MAX.
    #[arg(long, value_name = "MAX", requires = "provider", conflicts_with = "access", value_parser = clap::value_parser!(u64).range(1..))]
    pay: Option<u64>,
    #[arg(long, default_value = "producer-signed", value_parser = ["producer-signed", "apple-app-attest"])]
    assurance: String,
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    /// Request body, as @FILE.
    #[arg(long)]
    data: Option<String>,
    #[arg(long)]
    max_response_bytes: Option<u32>,
    /// The Fetch contract this request must run under: `http`, the HTTPS
    /// contract built into this release, or an exact contract JSON file. It is
    /// never taken from the provider's quote.
    #[arg(long, value_name = "http|FILE")]
    contract: String,
    /// DER trust anchor; repeat for private HTTPS roots.
    #[arg(long = "tls-root", value_name = "FILE")]
    tls_roots: Vec<PathBuf>,
    /// SHA-256 of the leaf certificate's DER SPKI; repeat for several pins.
    #[arg(long = "spki-sha256")]
    spki_sha256: Vec<String>,
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,
    #[arg(long, value_name = "DIR")]
    save_job: Option<PathBuf>,
    #[command(flatten)]
    target: TargetArgs,
}

use hellas_sdk::home::{Home as Context, TargetSpec};

impl ClientArgs {
    fn paid_provider(&self) -> super::CliResult<&Provider> {
        self.provider
            .as_ref()
            .context("paid execution requires --provider")
    }

    fn options_with_config(
        &self,
        context: &Context,
        price: u64,
        assurance: Assurance,
        config: hellas_sdk::work_config::WorkConfig,
        content: hellas_store::content::DiskStore,
    ) -> super::CliResult<PaidWorkOptions> {
        let provider = self.paid_provider()?;
        Ok(PaidWorkOptions {
            content,
            config,
            provider: provider.address,
            provider_addrs: provider
                .addresses
                .iter()
                .chain(&self.addresses)
                .copied()
                .collect(),
            apple_trust: self.trust(context, assurance)?,
            assurance,
            expected_price: price,
            acceptance_blocks: self.acceptance_blocks,
            terminal_blocks: self.terminal_blocks,
            payment_blocks: self.payment_blocks,
            timeout: self.timeout,
        })
    }

    fn trust(
        &self,
        context: &Context,
        assurance: Assurance,
    ) -> super::CliResult<Option<hellas_client::ProviderTrustAnchor>> {
        match (&self.trust_store, &self.trust_policy, assurance) {
            (Some(store), Some(policy), _) => Ok(Some(
                hellas_sdk::trust_policy::TrustPolicyStore::new(store).resolve(
                    policy,
                    assurance,
                    hellas_sdk::identity::assertion_counters(&context.home)?,
                )?,
            )),
            (None, None, Assurance::ProducerSigned) => Ok(None),
            _ => bail!("Apple providers require --trust-store and --trust-policy"),
        }
    }
}

#[cfg(test)]
use hellas_sdk::home::select_attempt;
#[cfg(test)]
use hellas_sdk::{home::select_policy, transact::PaidAttemptPath};

/// One deadline for the whole command, from `--timeout`; without one, wait
/// until it is done.
async fn bounded<T>(
    timeout: Option<Duration>,
    work: impl AsyncFnOnce(Option<tokio::time::Instant>) -> super::CliResult<T>,
) -> super::CliResult<T> {
    let deadline = timeout.map(|timeout| tokio::time::Instant::now() + timeout);
    work(deadline).await.map_err(|error| {
        match (timeout, error.downcast_ref::<ExecutionError>()) {
            (Some(timeout), Some(ExecutionError::Stopped(RequestStopped::Deadline))) => {
                anyhow::anyhow!(
                    "exceeded --timeout {timeout:?}; rerun with the same job folder to recover its attempt"
                )
            }
            _ => error,
        }
    })
}

/// Preparation under the command's deadline.
async fn within<T>(
    deadline: Option<tokio::time::Instant>,
    work: impl std::future::Future<Output = super::CliResult<T>>,
) -> super::CliResult<T> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, work)
            .await
            .map_err(|_| ExecutionError::Stopped(RequestStopped::Deadline))?,
        None => work.await,
    }
}

/// A resolved backend and the command-owned attempt.
struct ResolvedBackend {
    backend: Backend,
    attempt: Option<PathBuf>,
}

/// Shared model selection, placement and payment flags for rendered jobs.
#[derive(Debug, Args)]
struct ModelArgs {
    #[command(flatten)]
    client: ClientArgs,
    /// Local model path, Hub reference, or content-addressed model.
    #[arg(long, value_name = "MODEL")]
    model: PathBuf,
    /// Pay the provider its quoted price per job, at most MAX.
    #[arg(long, value_name = "MAX", requires = "provider", conflicts_with = "access", value_parser = clap::value_parser!(u64).range(1..))]
    pay: Option<u64>,
    #[command(flatten)]
    target: TargetArgs,
}
impl ModelArgs {
    async fn open(
        &mut self,
        context: &Context,
        companions: Option<&crate::hub::Companions>,
    ) -> super::CliResult<Arc<ModelPackage>> {
        use hellas_client::model::{CatalogUnavailable, ModelPackage, peer_locator};
        let spec = companions.map_or_else(|| self.model.clone().into(), |c| c.spec(&self.model));
        let mut pinned = crate::hub::Revisions::default().pin_spec(&spec).await?;
        let evaluator = self.target.renderer()?;
        let mut private = None;
        if let Some(uri) = hellas_client::model::peer_uri(&pinned.model) {
            let (id, address) = peer_locator(uri)?;
            let mut bare_contact = None;
            if let Some(file) = &self.target.access {
                let spec = self.target.access_spec(
                    file.clone(),
                    &self.client,
                    context,
                    Assurance::ProducerSigned,
                )?;
                let BackendState::Grant(grant) = context.target(spec).await?.state else {
                    unreachable!("access selects a grant")
                };
                let offer = grant.options.target.offer();
                let node = hellas_sdk::client::ProviderAddress::of(&offer.provider)?.node;
                if address.is_none() {
                    bare_contact = Some((node, offer.addresses.clone()));
                }
                if address.as_ref().is_none_or(|peer| peer.id == node) {
                    private = Some((id, node, grant));
                }
            } else if let Some(provider) = &self.client.provider {
                bare_contact = Some((
                    provider.address.node,
                    provider.addresses.iter().map(ToString::to_string).collect(),
                ));
            }
            if address.is_none() {
                let (node, mut ips) = bare_contact.context("hellas://model-id needs an addressed provider or an explicit @NODE_ID[@IP:PORT]")?;
                ips.extend(self.client.addresses.iter().map(ToString::to_string));
                pinned.model = std::iter::once(format!("{uri}@{node}"))
                    .chain(ips)
                    .collect::<Vec<_>>()
                    .join("@")
                    .into();
            }
        }
        let content = self.target.content(context, Some(&pinned)).await?;
        let package = match (pinned.open(&evaluator, content.as_ref()).await, private) {
            (Err(error), Some((id, node, grant))) if error.is::<CatalogUnavailable>() => {
                let store = grant.options.model_content(node, &grant.transport).await?;
                ModelPackage::open_peer(id, store, &evaluator).await?
            }
            (result, _) => result?,
        };
        Ok(Arc::new(package))
    }

    async fn run(
        self,
        context: &Context,
        package: &ModelPackage,
        job: ComputeJob,
        evidence: impl FnOnce(&Path) -> Option<PathBuf>,
        show: impl FnOnce(ModelResponse) -> super::CliResult<()> + Send,
    ) -> super::CliResult<()> {
        let evaluator = self.target.renderer()?;
        run_quoted(
            &self.client,
            self.target,
            context,
            self.pay,
            None,
            async |price| {
                Ok(Job::compute(
                    price,
                    evaluator,
                    job.environment,
                    job.plan,
                    job.inputs,
                    job.content,
                )
                .await?)
            },
            evidence,
            |_, completed, _| {
                show(package.decode(&completed.output)?)?;
                std::io::stdout().lock().flush()?;
                Ok(())
            },
        )
        .await
    }
}

impl TargetArgs {
    fn access_spec(
        &self,
        file: PathBuf,
        client: &ClientArgs,
        context: &Context,
        assurance: Assurance,
    ) -> super::CliResult<TargetSpec> {
        if let Some(provider) = &client.provider {
            ensure!(
                provider.addresses.is_empty(),
                "grant addresses come from the signed offer"
            );
        }
        Ok(TargetSpec::Access {
            file,
            provider: client.provider.as_ref().map(|p| p.address),
            trust: client.trust(context, assurance)?.map(Box::new),
            resource: self.resource,
        })
    }

    async fn content(
        &self,
        context: &Context,
        model: Option<&hellas_client::model::ModelSpec>,
    ) -> super::CliResult<Option<hellas_store::content::DiskStore>> {
        #[cfg(feature = "compute")]
        if self.local {
            let store = context
                .local_content
                .get_or_try_init(|| async {
                    let files = match model {
                        Some(model) => model.files().await?,
                        None => Default::default(),
                    };
                    crate::compute::content(&context.home, &self.native, &files.local, &files.hub)
                        .await
                })
                .await?;
            if let Some(uri) = model.and_then(|spec| hellas_client::model::peer_uri(&spec.model)) {
                hellas_client::model::acquire_peer_model(uri, store).await?;
            }
            return Ok(Some(store.clone()));
        }
        #[cfg(not(feature = "compute"))]
        let _ = (context, model);
        Ok(None)
    }

    /// The evaluator a rendered job names: the local GPU's, or the one remote
    /// work must select.
    fn renderer(&self) -> super::CliResult<String> {
        #[cfg(feature = "compute")]
        if self.local {
            return Ok(self.native.gpu.config()?.gpu.evaluator());
        }
        self.backend
            .clone()
            .context("remote jobs name their renderer with --backend EVALUATOR")
    }

    /// `pay` is the most a paid job may cost; free targets take 0.
    async fn resolve(
        self,
        client: &ClientArgs,
        context: &Context,
        pay: u64,
        assurance: Assurance,
    ) -> super::CliResult<ResolvedBackend> {
        #[cfg(feature = "compute")]
        if self.local {
            ensure!(pay == 0, "local work is not paid; drop --pay");
            let content = self
                .content(context, None)
                .await?
                .context("local content is not prepared")?;
            return Ok(ResolvedBackend {
                backend: context
                    .target(TargetSpec::Local {
                        content,
                        gpu: self.native.gpu.config()?,
                        timeout: client.timeout.unwrap_or(Duration::from_secs(86_400)),
                    })
                    .await?,
                attempt: None,
            });
        }
        let spec = match self.access {
            Some(ref file) => self.access_spec(file.clone(), client, context, assurance)?,
            None => TargetSpec::Paid(Box::new(client.options_with_config(
                context,
                pay,
                assurance,
                client::config(client, context).await?,
                hellas_sdk::chain_home::open_client_content(&context.chain).await?,
            )?)),
        };
        Ok(ResolvedBackend {
            backend: context.target(spec).await?,
            attempt: self.attempt,
        })
    }
}

impl ResolvedBackend {
    /// Commands add their durable attempt to the same executor gateways use.
    async fn executor(
        &self,
        client: &ClientArgs,
        context: &Context,
        job: &Job,
    ) -> super::CliResult<(Executor, String)> {
        let mut executor = self
            .backend
            .executor(job, self.attempt.as_deref(), client.buy_again)?;
        executor.settle = client.settle;
        let provider = match &self.backend.state {
            BackendState::Paid(paid) => paid.options.provider.to_string(),
            BackendState::Grant(grant) => {
                hellas_sdk::client::ProviderAddress::of(&grant.options.target.offer().provider)?
                    .to_string()
            }
            _ => hex::encode(context.producer.public_key().bytes()),
        };
        Ok((executor, provider))
    }

    async fn close(self) {
        if let BackendState::Paid(paid) = self.backend.state {
            paid.options.content.close().await;
        }
    }
}

/// A rendered model job at `price`.
/// Helper commands quote first: resolve the target, take its price (a paid
/// provider's quote, at most `pay`), build the job at that price, save it
/// (in `save`, or under the client state by digest) and run it once.
/// `evidence` names where the signed evidence goes, given the job folder.
#[allow(clippy::too_many_arguments)]
async fn run_quoted(
    client: &ClientArgs,
    target: TargetArgs,
    context: &Context,
    pay: Option<u64>,
    save: Option<PathBuf>,
    build: impl AsyncFnOnce(u64) -> super::CliResult<Job>,
    evidence: impl FnOnce(&Path) -> Option<PathBuf>,
    present: impl FnOnce(&Job, &Completed, &str) -> super::CliResult<()> + Send,
) -> super::CliResult<()> {
    bounded(client.timeout, async |deadline| {
        let mut target = within(
            deadline,
            target.resolve(client, context, pay.unwrap_or(0), Assurance::ProducerSigned),
        )
        .await?;
        let result = async {
            let price = within(deadline, target.backend.quote().err_into()).await?;
            let job = build(price).await?;
            let directory = save.unwrap_or_else(|| {
                context
                    .chain
                    .client()
                    .join("jobs")
                    .join(job.digest().to_string())
            });
            job.save(&directory).await?;
            eprintln!("job: {}", directory.display());
            let evidence = evidence(&directory);
            execute(
                client,
                context,
                &mut target,
                &job,
                deadline,
                evidence.as_deref(),
                |completed, provider| present(&job, completed, provider),
            )
            .await
        }
        .await;
        target.close().await;
        result
    })
    .await
}

/// A saved job folder keeps its exact signed price: resolve its target, run
/// it once through the executor, keep the signed evidence in `evidence`,
/// then present it.
async fn run_job(
    client: &ClientArgs,
    target: TargetArgs,
    context: &Context,
    job: &Job,
    evidence: Option<&Path>,
    present: impl FnOnce(&Completed, &str) -> super::CliResult<()> + Send,
) -> super::CliResult<()> {
    bounded(client.timeout, async |deadline| {
        let mut target = within(
            deadline,
            target.resolve(client, context, job.price(), job.assurance()),
        )
        .await?;
        let result = execute(
            client,
            context,
            &mut target,
            job,
            deadline,
            evidence,
            present,
        )
        .await;
        target.close().await;
        result
    })
    .await
}

async fn execute(
    client: &ClientArgs,
    context: &Context,
    target: &mut ResolvedBackend,
    job: &Job,
    deadline: Option<tokio::time::Instant>,
    evidence: Option<&Path>,
    present: impl FnOnce(&Completed, &str) -> super::CliResult<()> + Send,
) -> super::CliResult<()> {
    let (executor, provider) = within(deadline, target.executor(client, context, job)).await?;
    let stop = hellas_sdk::execution::stop_on(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    let deliver = |completed: &Completed| -> super::CliResult<()> {
        if let Some(directory) = evidence {
            save_outputs(directory, job, completed, &provider)?;
        }
        if let hellas_rpc::protocol::invocation::output::Outcome::Failed(reason) =
            &completed.output.outcome
        {
            bail!("work {} failed: {reason:?}", completed.work_id);
        }
        present(completed, &provider)
    };
    let completed = executor
        .run(
            job,
            &context.producer,
            deadline,
            stop,
            Default::default(),
            Box::new(|completed| deliver(completed).map_err(Into::into)),
        )
        .await?;
    if let Some(paid) = completed.paid
        && let Some(payout) = paid.settled
    {
        eprintln!(
            "settled channel {}: provider payout {payout}",
            paid.channel_id
        );
    }
    Ok(())
}

pub async fn run(args: TransactArgs, context: &Context) -> super::CliResult<()> {
    // Load every input before network activity or an owner approval.
    let Some(job) = args.job.as_deref() else {
        return bounded(args.client.timeout, async |deadline| {
            within(deadline, client::settle(&args.client, context)).await
        })
        .await;
    };
    let job = Job::load(job).await?;
    let output = args.output.as_deref();
    run_job(
        &args.client,
        args.target,
        context,
        &job,
        output,
        |completed, provider| present_job(&job, completed, provider, output),
    )
    .await
}

/// A job command's result: the output unless saved to a folder, then what
/// was bought from whom.
fn present_job(
    job: &Job,
    completed: &Completed,
    provider: &str,
    output: Option<&Path>,
) -> super::CliResult<()> {
    if output.is_none() {
        if is_https(job) {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            println!(
                "output-0000 (base64): {}",
                STANDARD.encode(http_body(job, completed)?)
            );
        } else {
            println!("output: {}", serde_json::to_string(&completed.output)?);
        }
    }
    println!("{}", wording(provider, job, completed));
    std::io::stdout().lock().flush()?;
    Ok(())
}

pub async fn fetch(args: FetchArgs, context: &Context) -> super::CliResult<()> {
    let mut request = args.request()?;
    let contract = args.contract()?;
    let assurance = args.assurance();
    let target = args.target;
    bounded(args.client.timeout, async |deadline| {
        let mut target = within(
            deadline,
            target.resolve(&args.client, context, args.pay.unwrap_or(0), assurance),
        )
        .await?;
        let result = async {
            let price = within(deadline, target.backend.quote().err_into()).await?;
            let policy = target.backend.policy().cloned();
            let policy = policy
                .context("local execution runs Compute jobs; Fetch needs --provider or --access")?;
            let admission = policy
                .admissions
                .iter()
                .find_map(|a| match a {
                    hellas_rpc::protocol::invocation::Admission::Fetch { admission }
                        if admission.contract == contract =>
                    {
                        Some(admission)
                    }
                    _ => None,
                })
                .context("provider does not admit the named contract. Nothing was paid.")?;
            let (service, method) = match &admission.route {
                hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy::OpenFetch { .. } => {
                    ("http".into(), "request".into())
                }
                hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy::SealedRoute {
                    service,
                    method,
                } => (service.clone(), method.clone()),
            };
            if args.max_response_bytes.is_none() {
                request.max_response_bytes = (policy.limits.max_output_bytes / 4 * 3)
                    .min(u64::from(hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES))
                    as u32;
            }
            let job = Job::fetch(
                price,
                contract.clone(),
                service,
                method,
                serde_json::to_vec(&request)?,
                assurance,
            )?;
            let directory = args.save_job.clone().unwrap_or_else(|| {
                context
                    .chain
                    .client()
                    .join("jobs")
                    .join(job.digest().to_string())
            });
            job.save(&directory).await?;
            eprintln!("job: {}", directory.display());
            execute(
                &args.client,
                context,
                &mut target,
                &job,
                deadline,
                None,
                |completed, provider| {
                    let body = http_body(&job, completed)?;
                    if let Some(path) = &args.output {
                        write(path, &body)?;
                    } else {
                        std::io::stdout().lock().write_all(&body)?;
                    }
                    eprintln!("{}", wording(provider, &job, completed));
                    std::io::stdout().lock().flush()?;
                    std::io::stderr().lock().flush()?;
                    Ok(())
                },
            )
            .await
        }
        .await;
        target.close().await;
        result
    })
    .await
}

impl FetchArgs {
    /// The named HTTPS contract; checked before any provider is contacted.
    fn contract(&self) -> super::CliResult<hellas_rpc::FetchContract> {
        let contract = match self.contract.as_str() {
            "http" => hellas_rpc::FetchContract::http()?,
            path => serde_json::from_slice(&super::read_bounded_regular_file(
                Path::new(path),
                "contract",
                hellas_rpc::protocol::fetch_contract::MAX_FETCH_CONTRACT_BYTES,
            )?)?,
        };
        ensure!(
            contract.schema() == hellas_rpc::FetchSchema::HttpV1,
            "hellas fetch requires an http_v1 contract"
        );
        Ok(contract)
    }

    fn assurance(&self) -> Assurance {
        if self.assurance == "apple-app-attest" {
            Assurance::AppleAppAttest
        } else {
            Assurance::ProducerSigned
        }
    }
    fn request(&self) -> super::CliResult<hellas_rpc::http_fetch::HttpFetchRequest> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use hellas_rpc::http_fetch::*;
        let headers = self
            .headers
            .iter()
            .map(|header| {
                let (key, value) = header
                    .split_once(':')
                    .context("--header must be 'Name: value'")?;
                Ok((key.trim().to_ascii_lowercase(), value.trim().to_owned()))
            })
            .collect::<super::CliResult<_>>()?;
        let body = match &self.data {
            Some(value) => super::read_bounded_regular_file(
                Path::new(value.strip_prefix('@').context("--data must name @FILE")?),
                "request body",
                hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES,
            )?,
            None => Vec::new(),
        };
        let roots = if self.tls_roots.is_empty() {
            HttpTrustRoots::WebPki
        } else {
            HttpTrustRoots::Certificates {
                der_base64: self
                    .tls_roots
                    .iter()
                    .map(|path| {
                        Ok(STANDARD.encode(super::read_bounded_regular_file(
                            path,
                            "TLS root",
                            24 * 1024,
                        )?))
                    })
                    .collect::<super::CliResult<_>>()?,
            }
        };
        let mut request = HttpFetchRequest {
            url: self.url.clone(),
            method: self.method.clone(),
            headers,
            body_base64: STANDARD.encode(body),
            tls: None,
            max_response_bytes: self
                .max_response_bytes
                .unwrap_or(hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES),
        };
        if request.parsed_url()?.scheme() == "https"
            || !self.tls_roots.is_empty()
            || !self.spki_sha256.is_empty()
        {
            request.tls = Some(HttpTls {
                roots,
                spki_sha256: self.spki_sha256.clone(),
            });
        }
        request.validate()?;
        Ok(request)
    }
}

fn is_https(job: &Job) -> bool {
    matches!(job.input(), JobInput::Fetch { contract, .. } if contract.schema() == hellas_rpc::FetchSchema::HttpV1)
}

fn http_body(job: &Job, completed: &Completed) -> super::CliResult<Vec<u8>> {
    let JobInput::Fetch { request, .. } = job.input() else {
        bail!("not an HTTPS Fetch job");
    };
    ensure!(is_https(job), "not an HTTPS Fetch contract");
    let request = hellas_rpc::http_fetch::HttpFetchRequest::decode(request)?;
    let output = hellas_rpc::protocol::invocation::fetch::decode_output(
        &completed.output,
        &completed.provider_key,
    )?;
    Ok(hellas_rpc::http_fetch::HttpFetchResponse::from_output(&request, &output)?.body)
}

/// The signed evidence of one completion, whoever funded it.
fn save_outputs(
    directory: &Path,
    job: &Job,
    completed: &Completed,
    provider: &str,
) -> super::CliResult<()> {
    hellas_private::create_dir_all_durable(directory)?;
    write(&directory.join("transcript.cbor"), &completed.transcript)?;
    let mut result = serde_json::json!({
        "job": job.digest().to_string(),
        "work": completed.work_id.to_string(),
        "provider": provider,
        "outcome": completed.output.outcome,
    });
    if let Some(paid) = completed.paid {
        result["channel"] = paid.channel_id.to_string().into();
        result["paid"] = paid.price.into();
    }
    write(
        &directory.join("result.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    if is_https(job) {
        write(&directory.join("output-0000"), &http_body(job, completed)?)?;
    } else {
        for (index, artifact) in completed.output.artifacts.iter().enumerate() {
            write(
                &directory.join(format!("output-{index:04}")),
                artifact.bytes.as_bytes(),
            )?;
        }
        write(
            &directory.join("output.json"),
            &serde_json::to_vec_pretty(&completed.output)?,
        )?;
    }
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> super::CliResult<()> {
    hellas_private::write_atomically(path, ".writing", bytes)?;
    Ok(())
}

fn wording(provider: &str, job: &Job, completed: &Completed) -> String {
    let funding = match completed.paid {
        Some(paid) => format!(
            "paid {} · work {} · channel {} (`hellas transact --settle --provider {provider}` settles this provider's channels)",
            paid.price, completed.work_id, paid.channel_id,
        ),
        None => format!("granted · work {}", completed.work_id),
    };
    format!(
        "signed by provider {provider} and matches this job {} (evaluator {}, adaptor {})\nHellas did not re-run this job. The signature shows who answered, not that the answer is right.\n{funding}",
        job.digest(),
        job.manifest().application().evaluator(),
        job.manifest().application().adaptor(),
    )
}

#[cfg(test)]
async fn check_rendered_plan(
    job: &ComputeJob,
    max_steps: u64,
    invalidate: impl FnOnce(&mut hellas_rpc::protocol::invocation::compute::Plan),
) {
    let object = job.environment.sources[0];
    let source = hellas_channel::content::read(
        &job.content.0,
        &job.content.1,
        object,
        hellas_rpc::protocol::invocation::compute::MAX_SOURCE_BYTES,
    )
    .await
    .unwrap();
    let source = String::from_utf8(source.to_vec()).unwrap();
    let module = hellas_executor::catena::compile::compile_sources(
        &[source],
        catena_lang::codegen::GpuDialect::Hip,
    )
    .unwrap();
    let inputs = job
        .inputs
        .iter()
        .map(|a| {
            (
                a.name.clone(),
                hellas_rpc::ContentRef::for_bytes(a.bytes.as_bytes()),
            )
        })
        .collect();
    let limits = hellas_rpc::protocol::invocation::Limits {
        max_upload_bytes: 4 << 20,
        max_output_bytes: 1 << 20,
        max_steps,
        execution_timeout_ms: 90000,
    };
    let validate = |plan| {
        hellas_executor::catena::validate::validate(
            &module,
            &job.environment,
            &inputs,
            plan,
            &limits,
        )
    };
    validate(&job.plan).unwrap();
    let mut invalid = job.plan.clone();
    invalidate(&mut invalid);
    assert!(validate(&invalid).is_err());
}
