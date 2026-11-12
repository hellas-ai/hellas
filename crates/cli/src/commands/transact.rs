//! Job folders and helpers share the SDK transaction and its existing journals.
use anyhow::{Context as _, bail, ensure};
use clap::Args;
use hellas_auth::ProducerSigningKey;
use hellas_auth::authority::{NodeKey, ResourceId, UnixMillis};
use hellas_kernel::Secp256k1Signer;
use hellas_private::StoreLocation;
use hellas_rpc::Assurance;
use hellas_sdk::{
    execution::{
        Completed, ExecutionAttempt, ExecutionError, ExecutionTarget, ExecutionTerms, Executor,
        RequestStopped,
    },
    grant_client::{GrantSessionOptions, UnpinnedOffer},
    job::{Job, JobInput},
    paid_client::{PaidJournalKind, PaidWorkOptions, bind_paid_endpoint},
    transact::PaidAttemptPath,
    {Backend, ExecutorGateway},
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
pub use run::{RunArgs, run as run_program};
pub use transcribe::{TranscribeArgs, transcribe};
mod image;
pub use image::{ImageArgs, image};
mod text;
pub use text::{TextArgs, text};
#[cfg(test)]
mod tests;

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
    native: crate::compute::ServeArgs,
    /// The registered renderer (evaluator id) remote jobs are rendered for,
    /// as `hellas program --backend` takes; local jobs render for this
    /// machine's GPU runtime.
    #[arg(long, value_name = "EVALUATOR")]
    backend: Option<String>,
    /// The model files or packages a helper or the gateway renders jobs
    /// from; local execution reads the jobs' weights from them.
    #[arg(skip)]
    pub(super) models: Vec<PathBuf>,
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

pub struct Context {
    pub transport: iroh::SecretKey,
    pub settlement: Secp256k1Signer,
    pub producer: ProducerSigningKey,
    owner: std::sync::OnceLock<hellas_kernel::SoftPasskey>,
    pub home: StoreLocation,
    pub chain: hellas_chain::chain_dir::ChainDir,
    /// Bound on first use; [`bounded`] closes them however the command ends,
    /// after the executor that borrowed them has finished.
    paid_endpoint: tokio::sync::OnceCell<iroh::Endpoint>,
    grant_endpoint: tokio::sync::OnceCell<iroh::Endpoint>,
}

impl Context {
    pub(crate) fn new(
        identity: &crate::identity::LocalIdentity,
        owner: Option<&hellas_kernel::SoftPasskey>,
        home: &StoreLocation,
        chain: &hellas_chain::genesis::ChainProfile,
    ) -> super::CliResult<Self> {
        Ok(Self {
            transport: identity.transport_key.clone(),
            settlement: crate::identity::settlement_signer(identity)?,
            producer: identity.node_key.clone(),
            owner: owner
                .cloned()
                .map_or_else(std::sync::OnceLock::new, Into::into),
            home: home.clone(),
            chain: hellas_chain::chain_dir::ChainDir::open(home, chain)?,
            paid_endpoint: tokio::sync::OnceCell::new(),
            grant_endpoint: tokio::sync::OnceCell::new(),
        })
    }

    /// Paid and granted work act for the principal, whose home key is
    /// created on first use; local work needs none.
    fn owner(&self) -> super::CliResult<&hellas_kernel::SoftPasskey> {
        if let Some(owner) = self.owner.get() {
            return Ok(owner);
        }
        let owner = crate::owner::principal(&self.home)?;
        Ok(self.owner.get_or_init(|| owner))
    }

    async fn paid_endpoint(&self) -> super::CliResult<iroh::Endpoint> {
        let bind = || bind_paid_endpoint(self.transport.clone());
        Ok(self.paid_endpoint.get_or_try_init(bind).await?.clone())
    }

    async fn grant_endpoint(&self) -> super::CliResult<iroh::Endpoint> {
        let bind = || hellas_sdk::grant_client::bind_endpoint(self.transport.clone());
        Ok(self.grant_endpoint.get_or_try_init(bind).await?.clone())
    }
}

impl ClientArgs {
    fn paid_provider(&self) -> super::CliResult<&Provider> {
        self.provider
            .as_ref()
            .context("paid execution requires --provider")
    }

    fn root(&self, context: &Context) -> PathBuf {
        context.chain.client().into_path_buf()
    }
    fn owner(
        &self,
        context: &Context,
    ) -> super::CliResult<Arc<hellas_sdk::client_owner::ClientOwner>> {
        Ok(Arc::new(hellas_sdk::client_owner::ClientOwner::new(
            Arc::new(context.owner()?.clone()),
            context.settlement.party_key(),
            &context.chain,
        )?))
    }
    /// The attempt `owner` keeps for `job` at this provider. Takes the
    /// owner rather than opening it: the funding wallet is one exclusive
    /// lock, and the job's executor already holds it.
    fn purchase(
        &self,
        context: &Context,
        job: &Job,
        options: &PaidWorkOptions,
        owner: &hellas_sdk::client_owner::ClientOwner,
    ) -> super::CliResult<ExecutionAttempt> {
        let path = PaidAttemptPath::new(
            &context.chain,
            options.provider,
            owner.principal(),
            job.digest(),
        );
        select_attempt(&path, job, self.buy_again)
    }

    async fn options(
        &self,
        context: &Context,
        price: u64,
        assurance: Assurance,
    ) -> super::CliResult<PaidWorkOptions> {
        self.paid_provider()?;
        let config = client::config(self, context).await?;
        let content = client::content(context, config.network()).await?;
        self.options_with_config(context, price, assurance, config, content)
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
        let apple_trust = match (&self.trust_store, &self.trust_policy, assurance) {
            (Some(directory), Some(id), _) => Some(
                hellas_sdk::trust_policy::TrustPolicyStore::new(directory).resolve(
                    id,
                    assurance,
                    crate::identity::assertion_counters(&context.home)?,
                )?,
            ),
            (None, None, Assurance::ProducerSigned) => None,
            _ => bail!("Apple providers require --trust-store and --trust-policy"),
        };
        Ok(PaidWorkOptions {
            content,
            journal_kind: PaidJournalKind::Client,
            config,
            provider: provider.address,
            provider_addrs: provider
                .addresses
                .iter()
                .chain(&self.addresses)
                .copied()
                .collect(),
            assurance,
            apple_trust,
            expected_price: price,
            acceptance_blocks: self.acceptance_blocks,
            terminal_blocks: self.terminal_blocks,
            payment_blocks: self.payment_blocks,
            timeout: self.timeout,
        })
    }
}

fn select_attempt(
    path: &PaidAttemptPath,
    job: &Job,
    buy_again: bool,
) -> super::CliResult<ExecutionAttempt> {
    let parent = path
        .as_path()
        .parent()
        .context("purchase directory is missing")?;
    path.durability().create_dir_all(parent)?;
    let pointer = path.as_path().with_extension("latest");
    struct AttemptPointerLock(std::fs::File);
    impl Drop for AttemptPointerLock {
        fn drop(&mut self) {
            let _ = self.0.unlock();
        }
    }
    let lock = hellas_private::open_lock_beside(&pointer)?;
    lock.try_lock()
        .map_err(|_| anyhow::anyhow!("another command is selecting this job's attempt"))?;
    let _lock = AttemptPointerLock(lock);
    let existing = match hellas_private::read_bounded_regular_file(&pointer, 32) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if !buy_again && let Some(id) = existing {
        let id = std::str::from_utf8(&id)?;
        ensure!(
            id.len() == 32
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "invalid purchase attempt pointer"
        );
        let nonce: [u8; 16] = hex::decode(id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid purchase attempt pointer"))?;
        let attempt_path = path.with_nonce(nonce);
        return Ok(ExecutionAttempt::open_existing_paid(
            &attempt_path,
            job.input(),
            job.price(),
        )?);
    }
    if !buy_again {
        let prefix = format!("{}.", job.digest());
        for entry in std::fs::read_dir(parent)? {
            let name = entry?.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(id) = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix(".json"))
                && id.len() == 32
                && id.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                bail!(
                    "purchase attempt pointer is missing; recover the existing attempt before starting another"
                );
            }
        }
    }
    let nonce = rand::random::<[u8; 16]>();
    let id = hex::encode(nonce);
    let attempt_path = path.with_nonce(nonce);
    ensure!(
        !attempt_path.as_path().try_exists()?,
        "purchase attempt identity already exists"
    );
    let attempt = ExecutionAttempt::open_paid(&attempt_path, job.input(), job.price())?;
    path.durability()
        .write_atomically(&pointer, ".writing", id.as_bytes())?;
    Ok(attempt)
}

/// One deadline for the whole command, from `--timeout`; without one, wait
/// until it is done. The endpoints the command bound close however it ends,
/// after the executor that borrowed them has finished.
async fn bounded<T>(
    context: &Context,
    timeout: Option<Duration>,
    work: impl AsyncFnOnce(Option<tokio::time::Instant>) -> super::CliResult<T>,
) -> super::CliResult<T> {
    let deadline = timeout.map(|timeout| tokio::time::Instant::now() + timeout);
    let result = work(deadline).await.map_err(|error| {
        match (timeout, error.downcast_ref::<ExecutionError>()) {
            (Some(timeout), Some(ExecutionError::Stopped(RequestStopped::Deadline))) => {
                anyhow::anyhow!(
                    "exceeded --timeout {timeout:?}; rerun with the same job folder to recover its attempt"
                )
            }
            _ => error,
        }
    });
    for endpoint in [context.paid_endpoint.get(), context.grant_endpoint.get()]
        .into_iter()
        .flatten()
    {
        endpoint.close().await;
    }
    result
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

/// A resolved backend and the command-owned attempt and content reload.
struct ResolvedBackend {
    backend: Backend,
    attempt: Option<PathBuf>,
    #[cfg(feature = "compute")]
    reload: Option<crate::content_configuration::ContentReload>,
}

impl From<Backend> for ResolvedBackend {
    fn from(backend: Backend) -> Self {
        Self {
            backend,
            attempt: None,
            #[cfg(feature = "compute")]
            reload: None,
        }
    }
}

impl TargetArgs {
    /// The evaluator id jobs for this target are rendered for.
    fn evaluator(&self) -> Option<String> {
        #[cfg(feature = "compute")]
        if self.local {
            return Some(hellas_executor::catena::evaluator(
                self.native.gpu.gpu_backend,
            ));
        }
        self.backend.clone()
    }

    /// The evaluator a rendered job names, which remote work must select.
    fn renderer(&self) -> super::CliResult<String> {
        self.evaluator()
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
            let mut native = self.native;
            native.content.extend(self.models);
            let (execution, reload) =
                crate::compute::local(&context.home, native, Arc::new(context.producer.clone()))
                    .await?;
            return Ok(ResolvedBackend {
                backend: Backend::Local {
                    execution,
                    timeout: client.timeout.unwrap_or(Duration::from_secs(86_400)),
                },
                attempt: None,
                reload: Some(reload),
            });
        }
        let Some(access) = self.access.as_deref() else {
            ensure!(
                pay > 0,
                "paid execution requires --pay MAX; select --access for grant work"
            );
            return Ok(Backend::Paid {
                options: client.options(context, pay, assurance).await?,
                policy: None,
                endpoint: context.paid_endpoint().await?,
                settlement_key: context.settlement.clone(),
                owner: client.owner(context)?,
            }
            .into());
        };
        let principal = super::contributions::principal(context.owner()?)?;
        let holder = NodeKey::from_public_key(context.producer.public_key())?;
        let (offers, application) =
            hellas_sdk::access_bundle::AccessBundle::load(access, &principal, &holder)
                .with_context(|| format!("access file {}", access.display()))?
                .into_parts();
        let [offer] = <[_; 1]>::try_from(offers)
            .map_err(|_| anyhow::anyhow!("a job uses an access file with one offer"))?;
        let provider = hellas_sdk::client::ProviderAddress::of(&offer.offer().provider)?;
        if let Some(expected) = &client.provider {
            ensure!(
                expected.addresses.is_empty(),
                "grant addresses come from the signed offer"
            );
            ensure!(
                provider == expected.address,
                "offer does not match --provider"
            );
        }
        let trust = match (&client.trust_store, &client.trust_policy, assurance) {
            (Some(directory), Some(id), assurance) => {
                hellas_sdk::trust_policy::TrustPolicyStore::new(directory).resolve(
                    id,
                    assurance,
                    crate::identity::assertion_counters(&context.home)?,
                )?
            }
            (None, None, Assurance::ProducerSigned) => hellas_client::ProviderTrustAnchor {
                expected_genesis: provider.enrollment,
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            },
            _ => bail!("Apple providers require --trust-store and --trust-policy"),
        };
        let target = UnpinnedOffer::decode(&offer.encode()?, UnixMillis(0))?.pin(&trust)?;
        let policy = select_policy(&offer.offer().grant.policies, self.resource)?.clone();
        let mut resolved = ResolvedBackend::from(Backend::Grant {
            options: GrantSessionOptions {
                target,
                principal,
                signer: Arc::new(context.producer.clone()),
                application: Arc::new(application),
                journal_root: super::contributions::client_journal_root(&context.home, &principal)?,
                control_timeout: Duration::from_secs(90),
            },
            policy,
            transport: hellas_sdk::grant_client::GrantTransport::Remote(
                context.grant_endpoint().await?,
            ),
        });
        resolved.attempt = self.attempt;
        Ok(resolved)
    }
}

impl ResolvedBackend {
    async fn quote(
        &mut self,
    ) -> super::CliResult<(
        Option<hellas_rpc::protocol::invocation::InvocationPolicy>,
        u64,
    )> {
        let price = self.backend.quote().await?;
        let policy = match &self.backend {
            Backend::Paid { policy, .. } => policy.clone(),
            Backend::Grant { policy, .. } => Some(policy.invocation_policy.clone()),
            #[cfg(feature = "compute")]
            Backend::Local { .. } => None,
        };
        Ok((policy, price))
    }

    /// Commands add their durable attempt to the same executor gateways use.
    async fn executor(
        &self,
        client: &ClientArgs,
        context: &Context,
        job: &Job,
    ) -> super::CliResult<(Executor, String)> {
        let mut executor = self.backend.executor(job)?;
        let provider = match &mut executor {
            Executor::Paid(execution) => {
                execution.attempt =
                    Some(client.purchase(context, job, &execution.options, &execution.owner)?);
                execution.settle = client.settle;
                execution.options.provider.to_string()
            }
            Executor::Grant(execution) => {
                let Backend::Grant { policy, .. } = &self.backend else {
                    unreachable!()
                };
                job.input().admits(&policy.invocation_policy, false)?;
                let offer = execution.options.target.offer();
                let provider = hellas_sdk::client::ProviderAddress::of(&offer.provider)?;
                let default_attempt = context
                    .home
                    .join("grants")
                    .join("grant-attempts")
                    .join(provider.to_string())
                    .join(offer.grant.id.to_string())
                    .join(format!("{}.json", job.digest()));
                let mut attempt = ExecutionAttempt::open(
                    self.attempt.as_deref().unwrap_or(&default_attempt),
                    job.input(),
                    ExecutionTerms::Grant {
                        resource: policy.resource,
                    },
                )?;
                attempt.bind_target(ExecutionTarget {
                    network: offer.network,
                    provider,
                })?;
                execution.attempt = Some(attempt);
                provider.to_string()
            }
            #[cfg(feature = "compute")]
            Executor::Local(..) => hex::encode(context.producer.public_key().bytes()),
        };
        Ok((executor, provider))
    }

    async fn close(self) -> super::CliResult<()> {
        match self.backend {
            Backend::Paid { options, .. } => options.content.close().await,
            Backend::Grant { .. } => {}
            #[cfg(feature = "compute")]
            Backend::Local { execution, .. } => {
                let stopped = match self.reload {
                    Some(reload) => reload.shutdown().await,
                    None => Ok(()),
                };
                execution.content.close().await;
                stopped?;
            }
        }
        Ok(())
    }
}

/// `hellas gateway`'s models, and its execution flags: the job commands' own.
#[derive(Debug, Args)]
pub struct GatewayArgs {
    /// A model the routes render jobs from, named after its file or
    /// directory: a Qwen GGUF serves the text routes, a converted Whisper
    /// package /v1/audio/transcriptions and a converted Flux package
    /// /v1/images/generations. Providers must hold the same weights.
    #[arg(long = "model", value_name = "PATH")]
    pub(crate) models: Vec<PathBuf>,
    #[command(flatten)]
    client: ClientArgs,
    /// Pay the provider named by --provider its quoted price per request, at most MAX.
    #[arg(long, value_name = "MAX", requires = "provider", conflicts_with = "access", value_parser = clap::value_parser!(u64).range(1..))]
    pay: Option<u64>,
    #[command(flatten)]
    target: TargetArgs,
}

/// Open the gateway's target as a job command opens its own and `serve`
/// HTTP with it. The endpoints and content it opened close however it ends.
pub async fn gateway(
    args: GatewayArgs,
    context: Context,
    serve: impl AsyncFnOnce(Arc<ExecutorGateway>) -> super::CliResult<()>,
) -> super::CliResult<()> {
    let GatewayArgs {
        models,
        client,
        pay,
        mut target,
    } = args;
    let evaluator = target.evaluator();
    target.models = models;
    ensure!(
        !client.settle && !client.buy_again && target.attempt.is_none(),
        "gateway requests are not tracked attempts: drop --settle, --buy-again and --attempt"
    );
    bounded(&context, None, async |_| {
        let mut target = target
            .resolve(
                &client,
                &context,
                pay.unwrap_or(0),
                Assurance::ProducerSigned,
            )
            .await?;
        let result = async {
            target.quote().await?;
            serve(ExecutorGateway::new(
                target.backend.clone(),
                evaluator,
                Arc::new(context.producer.clone()),
            ))
            .await
        }
        .await;
        result.and(target.close().await)
    })
    .await
}

fn select_policy(
    policies: &[hellas_authority::model::grant::records::GrantPolicy],
    resource: Option<ResourceId>,
) -> anyhow::Result<&hellas_authority::model::grant::records::GrantPolicy> {
    match resource {
        Some(id) => policies
            .iter()
            .find(|policy| policy.resource == id)
            .context("selected --resource is absent from the offer"),
        None => {
            ensure!(
                policies.len() == 1,
                "offer must contain one policy unless --resource selects an explicit resource ID"
            );
            Ok(&policies[0])
        }
    }
}

/// A rendered model job at `price`.
async fn compute_job(
    price: u64,
    evaluator: String,
    rendered: hellas_client::model::ComputeJob,
) -> super::CliResult<Job> {
    Ok(Job::compute(
        price,
        evaluator,
        rendered.environment,
        rendered.plan,
        rendered.inputs,
        rendered.content,
    )
    .await?)
}

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
    bounded(context, client.timeout, async |deadline| {
        let mut target = within(
            deadline,
            target.resolve(client, context, pay.unwrap_or(0), Assurance::ProducerSigned),
        )
        .await?;
        let result = async {
            let (_, price) = within(deadline, target.quote()).await?;
            let job = build(price).await?;
            let directory = save.unwrap_or_else(|| {
                client
                    .root(context)
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
        result.and(target.close().await)
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
    bounded(context, client.timeout, async |deadline| {
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
        result.and(target.close().await)
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

pub async fn run(args: TransactArgs, context: Context) -> super::CliResult<()> {
    // Load every input before network activity or an owner approval.
    let Some(job) = args.job.as_deref() else {
        return bounded(&context, args.client.timeout, async |deadline| {
            within(deadline, client::settle(&args.client, &context)).await
        })
        .await;
    };
    let job = Job::load(job).await?;
    let output = args.output.as_deref();
    run_job(
        &args.client,
        args.target,
        &context,
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

pub async fn fetch(args: FetchArgs, context: Context) -> super::CliResult<()> {
    let mut request = args.request()?;
    let contract = args.contract()?;
    let assurance = args.assurance();
    let target = args.target;
    bounded(&context, args.client.timeout, async |deadline| {
        let mut target = within(
            deadline,
            target.resolve(&args.client, &context, args.pay.unwrap_or(0), assurance),
        )
        .await?;
        let result = async {
            let (policy, price) = within(deadline, target.quote()).await?;
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
                args.client
                    .root(&context)
                    .join("jobs")
                    .join(job.digest().to_string())
            });
            job.save(&directory).await?;
            eprintln!("job: {}", directory.display());
            execute(
                &args.client,
                &context,
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
        result.and(target.close().await)
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
        let request = HttpFetchRequest {
            url: self.url.clone(),
            method: self.method.clone(),
            headers,
            body_base64: STANDARD.encode(body),
            tls: HttpTls {
                roots,
                spki_sha256: self.spki_sha256.clone(),
            },
            credential: None,
            max_response_bytes: self
                .max_response_bytes
                .unwrap_or(hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES),
        };
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
