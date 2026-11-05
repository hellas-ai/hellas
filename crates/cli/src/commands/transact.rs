//! Job folders and helpers share the SDK transaction and its existing journals.
use anyhow::{Context as _, bail, ensure};
use clap::Args;
use hellas_auth::ProducerSigningKey;
use hellas_kernel::Secp256k1Signer;
use hellas_rpc::Assurance;
use hellas_sdk::{
    execution::{Completion, Evidence, ExecutionAttempt, ExecutionTerms, RemoteEvidence},
    job::{Job, JobInput},
    paid_client::{PaidWorkOptions, bind_paid_endpoint, request_paid_quote},
    transact::PurchaseRecovery,
};
use std::{
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

mod client;
mod grant;
mod run;
mod task;
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
    /// Paid work requires it; --offer derives it from the signed offer.
    #[arg(long)]
    provider: Option<Provider>,
    /// Additional direct UDP addresses for the provider.
    #[arg(long = "address", value_delimiter = ',')]
    addresses: Vec<SocketAddr>,
    /// Caller-owned wallet and channel journals (default: beside the identity).
    #[arg(long, value_name = "DIR")]
    state_dir: Option<PathBuf>,
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
    /// Validator WebSocket URL; repeat exactly six times to override the devnet.
    #[arg(long = "validator")]
    validators: Vec<String>,
    /// Independently authenticated chain trust document.
    #[arg(long)]
    trust: Option<PathBuf>,
    /// Genesis document for a custom chain; requires --trust.
    #[arg(long, requires = "trust")]
    genesis: Option<PathBuf>,
    /// Independent Apple App Attest approval directory and policy.
    #[arg(long, requires = "trust_policy")]
    trust_store: Option<PathBuf>,
    #[arg(long, requires = "trust_store")]
    trust_policy: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("execution_target").required(true).multiple(true).args(["provider", "offer"])))]
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
    grant: grant::GrantArgs,
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("execution_target").required(true).multiple(true).args(["provider", "offer"])))]
pub struct FetchArgs {
    url: String,
    #[command(flatten)]
    client: ClientArgs,
    #[command(flatten)]
    grant: grant::GrantArgs,
    #[arg(long, required_unless_present = "offer", conflicts_with = "offer", value_parser = clap::value_parser!(u64).range(1..))]
    payment: Option<u64>,
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
}

pub struct Context {
    pub transport: iroh::SecretKey,
    pub settlement: Secp256k1Signer,
    pub producer: ProducerSigningKey,
    pub owner: hellas_kernel::SoftPasskey,
    pub root: PathBuf,
}

impl Context {
    pub(crate) fn new(
        identity: &crate::identity::LocalIdentity,
        owner: Option<&hellas_kernel::SoftPasskey>,
        path: Option<&Path>,
    ) -> super::CliResult<Self> {
        Ok(Self {
            transport: identity.transport_key.clone(),
            settlement: crate::identity::settlement_signer(identity)?,
            producer: identity.node_key.clone(),
            owner: owner
                .context("requester requires --passkey, --faucet or --faucet-account")?
                .clone(),
            root: crate::identity::funding_root(path)?,
        })
    }
}

impl ClientArgs {
    fn paid_provider(&self) -> super::CliResult<&Provider> {
        self.provider
            .as_ref()
            .context("paid execution requires --provider")
    }

    fn root(&self, context: &Context) -> PathBuf {
        self.state_dir
            .clone()
            .unwrap_or_else(|| context.root.join("client"))
    }
    fn owner(
        &self,
        context: &Context,
    ) -> super::CliResult<Arc<hellas_sdk::client_owner::ClientOwner>> {
        Ok(Arc::new(hellas_sdk::client_owner::ClientOwner::new(
            Arc::new(context.owner.clone()),
            context.settlement.party_key(),
            &self.root(context),
        )?))
    }
    async fn purchase(
        &self,
        context: &Context,
        job: &Job,
        options: &PaidWorkOptions,
    ) -> super::CliResult<ExecutionAttempt> {
        let owner = self.owner(context)?;
        let path = self
            .root(context)
            .join("purchases")
            .join(
                hellas_auth::hash_tuple(
                    "hellas.job.chain.v1",
                    &[
                        options.config.chain.network.as_str().as_bytes(),
                        options.config.chain.genesis_payload_digest.as_bytes(),
                    ],
                )
                .to_string(),
            )
            .join(options.provider.to_string())
            .join(hex::encode(owner.principal().as_bytes()))
            .join(format!("{}.json", job.digest()));
        if let Some(attempt) = select_attempt(&path, job, self.buy_again)? {
            return Ok(attempt);
        }
        let mut legacy = PurchaseRecovery::open(&path, job.digest(), job.price())?;
        let status = legacy.reconcile(options).await?;
        bail!("existing purchase is {status:?}; use --buy-again to create a new attempt");
    }

    /// One directory of channel journals per provider address.
    fn journals(&self, root: &Path) -> super::CliResult<PathBuf> {
        Ok(root
            .join("channels")
            .join(self.paid_provider()?.address.to_string()))
    }

    async fn options(
        &self,
        context: &Context,
        price: u64,
        assurance: Assurance,
    ) -> super::CliResult<PaidWorkOptions> {
        ensure!(
            price > 0,
            "paid execution requires a positive job payment; select --offer for grant work"
        );
        self.paid_provider()?;
        let root = self.root(context);
        let config = client::config(self, &root).await?;
        self.options_with_config(context, price, assurance, config)
    }

    fn options_with_config(
        &self,
        context: &Context,
        price: u64,
        assurance: Assurance,
        config: hellas_sdk::work_config::WorkConfig,
    ) -> super::CliResult<PaidWorkOptions> {
        let provider = self.paid_provider()?;
        let root = self.root(context);
        let apple_trust = match (&self.trust_store, &self.trust_policy, assurance) {
            (Some(directory), Some(id), _) => Some(
                hellas_sdk::trust_policy::TrustPolicyStore::new(directory).resolve(
                    id,
                    assurance,
                    crate::identity::assertion_counters()?,
                )?,
            ),
            (None, None, Assurance::ProducerSigned) => None,
            _ => bail!("Apple providers require --trust-store and --trust-policy"),
        };
        Ok(PaidWorkOptions {
            journal_root: self.journals(&root)?,
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
    path: &Path,
    job: &Job,
    buy_again: bool,
) -> super::CliResult<Option<ExecutionAttempt>> {
    let parent = path.parent().context("purchase directory is missing")?;
    hellas_private::create_dir_all_durable(parent)?;
    let pointer = path.with_extension("latest");
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
    let terms = ExecutionTerms::Paid { price: job.price() };
    if !buy_again && let Some(id) = existing {
        let id = std::str::from_utf8(&id)?;
        ensure!(
            id.len() == 32
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "invalid purchase attempt pointer"
        );
        let attempt_path = parent.join(format!("{}.{}.json", job.digest(), id));
        return Ok(Some(ExecutionAttempt::open_existing(
            &attempt_path,
            job.input(),
            terms,
        )?));
    }
    if !buy_again && path.try_exists()? {
        return Ok(None);
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
    let id = hex::encode(rand::random::<[u8; 16]>());
    let attempt_path = parent.join(format!("{}.{}.json", job.digest(), id));
    ensure!(
        !attempt_path.try_exists()?,
        "purchase attempt identity already exists"
    );
    let attempt = ExecutionAttempt::open(&attempt_path, job.input(), terms)?;
    hellas_private::write_atomically(&pointer, ".writing", id.as_bytes())?;
    Ok(Some(attempt))
}

/// Bound `work` by `--timeout`; without one, wait until it is done.
async fn bounded<T>(
    timeout: Option<Duration>,
    work: impl std::future::Future<Output = super::CliResult<T>>,
    expired: impl FnOnce(Duration) -> String,
) -> super::CliResult<T> {
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| anyhow::anyhow!(expired(timeout)))?,
        None => work.await,
    }
}

pub async fn run(args: TransactArgs, context: Context) -> super::CliResult<()> {
    let job = args.job.as_deref().map(Job::load).transpose()?;
    bounded(args.client.timeout, async {
        let Some(job) = job else { return client::settle(&args.client, &context).await; };
        let mut completion = task::remote(&args.client, &args.grant, &context, &job).await?;
        if let Some(directory) = args.output {
            save_outputs(&directory, &job, &completion)?;
        } else if matches!(job.input(), JobInput::Fetch { contract, .. } if contract.schema() == hellas_rpc::FetchSchema::HttpV1) {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            println!("output-0000 (base64): {}", STANDARD.encode(http_body(&job, &completion)?));
        } else {
            let output = match &completion.evidence {
                Evidence::Remote(evidence) if matches!(evidence.terms, ExecutionTerms::Paid { .. }) =>
                    serde_json::to_string(&hellas_channel::model::work::decode_transcript(&evidence.transcript, evidence.transcript.len())?)?,
                _ => serde_json::to_string(&completion.output)?,
            };
            println!("output: {output}");
        }
        ensure_succeeded(&completion)?;
        println!("{}", wording(&job, &completion.evidence));
        std::io::stdout().lock().flush()?;
        task::deliver_and_settle(&mut completion).await?;
        Ok(())
    }, |timeout| format!("transaction exceeded {timeout:?}; use the same folder to recover its existing attempt")).await
}

pub async fn fetch(args: FetchArgs, context: Context) -> super::CliResult<()> {
    let request = args.request()?;
    let contract = args.contract()?;
    bounded(args.client.timeout, async {
        let (job, executor) = if args.grant.offer.is_some() {
            let options = args.grant.options(&args.client, &context, args.assurance())?;
            let policy = &args.grant.policy(&options)?.invocation_policy;
            let job = args.job(request, contract, policy, &context)?;
            let executor = args.grant.executor(&args.client, &context, &job, options).await?;
            (job, executor)
        } else {
            let options = args.client.options(&context, args.payment.unwrap(), args.assurance()).await?;
            let endpoint = bind_paid_endpoint(context.transport.clone()).await?;
            let quote = request_paid_quote(&options, &endpoint, &context.settlement,
                args.client.owner(&context)?.principal()).await?;
            let job = args.job(request, contract, &quote.policy.invocation_policy, &context)?;
            let executor = args.client.executor(&context, &job, options, endpoint).await?;
            (job, executor)
        };
        let mut completion = task::execute(executor, &job).await?;
        let body = http_body(&job, &completion)?;
        if let Some(path) = &args.output {
            write(path, &body)?;
        } else {
            std::io::stdout().lock().write_all(&body)?;
        }
        eprintln!("{}", wording(&job, &completion.evidence));
        std::io::stdout().lock().flush()?;
        std::io::stderr().lock().flush()?;
        task::deliver_and_settle(&mut completion).await?;
        Ok(())
    }, |timeout| format!("Fetch exceeded {timeout:?}; recover the existing attempt with transact --job and the saved folder")).await
}

impl FetchArgs {
    fn job(
        &self,
        mut request: hellas_rpc::http_fetch::HttpFetchRequest,
        contract: hellas_rpc::FetchContract,
        policy: &hellas_rpc::protocol::invocation::InvocationPolicy,
        context: &Context,
    ) -> super::CliResult<Job> {
        let admission = policy
            .admissions
            .iter()
            .find_map(|admission| match admission {
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
        if self.max_response_bytes.is_none() {
            request.max_response_bytes = (policy.limits.max_output_bytes / 4 * 3)
                .min(u64::from(hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES))
                as u32;
        }
        let job = Job::fetch(
            self.payment.unwrap_or(0),
            contract,
            service,
            method,
            serde_json::to_vec(&request)?,
            self.assurance(),
        )?;
        let directory = self.save_job.clone().unwrap_or_else(|| {
            self.client
                .root(context)
                .join("jobs")
                .join(job.digest().to_string())
        });
        job.save(&directory)?;
        eprintln!("job: {}", directory.display());
        Ok(job)
    }

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

fn http_body(job: &Job, completion: &Completion) -> super::CliResult<Vec<u8>> {
    let Evidence::Remote(evidence) = &completion.evidence else {
        bail!("HTTPS Fetch requires remote evidence");
    };
    decode_http_body(job, &completion.output, &evidence.provider_key)
}

fn decode_http_body(
    job: &Job,
    output: &hellas_rpc::protocol::invocation::output::InvocationOutput,
    provider_key: &hellas_auth::PublicKey,
) -> super::CliResult<Vec<u8>> {
    let JobInput::Fetch {
        contract, request, ..
    } = job.input()
    else {
        bail!("not an HTTPS Fetch job");
    };
    ensure!(
        contract.schema() == hellas_rpc::FetchSchema::HttpV1,
        "not an HTTPS Fetch contract"
    );
    let request = hellas_rpc::http_fetch::HttpFetchRequest::decode(request)?;
    let output = hellas_rpc::protocol::invocation::fetch::decode_output(output, provider_key)?;
    Ok(hellas_rpc::http_fetch::HttpFetchResponse::from_output(&request, &output)?.body)
}

fn save_outputs(directory: &Path, job: &Job, completion: &Completion) -> super::CliResult<()> {
    hellas_private::create_dir_all_durable(directory)?;
    let metadata = match &completion.evidence {
        Evidence::Local => {
            serde_json::json!({"job": job.digest().to_string(), "execution": "local", "outcome": completion.output.outcome})
        }
        Evidence::Remote(evidence) => {
            let RemoteEvidence {
                terms,
                provider,
                channel,
                work,
                transcript,
                ..
            } = evidence.as_ref();
            write(&directory.join("transcript.cbor"), transcript)?;
            match terms {
                ExecutionTerms::Grant { resource } => serde_json::json!({
                    "job": job.digest().to_string(), "provider": provider.to_string(),
                    "funding": "grant", "resource": resource.to_string(),
                    "work": work.to_string(), "outcome": completion.output.outcome,
                }),
                ExecutionTerms::Paid { price } => serde_json::json!({
                    "job": job.digest().to_string(), "work": work.to_string(),
                    "channel": channel.to_string(), "paid": price,
                }),
            }
        }
    };
    write(
        &directory.join("result.json"),
        &serde_json::to_vec_pretty(&metadata)?,
    )?;
    if matches!(job.input(), JobInput::Fetch { contract, .. } if contract.schema() == hellas_rpc::FetchSchema::HttpV1)
    {
        write(&directory.join("output-0000"), &http_body(job, completion)?)?;
    } else {
        for (index, artifact) in completion.output.artifacts.iter().enumerate() {
            write(
                &directory.join(format!("output-{index:04}")),
                artifact.bytes.as_bytes(),
            )?;
        }
        write(
            &directory.join("output.json"),
            &serde_json::to_vec_pretty(&completion.output)?,
        )?;
    }
    Ok(())
}

fn ensure_succeeded(completion: &Completion) -> super::CliResult<()> {
    if let hellas_rpc::protocol::invocation::output::Outcome::Failed(reason) =
        &completion.output.outcome
    {
        bail!("work failed: {reason:?}");
    }
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> super::CliResult<()> {
    hellas_private::write_atomically(path, ".writing", bytes)?;
    Ok(())
}

fn wording(job: &Job, evidence: &Evidence) -> String {
    let Evidence::Remote(evidence) = evidence else {
        return "executed locally".into();
    };
    let RemoteEvidence {
        terms,
        provider,
        channel,
        work,
        settled_provider_payout,
        ..
    } = evidence.as_ref();
    match terms {
        ExecutionTerms::Grant { .. } => format!("grant work {work} completed on {provider}"),
        ExecutionTerms::Paid { price } => format!(
            "signed by provider {} and matches this job {} (evaluator {}, adaptor {})\nHellas did not re-run this job. The signature shows who answered, not that the answer is right.\npaid {} · work {} · channel {} ({})",
            provider,
            job.digest(),
            job.manifest().application().evaluator(),
            job.manifest().application().adaptor(),
            price,
            work,
            channel,
            if settled_provider_payout.is_some() {
                "settled".into()
            } else {
                format!("open; `hellas transact --settle --provider {provider}` closes it")
            }
        ),
    }
}
