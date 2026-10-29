//! Job folders and helpers share the SDK transaction and its existing journals.
use anyhow::{Context as _, bail, ensure};
use clap::Args;
use hellas_auth::ProducerSigningKey;
use hellas_kernel::Secp256k1Signer;
use hellas_rpc::Assurance;
use hellas_sdk::{
    job::{Job, JobInput},
    paid_client::{
        PaidWorkOptions, PaidWorkResult, PaidWorkSession, bind_paid_endpoint, request_paid_quote,
    },
    transact::{Purchase, TransactionOptions, transact},
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

fn duration(value: &str) -> Result<Duration, String> {
    let (digits, scale) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1000)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60_000)
    } else {
        return Err("timeout needs a unit: ms, s or m".into());
    };
    let millis = digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(scale))
        .filter(|n| *n > 0)
        .ok_or("timeout must be positive and bounded")?;
    Ok(Duration::from_millis(millis))
}

#[derive(Clone, Debug, Args)]
pub struct ClientArgs {
    /// Provider address ENROLLMENT_ID@NODE_ID, as `hellas serve` prints it,
    /// optionally followed by @IP:PORT.
    #[arg(long)]
    provider: Provider,
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
pub struct TransactArgs {
    #[command(flatten)]
    client: ClientArgs,
    /// Unsigned hellas.job.v1 folder. Omit only with --settle.
    #[arg(long, required_unless_present = "settle", value_name = "DIR")]
    job: Option<PathBuf>,
    /// Write the signed transcript and decoded outputs to this directory.
    #[arg(short = 'o', long = "output", requires = "job", value_name = "DIR")]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct FetchArgs {
    url: String,
    #[command(flatten)]
    client: ClientArgs,
    #[arg(long)]
    payment: u64,
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
    ) -> super::CliResult<Purchase> {
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
            .join(self.provider.address.to_string())
            .join(hex::encode(owner.principal().as_bytes()))
            .join(format!("{}.json", job.digest()));
        let mut purchase = Purchase::open(&path, job, self.buy_again)?;
        purchase.reconcile(options).await?;
        Ok(purchase)
    }

    /// One directory of channel journals per provider address.
    fn journals(&self, root: &Path) -> PathBuf {
        root.join("channels")
            .join(self.provider.address.to_string())
    }

    async fn options(
        &self,
        context: &Context,
        price: u64,
        assurance: Assurance,
    ) -> super::CliResult<PaidWorkOptions> {
        let root = self.root(context);
        let config = client::config(self, &root).await?;
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
            journal_root: self.journals(&root),
            config,
            provider: self.provider.address,
            provider_addrs: self
                .provider
                .addresses
                .iter()
                .chain(&self.addresses)
                .copied()
                .collect(),
            assurance,
            apple_trust,
            expected_price: price,
            acceptance_blocks: 16,
            terminal_blocks: 64,
            payment_blocks: 32,
            timeout: self.timeout,
        })
    }
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

async fn execute(
    args: &ClientArgs,
    context: &Context,
    job: &Job,
    options: PaidWorkOptions,
    endpoint: iroh::Endpoint,
    purchase: &mut Purchase,
) -> super::CliResult<PaidWorkResult> {
    let owner = args.owner(context)?;
    let mut session = if purchase.is_pending() {
        PaidWorkSession::open_retained(options, endpoint, context.settlement.clone(), owner).await?
    } else {
        PaidWorkSession::open_for_job(options, endpoint, context.settlement.clone(), owner, job)
            .await?
    };
    let result = transact(
        &mut session,
        job,
        &context.producer,
        TransactionOptions {
            settle: args.settle,
            purchase: Some(purchase),
            ..Default::default()
        },
    )
    .await;
    session.shutdown().await;
    Ok(result?)
}

async fn purchase_and_execute(
    args: &ClientArgs,
    context: &Context,
    job: &Job,
) -> super::CliResult<(Purchase, PaidWorkResult)> {
    let options = args.options(context, job.price(), job.assurance()).await?;
    let mut purchase = args.purchase(context, job, &options).await?;
    let endpoint = bind_paid_endpoint(context.transport.clone()).await?;
    let result = execute(args, context, job, options, endpoint.clone(), &mut purchase).await;
    endpoint.close().await;
    Ok((purchase, result?))
}

pub async fn run(args: TransactArgs, context: Context) -> super::CliResult<()> {
    // Load every input before network activity or an owner approval.
    let job = args.job.as_deref().map(Job::load).transpose()?;
    bounded(args.client.timeout, async {
        let Some(job) = job else { return client::settle(&args.client, &context).await; };
        let (mut purchase, result) = purchase_and_execute(&args.client, &context, &job).await?;
        if let Some(directory) = args.output { save_outputs(&directory, &job, &result)?; }
        else if matches!(job.input(), JobInput::Fetch { contract, .. } if contract.schema() == hellas_rpc::FetchSchema::HttpV1) {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            println!("output-0000 (base64): {}", STANDARD.encode(http_body(&job, &result)?));
        } else {
            println!("output: {}", serde_json::to_string(&hellas_channel::model::work::decode_transcript(&result.transcript, result.transcript.len())?)?);
        }
        println!("{}", wording(&args.client.provider, &job, &result));
        std::io::stdout().lock().flush()?;
        purchase.reported()?;
        Ok(())
    }, |timeout| format!("transaction exceeded {timeout:?}; retry the same folder to resume its unpaid work")).await
}

pub async fn fetch(args: FetchArgs, context: Context) -> super::CliResult<()> {
    let mut request = args.request()?;
    let contract = args.contract()?;
    ensure!(args.payment > 0, "--payment must be positive");
    bounded(
        args.client.timeout,
        async {
            let options = args
                .client
                .options(&context, args.payment, args.assurance())
                .await?;
            let endpoint = bind_paid_endpoint(context.transport.clone()).await?;
            let result = async {
                let quote = request_paid_quote(
                    &options,
                    &endpoint,
                    &context.settlement,
                    args.client.owner(&context)?.principal(),
                )
                .await?;
                let admission = quote
                    .policy
                    .invocation_policy
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
                let route = &admission.route;
                let (service, method) = match route {
                    hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy::OpenFetch {
                        ..
                    } => ("http".into(), "request".into()),
                    hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy::SealedRoute {
                        service,
                        method,
                    } => (service.clone(), method.clone()),
                };
                if args.max_response_bytes.is_none() {
                    request.max_response_bytes =
                        (quote.policy.invocation_policy.limits.max_output_bytes / 4 * 3)
                            .min(u64::from(hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES))
                            as u32;
                }
                let job = Job::fetch(
                    args.payment,
                    contract.clone(),
                    service,
                    method,
                    serde_json::to_vec(&request)?,
                    args.assurance(),
                )?;
                let directory = args.save_job.clone().unwrap_or_else(|| {
                    args.client
                        .root(&context)
                        .join("jobs")
                        .join(job.digest().to_string())
                });
                job.save(&directory)?;
                eprintln!("job: {}", directory.display());
                let mut purchase = args.client.purchase(&context, &job, &options).await?;
                let result = execute(
                    &args.client,
                    &context,
                    &job,
                    options,
                    endpoint.clone(),
                    &mut purchase,
                )
                .await?;
                let body = http_body(&job, &result)?;
                if let Some(path) = &args.output {
                    write(path, &body)?;
                } else {
                    std::io::stdout().lock().write_all(&body)?;
                }
                eprintln!("{}", wording(&args.client.provider, &job, &result));
                std::io::stdout().lock().flush()?;
                std::io::stderr().lock().flush()?;
                purchase.reported()?;
                Ok(())
            }
            .await;
            endpoint.close().await;
            result
        },
        |timeout| {
            format!("Fetch exceeded {timeout:?}; resume with transact --job and the saved folder")
        },
    )
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

fn http_body(job: &Job, result: &PaidWorkResult) -> super::CliResult<Vec<u8>> {
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
    let output = hellas_rpc::protocol::invocation::fetch::decode_output(
        &result.output,
        &result.provider_key,
    )?;
    Ok(hellas_rpc::http_fetch::HttpFetchResponse::from_output(&request, &output)?.body)
}

fn save_outputs(directory: &Path, job: &Job, result: &PaidWorkResult) -> super::CliResult<()> {
    hellas_private::create_dir_all_durable(directory)?;
    write(&directory.join("transcript.cbor"), &result.transcript)?;
    write(
        &directory.join("result.json"),
        &serde_json::to_vec_pretty(
            &serde_json::json!({"job": job.digest().to_string(), "work": result.work_id.to_string(), "channel": result.channel_id.to_string(), "paid": result.job_price, "settled": result.settled_provider_payout.is_some()}),
        )?,
    )?;
    if matches!(job.input(), JobInput::Fetch { contract, .. } if contract.schema() == hellas_rpc::FetchSchema::HttpV1)
    {
        write(&directory.join("output-0000"), &http_body(job, result)?)?;
    } else {
        for (index, artifact) in result.output.artifacts.iter().enumerate() {
            write(
                &directory.join(format!("output-{index:04}")),
                artifact.bytes.as_bytes(),
            )?;
        }
        write(
            &directory.join("output.json"),
            &serde_json::to_vec_pretty(&result.output)?,
        )?;
    }
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> super::CliResult<()> {
    hellas_private::write_atomically(path, ".writing", bytes)?;
    Ok(())
}

fn wording(provider: &Provider, job: &Job, result: &PaidWorkResult) -> String {
    format!(
        "signed by provider {} and matches this job {} (evaluator {}, adaptor {})\nHellas did not re-run this job. The signature shows who answered, not that the answer is right.\npaid {} · work {} · channel {} ({})",
        provider.address,
        job.digest(),
        job.manifest().application().evaluator(),
        job.manifest().application().adaptor(),
        result.job_price,
        result.work_id,
        result.channel_id,
        if result.settled_provider_payout.is_some() {
            "settled".to_owned()
        } else {
            format!(
                "open; `hellas transact --settle --provider {}` closes it",
                provider.address
            )
        }
    )
}
