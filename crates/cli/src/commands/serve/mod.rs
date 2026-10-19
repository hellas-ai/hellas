use crate::commands::CliResult;
use anyhow::{Context, bail};
use hellas_auth::ProducerSigningKey;
use hellas_executor::{
    ExecutorMetrics, ExecutorSpawnConfig, FetchRoute, FetchRouteEntry, FetchRoutePolicy,
    FetchRouteRegistry,
};
use hellas_kernel::Secp256k1Signer;
use hellas_rpc::Assurance;
use iroh::SecretKey;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

mod codex_provider;
pub mod provision;
pub mod work_config;

pub use provision::{ProvisionOptions, run_provision};
pub use work_config::{WorkConfig, load_work_config};

pub struct ServeOptions {
    pub grants: Option<hellas_sdk::grant_config::GrantConfig>,
    pub port: Option<u16>,
    pub discovery: bool,
    pub queue_size: usize,
    #[cfg(feature = "evaluate")]
    pub evaluation: crate::evaluate::ServeArgs,
    /// The loaded paid-work configuration, not the path it came from.
    /// Its presence is still what serves the two work ALPNs; what is new
    /// is that the node holds the chain cross-check, the validator
    /// fan-out, the journal root, and the policies it would mount a
    /// channel with.
    pub work_config: Option<WorkConfig>,
    pub chain_node: super::chain_node::ChainNodeArgs,
    pub metrics_port: Option<u16>,
    pub graffiti: String,
    pub fetch_config_file: Option<PathBuf>,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_size: usize,
    pub secret_key: SecretKey,
    pub producer_key: ProducerSigningKey,
    /// The settlement key both paid endpoints are built over, read from
    /// the stored identity before this node binds anything.
    ///
    /// A `SetupEndpoint` and a `CloseEndpoint` each take one of these
    /// and a journal, and neither the transport key nor the producer key
    /// above is one — so without it a node that had loaded its whole
    /// paid-work configuration still had nothing to sign a settlement
    /// with.
    pub settlement_key: Secp256k1Signer,
    pub open_identity: Arc<hellas_sdk::ProviderOpen<hellas_auth::ProducerSigningKey>>,
    pub assurance: Assurance,
}

pub fn validate_grant_resources(
    config: &hellas_sdk::grant_config::GrantConfig,
    routes: &FetchRouteRegistry,
) -> CliResult<()> {
    provider_resources(routes).validate(&config.resources)?;
    Ok(())
}

fn provider_resources(
    routes: &FetchRouteRegistry,
) -> hellas_sdk::grant_provider::ProviderResources<'_> {
    #[cfg(feature = "evaluate")]
    {
        hellas_sdk::grant_provider::ProviderResources::EvaluateAndFetch(routes)
    }
    #[cfg(not(feature = "evaluate"))]
    {
        hellas_sdk::grant_provider::ProviderResources::Fetch(routes)
    }
}

pub fn validate_provider_config(
    fetch: Option<&std::path::Path>,
    grant: Option<&std::path::Path>,
) -> CliResult<()> {
    anyhow::ensure!(
        fetch.is_some() || grant.is_some(),
        "--check-config requires --fetch-config or --grant-config"
    );
    let routes = fetch
        .map(load_fetch_config)
        .transpose()?
        .unwrap_or_default();
    if let Some(path) = grant {
        let config =
            hellas_sdk::grant_config::GrantConfig::load(path, Some(&std::env::current_dir()?))?;
        validate_grant_resources(&config, &routes)?;
    }
    Ok(())
}

pub async fn run(options: ServeOptions) -> CliResult<()> {
    let fetch_routes = match options.fetch_config_file.as_deref() {
        // The config file is the single source of fetch truth: routes,
        // capabilities, cross-validated at load. No file
        // means this node serves no Fetch routes. Work authorizes every execution.
        Some(path) => load_fetch_config(path)?,
        None => FetchRouteRegistry::default(),
    };
    // Counters live in the executor and are mutated inline; cloning the
    // counter handles into a registry just adds a scrape view on the same
    // underlying state.
    let metrics = Arc::new(ExecutorMetrics::default());
    let mut executor = ExecutorSpawnConfig::fetch_only(
        Arc::new(options.producer_key),
        options.assurance,
        fetch_routes,
    );
    executor.queue_capacity = options.queue_size;
    executor.metrics = metrics.clone();
    executor.fetch_max_in_flight = options.fetch_max_in_flight;
    executor.fetch_queue_capacity = options.fetch_queue_size;
    #[cfg(feature = "evaluate")]
    options.evaluation.configure(&mut executor)?;

    // What the operator configured, said back once. A node with a
    // paid-work configuration serves its journals, answers every
    // contest, and countersigns new paid channels over the policy that
    // configuration makes. There is no second gate in front of that.
    let mut work_runner = None;
    if let Some(work) = options.work_config.as_ref() {
        // A configured route is a promise about durable state, so verify all
        // of them before the endpoint binds or advertises WorkSetup. This is
        // intentionally later than parsing: provisioning shares the parser
        // and is the command that may create the journal named here.
        work_config::validate_work_routes(work).await?;
        info!(
            network = %work.chain.network,
            validators = work.validators.len(),
            journal_root = %work.journal_root.display(),
            routes = work.routes.len(),
            poll_ms = work.poll.as_millis(),
            min_omit_response_blocks = work.min_omit_response_blocks,
            // Said back because it is the party the chain will see: an
            // operator who funded a different one has configured a node
            // that can settle nothing, and this is where they find out.
            settlement_party = %hex::encode(options.settlement_key.party_key().to_bytes()),
            "loaded the paid-work configuration; paid admission is on",
        );
        let chain = options.chain_node.start(work).await?;
        work_runner = Some((
            hellas_sdk::paid_provider::WorkRunnerConfig {
                network: work.chain.network,
                journal_root: work.journal_root.clone(),
                routes: work.routes.clone(),
                poll: work.poll,
                max_observation_age: work.max_observation_age,
                settlement_key: options.settlement_key.clone(),
                policy: work.provider_policy(),
            },
            chain,
        ));
    }

    let build = option_env!("GIT_REV").unwrap_or("unknown").to_string();
    let graffiti = {
        let mut buf = [0u8; 16];
        let src = options.graffiti.as_bytes();
        let len = src.len().min(16);
        buf[..len].copy_from_slice(&src[..len]);
        buf.to_vec()
    };
    // Install signal handlers before publishing a ready local control socket.
    let shutdown = shutdown_signal().context("failed to listen for shutdown signal")?;
    let chain = work_runner.as_ref().map(|(_, chain)| chain.clone());
    let node_id = options.secret_key.public();
    let node = hellas_sdk::node_control::host::HostHandle::serve(
        hellas_sdk::ProviderOptions {
            port: options.port,
            executor,
            build,
            graffiti,
            work: work_runner,
            grants: None,
            discovery: options.discovery,
            secret_key: options.secret_key,
            open_identity: options.open_identity,
        },
        options.grants,
    )
    .await
    .context("failed to start node server")?;

    if let Some(metrics_port) = options.metrics_port {
        let mut registry = prometheus_client::registry::Registry::default();
        metrics.register_with(&mut registry);
        let bundle = crate::metrics::MetricsBundle::new(Arc::new(registry));
        #[cfg(feature = "otel")]
        let bundle = bundle.with_iroh(node.provider_endpoint());
        crate::metrics::spawn_metrics_server(metrics_port, bundle);
    }

    let add_url = format!("https://explorer.hellas.ai/executors/add/{node_id}");

    eprintln!("Node ID:      {node_id}");
    print_qr(&add_url);
    eprintln!("Explorer:     {add_url}");

    println!("RPC server running. Press Ctrl+C to stop.");
    shutdown.await?;

    println!("Shutting down...");
    // Return failures through the CLI so its telemetry guard still flushes.
    let mut result = node.shutdown().await.map_err(anyhow::Error::from);
    if let Some(chain) = chain {
        result = result.and(chain.shutdown().await.map_err(anyhow::Error::from));
    }
    result.context("failed to drain and shut down RPC server")?;

    Ok(())
}

fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = std::io::Result<()>>> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        Ok(async move {
            tokio::select! {
                _ = interrupt.recv() => Ok(()),
                _ = terminate.recv() => Ok(()),
            }
        })
    }
    #[cfg(not(unix))]
    Ok(tokio::signal::ctrl_c())
}

fn load_fetch_config(path: &std::path::Path) -> CliResult<FetchRouteRegistry> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file: FetchConfigFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let mut registry = FetchRouteRegistry::new();
    for route in file.routes {
        if route.service.trim().is_empty() || route.method.trim().is_empty() {
            bail!("fetch config route service and method must be non-empty");
        }
        let entry = route
            .destination
            .into_entry(route.capabilities.into_policy()?)?;
        info!(
            service = %route.service,
            method = %route.method,
            execution_environment = %entry.execution_environment(),
            "loaded sealed Fetch route",
        );
        registry
            .register(FetchRoute::new(route.service, route.method), entry)
            .map_err(|err| anyhow::anyhow!("invalid fetch config: {err}"))?;
    }

    Ok(registry)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchConfigFile {
    #[serde(default)]
    routes: Vec<FetchConfigRoute>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchConfigRoute {
    service: String,
    method: String,
    /// One sealed, compiled destination plus provider-local credentials. This
    /// one selection constructs both the HTTP driver and the projector whose
    /// manifest is quoted; a URL or separate identity cannot be supplied.
    destination: FetchDestination,
    #[serde(default)]
    capabilities: FetchPolicyLimits,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum FetchDestination {
    /// Caller-signed HTTPS URL and TLS settings with operator-owned account aliases.
    Http {
        config: hellas_providers::HttpProviderConfig,
    },
    /// Official Codex Responses, authenticated by the local Codex OAuth store.
    CodexResponses {
        #[serde(default)]
        auth_path: Option<PathBuf>,
    },
}

impl FetchDestination {
    fn into_entry(self, capabilities: FetchRoutePolicy) -> CliResult<FetchRouteEntry> {
        let provider: Arc<dyn hellas_executor::FetchProvider> = match self {
            Self::Http { config } => return Ok(config.into_entry(capabilities)?),
            Self::CodexResponses { auth_path } => Arc::new(
                codex_provider::CodexResponsesFetchProvider::new(auth_path.as_deref())?,
            ),
        };
        let adaptor_factory = Arc::new(hellas_providers::CodexResponsesAdaptorFactory::new()?);
        Ok(FetchRouteEntry::new(
            provider,
            adaptor_factory,
            capabilities,
        )?)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchPolicyLimits {
    #[serde(default)]
    models: Vec<String>,
    #[serde(default, alias = "max_output_units")]
    max_output_tokens: Option<u64>,
}

impl FetchPolicyLimits {
    fn into_policy(self) -> CliResult<FetchRoutePolicy> {
        let allowed_models = if self.models.is_empty() {
            None
        } else {
            let mut models = BTreeSet::new();
            for model in self.models {
                let model = model.trim();
                if model.is_empty() {
                    bail!("fetch config model names must be non-empty");
                }
                models.insert(model.to_string());
            }
            Some(models)
        };
        Ok(FetchRoutePolicy {
            allowed_models,
            max_output_units: self.max_output_tokens,
        })
    }
}

fn print_qr(data: &str) {
    use qrcode::QrCode;
    let Ok(code) = QrCode::new(data.as_bytes()) else {
        return;
    };
    let width = code.width();
    let modules = code.into_colors();
    // Two rows per character using upper/lower half blocks.
    // ██ = both dark, ▀ = top dark, ▄ = bottom dark, ' ' = both light.
    for y in (0..width).step_by(2) {
        eprint!("  ");
        for x in 0..width {
            let top = modules[y * width + x] == qrcode::Color::Dark;
            let bottom = if y + 1 < width {
                modules[(y + 1) * width + x] == qrcode::Color::Dark
            } else {
                false
            };
            eprint!(
                "{}",
                match (top, bottom) {
                    (true, true) => "█",
                    (true, false) => "▀",
                    (false, true) => "▄",
                    (false, false) => " ",
                }
            );
        }
        eprintln!();
    }
}

#[cfg(test)]
mod tests;
