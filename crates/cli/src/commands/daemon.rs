//! Both command forms translate into the SDK's single daemon document.
use anyhow::{Context, Result, ensure};
use hellas_auth::authority::{NodeKey, PrincipalId};
use hellas_authority::authenticator::Authenticator;
use hellas_client::model::ModelSpec;
use hellas_gateway::{Presentation, Route};
use hellas_private::StoreLocation;
use hellas_sdk::daemon::{Core, Options};
use hellas_sdk::daemon_config::{Backend, BackendKind, Document, Listener};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

mod config;

#[derive(clap::Args)]
pub struct ServeArgs {
    /// Keep keys and identity-bound authority state in DIR. Models stay under --home/content.
    #[arg(long, value_name = "DIR")]
    pub secrets_dir: Option<PathBuf>,
    /// Reconcile a TOML daemon configuration and optional owner-approved paid terms.
    #[arg(long = "config", conflicts_with = "port")]
    config_file: Option<PathBuf>,
    #[arg(long)]
    port: Option<u16>,
}

#[derive(clap::Args)]
pub struct GatewayArgs {
    /// TOML routing and listener configuration.
    #[arg(long, conflicts_with_all = ["models", "upstreams", "bind","voices"])]
    pub config: Option<PathBuf>,
    /// Model path or URI, MODEL@CONTACT, or NAME@UPSTREAM. Phonon accepts ,codec=SOURCE,voices=SOURCE after the model selection.
    #[arg(long = "model", required_unless_present = "config")]
    pub models: Vec<String>,
    /// Named voices to serve with a native Phonon model (repeatable).
    #[arg(long = "voice")]
    pub voices: Vec<String>,
    /// NAME=HTTPS_API_URL,key-file=PATH (an OpenAI-compatible service).
    #[arg(long = "upstream")]
    pub upstreams: Vec<String>,
    #[arg(long)]
    pub bind: Option<std::net::SocketAddr>,
    #[arg(long)]
    pub wrap: Option<String>,
    /// Write the gateway bearer atomically to this private file (mode 0600).
    #[arg(long)]
    pub bearer_file: Option<PathBuf>,
    /// Require the bearer even on a loopback bind. A non-loopback bind always
    /// requires it; `--config` listeners set `require_auth` themselves.
    #[arg(long, conflicts_with = "config")]
    pub require_auth: bool,
    #[arg(last = true, allow_hyphen_values = true, requires = "wrap")]
    pub wrap_args: Vec<String>,
}

#[derive(clap::Args)]
pub struct ControlArgs {
    /// Paired node profile; defaults to the only paired node in this home.
    #[arg(long, global = true)]
    pub profile: Option<PathBuf>,
    #[arg(long, global = true)]
    pub control_socket: Option<PathBuf>,
}
#[derive(clap::Subcommand)]
pub enum BackendCommand {
    Add {
        name: String,
        url: String,
        #[arg(long)]
        key_file: PathBuf,
    },
    Rm {
        name: String,
    },
}
#[derive(clap::Subcommand)]
pub enum RouteCommand {
    Add {
        model: String,
    },
    Rm {
        model: String,
    },
    /// Add or move the stateful HTTP listener.
    Listen {
        bind: std::net::SocketAddr,
    },
}

pub enum Edit {
    Configure(PathBuf),
    Backend(BackendCommand),
    Route(RouteCommand),
}

pub struct ModelContext {
    revisions: crate::hub::Revisions,
    voices: Vec<String>,
    pub home: PathBuf,
    pub principal: Option<PrincipalId>,
    pub holder: NodeKey,
    pub content: Option<hellas_store::content::DiskStore>,
}
impl ModelContext {
    pub fn new(
        home: &Path,
        identity: &hellas_sdk::identity::LocalIdentity,
        owner: Option<&dyn Authenticator>,
    ) -> Result<Self> {
        Ok(Self {
            revisions: Default::default(),
            voices: vec![],
            home: home.into(),
            content: None,
            holder: NodeKey::from_public_key(identity.node_key.public_key())?,
            principal: owner
                .map(|owner| {
                    Ok::<_, anyhow::Error>(PrincipalId::from_public_key(
                        hellas_auth::PublicKey::P256(owner.public_key()?.to_compressed()),
                    )?)
                })
                .transpose()?,
        })
    }

    async fn add(&self, document: &mut Document, model: &str) -> Result<()> {
        let (spec, destination) = model_spec(model)?;
        let pinned = self.revisions.pin_spec(&spec).await?;
        let name = pinned
            .model
            .to_str()
            .context("model selection needs UTF-8")?;
        let Some(destination) = destination else {
            let path = model_package(&pinned)?.with_context(|| format!("model package {model}"))?;
            document
                .backends
                .entry("local".into())
                .or_insert_with(|| Backend {
                    max_in_flight: std::num::NonZeroUsize::new(8).unwrap(),
                    kind: BackendKind::Local {
                        evaluator: None,
                        content: vec![],
                    },
                });
            document
                .add_route(package_route(path, "local", &self.voices).await?)
                .map_err(anyhow::Error::from_boxed)?;
            return Ok(());
        };
        if document
            .backends
            .get(destination)
            .is_some_and(|backend| matches!(backend.kind, BackendKind::Fetch { .. }))
        {
            ensure!(
                !pinned.has_companions(),
                "companion sources require a native model"
            );
            return document
                .add_upstream_model(name, destination)
                .map_err(anyhow::Error::from_boxed);
        }
        validate_name(destination)?;
        let path = self.home.join("nodes").join(destination).join("access");
        let bundle = hellas_sdk::access_bundle::AccessBundle::load(
            &path,
            &self
                .principal
                .context("a grant requires the contact's principal key")?,
            &self.holder,
        )?;
        let trust = bundle
            .offers
            .first()
            .filter(|offer| {
                offer.offer().provider.genesis.statement.root_kind
                    == hellas_rpc::RootKind::SecureEnclave
            })
            .map(|_| hellas_sdk::daemon_config::Trust {
                store: self.home.join("trust"),
                policy: destination.into(),
            });
        let package = model_package(&pinned)?;
        let policies = || {
            bundle
                .offers
                .iter()
                .flat_map(|offer| &offer.offer().grant.policies)
        };
        let mut programs = Vec::new();
        if let Some(path) = &package {
            let evaluators = policies()
                .flat_map(|policy| policy.render_evaluators())
                .map(str::to_owned);
            for (evaluator, package) in path.open_many(evaluators, self.content.as_ref()).await? {
                programs.push((evaluator, package.programs()?));
            }
        }
        let mut matches = vec![];
        for policy in policies() {
            if package.is_some() {
                for (evaluator, manifests) in &programs {
                    if !policy.render_evaluators().contains(evaluator.as_str()) {
                        continue;
                    }
                    if manifests
                        .iter()
                        .any(|m| policy.invocation_policy.candidates_for(m).next().is_some())
                    {
                        matches.push((policy, Some(evaluator.clone())));
                    }
                }
            } else if policy
                .responses
                .as_ref()
                .is_some_and(|resource| resource.model == name)
                || policy
                    .https
                    .as_ref()
                    .and_then(|resource| resource.model_policy.as_ref())
                    .is_some_and(|paths| {
                        paths
                            .iter()
                            .any(|path| path.models.iter().any(|model| model == name))
                    })
            {
                matches.push((policy, None));
            }
        }
        ensure!(
            matches.len() == 1,
            "model must match exactly one resource offered by {destination}; remote Compute uses PATH@CONTACT"
        );
        let (policy, evaluator) = matches.pop().unwrap();
        let access =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bundle.encode()?);
        let id = grant_backend(
            document,
            destination,
            policy.resource,
            access,
            evaluator,
            trust,
        );
        if let Some(package) = package {
            document
                .add_route(package_route(package, &id, &self.voices).await?)
                .map_err(anyhow::Error::from_boxed)?;
        } else {
            for route in hellas_sdk::grant_routes(policy, &id, Some(name))? {
                document
                    .add_route(route)
                    .map_err(anyhow::Error::from_boxed)?;
            }
        }
        Ok(())
    }
}

fn grant_backend_id(destination: &str, resource: hellas_auth::authority::ResourceId) -> String {
    hellas_auth::hash_tuple(
        "hellas.gateway.grant-backend.v1",
        &[destination.as_bytes(), resource.to_string().as_bytes()],
    )
    .to_string()
}

fn grant_backend(
    document: &mut Document,
    destination: &str,
    resource: hellas_auth::authority::ResourceId,
    access: String,
    evaluator: Option<String>,
    trust: Option<hellas_sdk::daemon_config::Trust>,
) -> String {
    let id = grant_backend_id(destination, resource);
    let max_in_flight = document
        .backends
        .get(&id)
        .map_or(std::num::NonZeroUsize::new(8).unwrap(), |backend| {
            backend.max_in_flight
        });
    document.backends.insert(
        id.clone(),
        Backend {
            max_in_flight,
            kind: BackendKind::Grant {
                access: Some(access),
                resource: Some(resource),
                evaluator,
                trust,
            },
        },
    );
    id
}

fn split_model(value: &str) -> (&str, Option<&str>) {
    let Some((source, contact)) = value.rsplit_once('@') else {
        return (value, None);
    };
    use hellas_store::content::Locator;
    if value.starts_with("hellas://")
        && matches!(value.parse::<Locator>(), Ok(Locator::Hellas { .. }))
    {
        return (value, None);
    }
    if source.starts_with("hf://")
        && (hellas_store::hf::is_bare_repo(source)
            || contact.contains('/')
            || (value.to_ascii_lowercase().ends_with(".gguf")
                && !source.to_ascii_lowercase().ends_with(".gguf")))
    {
        return (value, None);
    }
    (source, Some(contact))
}

/// The destination belongs to the primary model. Hub refs in companion fields remain intact.
fn model_spec(value: &str) -> Result<(ModelSpec, Option<&str>)> {
    let options = [",codec=", ",voices="]
        .iter()
        .filter_map(|key| value.find(key))
        .min();
    let (root, options) = options.map_or((value, ""), |index| value.split_at(index));
    let (root, destination) = split_model(root);
    let mut spec = ModelSpec::from(PathBuf::from(root));
    for option in options.split(',').skip(1) {
        let (key, value) = option
            .split_once('=')
            .context("model companion must be codec=SOURCE or voices=SOURCE")?;
        let selected = match key {
            "codec" => &mut spec.codec,
            "voices" => &mut spec.voices,
            _ => anyhow::bail!("unknown model companion {key}"),
        };
        ensure!(
            !value.is_empty() && selected.is_none(),
            "model companion {key} must occur once with a source"
        );
        *selected = Some(value.into());
    }
    spec.check_locator()?;
    Ok((spec, destination))
}

fn model_package(spec: &ModelSpec) -> Result<Option<ModelSpec>> {
    let mut spec = spec.clone();
    use hellas_client::model::is_local;
    if is_local(&spec.model) && !spec.model.try_exists()? {
        ensure!(
            !spec.has_companions(),
            "companion sources require a native model"
        );
        return Ok(None);
    }
    for path in spec.paths_mut().filter(|p| is_local(p)) {
        *path = path
            .canonicalize()
            .with_context(|| format!("model file {}", path.display()))?;
    }
    Ok(Some(spec))
}

async fn package_route(package: ModelSpec, backend: &str, voices: &[String]) -> Result<Route> {
    let input = package.model.clone();
    let (modality, model) =
        tokio::task::spawn_blocking(move || hellas_client::model::ModelKind::named(&input))
            .await??;
    Ok(Route {
        backends: vec![backend.into()],
        presentation: match modality {
            hellas_client::model::ModelKind::Speech => Presentation::Speech {
                model,
                target: hellas_gateway::SpeechTarget::Native {
                    package,
                    voices: voices.to_vec(),
                },
            },
            modality => Presentation::Model {
                modality,
                model,
                package,
                max_tokens: 128,
            },
        },
    })
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "name must use 1..64 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit"
    );
    Ok(())
}
fn key(path: &Path) -> Result<String> {
    let path = if let Some(name) = path
        .to_str()
        .and_then(|path| path.strip_prefix("credential:"))
    {
        validate_name(name)?;
        PathBuf::from(
            std::env::var_os("CREDENTIALS_DIRECTORY")
                .context("credential: references require CREDENTIALS_DIRECTORY")?,
        )
        .join(name)
    } else if let Some(suffix) = path.to_str().and_then(|p| p.strip_prefix("~/")) {
        PathBuf::from(std::env::var_os("HOME").context("HOME is unset")?).join(suffix)
    } else {
        path.to_owned()
    };
    let value = hellas_private::read_secret_file(&path, 16 * 1024)?;
    let value = std::str::from_utf8(&value)?.trim();
    ensure!(
        !value.is_empty() && !value.contains(['\r', '\n']),
        "key file must contain one nonempty line"
    );
    Ok(value.into())
}

fn expand_upstream(document: &mut Document, name: &str, url: &str, key_file: &Path) -> Result<()> {
    validate_name(name)?;
    document
        .add_upstream(name, url, Some(key(key_file)?))
        .map_err(anyhow::Error::from_boxed)
}

pub async fn apply(document: &mut Document, edit: Edit, context: &ModelContext) -> Result<()> {
    match edit {
        Edit::Configure(path) => {
            let config = config::Config::load(&path)?;
            ensure!(
                config.paid_policy.is_none(),
                "set paid policy with admin work"
            );
            *document = config.resolve(context).await?.0;
        }
        Edit::Backend(BackendCommand::Add {
            name,
            url,
            key_file,
        }) => {
            expand_upstream(document, &name, &url, &key_file)?;
        }
        Edit::Backend(BackendCommand::Rm { name }) => document
            .remove_backend(&name)
            .map_err(anyhow::Error::from_boxed)?,
        Edit::Route(RouteCommand::Add { model }) => context.add(document, &model).await?,
        Edit::Route(RouteCommand::Listen { bind }) => {
            document
                .listeners
                .insert("api".into(), Listener::http(bind));
        }
        Edit::Route(RouteCommand::Rm { model }) => {
            let (spec, destination) = model_spec(&model)?;
            let pinned = context.revisions.pin_spec(&spec).await?;
            let name = pinned
                .model
                .to_str()
                .context("model selection needs UTF-8")?;
            let package = model_package(&pinned)?;
            let mut removed = false;
            for route in &mut document.routes {
                let matches = match route.model_package() {
                    Some((_, path)) => package.as_ref() == Some(path),
                    None => route
                        .keys()
                        .iter()
                        .any(|(_, _, model)| model.as_deref() == Some(name)),
                };
                if !matches {
                    continue;
                }
                route.backends.retain(|id| {
                    let selected = destination.is_none_or(|destination| id == destination || document.backends.get(id).is_some_and(|backend| matches!(&backend.kind, BackendKind::Grant { resource: Some(resource), .. } if *id == grant_backend_id(destination, *resource))));
                    removed |= selected;
                    !selected
                });
                if let Presentation::Http { targets } = &mut route.presentation {
                    targets.retain(|id, _| route.backends.contains(id));
                }
            }
            ensure!(removed, "route not found");
            document.routes.retain(|route| !route.backends.is_empty());
        }
    }
    // Interactive operator edits expose executable backends on the work listener.
    // Declarative compilation never calls this command-layer attachment step.
    for listener in document.listeners.values_mut() {
        if let Listener::Iroh { backends, .. } = listener {
            *backends = document
                .backends
                .iter()
                .filter_map(|(id, backend)| {
                    matches!(
                        backend.kind,
                        BackendKind::Local { .. } | BackendKind::Fetch { .. }
                    )
                    .then_some(id.clone())
                })
                .collect();
        }
    }
    Ok(())
}

pub fn print(view: &hellas_sdk::daemon::View) {
    println!("MODEL\tMODALITY\tAPI PATH\tBACKEND\tSTATE\tJOBS\tPROVIDER\tSCOPE\tMAX PRICE");
    for route in &view.document.routes {
        let modality = match &route.presentation {
            Presentation::Model { modality, .. } => match modality {
                hellas_client::model::ModelKind::Text => "text",
                hellas_client::model::ModelKind::Decision => "decision",
                hellas_client::model::ModelKind::Transcription => "audio",
                hellas_client::model::ModelKind::Speech => "speech",
                hellas_client::model::ModelKind::Image => "image",
            },
            Presentation::Speech { .. } => "speech",
            _ => "text",
        };
        for (path, method, model) in route.keys() {
            let modality = if path == "/v1/audio/transcriptions" && method == "POST" {
                "audio"
            } else {
                modality
            };
            for id in &route.backends {
                let backend = view.backends.iter().find(|backend| backend.id == *id);
                let state = match backend {
                    None => "Unknown",
                    Some(backend) if backend.down || backend.error.is_some() => "Down",
                    Some(backend) if backend.in_flight >= backend.max_in_flight => "Busy",
                    Some(_) => "Up",
                };
                let jobs = backend.map_or("-".into(), |backend| {
                    format!("{}/{}", backend.in_flight, backend.max_in_flight)
                });
                let kind = view.document.backends.get(id).map(|backend| &backend.kind);
                let (provider, max_price) = match kind {
                    Some(BackendKind::Paid {
                        provider,
                        max_price,
                        ..
                    }) => (
                        provider
                            .parse::<hellas_client::ProviderAddress>()
                            .ok()
                            .map(|id| id.to_string()),
                        Some(max_price.to_string()),
                    ),
                    _ => (None, None),
                };
                let scope = match &route.presentation {
                    Presentation::Responses {
                        service, method, ..
                    }
                    | Presentation::Speech {
                        target:
                            hellas_gateway::SpeechTarget::Hosted {
                                service, method, ..
                            },
                        ..
                    } => Some(format!("{service}/{method}")),
                    Presentation::Http { targets } => targets
                        .get(id)
                        .map(|target| format!("{}/{}", target.service, target.method)),
                    _ => None,
                };
                let resource = match kind {
                    Some(BackendKind::Grant { resource, .. }) => resource.map(|id| id.to_string()),
                    _ => None,
                };
                println!(
                    "{}\t{modality}\t{method} {path}\t{id}\t{state}\t{jobs}\t{}\t{}\t{}",
                    model.as_deref().unwrap_or("*"),
                    provider.as_deref().unwrap_or("-"),
                    resource.or(scope).as_deref().unwrap_or("compute"),
                    max_price.as_deref().unwrap_or("-"),
                );
            }
        }
    }
}

pub async fn control<T>(
    client: &hellas_rpc::services::host_control::HostControlClientImpl<T>,
    authorization: hellas_auth::authority::GrantId,
    edit: Option<Edit>,
    context: ModelContext,
) -> Result<()>
where
    T: hellas_wire::StreamTransport + Send + Sync,
    T::Stream: Send + 'static,
{
    use hellas_rpc::pb::host::ConfigureRequest;
    let view = view(client, authorization).await?;
    let Some(edit) = edit else {
        print(&view);
        return Ok(());
    };
    let mut document = view.document;
    apply(&mut document, edit, &context).await?;
    let result = client
        .configure(ConfigureRequest {
            authorization: authorization.0.to_vec(),
            expected_revision: view.revision.0,
            document: serde_json::to_vec(&document)?,
        })
        .await?;
    println!("Configured revision {}", result.revision);
    Ok(())
}

pub async fn view<T>(
    client: &hellas_rpc::services::host_control::HostControlClientImpl<T>,
    authorization: hellas_auth::authority::GrantId,
) -> Result<hellas_sdk::daemon::View>
where
    T: hellas_wire::StreamTransport + Send + Sync,
    T::Stream: Send + 'static,
{
    use futures::StreamExt;
    use hellas_rpc::pb::host::*;
    let mut watch = client
        .watch(WatchRequest {
            authorization: authorization.0.to_vec(),
        })
        .await?;
    let first = watch
        .next()
        .await
        .context("Watch ended before its snapshot")??;
    let Some(watch_response::Update::Snapshot(bytes)) = first.update else {
        anyhow::bail!("Watch did not start with a snapshot")
    };
    let view: hellas_sdk::daemon::View = serde_json::from_slice(&bytes)?;
    drop(watch);
    Ok(view)
}

async fn options(
    home: StoreLocation,
    content_dir: StoreLocation,
    identity: &hellas_sdk::identity::LocalIdentity,
    owner: Option<&hellas_kernel::SoftPasskey>,
    profile: &hellas_chain::genesis::ChainProfile,
    node: hellas_authority::node::NodeCoordinator,
    endpoint: Option<iroh::Endpoint>,
) -> Result<hellas_sdk::daemon::Options> {
    let settlement = hellas_sdk::identity::settlement_signer(identity)?;
    let content = hellas_store::content::DiskStore::open(
        content_dir,
        vec![],
        hellas_store::content::IndexMode::Resume,
        None,
        hellas_store::content::Reservations::ram(
            hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
        ),
        false,
    )
    .await?;
    Ok(hellas_sdk::daemon::Options {
        discovery: true,
        chain: hellas_chain::chain_dir::ChainDir::open(&home, profile)?,
        home,
        signer: Arc::new(identity.node_key.clone()),
        transport: identity.transport_key.clone(),
        settlement,
        prover: None,
        owner: owner
            .cloned()
            .map(|owner| Arc::new(owner) as Arc<dyn Authenticator>),
        node,
        content,
        endpoint,
        remote_control: Default::default(),
    })
}

pub async fn gateway(
    args: GatewayArgs,
    home: &StoreLocation,
    identity: &hellas_sdk::identity::LocalIdentity,
    owner: Option<&hellas_kernel::SoftPasskey>,
    chain: &hellas_chain::genesis::ChainProfile,
    #[cfg(feature = "otel")] metrics: Option<(std::net::SocketAddr, crate::metrics::MetricsBundle)>,
) -> Result<()> {
    let configured = match args.config {
        Some(path) => config::Config::load(&path)?,
        None => config::Config::gateway(args.models, args.upstreams, args.bind, args.require_auth)?,
    };
    ensure!(
        configured.paid_policy.is_none(),
        "gateway configuration cannot set paid provider policy"
    );
    ensure!(
        configured.document.listeners.len() == 1,
        "gateway requires exactly one HTTP listener"
    );
    let (listener, kind) = configured
        .document
        .listeners
        .iter()
        .next()
        .context("missing HTTP listener")?;
    let Listener::Http { require_auth, .. } = *kind else {
        anyhow::bail!("gateway requires an HTTP listener")
    };
    let listener = listener.clone();
    // Without authentication there is no secret that must reach the operator.
    let mut tty = if require_auth && args.wrap.is_none() && args.bearer_file.is_none() {
        let terminal = if cfg!(windows) { "CONOUT$" } else { "/dev/tty" };
        Some(
            std::fs::OpenOptions::new()
                .write(true)
                .open(terminal)
                .context("gateway needs --wrap, --bearer-file PATH, or a controlling terminal")?,
        )
    } else {
        None
    };
    let mut context = ModelContext::new(
        home,
        identity,
        owner.map(|owner| owner as &dyn Authenticator),
    )?;
    context.voices = args.voices;
    hellas_private::create_dir_all_durable(home)?;
    let temporary = tempfile::Builder::new()
        .prefix(".gateway-")
        .tempdir_in(home)?;
    let ephemeral = hellas_kernel::SoftPasskey::from_secret_scalar(rand::random())
        .map_err(|_| anyhow::anyhow!("invalid ephemeral key"))?;
    let (node, access) =
        super::admin::gateway_authority(&home.child(temporary.path()), identity, &ephemeral)
            .await?;
    let options = options(
        home.clone(),
        home.child("content"),
        identity,
        owner,
        chain,
        node.clone(),
        None,
    )
    .await?;
    context.content = Some(options.content.clone());
    run_daemon(
        options,
        async |options| {
            let (document, _) = configured.resolve(&context).await?;
            Core::open(options, document)
                .await
                .map_err(anyhow::Error::from_boxed)
        },
        #[cfg(feature = "otel")]
        metrics,
        async |core| {
            print(&core.watch().0);
            let address = *core
                .http_addresses()
                .get(&listener)
                .context("gateway HTTP listener is unavailable")?;
            if let Some(path) = args.bearer_file {
                hellas_private::write_secret_file(&path, ".bearer", access.bearer().as_bytes())?;
            }
            // The address goes to stderr once; the bearer goes only to the
            // controlling terminal, never to a redirected stderr or log.
            eprintln!("Gateway: http://{address}");
            if !require_auth {
                eprintln!(
                    "Authorization: not required for loopback callers (--require-auth to enable)"
                );
            }
            if let Some(command) = args.wrap {
                let mut child = crate::wrap::spawn(
                    &command,
                    &args.wrap_args,
                    &format!("http://{address}"),
                    &access.bearer(),
                )?;
                tokio::select! {
                    result = shutdown_signal()? => result?,
                    result = core.wait() => result.map_err(anyhow::Error::from_boxed)?,
                    status = child.wait() => ensure!(status?.success(), "wrapped command failed"),
                }
            } else {
                use std::io::{IsTerminal, Write};
                if let Some(tty) = &mut tty {
                    if !std::io::stderr().is_terminal() {
                        writeln!(tty, "Gateway: http://{address}")?;
                    }
                    writeln!(tty, "Authorization: Bearer {}", access.bearer())?;
                }
                tokio::select! {
                    result = shutdown_signal()? => result?,
                    result = core.wait() => result.map_err(anyhow::Error::from_boxed)?,
                }
            }
            Ok(())
        },
    )
    .await
}

pub async fn serve(
    home: &StoreLocation,
    identity: &hellas_sdk::identity::LocalIdentity,
    owner: Option<&hellas_kernel::SoftPasskey>,
    chain: &hellas_chain::genesis::ChainProfile,
    args: ServeArgs,
    content_dir: StoreLocation,
    #[cfg(feature = "otel")] metrics: Option<(std::net::SocketAddr, crate::metrics::MetricsBundle)>,
) -> Result<()> {
    let ServeArgs {
        port, config_file, ..
    } = args;
    let declarative = config_file.is_some();
    let desired = if let Some(path) = config_file {
        let state = config::Config::load(&path)?;
        let context = ModelContext::new(
            home,
            identity,
            owner.map(|owner| owner as &dyn Authenticator),
        )?;
        Some(state.resolve(&context).await?)
    } else {
        None
    };
    let ownership = hellas_authority::work_store::grant::StartupLock::acquire(
        &home.child("provider/authority"),
    )?;
    let shutdown = shutdown_signal()?;
    tokio::pin!(shutdown);
    let (endpoint, store, declarative_start) = if let Some(state) = desired {
        let (store, credential) = super::bootstrap::prepare_local(
            home,
            identity,
            owner.context("--config requires --passkey")?,
            &ownership,
        )
        .await?;
        let authorization = store.state().authority().root_grant();
        (None, store, Some((state, credential, authorization)))
    } else {
        let (endpoint, store) = tokio::select! {
            result = super::bootstrap::prepare(home, &identity.transport_key, &identity.enrollment, port, &ownership) => result?,
            signal = &mut shutdown => return Ok(signal?),
        };
        (endpoint, store, None)
    };
    let node = hellas_authority::node::NodeCoordinator::new(
        store,
        Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
    );
    let mut options = options(
        home.clone(),
        content_dir,
        identity,
        owner,
        chain,
        node,
        endpoint,
    )
    .await?;
    options.remote_control = hellas_sdk::node_control::RemoteControlAdmission::credential_gated();
    run_daemon(
        options,
        async |options| {
            let core = if let Some(((document, paid_policy), credential, authorization)) =
                declarative_start
            {
                let caller = options
                    .node
                    .authenticate_session(
                        &credential,
                        hellas_authority::node::SessionKey::Passkey(
                            owner.context("--config requires --passkey")?,
                        ),
                    )
                    .await?;
                Core::reconcile(options, document, caller, authorization, paid_policy).await
            } else if options.node.configuration().await?.is_some() {
                Core::restore(options, port).await
            } else {
                let mut document = Document::default();
                document.listeners.insert(
                    "work".into(),
                    Listener::Iroh {
                        chain: None,
                        port: port.unwrap_or(0),
                        backends: vec![],
                    },
                );
                Core::open(options, document).await
            };
            core.map_err(anyhow::Error::from_boxed)
        },
        #[cfg(feature = "otel")]
        metrics,
        async |core| {
            let tls = hellas_sdk::node_control::profile::server_identity(
                &home.join("provider/control.cert.der"),
                &home.join("provider/control.key.der"),
            )?;
            let control = core
                .control()
                .map_err(anyhow::Error::from_boxed)?
                .bind_local(home.join("provider/control.sock"), tls)?;
            eprintln!(
                "Provider: {}",
                hellas_sdk::client::ProviderAddress::of(&identity.enrollment)?
            );
            if declarative {
                eprintln!("Daemon ready; declared configuration reconciled.");
            } else {
                eprintln!("Daemon ready; configure it with hellas backend and hellas route.");
            }
            let signal: Result<()> = tokio::select! {
                result = &mut shutdown => result.map_err(Into::into),
                result = core.wait() => result.map_err(anyhow::Error::from_boxed),
            };
            let stopped = control.shutdown().await;
            signal?;
            stopped?;
            Ok(())
        },
    )
    .await
}

async fn run_daemon(
    options: Options,
    open: impl AsyncFnOnce(Options) -> Result<Arc<Core>>,
    #[cfg(feature = "otel")] metrics: Option<(std::net::SocketAddr, crate::metrics::MetricsBundle)>,
    run: impl AsyncFnOnce(Arc<Core>) -> Result<()>,
) -> Result<()> {
    let content = options.content.clone();
    let node = options.node.clone();
    let serving = async {
        let core = open(options).await?;
        let result = async {
            #[cfg(feature = "otel")]
            if let Some((address, bundle)) = metrics {
                crate::metrics::spawn_metrics_server(address, bundle.with_core(&core)).await?;
            }
            run(core.clone()).await
        }
        .await;
        result.and(core.shutdown().await.map_err(anyhow::Error::from_boxed))
    }
    .await;
    content.close().await;
    node.close().await;
    serving
}

pub fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = std::io::Result<()>>>
{
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        Ok(async move {
            tokio::select! { _ = terminate.recv() => Ok(()), _ = interrupt.recv() => Ok(()) }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(tokio::signal::ctrl_c())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    pub(super) fn model_context(home: &Path) -> ModelContext {
        ModelContext {
            revisions: Default::default(),
            voices: vec![],
            home: home.into(),
            principal: None,
            content: None,
            holder: NodeKey::from_public_key(
                hellas_auth::ProducerSigningKey::from_secret_bytes([1; 32])
                    .unwrap()
                    .public_key(),
            )
            .unwrap(),
        }
    }

    #[tokio::test]
    async fn configuring_from_toml_replaces_the_previous_document() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("daemon.toml");
        std::fs::write(
            &path,
            "[listeners.api]\nkind = 'http'\nbind = '127.0.0.1:8888'\n",
        )?;
        let mut document = Document::default();
        document
            .listeners
            .insert("previous".into(), Listener::http("127.0.0.1:8889".parse()?));
        apply(
            &mut document,
            Edit::Configure(path),
            &model_context(root.path()),
        )
        .await?;
        assert_eq!(document.listeners.keys().collect::<Vec<_>>(), ["api"]);
        Ok(())
    }

    #[test]
    fn gateway_model_companions_keep_their_own_refs_and_primary_destination() {
        let (spec, destination) =
            model_spec("hf://org/model@v2@alice,voices=hf://org/voices@v4,codec=/srv/codec")
                .unwrap();
        assert_eq!(destination, Some("alice"));
        assert_eq!(spec.model, Path::new("hf://org/model@v2"));
        assert_eq!(
            spec.voices.as_deref(),
            Some(Path::new("hf://org/voices@v4"))
        );
        assert_eq!(spec.codec.as_deref(), Some(Path::new("/srv/codec")));
        assert_eq!(
            model_spec("/a/model,with,commas").unwrap().0.model,
            Path::new("/a/model,with,commas")
        );
        for invalid in [
            "local,codec=",
            "local,voices=a,voices=b",
            "local,codec=a,catalog=b",
            "hellas://fixed,codec=a",
        ] {
            assert!(model_spec(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn hub_route_ref_and_contact_are_independent() {
        for uri in [
            "hf://org/repo",
            "hf://org/repo@release",
            "hf://org/repo@release/path/to/model.gguf",
            "hf://org/repo/weights@2.gguf",
        ] {
            assert_eq!(split_model(uri), (uri, None));
        }
        for uri in [
            "hf://org/repo@release",
            "hf://org/repo/path/to/model.gguf",
            "hf://org/repo@release/model@2.gguf",
        ] {
            assert_eq!(split_model(&format!("{uri}@friend")), (uri, Some("friend")));
        }
    }

    #[cfg(target_os = "linux")]
    const WEIGHTS_BYTES: u64 = 32 << 20;

    #[cfg(target_os = "linux")]
    fn isolated(test: &str) -> bool {
        const CHILD: &str = "HELLAS_TEST_WEIGHT_READ_CASE";
        if std::env::var(CHILD).ok().as_deref() == Some(test) {
            return true;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("commands::daemon::tests::{test}"),
                "--nocapture",
            ])
            .env(CHILD, test)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    #[cfg(target_os = "linux")]
    fn full_weights() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("full.gguf");
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../client/src/model/package/mini-qwen3.gguf"),
            &path,
        )
        .unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(WEIGHTS_BYTES)
            .unwrap();
        (root, path)
    }

    #[cfg(target_os = "linux")]
    fn read_bytes() -> u64 {
        std::fs::read_to_string("/proc/self/io")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("rchar: ").map(|n| n.parse().unwrap()))
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn assert_weights_once(before: u64) {
        let bytes = read_bytes() - before;
        assert!(
            (WEIGHTS_BYTES..WEIGHTS_BYTES + (1 << 20)).contains(&bytes),
            "expected one full read of {WEIGHTS_BYTES} weights bytes, observed {bytes}"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn gateway_matching_and_store_preparation_hash_full_weights_once() {
        if !isolated("gateway_matching_and_store_preparation_hash_full_weights_once") {
            return;
        }
        let (root, path) = full_weights();
        let size = WEIGHTS_BYTES;
        let store = hellas_store::content::DiskStore::open(
            hellas_private::StoreLocation::for_test(&root.path().join("content")),
            vec![],
            hellas_store::content::IndexMode::Resume,
            None,
            hellas_store::content::Reservations::ram(
                hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
            ),
            false,
        )
        .await
        .unwrap();
        let mut context = model_context(root.path());
        context.content = Some(store.clone());
        let before = read_bytes();
        let hip = hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip, "gfx1151");
        let cuda =
            hellas_client::model::evaluator(hellas_client::model::GpuDialect::Cuda, "sm_120");
        let packages = ModelSpec::from(path.clone())
            .open_many([hip.clone(), hip, cuda], context.content.as_ref())
            .await
            .unwrap();
        assert_eq!(packages.len(), 2);
        let inspected = store.inspect_files(vec![path.clone()]).await.unwrap();
        assert_eq!(inspected[&path].bytes(), size);
        store
            .rescan(vec![path], hellas_store::content::IndexMode::Resume)
            .await
            .unwrap();
        assert_weights_once(before);
        store.close().await;
    }

    #[cfg(all(target_os = "linux", feature = "compute"))]
    #[tokio::test]
    async fn local_rendering_and_indexing_hash_full_weights_once() {
        if !isolated("local_rendering_and_indexing_hash_full_weights_once") {
            return;
        }
        let (root, path) = full_weights();
        let size = WEIGHTS_BYTES;
        let native = crate::compute::LocalArgs {
            content_config: None,
            content: vec![],
            gpu: crate::compute::GpuArgs {
                evaluator: None,
                gpu_session_programs: 1,
                gpu_session_asset_bytes: size,
            },
        };
        let before = read_bytes();
        let store = crate::compute::content(
            &StoreLocation::for_test(root.path()),
            &native,
            std::slice::from_ref(&path),
            &[],
        )
        .await
        .unwrap();
        let evaluator =
            hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip, "gfx1151");
        let packages = ModelSpec::from(path)
            .open_many([evaluator.clone()], Some(&store))
            .await
            .unwrap();
        packages[&evaluator].programs().unwrap();
        assert_weights_once(before);
        store.close().await;
    }

    #[test]
    fn gateway_peer_address_survives_route_shorthand() {
        let node = iroh::SecretKey::from_bytes(&[3; 32]).public();
        let uri = format!(
            "hellas://{}?seed={node}",
            hellas_rpc::ContentId::hash(b"catalog")
        );
        for source in [uri.clone(), format!("{uri}@127.0.0.1:42")] {
            assert_eq!(split_model(&source), (source.as_str(), None));
            let model = ModelSpec::from(PathBuf::from(&source));
            assert_eq!(model_package(&model).unwrap(), Some(model));
            let grant = format!("{source}@friend");
            assert_eq!(split_model(&grant), (source.as_str(), Some("friend")));
        }
    }

    #[test]
    fn generated_grant_ids_fit_and_repair_refreshes_access() {
        let resource = hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"model"));
        let mut document = Document::default();
        let contact = "a".repeat(64);
        let id = grant_backend(
            &mut document,
            &contact,
            resource,
            "first".into(),
            None,
            None,
        );
        validate_name(&id).unwrap();
        document.backends.get_mut(&id).unwrap().max_in_flight =
            std::num::NonZeroUsize::new(3).unwrap();
        assert_eq!(
            grant_backend(
                &mut document,
                &contact,
                resource,
                "repaired".into(),
                None,
                None
            ),
            id
        );
        assert_eq!(document.backends[&id].max_in_flight.get(), 3);
        assert!(
            matches!(&document.backends[&id].kind, BackendKind::Grant { access: Some(access), .. } if access == "repaired")
        );
        let other = format!("{}b", &contact[..63]);
        assert_ne!(
            grant_backend(&mut document, &other, resource, "other".into(), None, None),
            id
        );
    }

    #[tokio::test]
    async fn remove_grant_route_by_contact_uses_its_generated_id() {
        let directory = tempfile::tempdir().unwrap();
        let context = model_context(directory.path());
        let contact = "a".repeat(64);
        let mut document = Document::default();
        let id = grant_backend(
            &mut document,
            &contact,
            hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"model")),
            "access".into(),
            None,
            None,
        );
        document.routes.push(Route {
            backends: vec![id],
            presentation: Presentation::Responses {
                service: "openai".into(),
                method: "responses".into(),
                models: vec!["model".into()],
                overrides: Default::default(),
            },
        });
        apply(
            &mut document,
            Edit::Route(RouteCommand::Rm {
                model: format!("model@{contact}"),
            }),
            &context,
        )
        .await
        .unwrap();
        assert!(document.routes.is_empty());
    }

    #[test]
    fn the_command_line_is_well_formed() {
        use clap::CommandFactory;
        crate::Cli::command().debug_assert();
    }

    #[test]
    fn command_forms_share_config_and_reject_ambiguous_routing_flags() {
        let parsed = crate::Cli::try_parse_from([
            "hellas",
            "gateway",
            "--model",
            "qwen.gguf",
            "--model",
            "whisper",
            "--model",
            "flux@friend",
            "--upstream",
            "api=https://api.example/v1,key-file=key",
            "--model",
            "gpt@api",
        ])
        .unwrap();
        let crate::Commands::Gateway { args, .. } = parsed.command else {
            unreachable!()
        };
        assert_eq!(args.models.len(), 4);
        for command in ["serve", "gateway"] {
            assert!(crate::Cli::try_parse_from(["hellas", command, "--config", "file"]).is_ok());
        }

        for args in [
            vec![
                "hellas",
                "gateway",
                "--config",
                "file",
                "--model",
                "model.gguf",
            ],
            vec![
                "hellas",
                "gateway",
                "--config",
                "file",
                "--upstream",
                "api=https://api.example/v1,key-file=key",
            ],
            vec![
                "hellas",
                "gateway",
                "--config",
                "file",
                "--bind",
                "127.0.0.1:8080",
            ],
            vec!["hellas", "serve", "--config", "file", "--port", "0"],
        ] {
            assert!(crate::Cli::try_parse_from(args).is_err());
        }
        assert!(
            crate::Cli::try_parse_from([
                "hellas",
                "backend",
                "add",
                "api",
                "https://api.example",
                "--key-file",
                "key"
            ])
            .is_ok()
        );
        assert!(crate::Cli::try_parse_from(["hellas", "route", "add", "model@api"]).is_ok());
        assert!(crate::Cli::try_parse_from(["hellas", "routes"]).is_ok());
    }

    #[tokio::test]
    async fn upstream_edits_share_one_document_with_bounded_resources_and_write_only_keys() {
        let directory = tempfile::tempdir().unwrap();
        let key_file = directory.path().join("key");
        hellas_private::write_secret_file(&key_file, ".key", b"test-secret\n").unwrap();
        let context = model_context(directory.path());
        let mut document = Document::default();
        document.listeners.insert(
            "work".into(),
            Listener::Iroh {
                chain: None,
                port: 0,
                backends: vec![],
            },
        );
        for name in ["first", "second"] {
            apply(
                &mut document,
                Edit::Backend(BackendCommand::Add {
                    name: name.into(),
                    url: format!("https://{name}.example/api"),
                    key_file: key_file.clone(),
                }),
                &context,
            )
            .await
            .unwrap();
            apply(
                &mut document,
                Edit::Route(RouteCommand::Add {
                    model: format!("model@{name}"),
                }),
                &context,
            )
            .await
            .unwrap();
        }
        assert_eq!(document.routes.len(), 3);
        let redacted = serde_json::to_string(&document.redacted().0).unwrap();
        assert!(!redacted.contains("test-secret"));
        let decoded: Document = serde_json::from_str(&redacted).unwrap();
        assert_eq!(decoded.routes[0].backends, ["first", "second"]);
        let Presentation::Http { targets } = &decoded.routes[0].presentation else {
            unreachable!()
        };
        assert_eq!(
            targets["second"].route.url,
            "https://second.example/api/v1/responses"
        );
        apply(
            &mut document,
            Edit::Route(RouteCommand::Add {
                model: "another@first".into(),
            }),
            &context,
        )
        .await
        .unwrap();
        apply(
            &mut document,
            Edit::Backend(BackendCommand::Rm {
                name: "first".into(),
            }),
            &context,
        )
        .await
        .unwrap();
        assert!(
            document
                .routes
                .iter()
                .all(|route| route.backends == ["second"])
        );
        document.validate().unwrap();
        apply(
            &mut document,
            Edit::Backend(BackendCommand::Add {
                name: "first".into(),
                url: "https://changed.example/v1".into(),
                key_file,
            }),
            &context,
        )
        .await
        .unwrap();
        apply(
            &mut document,
            Edit::Route(RouteCommand::Add {
                model: "model@first".into(),
            }),
            &context,
        )
        .await
        .unwrap();
    }
}
