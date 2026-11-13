//! Both command forms translate into the SDK's single daemon document.
use anyhow::{Context, Result, ensure};
use hellas_auth::authority::{NodeKey, PrincipalId};
use hellas_authority::authenticator::Authenticator;
use hellas_gateway::{Presentation, Route};
use hellas_private::StoreLocation;
use hellas_sdk::daemon_config::{Backend, BackendKind, Document, Listener};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(clap::Args)]
pub struct GatewayArgs {
    /// Qwen GGUF, Whisper/Flux package or descriptor; PATH@CONTACT or NAME@UPSTREAM.
    #[arg(long = "model", required = true)]
    pub models: Vec<String>,
    /// NAME=HTTPS_API_URL,key-file=PATH (an OpenAI-compatible service).
    #[arg(long = "upstream")]
    pub upstreams: Vec<String>,
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub bind: std::net::SocketAddr,
    #[arg(long)]
    pub wrap: Option<String>,
    /// Write the gateway bearer atomically to this private file (mode 0600).
    #[arg(long)]
    pub bearer_file: Option<PathBuf>,
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
    Backend(BackendCommand),
    Route(RouteCommand),
}

pub struct ModelContext {
    pub home: PathBuf,
    pub principal: Option<PrincipalId>,
    pub holder: NodeKey,
    pub content: Option<hellas_store::content::DiskStore>,
}
impl ModelContext {
    pub fn new(
        home: &Path,
        identity: &crate::identity::LocalIdentity,
        owner: Option<&dyn Authenticator>,
    ) -> Result<Self> {
        Ok(Self {
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

    async fn open_many(
        &self,
        path: &Path,
        evaluators: impl IntoIterator<Item = String>,
    ) -> Result<std::collections::BTreeMap<String, Arc<hellas_client::model::ModelPackage>>> {
        hellas_client::model::ModelPackage::open_many(path, evaluators, self.content.as_ref()).await
    }

    async fn add(&self, document: &mut Document, model: &str) -> Result<()> {
        let Some((name, destination)) = model.rsplit_once('@') else {
            let path =
                std::fs::canonicalize(model).with_context(|| format!("model package {model}"))?;
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
                .add_route(package_route(path, "local")?)
                .map_err(anyhow::Error::from_boxed)?;
            return Ok(());
        };
        if document
            .backends
            .get(destination)
            .is_some_and(|backend| matches!(backend.kind, BackendKind::Fetch { .. }))
        {
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
        let package = Path::new(name)
            .exists()
            .then(|| std::fs::canonicalize(name))
            .transpose()?;
        let packages = if let Some(path) = &package {
            let evaluators = bundle
                .offers
                .iter()
                .flat_map(|offer| &offer.offer().grant.policies)
                .flat_map(|policy| &policy.invocation_policy.admissions)
                .filter_map(|admission| match admission {
                    hellas_rpc::protocol::invocation::Admission::Compute { evaluator, .. } => {
                        Some(evaluator.clone())
                    }
                    _ => None,
                });
            self.open_many(path, evaluators).await?
        } else {
            Default::default()
        };
        let mut matches = vec![];
        for policy in bundle
            .offers
            .iter()
            .flat_map(|offer| &offer.offer().grant.policies)
        {
            if package.is_some() {
                for admission in &policy.invocation_policy.admissions {
                    if let hellas_rpc::protocol::invocation::Admission::Compute {
                        evaluator,
                        programs,
                    } = admission
                    {
                        let opened = &packages[evaluator];
                        if let Ok(program) = opened.program() {
                            match programs {
                                hellas_rpc::protocol::invocation::ComputePrograms::Any {} => {}
                                hellas_rpc::protocol::invocation::ComputePrograms::Only {
                                    manifests,
                                } if manifests.contains(&program.manifest) => {}
                                _ => continue,
                            }
                        } else if !matches!(
                            programs,
                            hellas_rpc::protocol::invocation::ComputePrograms::Any {}
                        ) {
                            continue;
                        }
                        matches.push((policy.clone(), Some(evaluator.clone())));
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
                matches.push((policy.clone(), None));
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
                .add_route(package_route(package, &id)?)
                .map_err(anyhow::Error::from_boxed)?;
        } else {
            for mut route in hellas_sdk::grant_routes(&policy, &id).map_err(anyhow::Error::from)? {
                match &mut route.presentation {
                    Presentation::Responses { models, .. } => *models = vec![name.into()],
                    Presentation::Http { targets } => {
                        if !targets.values().all(|target| {
                            target
                                .route
                                .models
                                .as_ref()
                                .is_some_and(|models| models.iter().any(|model| model == name))
                        }) {
                            continue;
                        }
                        for target in targets.values_mut() {
                            target.route.models = Some(vec![name.into()]);
                        }
                    }
                    Presentation::Model { .. } => {
                        anyhow::bail!("model resource needs a local package")
                    }
                }
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

fn package_route(package: PathBuf, backend: &str) -> Result<Route> {
    let model = package
        .file_stem()
        .and_then(|name| name.to_str())
        .context("model package needs a UTF-8 name")?
        .to_owned();
    Ok(Route {
        backends: vec![backend.into()],
        presentation: Presentation::Model {
            modality: hellas_client::model::ModelKind::of(&package)?,
            model,
            package,
            max_tokens: 128,
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
    let path = if let Some(suffix) = path.to_str().and_then(|p| p.strip_prefix("~/")) {
        PathBuf::from(std::env::var_os("HOME").context("HOME is unset")?).join(suffix)
    } else {
        path.to_owned()
    };
    let value = String::from_utf8(hellas_private::read_bounded_regular_file(&path, 16 * 1024)?)?;
    let value = value.trim();
    ensure!(
        !value.is_empty() && !value.contains(['\r', '\n']),
        "key file must contain one nonempty line"
    );
    Ok(value.into())
}

pub async fn apply(document: &mut Document, edit: Edit, context: &ModelContext) -> Result<()> {
    match edit {
        Edit::Backend(BackendCommand::Add {
            name,
            url,
            key_file,
        }) => {
            validate_name(&name)?;
            document
                .add_upstream(&name, &url, Some(key(&key_file)?))
                .map_err(anyhow::Error::from_boxed)?;
        }
        Edit::Backend(BackendCommand::Rm { name }) => document
            .remove_backend(&name)
            .map_err(anyhow::Error::from_boxed)?,
        Edit::Route(RouteCommand::Add { model }) => context.add(document, &model).await?,
        Edit::Route(RouteCommand::Listen { bind }) => {
            document
                .listeners
                .insert("api".into(), Listener::Http { bind, zdr: true });
        }
        Edit::Route(RouteCommand::Rm { model }) => {
            let (name, destination) = model
                .rsplit_once('@')
                .map_or((model.as_str(), None), |(a, b)| (a, Some(b)));
            let package = Path::new(name)
                .exists()
                .then(|| std::fs::canonicalize(name))
                .transpose()?;
            let mut removed = false;
            for route in &mut document.routes {
                let matches = match &route.presentation {
                    Presentation::Model { package: path, .. } => package.as_ref() == Some(path),
                    _ => route
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
    println!("MODEL\tMODALITY\tAPI PATH\tBACKEND\tSTATE\tJOBS\tERROR");
    for route in &view.document.routes {
        let modality = match &route.presentation {
            Presentation::Model { modality, .. } => match modality {
                hellas_client::model::ModelKind::Text => "text",
                hellas_client::model::ModelKind::Transcription => "audio",
                hellas_client::model::ModelKind::Image => "image",
            },
            _ => "text",
        };
        for (path, _, model) in route.keys() {
            for id in &route.backends {
                let backend = view.backends.iter().find(|backend| backend.id == *id);
                println!(
                    "{}\t{modality}\t{path}\t{id}\t{}\t{}\t{}",
                    model.as_deref().unwrap_or("*"),
                    if backend.is_some_and(|backend| backend.down) {
                        "Down"
                    } else {
                        "Up"
                    },
                    backend.map_or(0, |backend| backend.in_flight),
                    backend
                        .and_then(|backend| backend.error.as_deref())
                        .unwrap_or("")
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
    identity: &crate::identity::LocalIdentity,
    owner: Option<&hellas_kernel::SoftPasskey>,
    profile: &hellas_chain::genesis::ChainProfile,
    node: hellas_authority::node::NodeCoordinator,
    endpoint: Option<iroh::Endpoint>,
) -> Result<hellas_sdk::daemon::Options> {
    let settlement = crate::identity::settlement_signer(identity)?;
    let content = hellas_store::content::DiskStore::open(
        home.child("content"),
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
    identity: &crate::identity::LocalIdentity,
    owner: Option<&hellas_kernel::SoftPasskey>,
    chain: &hellas_chain::genesis::ChainProfile,
    #[cfg(feature = "otel")] metrics: Option<(std::net::SocketAddr, crate::metrics::MetricsBundle)>,
) -> Result<()> {
    let mut tty = if args.wrap.is_none() && args.bearer_file.is_none() {
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
    hellas_private::create_dir_all_durable(home)?;
    let temporary = tempfile::Builder::new()
        .prefix(".gateway-")
        .tempdir_in(home)?;
    let ephemeral = hellas_kernel::SoftPasskey::from_secret_scalar(rand::random())
        .map_err(|_| anyhow::anyhow!("invalid ephemeral key"))?;
    let (node, access) =
        super::admin::gateway_authority(&home.child(temporary.path()), identity, &ephemeral)
            .await?;
    let options = options(home.clone(), identity, owner, chain, node.clone(), None).await?;
    context.content = Some(options.content.clone());
    let prepared: Result<_> = async {
        let mut document = Document::default();
        document.listeners.insert(
            "api".into(),
            Listener::Http {
                bind: args.bind,
                zdr: true,
            },
        );
        for upstream in args.upstreams {
            let (definition, key_file) = upstream
                .rsplit_once(",key-file=")
                .context("upstream is NAME=HTTPS_API_URL,key-file=PATH")?;
            let (name, url) = definition
                .split_once('=')
                .context("upstream is NAME=HTTPS_API_URL,key-file=PATH")?;
            apply(
                &mut document,
                Edit::Backend(BackendCommand::Add {
                    name: name.into(),
                    url: url.into(),
                    key_file: key_file.into(),
                }),
                &context,
            )
            .await?;
        }
        for model in args.models {
            apply(
                &mut document,
                Edit::Route(RouteCommand::Add { model }),
                &context,
            )
            .await?;
        }
        Ok(document)
    }
    .await;
    let document = match prepared {
        Ok(document) => document,
        Err(error) => {
            options.content.close().await;
            node.close().await;
            return Err(error);
        }
    };
    run_daemon(
        options,
        Some(document),
        None,
        #[cfg(feature = "otel")]
        metrics,
        async |core| {
            print(&core.watch().0);
            let address = core.http_addresses()["api"];
            if let Some(path) = args.bearer_file {
                hellas_private::write_atomically(&path, ".bearer", access.bearer().as_bytes())?;
            }
            eprintln!("Gateway: http://{address}");
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
                use std::io::Write;
                if let Some(tty) = &mut tty {
                    writeln!(
                        tty,
                        "Gateway: http://{address}\nAuthorization: Bearer {}",
                        access.bearer()
                    )?;
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
    identity: &crate::identity::LocalIdentity,
    owner: Option<&hellas_kernel::SoftPasskey>,
    chain: &hellas_chain::genesis::ChainProfile,
    port: Option<u16>,
    #[cfg(feature = "otel")] metrics: Option<(std::net::SocketAddr, crate::metrics::MetricsBundle)>,
) -> Result<()> {
    let shutdown = shutdown_signal()?;
    tokio::pin!(shutdown);
    let endpoint = tokio::select! {
        result = super::bootstrap::prepare(home, &identity.transport_key, &identity.enrollment, port) => result?,
        signal = &mut shutdown => return Ok(signal?),
    };
    let store = hellas_authority::work_store::grant::NodeStore::open(
        &home.child("provider").child("authority"),
        hellas_authority::model::grant::grant_network(),
        Some(identity.enrollment.clone()),
        hellas_auth::authority::UnixMillis::now()?,
    )
    .await?;
    let node = hellas_authority::node::NodeCoordinator::new(
        store,
        Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
    );
    let mut options = options(home.clone(), identity, owner, chain, node.clone(), endpoint).await?;
    options.remote_control = hellas_sdk::node_control::RemoteControlAdmission::credential_gated();
    let document = if node.configuration().await?.is_some() {
        None
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
        Some(document)
    };
    run_daemon(
        options,
        document,
        port,
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
            eprintln!("Daemon ready; configure it with hellas backend and hellas route.");
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
    options: hellas_sdk::daemon::Options,
    document: Option<Document>,
    port: Option<u16>,
    #[cfg(feature = "otel")] metrics: Option<(std::net::SocketAddr, crate::metrics::MetricsBundle)>,
    run: impl AsyncFnOnce(Arc<hellas_sdk::daemon::Core>) -> Result<()>,
) -> Result<()> {
    let content = options.content.clone();
    let node = options.node.clone();
    let serving = async {
        let core = match document {
            Some(document) => hellas_sdk::daemon::Core::open(options, document).await,
            None => hellas_sdk::daemon::Core::restore(options, port).await,
        }
        .map_err(anyhow::Error::from_boxed)?;
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn gateway_matching_and_store_preparation_hash_full_weights_once() {
        const CHILD: &str = "HELLAS_TEST_GATEWAY_HASH_ONCE";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::daemon::tests::gateway_matching_and_store_preparation_hash_full_weights_once", "--nocapture"])
                .env(CHILD, "1")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("full.gguf");
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../client/src/model/package/mini-qwen3.gguf"),
            &path,
        )
        .unwrap();
        let size = 32 << 20;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(size)
            .unwrap();
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
        let context = ModelContext {
            home: root.path().into(),
            principal: None,
            holder: NodeKey::from_public_key(
                hellas_auth::ProducerSigningKey::from_secret_bytes([1; 32])
                    .unwrap()
                    .public_key(),
            )
            .unwrap(),
            content: Some(store.clone()),
        };
        let read_bytes = || -> u64 {
            std::fs::read_to_string("/proc/self/io")
                .unwrap()
                .lines()
                .find_map(|line| line.strip_prefix("rchar: ").map(|n| n.parse().unwrap()))
                .unwrap()
        };
        let before = read_bytes();
        let hip = hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip);
        let cuda = hellas_client::model::evaluator(hellas_client::model::GpuDialect::Cuda);
        let packages = context
            .open_many(&path, [hip.clone(), hip, cuda])
            .await
            .unwrap();
        assert_eq!(packages.len(), 2);
        let inspected = store.inspect_files(vec![path.clone()]).await.unwrap();
        assert_eq!(inspected[&path].bytes(), size);
        store
            .rescan(vec![path], hellas_store::content::IndexMode::Resume)
            .await
            .unwrap();
        let bytes = read_bytes() - before;
        assert!(bytes >= size, "cold weights were not read: {bytes}");
        assert!(
            bytes < size + (1 << 20),
            "weights were read more than once: {bytes} bytes for {size} weights bytes"
        );
        store.close().await;
    }

    #[cfg(all(target_os = "linux", feature = "compute"))]
    #[tokio::test]
    async fn local_rendering_and_indexing_hash_full_weights_once() {
        const CHILD: &str = "HELLAS_TEST_LOCAL_HASH_ONCE";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::daemon::tests::local_rendering_and_indexing_hash_full_weights_once",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("full.gguf");
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../client/src/model/package/mini-qwen3.gguf"),
            &path,
        )
        .unwrap();
        let size = 32 << 20;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(size)
            .unwrap();
        let native = crate::compute::LocalArgs {
            content_config: None,
            content: vec![],
            gpu: crate::compute::GpuArgs {
                evaluator: None,
                gpu_session_programs: 1,
                gpu_session_asset_bytes: size,
            },
        };
        let read_bytes = || -> u64 {
            std::fs::read_to_string("/proc/self/io")
                .unwrap()
                .lines()
                .find_map(|line| line.strip_prefix("rchar: ").map(|n| n.parse().unwrap()))
                .unwrap()
        };
        let before = read_bytes();
        let store = crate::compute::content(
            &StoreLocation::for_test(root.path()),
            &native,
            std::slice::from_ref(&path),
        )
        .await
        .unwrap();
        let evaluator = hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip);
        let packages =
            hellas_client::model::ModelPackage::open_many(&path, [evaluator.clone()], Some(&store))
                .await
                .unwrap();
        packages[&evaluator].program().unwrap();
        let bytes = read_bytes() - before;
        assert!(
            bytes >= size && bytes < size + (1 << 20),
            "weights were read more than once: {bytes} bytes for {size} weights bytes"
        );
        store.close().await;
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
        let context = ModelContext {
            home: directory.path().into(),
            content: None,
            principal: None,
            holder: NodeKey::from_public_key(
                hellas_auth::ProducerSigningKey::from_secret_bytes([1; 32])
                    .unwrap()
                    .public_key(),
            )
            .unwrap(),
        };
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

    #[cfg(feature = "compute")]
    #[test]
    fn local_commands_accept_registered_evaluator_ids() {
        use clap::CommandFactory;
        let evaluator = hellas_executor::catena::evaluator(hellas_executor::GpuDialect::Hip);
        let command = clap::Command::new("test");
        use clap::Args;
        let matches = crate::compute::GpuArgs::augment_args(command).try_get_matches_from([
            "test",
            "--evaluator",
            &evaluator,
        ]);
        assert!(matches.is_ok(), "{matches:?}");
        crate::Cli::command().debug_assert();
    }

    #[test]
    fn stateless_and_stateful_command_surfaces_have_no_config_file() {
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
        for args in [
            vec!["hellas", "gateway", "--config", "file"],
            vec!["hellas", "serve", "--model", "model.gguf"],
            vec!["hellas", "serve", "--fetch-config", "file"],
            vec!["hellas", "serve", "apply", "file"],
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
        std::fs::write(&key_file, "test-secret\n").unwrap();
        let context = ModelContext {
            home: directory.path().into(),
            content: None,
            principal: None,
            holder: NodeKey::from_public_key(
                hellas_auth::ProducerSigningKey::from_secret_bytes([1; 32])
                    .unwrap()
                    .public_key(),
            )
            .unwrap(),
        };
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
