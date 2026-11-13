//! One live configuration, with preparation before the journal's commit point.
use crate::daemon_config::{Document, Listener};
use crate::{BackendEntry, ExecutorGateway};
use arc_swap::ArcSwap;
use axum::{Router, extract::Request, response::Response};
use futures::FutureExt;
use hellas_auth::authority::{AuthenticatedSession, GrantId, Revision};
use hellas_authority::{model::grant::configuration::ConfigurationDocument, node::NodeCoordinator};
use hellas_gateway::{
    WorkExecutionBackend,
    jobs::{Event, Jobs, RequestLimit},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

mod iroh_listener;
mod runtime;
#[cfg(any(test, feature = "integration-tests"))]
pub mod testing;
pub use runtime::Options;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;
type ListenerExit = (String, std::sync::Weak<BoundListener>, Result<()>);

/// The local runtime's registered evaluator, without starting a worker.
pub fn local_evaluator() -> Option<String> {
    #[cfg(feature = "compute")]
    {
        Some(hellas_executor::catena::evaluator(runtime::automatic_gpu()))
    }
    #[cfg(not(feature = "compute"))]
    {
        None
    }
}

pub struct Core {
    runtime: runtime::Runtime,
    pub(crate) snapshot: ArcSwap<Snapshot>,
    pub jobs: Arc<Jobs>,
    limit: Arc<RequestLimit>,
    routing: Arc<hellas_gateway::RoutingState>,
    configuring: Arc<tokio::sync::Mutex<()>>,
    listeners: Mutex<tokio::task::JoinSet<ListenerExit>>,
    #[cfg(test)]
    pub(crate) after_commit:
        Mutex<Option<(Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>)>>,
}

pub(crate) struct Snapshot {
    revision: Revision,
    pub(crate) document: Document,
    pub(crate) work: Arc<ExecutorGateway>,
    routers: BTreeMap<String, Router>,
    listeners: BTreeMap<String, Arc<BoundListener>>,
}

struct BoundListener {
    bound: Bound,
    stop: tokio::sync::watch::Sender<bool>,
    started: std::sync::atomic::AtomicBool,
}
enum Bound {
    Http {
        bind: std::net::SocketAddr,
        address: std::net::SocketAddr,
        socket: Mutex<Option<tokio::net::TcpListener>>,
    },
    Iroh(Arc<iroh_listener::Bound>),
}
impl Drop for BoundListener {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct View {
    pub revision: Revision,
    pub local_evaluator: Option<String>,
    pub document: Document,
    pub backends: Vec<hellas_gateway::BackendInfo>,
    pub jobs: Vec<hellas_gateway::jobs::Info>,
    pub http_addresses: BTreeMap<String, std::net::SocketAddr>,
    pub iroh_addresses: BTreeMap<String, iroh::EndpointAddr>,
}

impl Core {
    /// Observe listener termination without lending it the caller's lifetime.
    pub async fn wait(&self) -> Result<()> {
        let (_, mut events) = self.jobs.watch(|_| ());
        loop {
            tokio::select! {
                result = std::future::poll_fn(|cx| self.listeners.lock().unwrap_or_else(|e| e.into_inner()).poll_join_next(cx)) => {
                    match result {
                        Some(result) => {
                            let (id, listener, result) = result?;
                            if listener.upgrade().is_some_and(|listener| !*listener.stop.borrow()) {
                                result?;
                                return Err(format!("listener {id} stopped").into());
                            }
                            if let Err(error) = result { tracing::warn!(%error, "retired listener stopped with an error"); }
                        }
                        None => { let _ = events.recv().await; }
                    }
                }
                _ = events.recv() => {},
            }
        }
    }

    /// Both CLI forms enter here. A saved document is read from the authority journal.
    pub async fn open(options: Options, document: Document) -> Result<Arc<Self>> {
        let revision = options
            .node
            .configuration()
            .await?
            .map_or(Revision(0), |c| c.revision);
        Self::open_prepared(options, document, BTreeMap::new(), revision, false).await
    }

    /// Use deterministic executors while exercising the real daemon and transports.
    #[cfg(any(test, feature = "integration-tests"))]
    pub async fn open_with_backends(
        options: Options,
        document: Document,
        backends: BTreeMap<String, BackendEntry>,
    ) -> Result<Arc<Self>> {
        let revision = options
            .node
            .configuration()
            .await?
            .map_or(Revision(0), |c| c.revision);
        Self::open_prepared(options, document, backends, revision, false).await
    }

    async fn open_prepared(
        mut options: Options,
        document: Document,
        entries: BTreeMap<String, BackendEntry>,
        revision: Revision,
        commit: bool,
    ) -> Result<Arc<Self>> {
        if options.node.provider().await?.is_some_and(|enrollment| {
            enrollment.genesis.statement.root_kind == hellas_rpc::RootKind::Software
        }) {
            options.prover = None;
        }
        let limit = Arc::new(RequestLimit::default());
        let jobs = Arc::new(Jobs::new(limit.clone()));
        let work = ExecutorGateway::prepare(
            BTreeMap::new(),
            options.signer.clone(),
            jobs.clone(),
            None,
            &BTreeSet::new(),
        );
        let core = Arc::new(Self {
            runtime: runtime::Runtime::new(options),
            snapshot: ArcSwap::from_pointee(Snapshot {
                revision,
                document: Document::default(),
                work,
                routers: BTreeMap::new(),
                listeners: BTreeMap::new(),
            }),
            jobs,
            limit,
            routing: Default::default(),
            configuring: Arc::new(tokio::sync::Mutex::new(())),
            listeners: Mutex::new(tokio::task::JoinSet::new()),
            #[cfg(test)]
            after_commit: Mutex::new(None),
        });
        crate::chain_home::recover_provider_chains(
            &core.runtime.options.home,
            &core.runtime.options.settlement,
            &core.runtime.options.content,
        )
        .await?;
        let next = if commit {
            revision.next().ok_or("configuration revision overflow")?
        } else {
            revision
        };
        let (snapshot, configuration) = core.prepare(document, entries, next).await?;
        if commit {
            let (redacted, secrets) = snapshot.document.redacted();
            core.node()
                .configure_startup(
                    ConfigurationDocument {
                        revision,
                        document: serde_json::to_string(&redacted)?,
                        secrets,
                    },
                    &configuration,
                )
                .await?;
        }
        core.publish(snapshot);
        Ok(core)
    }

    pub async fn restore(options: Options) -> Result<Arc<Self>> {
        Self::restore_on_port(options, None).await
    }

    /// Apply an explicit process startup port as a journaled edit before listening.
    pub async fn restore_on_port(options: Options, port: Option<u16>) -> Result<Arc<Self>> {
        let (mut document, revision) = match options.node.configuration().await? {
            Some(stored) => {
                let mut document: Document = serde_json::from_str(&stored.document)?;
                document.restore_secrets(&stored.secrets);
                (document, stored.revision)
            }
            None => (Document::default(), Revision(0)),
        };
        let mut changed = false;
        if let Some(port) = port {
            let listener = document
                .listeners
                .values_mut()
                .find(|listener| matches!(listener, Listener::Iroh { .. }));
            match listener {
                Some(Listener::Iroh { port: saved, .. }) => {
                    changed = *saved != port;
                    *saved = port;
                }
                _ => {
                    document.listeners.insert(
                        "work".into(),
                        Listener::Iroh {
                            port,
                            chain: None,
                            backends: vec![],
                        },
                    );
                    changed = true;
                }
            }
        }
        Self::open_prepared(options, document, BTreeMap::new(), revision, changed).await
    }

    pub fn node(&self) -> &NodeCoordinator {
        &self.runtime.options.node
    }

    /// The same backends and job table used by listeners, for an embedded native UI.
    pub fn execution(&self) -> Arc<ExecutorGateway> {
        self.snapshot.load().work.clone()
    }

    pub fn http_addresses(&self) -> BTreeMap<String, std::net::SocketAddr> {
        self.snapshot
            .load()
            .listeners
            .iter()
            .filter_map(|(id, listener)| match &listener.bound {
                Bound::Http { address, .. } => Some((id.clone(), *address)),
                Bound::Iroh(_) => None,
            })
            .collect()
    }

    pub(crate) fn iroh_endpoints(&self) -> Vec<iroh::Endpoint> {
        self.snapshot
            .load()
            .listeners
            .values()
            .filter_map(|listener| match &listener.bound {
                Bound::Iroh(bound) => Some(bound.endpoint.clone()),
                _ => None,
            })
            .collect()
    }

    /// Bound provider and consumer endpoints for transport telemetry.
    pub fn transport_endpoints(&self) -> Vec<iroh::Endpoint> {
        let mut endpoints = self.iroh_endpoints();
        endpoints.extend(self.runtime.consumer_endpoints());
        endpoints
    }

    pub fn iroh_addresses(&self) -> BTreeMap<String, ::iroh::EndpointAddr> {
        self.snapshot
            .load()
            .listeners
            .iter()
            .filter_map(|(id, listener)| match &listener.bound {
                Bound::Iroh(bound) => Some((id.clone(), bound.endpoint.addr())),
                Bound::Http { .. } => None,
            })
            .collect()
    }

    pub fn control(self: &Arc<Self>) -> Result<crate::node_control::NodeControl> {
        Ok(crate::node_control::NodeControl::new(self.node().clone())
            .with_content_store(self.runtime.options.content.clone())
            .with_core(self.clone())?)
    }

    pub(crate) fn administration(
        &self,
    ) -> Option<hellas_authority::grant_service::WorkAdministration> {
        self.snapshot
            .load()
            .listeners
            .values()
            .find_map(|listener| match &listener.bound {
                Bound::Iroh(bound) => Some(bound.administration.clone()),
                Bound::Http { .. } => None,
            })
    }

    pub fn watch(&self) -> (View, tokio::sync::broadcast::Receiver<Event>) {
        self.jobs.watch(|jobs| {
            let snapshot = self.snapshot.load();
            View {
                revision: snapshot.revision,
                local_evaluator: local_evaluator(),
                document: snapshot.document.redacted().0,
                backends: snapshot.work.backends(),
                jobs,
                http_addresses: self.http_addresses(),
                iroh_addresses: self.iroh_addresses(),
            }
        })
    }

    pub async fn configure(
        self: &Arc<Self>,
        session: Arc<AuthenticatedSession>,
        binding: hellas_auth::Digest,
        authorization: GrantId,
        expected: Revision,
        mut document: Document,
    ) -> Result<Revision> {
        let serial = self.configuring.clone().lock_owned().await;
        if self.jobs.is_closed() {
            return Err("daemon is draining".into());
        }
        let current = self.snapshot.load_full();
        if current.revision != expected {
            return Err("configuration revision changed".into());
        }
        document.restore_secrets(&current.document.redacted().1);
        let revision = expected.next().ok_or("configuration revision overflow")?;
        let (candidate, configuration) = self.prepare(document, BTreeMap::new(), revision).await?;
        let (redacted, secrets) = candidate.document.redacted();
        let stored = ConfigurationDocument {
            revision: expected,
            document: serde_json::to_string(&redacted)?,
            secrets,
        };
        let core = self.clone();
        // Dropping the caller detaches this commit-and-publication task.
        tokio::spawn(async move {
            let _serial = serial;
            let caller = core.node().session_caller(&session, binding).await?;
            core.node()
                .configure(caller, authorization, stored, &configuration)
                .await?;
            #[cfg(test)]
            {
                let barrier = core.after_commit.lock().unwrap().take();
                if let Some((committed, resume)) = barrier {
                    committed.add_permits(1);
                    resume.acquire().await.unwrap().forget();
                }
            }
            let revision = candidate.revision;
            let previous = core.publish(candidate.clone());
            if let Err(error) = previous.work.retire(&candidate.work).await {
                tracing::warn!(%error, "retired backend retains recovery obligations");
            }
            for (id, listener) in &previous.listeners {
                if candidate
                    .listeners
                    .get(id)
                    .is_some_and(|next| Arc::ptr_eq(listener, next))
                {
                    continue;
                }
                listener.stop.closed().await;
            }
            Ok::<_, Error>(revision)
        })
        .await?
    }

    async fn prepare(
        self: &Arc<Self>,
        document: Document,
        mut entries: BTreeMap<String, BackendEntry>,
        revision: Revision,
    ) -> Result<(
        Arc<Snapshot>,
        hellas_authority::model::grant::configuration::NodeConfiguration,
    )> {
        document.validate().map_err(Error::from)?;
        let old = self.snapshot.load_full();
        let mut reuse = BTreeSet::new();
        for (id, backend) in &document.backends {
            if entries.contains_key(id) {
                continue;
            }
            let unchanged = old.document.backends.get(id) == Some(backend);
            let local = matches!(
                backend.kind,
                crate::daemon_config::BackendKind::Local { .. }
            );
            let approved = match old.work.backend(id) {
                Some(active) if unchanged => {
                    self.runtime.approval_current(&backend.kind, active)?
                }
                _ => false,
            };
            if unchanged && approved && !local {
                reuse.insert(id.clone());
            } else {
                entries.insert(
                    id.clone(),
                    self.runtime.open_backend(id, backend, &document).await?,
                );
            }
        }
        let work = ExecutorGateway::prepare(
            entries,
            self.runtime.options.signer.clone(),
            self.jobs.clone(),
            Some(&old.work),
            &reuse,
        );
        let configuration = document.configuration(&work.backends()).await?;
        work.validate_resources(configuration.resources())
            .map_err(Error::from)?;
        document
            .validate_resolved(&work.backends())
            .map_err(Error::from)?;
        let router = hellas_gateway::router::router(
            document.routes.clone(),
            work.clone(),
            self.jobs.clone(),
            self.routing.clone(),
        )
        .await?;
        let mut listeners = BTreeMap::new();
        let mut routers = BTreeMap::new();
        for (id, listener) in &document.listeners {
            let reusable = old
                .listeners
                .get(id)
                .filter(|old| match (&old.bound, listener) {
                    (Bound::Http { bind: old, .. }, Listener::Http { bind, .. }) => old == bind,
                    (Bound::Iroh(old), Listener::Iroh { port, chain, .. }) => {
                        old.port == *port && old.profile == *chain
                    }
                    _ => false,
                });
            let bound = match reusable {
                Some(bound) => bound.clone(),
                None => Arc::new(BoundListener {
                    bound: match listener {
                        Listener::Http { bind, .. } => {
                            let socket = tokio::net::TcpListener::bind(bind).await?;
                            Bound::Http {
                                bind: *bind,
                                address: socket.local_addr()?,
                                socket: Mutex::new(Some(socket)),
                            }
                        }
                        Listener::Iroh { port, chain, .. } => Bound::Iroh(Arc::new(
                            iroh_listener::Bound::prepare(self, id, *port, chain).await?,
                        )),
                    },
                    stop: tokio::sync::watch::channel(false).0,
                    started: Default::default(),
                }),
            };
            listeners.insert(id.clone(), bound);
            let Listener::Http { zdr, .. } = listener else {
                continue;
            };
            routers.insert(
                id.clone(),
                hellas_gateway::listener_router(
                    router.clone(),
                    self.node().clone(),
                    hellas_gateway::ArchiveOptions {
                        directory: self.runtime.options.home.join("gateway-archive"),
                        zdr: *zdr,
                    },
                )
                .await?,
            );
        }
        Ok((
            Arc::new(Snapshot {
                revision,
                document,
                work,
                routers,
                listeners,
            }),
            configuration,
        ))
    }

    fn publish(self: &Arc<Self>, next: Arc<Snapshot>) -> Arc<Snapshot> {
        let mut previous = None;
        self.jobs.change(|| {
            self.limit
                .configure(next.document.limits.requests_per_minute);
            previous = Some(self.snapshot.swap(next.clone()));
            Some(Event::Revision {
                revision: next.revision,
            })
        });
        let previous = previous.expect("publication runs synchronously");
        if let Some(endpoint) = self.iroh_endpoints().into_iter().next() {
            self.runtime.options.content.clone().with_peers(
                hellas_wire::iroh::Pool::for_service::<hellas_rpc::services::content::Content>(
                    endpoint,
                    Default::default(),
                ),
            );
        } else {
            self.runtime.options.content.clear_peers();
        }

        for (id, listener) in &previous.listeners {
            if next
                .listeners
                .get(id)
                .is_none_or(|next| !Arc::ptr_eq(listener, next))
            {
                listener.stop.send_replace(true);
            }
        }
        let mut owned = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        for (id, listener) in &next.listeners {
            if listener
                .started
                .swap(true, std::sync::atomic::Ordering::AcqRel)
            {
                continue;
            }
            let core = Arc::downgrade(self);
            let serve: futures::future::BoxFuture<'static, Result<()>> = match &listener.bound {
                Bound::Http { socket, .. } => {
                    let socket = socket
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .take()
                        .expect("unstarted HTTP listener owns its socket");
                    let id = id.clone();
                    let router = Router::new().fallback(move |request: Request| {
                        let core = core.clone();
                        let id = id.clone();
                        async move {
                            let Some(core) = core.upgrade() else {
                                return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                            };
                            core.http(&id, request).await
                        }
                    });
                    hellas_gateway::serve_listener(socket, router, listener.stop.subscribe())
                        .map(|result| result.map_err(Error::from))
                        .boxed()
                }
                Bound::Iroh(bound) => {
                    let bound = bound.clone();
                    let stop = listener.stop.subscribe();
                    async move { bound.serve(core, stop).await }.boxed()
                }
            };
            let id = id.clone();
            let stopped = listener.stop.subscribe();
            let listener = Arc::downgrade(listener);
            owned.spawn(async move {
                // Keep the stop receiver alive through physical listener teardown.
                let _stopped = stopped;
                (id, listener, serve.await)
            });
        }
        previous
    }

    async fn http(&self, listener: &str, request: Request) -> Response {
        let snapshot = self.snapshot.load_full();
        let Some(router) = snapshot.routers.get(listener) else {
            return axum::http::StatusCode::NOT_FOUND.into_response();
        };
        router
            .clone()
            .oneshot(request)
            .await
            .unwrap_or_else(|never| match never {})
    }

    pub async fn shutdown(&self) -> Result<()> {
        let _serial = self.configuring.lock().await;
        self.jobs.close();
        let snapshot = self.snapshot.load_full();
        for listener in snapshot.listeners.values() {
            listener.stop.send_replace(true);
        }
        let mut failure = None;
        while let Some(result) = std::future::poll_fn(|cx| {
            self.listeners
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .poll_join_next(cx)
        })
        .await
        {
            if let Err(error) = result
                .map_err(Error::from)
                .and_then(|(_, _, result)| result)
            {
                failure.get_or_insert(error);
            }
        }
        if let Err(error) = snapshot.work.drain().await {
            failure.get_or_insert(Error::from(error));
        }
        self.runtime.shutdown().await;
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }
}
use axum::response::IntoResponse;
