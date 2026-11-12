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
type Task<T> =
    futures::future::Shared<futures::future::BoxFuture<'static, std::result::Result<T, String>>>;

mod runtime;
pub use runtime::Options;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

pub struct Core {
    runtime: runtime::Runtime,
    snapshot: ArcSwap<Snapshot>,
    pub jobs: Arc<Jobs>,
    limit: Arc<RequestLimit>,
    configuring: Arc<tokio::sync::Mutex<()>>,
    commit: Mutex<Option<Task<Revision>>>,
    listeners: Mutex<Vec<Arc<HttpListener>>>,
    closed: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(crate) after_commit:
        Mutex<Option<(Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>)>>,
}

struct Snapshot {
    document: Document,
    work: Arc<ExecutorGateway>,
    routers: BTreeMap<String, Router>,
    listeners: BTreeMap<String, Arc<HttpListener>>,
}

struct HttpListener {
    bind: std::net::SocketAddr,
    address: std::net::SocketAddr,
    socket: Mutex<Option<tokio::net::TcpListener>>,
    stop: tokio::sync::watch::Sender<bool>,
    task: Mutex<Option<Task<()>>>,
}
impl Drop for HttpListener {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct View {
    pub document: Document,
    pub backends: Vec<hellas_gateway::BackendInfo>,
    pub jobs: Vec<hellas_gateway::jobs::Info>,
}

impl Core {
    /// Both CLI forms enter here. A saved document is read from the authority journal.
    pub async fn open(options: Options, document: Document) -> Result<Arc<Self>> {
        let limit = Arc::new(RequestLimit::default());
        let jobs = Arc::new(Jobs::new(vec![limit.clone()]));
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
                document: Document::default(),
                work,
                routers: BTreeMap::new(),
                listeners: BTreeMap::new(),
            }),
            jobs,
            limit,
            configuring: Arc::new(tokio::sync::Mutex::new(())),
            commit: Mutex::new(None),
            listeners: Mutex::new(Vec::new()),
            closed: Default::default(),
            #[cfg(test)]
            after_commit: Mutex::new(None),
        });
        let snapshot = core.prepare(document).await?;
        core.publish(snapshot);
        Ok(core)
    }

    pub async fn restore(options: Options) -> Result<Arc<Self>> {
        let document = match options.node.configuration().await? {
            Some(stored) => {
                let mut document: Document = serde_json::from_str(&stored.document)?;
                if document.revision != stored.revision {
                    return Err("stored configuration revision mismatch".into());
                }
                document.restore_secrets(&stored.secrets);
                document
            }
            None => Document::default(),
        };
        Self::open(options, document).await
    }

    pub fn node(&self) -> &NodeCoordinator {
        &self.runtime.options.node
    }

    pub fn http_addresses(&self) -> BTreeMap<String, std::net::SocketAddr> {
        self.snapshot
            .load()
            .listeners
            .iter()
            .map(|(id, listener)| (id.clone(), listener.address))
            .collect()
    }

    pub fn watch(&self) -> (View, tokio::sync::broadcast::Receiver<Event>) {
        self.jobs.watch(|jobs| {
            let snapshot = self.snapshot.load();
            View {
                document: snapshot.document.redacted().0,
                backends: snapshot.work.backends(),
                jobs,
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
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err("daemon is draining".into());
        }
        let caller = self.node().session_caller(&session, binding).await?;
        self.node()
            .host_action(
                caller,
                authorization,
                hellas_authority::node::HOST_CONFIGURE,
                |_| (),
            )
            .await?;
        let current = self.snapshot.load_full();
        if current.document.revision != expected || document.revision != expected {
            return Err("configuration revision changed".into());
        }
        document.restore_secrets(&current.document.redacted().1);
        document.revision = expected.next().ok_or("configuration revision overflow")?;
        let candidate = self.prepare(document).await?;
        let (redacted, secrets) = candidate.document.redacted();
        let stored = ConfigurationDocument {
            revision: expected,
            document: serde_json::to_string(&redacted)?,
            secrets,
        };
        let core = self.clone();
        // The daemon retains this task; dropping the caller's cloned future cannot abort it.
        let task = {
            let mut retained = self
                .commit
                .lock()
                .map_err(|_| "configuration task lock poisoned")?;
            let task = tokio::spawn(async move {
                let _serial = serial;
                let caller = core.node().session_caller(&session, binding).await?;
                core.node()
                    .configure(caller, authorization, stored, &candidate.document.authority)
                    .await?;
                #[cfg(test)]
                {
                    let barrier = core.after_commit.lock().unwrap().take();
                    if let Some((committed, resume)) = barrier {
                        committed.add_permits(1);
                        resume.acquire().await.unwrap().forget();
                    }
                }
                let revision = candidate.document.revision;
                let previous = core.publish(candidate.clone());
                if let Err(error) = previous.work.retire(&candidate.work).await {
                    tracing::warn!(%error, "retired backend retains recovery obligations");
                }
                Ok::<_, Error>(revision)
            })
            .map(|result| match result {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(error) => Err(error.to_string()),
            })
            .boxed()
            .shared();
            *retained = Some(task.clone());
            task
        };
        task.await.map_err(Into::into)
    }

    async fn prepare(&self, document: Document) -> Result<Arc<Snapshot>> {
        document.validate().map_err(Error::from)?;
        let old = self.snapshot.load_full();
        let mut entries = BTreeMap::<String, BackendEntry>::new();
        let mut reuse = BTreeSet::new();
        for (id, backend) in &document.backends {
            let unchanged = old
                .document
                .backends
                .get(id)
                .map(serde_json::to_value)
                .transpose()?
                == Some(serde_json::to_value(backend)?);
            let local = matches!(
                backend.kind,
                crate::daemon_config::BackendKind::Local { .. }
            );
            if unchanged && !local {
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
        document
            .validate_resolved(&work.backends())
            .map_err(Error::from)?;
        let router = hellas_gateway::router::router(
            document.routes.clone(),
            work.clone(),
            self.jobs.clone(),
        )
        .await?;
        let mut listeners = BTreeMap::new();
        let mut routers = BTreeMap::new();
        for (id, listener) in &document.listeners {
            let Listener::Http { bind, zdr, .. } = listener else {
                return Err("iroh listener preparation is not installed".into());
            };
            let bound =
                if let Some(bound) = old.listeners.get(id).filter(|bound| bound.bind == *bind) {
                    bound.clone()
                } else {
                    let socket = tokio::net::TcpListener::bind(bind).await?;
                    Arc::new(HttpListener {
                        bind: *bind,
                        address: socket.local_addr()?,
                        socket: Mutex::new(Some(socket)),
                        stop: tokio::sync::watch::channel(false).0,
                        task: Mutex::new(None),
                    })
                };
            let access = self
                .runtime
                .options
                .access
                .clone()
                .ok_or("HTTP listener requires provisioned gateway access")?;
            if !access.shares_writer(self.node()) {
                return Err("HTTP listener must share the daemon authority".into());
            }
            routers.insert(
                id.clone(),
                hellas_gateway::listener_router(
                    router.clone(),
                    access,
                    hellas_gateway::ArchiveOptions {
                        directory: self.runtime.options.home.join("gateway-archive"),
                        zdr: *zdr,
                    },
                )
                .await?,
            );
            listeners.insert(id.clone(), bound);
        }
        Ok(Arc::new(Snapshot {
            document,
            work,
            routers,
            listeners,
        }))
    }

    fn publish(self: &Arc<Self>, next: Arc<Snapshot>) -> Arc<Snapshot> {
        let mut previous = None;
        self.jobs.change(|| {
            self.limit
                .configure(next.document.limits.requests_per_minute);
            previous = Some(self.snapshot.swap(next.clone()));
            Some(Event::Revision {
                revision: next.document.revision,
            })
        });
        let previous = previous.expect("publication runs synchronously");
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
        owned.retain(|listener| {
            let task = listener
                .task
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            match task.and_then(|task| task.now_or_never()) {
                Some(result) => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "HTTP listener ended with an error");
                    }
                    false
                }
                None => true,
            }
        });
        for (id, listener) in &next.listeners {
            if let Some(socket) = listener
                .socket
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                let core = Arc::downgrade(self);
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
                *listener.task.lock().unwrap_or_else(|e| e.into_inner()) = Some(
                    hellas_gateway::serve_listener(socket, router, listener.stop.subscribe())
                        .map(|result| match result {
                            Ok(result) => result.map_err(|error| error.to_string()),
                            Err(error) => Err(error.to_string()),
                        })
                        .boxed()
                        .shared(),
                );
                owned.push(listener.clone());
            }
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
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.jobs.close();
        let snapshot = self.snapshot.load_full();
        let listeners = self
            .listeners
            .lock()
            .map_err(|_| "listener lock poisoned")?
            .clone();
        for listener in &listeners {
            listener.stop.send_replace(true);
        }
        let mut failure = None;
        for listener in listeners {
            let task = listener
                .task
                .lock()
                .map_err(|_| "listener task lock poisoned")?
                .clone();
            if let Some(task) = task
                && let Err(error) = task.await
            {
                failure.get_or_insert(Error::from(error));
            }
        }
        if let Err(error) = snapshot.work.drain().await {
            failure.get_or_insert(Error::from(error));
        }
        self.runtime.shutdown().await;
        if let Some(error) = failure {
            return Err(error);
        }
        self.listeners
            .lock()
            .map_err(|_| "listener lock poisoned")?
            .clear();
        Ok(())
    }
}
use axum::response::IntoResponse;
