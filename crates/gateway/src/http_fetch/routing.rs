use super::{
    affinity::{Hints, family},
    config::{HttpBackend, HttpGatewayConfig, HttpRoute},
};
use anyhow::ensure;
use axum::http::{HeaderMap, StatusCode};
use hellas_client::{ExecutionRoute, ProviderTrustAnchor};
use hellas_rpc::ContentId;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct Account {
    capacity: usize,
    slots: Arc<Semaphore>,
    backoff: Mutex<Option<(Instant, u16)>>,
}

impl Account {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            slots: Arc::new(Semaphore::new(capacity)),
            backoff: Mutex::new(None),
        }
    }

    fn load(&self) -> usize {
        (self.capacity - self.slots.available_permits()) * 1024 / self.capacity
    }

    fn acquire(&self) -> Result<OwnedSemaphorePermit, (u16, Duration)> {
        if let Some((status, delay)) = self.cooldown() {
            return Err((status, delay));
        }
        self.slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| (503, Duration::ZERO))
    }

    fn cooldown(&self) -> Option<(u16, Duration)> {
        let (until, status) = (*self.backoff.lock().unwrap())?;
        let delay = until.saturating_duration_since(Instant::now());
        (!delay.is_zero()).then_some((status, delay))
    }

    fn observe(&self, status: u16, headers: &HeaderMap) {
        if status == 429 || (status >= 500 && headers.contains_key("retry-after")) {
            self.back_off(status, retry_delay(headers));
        }
    }

    fn back_off(&self, status: u16, delay: Duration) {
        let until = Instant::now() + delay.min(Duration::from_secs(u32::MAX as u64));
        let mut backoff = self.backoff.lock().unwrap();
        if backoff.is_none_or(|(previous, _)| until > previous) {
            *backoff = Some((until, status));
        }
    }
}

const MAX_BINDINGS: usize = 16_384;
const SESSION_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

pub(super) struct Backend {
    pub name: String,
    pub models: Vec<String>,
    pub routes: Vec<HttpRoute>,
    pub remote: ExecutionRoute,
    account: Arc<Account>,
}

struct Binding {
    // None means different backends reported the same server-side identifier.
    backend: Option<usize>,
    touched: Instant,
    connection: Option<Weak<()>>,
}

#[derive(Default)]
struct State {
    bindings: HashMap<ContentId, Binding>,
    next: usize,
}

impl State {
    fn resolve(
        &mut self,
        session: Option<ContentId>,
        continuations: &[ContentId],
    ) -> Result<Option<usize>, Unavailable> {
        let now = Instant::now();
        self.bindings.retain(|_, binding| {
            now.duration_since(binding.touched) < SESSION_IDLE
                && binding
                    .connection
                    .as_ref()
                    .is_none_or(|c| c.strong_count() > 0)
        });
        let mut pinned = None;
        for (key, required) in continuations
            .iter()
            .map(|key| (*key, true))
            .chain(session.map(|key| (key, false)))
        {
            let Some(binding) = self.bindings.get_mut(&key) else {
                if required {
                    return Err(Unavailable::conflict(
                        "unknown or expired server-side continuation; resend full context",
                    ));
                }
                continue;
            };
            binding.touched = now;
            let backend = binding
                .backend
                .ok_or_else(|| Unavailable::conflict("ambiguous server-side continuation"))?;
            if pinned.is_some_and(|p| p != backend) {
                return Err(Unavailable::conflict(
                    "conflicting session or continuation backends",
                ));
            }
            pinned = Some(backend);
        }
        Ok(pinned)
    }

    fn check_capacity(&self, session: Option<ContentId>) -> Result<(), Unavailable> {
        if session.is_some_and(|key| !self.bindings.contains_key(&key))
            && self.bindings.len() >= MAX_BINDINGS
        {
            return Err(Unavailable::busy(503, Duration::ZERO));
        }
        Ok(())
    }

    fn bind(&mut self, key: ContentId, backend: usize, connection: Option<Weak<()>>) {
        // Never overwrite a conflicting identifier or evict a live session.
        // An unrecorded or ambiguous continuation will fail closed later.
        if let Some(binding) = self.bindings.get_mut(&key) {
            binding.backend = binding.backend.filter(|existing| *existing == backend);
            binding.touched = Instant::now();
        } else if self.bindings.len() < MAX_BINDINGS {
            self.bindings.insert(
                key,
                Binding {
                    backend: Some(backend),
                    touched: Instant::now(),
                    connection,
                },
            );
        }
    }
}

pub(super) struct Routing {
    pub backends: Vec<Backend>,
    pooled: bool,
    salt: [u8; 32],
    state: Mutex<State>,
}

pub(super) struct Selected {
    pub backend: usize,
    pub endpoint: usize,
    pub permit: OwnedSemaphorePermit,
    pub affinity: &'static str,
    pub model: Option<String>,
}

#[derive(Debug)]
pub(super) struct Unavailable {
    pub status: StatusCode,
    pub message: &'static str,
    pub retry: Option<u64>,
    pub backend: Option<usize>,
}

impl Unavailable {
    fn new(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            retry: None,
            backend: None,
        }
    }

    fn conflict(message: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    fn busy(status: u16, delay: Duration) -> Self {
        Self {
            retry: Some(delay.as_secs() + 1),
            ..Self::new(
                StatusCode::from_u16(status).unwrap(),
                "selected backend is temporarily unavailable",
            )
        }
    }
}

impl Routing {
    pub fn new(
        config: &HttpGatewayConfig,
        remote: ExecutionRoute,
        trust: ProviderTrustAnchor,
    ) -> anyhow::Result<Self> {
        let routes = config.routes.iter().enumerate().map(|(index, route)| {
            (
                format!("route-{index}"),
                HttpBackend {
                    models: vec![],
                    credential: route.credential.clone(),
                    routes: vec![route.clone()],
                    max_in_flight: None,
                    provider: None,
                },
            )
        });
        let mut backends = Vec::new();
        let mut accounts = HashMap::new();
        for (name, mut backend) in routes.chain(config.backends.clone()) {
            let remote = match backend.provider {
                Some(provider) => ExecutionRoute::remote(
                    Some(provider.node_id),
                    provider.node_addrs,
                    0,
                    ProviderTrustAnchor {
                        expected_genesis: provider.genesis,
                        ..trust.clone()
                    },
                ),
                None => remote.clone(),
            };
            for route in &mut backend.routes {
                route.credential = backend.credential.clone();
            }
            let account = backend.routes[0].account();
            ensure!(
                backend.routes.iter().all(|r| r.account() == account),
                "a backend must use one account or origin"
            );
            // Enrollment pins share admission across direct and discovered routes.
            let genesis = match &remote {
                ExecutionRoute::RemoteDirect(target) => target.provider_trust.expected_genesis,
                ExecutionRoute::RemoteDiscovery { provider_trust, .. } => {
                    provider_trust.expected_genesis
                }
                ExecutionRoute::Local => unreachable!(),
            };
            let capacity = backend.max_in_flight.unwrap_or(config.max_in_flight);
            let account = accounts
                .entry((genesis, account))
                .or_insert_with(|| Arc::new(Account::new(capacity)));
            ensure!(
                account.capacity == capacity,
                "shared accounts require the same concurrency limit"
            );
            backends.push(Backend {
                name,
                models: backend.models,
                routes: backend.routes,
                remote,
                account: account.clone(),
            });
        }
        Ok(Self {
            backends,
            pooled: !config.backends.is_empty(),
            salt: rand::random(),
            state: Mutex::new(State::default()),
        })
    }

    fn key(&self, domain: &str, parts: &[&str]) -> ContentId {
        let mut fields: Vec<&[u8]> = vec![&self.salt];
        fields.extend(parts.iter().map(|s| s.as_bytes()));
        ContentId::from_slice(hellas_rpc::hash_tuple(domain, &fields).as_bytes()).unwrap()
    }

    pub fn select(
        &self,
        path: &str,
        method: &str,
        headers: &HeaderMap,
        body: &[u8],
        connection: Option<&crate::ConnectionId>,
    ) -> Result<Selected, Unavailable> {
        let hints = if self.pooled {
            Hints::read(headers, body)
                .map_err(|message| Unavailable::new(StatusCode::BAD_REQUEST, message))?
        } else {
            Hints::default()
        };
        let model = hints.model.as_deref();
        let mut candidates: Vec<_> = self
            .backends
            .iter()
            .enumerate()
            .filter(|(_, backend)| {
                model.is_none_or(|model| {
                    backend.models.is_empty() || backend.models.iter().any(|m| m == model)
                })
            })
            .filter_map(|(index, backend)| {
                backend
                    .routes
                    .iter()
                    .position(|r| r.path == path && r.method == method)
                    .map(|endpoint| (index, endpoint))
            })
            .collect();
        if candidates.is_empty() {
            return Err(Unavailable::new(
                StatusCode::NOT_FOUND,
                "no backend serves this route and model",
            ));
        }
        let family = family(path);
        let continuations: Vec<_> = [
            ("response", &hints.previous),
            ("conversation", &hints.conversation),
        ]
        .into_iter()
        .filter_map(|(kind, id)| id.as_ref().map(|id| self.key(kind, &[family, id])))
        .collect();
        if self.pooled && model.is_none() && !body.is_empty() && continuations.is_empty() {
            return Err(Unavailable::new(
                StatusCode::BAD_REQUEST,
                "model is required",
            ));
        }
        let connection = connection.filter(|_| self.pooled && hints.session.is_none());
        let session = hints
            .session
            .as_ref()
            .map(|(kind, id)| self.key("session", &[family, model.unwrap_or(""), kind, id]))
            .or_else(|| {
                connection.map(|c| {
                    self.key(
                        "connection",
                        &[family, model.unwrap_or(""), &c.id.to_string()],
                    )
                })
            });
        // Keep resolution, admission and first binding atomic across requests.
        let mut state = self.state.lock().unwrap();
        let pinned = state.resolve(session, &continuations)?;
        if let Some(index) = pinned {
            candidates.retain(|(backend, _)| *backend == index);
            if candidates.is_empty() {
                return Err(Unavailable::conflict(
                    "session backend cannot serve this model and route",
                ));
            }
        }
        state.check_capacity(session)?;
        let count = self.backends.len();
        // Snapshot loads before sorting: other responses may release permits.
        // Least occupied account first, rotating ties; aliases share its permits.
        candidates.sort_by_cached_key(|(index, _)| {
            (
                self.backends[*index].account.load(),
                (*index + count - state.next) % count,
            )
        });
        let mut unavailable: Option<(u16, Duration)> = None;
        for (backend, endpoint) in candidates {
            let permit = match self.backends[backend].account.acquire() {
                Ok(permit) => permit,
                Err(failure) => {
                    if unavailable.as_ref().is_none_or(|old| failure.1 < old.1) {
                        unavailable = Some(failure);
                    }
                    continue;
                }
            };
            if let Some(key) = session {
                state.bind(key, backend, connection.map(|c| Arc::downgrade(&c.alive)));
            }
            state.next = (backend + 1) % count;
            return Ok(Selected {
                backend,
                endpoint,
                permit,
                model: hints.model,
                affinity: if !continuations.is_empty() {
                    "continuation"
                } else if pinned.is_none() {
                    "new"
                } else if connection.is_some() {
                    "connection"
                } else {
                    "session"
                },
            });
        }
        let (status, delay) = unavailable.expect("nonempty backend candidates");
        let mut failure = Unavailable::busy(status, delay);
        failure.backend = pinned;
        Err(failure)
    }

    pub fn observe(&self, backend: usize, status: u16, headers: &HeaderMap) {
        self.backends[backend].account.observe(status, headers);
    }

    pub fn transport_failed(&self, backend: usize) {
        if self.pooled {
            self.backends[backend]
                .account
                .back_off(503, Duration::from_secs(1));
        }
    }

    pub fn response_binding(
        self: &Arc<Self>,
        backend: usize,
        path: &str,
    ) -> Option<ResponseBinding> {
        (self.pooled && family(path).ends_with("/responses")).then(|| ResponseBinding {
            routing: self.clone(),
            backend,
            family: family(path).into(),
        })
    }
}

#[derive(Clone)]
pub(super) struct ResponseBinding {
    routing: Arc<Routing>,
    backend: usize,
    family: String,
}

impl ResponseBinding {
    pub fn observe(&self, value: &serde_json::Value) {
        let response = value.get("response").unwrap_or(value);
        for (kind, id) in [
            (
                "response",
                response
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|_| {
                        response.get("object").and_then(serde_json::Value::as_str)
                            == Some("response")
                    }),
            ),
            (
                "conversation",
                response.get("conversation").and_then(|v| {
                    v.as_str()
                        .or_else(|| v.get("id").and_then(serde_json::Value::as_str))
                }),
            ),
        ] {
            let Some(id) = id.filter(|id| !id.is_empty() && id.len() <= 1024) else {
                continue;
            };
            let key = self.routing.key(kind, &[&self.family, id]);
            self.routing
                .state
                .lock()
                .unwrap()
                .bind(key, self.backend, None);
        }
    }
}

pub(super) fn retry_delay(headers: &HeaderMap) -> Duration {
    let value = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok());
    value
        .and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
                .or_else(|| {
                    httpdate::parse_http_date(value)
                        .ok()
                        .map(|date| date.duration_since(SystemTime::now()).unwrap_or_default())
                })
        })
        .unwrap_or(Duration::from_secs(1))
        .max(Duration::from_secs(1))
}

#[cfg(test)]
mod tests;
