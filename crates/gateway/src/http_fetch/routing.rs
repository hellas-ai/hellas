use super::*;

pub(super) struct Account {
    pub(super) slots: Arc<Semaphore>,
    pub(super) backoff: Mutex<Option<(Instant, u16)>>,
}

impl Account {
    pub(super) fn cooldown(&self) -> Option<(u16, Duration)> {
        let (until, status) = (*self.backoff.lock().unwrap())?;
        let delay = until.saturating_duration_since(Instant::now());
        (!delay.is_zero()).then_some((status, delay))
    }

    pub(super) fn observe(&self, status: u16, headers: &HeaderMap) {
        if status == 429 || (status >= 500 && headers.contains_key("retry-after")) {
            let delay = retry_delay(headers).min(Duration::from_secs(u32::MAX as u64));
            let until = Instant::now() + delay;
            let mut backoff = self.backoff.lock().unwrap();
            if backoff.is_none_or(|(previous, _)| until > previous) {
                *backoff = Some((until, status));
            }
        }
    }
}

use super::affinity::{Hints, family};
use hellas_rpc::ContentId;
use std::collections::HashMap;
use tokio::sync::OwnedSemaphorePermit;

const MAX_BINDINGS: usize = 16_384;
const SESSION_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

pub(super) struct Backend {
    pub name: String,
    pub models: Vec<String>,
    pub routes: Vec<HttpRoute>,
    pub remote: ExecutionRoute,
    capacity: usize,
    account: Arc<Account>,
}

struct Binding {
    backend: usize,
    touched: Instant,
    connection: Option<std::sync::Weak<()>>,
}

#[derive(Default)]
struct State {
    bindings: HashMap<ContentId, Binding>,
    next: usize,
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
    fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message,
            retry: None,
            backend: None,
        }
    }
    fn busy(status: u16, delay: Duration) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap(),
            message: "selected backend is temporarily unavailable",
            retry: Some(delay.as_secs() + 1),
            backend: None,
        }
    }
}

impl Routing {
    pub fn new(
        config: &HttpGatewayConfig,
        remote: ExecutionRoute,
        trust: hellas_client::ProviderTrustAnchor,
    ) -> anyhow::Result<Self> {
        let mut backends = Vec::new();
        let mut accounts: BTreeMap<String, (usize, Arc<Account>)> = BTreeMap::new();
        let mut add = |name: String,
                       models: Vec<String>,
                       routes: Vec<HttpRoute>,
                       remote: ExecutionRoute,
                       limit: usize|
         -> anyhow::Result<()> {
            let account = routes[0].account();
            ensure!(
                routes.iter().all(|r| r.account() == account),
                "a backend must use one account or origin"
            );
            // The enrollment pin identifies the provider even when one route
            // uses discovery and another dials that provider directly.
            let scope = match &remote {
                ExecutionRoute::RemoteDirect(target) => {
                    target.provider_trust.expected_genesis.to_string()
                }
                ExecutionRoute::RemoteDiscovery { provider_trust, .. } => {
                    provider_trust.expected_genesis.to_string()
                }
                ExecutionRoute::Local => unreachable!(),
            };
            let (configured_limit, shared) = accounts
                .entry(format!("{scope}:{account}"))
                .or_insert_with(|| {
                    (
                        limit,
                        Arc::new(Account {
                            slots: Arc::new(Semaphore::new(limit)),
                            backoff: Mutex::new(None),
                        }),
                    )
                });
            ensure!(
                *configured_limit == limit,
                "shared accounts require the same concurrency limit"
            );
            let shared = shared.clone();
            backends.push(Backend {
                name,
                models,
                routes,
                remote,
                capacity: limit,
                account: shared,
            });
            Ok(())
        };
        if config.backends.is_empty() {
            for (index, route) in config.routes.iter().enumerate() {
                add(
                    format!("route-{index}"),
                    vec![],
                    vec![route.clone()],
                    remote.clone(),
                    config.max_in_flight,
                )?;
            }
        } else {
            for (name, backend) in &config.backends {
                let remote = if let Some(provider) = &backend.provider {
                    let mut trust = trust.clone();
                    trust.expected_genesis = provider.genesis;
                    ExecutionRoute::remote(
                        Some(provider.node_id),
                        provider.node_addrs.clone(),
                        0,
                        trust,
                    )
                } else {
                    remote.clone()
                };
                let routes = backend
                    .routes
                    .iter()
                    .cloned()
                    .map(|mut r| {
                        r.credential = backend.credential.clone();
                        r
                    })
                    .collect();
                add(
                    name.clone(),
                    backend.models.clone(),
                    routes,
                    remote,
                    backend.max_in_flight.unwrap_or(config.max_in_flight),
                )?;
            }
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
            Some(Hints::read(headers, body).map_err(|message| Unavailable {
                status: StatusCode::BAD_REQUEST,
                message,
                retry: None,
                backend: None,
            })?)
        } else {
            None
        };
        let model = hints.as_ref().and_then(|h| h.model.as_deref());
        let mut candidates = Vec::new();
        for (index, backend) in self.backends.iter().enumerate() {
            if let Some(endpoint) = backend
                .routes
                .iter()
                .position(|r| r.path == path && r.method == method)
            {
                if model.is_none_or(|model| {
                    backend.models.is_empty() || backend.models.iter().any(|m| m == model)
                }) {
                    candidates.push((index, endpoint));
                }
            }
        }
        if candidates.is_empty() {
            return Err(Unavailable {
                status: StatusCode::NOT_FOUND,
                message: "no backend serves this route and model",
                retry: None,
                backend: None,
            });
        }
        if self.pooled
            && model.is_none()
            && !body.is_empty()
            && !hints
                .as_ref()
                .is_some_and(|h| h.previous.is_some() || h.conversation.is_some())
        {
            return Err(Unavailable {
                status: StatusCode::BAD_REQUEST,
                message: "model is required",
                retry: None,
                backend: None,
            });
        }
        let family = family(path);
        let session = hints
            .as_ref()
            .and_then(|h| h.session.as_ref())
            .map(|(kind, id)| self.key("session", &[family, model.unwrap_or(""), kind, id]));
        let connection_key =
            connection
                .filter(|_| self.pooled && session.is_none())
                .map(|connection| {
                    self.key(
                        "connection",
                        &[family, model.unwrap_or(""), &connection.id.to_string()],
                    )
                });
        let affinity_key = session.or(connection_key);
        let state_keys: Vec<_> = hints
            .as_ref()
            .into_iter()
            .flat_map(|h| {
                [
                    h.previous
                        .as_ref()
                        .map(|id| self.key("response", &[family, id])),
                    h.conversation
                        .as_ref()
                        .map(|id| self.key("conversation", &[family, id])),
                ]
            })
            .flatten()
            .collect();
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        state.bindings.retain(|_, b| {
            now.duration_since(b.touched) < SESSION_IDLE
                && b.connection.as_ref().is_none_or(|c| c.strong_count() > 0)
        });
        let mut pinned = None;
        for key in &state_keys {
            let binding = state.bindings.get_mut(key).ok_or_else(|| {
                Unavailable::conflict(
                    "unknown or expired server-side continuation; resend full context",
                )
            })?;
            binding.touched = now;
            if pinned.is_some_and(|p| p != binding.backend) {
                return Err(Unavailable::conflict("conflicting continuation backends"));
            }
            pinned = Some(binding.backend);
        }
        if let Some(binding) = affinity_key.and_then(|k| state.bindings.get_mut(&k)) {
            binding.touched = now;
            if pinned.is_some_and(|p| p != binding.backend) {
                return Err(Unavailable::conflict(
                    "session and continuation refer to different backends",
                ));
            }
            pinned = Some(binding.backend);
        }
        if let Some(index) = pinned {
            candidates.retain(|(backend, _)| *backend == index);
            if candidates.is_empty() {
                return Err(Unavailable::conflict(
                    "session backend cannot serve this model and route",
                ));
            }
        }
        if affinity_key.is_some_and(|key| !state.bindings.contains_key(&key))
            && state.bindings.len() >= MAX_BINDINGS
        {
            return Err(Unavailable::busy(503, Duration::ZERO));
        }
        let count = self.backends.len();
        candidates.sort_by_key(|(index, _)| {
            let backend = &self.backends[*index];
            // Least active first, rotating equal candidates. Shared account permits
            // also cover aliases used by multiple model configurations.
            (
                (backend.capacity - backend.account.slots.available_permits()) * 1024
                    / backend.capacity,
                (*index + count - state.next) % count,
            )
        });
        let mut unavailable = None;
        for (backend, endpoint) in candidates {
            let account = &self.backends[backend].account;
            if let Some((status, delay)) = account.cooldown() {
                if unavailable.as_ref().is_none_or(|(_, old)| delay < *old) {
                    unavailable = Some((status, delay));
                }
                continue;
            }
            let Ok(permit) = account.slots.clone().try_acquire_owned() else {
                unavailable = Some((503, Duration::ZERO));
                continue;
            };
            for key in state_keys.iter().copied().chain(affinity_key) {
                state.bindings.insert(
                    key,
                    Binding {
                        backend,
                        touched: now,
                        connection: if Some(key) == connection_key {
                            connection.map(|c| Arc::downgrade(&c.alive))
                        } else {
                            None
                        },
                    },
                );
            }
            state.next = (backend + 1) % count;
            return Ok(Selected {
                backend,
                endpoint,
                permit,
                model: model.map(str::to_owned),
                affinity: if !state_keys.is_empty() {
                    "continuation"
                } else if pinned.is_some() && connection_key.is_some() {
                    "connection"
                } else if pinned.is_some() {
                    "session"
                } else {
                    "new"
                },
            });
        }
        let (status, delay) = unavailable.unwrap_or((503, Duration::ZERO));
        let mut failure = Unavailable::busy(status, delay);
        failure.backend = pinned;
        Err(failure)
    }

    pub fn observe(&self, backend: usize, status: u16, headers: &HeaderMap) {
        self.backends[backend].account.observe(status, headers);
    }

    pub fn transport_failed(&self, backend: usize) {
        if self.pooled {
            self.observe(
                backend,
                503,
                &HeaderMap::from_iter([(
                    "retry-after".parse().unwrap(),
                    HeaderValue::from_static("1"),
                )]),
            );
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
            let mut state = self.routing.state.lock().unwrap();
            // Never silently overwrite another account's identifier or evict a
            // live session. An unrecorded continuation will fail closed later.
            if let Some(existing) = state.bindings.get_mut(&key) {
                if existing.backend != self.backend {
                    existing.backend = usize::MAX;
                }
                existing.touched = Instant::now();
            } else if state.bindings.len() < MAX_BINDINGS {
                state.bindings.insert(
                    key,
                    Binding {
                        backend: self.backend,
                        touched: Instant::now(),
                        connection: None,
                    },
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
