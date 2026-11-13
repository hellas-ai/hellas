use crate::{
    BackendInfo, Route, WorkExecutionBackend,
    affinity::{Hints, family},
};
use axum::http::{HeaderMap, StatusCode};
use hellas_auth::authority::UnixMillis;
use hellas_rpc::ContentId;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, UNIX_EPOCH},
};

const MAX_BINDINGS: usize = 16_384;
const SESSION_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct RoutingError(pub String);

struct Binding {
    backend: Option<(String, u64)>,
    pending: Option<Arc<AtomicBool>>,
    touched: Instant,
    connection: Option<Weak<()>>,
}
#[derive(Default)]
struct State {
    bindings: HashMap<ContentId, Binding>,
    cooldown: HashMap<String, (Instant, u16)>,
    next: usize,
}

/// Session and continuation bindings shared by successive daemon snapshots.
pub struct RoutingState {
    salt: [u8; 32],
    state: Mutex<State>,
}
impl Default for RoutingState {
    fn default() -> Self {
        Self {
            salt: rand::random(),
            state: Mutex::new(State::default()),
        }
    }
}

pub(crate) struct Routing {
    pub routes: Vec<Route>,
    keys: BTreeMap<(String, String, Option<String>), usize>,
    work: Arc<dyn WorkExecutionBackend>,
    memory: Arc<RoutingState>,
    instances: BTreeMap<String, u64>,
}

#[derive(Clone)]
pub(crate) struct Selection {
    pub job: Arc<crate::jobs::Job>,
    routing: Arc<Routing>,
    candidates: Vec<String>,
    cursor: usize,
    session: Option<ContentId>,
    pub backend: Option<String>,
    pub affinity: &'static str,
    pub model: Option<String>,
}
pub(crate) struct Pending {
    routing: Arc<Routing>,
    key: ContentId,
    proposed: Arc<AtomicBool>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        let mut state = self.routing.memory.state.lock().unwrap();
        if let Some(binding) = state.bindings.get_mut(&self.key)
            && binding
                .pending
                .as_ref()
                .is_some_and(|p| Arc::ptr_eq(p, &self.proposed))
        {
            if self.proposed.load(Ordering::Acquire) {
                binding.pending = None;
            } else {
                state.bindings.remove(&self.key);
            }
        }
    }
}
impl Selection {
    pub fn next(&mut self) -> Option<String> {
        let id = self.candidates.get(self.cursor)?.clone();
        self.cursor += 1;
        self.backend = Some(id.clone());
        if let Some(key) = self.session
            && let Some(binding) = self
                .routing
                .memory
                .state
                .lock()
                .unwrap()
                .bindings
                .get_mut(&key)
            && binding.pending.is_some()
        {
            binding.backend = Some((id.clone(), self.routing.instances[&id]));
        }
        Some(id)
    }
    pub fn accept(&mut self, backend: &str) {
        let mut state = self.routing.memory.state.lock().unwrap();
        if let Some(key) = self.session
            && let Some(binding) = state.bindings.get_mut(&key)
        {
            binding.backend = Some((backend.into(), self.routing.instances[backend]));
            binding.pending = None;
        }
        state.next = state.next.wrapping_add(1);
    }
    pub fn observe(&self, status: u16, headers: &HeaderMap) {
        if let (Some(backend), Some(delay)) = (&self.backend, retry_delay(headers))
            && (status == 429 || status >= 500)
        {
            let until = Instant::now() + delay.min(Duration::from_secs(u32::MAX as u64));
            let mut state = self.routing.memory.state.lock().unwrap();
            let previous = state
                .cooldown
                .entry(backend.clone())
                .or_insert((until, status));
            if until > previous.0 {
                *previous = (until, status);
            }
        }
    }
    pub fn response_binding(&self, path: &str) -> Option<ResponseBinding> {
        if !family(path).ends_with("/responses") {
            return None;
        }
        Some(ResponseBinding {
            routing: self.routing.clone(),
            backend: (
                self.backend.clone()?,
                self.routing.instances[self.backend.as_ref()?],
            ),
            family: family(path).into(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct Unavailable {
    pub status: StatusCode,
    pub message: &'static str,
    pub retry: Option<u64>,
}
impl Unavailable {
    fn new(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            retry: None,
        }
    }
    fn conflict(message: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
    fn busy(status: u16, delay: Duration) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap(),
            message: "selected backend is temporarily unavailable",
            retry: Some(delay.as_secs().saturating_add(1)),
        }
    }
}

impl Routing {
    pub fn new(
        routes: Vec<Route>,
        work: Arc<dyn WorkExecutionBackend>,
        memory: Arc<RoutingState>,
    ) -> Result<Arc<Self>, RoutingError> {
        let backends = work.backends();
        let mut keys = BTreeMap::new();
        for (row, route) in routes.iter().enumerate() {
            let mut unique = std::collections::BTreeSet::new();
            if route.backends.is_empty()
                || route
                    .backends
                    .iter()
                    .any(|id| !unique.insert(id) || !backends.iter().any(|b| b.id == *id))
            {
                return Err(RoutingError(
                    "a route needs distinct configured backends".into(),
                ));
            }
            if let crate::Presentation::Http { targets } = &route.presentation
                && (targets.len() != route.backends.len()
                    || route.backends.iter().any(|id| !targets.contains_key(id)))
            {
                return Err(RoutingError(
                    "HTTP targets must name exactly the route's backends".into(),
                ));
            }
            for key in route.keys() {
                if !key.0.starts_with('/')
                    || key.0.contains(['?', '#', '{', '}'])
                    || key.2.as_ref().is_some_and(|model| model.is_empty())
                {
                    return Err(RoutingError("invalid route key".into()));
                }
                if keys.insert(key, row).is_some() {
                    return Err(RoutingError("duplicate route key".into()));
                }
            }
        }
        for (path, method, model) in keys.keys() {
            if model.is_some() && keys.contains_key(&(path.clone(), method.clone(), None)) {
                return Err(RoutingError(
                    "a path cannot mix named models and an unrestricted route".into(),
                ));
            }
        }
        Ok(Arc::new(Self {
            instances: backends.into_iter().map(|b| (b.id, b.instance)).collect(),
            routes,
            keys,
            work,
            memory,
        }))
    }
    fn key(&self, domain: &str, parts: &[&str]) -> ContentId {
        let mut fields: Vec<&[u8]> = vec![&self.memory.salt];
        fields.extend(parts.iter().map(|s| s.as_bytes()));
        ContentId::from_bytes(*hellas_auth::hash_tuple(domain, &fields).as_bytes())
    }
    pub fn select(
        self: &Arc<Self>,
        path: &str,
        method: &str,
        hints: Hints,
        connection: Option<&crate::ConnectionId>,
        job: Arc<crate::jobs::Job>,
    ) -> Result<(usize, Selection), Unavailable> {
        let named = self
            .keys
            .keys()
            .any(|(p, m, model)| p == path && m == method && model.is_some());
        if named && hints.model.is_none() {
            return Err(Unavailable::new(
                StatusCode::BAD_REQUEST,
                "model is required",
            ));
        }
        let row = *self
            .keys
            .get(&(
                path.into(),
                method.into(),
                if named { hints.model.clone() } else { None },
            ))
            .ok_or_else(|| {
                Unavailable::new(
                    StatusCode::NOT_FOUND,
                    "no backend serves this route and model",
                )
            })?;
        let route = &self.routes[row];
        let connection = connection.filter(|_| route.backends.len() > 1 && hints.session.is_none());
        let family = family(path);
        let model = hints.model.as_deref().unwrap_or("");
        let session = hints
            .session
            .as_ref()
            .map(|(kind, id)| self.key("session", &[family, model, kind, id]))
            .or_else(|| {
                connection.map(|c| self.key("connection", &[family, model, &c.id.to_string()]))
            });
        let continuations: Vec<_> = [
            ("response", &hints.previous),
            ("conversation", &hints.conversation),
        ]
        .into_iter()
        .filter_map(|(kind, id)| id.as_ref().map(|id| self.key(kind, &[family, id])))
        .collect();
        let mut state = self.memory.state.lock().unwrap();
        let now = Instant::now();
        state.bindings.retain(|_, b| {
            now.duration_since(b.touched) < SESSION_IDLE
                && b.connection.as_ref().is_none_or(|c| c.strong_count() > 0)
        });
        let mut pinned = None;
        for (key, required) in continuations
            .iter()
            .map(|key| (*key, true))
            .chain(session.map(|key| (key, false)))
        {
            let Some(binding) = state.bindings.get_mut(&key) else {
                if required {
                    return Err(Unavailable::conflict(
                        "unknown or expired server-side continuation; resend full context",
                    ));
                }
                continue;
            };
            if let Some(proposed) = &binding.pending {
                if !proposed.load(Ordering::Acquire) {
                    return Err(Unavailable::busy(503, Duration::ZERO));
                }
                binding.pending = None;
            }
            let backend = binding
                .backend
                .clone()
                .ok_or_else(|| Unavailable::conflict("ambiguous server-side continuation"))?;
            if self.instances.get(&backend.0) != Some(&backend.1) {
                return Err(Unavailable::conflict(
                    "session backend was replaced; resend full context",
                ));
            }
            if pinned.as_ref().is_some_and(|p| *p != backend) {
                return Err(Unavailable::conflict(
                    "conflicting session or continuation backends",
                ));
            }
            binding.touched = now;
            pinned = Some(backend);
        }
        if pinned
            .as_ref()
            .is_some_and(|(id, _)| !route.backends.contains(id))
        {
            return Err(Unavailable::conflict(
                "session backend cannot serve this model and route",
            ));
        }
        let backends = self.work.backends();
        let count = route.backends.len();
        let mut candidates: Vec<_> = route
            .backends
            .iter()
            .enumerate()
            .filter(|(_, id)| pinned.as_ref().is_none_or(|p| p.0 == **id))
            .filter_map(|(position, id)| {
                backends.iter().find(|b| b.id == *id).map(|b| (position, b))
            })
            .collect();
        candidates.sort_by_cached_key(|(position, b)| order(b, *position, count, state.next));
        let mut unavailable = (503, Duration::ZERO);
        candidates.retain(|(_, backend)| {
            if let Some((until, status)) = state.cooldown.get(&backend.id)
                && *until > now
            {
                unavailable = (*status, until.saturating_duration_since(now));
                false
            } else {
                backend.in_flight < backend.max_in_flight
            }
        });
        if candidates.is_empty() {
            return Err(Unavailable::busy(unavailable.0, unavailable.1));
        }
        let pending = if let Some(key) = session.filter(|key| !state.bindings.contains_key(key)) {
            if state.bindings.len() >= MAX_BINDINGS {
                return Err(Unavailable::busy(503, Duration::ZERO));
            }
            state.bindings.insert(
                key,
                Binding {
                    backend: None,
                    pending: Some(job.proposal()),
                    touched: now,
                    connection: connection.map(|c| Arc::downgrade(&c.alive)),
                },
            );
            Some(Pending {
                routing: self.clone(),
                key,
                proposed: job.proposal(),
            })
        } else {
            None
        };
        *job.binding.lock().unwrap() = pending;
        Ok((
            row,
            Selection {
                job,
                routing: self.clone(),
                candidates: candidates.into_iter().map(|(_, b)| b.id.clone()).collect(),
                cursor: 0,
                session,
                backend: None,
                affinity: if !continuations.is_empty() {
                    "continuation"
                } else if pinned.is_none() {
                    "new"
                } else if connection.is_some() {
                    "connection"
                } else {
                    "session"
                },
                model: hints.model,
            },
        ))
    }
}
fn order(
    backend: &BackendInfo,
    position: usize,
    count: usize,
    next: usize,
) -> (bool, usize, usize) {
    if backend.down {
        (true, 0, position)
    } else {
        (
            false,
            backend.in_flight.saturating_mul(1024) / backend.max_in_flight.max(1),
            (position + count - next % count) % count,
        )
    }
}

#[derive(Clone)]
pub(crate) struct ResponseBinding {
    routing: Arc<Routing>,
    backend: (String, u64),
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
            let mut state = self.routing.memory.state.lock().unwrap();
            if let Some(binding) = state.bindings.get_mut(&key) {
                if binding.backend.as_ref() != Some(&self.backend) {
                    binding.backend = None;
                }
                binding.touched = Instant::now();
            } else if state.bindings.len() < MAX_BINDINGS {
                state.bindings.insert(
                    key,
                    Binding {
                        backend: Some(self.backend.clone()),
                        pending: None,
                        touched: Instant::now(),
                        connection: None,
                    },
                );
            }
        }
    }
}
fn retry_delay(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get("retry-after")?.to_str().ok()?;
    value
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
        .or_else(|| {
            let date = httpdate::parse_http_date(value).ok()?;
            let now = UNIX_EPOCH + Duration::from_millis(UnixMillis::now().ok()?.0);
            Some(date.duration_since(now).unwrap_or_default())
        })
}

#[cfg(test)]
mod tests;
