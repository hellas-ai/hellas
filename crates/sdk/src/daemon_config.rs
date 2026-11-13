//! The daemon's single configuration document. Runtime credentials are write-only.
use hellas_auth::authority::{ResourceId, Revision};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr, num::NonZeroUsize, path::PathBuf};
mod entries;
mod fetch;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    #[serde(default = "initial_revision")]
    pub revision: Revision,
    pub listeners: BTreeMap<String, Listener>,
    pub backends: BTreeMap<String, Backend>,
    #[serde(default)]
    pub routes: Vec<hellas_gateway::Route>,
    #[serde(default)]
    pub authority: hellas_authority::model::grant::configuration::NodeConfiguration,
    #[serde(default)]
    pub limits: Limits,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub requests_per_minute: Option<std::num::NonZeroU64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Listener {
    Http {
        bind: SocketAddr,
        #[serde(default)]
        zdr: bool,
    },
    Iroh {
        port: u16,
        backends: Vec<String>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Backend {
    pub max_in_flight: NonZeroUsize,
    #[serde(flatten)]
    pub kind: BackendKind,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackendKind {
    Local {
        #[serde(default = "gpu")]
        runtime: String,
        #[serde(default)]
        content: Vec<PathBuf>,
    },
    Grant {
        access: PathBuf,
        #[serde(default)]
        resource: Option<ResourceId>,
        #[serde(default)]
        evaluator: Option<String>,
        #[serde(default)]
        trust: Option<Trust>,
    },
    Paid {
        provider: String,
        max_price: u64,
        #[serde(default)]
        evaluator: Option<String>,
        #[serde(default)]
        trust: Option<Trust>,
    },
    Fetch {
        service: String,
        method: String,
        upstream: Upstream,
    },
}
fn gpu() -> String {
    "auto".into()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub store: PathBuf,
    pub policy: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Upstream {
    OpenaiHttp {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret: Option<String>,
    },
    Http {
        allowed_hosts: Vec<String>,
        #[serde(default)]
        allow_private_addresses: bool,
        #[serde(default)]
        credentials: BTreeMap<String, Credential>,
    },
    OpenaiResponses {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret: Option<String>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    #[serde(default = "web_pki")]
    pub trust_roots: hellas_rpc::http_fetch::HttpTrustRoots,
    pub allowed_origins: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub header_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl Default for Document {
    fn default() -> Self {
        Self {
            revision: Revision(0),
            listeners: BTreeMap::new(),
            backends: BTreeMap::new(),
            routes: vec![],
            authority: Default::default(),
            limits: Default::default(),
        }
    }
}

impl Document {
    /// Keys are inputs only. The redacted copy is the persisted echo and Watch document.
    pub fn redacted(
        &self,
    ) -> (
        Self,
        hellas_authority::model::grant::configuration::ConfigurationSecrets,
    ) {
        let mut document = self.clone();
        let mut secrets =
            hellas_authority::model::grant::configuration::ConfigurationSecrets::default();
        document.secrets(|backend, alias, secret| {
            if let Some(value) = secret.take() {
                secrets
                    .0
                    .entry(backend.into())
                    .or_default()
                    .insert(alias.into(), value);
            }
        });
        (document, secrets)
    }

    /// An omitted key retains the previously supplied value for the same entry.
    pub fn restore_secrets(
        &mut self,
        stored: &hellas_authority::model::grant::configuration::ConfigurationSecrets,
    ) {
        self.secrets(|backend, alias, secret| {
            if secret.is_none() {
                *secret = stored
                    .0
                    .get(backend)
                    .and_then(|values| values.get(alias))
                    .cloned();
            }
        });
    }

    fn secrets(&mut self, mut visit: impl FnMut(&str, &str, &mut Option<String>)) {
        for (id, backend) in &mut self.backends {
            match &mut backend.kind {
                BackendKind::Fetch {
                    upstream: Upstream::Http { credentials, .. },
                    ..
                } => {
                    for (alias, credential) in credentials {
                        visit(id, alias, &mut credential.secret);
                    }
                }
                BackendKind::Fetch {
                    upstream:
                        Upstream::OpenaiResponses { secret } | Upstream::OpenaiHttp { secret, .. },
                    ..
                } => visit(id, "", secret),
                _ => {}
            }
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.authority
            .validate()
            .map_err(|_| "invalid authority configuration")?;
        // One provider enrollment owns one transport identity and set of paid journals.
        if self
            .listeners
            .values()
            .filter(|listener| matches!(listener, Listener::Iroh { .. }))
            .count()
            > 1
        {
            return Err("a daemon has one iroh provider identity");
        }
        if self
            .backends
            .keys()
            .chain(self.listeners.keys())
            .any(|id| id.is_empty() || id.len() > 64)
        {
            return Err("invalid listener or backend id");
        }
        if self
            .backends
            .values()
            .any(|backend| backend.max_in_flight.get() > tokio::sync::Semaphore::MAX_PERMITS)
        {
            return Err("backend capacity exceeds the runtime limit");
        }
        for listener in self.listeners.values() {
            if let Listener::Iroh { backends, .. } = listener {
                let mut ids = std::collections::BTreeSet::new();
                for id in backends {
                    if !ids.insert(id) {
                        return Err("duplicate iroh backend");
                    }
                    match &self.backends.get(id).ok_or("unknown iroh backend")?.kind {
                        BackendKind::Local { .. } | BackendKind::Fetch { .. } => {}
                        _ => return Err("iroh listeners only serve local and fetch backends"),
                    }
                }
            }
        }
        for route in &self.routes {
            for id in &route.backends {
                self.backends.get(id).ok_or("unknown HTTP backend")?;
            }
        }
        Ok(())
    }

    /// Runtime aliases are resolved before checking an iroh listener's exact keys.
    pub fn validate_resolved(
        &self,
        resolved: &[hellas_gateway::BackendInfo],
    ) -> Result<(), &'static str> {
        self.validate()?;
        for listener in self.listeners.values() {
            let Listener::Iroh { backends, .. } = listener else {
                continue;
            };
            let mut keys = std::collections::BTreeSet::new();
            for id in backends {
                let key = match &self.backends[id].kind {
                    BackendKind::Local { .. } => {
                        let evaluator = resolved
                            .iter()
                            .find(|backend| backend.id == *id)
                            .and_then(|backend| backend.evaluator.as_deref())
                            .ok_or("local backend has no registered evaluator")?;
                        ("compute", evaluator, "")
                    }
                    BackendKind::Fetch {
                        service, method, ..
                    } => ("fetch", service.as_str(), method.as_str()),
                    _ => return Err("iroh listeners only serve local and fetch backends"),
                };
                if !keys.insert(key) {
                    return Err("ambiguous iroh invocation key");
                }
            }
        }
        Ok(())
    }
}

fn initial_revision() -> Revision {
    Revision(0)
}

#[cfg(test)]
mod tests;

fn web_pki() -> hellas_rpc::http_fetch::HttpTrustRoots {
    hellas_rpc::http_fetch::HttpTrustRoots::WebPki
}
