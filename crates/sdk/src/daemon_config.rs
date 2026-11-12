//! The daemon's single configuration document. Runtime credentials are write-only.
use hellas_auth::authority::{ResourceId, Revision};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr, num::NonZeroUsize, path::PathBuf};

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
        profile: Option<PathBuf>,
        #[serde(default)]
        zdr: bool,
    },
    Iroh {
        port: u16,
        backends: Vec<String>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    Http {
        allowed_hosts: Vec<String>,
        #[serde(default)]
        allow_private_addresses: bool,
        #[serde(default)]
        credentials: BTreeMap<String, Credential>,
    },
    OpenaiResponses {
        #[serde(default, skip_serializing)]
        secret: Option<String>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub allowed_origins: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub header_name: String,
    #[serde(default, skip_serializing)]
    pub secret: Option<String>,
}

impl Document {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.backends.is_empty() || self.listeners.is_empty() {
            return Err("configure at least one listener and backend");
        }
        if self
            .backends
            .keys()
            .chain(self.listeners.keys())
            .any(|id| id.is_empty() || id.len() > 64)
        {
            return Err("invalid listener or backend id");
        }
        for listener in self.listeners.values() {
            match listener {
                Listener::Iroh { backends, .. } => {
                    let mut keys = std::collections::BTreeSet::new();
                    for id in backends {
                        let backend = self.backends.get(id).ok_or("unknown iroh backend")?;
                        let key = match &backend.kind {
                            BackendKind::Local { runtime, .. } => ("compute", runtime.as_str(), ""),
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
                Listener::Http { bind, profile, .. }
                    if !bind.ip().is_loopback() && profile.is_none() =>
                {
                    return Err("remote HTTP requires an authority profile");
                }
                _ => {}
            }
        }
        for route in &self.routes {
            for id in &route.backends {
                if matches!(
                    self.backends.get(id).ok_or("unknown HTTP backend")?.kind,
                    BackendKind::Fetch { .. }
                ) {
                    return Err("HTTP routes only use local, grant and paid backends");
                }
            }
        }
        Ok(())
    }
}

fn initial_revision() -> Revision {
    Revision(0)
}
