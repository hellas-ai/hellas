//! Document edits shared by the command line and embedding applications.
use super::*;
use hellas_gateway::{HttpRoute, HttpTarget, Presentation, Route};
use hellas_rpc::http_fetch::{HttpTls, HttpTrustRoots};

impl Document {
    pub fn add_upstream(
        &mut self,
        name: &str,
        url: &str,
        secret: Option<String>,
    ) -> Result<(), crate::daemon::Error> {
        if self.backends.contains_key(name) {
            return Err("backend already exists".into());
        }
        let upstream = Upstream::OpenaiHttp {
            url: url.trim_end_matches('/').into(),
            secret,
        };
        upstream.http_configuration()?;
        self.backends.insert(
            name.into(),
            Backend {
                max_in_flight: NonZeroUsize::new(8).unwrap(),
                kind: BackendKind::Fetch {
                    service: name.into(),
                    method: "request".into(),
                    upstream,
                },
            },
        );
        Ok(())
    }

    pub fn add_upstream_model(
        &mut self,
        model: &str,
        id: &str,
    ) -> Result<(), crate::daemon::Error> {
        let BackendKind::Fetch {
            service,
            method,
            upstream: Upstream::OpenaiHttp { url, secret: _ },
        } = &self.backends.get(id).ok_or("unknown upstream")?.kind
        else {
            return Err("backend is not an OpenAI-compatible HTTP upstream".into());
        };
        let base = url.strip_suffix("/v1").unwrap_or(url);
        let routes =
            ["/v1/responses", "/v1/chat/completions", "/v1/completions"].map(|path| Route {
                backends: vec![id.into()],
                presentation: Presentation::Http {
                    targets: [(
                        id.into(),
                        HttpTarget {
                            service: service.clone(),
                            method: method.clone(),
                            route: HttpRoute {
                                path: path.into(),
                                method: "POST".into(),
                                url: format!("{base}{path}"),
                                credential: Some("api".into()),
                                tls: HttpTls {
                                    roots: HttpTrustRoots::WebPki,
                                    spki_sha256: vec![],
                                },
                                headers: vec![],
                                max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
                                models: Some(vec![model.into()]),
                            },
                        },
                    )]
                    .into(),
                },
            });
        for route in routes {
            self.add_route(route)?;
        }
        Ok(())
    }

    /// Repeated model selections form one row, preserving candidate order.
    pub fn add_route(&mut self, route: Route) -> Result<(), crate::daemon::Error> {
        let Some(existing) = self
            .routes
            .iter_mut()
            .find(|existing| existing.keys() == route.keys())
        else {
            self.routes.push(route);
            return Ok(());
        };
        if route
            .backends
            .iter()
            .any(|id| existing.backends.contains(id))
        {
            return Err("route already includes this backend".into());
        }
        match (&mut existing.presentation, &route.presentation) {
            (Presentation::Http { targets }, Presentation::Http { targets: added }) => {
                targets.extend(added.clone())
            }
            (old, new) if serde_json::to_vec(old)? == serde_json::to_vec(new)? => {}
            _ => return Err("route presentations disagree".into()),
        }
        existing.backends.extend(route.backends);
        Ok(())
    }

    pub fn remove_backend(&mut self, id: &str) -> Result<(), crate::daemon::Error> {
        if self.backends.remove(id).is_none() {
            return Err("unknown backend".into());
        }
        for listener in self.listeners.values_mut() {
            if let Listener::Iroh { backends, .. } = listener {
                backends.retain(|backend| backend != id);
            }
        }
        for route in &mut self.routes {
            route.backends.retain(|backend| backend != id);
            if let Presentation::Http { targets } = &mut route.presentation {
                targets.remove(id);
            }
        }
        self.routes.retain(|route| !route.backends.is_empty());
        Ok(())
    }
}

impl Upstream {
    pub(super) fn http_configuration(&self) -> Result<Self, crate::daemon::Error> {
        let Self::OpenaiHttp { url, secret } = self else {
            return Err("not an HTTP upstream".into());
        };
        let parsed = url::Url::parse(url)?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(
                "upstream must be an HTTPS API URL without credentials, query or fragment".into(),
            );
        }
        let base = parsed.path().trim_end_matches('/');
        let base = base.strip_suffix("/v1").unwrap_or(base);
        Ok(Self::Http {
            allowed_hosts: vec![parsed.host_str().ok_or("upstream has no host")?.into()],
            allow_private_addresses: false,
            credentials: [(
                "api".into(),
                Credential {
                    allowed_origins: vec![parsed.origin().ascii_serialization()],
                    allowed_paths: ["responses", "chat/completions", "completions"]
                        .map(|path| format!("{base}/v1/{path}"))
                        .into(),
                    allowed_methods: vec!["POST".into()],
                    header_name: "authorization".into(),
                    secret: secret.as_ref().map(|key| format!("Bearer {key}")),
                },
            )]
            .into(),
        })
    }
}
