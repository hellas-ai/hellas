use super::{connection_headers, hop_header};
use axum::{body::Bytes, http::HeaderMap};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_rpc::http_fetch::{HttpFetchRequest, HttpTls, HttpTrustRoots, credential_header};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpGatewayConfig {
    /// The Fetch route, when a provider's policy does not seal one. A sealed
    /// route is taken from the policy; naming a different one is an error.
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub routes: Vec<HttpRoute>,
    #[serde(default)]
    pub backends: BTreeMap<String, HttpBackend>,
    #[serde(default = "default_concurrency")]
    pub max_in_flight: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpBackend {
    pub models: Vec<String>,
    pub credential: Option<String>,
    pub routes: Vec<HttpRoute>,
    pub max_in_flight: Option<usize>,
    /// Endpoint in the paid pool. May be omitted when there is exactly one.
    pub provider: Option<iroh::EndpointId>,
    /// Canonical resource selected within the provider's grant channel.
    #[serde(default)]
    pub resource: Option<hellas_auth::authority::ResourceId>,
    #[serde(default)]
    pub channel: Option<hellas_channel::model::grant::ChannelId>,
}

fn default_concurrency() -> usize {
    4
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRoute {
    pub path: String,
    pub method: String,
    pub url: String,
    pub credential: Option<String>,
    #[serde(default = "public_tls")]
    pub tls: HttpTls,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default = "default_response_bytes")]
    pub max_response_bytes: u32,
    /// Exact model identifiers for this path, when the resource restricts it.
    #[serde(default)]
    pub models: Option<Vec<String>>,
}

fn default_response_bytes() -> u32 {
    hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES
}

pub(super) fn public_tls() -> HttpTls {
    HttpTls {
        roots: HttpTrustRoots::WebPki,
        spki_sha256: vec![],
    }
}

impl HttpGatewayConfig {
    /// Checks routes and backend limits, as the gateway does before it starts.
    pub fn validate(&self) -> crate::GatewayResult<()> {
        if self.routes.is_empty() == self.backends.is_empty() {
            return Err(crate::GatewayConfigError::RouteMode.into());
        }
        if !(self.max_in_flight > 0 && self.max_in_flight <= 1024) {
            return Err(crate::GatewayConfigError::HttpConcurrency.into());
        }
        if !self.routes.is_empty() {
            return validate_routes(&self.routes);
        }
        if self.backends.len() > 256 {
            return Err(crate::GatewayConfigError::BackendCount.into());
        }
        for (name, backend) in &self.backends {
            if name.is_empty() || name.len() > 64 {
                return Err(crate::GatewayConfigError::BackendName.into());
            }
            if !((!backend.models.is_empty() || backend.resource.is_some())
                && backend.models.len() <= 256
                && backend
                    .models
                    .iter()
                    .all(|m| !m.is_empty() && m.len() <= 256))
            {
                return Err(crate::GatewayConfigError::ModelNames.into());
            }
            if !(backend
                .max_in_flight
                .is_none_or(|n| (1..=1024).contains(&n)))
            {
                return Err(crate::GatewayConfigError::BackendConcurrency.into());
            }
            if !(backend.routes.iter().all(|r| r.credential.is_none())) {
                return Err(crate::GatewayConfigError::BackendCredential.into());
            }
            validate_routes(&backend.routes)?;
        }
        let mut grant_paths = BTreeMap::<(&str, &str), (bool, bool)>::new();
        for backend in self
            .backends
            .values()
            .filter(|backend| backend.resource.is_some())
        {
            for route in &backend.routes {
                let flags = grant_paths.entry((&route.path, &route.method)).or_default();
                if route.models.is_some() {
                    flags.0 = true;
                } else {
                    flags.1 = true;
                }
            }
        }
        if grant_paths
            .values()
            .any(|(restricted, unrestricted)| *restricted && *unrestricted)
        {
            return Err(crate::GatewayConfigError::ModelNames.into());
        }
        Ok(())
    }
}

fn validate_routes(routes: &[HttpRoute]) -> crate::GatewayResult<()> {
    if routes.is_empty() {
        return Err(crate::GatewayConfigError::EmptyRoutes.into());
    }
    let mut paths = std::collections::BTreeSet::new();
    for route in routes {
        if let Some(models) = &route.models {
            let mut unique = std::collections::BTreeSet::new();
            if models.is_empty()
                || models.len() > 128
                || models
                    .iter()
                    .any(|model| model.is_empty() || model.len() > 256 || !unique.insert(model))
            {
                return Err(crate::GatewayConfigError::ModelNames.into());
            }
        }
        if !route.path.starts_with('/') || route.path.contains(['?', '#', '{', '}']) {
            return Err(crate::GatewayConfigError::RoutePath.into());
        }
        if !(paths.insert((&route.path, &route.method))) {
            return Err(crate::GatewayConfigError::DuplicateRoute.into());
        }
        if !(route
            .headers
            .iter()
            .all(|(name, _)| !credential_header(name)))
        {
            return Err(crate::GatewayConfigError::CredentialAlias.into());
        }
        route.request(Bytes::new(), &HeaderMap::new())?.validate()?;
    }
    Ok(())
}

impl HttpRoute {
    pub(super) fn account(&self) -> String {
        match &self.credential {
            Some(alias) => format!("credential:{alias}"),
            None => format!(
                "origin:{}",
                self.url
                    .parse::<reqwest::Url>()
                    .expect("validated URL")
                    .origin()
                    .ascii_serialization()
            ),
        }
    }

    pub(super) fn request(
        &self,
        body: Bytes,
        incoming: &HeaderMap,
    ) -> crate::GatewayResult<HttpFetchRequest> {
        let mut headers = self.headers.clone();
        // Connection values are ASCII by contract; a non-UTF-8 value still
        // names its tokens, so parse lossily rather than silently keeping
        // every header it named.
        let values: Vec<String> = incoming
            .get_all("connection")
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect();
        let connection = connection_headers(
            std::iter::repeat("connection").zip(values.iter().map(String::as_str)),
        );
        for (name, value) in incoming {
            let name = name.as_str();
            if !hop_header(name)
                && !connection.iter().any(|token| token == name)
                && !credential_header(name)
                && !matches!(name, "host" | "content-length" | "forwarded")
                && !name.starts_with("x-hellas-")
                && !name.starts_with("x-forwarded-")
                && !self
                    .headers
                    .iter()
                    .any(|(configured, _)| configured == name)
            {
                headers.push((name.into(), value.to_str()?.into()));
            }
        }
        Ok(HttpFetchRequest {
            url: self.url.clone(),
            method: self.method.clone(),
            headers,
            body_base64: STANDARD.encode(body),
            tls: self.tls.clone(),
            credential: self.credential.clone(),
            max_response_bytes: self.max_response_bytes,
        })
    }
}
