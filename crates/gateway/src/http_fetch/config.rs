use super::*;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpGatewayConfig {
    pub service: String,
    pub method: String,
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
    pub provider: Option<Provider>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub node_id: iroh::EndpointId,
    #[serde(default)]
    pub node_addrs: Vec<std::net::SocketAddr>,
    #[serde(deserialize_with = "genesis_from_hex")]
    pub genesis: hellas_rpc::ContentId,
}

fn genesis_from_hex<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<hellas_rpc::ContentId, D::Error> {
    String::deserialize(deserializer)?
        .parse()
        .map_err(serde::de::Error::custom)
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
}

pub(super) fn public_tls() -> HttpTls {
    HttpTls {
        roots: HttpTrustRoots::WebPki,
        spki_sha256: vec![],
    }
}

impl HttpGatewayConfig {
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.routes.is_empty() != self.backends.is_empty(),
            "configure either HTTP backends or legacy routes"
        );
        ensure!(
            self.max_in_flight > 0 && self.max_in_flight <= 1024,
            "invalid HTTP concurrency limit"
        );
        if !self.routes.is_empty() {
            return validate_routes(&self.routes);
        }
        ensure!(self.backends.len() <= 256, "too many HTTP backends");
        for (name, backend) in &self.backends {
            ensure!(!name.is_empty() && name.len() <= 64, "invalid backend name");
            ensure!(
                !backend.models.is_empty()
                    && backend.models.len() <= 256
                    && backend
                        .models
                        .iter()
                        .all(|m| !m.is_empty() && m.len() <= 256),
                "backend needs explicit model names"
            );
            ensure!(
                backend
                    .max_in_flight
                    .is_none_or(|n| (1..=1024).contains(&n)),
                "invalid backend concurrency limit"
            );
            ensure!(
                backend.routes.iter().all(|r| r.credential.is_none()),
                "set the credential on the backend, not its routes"
            );
            validate_routes(&backend.routes)?;
        }
        Ok(())
    }
}

fn validate_routes(routes: &[HttpRoute]) -> anyhow::Result<()> {
    ensure!(!routes.is_empty(), "HTTP backend needs at least one route");
    let mut paths = std::collections::BTreeSet::new();
    for route in routes {
        ensure!(
            route.path.starts_with('/') && !route.path.contains(['?', '#', '{', '}']),
            "HTTP routes must be exact paths"
        );
        ensure!(
            paths.insert((&route.path, &route.method)),
            "duplicate HTTP route"
        );
        ensure!(
            route.headers.iter().all(|(name, _)| !matches!(
                name.as_str(),
                "authorization" | "x-api-key" | "cookie"
            )),
            "use a provider credential alias for authentication"
        );
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
    ) -> anyhow::Result<HttpFetchRequest> {
        let mut headers = self.headers.clone();
        let connection = connection_headers(
            incoming
                .iter()
                .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or_default())),
        );
        for (name, value) in incoming {
            let name = name.as_str();
            if !hop_header(name)
                && !connection.iter().any(|token| token == name)
                && !matches!(
                    name,
                    "host"
                        | "content-length"
                        | "authorization"
                        | "x-api-key"
                        | "api-key"
                        | "x-goog-api-key"
                        | "cookie"
                        | "forwarded"
                )
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
            max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
        })
    }
}
