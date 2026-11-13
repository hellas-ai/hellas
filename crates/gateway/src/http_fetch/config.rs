use super::{connection_headers, hop_header};
use axum::{body::Bytes, http::HeaderMap};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_rpc::http_fetch::{HttpFetchRequest, HttpTls, HttpTrustRoots, credential_header};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
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

impl HttpRoute {
    pub fn validate(&self) -> crate::GatewayResult<()> {
        let route = self;
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
        if !(route
            .headers
            .iter()
            .all(|(name, _)| !credential_header(name)))
        {
            return Err(crate::GatewayConfigError::CredentialAlias.into());
        }
        route.request(Bytes::new(), &HeaderMap::new())?.validate()?;
        Ok(())
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
