//! An operator's HTTPS template. Repair belongs to the signing client; a
//! provider only compares the already signed request with these terms.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_rpc::http_fetch::{
    HttpFetchRequest, HttpRequestError, HttpTls, MAX_HTTP_RESPONSE_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::model::http_usage::AccountingProfile;

/// Exact model identifiers allowed on one existing HTTPS path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathModelPolicy {
    pub path: String,
    pub models: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsResource {
    pub origin: String,
    pub paths: Vec<String>,
    pub methods: Vec<String>,
    pub credential: Option<String>,
    pub tls: HttpTls,
    pub accounting: AccountingProfile,
    pub max_output_tokens: u64,
    pub max_response_bytes: u32,
    /// Unlisted paths retain their existing unrestricted model behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_policy: Option<Vec<PathModelPolicy>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum TemplateError {
    #[error("request model is outside the resource policy")]
    Model,
    #[error("request settings are outside the resource policy")]
    Settings,
    #[error("HTTPS origin mismatch")]
    Origin,
    #[error("HTTPS path or method mismatch")]
    PathMethod,
    #[error("HTTPS trust roots or pins mismatch")]
    Tls,
    #[error("HTTPS credential mismatch")]
    Credential,
    #[error("invalid request headers")]
    Headers,
    #[error("invalid generation bound")]
    GenerationCap,
    #[error("invalid streaming usage request")]
    StreamUsage,
    #[error("response byte limit exceeds resource ceiling")]
    ResponseCap,
    #[error("malformed resource request")]
    Malformed,
}
impl From<HttpRequestError> for TemplateError {
    fn from(_: HttpRequestError) -> Self {
        Self::Malformed
    }
}
impl HttpsResource {
    pub fn validate(&self) -> Result<(), TemplateError> {
        let url = url::Url::parse(&self.origin).map_err(|_| TemplateError::Origin)?;
        if url.scheme() != "https"
            || url.origin().ascii_serialization() != self.origin
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(TemplateError::Origin);
        }
        self.tls.validate()?;
        if self.paths.is_empty()
            || self.paths.len() > 32
            || self.methods.is_empty()
            || self.methods.len() > 7
            || self
                .paths
                .iter()
                .any(|p| !p.starts_with('/') || p.starts_with("//") || p.contains(['?', '#', '\\']))
            || self.methods.iter().any(|m| {
                !matches!(
                    m.as_str(),
                    "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
                )
            })
        {
            return Err(TemplateError::PathMethod);
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_HTTP_RESPONSE_BYTES {
            return Err(TemplateError::ResponseCap);
        }
        if let Some(policies) = &self.model_policy {
            let mut paths = std::collections::BTreeSet::new();
            if policies.is_empty() || policies.len() > 32 {
                return Err(TemplateError::Model);
            }
            for policy in policies {
                let mut models = std::collections::BTreeSet::new();
                if !self.paths.contains(&policy.path)
                    || !paths.insert(&policy.path)
                    || policy.models.is_empty()
                    || policy.models.len() > 128
                    || policy
                        .models
                        .iter()
                        .any(|model| model.is_empty() || model.len() > 256 || !models.insert(model))
                {
                    return Err(TemplateError::Model);
                }
            }
        }
        if self.accounting != AccountingProfile::None && self.max_output_tokens == 0 {
            return Err(TemplateError::GenerationCap);
        }
        let sample = HttpFetchRequest {
            url: format!("{}{}", self.origin, self.paths[0]),
            method: self.methods[0].clone(),
            headers: vec![],
            body_base64: String::new(),
            tls: self.tls.clone(),
            credential: self.credential.clone(),
            max_response_bytes: self.max_response_bytes,
        };
        sample.validate()?;
        Ok(())
    }
    pub fn matches(&self, request: &HttpFetchRequest) -> Result<u64, TemplateError> {
        request.validate()?;
        let url = request.parsed_url()?;
        if url.origin().ascii_serialization() != self.origin {
            return Err(TemplateError::Origin);
        }
        if url.query().is_some()
            || !self.paths.iter().any(|p| p == url.path())
            || !self.methods.contains(&request.method)
        {
            return Err(TemplateError::PathMethod);
        }
        if request.tls != self.tls {
            return Err(TemplateError::Tls);
        }
        if request.credential != self.credential {
            return Err(TemplateError::Credential);
        }
        if request
            .headers
            .iter()
            .any(|(k, _)| hellas_rpc::http_fetch::credential_header(k))
        {
            return Err(TemplateError::Headers);
        }
        if request.max_response_bytes > self.max_response_bytes {
            return Err(TemplateError::ResponseCap);
        }
        let policy = self
            .model_policy
            .as_ref()
            .and_then(|policies| policies.iter().find(|p| p.path == url.path()));
        if policy.is_none()
            && (self.accounting == AccountingProfile::None
                || (request.body_base64.is_empty()
                    && matches!(request.method.as_str(), "GET" | "HEAD")))
        {
            return Ok(0);
        }
        let body = request.body()?;
        let encoding = request_encoding(request)?;
        let decoded = crate::model::http_usage::decode_request_body(encoding, &body)
            .map_err(|_| TemplateError::Malformed)?;
        let body: Value = crate::model::http_usage::unique_json(&decoded)
            .map_err(|_| TemplateError::Malformed)?;
        if let Some(policy) = policy {
            let model = crate::model::http_usage::request_model(&body)
                .map_err(|_| TemplateError::Model)?
                .ok_or(TemplateError::Model)?;
            if !policy.models.iter().any(|allowed| allowed == model) {
                return Err(TemplateError::Model);
            }
        }
        if self.accounting == AccountingProfile::None {
            Ok(0)
        } else {
            self.generation_cap(&body)
        }
    }
    fn generation_cap(&self, body: &Value) -> Result<u64, TemplateError> {
        let object = body.as_object().ok_or(TemplateError::Malformed)?;
        if object.get("n").is_some_and(|n| n.as_u64() != Some(1)) {
            return Err(TemplateError::GenerationCap);
        }
        let field = match self.accounting {
            AccountingProfile::OpenaiChat => "max_tokens",
            AccountingProfile::OpenaiResponses => "max_output_tokens",
            AccountingProfile::None => return Ok(0),
        };
        let cap = if self.accounting == AccountingProfile::OpenaiChat
            && object.contains_key("max_completion_tokens")
        {
            let cap = object["max_completion_tokens"]
                .as_u64()
                .ok_or(TemplateError::GenerationCap)?;
            if object.get(field).is_some_and(|v| v.as_u64() != Some(cap)) {
                return Err(TemplateError::GenerationCap);
            }
            cap
        } else {
            object
                .get(field)
                .and_then(Value::as_u64)
                .ok_or(TemplateError::GenerationCap)?
        };
        if cap == 0 || cap > self.max_output_tokens {
            return Err(TemplateError::GenerationCap);
        }
        if let Some(stream) = object.get("stream") {
            let stream = stream.as_bool().ok_or(TemplateError::StreamUsage)?;
            if stream
                && self.accounting == AccountingProfile::OpenaiChat
                && body
                    .pointer("/stream_options/include_usage")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                return Err(TemplateError::StreamUsage);
            }
        }
        Ok(cap)
    }
    /// Called before signing only. Explicit excessive caps are refused, never
    /// silently reduced. An invalid body or stream_options cannot be repaired.
    pub fn prepare(&self, request: &mut HttpFetchRequest) -> Result<u64, TemplateError> {
        if self.accounting == AccountingProfile::None
            || (request.body()?.is_empty() && matches!(request.method.as_str(), "GET" | "HEAD"))
        {
            return self.matches(request);
        }
        let raw = request.body()?;
        let decoded =
            crate::model::http_usage::decode_request_body(request_encoding(request)?, &raw)
                .map_err(|_| TemplateError::Malformed)?;
        let mut body: Value = crate::model::http_usage::unique_json(&decoded)
            .map_err(|_| TemplateError::Malformed)?;
        let object = body.as_object_mut().ok_or(TemplateError::Malformed)?;
        let field = if self.accounting == AccountingProfile::OpenaiChat {
            "max_tokens"
        } else {
            "max_output_tokens"
        };
        if !(object.contains_key(field)
            || self.accounting == AccountingProfile::OpenaiChat
                && object.contains_key("max_completion_tokens"))
        {
            object.insert(field.into(), self.max_output_tokens.into());
        }
        if object.get("stream").and_then(Value::as_bool) == Some(true)
            && self.accounting == AccountingProfile::OpenaiChat
        {
            let options = object
                .entry("stream_options")
                .or_insert_with(|| serde_json::json!({}));
            options
                .as_object_mut()
                .ok_or(TemplateError::StreamUsage)?
                .insert("include_usage".into(), true.into());
        }
        let cap = self.generation_cap(&body)?;
        let mut candidate = request.clone();
        candidate
            .headers
            .retain(|(name, _)| name != "content-encoding");
        candidate.body_base64 =
            STANDARD.encode(serde_json::to_vec(&body).map_err(|_| TemplateError::Malformed)?);
        self.matches(&candidate)?;
        *request = candidate;
        Ok(cap)
    }
}

fn request_encoding(request: &HttpFetchRequest) -> Result<Option<&str>, TemplateError> {
    let mut values = request
        .headers
        .iter()
        .filter(|(name, _)| name == "content-encoding")
        .map(|(_, value)| value.as_str());
    let first = values.next();
    if values.next().is_some() {
        return Err(TemplateError::Malformed);
    }
    Ok(first)
}
