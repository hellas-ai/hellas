//! A generic HTTPS driver. The URL and TLS contract are in the signed input;
//! provider credentials are origin-scoped and held in memory.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt as _;
use hellas_executor::{
    FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchCall, FetchProjector,
    FetchProvider, FetchProviderError, FetchProviderFuture, FetchProviderResponse,
    FetchProviderResponseHead, FetchRequestView, HttpResponseHead, PreparedFetchRequest,
    ProjectedFetch,
};
use hellas_rpc::http_fetch::{HttpFetchRequest, check_headers};
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason};
use hellas_rpc::{ContentId, FetchEnvironment};
use reqwest::{
    Url,
    header::{HeaderName, HeaderValue},
};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tracing::Instrument;
mod config;
mod tls;
pub use config::{CredentialRefresh, HttpCredentialConfig, HttpProviderConfig, HttpSecret};

const CHUNK_BYTES: usize = 16 * 1024;
const IDLE: Duration = Duration::from_secs(90);

/// Exact DNS names (not suffixes/wildcards). Empty allows any public host.
/// Private addresses require an explicit operator opt-in and a nonempty host
/// allowlist. Resolved addresses are checked and pinned for the connection.
#[derive(Clone, Debug, Default)]
pub struct HttpEgressPolicy {
    pub allowed_hosts: Vec<String>,
    pub allow_private_addresses: bool,
}

/// In-memory account credential. The exact HTTPS origins are operator-owned;
/// neither a request URL nor its trust anchors can widen this scope.
#[derive(Clone)]
pub struct HttpCredential {
    pub allowed_origins: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub header_name: String,
    pub header_value: HttpSecret,
}

impl std::fmt::Debug for HttpCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpCredential")
            .field("allowed_origins", &self.allowed_origins)
            .field("header_name", &self.header_name)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct HttpFetchProvider {
    policy: HttpEgressPolicy,
    credentials: Arc<BTreeMap<String, HttpCredential>>,
}

fn fault(message: &'static str) -> FetchProviderError {
    FetchProviderError::failed(message)
}

impl HttpFetchProvider {
    pub fn new(
        policy: HttpEgressPolicy,
        credentials: BTreeMap<String, HttpCredential>,
    ) -> Result<Self, FetchProviderError> {
        if policy.allow_private_addresses && policy.allowed_hosts.is_empty() {
            return Err(fault("private egress requires an explicit host allowlist"));
        }
        for host in &policy.allowed_hosts {
            let parsed = Url::parse(&format!("https://{host}/"))
                .map_err(|_| fault("invalid egress host"))?;
            if parsed.host_str() != Some(host)
                || parsed.port().is_some()
                || !parsed.username().is_empty()
            {
                return Err(fault("egress hosts must be canonical names without ports"));
            }
        }
        for (alias, credential) in &credentials {
            if alias.is_empty()
                || credential.allowed_origins.is_empty()
                || credential.allowed_paths.is_empty()
                || credential.allowed_methods.is_empty()
            {
                return Err(fault(
                    "credential requires an alias, exact origins, paths and methods",
                ));
            }
            check_headers(&[(credential.header_name.clone(), String::new())], true)
                .map_err(|_| fault("invalid credential header"))?;
            if let HttpSecret::Value(value) = &credential.header_value {
                check_headers(&[(credential.header_name.clone(), value.clone())], true)
                    .map_err(|_| fault("invalid credential header"))?;
            }
            for path in &credential.allowed_paths {
                let parsed = Url::parse(&format!("https://scope.invalid{path}"))
                    .map_err(|_| fault("invalid credential path"))?;
                if !path.starts_with('/')
                    || parsed.path() != path
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                {
                    return Err(fault("credential paths must be exact canonical URL paths"));
                }
            }
            if credential.allowed_methods.iter().any(|method| {
                !matches!(
                    method.as_str(),
                    "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
                )
            }) {
                return Err(fault("invalid credential method"));
            }
            for origin in &credential.allowed_origins {
                let parsed = Url::parse(origin).map_err(|_| fault("invalid credential origin"))?;
                if parsed.scheme() != "https" || parsed.origin().ascii_serialization() != *origin {
                    return Err(fault(
                        "credential origins must be exact canonical HTTPS origins",
                    ));
                }
            }
        }
        Ok(Self {
            policy,
            credentials: Arc::new(credentials),
        })
    }

    fn credential(
        &self,
        request: &HttpFetchRequest,
        url: &Url,
    ) -> Result<Option<&HttpCredential>, FetchProviderError> {
        let Some(alias) = &request.credential else {
            return Ok(None);
        };
        let credential = self
            .credentials
            .get(alias)
            .ok_or_else(|| fault("unknown credential alias"))?;
        if !credential
            .allowed_origins
            .contains(&url.origin().ascii_serialization())
            || !credential
                .allowed_paths
                .iter()
                .any(|path| path == url.path())
            || !credential.allowed_methods.contains(&request.method)
        {
            return Err(fault(
                "credential is not authorized for this URL and method",
            ));
        }
        // A caller-controlled CA could impersonate the allowed origin and
        // steal the provider's credential. Account requests must keep the
        // public WebPKI trust boundary; additional pins can only narrow it.
        if !matches!(
            request.tls.roots,
            hellas_rpc::http_fetch::HttpTrustRoots::WebPki
        ) {
            return Err(fault("provider credentials require WebPKI roots"));
        }
        if request
            .headers
            .iter()
            .any(|(name, _)| name == &credential.header_name)
        {
            return Err(fault("request overrides a provider credential header"));
        }
        Ok(Some(credential))
    }

    async fn execute(
        &self,
        prepared: PreparedFetchRequest,
    ) -> Result<FetchProviderResponse, FetchProviderError> {
        let request = HttpFetchRequest::decode(prepared.body.as_bytes())
            .map_err(|_| fault("invalid HTTPS request"))?;
        let url = request
            .parsed_url()
            .map_err(|_| fault("invalid HTTPS URL"))?;
        let host = url.host_str().ok_or_else(|| fault("missing HTTPS host"))?;
        if !self.policy.allowed_hosts.is_empty()
            && !self
                .policy
                .allowed_hosts
                .iter()
                .any(|allowed| allowed == host)
        {
            return Err(fault("HTTPS host is outside the egress policy"));
        }
        let credential = self.credential(&request, &url)?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| fault("missing HTTPS port"))?;
        let addresses: Vec<SocketAddr> =
            match url.host().ok_or_else(|| fault("missing HTTPS host"))? {
                url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
                url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
                url::Host::Domain(host) => tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio::net::lookup_host((host, port)),
                )
                .await
                .map_err(|_| fault("HTTPS DNS lookup timed out"))?
                .map_err(|_| fault("HTTPS DNS lookup failed"))?
                .take(65)
                .collect(),
            };
        if addresses.is_empty()
            || addresses.len() > 64
            || addresses.iter().any(|address| {
                !self.policy.allow_private_addresses && !public_address(address.ip())
            })
        {
            return Err(fault("HTTPS DNS addresses are outside the egress policy"));
        }
        let tls = tls::config(&request.tls).map_err(fault)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20 * 60))
            .resolve_to_addrs(host, &addresses)
            .tls_backend_preconfigured(tls)
            .build()
            .map_err(|_| fault("HTTPS client initialization failed"))?;
        let method = request
            .method
            .parse()
            .map_err(|_| fault("invalid HTTP method"))?;
        let mut outbound = client.request(method, url.clone());
        for (name, value) in &request.headers {
            outbound = outbound.header(
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| fault("invalid HTTP header"))?,
                HeaderValue::from_str(value).map_err(|_| fault("invalid HTTP header"))?,
            );
        }
        if let Some(credential) = credential {
            let secret = credential.header_value.resolve().await?;
            let mut value =
                HeaderValue::from_str(&secret).map_err(|_| fault("invalid credential header"))?;
            value.set_sensitive(true);
            outbound = outbound.header(&credential.header_name, value);
        }
        let mut trace =
            crate::responses_fetch::telemetry::Request::for_method(&url, &request.method);
        let response = trace
            .propagate(outbound)
            .body(request.body().map_err(|_| fault("invalid HTTP body"))?)
            .send()
            .instrument(trace.span.clone())
            .await
            .map_err(|_| {
                trace.fail("transport_error");
                fault("HTTPS transport or certificate verification failed")
            })?;
        trace.status(response.status().as_u16());
        // A non-2xx status is still a completed HTTP exchange. Return it, with
        // its exact body, to the authenticated client; do not log it.
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                Ok((
                    k.to_string(),
                    v.to_str()
                        .map_err(|_| fault("unsupported HTTP response header encoding"))?
                        .to_string(),
                ))
            })
            .collect::<Result<Vec<_>, FetchProviderError>>()?;
        check_headers(&headers, false).map_err(|_| fault("HTTP response header limit"))?;
        let head = HttpResponseHead {
            status: response.status().as_u16(),
            headers,
        };
        let limit = request.max_response_bytes as usize;
        let stream = async_stream::try_stream! {
            let mut upstream = response.bytes_stream();
            let mut received = 0usize;
            loop {
                let next = tokio::time::timeout(IDLE, upstream.next()).await
                    .map_err(|_| fault("HTTPS response idle timeout"))?;
                let Some(chunk) = next else { break; };
                let chunk = chunk.map_err(|_| fault("HTTPS response stream failed"))?;
                received = received.checked_add(chunk.len()).ok_or_else(|| fault("HTTPS response size overflow"))?;
                if received > limit { Err(fault("HTTPS response exceeds signed byte limit"))?; }
                // Flush each upstream delivery. Waiting for a full 16 KiB
                // record otherwise holds small SSE responses until EOF.
                for part in chunk.chunks(CHUNK_BYTES) {
                    yield part.to_vec();
                }
            }
        };
        Ok(FetchProviderResponse {
            head: FetchProviderResponseHead {
                effective_model: None,
                http: Some(head),
            },
            stream: Box::pin(trace.stream(stream)),
        })
    }
}

impl FetchProvider for HttpFetchProvider {
    fn execution_environment(&self) -> ContentId {
        FetchEnvironment::Http.manifest_id()
    }
    fn run(&self, request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
        Box::pin(self.execute(request))
    }
}

fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || (a == 192 && b == 0))
        }
        IpAddr::V6(ip) => {
            // Restrict to global unicast, excluding documentation, special
            // transition ranges, and mapped addresses.
            let s = ip.segments();
            (s[0] & 0xe000 == 0x2000)
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HttpFetchAdaptorFactory;
impl FetchAdaptorFactory for HttpFetchAdaptorFactory {
    fn execution_environment(&self) -> ContentId {
        FetchEnvironment::Http.manifest_id()
    }
    fn create(&self, call: &FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError> {
        HttpFetchRequest::decode(call.body.as_bytes())
            .map_err(|_| FetchAdaptorError::failed("invalid HTTPS request"))?;
        Ok(FetchAdaptorSession {
            request_view: FetchRequestView::from_call(call),
            provider_request: PreparedFetchRequest::new(call, call.body.clone()),
            projector: Box::new(HttpProjector { started: false }),
        })
    }
}
struct HttpProjector {
    started: bool,
}
fn event(event: HttpResponseEvent) -> Result<ProjectedFetch, FetchAdaptorError> {
    hellas_rpc::fetch::encode_fetch_event_payload(&OutputEvent::Adaptor(AdaptorEvent::Http(event)))
        .map(ProjectedFetch::Event)
        .map_err(|_| FetchAdaptorError::failed("HTTP event encoding failed"))
}
impl FetchProjector for HttpProjector {
    fn begin(
        &mut self,
        head: FetchProviderResponseHead,
    ) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if self.started || head.effective_model.is_some() {
            return Err(FetchAdaptorError::failed("invalid HTTP response head"));
        }
        let head = head
            .http
            .ok_or_else(|| FetchAdaptorError::failed("missing HTTP response head"))?;
        if !(100..=599).contains(&head.status) {
            return Err(FetchAdaptorError::failed("invalid HTTP status"));
        }
        check_headers(&head.headers, false)
            .map_err(|_| FetchAdaptorError::failed("invalid HTTP response headers"))?;
        self.started = true;
        Ok(vec![event(HttpResponseEvent::Head {
            status: head.status,
            headers: head.headers,
        })?])
    }
    fn project(&mut self, bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if !self.started {
            return Err(FetchAdaptorError::failed("HTTP body before headers"));
        }
        Ok(vec![event(HttpResponseEvent::Body {
            base64: STANDARD.encode(bytes),
        })?])
    }
    fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if !self.started {
            return Err(FetchAdaptorError::failed("HTTP response missing"));
        }
        hellas_rpc::fetch::encode_fetch_terminal_payload(&OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        })
        .map(|payload| vec![ProjectedFetch::Terminal(payload)])
        .map_err(|_| FetchAdaptorError::failed("HTTP terminal encoding failed"))
    }
}

#[cfg(test)]
mod tests;
