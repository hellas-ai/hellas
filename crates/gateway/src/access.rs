//! HTTP admission through the host's existing Auth authority.
use axum::body::Body;
use axum::http::{HeaderMap, Request, Response, StatusCode, header};
use futures::future::BoxFuture;
use hellas_auth::authority::{CredentialId, CredentialSecret, GrantId};
use hellas_authority::node::NodeCoordinator;
use std::{
    fmt,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

/// A provisioned bearer credential scoped to gateway.invoke, authorized by
/// `authorization`. HTTP requests present a bearer authorized by that grant,
/// or one whose subject holds its own current grant of gateway.invoke alone. The host owns the authority
/// writer; starting a listener never creates grants or credentials.
#[derive(Clone)]
pub struct GatewayAccess {
    node: NodeCoordinator,
    authorization: GrantId,
    credential: Arc<CredentialSecret>,
}
impl GatewayAccess {
    pub async fn new(
        node: NodeCoordinator,
        authorization: GrantId,
        credential: CredentialSecret,
    ) -> crate::GatewayResult<Self> {
        let access = Self {
            node,
            authorization,
            credential: Arc::new(credential),
        };
        access.validate().await?;
        Ok(access)
    }

    #[cfg(test)]
    pub(crate) fn node(&self) -> NodeCoordinator {
        self.node.clone()
    }

    /// The gateway's own credential, under its configured grant.
    pub async fn validate(&self) -> crate::GatewayResult<()> {
        let caller = self.node.authenticate(&self.credential).await?;
        self.node
            .authorize_gateway(&caller, self.authorization)
            .await
            .map_err(Into::into)
    }

    /// Secret material for an explicitly authorized control response or child.
    pub fn bearer(&self) -> String {
        format!(
            "{}{}",
            self.credential.id(),
            hellas_rpc::provenance::encode_hex(self.credential.expose_secret())
        )
    }
}

async fn authorizes(node: &NodeCoordinator, headers: &HeaderMap) -> Option<crate::jobs::Origin> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.as_bytes();
    let (scheme, text) = value.split_at_checked(7)?;
    if !scheme.eq_ignore_ascii_case(b"bearer ") {
        return None;
    }
    let Ok(text) = std::str::from_utf8(text) else {
        return None;
    };
    let Ok(bytes) = hellas_auth::hex::parse_lower::<48>(text) else {
        return None;
    };
    let Ok(id) = CredentialId::try_from(&bytes[..16]) else {
        return None;
    };
    let Ok(secret) = bytes[16..].try_into() else {
        return None;
    };
    let caller = node
        .authenticate(&CredentialSecret::from_parts(id, secret))
        .await
        .ok()?;
    node.authorize_gateway_bearer(&caller).await.ok()?;
    Some(crate::jobs::Origin::Http {
        credential: id.to_string(),
    })
}
impl fmt::Debug for GatewayAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayAccess(redacted)")
    }
}

/// Whether a bearer-less request may be admitted on a listener that does not
/// require authentication. The listener itself is bound to loopback (checked
/// by configuration), so the peer is local. The Host must also name a loopback
/// address, which defeats DNS rebinding, and any browser `Origin` must be
/// loopback too, which defeats cross-site requests from web pages.
fn loopback_request<B>(request: &Request<B>) -> bool {
    let headers = request.headers();
    let mut hosts = headers.get_all(header::HOST).iter();
    let host = match (request.uri().authority(), hosts.next(), hosts.next()) {
        (Some(authority), _, _) => Some(authority.host().to_owned()),
        (None, Some(host), None) => host
            .to_str()
            .ok()
            .and_then(|host| host.parse::<axum::http::uri::Authority>().ok())
            .map(|authority| authority.host().to_owned()),
        _ => None,
    };
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let origin = match (origins.next(), origins.next()) {
        (None, _) => true,
        (Some(origin), None) => origin
            .to_str()
            .ok()
            .and_then(|origin| origin.parse::<axum::http::Uri>().ok())
            .is_some_and(|origin| {
                matches!(origin.scheme_str(), Some("http" | "https"))
                    && origin.host().is_some_and(loopback_host)
            }),
        _ => false,
    };
    host.as_deref().is_some_and(loopback_host) && origin
}

fn loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[derive(Clone)]
pub(crate) struct BearerLayer {
    node: NodeCoordinator,
    require_auth: bool,
}
impl BearerLayer {
    pub(crate) fn new(node: NodeCoordinator, require_auth: bool) -> Self {
        Self { node, require_auth }
    }
}
impl<S> Layer<S> for BearerLayer {
    type Service = BearerService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        BearerService {
            inner,
            node: self.node.clone(),
            require_auth: self.require_auth,
        }
    }
}
#[derive(Clone)]
pub(crate) struct BearerService<S> {
    inner: S,
    node: NodeCoordinator,
    require_auth: bool,
}
impl<S, B> Service<Request<B>> for BearerService<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let node = self.node.clone();
        let require_auth = self.require_auth;
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            // Without a bearer, an open loopback listener admits the request as
            // a local caller. A presented bearer is always checked.
            if !require_auth && !request.headers().contains_key(header::AUTHORIZATION) {
                if !loopback_request(&request) {
                    return Ok(crate::path_error(
                        request.uri().path(),
                        StatusCode::FORBIDDEN,
                        "requests without a gateway credential must use a loopback Host and no cross-origin Origin",
                    ));
                }
                request.extensions_mut().insert(crate::jobs::Origin::Local);
                return inner.call(request).await;
            }
            let Some(origin) = authorizes(&node, request.headers()).await else {
                return Ok(unauthorized(request.uri().path()));
            };
            request.extensions_mut().insert(origin);
            // This credential belongs to local HTTP admission, never upstream.
            request.headers_mut().remove(header::AUTHORIZATION);
            inner.call(request).await
        })
    }
}
fn unauthorized(path: &str) -> Response<Body> {
    let mut response = crate::path_error(
        path,
        StatusCode::UNAUTHORIZED,
        "a current gateway credential is required",
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}

#[cfg(test)]
pub(crate) mod tests;
