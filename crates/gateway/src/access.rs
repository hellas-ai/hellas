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

#[derive(Clone)]
pub(crate) struct BearerLayer {
    node: NodeCoordinator,
}
impl BearerLayer {
    pub(crate) fn new(node: NodeCoordinator) -> Self {
        Self { node }
    }
}
impl<S> Layer<S> for BearerLayer {
    type Service = BearerService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        BearerService {
            inner,
            node: self.node.clone(),
        }
    }
}
#[derive(Clone)]
pub(crate) struct BearerService<S> {
    inner: S,
    node: NodeCoordinator,
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
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
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
