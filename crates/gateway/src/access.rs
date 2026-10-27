//! HTTP admission through the host's existing Auth authority.
use axum::body::Body;
use axum::http::{HeaderMap, Request, Response, StatusCode, header};
use futures::future::BoxFuture;
use hellas_auth::authority::{CredentialId, CredentialSecret, GrantId};
use hellas_authority::node::NodeCoordinator;
use std::{
    fmt,
    io::Write,
    net::SocketAddr,
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

    pub fn shares_writer(&self, node: &NodeCoordinator) -> bool {
        self.node.shares_writer(node)
    }

    /// The gateway's own credential, under its configured grant.
    pub async fn validate(&self) -> crate::GatewayResult<()> {
        let caller = self.node.authenticate(&self.credential).await?;
        self.node
            .authorize_gateway(&caller, self.authorization)
            .await
            .map_err(Into::into)
    }

    async fn authenticate(
        &self,
        credential: &CredentialSecret,
    ) -> Result<(), hellas_authority::work_store::grant::NodeStoreError> {
        let caller = self.node.authenticate(credential).await?;
        if self
            .node
            .authorize_gateway(&caller, self.authorization)
            .await
            .is_ok()
        {
            return Ok(());
        }
        self.node.authorize_gateway_bearer(&caller).await.map(drop)
    }

    /// Secret material for an explicitly authorized control response or child.
    pub fn bearer(&self) -> String {
        format!(
            "{}{}",
            self.credential.id(),
            hellas_rpc::provenance::encode_hex(self.credential.expose_secret())
        )
    }

    pub(crate) fn announce(&self) {
        let terminal = if cfg!(windows) { "CONOUT$" } else { "/dev/tty" };
        // Never fall back to stdout/stderr, which are routinely captured.
        match std::fs::OpenOptions::new().write(true).open(terminal) {
            Ok(mut tty) => {
                if let Err(error) = writeln!(
                    tty,
                    "gateway bearer: Authorization: Bearer {}",
                    self.bearer()
                ) {
                    warn!(%error, "gateway credential could not be written to the controlling terminal");
                }
            }
            Err(error) => warn!(%error, "gateway credential not shown: no controlling terminal"),
        }
    }

    async fn authorizes(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let value = value.as_bytes();
        let Some((scheme, text)) = value.split_at_checked(7) else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case(b"bearer ") {
            return false;
        }
        let Ok(text) = std::str::from_utf8(text) else {
            return false;
        };
        let Ok(bytes) = hellas_auth::hex::parse_lower::<48>(text) else {
            return false;
        };
        let Ok(id) = CredentialId::try_from(&bytes[..16]) else {
            return false;
        };
        let Ok(secret) = bytes[16..].try_into() else {
            return false;
        };
        self.authenticate(&CredentialSecret::from_parts(id, secret))
            .await
            .is_ok()
    }
}
impl fmt::Debug for GatewayAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayAccess(redacted)")
    }
}

#[derive(Clone)]
pub(crate) struct BearerLayer {
    access: GatewayAccess,
}
impl BearerLayer {
    pub(crate) fn new(access: GatewayAccess) -> Self {
        Self { access }
    }
}
impl<S> Layer<S> for BearerLayer {
    type Service = BearerService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        BearerService {
            inner,
            access: self.access.clone(),
        }
    }
}
#[derive(Clone)]
pub(crate) struct BearerService<S> {
    inner: S,
    access: GatewayAccess,
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
        let access = self.access.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            if !access.authorizes(request.headers()).await {
                return Ok(unauthorized());
            }
            // This credential belongs to local HTTP admission, never upstream.
            request.headers_mut().remove(header::AUTHORIZATION);
            inner.call(request).await
        })
    }
}
fn unauthorized() -> Response<Body> {
    let mut response = crate::json_error(
        StatusCode::UNAUTHORIZED,
        "a current gateway credential is required",
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}

pub(crate) async fn bind_addr(
    host: &str,
    port: u16,
    allow_remote: bool,
) -> crate::GatewayResult<SocketAddr> {
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|source| crate::GatewayError::Resolve {
            host: host.into(),
            port,
            source,
        })?
        .collect();
    let Some(first) = resolved.first().copied() else {
        return Err(crate::GatewayError::NoAddress {
            host: host.into(),
            port,
        });
    };
    if !(allow_remote || resolved.iter().all(|addr| addr.ip().is_loopback())) {
        return Err(crate::GatewayConfigError::RemoteBinding.into());
    }
    Ok(first)
}

#[cfg(test)]
pub(crate) mod tests;
