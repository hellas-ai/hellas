use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

pub(super) async fn trace_request(request: Request, next: Next) -> Response {
    next.run(request).await
}
