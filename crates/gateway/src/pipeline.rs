//! Shared HTTP request and response boundary for model presentations.
use crate::{
    WorkFetchRequest, WorkGatewayError, affinity::Hints, completion::HttpReply,
    route::RouteExecution, routing::Selection,
};
use axum::{
    body::Bytes,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use hellas_client::model::{ModelRequest, ModelResponse};

pub(super) type Decode = for<'a> fn(
    &'a mut Parts,
    &'a Bytes,
)
    -> futures::future::BoxFuture<'a, Result<Hints, Box<Response>>>;

pub(super) enum Operation<'a> {
    Compute(ModelRequest<'a>),
    Fetch(WorkFetchRequest, u32),
}

pub(super) enum Reply {
    Http(HttpReply),
    Json(serde_json::Value),
    PlainText(String),
}

pub(super) type Failure = (StatusCode, String);

pub(super) fn invalid_output(error: impl ToString) -> Failure {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

pub(super) async fn buffered(
    work: &RouteExecution,
    mut selected: Selection,
    operation: Operation<'_>,
    decode: impl FnOnce(ModelResponse) -> Result<Reply, Failure> + Send + 'static,
) -> Response {
    let completed = async {
        Ok(match operation {
            Operation::Compute(request) => {
                let (package, stream) = work.compute(&mut selected, false, |_| request).await?;
                crate::completion::compute(stream)
                    .await
                    .map(async |output| {
                        tokio::task::spawn_blocking(move || {
                            decode(package.decode(&output).map_err(invalid_output)?)
                        })
                        .await
                        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
                    })
                    .await
            }
            Operation::Fetch(request, limit) => {
                let stream = work.fetch(&mut selected, |_| Ok(request.clone())).await?;
                crate::completion::http(stream, limit)
                    .await
                    .map(async |reply| Ok(Reply::Http(reply)))
                    .await
            }
        })
    }
    .await;
    let completed = match completed {
        Ok(completed) => completed,
        Err(error) => return crate::work_error(error),
    };
    use crate::backend::provenance::json_response;
    let accepted = completed.accepted.as_ref();
    let transcript = completed.transcript.as_deref();
    let mut response = match completed.output {
        Ok(Reply::Http(reply)) => with_evidence(
            (reply.status, reply.headers, reply.bytes).into_response(),
            transcript,
        ),
        Ok(Reply::Json(body)) => json_response(StatusCode::OK, body, accepted, transcript),
        Ok(Reply::PlainText(body)) => plain_text(body, transcript),
        Err((status, message)) => with_evidence(
            json_response(
                status,
                hellas_adaptors::openai::error_json(message),
                accepted,
                transcript,
            ),
            transcript,
        ),
    };
    if let Some(accepted) = completed.accepted {
        response.extensions_mut().insert(accepted);
    }
    selected.observe(response.status().as_u16(), response.headers());
    response
}

fn with_evidence(mut response: Response, transcript: Option<&[u8]>) -> Response {
    if let Some(transcript) = transcript {
        let (name, value) = crate::backend::provenance::transcript_header(transcript);
        response.headers_mut().insert(name, value);
    }
    response
}

fn plain_text(body: String, transcript: Option<&[u8]>) -> Response {
    use axum::{
        body::Body,
        http::{HeaderMap, HeaderValue, header},
    };
    use http_body::Frame;
    let Some(transcript) = transcript else {
        return body.into_response();
    };
    let (name, signed) = crate::backend::provenance::transcript_header(transcript);
    let trailer = HeaderValue::from_str(name.as_str()).expect("a header name is a valid token");
    let frames = futures::stream::iter([
        Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from(body))),
        Ok(Frame::trailers(HeaderMap::from_iter([(name, signed)]))),
    ]);
    let mut response = Response::new(Body::new(http_body_util::StreamBody::new(frames)));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(header::TRAILER, trailer);
    response
}

pub(super) fn rejected(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Response {
    crate::work_error(WorkGatewayError::Rejected(error.into()))
}

/// Open a streaming response with the same accepted identity as a buffered one.
pub(super) async fn streaming<E, S>(
    mut events: crate::WorkOutputStream<E>,
    project: impl FnOnce(
        crate::WorkOutputStream<E>,
        Option<hellas_rpc::provenance::ExecutionProvenance>,
    ) -> S,
) -> hellas_adaptors::BackendStream
where
    E: Send + 'static,
    S: futures::Stream<Item = Result<hellas_adaptors::BackendEvent, hellas_adaptors::BackendError>>
        + Send
        + 'static,
{
    let accepted = crate::accepted(&mut events).await;
    let initial = accepted
        .as_ref()
        .map(crate::backend::provenance::provenance_from_execution);
    hellas_adaptors::BackendStream::new(project(events, accepted), initial)
}
