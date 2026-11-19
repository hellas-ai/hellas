//! Collect a complete Work response with its accepted identity and signed evidence.
use super::{ComputeEvent, WorkEvent, WorkGatewayError};
use axum::http::{HeaderMap, StatusCode, header};
use futures::StreamExt;
use hellas_rpc::{
    output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason},
    protocol::invocation::output::InvocationOutput,
    provenance::ExecutionProvenance,
};

#[cfg(test)]
mod tests;

pub(super) struct Completion<T = InvocationOutput> {
    pub output: Result<T, (StatusCode, String)>,
    pub accepted: Option<ExecutionProvenance>,
    pub transcript: Option<Vec<u8>>,
}

impl<T> Completion<T> {
    pub fn map<U>(self, map: impl FnOnce(T) -> Result<U, (StatusCode, String)>) -> Completion<U> {
        Completion {
            output: self.output.and_then(map),
            accepted: self.accepted,
            transcript: self.transcript,
        }
    }
}

async fn collect<E, T>(
    mut stream: crate::WorkOutputStream<E>,
    mut receive: impl FnMut(E) -> Result<Option<T>, WorkGatewayError>,
) -> Completion<T> {
    let (mut accepted, mut transcript) = (None, None);
    let output = loop {
        match stream.next().await {
            Some(Ok(WorkEvent::Accepted(value))) => accepted = Some(value),
            Some(Ok(WorkEvent::Transcript(value))) => transcript = Some(value),
            Some(Ok(WorkEvent::Output(event))) => match receive(event) {
                Ok(Some(output)) => break Ok(output),
                Ok(None) => {}
                Err(error) => break Err(failure(error)),
            },
            Some(Err(error)) => break Err(failure(error)),
            None => {
                break Err((
                    StatusCode::BAD_GATEWAY,
                    "execution stream ended without terminal outcome".into(),
                ));
            }
        }
    };
    Completion {
        output,
        accepted,
        transcript,
    }
}

pub(super) async fn compute(stream: crate::WorkOutputStream<ComputeEvent>) -> Completion {
    collect(stream, |event| {
        Ok(match event {
            ComputeEvent::Output(_) => None,
            ComputeEvent::Done { output, .. } => Some(output),
        })
    })
    .await
}

pub(super) struct HttpReply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub bytes: Vec<u8>,
}

/// Buffer an HTTP Fetch result up to its signed raw-byte cap. The caller can
/// send one complete response, including evidence, after terminal verification.
pub(super) async fn http(stream: crate::WorkFetchStream, limit: u32) -> Completion<HttpReply> {
    let mut reply: Option<HttpReply> = None;
    collect(stream, |event| {
        match event {
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
                status,
                headers,
            })) if reply.is_none() && (200..=599).contains(&status) => {
                hellas_rpc::http_fetch::check_headers(&headers, false)
                    .map_err(|error| WorkGatewayError::Execution(error.into()))?;
                let mut retained = HeaderMap::new();
                for (name, value) in headers {
                    let name = match name.as_str() {
                        "content-type" => header::CONTENT_TYPE,
                        "content-encoding" => header::CONTENT_ENCODING,
                        "retry-after" => header::RETRY_AFTER,
                        _ => continue,
                    };
                    retained.append(
                        name,
                        value
                            .parse()
                            .map_err(|error| WorkGatewayError::Execution(Box::new(error)))?,
                    );
                }
                reply = Some(HttpReply {
                    status: StatusCode::from_u16(status).unwrap(),
                    headers: retained,
                    bytes: vec![],
                });
            }
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body { base64 }))
                if reply.is_some() =>
            {
                let bytes = hellas_rpc::http_fetch::decode_base64(&base64)
                    .map_err(|error| WorkGatewayError::Execution(error.into()))?;
                let body = &mut reply.as_mut().unwrap().bytes;
                if bytes.len() > (limit as usize).saturating_sub(body.len()) {
                    return Err(WorkGatewayError::Execution(
                        "HTTP response exceeds Fetch limit".into(),
                    ));
                }
                body.extend(bytes);
            }
            OutputEvent::Finished {
                stop_reason: StopReason::EndOfText,
                usage: None,
            } if reply.is_some() => return Ok(reply.take()),
            _ => {
                return Err(WorkGatewayError::Execution(
                    "unexpected HTTP Fetch event".into(),
                ));
            }
        }
        Ok(None)
    })
    .await
}

fn failure(error: WorkGatewayError) -> (StatusCode, String) {
    let error: hellas_adaptors::BackendError = error.into();
    (super::backend_status(&error), error.to_string())
}
