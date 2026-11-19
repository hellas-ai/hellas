//! One speech presentation over Compute packages and prepared paid Fetch requests.
#[cfg(test)]
mod tests;

use crate::{WorkEvent, WorkFetchRequest, WorkGatewayError, compute::Completion};
use axum::{
    Extension, Router,
    extract::State,
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::post,
};
use futures::StreamExt;
pub(super) use hellas_adaptors::openai::audio_speech::PATH;
use hellas_adaptors::openai::audio_speech::{HostedSpeech, SpeechRequest};
use hellas_client::model::{ModelKind, ModelRequest, ModelResponse};
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpeechTarget {
    Native {
        package: PathBuf,
    },
    Hosted {
        service: String,
        method: String,
        adaptor: HostedSpeech,
    },
}
struct StateData {
    target: SpeechTarget,
    work: Arc<crate::route::RouteExecution>,
}
pub(super) fn router(
    target: SpeechTarget,
    work: Arc<crate::route::RouteExecution>,
) -> crate::GatewayResult<Router> {
    match &target {
        SpeechTarget::Native { package } => {
            if ModelKind::of(package).map_err(|e| crate::GatewayError::Presentation(e.into()))?
                != ModelKind::Speech
            {
                return Err(
                    crate::RoutingError("native speech requires a speech package".into()).into(),
                );
            }
        }
        SpeechTarget::Hosted { adaptor, .. } => adaptor
            .validate()
            .map_err(|e| crate::RoutingError(e.message))?,
    }
    Ok(Router::new()
        .route(PATH, post(handle))
        .with_state(Arc::new(StateData { target, work })))
}

pub(super) fn parse(
    parts: &Parts,
    body: &[u8],
) -> Result<(SpeechRequest, crate::affinity::Hints), String> {
    if parts.uri.query().is_some() {
        return Err("speech does not accept query settings".into());
    }
    let body = crate::affinity::decoded_body(&parts.headers, body).map_err(str::to_owned)?;
    let request = SpeechRequest::parse(&body).map_err(|e| e.message)?;
    let hints = crate::affinity::Hints {
        model: Some(request.model.clone()),
        session: crate::affinity::Hints::session(&parts.headers).map_err(str::to_owned)?,
        ..Default::default()
    };
    Ok((request, hints))
}

struct Audio {
    status: StatusCode,
    headers: HeaderMap,
    bytes: Vec<u8>,
}

async fn handle(
    State(state): State<Arc<StateData>>,
    Extension(mut selected): Extension<crate::routing::Selection>,
    Extension(request): Extension<SpeechRequest>,
) -> Response {
    let result = async {
        match &state.target {
            SpeechTarget::Native { .. } => {
                request
                    .native()
                    .map_err(|e| WorkGatewayError::Rejected(e.message.into()))?;
                let (package, stream) = state
                    .work
                    .compute(
                        &mut selected,
                        &ModelRequest::Speech {
                            text: &request.input,
                            speed: request.speed,
                        },
                    )
                    .await?;
                let Completion {
                    output,
                    accepted,
                    transcript,
                } = crate::compute::collect(stream).await;
                let output = output.and_then(|output| {
                    let audio = match package
                        .decode(&output)
                        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?
                    {
                        ModelResponse::Speech(audio) => audio,
                        _ => {
                            return Err((
                                StatusCode::BAD_GATEWAY,
                                "unexpected model response".into(),
                            ));
                        }
                    };
                    Ok(Audio {
                        status: StatusCode::OK,
                        headers: HeaderMap::from_iter([(
                            axum::http::header::CONTENT_TYPE,
                            axum::http::HeaderValue::from_static("audio/wav"),
                        )]),
                        bytes: audio
                            .wav()
                            .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?,
                    })
                });
                Ok(Completion {
                    output,
                    accepted,
                    transcript,
                })
            }
            SpeechTarget::Hosted {
                service,
                method,
                adaptor,
            } => {
                let upstream = adaptor
                    .translate(&request)
                    .map_err(|e| WorkGatewayError::Rejected(e.message.into()))?;
                let prepared = WorkFetchRequest {
                    service: service.clone(),
                    method: method.clone(),
                    body: serde_json::to_vec(&upstream)
                        .map_err(|e| WorkGatewayError::Rejected(e.into()))?,
                };
                let stream = state
                    .work
                    .fetch(&mut selected, |_| Ok(prepared.clone()))
                    .await?;
                Ok(collect(stream, adaptor.max_response_bytes).await)
            }
        }
    }
    .await;
    let Completion {
        output,
        accepted,
        transcript,
    } = match result {
        Ok(completion) => completion,
        Err(error) => return crate::work_error(error),
    };
    let mut response = match output {
        Ok(audio) => (audio.status, audio.headers, audio.bytes).into_response(),
        Err((status, message)) => crate::backend::provenance::json_response(
            status,
            hellas_adaptors::openai::error_json(message),
            accepted.as_ref(),
            transcript.as_deref(),
        ),
    };
    selected.observe(response.status().as_u16(), response.headers());
    if let Some(transcript) = transcript {
        let (name, value) = crate::backend::provenance::transcript_header(&transcript);
        response.headers_mut().insert(name, value);
    }
    if let Some(accepted) = accepted {
        response.extensions_mut().insert(accepted);
    }
    response
}

async fn collect(mut stream: crate::WorkFetchStream, limit: u32) -> Completion<Audio> {
    let (mut accepted, mut transcript) = (None, None);
    let output = async {
        let mut audio: Option<Audio> = None;
        while let Some(event) = stream.next().await {
            match event? {
                WorkEvent::Accepted(value) => accepted = Some(value),
                WorkEvent::Transcript(value) => transcript = Some(value),
                WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
                    HttpResponseEvent::Head { status, headers },
                ))) if audio.is_none() && (200..=599).contains(&status) => {
                    hellas_rpc::http_fetch::check_headers(&headers, false)
                        .map_err(|e| WorkGatewayError::Execution(e.into()))?;
                    let mut retained = HeaderMap::new();
                    for (name, value) in headers {
                        if matches!(
                            name.as_str(),
                            "content-type" | "content-encoding" | "retry-after"
                        ) {
                            retained.append(
                                name.parse::<axum::http::HeaderName>().unwrap(),
                                value
                                    .parse()
                                    .map_err(|e| WorkGatewayError::Execution(Box::new(e)))?,
                            );
                        }
                    }
                    audio = Some(Audio {
                        status: StatusCode::from_u16(status).unwrap(),
                        headers: retained,
                        bytes: vec![],
                    });
                }
                WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
                    HttpResponseEvent::Body { base64 },
                ))) if audio.is_some() => {
                    let bytes = hellas_rpc::http_fetch::decode_base64(&base64)
                        .map_err(|e| WorkGatewayError::Execution(e.into()))?;
                    let audio = audio.as_mut().unwrap();
                    if bytes.len() > (limit as usize).saturating_sub(audio.bytes.len()) {
                        return Err(WorkGatewayError::Execution(
                            "speech response exceeds Fetch limit".into(),
                        ));
                    }
                    audio.bytes.extend(bytes);
                }
                WorkEvent::Output(OutputEvent::Finished {
                    stop_reason: StopReason::EndOfText,
                    usage: None,
                }) if audio.is_some() => return Ok(audio.unwrap()),
                _ => {
                    return Err(WorkGatewayError::Execution(
                        "unexpected speech Fetch event".into(),
                    ));
                }
            }
        }
        Err(WorkGatewayError::Execution(
            "speech Fetch ended without verified completion".into(),
        ))
    }
    .await
    .map_err(crate::compute::failure);
    Completion {
        output,
        accepted,
        transcript,
    }
}
