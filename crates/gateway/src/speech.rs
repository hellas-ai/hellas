//! One speech presentation over Compute packages and prepared Fetch requests.
use crate::{
    WorkFetchRequest, WorkGatewayError,
    completion::{Completion, HttpReply},
};
use axum::{
    Extension, Router,
    extract::State,
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::post,
};
pub(super) use hellas_adaptors::openai::audio_speech::PATH;
use hellas_adaptors::openai::audio_speech::{HostedSpeech, SpeechRequest};
use hellas_client::model::{ModelKind, ModelRequest, ModelResponse};
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
                Ok(crate::completion::compute(stream).await.map(|output| {
                    let audio = match package.decode(&output).map_err(bad_gateway)? {
                        ModelResponse::Speech(audio) => audio,
                        _ => return Err(bad_gateway("unexpected model response")),
                    };
                    Ok(HttpReply {
                        status: StatusCode::OK,
                        headers: HeaderMap::from_iter([(
                            axum::http::header::CONTENT_TYPE,
                            axum::http::HeaderValue::from_static("audio/wav"),
                        )]),
                        bytes: audio.wav().map_err(bad_gateway)?,
                    })
                }))
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
                Ok(crate::completion::http(stream, adaptor.max_response_bytes).await)
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

fn bad_gateway(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}
