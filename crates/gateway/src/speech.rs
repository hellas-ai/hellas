//! One speech presentation over Compute packages and prepared Fetch requests.
use crate::{
    WorkFetchRequest,
    completion::HttpReply,
    pipeline::{self, Operation, Reply},
};
use axum::{
    Extension, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, request::Parts},
    response::Response,
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
        SpeechTarget::Native { .. } => work.require_kind(ModelKind::Speech)?,
        SpeechTarget::Hosted { adaptor, .. } => adaptor
            .validate()
            .map_err(|e| crate::RoutingError(e.message))?,
    }
    Ok(Router::new()
        .route(PATH, post(handle))
        .with_state(Arc::new(StateData { target, work })))
}

pub(super) fn decode<'a>(
    parts: &'a mut Parts,
    body: &'a Bytes,
) -> futures::future::BoxFuture<'a, Result<crate::affinity::Hints, Box<Response>>> {
    Box::pin(async move {
        let invalid = |message| Box::new(crate::json_error(StatusCode::BAD_REQUEST, message));
        if parts.uri.query().is_some() {
            return Err(invalid("speech does not accept query settings".to_owned()));
        }
        let bytes = crate::affinity::decoded_body(&parts.headers, body)
            .map_err(|error| invalid(error.to_owned()))?;
        let request = SpeechRequest::parse(&bytes).map_err(|error| invalid(error.message))?;
        let hints = crate::affinity::Hints {
            model: Some(request.model.clone()),
            session: crate::affinity::Hints::session(&parts.headers)
                .map_err(|error| invalid(error.to_owned()))?,
            ..Default::default()
        };
        parts.extensions.insert(request);
        Ok(hints)
    })
}

async fn handle(
    State(state): State<Arc<StateData>>,
    Extension(selected): Extension<crate::routing::Selection>,
    Extension(request): Extension<SpeechRequest>,
) -> Response {
    let operation = match &state.target {
        SpeechTarget::Native { .. } => {
            if let Err(error) = request.native() {
                return pipeline::rejected(error.message);
            }
            Operation::Compute(ModelRequest::Speech {
                text: &request.input,
                speed: request.speed,
            })
        }
        SpeechTarget::Hosted {
            service,
            method,
            adaptor,
        } => {
            let upstream = match adaptor.translate(&request) {
                Ok(upstream) => upstream,
                Err(error) => return pipeline::rejected(error.message),
            };
            let body = match serde_json::to_vec(&upstream) {
                Ok(body) => body,
                Err(error) => return pipeline::rejected(error),
            };
            Operation::Fetch(
                WorkFetchRequest {
                    service: service.clone(),
                    method: method.clone(),
                    body,
                },
                adaptor.max_response_bytes,
            )
        }
    };
    pipeline::buffered(&state.work, selected, operation, |output| {
        let ModelResponse::Speech(audio) = output else {
            return Err(pipeline::invalid_output("unexpected model response"));
        };
        Ok(Reply::Http(HttpReply {
            status: StatusCode::OK,
            headers: HeaderMap::from_iter([(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("audio/wav"),
            )]),
            bytes: audio.wav().map_err(pipeline::invalid_output)?,
        }))
    })
    .await
}
