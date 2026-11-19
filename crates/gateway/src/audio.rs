//! Multipart transcription request and response shapes.
use super::{
    GatewayError, GatewayResult, json_error,
    pipeline::{self, Operation, Reply},
    route::RouteExecution,
};
use axum::{
    Extension, Router,
    body::{Body, Bytes},
    extract::{FromRequest, Multipart, Request, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::post,
};
use hellas_adaptors::openai::audio_transcriptions::TranscriptionForm;
use hellas_client::model::{ModelRequest, ModelResponse, wav};
use std::sync::Arc;
pub(super) const PATH: &str = "/v1/audio/transcriptions";
pub(super) const MAX_REQUEST_BYTES: usize = wav::MAX_WAV_BYTES + (64 << 10);

struct AudioState {
    max_tokens: usize,
    work: Arc<RouteExecution>,
}

pub(super) fn router(max_tokens: usize, work: Arc<RouteExecution>) -> GatewayResult<Router> {
    let package = work
        .packages
        .values()
        .next()
        .ok_or_else(|| GatewayError::Presentation("audio route needs a renderer".into()))?;
    let capacity = package
        .transcription_capacity()
        .ok_or_else(|| GatewayError::Presentation("audio route requires a Whisper model".into()))?;
    if max_tokens == 0 || max_tokens > capacity {
        return Err(super::GatewayConfigError::MaxTokens.into());
    }
    Ok(Router::new()
        .route(PATH, post(handle))
        .with_state(Arc::new(AudioState { max_tokens, work })))
}

#[derive(Clone)]
struct AudioRequest {
    file: Bytes,
    language: Option<String>,
    text: bool,
}

pub(super) fn decode<'a>(
    parts: &'a mut Parts,
    body: &'a Bytes,
) -> futures::future::BoxFuture<'a, Result<crate::affinity::Hints, Box<Response>>> {
    Box::pin(async move {
        let mut multipart = Multipart::from_request(
            Request::from_parts(parts.clone(), Body::from(body.clone())),
            &(),
        )
        .await
        .map_err(IntoResponse::into_response)?;
        let mut form = TranscriptionForm::default();
        let multipart_error = |error: axum::extract::multipart::MultipartError| {
            json_error(error.status(), error.body_text())
        };
        while let Some(field) = multipart.next_field().await.map_err(multipart_error)? {
            let name = field.name().unwrap_or_default().to_owned();
            form.admit(&name).map_err(crate::request_error)?;
            let bytes = field.bytes().await.map_err(multipart_error)?;
            if name == "file" && bytes.len() > wav::MAX_WAV_BYTES {
                return Err(Box::new(StatusCode::PAYLOAD_TOO_LARGE.into_response()));
            }
            form.insert(&name, bytes.into())
                .map_err(crate::request_error)?;
        }
        let model = form.model().map_err(crate::request_error)?.to_owned();
        let (file, language, text) = form.finish(&model).map_err(crate::request_error)?;
        parts.extensions.insert(AudioRequest {
            file: Bytes::from(file),
            language,
            text,
        });
        Ok(crate::affinity::Hints {
            model: Some(model),
            ..Default::default()
        })
    })
}

async fn handle(
    State(state): State<Arc<AudioState>>,
    Extension(selected): Extension<crate::routing::Selection>,
    Extension(AudioRequest {
        file,
        language,
        text,
    }): Extension<AudioRequest>,
) -> Response {
    let samples = match tokio::task::spawn_blocking(move || wav::decode(&file)).await {
        Ok(Ok(samples)) => samples,
        Ok(Err(error)) => return json_error(StatusCode::BAD_REQUEST, error.to_string()),
        Err(error) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    pipeline::buffered(
        &state.work,
        selected,
        Operation::Compute(ModelRequest::Transcription {
            samples: &samples,
            language: language.as_deref(),
            max_new_tokens: state.max_tokens,
        }),
        move |output| match output {
            ModelResponse::Transcription(result) if text => Ok(Reply::PlainText(result.text)),
            ModelResponse::Transcription(result) => {
                Ok(Reply::Json(serde_json::json!({"text":result.text})))
            }
            _ => Err(pipeline::invalid_output("unexpected model response")),
        },
    )
    .await
}
#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "inventory class A/B/C: test timing fixtures pending their rollout"
)]
mod tests;
