//! Multipart audio is extracted here, interpreted by
//! `hellas_adaptors::openai::audio_transcriptions`, and decoded through one
//! Compute job.
use super::backend::provenance::json_response;
use super::{AudioOptions, GatewayError, GatewayResult, WorkExecutionBackend, json_error};
use axum::{
    Router,
    extract::{DefaultBodyLimit, FromRequest, Multipart, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use hellas_adaptors::openai::audio_transcriptions::TranscriptionForm;
use hellas_client::model::{ModelPackage, ModelRequest, ModelResponse, wav};
use std::sync::Arc;
pub(super) const PATH: &str = "/v1/audio/transcriptions";
pub(super) const MAX_REQUEST_BYTES: usize = wav::MAX_WAV_BYTES + (64 << 10);

struct AudioState {
    package: Arc<ModelPackage>,
    options: AudioOptions,
    work: Arc<dyn WorkExecutionBackend>,
}
pub(super) async fn router(
    options: &AudioOptions,
    work: Arc<dyn WorkExecutionBackend>,
) -> GatewayResult<Router> {
    if options.default_max_tokens == 0 {
        return Err(super::GatewayConfigError::MaxTokens.into());
    }
    let path = options.model.clone();
    let package = ModelPackage::open(
        &path,
        &work.evaluator().ok_or(crate::GatewayError::Presentation(
            "Compute models need a renderer (evaluator id)".into(),
        ))?,
    )
    .await
    .map_err(|error| GatewayError::Presentation(error.into()))?;
    let capacity = package
        .transcription_capacity()
        .ok_or_else(|| GatewayError::Presentation("audio route requires a Whisper model".into()))?;
    if options.default_max_tokens > capacity {
        return Err(super::GatewayConfigError::MaxTokens.into());
    }
    let state = Arc::new(AudioState {
        package: Arc::new(package),
        options: options.clone(),
        work,
    });
    Ok(Router::new()
        .route(PATH, post(handle))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state))
}
fn multipart_error(error: axum::extract::multipart::MultipartError) -> Response {
    json_error(error.status(), error.body_text())
}

pub(super) async fn multipart_model(request: Request) -> Result<String, Box<Response>> {
    let mut multipart = Multipart::from_request(request, &())
        .await
        .map_err(IntoResponse::into_response)?;
    let mut form = TranscriptionForm::default();
    while let Some(field) = multipart.next_field().await.map_err(multipart_error)? {
        if field.name() == Some("model") {
            form.admit("model").map_err(crate::request_error)?;
            let bytes = field.bytes().await.map_err(multipart_error)?;
            form.insert("model", bytes.into())
                .map_err(crate::request_error)?;
        }
    }
    Ok(form.model().map_err(crate::request_error)?.to_owned())
}

async fn handle(State(state): State<Arc<AudioState>>, mut form: Multipart) -> Response {
    let mut fields = TranscriptionForm::default();
    while let Some(field) = match form.next_field().await {
        Ok(field) => field,
        Err(error) => return multipart_error(error),
    } {
        let name = field.name().unwrap_or_default().to_owned();
        if let Err(error) = fields.admit(&name) {
            return crate::request_error(error);
        }
        let bytes = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => return multipart_error(error),
        };
        if name == "file" && bytes.len() > wav::MAX_WAV_BYTES {
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
        if let Err(error) = fields.insert(&name, bytes.into()) {
            return crate::request_error(error);
        }
    }
    let (file, language, text) = match fields.finish(&state.options.model_name) {
        Ok(fields) => fields,
        Err(error) => return crate::request_error(error),
    };
    let deadline = state
        .work
        .timeout()
        .map(|timeout| tokio::time::Instant::now() + timeout);
    let package = state.package.clone();
    let max_new_tokens = state.options.default_max_tokens;
    let job = match crate::before_deadline(deadline, async move {
        let samples = tokio::task::spawn_blocking(move || wav::decode(&file)).await??;
        package
            .render_job(&ModelRequest::Transcription {
                samples: &samples,
                language: language.as_deref(),
                max_new_tokens,
            })
            .await
    })
    .await
    {
        Ok(Ok(job)) => job,
        Ok(Err(error)) => return json_error(StatusCode::BAD_REQUEST, error.to_string()),
        Err(_) => {
            return json_error(
                StatusCode::GATEWAY_TIMEOUT,
                "transcription preparation timed out",
            );
        }
    };
    if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
        return json_error(
            StatusCode::GATEWAY_TIMEOUT,
            "transcription preparation timed out",
        );
    }
    let crate::compute::Completion {
        output,
        accepted,
        transcript,
    } = crate::compute::collect(
        state.work.as_ref(),
        job,
        deadline,
        "transcription timed out",
    )
    .await;
    let mut response = match output {
        Ok(output) => match state.package.decode(&output) {
            Ok(ModelResponse::Transcription(result)) if text => {
                text_response(result.text, transcript.as_deref())
            }
            Ok(ModelResponse::Transcription(result)) => json_response(
                StatusCode::OK,
                serde_json::json!({"text":result.text}),
                accepted.as_ref(),
                transcript.as_deref(),
            ),
            Ok(_) => audio_error(
                StatusCode::BAD_GATEWAY,
                "unexpected model response",
                accepted.as_ref(),
                transcript.as_deref(),
            ),
            Err(error) => audio_error(
                StatusCode::BAD_GATEWAY,
                error.to_string(),
                accepted.as_ref(),
                transcript.as_deref(),
            ),
        },
        Err((status, message)) => {
            audio_error(status, message, accepted.as_ref(), transcript.as_deref())
        }
    };
    if let Some(accepted) = accepted {
        response.extensions_mut().insert(accepted);
    }
    response
}

fn audio_error(
    status: StatusCode,
    message: impl Into<String>,
    accepted: Option<&hellas_rpc::provenance::ExecutionProvenance>,
    transcript: Option<&[u8]>,
) -> Response {
    json_response(
        status,
        hellas_adaptors::openai::error_json(message),
        accepted,
        transcript,
    )
}

/// Keep the transcription's text bytes intact; trail its signed evidence.
fn text_response(text: String, transcript: Option<&[u8]>) -> Response {
    use crate::backend::provenance::transcript_header;
    use axum::{
        body::Body,
        http::{HeaderMap, HeaderValue, header},
    };
    use http_body::Frame;

    let Some(transcript) = transcript else {
        return text.into_response();
    };
    let (name, signed) = transcript_header(transcript);
    let trailer = HeaderValue::from_str(name.as_str()).expect("a header name is a valid token");
    let frames = futures::stream::iter([
        Ok::<_, std::convert::Infallible>(Frame::data(axum::body::Bytes::from(text))),
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
#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "inventory class A/B/C: test timing fixtures pending their rollout"
)]
mod tests;
