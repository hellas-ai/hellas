//! Multipart audio is prepared and decoded on the gateway, through one Compute job.
use super::{
    AudioOptions, ComputeEvent, GatewayError, GatewayResult, WorkExecutionBackend, json_error,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Multipart, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use futures::StreamExt;
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
    let package = tokio::task::spawn_blocking(move || ModelPackage::open(&path))
        .await?
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
fn bad(message: impl Into<String>) -> Response {
    json_error(StatusCode::BAD_REQUEST, message)
}
fn multipart_error(error: axum::extract::multipart::MultipartError) -> Response {
    json_error(error.status(), error.body_text())
}

pub(super) async fn multipart_model(request: Request) -> Result<String, Response> {
    let mut form = Multipart::from_request(request, &())
        .await
        .map_err(IntoResponse::into_response)?;
    let mut model = None;
    while let Some(field) = form.next_field().await.map_err(multipart_error)? {
        if field.name() == Some("model") {
            if model.is_some() {
                return Err(bad("duplicate model field"));
            }
            let bytes = field.bytes().await.map_err(multipart_error)?;
            if bytes.len() > 256 {
                return Err(bad("model name too long"));
            }
            model = Some(
                std::str::from_utf8(&bytes)
                    .map_err(|_| bad("invalid model name"))?
                    .to_owned(),
            );
        }
    }
    model
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("model field is required"))
}

async fn handle(State(state): State<Arc<AudioState>>, mut form: Multipart) -> Response {
    let mut fields = std::collections::BTreeSet::new();
    let (mut model, mut file, mut language, mut format) = (None, None, None, String::from("json"));
    while let Some(field) = match form.next_field().await {
        Ok(field) => field,
        Err(error) => return multipart_error(error),
    } {
        let name = field.name().unwrap_or_default().to_owned();
        if !fields.insert(name.clone()) {
            return bad(format!("duplicate {name} field"));
        }
        if !matches!(
            name.as_str(),
            "model" | "file" | "language" | "response_format"
        ) {
            return bad(format!("unsupported field {name}"));
        }
        let bytes = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => return multipart_error(error),
        };
        if name == "file" {
            if bytes.len() > wav::MAX_WAV_BYTES {
                return StatusCode::PAYLOAD_TOO_LARGE.into_response();
            }
            file = Some(bytes);
            continue;
        }
        if bytes.len() > 256 {
            return bad("form field too long");
        }
        let value = match std::str::from_utf8(&bytes) {
            Ok(value) => value.to_owned(),
            Err(_) => return bad("invalid UTF-8 form field"),
        };
        match name.as_str() {
            "model" => model = Some(value),
            "language" => language = Some(value),
            "response_format" => format = value,
            _ => unreachable!(),
        }
    }
    if model.as_deref() != Some(state.options.model_name.as_str()) {
        return json_error(StatusCode::NOT_FOUND, "unknown model");
    }
    if !matches!(format.as_str(), "json" | "text") {
        return bad("response_format must be json or text");
    }
    let Some(file) = file else {
        return bad("file field is required");
    };
    let deadline = tokio::time::Instant::now() + state.work.timeout();
    let package = state.package.clone();
    let max_new_tokens = state.options.default_max_tokens;
    let job = match tokio::time::timeout_at(
        deadline,
        tokio::task::spawn_blocking(move || {
            let samples = wav::decode(&file)?;
            package.render_job(&ModelRequest::Transcription {
                samples: &samples,
                language: language.as_deref(),
                max_new_tokens,
            })
        }),
    )
    .await
    {
        Ok(Ok(Ok(job))) => job,
        Ok(Ok(Err(error))) => return bad(error.to_string()),
        Ok(Err(error)) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        Err(_) => {
            return json_error(
                StatusCode::GATEWAY_TIMEOUT,
                "transcription preparation timed out",
            );
        }
    };
    if tokio::time::Instant::now() >= deadline {
        return json_error(
            StatusCode::GATEWAY_TIMEOUT,
            "transcription preparation timed out",
        );
    }
    let mut stream = match state.work.run(job) {
        Ok(stream) => stream,
        Err(error) => return work_error(error),
    };
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(ComputeEvent::Output(_)))) => {}
            Ok(Some(Ok(ComputeEvent::Done { output, .. }))) => {
                return match state.package.decode(&output) {
                    Ok(ModelResponse::Transcription(result)) if format == "text" => {
                        result.text.into_response()
                    }
                    Ok(ModelResponse::Transcription(result)) => {
                        Json(serde_json::json!({"text":result.text})).into_response()
                    }
                    Ok(_) => json_error(StatusCode::BAD_GATEWAY, "unexpected model response"),
                    Err(error) => json_error(StatusCode::BAD_GATEWAY, error.to_string()),
                };
            }
            Ok(Some(Err(error))) => return work_error(error),
            Ok(None) => {
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    "execution stream ended without terminal outcome",
                );
            }
            Err(_) => return json_error(StatusCode::GATEWAY_TIMEOUT, "transcription timed out"),
        }
    }
}
fn work_error(error: super::WorkGatewayError) -> Response {
    let error: hellas_adaptors::BackendError = error.into();
    json_error(super::backend_status(&error), error.to_string())
}

#[cfg(test)]
mod tests;
