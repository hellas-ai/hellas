use axum::{body::Bytes, http::HeaderMap};
use futures::StreamExt;
use serde_json::json;
use std::{
    io,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::AsyncWriteExt;
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct ArchiveOptions {
    pub directory: PathBuf,
    pub zdr: bool,
}

#[derive(Clone)]
pub(crate) struct Policy {
    pub options: ArchiveOptions,
    pub cache_enabled: bool,
}

pub(crate) fn zdr(headers: &HeaderMap, required: bool) -> Result<bool, &'static str> {
    let values: Vec<_> = headers.get_all("x-hellas-zdr").iter().collect();
    match values.as_slice() {
        [] => Ok(required),
        [value] if *value == "true" => Ok(true),
        [value] if *value == "false" && !required => Ok(false),
        _ => Err("invalid x-hellas-zdr header"),
    }
}

pub(crate) async fn record(
    axum::extract::State(policy): axum::extract::State<Policy>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::{body::Body, http::StatusCode, response::IntoResponse};
    let ephemeral = match zdr(request.headers(), policy.options.zdr) {
        Ok(value) => value,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
    if ephemeral && policy.cache_enabled {
        return (StatusCode::BAD_REQUEST, "ZDR requires output-cache off").into_response();
    }
    let (parts, body) = request.into_parts();
    let body = match axum::body::to_bytes(body, 2 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    if ephemeral {
        if serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| value.get("store").cloned())
            == Some(json!(true))
        {
            return (StatusCode::BAD_REQUEST, "ZDR forbids store=true").into_response();
        }
        return next
            .run(axum::extract::Request::from_parts(parts, Body::from(body)))
            .await;
    }
    let mut archive = match Exchange::new(
        &policy.options.directory,
        parts.uri.path(),
        parts.method.as_str(),
        &body,
    )
    .await
    {
        Ok(archive) => archive,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "request archive unavailable",
            )
                .into_response();
        }
    };
    let response = next
        .run(axum::extract::Request::from_parts(parts, Body::from(body)))
        .await;
    if archive
        .head(response.status().as_u16(), response.headers())
        .await
        .is_err()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "response archive unavailable",
        )
            .into_response();
    }
    let (mut parts, body) = response.into_parts();
    if let Some(id) = archive.directory.file_name().and_then(|id| id.to_str()) {
        parts
            .headers
            .insert("x-hellas-request-id", id.parse().unwrap());
    }
    let mut source = body.into_data_stream();
    let stream: futures::stream::BoxStream<'static, Result<Bytes, io::Error>> =
        Box::pin(async_stream::try_stream! {
            while let Some(bytes) = source.next().await {
                let bytes = bytes.map_err(|_| io::Error::other("response stream failed"))?;
                archive.chunk(&bytes).await?;
                yield bytes;
            }
            archive.finish().await?;
        });
    axum::response::Response::from_parts(parts, Body::from_stream(stream))
}

pub(super) fn prepare(path: &Path) -> io::Result<()> {
    hellas_private::create_dir_all_durable(path)?;
    hellas_private::restrict_directory(path)
}

pub(super) struct Exchange {
    directory: PathBuf,
    metadata: serde_json::Value,
    response: tokio::fs::File,
    started: Instant,
    bytes: usize,
}

impl Exchange {
    pub(super) async fn new(
        root: &Path,
        path: &str,
        method: &str,
        body: &Bytes,
    ) -> io::Result<Self> {
        let root = root.to_owned();
        let body = body.clone();
        let mut metadata = json!({
            "version": 1, "path": path, "method": method, "complete": false,
            "started_unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
            "request_bytes": body.len(),
        });
        #[cfg(feature = "otel")]
        {
            let mut context = hellas_wire::metadata::Metadata::new();
            hellas_rpc::telemetry::inject(&tracing::Span::current(), &mut context);
            metadata["traceparent"] =
                json!(context.get("traceparent").and_then(|value| value.as_text()));
        }
        let initial = metadata.clone();
        let (directory, response) = tokio::task::spawn_blocking(move || {
            let directory = root.join(format!("{:032x}", rand::random::<u128>()));
            prepare(&directory)?;
            hellas_private::write_atomically(&directory.join("request.bin"), ".tmp", &body)?;
            write_metadata(&directory, &initial)?;
            let temporary = hellas_private::private_tempfile(&directory, ".response-", ".tmp")?;
            let file = temporary
                .persist(directory.join("response.bin"))
                .map_err(|error| error.error)?;
            Ok::<_, io::Error>((directory, file))
        })
        .await
        .map_err(io::Error::other)??;
        metadata["response_bytes"] = json!(0);
        Ok(Self {
            directory,
            metadata,
            response: tokio::fs::File::from_std(response),
            started: Instant::now(),
            bytes: 0,
        })
    }

    pub(super) async fn head(&mut self, status: u16, headers: &HeaderMap) -> io::Result<()> {
        self.metadata["status"] = json!(status);
        // Protocol metadata only. Arbitrary response headers may carry secrets.
        self.metadata["content_type"] = json!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
        );
        self.save().await
    }

    pub(super) async fn chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.response.write_all(bytes).await?;
        self.bytes += bytes.len();
        Ok(())
    }

    pub(super) async fn finish(&mut self) -> io::Result<()> {
        self.response.sync_all().await?;
        self.metadata["response_bytes"] = json!(self.bytes);
        self.metadata["duration_ms"] = json!(self.started.elapsed().as_millis() as u64);
        self.metadata["complete"] = json!(true);
        self.save().await
    }

    async fn save(&self) -> io::Result<()> {
        let directory = self.directory.clone();
        let metadata = self.metadata.clone();
        tokio::task::spawn_blocking(move || write_metadata(&directory, &metadata))
            .await
            .map_err(io::Error::other)?
    }
}

fn write_metadata(directory: &Path, metadata: &serde_json::Value) -> io::Result<()> {
    hellas_private::write_atomically(
        &directory.join("metadata.json"),
        ".tmp",
        &serde_json::to_vec(metadata)?,
    )
}
