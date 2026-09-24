use super::*;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use tower::ServiceExt;

fn policy(directory: &Path) -> Policy {
    Policy::new(
        ArchiveOptions {
            directory: directory.into(),
            zdr: false,
        },
        false,
    )
}

async fn exchange(directory: &Path) -> Exchange {
    Exchange::new(
        directory,
        "/v1/test",
        "POST",
        &Bytes::from_static(b"synthetic request"),
        &HeaderMap::new(),
    )
    .await
    .unwrap()
}

fn metadata(directory: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(directory.join("metadata.json")).unwrap()).unwrap()
}

fn router(directory: &Path, required: bool, cache_enabled: bool) -> Router {
    Router::new()
        .route(
            "/v1/test",
            post(|body: Bytes| async move { (StatusCode::TOO_MANY_REQUESTS, body) }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Policy::new(
                ArchiveOptions {
                    directory: directory.into(),
                    zdr: required,
                },
                cache_enabled,
            ),
            record,
        ))
}

#[tokio::test]
async fn archives_errors_by_default_without_auth_headers_and_zdr_leaves_no_payload() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("archive");
    prepare(&archive).unwrap();
    let app = router(&archive, false, false);
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/test")
                .header("authorization", "Bearer SECRET-HEADER")
                .body(Body::from("ordinary payload"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let id = response.headers()["x-hellas-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(bytes, "ordinary payload");
    let directory = archive.join(id);
    assert_eq!(
        std::fs::read(directory.join("request.bin")).unwrap(),
        b"ordinary payload"
    );
    assert_eq!(
        std::fs::read(directory.join("response.bin")).unwrap(),
        b"ordinary payload"
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(metadata["complete"], true);
    assert_eq!(metadata["status"], 429);
    assert!(!metadata.to_string().contains("SECRET-HEADER"));
    for entry in std::fs::read_dir(&directory).unwrap() {
        let file = std::fs::File::open(entry.unwrap().path()).unwrap();
        assert!(hellas_private::is_private(&file).unwrap());
    }
    let response = app
        .oneshot(
            Request::post("/v1/test")
                .header("x-hellas-zdr", "true")
                .body(Body::from("ZDR-SECRET"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.headers().get("x-hellas-request-id").is_none());
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "ZDR-SECRET"
    );
    assert_eq!(std::fs::read_dir(&archive).unwrap().count(), 1);
}

#[tokio::test]
async fn cancellation_leaves_an_incomplete_archive() {
    let root = tempfile::tempdir().unwrap();
    let response = router(root.path(), false, false)
        .oneshot(
            Request::post("/v1/test")
                .body(Body::from("cancelled"))
                .unwrap(),
        )
        .await
        .unwrap();
    let id = response.headers()["x-hellas-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    drop(response);
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join(id).join("metadata.json")).unwrap())
            .unwrap();
    assert_eq!(metadata["complete"], false);
}

#[tokio::test]
async fn zdr_rejects_ambiguous_flags_retain_and_enabled_replay_before_disk_writes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("must-not-exist");
    for (required, cache, header, body) in [
        (false, false, "yes", "{}"),
        (true, false, "false", "{}"),
        (false, true, "true", "{}"),
        (false, false, "true", "{\"store\":true}"),
    ] {
        let response = router(&path, required, cache)
            .oneshot(
                Request::post("/v1/test")
                    .header("x-hellas-zdr", header)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!path.exists());
    }
    let response = router(&path, true, false)
        .oneshot(
            Request::post("/v1/test")
                .body(Body::from("private"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "private"
    );
    assert!(!path.exists());
}

#[tokio::test]
async fn unavailable_archive_preserves_errors_and_recovers_on_the_next_request() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("unavailable");
    std::fs::write(&archive, b"not a directory").unwrap();
    policy(&archive).prepare(); // Startup must also remain available.
    let app = router(&archive, false, false);
    for recovered in [false, true] {
        if recovered {
            std::fs::remove_file(&archive).unwrap();
        }
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/test")
                    .body(Body::from("unchanged error"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let id = response.headers().get("x-hellas-request-id").cloned();
        assert_eq!(id.is_some(), recovered);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap(),
            "unchanged error"
        );
        if let Some(id) = id {
            assert_eq!(
                metadata(&archive.join(id.to_str().unwrap()))["complete"],
                true
            );
        }
    }
}

#[tokio::test]
async fn response_head_archive_failure_preserves_status_headers_and_body() {
    let root = tempfile::tempdir().unwrap();
    let archive = exchange(root.path()).await;
    let id = archive
        .directory
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let moved = root.path().join("moved");
    std::fs::rename(&archive.directory, &moved).unwrap();
    std::fs::write(&archive.directory, b"unavailable").unwrap();
    let response = axum::response::Response::builder()
        .status(429)
        .header("retry-after", "3")
        .body(Body::from("upstream error"))
        .unwrap();
    let response = archive_response(policy(root.path()), archive, response).await;
    assert_eq!(response.status(), 429);
    assert_eq!(response.headers()["x-hellas-request-id"], id);
    assert_eq!(response.headers()["retry-after"], "3");
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "upstream error"
    );
    assert_eq!(metadata(&moved)["complete"], false);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn disk_full_does_not_truncate_a_stream_or_replace_an_empty_response() {
    let root = tempfile::tempdir().unwrap();
    for empty in [false, true] {
        let mut archive = exchange(root.path()).await;
        let directory = archive.directory.clone();
        // /dev/full injects ENOSPC on writes without filling the host filesystem.
        archive.response = tokio::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .await
            .unwrap();
        let body = if empty {
            Body::empty()
        } else {
            Body::from_stream(futures::stream::iter(
                ["first", "second", "third"]
                    .map(|s| Ok::<_, io::Error>(Bytes::from_static(s.as_bytes()))),
            ))
        };
        let response = axum::response::Response::builder()
            .status(if empty { 204 } else { 200 })
            .body(body)
            .unwrap();
        let response = archive_response(policy(root.path()), archive, response).await;
        assert_eq!(response.status(), if empty { 204 } else { 200 });
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap(),
            if empty { "" } else { "firstsecondthird" }
        );
        assert_eq!(metadata(&directory)["complete"], false);
    }
}

#[tokio::test]
async fn final_metadata_failure_keeps_all_delivered_bytes() {
    let root = tempfile::tempdir().unwrap();
    let archive = exchange(root.path()).await;
    let directory = archive.directory.clone();
    let moved = root.path().join("moved");
    let moved_in_stream = moved.clone();
    let body: futures::stream::BoxStream<'static, Result<Bytes, io::Error>> =
        Box::pin(async_stream::try_stream! {
            yield Bytes::from_static(b"first");
            std::fs::rename(&directory, &moved_in_stream)?;
            std::fs::write(&directory, b"unavailable")?;
            yield Bytes::from_static(b"second");
        });
    let response = axum::response::Response::new(Body::from_stream(body));
    let response = archive_response(policy(root.path()), archive, response).await;
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "firstsecond"
    );
    assert_eq!(
        std::fs::read(moved.join("response.bin")).unwrap(),
        b"firstsecond"
    );
    assert_eq!(metadata(&moved)["complete"], false);
}

#[tokio::test]
async fn genuine_upstream_stream_errors_still_fail() {
    let root = tempfile::tempdir().unwrap();
    let archive = exchange(root.path()).await;
    let directory = archive.directory.clone();
    let body = Body::from_stream(futures::stream::iter([
        Ok(Bytes::from_static(b"partial")),
        Err(io::Error::other("synthetic upstream failure")),
    ]));
    let response = archive_response(
        policy(root.path()),
        archive,
        axum::response::Response::new(body),
    )
    .await;
    let mut stream = response.into_body().into_data_stream();
    assert_eq!(stream.next().await.unwrap().unwrap(), "partial");
    assert!(stream.next().await.unwrap().is_err());
    assert_eq!(metadata(&directory)["complete"], false);
}

#[cfg(feature = "otel")]
#[tokio::test]
async fn archive_failures_are_counted_without_changing_http_outcomes_or_counting_zdr() {
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};

    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(exporter.clone())
        .build();
    let root = tempfile::tempdir().unwrap();
    let unavailable = root.path().join("unavailable");
    std::fs::write(&unavailable, b"not a directory").unwrap();
    let mut policy = policy(&unavailable);
    policy.failures = provider
        .meter("archive-test")
        .u64_counter("hellas.gateway.archive.failures")
        .build();
    policy.prepare();
    let app = Router::new()
        .route("/", post(|| async { "success" }))
        .layer(axum::middleware::from_fn_with_state(policy, record));
    for zdr in [false, true] {
        let response = app
            .clone()
            .oneshot(
                Request::post("/")
                    .header("x-hellas-zdr", zdr.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap(),
            "success"
        );
    }
    provider.force_flush().unwrap();
    let mut stages = Vec::new();
    for resource in exporter.get_finished_metrics().unwrap() {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                assert_eq!(metric.name(), "hellas.gateway.archive.failures");
                let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
                    panic!("failure counter must be a sum");
                };
                for point in sum.data_points() {
                    assert_eq!(point.value(), 1);
                    let attributes: Vec<_> = point.attributes().collect();
                    assert_eq!(attributes.len(), 2);
                    stages.push(
                        attributes
                            .iter()
                            .find(|a| a.key.as_str() == "archive.stage")
                            .unwrap()
                            .value
                            .to_string(),
                    );
                    assert!(
                        attributes
                            .iter()
                            .all(|a| !a.value.to_string().contains("unavailable"))
                    );
                }
            }
        }
    }
    stages.sort();
    assert_eq!(stages, ["prepare", "request"]);
}
