use super::*;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use tower::ServiceExt;

fn router(directory: &Path, required: bool, cache_enabled: bool) -> Router {
    Router::new()
        .route(
            "/v1/test",
            post(|body: Bytes| async move { (StatusCode::TOO_MANY_REQUESTS, body) }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Policy {
                options: ArchiveOptions {
                    directory: directory.into(),
                    zdr: required,
                },
                cache_enabled,
            },
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
