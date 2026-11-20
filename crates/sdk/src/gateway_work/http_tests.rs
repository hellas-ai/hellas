use super::*;
use crate::daemon_config::{BackendKind, Upstream};
use futures::StreamExt as _;
use hellas_gateway::{HttpTarget, Presentation, Route};

#[tokio::test]
async fn plaintext_sse_crosses_the_executor_and_gateway_without_waiting_for_eof() {
    let release = Arc::new(tokio::sync::Notify::new());
    let ready = release.clone();
    let upstream = axum::Router::new().route(
        "/events",
        axum::routing::get(move || {
            let ready = ready.clone();
            async move {
                let stream = async_stream::stream! {
                    yield Ok::<_, std::io::Error>("data: first\n\n");
                    ready.notified().await;
                    yield Ok("data: last\n\n");
                };
                (
                    [("content-type", "text/event-stream")],
                    axum::body::Body::from_stream(stream),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/events", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let signer = Arc::new(hellas_auth::ProducerSigningKey::generate());
    let configured = crate::daemon_config::Backend {
        max_in_flight: std::num::NonZeroUsize::MIN,
        kind: BackendKind::Fetch {
            service: "http".into(),
            method: "request".into(),
            upstream: Upstream::Http {
                allowed_hosts: vec!["127.0.0.1".into()],
                plain_http_hosts: vec!["127.0.0.1".into()],
                allow_private_addresses: true,
                credentials: vec![],
            },
        },
    };
    let backend = configured.open_fetch(signer.clone()).await.unwrap();
    let gateway = ExecutorGateway::new(
        [(
            "test".into(),
            BackendEntry {
                backend,
                evaluator: None,
                max_in_flight: configured.max_in_flight,
            },
        )]
        .into(),
        signer,
    );
    let host = crate::test_support::Host::builder().build().await;
    let access = host.gateway_access().await;
    let server = crate::test_support::server::serve(
        host.world.service.node(),
        access.bearer(),
        hellas_gateway::ArchiveOptions {
            directory: host.root.path().join("archive"),
            zdr: true,
        },
        gateway.clone(),
        gateway.jobs.clone(),
        vec![Route {
            backends: vec!["test".into()],
            presentation: Presentation::Http {
                targets: [(
                    "test".into(),
                    HttpTarget {
                        service: "http".into(),
                        method: "request".into(),
                        route: serde_json::from_value(serde_json::json!({
                            "path": "/events", "method": "GET", "url": url,
                        }))
                        .unwrap(),
                    },
                )]
                .into(),
            },
        }],
    )
    .await
    .unwrap();
    let response = reqwest::Client::new()
        .get(format!("http://{}/events", server.address()))
        .bearer_auth(access.bearer())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut body = response.bytes_stream();
    assert_eq!(body.next().await.unwrap().unwrap(), "data: first\n\n");
    release.notify_one();
    assert_eq!(body.next().await.unwrap().unwrap(), "data: last\n\n");
    assert!(body.next().await.is_none());
    server.shutdown().await.unwrap();
    upstream.abort();
}
