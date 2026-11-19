//! Raw response boundaries through the paid seller, buyer and HTTP listener.
use super::*;
use futures::StreamExt as _;
use hellas_gateway::{HttpRoute, HttpTarget, Presentation, Route, WorkExecutionBackend as _};

use super::http_fixture::{Mock, Reply, SECRET, access};
const PATH: &str = "/v1/text-to-speech/voice-a";
const BODY_JSON: &str = r#"{"text":"hello","model_id":"hosted-test","voice_settings":{"speed":1}}"#;

fn reply(target: &str) -> Reply {
    let size = target
        .split('?')
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .strip_prefix("bytes=")
        .unwrap()
        .parse()
        .unwrap();
    Reply {
        status: 200,
        content: "audio/mpeg",
        bytes: audio(size),
        chunked: !target.ends_with("&length"),
    }
}
fn route(mock: &Mock, path: &str, method: &str) -> Route {
    Route {
        backends: vec!["test".into()],
        presentation: Presentation::Http {
            targets: [(
                "test".into(),
                HttpTarget {
                    service: "openai".into(),
                    method: "responses".into(),
                    route: HttpRoute {
                        path: path.into(),
                        method: method.into(),
                        url: format!("{}{path}", mock.origin),
                        tls: mock.tls.clone(),
                        headers: vec![],
                        max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
                        models: None,
                    },
                },
            )]
            .into(),
        },
    }
}
fn audio(size: usize) -> Vec<u8> {
    (0..size).map(|n| (n % 256) as u8).collect()
}

#[test]
fn http_raw_response_bound_is_deliverable_over_paid_fetch() {
    run(|runtime| {
        Box::pin(async move {
            let mock = Mock::start(reply).await;
            let mut case = paid_fixture_for(runtime, Some(mock.backend(&[PATH]))).await;
            let gateway = hellas_sdk::ExecutorGateway::new(
                [(
                    "test".into(),
                    hellas_sdk::BackendEntry {
                        backend: hellas_sdk::Backend::paid(
                            Some(case.quote.policy.invocation_policy.clone()),
                            case.options.clone(),
                            case.endpoint.clone(),
                            client_settlement(),
                            case.owner.clone(),
                        ),
                        evaluator: None,
                        max_in_flight: std::num::NonZeroUsize::MIN,
                    },
                )]
                .into(),
                Arc::new(ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap()),
            );
            let (node, access) = access(&case.root.path().join("http-authority")).await;
            let server = hellas_gateway::test_server::serve(
                node,
                access.bearer(),
                hellas_gateway::ArchiveOptions {
                    directory: case.root.path().join("archive"),
                    zdr: true,
                },
                gateway.clone(),
                gateway.jobs.clone(),
                vec![route(&mock, PATH, "POST")],
            )
            .await
            .unwrap();
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let send = |bytes, framing: &str| {
                client
                    .post(format!(
                        "http://{}{PATH}?bytes={bytes}{framing}",
                        server.address()
                    ))
                    .bearer_auth(server.bearer())
                    .header("content-type", "application/json")
                    .body(BODY_JSON)
            };
            let limit = hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES as usize;
            let work = async {
                for size in [limit - 1, limit] {
                    let response = send(size, "").send().await.unwrap();
                    assert_eq!(response.status(), 200);
                    assert_eq!(response.headers()["content-type"], "audio/mpeg");
                    let mut received = Vec::new();
                    let mut body = response.bytes_stream();
                    while let Some(chunk) = body.next().await {
                        received.extend_from_slice(&chunk.unwrap_or_else(|e| {
                            panic!("size={size} received={} error={e}", received.len())
                        }));
                    }
                    assert_eq!(received, audio(size));
                }
                let response = send(limit + 1, "&length").send().await.unwrap();
                assert_eq!(
                    response.status(),
                    502,
                    "known oversize fails before a successful head"
                );
                assert!(!response.bytes().await.unwrap().is_empty());
                let response = send(limit + 1, "").send().await.unwrap();
                assert_eq!(
                    response.status(),
                    200,
                    "an unknown length cannot be refused before streaming"
                );
                assert!(
                    response.bytes().await.is_err(),
                    "the over-limit stream must not complete successfully"
                );
            };
            sealing_while(&mut case.devnet, Duration::from_secs(1), work).await;
            gateway.drain().await.unwrap();
            let seen = mock.seen.lock().unwrap().clone();
            assert_eq!(seen.len(), 4);
            assert!(seen.iter().all(|request| {
                String::from_utf8_lossy(request).contains(&format!("x-hosted-key: {SECRET}"))
            }));
            let endpoint = bind_paid_endpoint(case.client_transport.clone())
                .await
                .unwrap();
            let mut session = PaidWorkSession::open(
                case.options.clone(),
                endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
                SessionOpenMode::Retained,
                SessionFundingOptions::default(),
            )
            .await
            .unwrap();
            session
                .with_state(|state| {
                    assert_eq!(state.jobs().count(), 0);
                    assert_eq!(state.terminals().count(), 4);
                    assert_eq!(state.ledger().credited_cumulative(), 2 * PRICE);
                })
                .await
                .unwrap();
            session.shutdown().await;
            drop(session);
            endpoint.close().await;
            server.shutdown().await.unwrap();
            case.provider.shutdown().await.unwrap();
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}
