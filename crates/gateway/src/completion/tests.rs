use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[tokio::test]
async fn fetch_completion_requires_a_bounded_verified_body_and_keeps_evidence() {
    let accepted = hellas_rpc::provenance::ExecutionProvenance {
        commitment_id: [7; 32],
        provider: hellas_auth::ProducerSigningKey::from_secret_bytes([9; 32])
            .unwrap()
            .public_key(),
    };
    let head = || {
        WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
            HttpResponseEvent::Head {
                status: 422,
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    ("x-hellas-provider".into(), "untrusted".into()),
                    ("set-cookie".into(), "secret".into()),
                ],
            },
        )))
    };
    let body = || {
        WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
            HttpResponseEvent::Body {
                base64: STANDARD.encode(b"error"),
            },
        )))
    };
    let end = || {
        WorkEvent::Output(OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        })
    };
    for (limit, events, succeeds) in [
        (5, vec![Ok(head()), Ok(body()), Ok(end())], true),
        (4, vec![Ok(head()), Ok(body()), Ok(end())], false),
        (5, vec![Ok(head()), Ok(body())], false),
        (5, vec![Ok(head()), Ok(head()), Ok(end())], false),
        (5, vec![Ok(body()), Ok(end())], false),
        (
            5,
            vec![
                Ok(head()),
                Ok(body()),
                Err(WorkGatewayError::Execution("typed Fetch failure".into())),
            ],
            false,
        ),
    ] {
        let stream = futures::stream::iter([
            Ok(WorkEvent::Accepted(accepted.clone())),
            Ok(WorkEvent::Transcript(b"fixture evidence".to_vec())),
        ])
        .chain(futures::stream::iter(events));
        let completed = http(Box::pin(stream), limit).await;
        assert_eq!(
            completed.accepted.unwrap().commitment_id,
            accepted.commitment_id
        );
        assert_eq!(completed.transcript.unwrap(), b"fixture evidence");
        if succeeds {
            let audio = completed.output.unwrap();
            assert_eq!(audio.status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(audio.bytes, b"error");
            assert_eq!(audio.headers.len(), 1);
            assert_eq!(audio.headers["content-type"], "application/json");
        } else {
            assert_eq!(completed.output.err().unwrap().0, StatusCode::BAD_GATEWAY);
        }
    }
}
