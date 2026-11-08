//! Bounds checked through the real Owner acquisition and atomic pin path.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Response {
    Valid,
    OversizedToken,
    OverlongRange,
    WrongStatus,
    ShortRange,
}

async fn acquire_response(response: Response) {
    let content: Vec<u8> = (0..5_000_u32).map(|i| (i * 31 % 251) as u8).collect();
    let object = ContentRef::for_bytes(&content);
    let xorb = hellas_xet::XetHash::ZERO;
    let framed = framed(&content);
    let (base, serving) = hub(|base| {
        let sha = "a".repeat(40);
        let mut replies = vec![
            (format!("/api/models/org/repo/tree/{sha}?recursive=true"), 200,
             serde_json::json!([{"type":"file","path":"model.safetensors","size":object.bytes(),"xetHash":object.id().to_string()}]).to_string().into_bytes()),
            (format!("/api/models/org/repo/xet-read-token/{sha}"), 200,
             serde_json::json!({"accessToken": if response == Response::OversizedToken { "a".repeat(70_000) } else { "t".into() }, "casUrl":base}).to_string().into_bytes()),
        ];
        if response == Response::OversizedToken {
            return replies;
        }
        let plan = serde_json::json!({
            "offset_into_first_range":0,
            "terms":[{"hash":xorb.to_string(),"unpacked_length":content.len(),"range":{"start":0,"end":1}}],
            "xorbs":{xorb.to_string():[{"url":format!("{base}/xorb"),"ranges":[{"chunks":{"start":0,"end":1},"bytes":{"start":0,"end":framed.len()-1}}]}]}
        });
        replies.push((
            format!("/v2/reconstructions/{}", object.id()),
            200,
            plan.to_string().into_bytes(),
        ));
        let mut body = framed.clone();
        match response {
            Response::OverlongRange => body.extend_from_slice(b"unrequested bytes"),
            Response::ShortRange => body.truncate(body.len() - 10),
            _ => {}
        }
        replies.push((
            "/xorb".into(),
            if response == Response::WrongStatus {
                200
            } else {
                206
            },
            body,
        ));
        replies
    });
    let ram = Reservations::ram(32 << 20);
    let mut store = MemoryStore::new(ram.clone());
    store.core.hf_hub = Some(base);
    let result = store
        .acquire(
            &Scope::Owner,
            Source::HfXet {
                repo: repo(crate::hf::RepoKind::Model),
                commit: "a".repeat(40),
                path: Some("model.safetensors".into()),
            },
            Some(object),
            PinTarget {
                name: pin("bounded").name,
                policy: PinPolicy::Owner,
            },
        )
        .await;
    // The server accepts exactly the expected requests and checks their paths;
    // a refusal before the hostile response therefore cannot pass this test.
    serving.join().unwrap();
    if response == Response::Valid {
        assert_eq!(result.unwrap().object, object);
        let mut read = store
            .read(&Scope::Owner, &path("bounded"), 0..object.bytes())
            .await
            .unwrap();
        let mut actual = Vec::new();
        while let Some(chunk) = read.bytes.next().await {
            actual.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(actual, content);
        drop(read);
        assert_eq!(ram.held(), object.bytes());
    } else {
        assert!(result.is_err(), "{response:?}");
        assert!(
            store
                .stat(&Scope::Owner, &path("bounded"))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(ram.held(), 0);
        assert_eq!(store.collect(&Scope::Owner).await.unwrap().objects, 0);
    }
}

#[tokio::test]
async fn a_well_behaved_hub_is_acquired_verified_and_pinned() {
    acquire_response(Response::Valid).await;
}
#[tokio::test]
async fn oversized_token_is_refused_without_publication() {
    acquire_response(Response::OversizedToken).await;
}
#[tokio::test]
async fn overlong_206_range_is_refused_without_publication() {
    acquire_response(Response::OverlongRange).await;
}
#[tokio::test]
async fn a_200_range_is_refused_without_publication() {
    acquire_response(Response::WrongStatus).await;
}
#[tokio::test]
async fn short_206_range_is_refused_without_publication() {
    acquire_response(Response::ShortRange).await;
}
