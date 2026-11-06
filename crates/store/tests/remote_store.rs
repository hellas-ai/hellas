#[path = "support/mux.rs"]
mod mux;
mod support;
use futures::StreamExt;
use hellas_auth::Digest;
use hellas_rpc::{ContentId, ContentRef};
use hellas_store::content::*;
use std::{collections::BTreeMap, sync::atomic::Ordering};
use support::{File, Fixture, Mode};
fn pin() -> PinTarget {
    PinTarget {
        name: PinName::new("uploaded".into()).unwrap(),
        policy: PinPolicy::Owner,
    }
}
fn at() -> Path {
    Path::new(PinName::new("source".into()).unwrap(), String::new()).unwrap()
}
fn remote(fixture: std::sync::Arc<Fixture>) -> RemoteStore<hellas_wire::mux::MuxTransport> {
    RemoteStore::new(mux::mux(fixture), Reservations::ram(4 << 20))
}
async fn upload(store: &RemoteStore<hellas_wire::mux::MuxTransport>, bytes: &[u8]) -> bool {
    let mut upload = store
        .upload(&Scope::Owner, ContentRef::for_bytes(bytes), Some(pin()))
        .await
        .unwrap();
    upload
        .declare(&hellas_xet::chunk(bytes), true)
        .await
        .unwrap();
    upload.accept_chunk(bytes).await.unwrap();
    upload.complete()
}
#[tokio::test]
async fn ranged_and_empty_reads_verify_the_complete_manifest_before_data() {
    let file = File::new(vec![b'x'; 150_000], false);
    let fixture = Fixture::new(BTreeMap::from([(String::new(), file.clone())]), Mode::Good);
    let store = remote(fixture.clone());
    let mut read = store
        .read(&Scope::Public, &at(), 130_000..140_000)
        .await
        .unwrap();
    let mut bytes = Vec::new();
    while let Some(chunk) = read.bytes.next().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(bytes, file.bytes[130_000..140_000]);
    let mut empty = store.read(&Scope::Public, &at(), 0..0).await.unwrap();
    assert_eq!(empty.object, file.object);
    assert!(empty.bytes.next().await.is_none());
    fixture.corrupt_manifest.store(true, Ordering::SeqCst);
    let reads = fixture.reads.load(Ordering::SeqCst);
    assert!(store.read(&Scope::Public, &at(), 0..1).await.is_err());
    assert_eq!(fixture.reads.load(Ordering::SeqCst), reads);
}
#[tokio::test]
async fn pin_movement_or_corrupt_payload_is_rejected_before_range_bytes_escape() {
    for moved in [false, true] {
        let file = File::new(vec![3; 100], false);
        let fixture = Fixture::new(BTreeMap::from([(String::new(), file)]), Mode::Good);
        if moved {
            fixture.moved.store(true, Ordering::SeqCst);
        } else {
            fixture.corrupt_bytes.store(true, Ordering::SeqCst);
        }
        let store = remote(fixture);
        let mut read = store.read(&Scope::Public, &at(), 0..50).await.unwrap();
        assert!(read.bytes.next().await.unwrap().is_err());
    }
}
#[tokio::test]
async fn correctly_hashed_noncanonical_selected_boundaries_are_not_returned() {
    let data = vec![b'x'; 32_768];
    let wrong = vec![
        hellas_xet::Chunk::new(hellas_xet::chunk_hash(&data[..16_384]), 16_384),
        hellas_xet::Chunk::new(hellas_xet::chunk_hash(&data[16_384..]), 16_384),
    ];
    let object = ContentRef::new(
        ContentId::from_bytes(hellas_xet::file_hash(&wrong).into_bytes()),
        data.len() as u64,
    );
    assert_ne!(object.id(), ContentId::hash(&data));
    let file = File {
        bytes: data,
        object,
        chunks: wrong,
        tree: false,
    };
    let store = remote(Fixture::new(
        BTreeMap::from([(String::new(), file)]),
        Mode::Good,
    ));
    let mut read = store
        .read(&Scope::Public, &at(), 0..object.bytes())
        .await
        .unwrap();
    assert!(read.bytes.next().await.unwrap().is_err());
}
#[tokio::test]
async fn failed_acknowledgements_and_trailers_never_report_complete_and_allow_clean_retry() {
    for mode in [Mode::BadDeclarationOnce, Mode::BadTrailerOnce] {
        let fixture = Fixture::new(BTreeMap::new(), mode);
        let store = remote(fixture.clone());
        let bytes = b"sent";
        let mut session = store
            .upload(&Scope::Owner, ContentRef::for_bytes(bytes), Some(pin()))
            .await
            .unwrap();
        let declared = session.declare(&hellas_xet::chunk(bytes), true).await;
        if mode == Mode::BadDeclarationOnce {
            assert!(declared.is_err());
        } else {
            declared.unwrap();
            assert!(session.accept_chunk(bytes).await.is_err());
        }
        assert!(!session.complete());
        drop(session);
        assert!(upload(&store, bytes).await);
        assert_eq!(fixture.uploads.load(Ordering::SeqCst), 2);
    }
}
#[tokio::test]
async fn concurrent_objects_are_refused_and_cancellation_owns_the_stream() {
    let fixture = Fixture::new(BTreeMap::new(), Mode::HoldFirstDeclaration);
    let store = remote(fixture.clone());
    let bytes = b"payload";
    let mut first = store
        .upload(&Scope::Owner, ContentRef::for_bytes(bytes), Some(pin()))
        .await
        .unwrap();
    assert!(matches!(
        store
            .upload(&Scope::Owner, ContentRef::for_bytes(b"other"), Some(pin()))
            .await,
        Err(Error::Conflict)
    ));
    let chunks = hellas_xet::chunk(bytes);
    {
        let declaring = first.declare(&chunks, true);
        tokio::pin!(declaring);
        tokio::select! {
            result = &mut declaring => panic!("declaration unexpectedly returned: {result:?}"),
            _ = fixture.entered.notified() => {}
        }
    }
    // Cancelling a borrowed operation poisons its verifier until it is dropped;
    // the unacknowledged chunk-list progress cannot be reused.
    assert!(!first.complete());
    assert!(first.accept_chunk(bytes).await.is_err());
    drop(first);
    assert!(upload(&store, bytes).await);
}
#[tokio::test]
async fn a_work_opening_uses_one_upload_stream_for_multiple_objects() {
    let fixture = Fixture::new(BTreeMap::new(), Mode::Good);
    let store = remote(fixture.clone()).with_opening(hellas_rpc::pb::content::WorkOpening {
        binding_signature: vec![],
        signed_opening: vec![1],
        manifest: vec![2],
        root: Some(support::reference(ContentRef::for_bytes(b"root"))),
    });
    let scope = Scope::work(
        JobId {
            channel: Digest::ZERO,
            id: Digest::ZERO,
        },
        vec![
            ContentRef::for_bytes(b"root"),
            ContentRef::for_bytes(b"next"),
        ],
        0,
    );
    for bytes in [b"root", b"next"] {
        let mut session = store
            .upload(&scope, ContentRef::for_bytes(bytes), None)
            .await
            .unwrap();
        session
            .declare(&hellas_xet::chunk(bytes), true)
            .await
            .unwrap();
        session.accept_chunk(bytes).await.unwrap();
        assert!(session.complete());
    }
    store.finish_uploads().await.unwrap();
    assert_eq!(fixture.uploads.load(Ordering::SeqCst), 1);
}
