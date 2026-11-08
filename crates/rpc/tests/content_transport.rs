//! Generated bidi dispatch must preserve the live transport's authentication facts.
use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use hellas_rpc::{
    call::ResponseStream,
    pb::content as pb,
    services::content::{ContentClientImpl, ContentHandler, ContentServer},
};
use hellas_wire::{
    AuthLevel, Dispatcher, PeerIdentity, StreamTransport, TransportContext, WireCode, WireStatus,
    clock::DefaultClock,
    mux::{MessagePipe, MuxConfig, MuxTransport, Role},
};
use std::pin::Pin;
use tokio::sync::mpsc;

struct Pipe(mpsc::UnboundedSender<Bytes>, mpsc::UnboundedReceiver<Bytes>);
impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;
    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        self.0.send(bytes).map_err(std::io::Error::other)
    }
    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.1.recv().await)
    }
}
struct Handler;
macro_rules! unused {
    ($method:ident, $request:ty, stream $response:ty) => {
        async fn $method(
            &self,
            _: $request,
            _: TransportContext,
        ) -> Result<ResponseStream<$response>, WireStatus> {
            Err(WireStatus::new(
                WireCode::Unavailable,
                "not used by this transport test",
            ))
        }
    };
    ($method:ident, $request:ty, $response:ty) => {
        async fn $method(
            &self,
            _: $request,
            _: TransportContext,
        ) -> Result<impl Into<hellas_rpc::call::WithTrailer<$response>> + Send, WireStatus> {
            Err::<$response, _>(WireStatus::new(
                WireCode::Unavailable,
                "not used by this transport test",
            ))
        }
    };
}
impl ContentHandler for Handler {
    unused!(stat, pb::StatRequest, pb::StatResponse);
    unused!(chunks, pb::ChunksRequest, pb::ChunksResponse);
    unused!(read, pb::ReadRequest, stream pb::ReadResponse);
    unused!(acquire, pb::AcquireRequest, pb::ContentRef);
    unused!(set_pin, pb::SetPinRequest, pb::SetPinResponse);
    unused!(list_pins, pb::ListPinsRequest, pb::ListPinsResponse);
    unused!(
        watch_pins,
        pb::WatchPinsRequest,
        stream pb::WatchPinsResponse
    );
    unused!(collect, pb::CollectRequest, pb::CollectResponse);
    async fn upload(
        &self,
        requests: Pin<Box<dyn Stream<Item = Result<pb::UploadRequest, WireStatus>> + Send>>,
        context: TransportContext,
    ) -> Result<ResponseStream<pb::UploadResponse>, WireStatus> {
        assert_eq!(context.peer, Some(PeerIdentity([7; 32])));
        assert_eq!(context.auth_level, AuthLevel::Vouched);
        assert_eq!(context.open_exporter, Some([9; 32]));
        Ok(ResponseStream::new(requests.map(|request| {
            let Some(pb::upload_request::Part::Chunk(bytes)) = request?.part else {
                panic!("wrong request reached upload handler");
            };
            assert_eq!(bytes, b"streamed body");
            Ok(pb::UploadResponse {
                next_chunk: bytes.len() as u64,
                missing: false,
                complete: true,
            })
        })))
    }
}

#[tokio::test]
async fn generated_upload_dispatch_delivers_context_and_streams_both_directions() {
    let (a_tx, a_rx) = mpsc::unbounded_channel();
    let (b_tx, b_rx) = mpsc::unbounded_channel();
    let client = MuxTransport::spawn::<8, _, _>(
        Role::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe(a_tx, b_rx),
        TransportContext::default(),
    );
    let server = MuxTransport::spawn::<8, _, _>(
        Role::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe(b_tx, a_rx),
        TransportContext {
            peer: Some(PeerIdentity([7; 32])),
            auth_level: AuthLevel::Vouched,
            open_exporter: Some([9; 32]),
            ..Default::default()
        },
    );
    let serving = tokio::spawn(async move {
        let inbound = server.accept().await.unwrap().unwrap();
        <ContentServer<Handler> as Dispatcher<MuxTransport>>::dispatch(
            &ContentServer(Handler),
            inbound,
        )
        .await
        .unwrap();
    });
    let mut call = ContentClientImpl::new(client).upload().await.unwrap();
    call.send(pb::UploadRequest {
        part: Some(pb::upload_request::Part::Chunk(b"streamed body".to_vec())),
    })
    .await
    .unwrap();
    let progress = call.next().await.unwrap().unwrap();
    assert_eq!(progress.next_chunk, b"streamed body".len() as u64);
    assert!(progress.complete);
    call.close().await.unwrap();
    assert!(call.next().await.is_none());
    call.finish().unwrap();
    serving.await.unwrap();
}
