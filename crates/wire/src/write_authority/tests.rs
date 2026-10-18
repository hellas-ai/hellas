use super::*;
use std::task::Waker;

#[derive(Clone, Default)]
pub(crate) struct Gate {
    state: Arc<Mutex<(bool, Option<Waker>)>>,
    pub(crate) blocked: Arc<tokio::sync::Notify>,
}
impl Gate {
    pub(crate) fn authority(&self) -> WriteAuthority {
        WriteAuthority::new(self.clone())
    }
    pub(crate) fn revoke(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        if let Some(waker) = state.1.take() {
            waker.wake();
        }
    }
}
impl WriteAuthorization for Gate {
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        write: &mut dyn FnMut(&mut Context<'_>) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        let mut state = self.state.lock().unwrap();
        state.1 = Some(cx.waker().clone());
        if state.0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "revoked",
            )));
        }
        let result = write(cx);
        if result.is_pending() {
            self.blocked.notify_one();
        }
        result
    }
}

#[cfg(all(not(target_family = "wasm"), any(feature = "mux", feature = "iroh")))]
#[tokio::test]
async fn rechecks_each_carrier_poll_and_releases_authority_during_backpressure() {
    use tokio::io::AsyncReadExt;
    let gate = Gate::default();
    let authority = gate.authority();
    let (mut writer, mut reader) = tokio::io::duplex(3);
    let mut sending = Box::pin(authority.write_all(&mut writer, b"abcdef"));
    assert!(futures::poll!(&mut sending).is_pending());
    // This acquires the same authority mutex used around poll_write.
    gate.revoke();
    let mut first = [0; 3];
    reader.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"abc");
    assert_eq!(
        sending.await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    drop(writer);
    let mut rest = vec![];
    reader.read_to_end(&mut rest).await.unwrap();
    assert!(
        rest.is_empty(),
        "unsent bytes must not reach newly available capacity"
    );
}

#[cfg(all(not(target_family = "wasm"), any(feature = "mux", feature = "iroh")))]
#[tokio::test]
async fn writes_are_bounded_and_inside_the_authority_writer() {
    use std::pin::Pin;
    use tokio::io::AsyncWrite;
    struct Writer {
        gate: Gate,
        sizes: Vec<usize>,
    }
    impl AsyncWrite for Writer {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            assert!(
                self.gate.state.try_lock().is_err(),
                "write must share the authority writer"
            );
            self.sizes.push(bytes.len());
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let gate = Gate::default();
    let mut writer = Writer {
        gate: gate.clone(),
        sizes: vec![],
    };
    gate.authority()
        .write_all(&mut writer, &vec![0; 150_000])
        .await
        .unwrap();
    assert_eq!(writer.sizes, [65536, 65536, 18928]);
}

#[cfg(all(feature = "mux", not(target_family = "wasm")))]
#[tokio::test]
async fn mux_rechecks_below_its_queues_when_the_byte_carrier_is_blocked() {
    use crate::framed::LengthDelimitedMessagePipe;
    use crate::mux::{MessagePipe, MuxConfig, MuxTransport, Role};
    use crate::{SendHalf, Stream, StreamTransport};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (local, mut remote) = tokio::io::duplex(64);
    let transport = MuxTransport::spawn::<8, _, _>(
        Role::Client,
        crate::DefaultClock,
        MuxConfig {
            stream_window: 1024,
        },
        LengthDelimitedMessagePipe::new(local, 2048).unwrap(),
        Default::default(),
    );
    let stream = transport.open(7, Default::default()).await.unwrap();
    let mut length = [0; 4];
    remote.read_exact(&mut length).await.unwrap();
    let mut open = vec![0; u32::from_be_bytes(length) as usize];
    remote.read_exact(&mut open).await.unwrap();
    let (mut send, _recv) = stream.split();
    let gate = Gate::default();
    send.set_write_authority(gate.authority()).unwrap();
    send.send_body(bytes::Bytes::from(vec![42; 512]))
        .await
        .unwrap();
    gate.blocked.notified().await;
    gate.revoke();
    // Only the already handed-off prefix may remain in the byte pipe. The mux
    // must discard the rest instead of completing its earlier queued send.
    let mut accepted = vec![];
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        remote.read_to_end(&mut accepted),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(accepted.len(), 64);
    remote.shutdown().await.unwrap();
    // A pipe without an authorized implementation never falls back to send_message.
    struct Unsupported;
    impl MessagePipe for Unsupported {
        type SendError = io::Error;
        type RecvError = io::Error;
        async fn send_message(&mut self, _: bytes::Bytes) -> io::Result<()> {
            panic!("unguarded fallback")
        }
        async fn recv_message(&mut self) -> io::Result<Option<bytes::Bytes>> {
            Ok(None)
        }
    }
    assert_eq!(
        Unsupported
            .send_message_authorized(bytes::Bytes::from_static(b"secret"), &gate.authority())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
}

#[cfg(all(feature = "mux", not(target_family = "wasm")))]
#[tokio::test]
async fn mux_revocation_wakes_credit_waiters_and_drops_their_queued_body() {
    use crate::RecvHalf;
    use crate::framed::LengthDelimitedMessagePipe;
    use crate::mux::{MessagePipe, MuxConfig, MuxTransport, Role, decode_keyed_frame};
    use crate::{SendHalf, Stream, StreamTransport};
    use futures::StreamExt;
    let (local, remote) = tokio::io::duplex(512);
    let transport = MuxTransport::spawn::<8, _, _>(
        Role::Client,
        crate::DefaultClock,
        MuxConfig { stream_window: 8 },
        LengthDelimitedMessagePipe::new(local, 512).unwrap(),
        Default::default(),
    );
    let mut remote = LengthDelimitedMessagePipe::new(remote, 512).unwrap();
    let stream = transport.open(7, Default::default()).await.unwrap();
    remote.recv_message().await.unwrap().unwrap();
    let (mut send, mut recv) = stream.split();
    let gate = Gate::default();
    send.set_write_authority(gate.authority()).unwrap();
    assert!(
        send.set_write_authority(Gate::default().authority())
            .is_err()
    );
    send.send_body(bytes::Bytes::from_static(b"accepted"))
        .await
        .unwrap();
    let first = remote.recv_message().await.unwrap().unwrap();
    assert!(matches!(
        decode_keyed_frame(&first).unwrap().frame,
        crate::Frame::Body(_)
    ));
    let mut pending = Box::pin(send.send_body(bytes::Bytes::from_static(b"private!")));
    assert!(futures::poll!(&mut pending).is_pending());
    // Commands are FIFO: this Open proves the second body reached the mux and
    // is waiting for credit before revocation, rather than just sitting at ingress.
    let _barrier = transport.open(8, Default::default()).await.unwrap();
    let barrier = remote.recv_message().await.unwrap().unwrap();
    assert!(matches!(
        decode_keyed_frame(&barrier).unwrap().frame,
        crate::Frame::Open(_)
    ));
    gate.revoke();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), pending)
            .await
            .unwrap()
            .is_err()
    );
    let frame = remote.recv_message().await.unwrap().unwrap();
    assert!(matches!(
        decode_keyed_frame(&frame).unwrap().frame,
        crate::Frame::Reset(_)
    ));
    assert!(recv.next().await.is_none());
    assert_eq!(
        recv.trailer().unwrap().status,
        crate::WireCode::PermissionDenied
    );
}
