use super::*;
use crate::clock::DefaultClock;
use crate::frame::{CreditFrame, EndFrame, Frame, OpenFrame};
use crate::metadata::Trailer;
use crate::mux::{SendBodyOutcome, StreamKey, decode_keyed_frame, encode_keyed_frame};

struct IdlePipe {
    recv_rx: mpsc::UnboundedReceiver<Bytes>,
    dropped: Option<oneshot::Sender<()>>,
}

impl MessagePipe for IdlePipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    async fn send_message(&mut self, _bytes: Bytes) -> Result<(), Self::SendError> {
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.recv_rx.recv().await)
    }
}

impl Drop for IdlePipe {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

/// A pipe that keeps every frame the driver ships, so a test can ask
/// what actually went out rather than what the driver meant to send.
struct RecordingPipe {
    recv_rx: mpsc::UnboundedReceiver<Bytes>,
    sent: mpsc::UnboundedSender<Bytes>,
}

impl MessagePipe for RecordingPipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        let _ = self.sent.send(bytes);
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.recv_rx.recv().await)
    }
}

fn open_frame(slot: SlotIndex, generation: u16, method_id: u32) -> Bytes {
    encode_keyed_frame(
        StreamKey::new(slot, generation),
        &Frame::Open(OpenFrame {
            method_id,
            headers: Metadata::new(),
        }),
    )
}

fn body_frame(slot: SlotIndex, generation: u16, payload: &'static [u8]) -> Bytes {
    encode_keyed_frame(
        StreamKey::new(slot, generation),
        &Frame::Body(Bytes::from_static(payload)),
    )
}

fn end_frame(slot: SlotIndex, generation: u16) -> Bytes {
    encode_keyed_frame(
        StreamKey::new(slot, generation),
        &Frame::End(EndFrame {
            status: WireCode::Ok,
            trailer: Trailer::ok(),
        }),
    )
}

/// A slot index is a seat, not a name. A half that lets go of a
/// finished stream cancels that stream and no other — even when the
/// peer has already seated a new stream in the same index.
///
/// The sequence is the one a unary server dispatch produces: it reads
/// one body and never drains to EOF, so its recv half is still "live"
/// when it drops and asks the driver to reset. The peer, meanwhile, is
/// free to reuse the index the moment both terminals have crossed.
#[tokio::test]
async fn a_finished_stream_s_reset_cannot_cancel_the_slot_s_next_tenant() {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
    let (_wire_tx, wire_rx) = mpsc::unbounded_channel();
    let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
    let mut driver = MuxDriver::<8, _, _> {
        mux: Multiplexer::new(Role::Server, DefaultClock, MuxConfig::default()),
        pipe: RecordingPipe {
            recv_rx: wire_rx,
            sent: sent_tx,
        },
        cmd_rx,
        cmd_tx: cmd_tx.downgrade(),
        inbound_tx,
        slot_to_chans: Default::default(),
        pending_sends: Default::default(),
        authorities: Default::default(),
        context: TransportContext::default(),
    };

    // The peer opens slot 0 generation 1 and completes its request.
    driver.handle_inbound(open_frame(0, 1, 7)).await;
    let first = inbound_rx.try_recv().expect("first inbound stream");
    let (_send, recv) = crate::transport::Stream::split(first.stream);
    driver.handle_inbound(body_frame(0, 1, b"one")).await;
    driver.handle_inbound(end_frame(0, 1)).await;

    // We answer and close. Both terminals have now crossed on
    // generation 1, which is precisely what entitles the peer to
    // reuse the index.
    let (reply, _replied) = oneshot::channel();
    driver
        .handle_command(Command::CloseSend {
            authority: None,
            key: StreamKey::new(0, 1),
            trailer: None,
            reply,
        })
        .await;
    assert!(driver.flush_outbound().await);

    // The handler drops a recv half it never drained, which asks the
    // driver to reset the stream it was reading.
    drop(recv);

    // Before that command is served, the peer seats a new stream in
    // the freed index.
    driver.handle_inbound(open_frame(0, 2, 9)).await;
    let second = inbound_rx.try_recv().expect("second inbound stream");
    let (_send, recv) = crate::transport::Stream::split(second.stream);

    let stale = driver
        .cmd_rx
        .try_recv()
        .expect("dropping an undrained recv half resets its slot");
    assert!(matches!(
        stale,
        Command::Reset {
            key: StreamKey {
                stream_id: 0,
                generation: 1,
            },
            code: WireCode::Cancelled,
        }
    ));
    driver.handle_command(stale).await;
    assert!(driver.flush_outbound().await);

    // Nothing may have gone out cancelling the new tenant.
    while let Ok(bytes) = sent_rx.try_recv() {
        let decoded = decode_keyed_frame(&bytes).expect("driver ships decodable frames");
        assert!(
            !(decoded.key == StreamKey::new(0, 2) && matches!(decoded.frame, Frame::Reset(_))),
            "generation 1's reset was applied to generation 2"
        );
    }

    // And the new tenant's request body must still reach it.
    driver.handle_inbound(body_frame(0, 2, b"two")).await;
    let mut recv = std::pin::pin!(recv);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match futures_core::Stream::poll_next(recv.as_mut(), &mut cx) {
        std::task::Poll::Ready(Some(Ok(bytes))) => assert_eq!(&bytes[..], b"two"),
        other => panic!("the new tenant lost its request body: {other:?}"),
    }
}

#[tokio::test]
async fn blocked_send_resumes_when_peer_credit_arrives() {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let (_wire_tx, wire_rx) = mpsc::unbounded_channel();
    let mut driver = MuxDriver::<8, _, _> {
        mux: Multiplexer::new(Role::Client, DefaultClock, MuxConfig { stream_window: 8 }),
        pipe: IdlePipe {
            recv_rx: wire_rx,
            dropped: None,
        },
        cmd_rx,
        cmd_tx: cmd_tx.downgrade(),
        inbound_tx,
        slot_to_chans: Default::default(),
        pending_sends: Default::default(),
        authorities: Default::default(),
        context: TransportContext::default(),
    };

    let slot = driver.mux.open(7, Metadata::new()).unwrap();
    driver.mux.next_outbound().expect("open frame");
    assert!(matches!(
        driver
            .mux
            .try_send_body(slot, Bytes::from_static(b"123456")),
        Ok(SendBodyOutcome::Accepted)
    ));
    driver.mux.next_outbound().expect("first body");

    let (reply_tx, mut reply_rx) = oneshot::channel();
    driver.start_send(slot, Bytes::from_static(b"abcdef"), reply_tx);
    assert!(matches!(
        reply_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let credit = encode_keyed_frame(
        StreamKey::new(slot, 1),
        &Frame::Credit(CreditFrame {
            additional_bytes: 6,
        }),
    );
    driver.handle_inbound(credit).await;
    assert!(reply_rx.await.unwrap().is_ok());
}

#[tokio::test]
async fn dropping_last_transport_owner_drops_the_pipe() {
    let (_wire_tx, wire_rx) = mpsc::unbounded_channel();
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let transport = MuxTransport::spawn::<8, _, _>(
        Role::Client,
        DefaultClock,
        MuxConfig::default(),
        IdlePipe {
            recv_rx: wire_rx,
            dropped: Some(dropped_tx),
        },
        TransportContext::default(),
    );

    drop(transport);
    dropped_rx
        .await
        .expect("driver must terminate when its final owner disappears");
}

#[tokio::test]
async fn recycled_peer_slots_cannot_overflow_the_inbound_queue() {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
    let (_wire_tx, wire_rx) = mpsc::unbounded_channel();
    let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
    let mut driver = MuxDriver::<8, _, _> {
        mux: Multiplexer::new(Role::Server, DefaultClock, MuxConfig::default()),
        pipe: RecordingPipe {
            recv_rx: wire_rx,
            sent: sent_tx,
        },
        cmd_rx,
        cmd_tx: cmd_tx.downgrade(),
        inbound_tx,
        slot_to_chans: Default::default(),
        pending_sends: Default::default(),
        authorities: Default::default(),
        context: TransportContext::default(),
    };
    for generation in 1..=12 {
        driver.handle_inbound(open_frame(0, generation, 7)).await;
        assert!(driver.flush_outbound().await);
        driver
            .handle_inbound(encode_keyed_frame(
                StreamKey::new(0, generation),
                &Frame::Reset(crate::ResetFrame {
                    code: WireCode::Cancelled,
                }),
            ))
            .await;
        assert!(driver.flush_outbound().await);
    }
    assert_eq!(
        inbound_rx.len(),
        4,
        "resetting slots cannot grow the pending queue"
    );
    let mut refused = 0;
    while let Ok(bytes) = sent_rx.try_recv() {
        if let Frame::Reset(reset) = decode_keyed_frame(&bytes).unwrap().frame {
            assert_eq!(reset.code, WireCode::ResourceExhausted);
            refused += 1;
        }
    }
    assert_eq!(
        refused, 8,
        "every overflowing Open gets a resource-exhausted reset"
    );
    for _ in 0..4 {
        drop(inbound_rx.try_recv().unwrap());
    }
    driver.handle_inbound(open_frame(0, 13, 99)).await;
    assert_eq!(
        inbound_rx.try_recv().unwrap().method_id,
        99,
        "draining restores admission"
    );
}
