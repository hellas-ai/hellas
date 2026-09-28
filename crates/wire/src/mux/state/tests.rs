use super::*;
use crate::clock::DefaultClock;

fn pair<const N: usize>() -> (Multiplexer<N, DefaultClock>, Multiplexer<N, DefaultClock>) {
    let cfg = MuxConfig::default();
    (
        Multiplexer::<N, _>::new(Role::Client, DefaultClock, cfg),
        Multiplexer::<N, _>::new(Role::Server, DefaultClock, cfg),
    )
}

fn drain<const N: usize>(
    from: &mut Multiplexer<N, DefaultClock>,
    to: &mut Multiplexer<N, DefaultClock>,
) -> Vec<Event> {
    let mut all_events = Vec::new();
    while let Some(bytes) = from.next_outbound() {
        let events = to.recv(&bytes).unwrap();
        all_events.extend(events);
    }
    all_events
}

fn queue_body<const N: usize>(
    mux: &mut Multiplexer<N, DefaultClock>,
    slot: SlotIndex,
    payload: Bytes,
) {
    assert!(matches!(
        mux.try_send_body(slot, payload),
        Ok(SendBodyOutcome::Accepted)
    ));
}

#[test]
fn open_send_close_roundtrip() {
    let (mut client, mut server) = pair::<32>();
    let slot = client.open(0xCAFEBABE, Metadata::new()).unwrap();
    assert_eq!(slot, 0); // client owns even, lowest is 0

    let events = drain(&mut client, &mut server);
    assert_eq!(events.len(), 1);
    match &events[0] {
        Event::NewIncomingStream {
            slot: s, method_id, ..
        } => {
            assert_eq!(*s, 0);
            assert_eq!(*method_id, 0xCAFEBABE);
        }
        _ => panic!("expected NewIncomingStream"),
    }

    queue_body(&mut client, slot, Bytes::from_static(b"hello"));
    let events = drain(&mut client, &mut server);
    match &events[0] {
        Event::BodyChunk { slot: s, payload } => {
            assert_eq!(*s, 0);
            assert_eq!(payload.as_ref(), b"hello");
        }
        _ => panic!("expected BodyChunk"),
    }

    client.close_send(slot, None).unwrap();
    let events = drain(&mut client, &mut server);
    match &events[0] {
        Event::EndStream { slot: s, .. } => assert_eq!(*s, 0),
        _ => panic!("expected EndStream"),
    }
}

#[test]
fn reset_after_close_send_emit_still_ships_reset() {
    // Regression: app calls close_send (queues End), the End is
    // emitted by next_outbound (added to pending_terminal_free),
    // then app calls reset() before peer's terminal arrives.
    // `reset` queues a Reset and flips peer_terminal=true; this
    // triggers `drain_pending_terminal_free` on the next
    // next_outbound call. Under the previous eager-clear
    // behavior, `maybe_free_slot` would clear send_queue and
    // discard the still-queued Reset, leaving the peer never
    // told the stream was cancelled.
    let (mut client, mut server) = pair::<32>();
    let s = client.open(0x1, Metadata::new()).unwrap();
    drain(&mut client, &mut server);

    // Client closes-send → emit End → slot enters
    // pending_terminal_free (only local_terminal=true so far).
    client.close_send(s, None).unwrap();
    let end_bytes = client.next_outbound().expect("End");
    let _ = server.recv(&end_bytes).unwrap();

    // App changes its mind and resets. peer_terminal was false,
    // so reset's both-terminal early-return doesn't fire; reset
    // queues a Reset and sets both terminals.
    client.reset(s, WireCode::Cancelled);
    let reset_bytes = client
        .next_outbound()
        .expect("Reset must be emitted, not silently swallowed by maybe_free_slot");
    // Decode and assert it's actually a Reset for our slot.
    let decoded = crate::mux::decode_keyed_frame(&reset_bytes).unwrap();
    assert_eq!(decoded.key.stream_id, s);
    assert!(
        matches!(
            decoded.frame,
            Frame::Reset(ResetFrame {
                code: WireCode::Cancelled
            })
        ),
        "emitted frame must be Reset/Cancelled, got {:?}",
        decoded.frame
    );

    // After the Reset ships, the slot finally frees up so the
    // next open() can reuse the index.
    let _ = client.next_outbound(); // triggers drain
    let new_idx = client.open(0x2, Metadata::new()).unwrap();
    assert_eq!(
        new_idx, s,
        "slot should be reclaimable after both terminals shipped"
    );
}

#[test]
fn parity_ownership() {
    let mut server: Multiplexer<32, _> =
        Multiplexer::new(Role::Server, DefaultClock, MuxConfig::default());
    let slot = server.open(0x1, Metadata::new()).unwrap();
    assert_eq!(slot & 1, 1); // server owns odd
    assert_eq!(slot, 1);
}

#[test]
fn credit_returns_only_after_application_consumption() {
    let cfg = MuxConfig { stream_window: 8 };
    let mut client: Multiplexer<32, _> = Multiplexer::new(Role::Client, DefaultClock, cfg);
    let mut server: Multiplexer<32, _> = Multiplexer::new(Role::Server, DefaultClock, cfg);
    let s = client.open(0x1, Metadata::new()).unwrap();
    drain(&mut client, &mut server);

    queue_body(&mut client, s, Bytes::from_static(b"123456"));
    let events = drain(&mut client, &mut server);
    assert!(matches!(
        &events[..],
        [Event::BodyChunk { payload, .. }] if payload.as_ref() == b"123456"
    ));
    assert!(
        server.next_outbound().is_none(),
        "socket receipt alone must not return credit"
    );

    assert!(matches!(
        client.try_send_body(s, Bytes::from_static(b"abcdef")),
        Ok(SendBodyOutcome::Blocked(_))
    ));
    server.consume(s, 6).unwrap();
    let credit = server.next_outbound().expect("consumption returns credit");
    let decoded = decode_keyed_frame(&credit).unwrap();
    assert!(matches!(
        decoded.frame,
        Frame::Credit(CreditFrame {
            additional_bytes: 6
        })
    ));
    client.recv(&credit).unwrap();
    assert!(matches!(
        client.try_send_body(s, Bytes::from_static(b"abcdef")),
        Ok(SendBodyOutcome::Accepted)
    ));
}

#[test]
fn request_end_still_allows_response_credit_and_cancellation() {
    let cfg = MuxConfig { stream_window: 8 };
    let mut client: Multiplexer<8, _> = Multiplexer::new(Role::Client, DefaultClock, cfg);
    let mut server: Multiplexer<8, _> = Multiplexer::new(Role::Server, DefaultClock, cfg);
    let slot = client.open(7, Metadata::new()).unwrap();
    drain(&mut client, &mut server);
    client.close_send(slot, None).unwrap();
    drain(&mut client, &mut server);
    queue_body(&mut server, slot, Bytes::from_static(b"response"));
    drain(&mut server, &mut client);
    assert!(matches!(
        server.try_send_body(slot, Bytes::from_static(b"next")),
        Ok(SendBodyOutcome::Blocked(_))
    ));
    client.consume(slot, 8).unwrap();
    assert!(matches!(
        drain(&mut client, &mut server).as_slice(),
        [Event::PeerCredit { .. }]
    ));
    queue_body(&mut server, slot, Bytes::from_static(b"next"));
    drain(&mut server, &mut client);
    client.reset(slot, WireCode::Cancelled);
    assert!(matches!(
        drain(&mut client, &mut server).as_slice(),
        [Event::ResetStream {
            code: WireCode::Cancelled,
            ..
        }]
    ));
    assert!(
        server
            .try_send_body(slot, Bytes::from_static(b"late"))
            .is_err()
    );
}

#[test]
fn stale_gen_discarded() {
    let (mut client, mut server) = pair::<32>();
    let s1 = client.open(0x1, Metadata::new()).unwrap();
    // Drain the open so server knows about the slot.
    drain(&mut client, &mut server);

    // Send a body, encode it, but withhold delivery to server.
    queue_body(&mut client, s1, Bytes::from_static(b"x"));
    let stale_bytes = client.next_outbound().unwrap();

    // Now reset and reuse the slot.
    client.reset(s1, WireCode::Cancelled);
    // Deliver the reset to server.
    let reset_bytes = client.next_outbound().unwrap();
    let _ = server.recv(&reset_bytes).unwrap();

    // Re-open: same slot index, new generation.
    let s2 = client.open(0x2, Metadata::new()).unwrap();
    assert_eq!(s2, s1);
    // Drain the new open.
    let open_bytes = client.next_outbound().unwrap();
    let _ = server.recv(&open_bytes).unwrap();

    // NOW deliver the stale body. Should be discarded.
    let events = server.recv(&stale_bytes).unwrap();
    assert!(
        events.is_empty(),
        "stale-generation body should produce no events"
    );
}
