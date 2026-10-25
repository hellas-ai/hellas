use super::*;

#[test]
fn varint_roundtrip() {
    for v in [0u64, 1, 127, 128, 300, 16384, u64::MAX] {
        let mut buf = bytes::BytesMut::new();
        write_varint(v, &mut buf);
        let (decoded, _) = read_varint(&buf).unwrap();
        assert_eq!(v, decoded);
    }
}

#[test]
fn varint_partial_distinguishes_truncated_from_malformed() {
    // Empty buffer is truncated, not malformed.
    assert_eq!(read_varint_partial(&[]).unwrap(), None);
    // 1..=9 continuation bytes is truncated; we don't know the next
    // byte yet.
    for n in 1usize..=9 {
        let buf = vec![0xFFu8; n];
        assert_eq!(
            read_varint_partial(&buf).unwrap(),
            None,
            "truncated at {n} should be Ok(None), got something else"
        );
    }
    // 10 continuation bytes — there is no legal u64 varint with
    // 10 continuation bytes, so this is fatal.
    let mut buf = vec![0xFFu8; 10];
    assert!(matches!(
        read_varint_partial(&buf),
        Err(FrameError::BadVarint)
    ));
    // 10 bytes where the 10th has the stop bit: valid u64 varint
    // (encodes u64::MAX with the standard LEB128 layout).
    buf[9] = 0x01;
    let (val, consumed) = read_varint_partial(&buf).unwrap().unwrap();
    assert_eq!(consumed, 10);
    assert_eq!(val, u64::MAX);

    // The tenth byte has only one payload bit. Without this check, the
    // shift discarded high bits and hostile overlong lengths aliased a
    // smaller u64 value.
    buf[9] = 0x02;
    assert!(matches!(
        read_varint_partial(&buf),
        Err(FrameError::BadVarint)
    ));

    assert!(matches!(
        read_varint_partial(&[0x80, 0x00]),
        Err(FrameError::BadVarint)
    ));
}

#[test]
fn varint_blocking_wrapper_rejects_truncation_as_badvarint() {
    // The `must-be-complete` wrapper collapses Ok(None) to BadVarint.
    // Anything that wasn't a complete varint is a hard error here.
    assert!(matches!(read_varint(&[]), Err(FrameError::BadVarint)));
    assert!(matches!(read_varint(&[0xFF]), Err(FrameError::BadVarint)));
}

#[test]
fn max_frame_bytes_is_a_real_cap() {
    // Documented expectation rather than a runtime check — pin the
    // constant so a change forces a deliberate audit.
    const {
        assert!(MAX_FRAME_BYTES >= 1 << 20);
        assert!(MAX_FRAME_BYTES <= 16 * 1024 * 1024);
    }
    assert_eq!(
        bounded_frame_len(MAX_FRAME_BYTES as u64).unwrap(),
        MAX_FRAME_BYTES
    );
    assert!(matches!(
        bounded_frame_len(u64::MAX),
        Err(FrameError::OversizedFrame {
            len: usize::MAX,
            cap: _
        })
    ));
}

#[test]
fn open_frame_roundtrip() {
    let mut headers = Metadata::new();
    headers.insert_text("k1", "v1");
    headers.insert_bytes("k2-bin", Bytes::from_static(b"\x01\x02\x03"));
    let frame = Frame::Open(OpenFrame {
        method_id: 0xDEAD_BEEF,
        headers,
    });
    let mut buf = bytes::BytesMut::new();
    encode_frame(&frame, &mut buf);
    let decoded = decode_frame(&buf).unwrap();
    match decoded {
        Frame::Open(o) => {
            assert_eq!(o.method_id, 0xDEAD_BEEF);
            assert_eq!(o.headers.get("k1").unwrap().as_text(), Some("v1"));
            assert_eq!(
                o.headers.get("k2-bin").unwrap().as_bytes(),
                Some(&b"\x01\x02\x03"[..])
            );
        }
        _ => panic!("expected Open"),
    }
}

#[test]
fn structured_frames_reject_trailing_bytes() {
    for frame in [
        Frame::Open(OpenFrame {
            method_id: 7,
            headers: Metadata::new(),
        }),
        Frame::End(EndFrame {
            status: WireCode::Ok,
            trailer: Trailer::ok(),
        }),
        Frame::Reset(ResetFrame {
            code: WireCode::Cancelled,
        }),
        Frame::Credit(CreditFrame {
            additional_bytes: 1,
        }),
    ] {
        let mut encoded = bytes::BytesMut::new();
        encode_frame(&frame, &mut encoded);
        encoded.extend_from_slice(&[0]);
        assert!(matches!(
            decode_frame(&encoded),
            Err(FrameError::TrailingBytes { remaining: 1 })
        ));
    }
}

#[test]
fn outbound_size_is_rejected_before_encoding() {
    let oversized = Frame::Body(Bytes::from(vec![0; MAX_FRAME_BYTES]));
    assert!(matches!(
        encoded_frame_len(&oversized),
        Err(FrameError::OversizedFrame {
            len,
            cap: MAX_FRAME_BYTES,
        }) if len == MAX_FRAME_BYTES + 1
    ));

    let mut metadata = Metadata::new();
    metadata.insert_bytes("large", Bytes::from(vec![0; METADATA_MAX_FIELD_LEN + 1]));
    let open = Frame::Open(OpenFrame {
        method_id: 8,
        headers: metadata,
    });
    assert!(matches!(
        encoded_frame_len(&open),
        Err(FrameError::BodyTooLarge {
            len,
            limit: METADATA_MAX_FIELD_LEN,
        }) if len == METADATA_MAX_FIELD_LEN + 1
    ));
}

#[test]
fn end_frame_roundtrip() {
    let frame = Frame::End(EndFrame {
        status: WireCode::Ok,
        trailer: Trailer::from_status(WireCode::Ok, "done"),
    });
    let mut buf = bytes::BytesMut::new();
    encode_frame(&frame, &mut buf);
    let decoded = decode_frame(&buf).unwrap();
    match decoded {
        Frame::End(e) => {
            assert_eq!(e.trailer.status, WireCode::Ok);
            assert_eq!(e.trailer.message.as_str(), "done");
        }
        _ => panic!("expected End"),
    }
}

#[test]
fn inbound_frame_size_is_rejected_before_body_copy() {
    let mut bytes = vec![0; MAX_FRAME_BYTES];
    bytes[0] = FrameKind::Body.as_u8();
    assert!(matches!(decode_frame(&bytes), Ok(Frame::Body(_))));
    bytes.push(0);
    assert!(
        matches!(decode_frame(&bytes), Err(FrameError::OversizedFrame { len, cap })
        if len == MAX_FRAME_BYTES + 1 && cap == MAX_FRAME_BYTES)
    );
}
