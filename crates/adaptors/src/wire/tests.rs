use super::*;
use serde_json::json;

#[test]
fn json_response_sets_content_type() {
    let response = WireResponse::json(200, json!({"ok": true}));
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}

#[test]
fn stream_event_can_be_named_json() {
    let event = WireStreamEvent::json(Some("response.created".to_string()), json!({"x": 1}));
    assert_eq!(event.name.as_deref(), Some("response.created"));
    assert_eq!(event.data, WireEventData::Json(json!({"x": 1})));
}

#[test]
fn sse_decoder_parses_split_lf_frames() {
    let mut decoder = SseDecoder::new();
    assert!(decoder.push(b"event: a\nda").unwrap().is_empty());
    let events = decoder.push(b"ta: one\n\n").unwrap();
    assert_eq!(
        events,
        vec![WireStreamEvent::text(Some("a".to_string()), "one")]
    );
    assert!(decoder.finish().unwrap().is_empty());
}

#[test]
fn sse_decoder_parses_crlf_and_multiline_data() {
    let mut decoder = SseDecoder::new();
    let events = decoder
        .push(b"event: delta\r\ndata: one\r\ndata: two\r\n\r\n")
        .unwrap();
    assert_eq!(
        events,
        vec![WireStreamEvent::text(Some("delta".to_string()), "one\ntwo")]
    );
}

#[test]
fn sse_decoder_counts_lines_hidden_by_permissive_sse_semantics() {
    let mut decoder = SseDecoder::new();
    let events = decoder
        .push(b": comment\nevent: delta\nevent: duplicate\nid: hidden\ndata: one\n\n")
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(decoder.ignored_line_count(), 3);
}

#[test]
fn sse_decoder_marks_permissive_data_framing_without_changing_its_output() {
    let mut decoder = SseDecoder::new();
    let events = decoder
        .push(b"data: one\nevent: delta\ndata: two\n\n")
        .unwrap();

    assert_eq!(
        events,
        vec![WireStreamEvent::text(Some("delta".to_string()), "one\ntwo")]
    );
    assert_eq!(decoder.noncanonical_line_count(), 3);
}

#[test]
fn sse_decoder_rejects_delimiter_free_frame_over_limit() {
    let mut decoder = SseDecoder::new();
    let oversized = vec![b'x'; MAX_SSE_FRAME_BYTES + 1];

    let error = decoder.push(&oversized).unwrap_err();

    assert!(error.to_string().contains("SSE frame exceeds"));
    assert!(decoder.buffer.len() <= MAX_SSE_FRAME_BYTES + MAX_SSE_DELIMITER_BYTES);
}

#[test]
fn sse_decoder_rejects_delimited_frame_over_limit_before_copying_frame() {
    let mut decoder = SseDecoder::new();
    let mut oversized = vec![b'x'; MAX_SSE_FRAME_BYTES + 1];
    oversized.extend_from_slice(b"\n\n");

    let error = decoder.push(&oversized).unwrap_err();

    assert!(error.to_string().contains("SSE frame exceeds"));
    assert!(decoder.buffer.len() <= MAX_SSE_FRAME_BYTES + MAX_SSE_DELIMITER_BYTES);
}

#[test]
fn sse_decoder_accepts_limit_sized_frame_with_split_crlf_delimiter() {
    let mut decoder = SseDecoder::new();
    let mut frame = b"data: ".to_vec();
    frame.resize(MAX_SSE_FRAME_BYTES, b'x');
    frame.extend_from_slice(b"\r\n\r");

    assert!(decoder.push(&frame).unwrap().is_empty());
    let events = decoder.push(b"\n").unwrap();

    assert_eq!(events.len(), 1);
    let WireEventData::Text(data) = &events[0].data else {
        panic!("SSE data should decode as text");
    };
    assert_eq!(data.len(), MAX_SSE_FRAME_BYTES - b"data: ".len());
}

#[test]
fn sse_decoder_accepts_response_made_of_many_bounded_frames() {
    let mut frame = b"data: ".to_vec();
    frame.resize(1022, b'x');
    frame.extend_from_slice(b"\n\n");
    let frame_count = MAX_SSE_RESPONSE_BYTES / frame.len();
    let mut aggregate = Vec::with_capacity(frame_count * frame.len());
    for _ in 0..frame_count {
        aggregate.extend_from_slice(&frame);
    }
    assert!(aggregate.len() <= MAX_SSE_RESPONSE_BYTES);

    let events = SseDecoder::new().push(&aggregate).unwrap();

    assert_eq!(events.len(), frame_count);
}

#[test]
fn sse_decoder_caps_semantic_events_across_network_pushes() {
    let mut decoder = SseDecoder::new();
    let frame = b"data: x\n\n";
    let first_half = frame.repeat(MAX_SSE_EVENTS as usize / 2);
    let second_half = frame.repeat(MAX_SSE_EVENTS as usize / 2);

    assert_eq!(
        decoder.push(&first_half).unwrap().len(),
        MAX_SSE_EVENTS as usize / 2
    );
    assert_eq!(
        decoder.push(&second_half).unwrap().len(),
        MAX_SSE_EVENTS as usize / 2
    );
    let error = decoder.push(frame).unwrap_err();

    assert!(error.to_string().contains("65536-event limit"));
}

#[test]
fn sse_comment_keepalives_do_not_consume_the_semantic_event_budget() {
    let mut decoder = SseDecoder::new();
    let keepalives = b": ping\n\n".repeat(MAX_SSE_EVENTS as usize + 1);

    assert!(decoder.push(&keepalives).unwrap().is_empty());
    assert_eq!(decoder.frame_count(), MAX_SSE_EVENTS + 1);
    assert_eq!(decoder.ignored_line_count(), MAX_SSE_EVENTS + 1);
}

#[test]
fn sse_decoder_enforces_the_aggregate_response_byte_limit() {
    let mut decoder = SseDecoder::new();
    let mut exact = vec![b' '; MAX_SSE_FRAME_BYTES];
    exact.extend_from_slice(b"\r\n\r\n");
    assert_eq!(exact.len(), MAX_SSE_RESPONSE_BYTES);
    assert!(decoder.push(&exact).unwrap().is_empty());

    let error = decoder.push(b"x").unwrap_err();
    assert!(error.to_string().contains("response exceeds"));
}

#[test]
fn fragmented_large_frames_preserve_payloads_and_framing_counters() {
    let payload = "x".repeat(32 * 1024) + "é";
    let wire = format!(
        "event: delta\r\ndata: {payload}\r\n\r\nevent: done\ndata: ok\n\nevent: eof\ndata: tail"
    );
    let expected = vec![
        WireStreamEvent::text(Some("delta".into()), payload),
        WireStreamEvent::text(Some("done".into()), "ok"),
        WireStreamEvent::text(Some("eof".into()), "tail"),
    ];
    for size in [1, 2, 3, 127, 16 * 1024, wire.len()] {
        let mut decoder = SseDecoder::new();
        let mut events = Vec::new();
        for chunk in wire.as_bytes().chunks(size) {
            events.extend(decoder.push(chunk).unwrap());
        }
        events.extend(decoder.finish().unwrap());
        assert_eq!(events, expected, "chunk size {size}");
        assert!(decoder.pending_bytes().is_empty());
        assert_eq!(decoder.frame_count(), 3);
        assert_eq!(decoder.ignored_line_count(), 0);
        assert_eq!(decoder.noncanonical_line_count(), 0);
    }
}
