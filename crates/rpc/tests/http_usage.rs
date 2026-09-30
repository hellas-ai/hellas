#![cfg(feature = "fetch")]
use hellas_rpc::http_usage::*;
use std::io::Write;
fn compressed(bytes: &[u8], encoding: &str) -> Vec<u8> {
    match encoding {
        "identity" => bytes.to_vec(),
        "gzip" => {
            let mut w = flate2::write::GzEncoder::new(vec![], flate2::Compression::fast());
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        }
        "deflate" => {
            let mut w = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::fast());
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        }
        "br" => {
            let mut w = brotli::CompressorWriter::new(vec![], 4096, 3, 22);
            w.write_all(bytes).unwrap();
            w.into_inner()
        }
        _ => unreachable!(),
    }
}
#[test]
fn strict_json_and_sse_verify_every_compression_and_fragment_boundary() {
    let json = br#"{"usage":{"prompt_tokens":7,"completion_tokens":3}}"#;
    let sse=b"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}],\"usage\":null}\r\n\r\ndata: {\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3}}\n\ndata: [DONE]\n\n";
    for (wire, content) in [
        (&json[..], "application/json"),
        (&sse[..], "text/event-stream"),
    ] {
        for encoding in ["identity", "gzip", "deflate", "br"] {
            let wire = compressed(wire, encoding);
            for size in 1..=wire.len() {
                let mut usage = UsageDecoder::new(
                    Mode::Strict(AccountingProfile::OpenaiChat),
                    Some(content),
                    Some(encoding),
                );
                for chunk in wire.chunks(size) {
                    usage.push(chunk);
                }
                usage.finish();
                assert_eq!(
                    usage.strict_usage(),
                    Ok((7, 3)),
                    "encoding {encoding}, fragment {size}"
                );
            }
        }
    }
}
#[test]
fn strict_refuses_missing_duplicate_regressing_and_ambiguous_usage() {
    for body in [
        &b"data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":8}}\n\n"[..],
        b"data: [DONE]\n\n",
        b"data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":8}}\n\ndata: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":7}}\n\ndata: [DONE]\n\n",
        b"data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":8}}\n\ndata: [DONE]\n\ndata: [DONE]\n\n",
        br#"{"usage":{"prompt_tokens":1,"completion_tokens":8,"completion_tokens":1}}"#,
        br#"{"usage":{"prompt_tokens":1,"completion_tokens":-1}}"#,
        br#"{"usage":{"prompt_tokens":1,"completion_tokens":3.5}}"#,
        br#"{"usage":{"input_tokens":1,"output_tokens":3}}"#,
        br#"{"error":"no usage"}"#,
    ] {
        let mut usage=UsageDecoder::new(Mode::Strict(AccountingProfile::OpenaiChat),None,None);
        for chunk in body.chunks(3){usage.push(chunk);}
        usage.finish();assert!(usage.strict_usage().is_err(),"body {body:?}");
    }
    let mut telemetry = UsageDecoder::default();
    telemetry.push(b"data: {\"usage\":{\"input_tokens\":1,\"output_tokens\":8}}\n\ndata: {\"usage\":{\"output_tokens\":7}}\n\n");
    telemetry.finish();
    assert_eq!((telemetry.input, telemetry.output), (Some(1), Some(8)));
}
#[test]
fn responses_requires_its_own_terminal_event() {
    for ending in ["response.completed", "response.incomplete"] {
        let body = format!(
            "event: {ending}\ndata: {{\"type\":\"{ending}\",\"response\":{{\"usage\":{{\"input_tokens\":2,\"output_tokens\":4}}}}}}\n\n"
        );
        let mut u = UsageDecoder::new(
            Mode::Strict(AccountingProfile::OpenaiResponses),
            Some("text/event-stream"),
            None,
        );
        u.push(body.as_bytes());
        u.finish();
        assert_eq!(u.strict_usage(), Ok((2, 4)));
    }
    let mut u = UsageDecoder::new(
        Mode::Strict(AccountingProfile::OpenaiResponses),
        Some("text/event-stream"),
        None,
    );
    u.push(b"data: {\"response\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":4}}}\n\ndata: [DONE]\n\n");
    u.finish();
    assert!(u.strict_usage().is_err());
}
#[test]
fn decompression_errors_and_bombs_never_leave_chargeable_partial_usage() {
    let good = compressed(
        br#"{"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
        "gzip",
    );
    for (bytes, encoding) in [
        (&good[..good.len() - 4], "gzip"),
        (good.as_slice(), "br"),
        (good.as_slice(), "zstd"),
    ] {
        let mut u = UsageDecoder::new(
            Mode::Strict(AccountingProfile::OpenaiChat),
            None,
            Some(encoding),
        );
        u.push(bytes);
        u.finish();
        assert!(u.strict_usage().is_err());
    }
    let bomb = compressed(&b": ping\n\n".repeat(MAX_DECODED_BYTES / 8 + 1), "gzip");
    let mut u = UsageDecoder::new(
        Mode::Strict(AccountingProfile::OpenaiChat),
        Some("text/event-stream"),
        Some("gzip"),
    );
    u.push(&bomb);
    u.finish();
    assert_eq!(u.strict_usage(), Err(UsageFault::Bounds));
}

#[test]
fn strict_identity_decode_and_sse_pending_limits_cannot_be_bypassed() {
    let mut trailing = UsageDecoder::new(
        Mode::Strict(AccountingProfile::OpenaiChat),
        Some("application/json"),
        None,
    );
    trailing.push(br#"{"usage":{"prompt_tokens":1,"completion_tokens":1}} trailing"#);
    trailing.finish();
    assert_eq!(trailing.strict_usage(), Err(UsageFault::Malformed));
    for (mime, size) in [
        ("application/json", MAX_DECODED_BYTES + 1),
        ("text/event-stream", 512 * 1024 + 1),
    ] {
        let mut usage = UsageDecoder::new(
            Mode::Strict(AccountingProfile::OpenaiChat),
            Some(mime),
            Some("identity"),
        );
        usage.push(&vec![b' '; size]);
        usage.finish();
        assert_eq!(usage.strict_usage(), Err(UsageFault::Bounds));
    }
}
