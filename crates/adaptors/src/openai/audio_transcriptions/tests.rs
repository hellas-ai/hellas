use super::*;

fn form(fields: &[(&str, &[u8])]) -> Result<(Vec<u8>, Option<String>, bool), TranscriptionError> {
    let mut form = TranscriptionForm::default();
    for (name, bytes) in fields {
        form.admit(name)?;
        form.insert(name, bytes.to_vec())?;
    }
    form.finish("tiny")
}

#[test]
fn transcription_forms_parse_or_reject_with_their_status() {
    let (tiny, file) = (("model", &b"tiny"[..]), ("file", &b""[..]));
    let text = ("response_format", &b"text"[..]);
    let parsed = form(&[("file", b"w"), ("language", b"en"), tiny, text]);
    assert_eq!(parsed, Ok((b"w".to_vec(), Some("en".into()), true)));
    let long = [b'a'; MAX_FIELD_BYTES + 1];
    let srt = ("response_format", &b"srt"[..]);
    assert_eq!(form(&[tiny, file]).map(|(.., text)| text), Ok(false));
    for (fields, status, message) in [
        (&[tiny, tiny][..], 400, "duplicate model field"),
        (&[("prompt", b"")], 400, "unsupported field prompt"),
        (&[("language", &long[..])], 400, "form field too long"),
        (&[("model", b"\xff")], 400, "invalid UTF-8 form field"),
        (&[("model", b"no"), srt], 404, "unknown model"),
        (&[tiny, srt], 400, "response_format must be json or text"),
        (&[tiny], 400, "file field is required"),
        (&[("model", b""), file], 400, "model field is required"),
    ] {
        let message = message.into();
        assert_eq!(form(fields), Err(TranscriptionError { status, message }));
    }
}
