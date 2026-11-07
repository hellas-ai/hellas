use super::{TranscriptionError::*, TranscriptionFormat::*, *};

fn form(fields: &[(&str, &[u8])]) -> Result<TranscriptionRequest, TranscriptionError> {
    let mut form = TranscriptionForm::default();
    for (name, bytes) in fields {
        form.insert(form.field(name)?, bytes.to_vec())?;
    }
    form.finish("tiny")
}

#[test]
fn transcription_forms_parse_reject_and_render() {
    let request = form(&[("file", b"w"), ("language", b"en"), ("model", b"tiny")]).unwrap();
    assert_eq!(request.file, b"w");
    assert_eq!(request.language.as_deref(), Some("en"));
    let (tiny, file) = (("model", &b"tiny"[..]), ("file", &b""[..]));
    let long = [b'a'; MAX_FIELD_BYTES + 1];
    let format = |value: &'static [u8]| ("response_format", value);
    for (fields, result) in [
        (&[tiny, file][..], Ok(Json)),
        (&[tiny, file, format(b"text")], Ok(Text)),
        (&[tiny, tiny], Err(DuplicateField("model".into()))),
        (&[("prompt", b"")], Err(UnsupportedField("prompt".into()))),
        (&[("language", &long[..])], Err(FieldTooLong)),
        (&[("model", b"\xff")], Err(InvalidUtf8)),
        (&[("model", b"no"), format(b"srt")], Err(UnknownModel)),
        (&[tiny, format(b"srt")], Err(UnsupportedResponseFormat)),
        (&[tiny], Err(MissingFile)),
    ] {
        assert_eq!(form(fields).map(|request| request.response_format), result);
    }
    assert_eq!((UnknownModel.status(), MissingFile.status()), (404, 400));
    assert_eq!(json_body("hi").to_string(), r#"{"text":"hi"}"#);
    let error = error_body("no").to_string();
    assert_eq!(error, r#"{"error":{"message":"no"}}"#);
}
