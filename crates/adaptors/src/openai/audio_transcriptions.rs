//! OpenAI `/v1/audio/transcriptions`: multipart form fields in, a `json`
//! or `text` body out. Multipart framing and the audio payload limit are
//! the HTTP server's; this module interprets the fields it extracts.

/// The longest non-file form field accepted, in bytes.
pub const MAX_FIELD_BYTES: usize = 256;

/// A rejected form, with the HTTP status it is reported under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptionError {
    pub status: u16,
    pub message: String,
}

fn bad(message: impl Into<String>) -> TranscriptionError {
    TranscriptionError {
        status: 400,
        message: message.into(),
    }
}

/// The form fields of one transcription request, in arrival order.
#[derive(Debug, Default)]
pub struct TranscriptionForm {
    model: Option<String>,
    file: Option<Vec<u8>>,
    language: Option<String>,
    response_format: Option<String>,
}

impl TranscriptionForm {
    fn slot(&mut self, name: &str) -> Option<&mut Option<String>> {
        match name {
            "model" => Some(&mut self.model),
            "language" => Some(&mut self.language),
            "response_format" => Some(&mut self.response_format),
            _ => None,
        }
    }

    /// Admit a field by name, before its bytes are read.
    pub fn admit(&mut self, name: &str) -> Result<(), TranscriptionError> {
        let seen = match name {
            "file" => self.file.is_some(),
            _ => self
                .slot(name)
                .ok_or_else(|| bad(format!("unsupported field {name}")))?
                .is_some(),
        };
        if seen {
            return Err(bad(format!("duplicate {name} field")));
        }
        Ok(())
    }

    /// Record the bytes of a field [`Self::admit`] accepted.
    pub fn insert(&mut self, name: &str, bytes: Vec<u8>) -> Result<(), TranscriptionError> {
        if name == "file" {
            self.file = Some(bytes);
            return Ok(());
        }
        if bytes.len() > MAX_FIELD_BYTES {
            return Err(bad("form field too long"));
        }
        let value = String::from_utf8(bytes).map_err(|_| bad("invalid UTF-8 form field"))?;
        *self.slot(name).expect("an admitted field") = Some(value);
        Ok(())
    }

    /// The audio file, its language, and whether the response is `text`
    /// rather than `json`, if the form names `served_model` and is complete.
    pub fn finish(
        self,
        served_model: &str,
    ) -> Result<(Vec<u8>, Option<String>, bool), TranscriptionError> {
        if self.model.as_deref() != Some(served_model) {
            return Err(TranscriptionError {
                status: 404,
                message: "unknown model".into(),
            });
        }
        let text = match self.response_format.as_deref().unwrap_or("json") {
            "json" => false,
            "text" => true,
            _ => return Err(bad("response_format must be json or text")),
        };
        let file = self.file.ok_or_else(|| bad("file field is required"))?;
        Ok((file, self.language, text))
    }
}

/// The `json` response body for a transcript.
pub fn json_body(text: &str) -> serde_json::Value {
    serde_json::json!({ "text": text })
}

#[cfg(test)]
mod tests;
