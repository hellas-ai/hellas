//! OpenAI `/v1/audio/transcriptions`: multipart form fields in, a `json`
//! or `text` body out. Multipart framing and the audio payload limit are
//! the HTTP server's; this module interprets the fields it extracts.

use serde_json::{Value as JsonValue, json};

/// The longest non-file form field accepted, in bytes.
pub const MAX_FIELD_BYTES: usize = 256;
/// The content type of a `text` transcription body.
pub const TEXT_CONTENT_TYPE: &str = "text/plain; charset=utf-8";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptionField {
    Model,
    File,
    Language,
    ResponseFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptionFormat {
    Json,
    Text,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptionRequest {
    pub model: String,
    pub file: Vec<u8>,
    pub language: Option<String>,
    pub response_format: TranscriptionFormat,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TranscriptionError {
    #[error("duplicate {0} field")]
    DuplicateField(String),
    #[error("unsupported field {0}")]
    UnsupportedField(String),
    #[error("form field too long")]
    FieldTooLong,
    #[error("invalid UTF-8 form field")]
    InvalidUtf8,
    #[error("unknown model")]
    UnknownModel,
    #[error("response_format must be json or text")]
    UnsupportedResponseFormat,
    #[error("file field is required")]
    MissingFile,
}

impl TranscriptionError {
    /// The HTTP status this error is reported with.
    pub fn status(&self) -> u16 {
        match self {
            Self::UnknownModel => 404,
            _ => 400,
        }
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
    /// Admit a field by name, before its bytes are read.
    pub fn field(&self, name: &str) -> Result<TranscriptionField, TranscriptionError> {
        let (field, seen) = match name {
            "model" => (TranscriptionField::Model, self.model.is_some()),
            "file" => (TranscriptionField::File, self.file.is_some()),
            "language" => (TranscriptionField::Language, self.language.is_some()),
            "response_format" => (
                TranscriptionField::ResponseFormat,
                self.response_format.is_some(),
            ),
            _ => return Err(TranscriptionError::UnsupportedField(name.to_owned())),
        };
        if seen {
            return Err(TranscriptionError::DuplicateField(name.to_owned()));
        }
        Ok(field)
    }

    /// Record the bytes of a field admitted by [`Self::field`].
    pub fn insert(
        &mut self,
        field: TranscriptionField,
        bytes: Vec<u8>,
    ) -> Result<(), TranscriptionError> {
        if field == TranscriptionField::File {
            self.file = Some(bytes);
            return Ok(());
        }
        if bytes.len() > MAX_FIELD_BYTES {
            return Err(TranscriptionError::FieldTooLong);
        }
        let value = String::from_utf8(bytes).map_err(|_| TranscriptionError::InvalidUtf8)?;
        *match field {
            TranscriptionField::Model => &mut self.model,
            TranscriptionField::Language => &mut self.language,
            TranscriptionField::ResponseFormat => &mut self.response_format,
            TranscriptionField::File => unreachable!(),
        } = Some(value);
        Ok(())
    }

    /// The request, if it names `served_model` and is complete.
    pub fn finish(self, served_model: &str) -> Result<TranscriptionRequest, TranscriptionError> {
        let model = self
            .model
            .filter(|model| model == served_model)
            .ok_or(TranscriptionError::UnknownModel)?;
        let response_format = match self.response_format.as_deref().unwrap_or("json") {
            "json" => TranscriptionFormat::Json,
            "text" => TranscriptionFormat::Text,
            _ => return Err(TranscriptionError::UnsupportedResponseFormat),
        };
        Ok(TranscriptionRequest {
            model,
            file: self.file.ok_or(TranscriptionError::MissingFile)?,
            language: self.language,
            response_format,
        })
    }
}

/// The `json` response body for a transcript.
pub fn json_body(text: &str) -> JsonValue {
    json!({ "text": text })
}

/// The error response body.
pub fn error_body(message: &str) -> JsonValue {
    json!({ "error": { "message": message } })
}

#[cfg(test)]
mod tests;
