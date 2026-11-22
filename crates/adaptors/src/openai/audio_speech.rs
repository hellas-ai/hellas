//! Shared speech request and the hosted audio interface translation.
use super::RequestError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_rpc::http_fetch::{HttpFetchRequest, HttpTls, HttpTrustRoots};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const PATH: &str = "/v1/audio/speech";
fn invalid(message: impl Into<String>) -> RequestError {
    RequestError::new(400, message)
}
fn speed() -> f32 {
    1.
}
fn format() -> String {
    "mp3".into()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpeechRequest {
    pub model: String,
    pub input: String,
    pub voice: String,
    #[serde(default = "format")]
    pub response_format: String,
    #[serde(default = "speed")]
    pub speed: f32,
}
impl SpeechRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self, RequestError> {
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|e| invalid(format!("invalid speech request: {e}")))?;
        if request.model.is_empty()
            || request.input.trim().is_empty()
            || request.input.len() > 16384
        {
            return Err(invalid(
                "model and nonempty input up to 16384 bytes are required",
            ));
        }
        if !request.speed.is_finite() || !(0.25..=4.).contains(&request.speed) {
            return Err(invalid("speed must be between 0.25 and 4"));
        }
        Ok(request)
    }
    pub fn native(&self) -> Result<(), RequestError> {
        if self.response_format != "wav" {
            return Err(invalid("native speech supports response_format wav"));
        }
        Ok(())
    }
}

/// Configured upstream model and explicit supported output-format mappings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedSpeech {
    pub url: String,
    #[serde(default = "public_tls")]
    pub tls: HttpTls,
    #[serde(default = "response_limit")]
    pub max_response_bytes: u32,
    pub model_id: String,
    pub formats: BTreeMap<String, String>,
}
fn public_tls() -> HttpTls {
    HttpTls {
        roots: HttpTrustRoots::WebPki,
        spki_sha256: vec![],
    }
}
fn response_limit() -> u32 {
    hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES
}
impl HostedSpeech {
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.model_id.is_empty()
            || self.model_id.len() > 256
            || self.formats.is_empty()
            || self.formats.iter().any(|(format, upstream)| {
                !matches!(format.as_str(), "mp3" | "wav")
                    || upstream.is_empty()
                    || upstream.len() > 128
            })
        {
            return Err(invalid(
                "hosted speech requires a model id and explicit wav/mp3 format mappings",
            ));
        }
        let url = hellas_rpc::http_fetch::path::substitute(&self.url, "segment")
            .map_err(|e| invalid(e.to_string()))?;
        self.prepared(url.into(), vec![]).map(|_| ())
    }
    pub fn translate(&self, request: &SpeechRequest) -> Result<HttpFetchRequest, RequestError> {
        if request.speed != 1. {
            return Err(invalid("hosted speech supports speed 1"));
        }
        let output = self
            .formats
            .get(&request.response_format)
            .ok_or_else(|| invalid("unsupported hosted speech response_format"))?;
        let mut url = hellas_rpc::http_fetch::path::substitute(&self.url, &request.voice)
            .map_err(|e| invalid(e.to_string()))?;
        url.query_pairs_mut().append_pair("output_format", output);
        let body = serde_json::to_vec(
            &serde_json::json!({"text": request.input, "model_id": self.model_id}),
        )
        .map_err(|e| invalid(e.to_string()))?;
        self.prepared(url.into(), body)
    }
    fn prepared(&self, url: String, body: Vec<u8>) -> Result<HttpFetchRequest, RequestError> {
        let request = HttpFetchRequest {
            url,
            method: "POST".into(),
            tls: Some(self.tls.clone()),
            max_response_bytes: self.max_response_bytes,
            headers: vec![("content-type".into(), "application/json".into())],
            body_base64: STANDARD.encode(body),
        };
        request.validate().map_err(|e| invalid(e.to_string()))?;
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_only_supported_speech_fields() {
        let adaptor = HostedSpeech {
            url: "https://audio.example/v1/text-to-speech/{segment}".into(),
            tls: public_tls(),
            max_response_bytes: response_limit(),
            model_id: "upstream-model".into(),
            formats: [("wav".into(), "pcm wav".into())].into(),
        };
        adaptor.validate().unwrap();
        let mut request = SpeechRequest::parse(
            br#"{"model":"hosted","input":"hello","voice":"voice two","response_format":"wav"}"#,
        )
        .unwrap();
        let prepared = adaptor.translate(&request).unwrap();
        assert_eq!(
            prepared.url,
            "https://audio.example/v1/text-to-speech/voice%20two?output_format=pcm+wav"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &STANDARD.decode(&prepared.body_base64).unwrap()
            )
            .unwrap(),
            serde_json::json!({"text":"hello","model_id":"upstream-model"})
        );
        request.speed = 2.;
        assert!(adaptor.translate(&request).is_err());
        for extra in [
            r#", "instructions":"whisper""#,
            r#", "stream":true"#,
            r#", "input":"duplicate""#,
        ] {
            assert!(
                SpeechRequest::parse(
                    format!(r#"{{"model":"mms","input":"hi","voice":"default"{extra}}}"#)
                        .as_bytes()
                )
                .is_err()
            );
        }
    }
}
