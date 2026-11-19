//! Shared speech request and the hosted audio interface translation.
use super::RequestError;
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

#[derive(Debug, Deserialize)]
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
        hellas_rpc::http_fetch::path::voice_segment(&request.voice)
            .map_err(|e| invalid(e.to_string()))?;
        Ok(request)
    }
    pub fn native(&self, model: &str) -> Result<(), RequestError> {
        if self.model != model {
            return Err(invalid("unknown speech model"));
        }
        if self.response_format != "wav" {
            return Err(invalid("MMS speech supports response_format wav"));
        }
        if self.voice != "default" {
            return Err(invalid("MMS English supports voice default"));
        }
        Ok(())
    }
}

/// Configured upstream model and explicit supported output-format mappings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedSpeech {
    pub model_id: String,
    pub formats: BTreeMap<String, String>,
}
impl HostedSpeech {
    pub fn validate(&self, url: &str) -> Result<(), RequestError> {
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
        hellas_rpc::http_fetch::path::substitute(url, "voice")
            .map_err(|e| invalid(e.to_string()))?;
        Ok(())
    }
    pub fn translate(
        &self,
        url: &str,
        request: &SpeechRequest,
    ) -> Result<(String, Vec<u8>), RequestError> {
        if request.speed != 1. {
            return Err(invalid("hosted speech supports speed 1"));
        }
        let output = self
            .formats
            .get(&request.response_format)
            .ok_or_else(|| invalid("unsupported hosted speech response_format"))?;
        let url = hellas_rpc::http_fetch::path::substitute(url, &request.voice)
            .map_err(|e| invalid(e.to_string()))?;
        let mut url = url::Url::parse(&url).map_err(|e| invalid(e.to_string()))?;
        url.query_pairs_mut().append_pair("output_format", output);
        let body = serde_json::to_vec(
            &serde_json::json!({"text": request.input, "model_id": self.model_id}),
        )
        .map_err(|e| invalid(e.to_string()))?;
        Ok((url.into(), body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_only_supported_speech_fields() {
        let adaptor = HostedSpeech {
            model_id: "upstream-model".into(),
            formats: [("wav".into(), "pcm wav".into())].into(),
        };
        let url = "https://audio.example/v1/text-to-speech/{voice_id}";
        adaptor.validate(url).unwrap();
        let mut request = SpeechRequest::parse(
            br#"{"model":"hosted","input":"hello","voice":"voice two","response_format":"wav"}"#,
        )
        .unwrap();
        let (url, body) = adaptor.translate(url, &request).unwrap();
        assert_eq!(
            url,
            "https://audio.example/v1/text-to-speech/voice%20two?output_format=pcm+wav"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"text":"hello","model_id":"upstream-model"})
        );
        request.speed = 2.;
        assert!(
            adaptor
                .translate("https://audio.example/{voice_id}", &request)
                .is_err()
        );
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
