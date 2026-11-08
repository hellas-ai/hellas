//! OpenAI `/v1/images/generations`: the request a server admits and the
//! body it answers with. Rendering the image and the request size limit
//! are the server's.

use base64::Engine as _;
use serde_json::{Value as JsonValue, json};

use super::RequestError;

/// One admitted image generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageGeneration {
    pub prompt: String,
    pub seed: u64,
    pub steps: usize,
    pub width: usize,
    pub height: usize,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    model: String,
    prompt: String,
    seed: Option<u64>,
    steps: Option<usize>,
    size: Option<String>,
    n: Option<usize>,
    response_format: Option<String>,
}

impl ImageGeneration {
    /// Admit `body` if it names `served_model` and asks for one base64 image.
    pub fn parse(body: JsonValue, served_model: &str) -> Result<Self, RequestError> {
        let request: Request = serde_json::from_value(body)
            .map_err(|error| RequestError::new(400, error.to_string()))?;
        if request.model != served_model {
            return Err(RequestError::new(404, "unknown model"));
        }
        if request.n.unwrap_or(1) != 1
            || request.response_format.as_deref().unwrap_or("b64_json") != "b64_json"
        {
            return Err(RequestError::new(
                400,
                "n must be 1 and response_format must be b64_json",
            ));
        }
        let size = request.size.as_deref().unwrap_or("512x512");
        let (width, height) = size
            .split_once('x')
            .and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?)))
            .ok_or_else(|| RequestError::new(400, "size must be WIDTHxHEIGHT"))?;
        Ok(Self {
            prompt: request.prompt,
            seed: request.seed.unwrap_or(0),
            steps: request.steps.unwrap_or(4),
            width,
            height,
        })
    }
}

/// The response body carrying one generated PNG.
pub fn render(png: &[u8], created: u64) -> JsonValue {
    json!({
        "created": created,
        "data": [{ "b64_json": base64::engine::general_purpose::STANDARD.encode(png) }],
    })
}
